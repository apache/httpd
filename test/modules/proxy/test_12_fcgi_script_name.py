import json
import os

import pytest

from pyhttpd.conf import HttpdConf
from .fcgi_echo import FcgiEcho


class TestProxyFcgiScriptName:
    """SCRIPT_NAME sent to a FastCGI backend with proxy-fcgi-pathinfo set.
    It must not include the PATH_INFO part (RFC 3875 4.1.13), also when the
    URL path holds %-escapes (PR 66608)."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("proxy_fcgi"),
                    "mod_proxy_fcgi not available", dep="mod_proxy_fcgi",
                    detected=f"no mod_proxy_fcgi.so in {env.libexec_dir}")
        env.require(env.has_shared_module("include"),
                    "mod_include not available", dep="mod_include",
                    detected=f"no mod_include.so in {env.libexec_dir}")
        # An SSI page including the FastCGI paths as subrequests, which run
        # with SERVER_PROTOCOL "INCLUDED".
        with open(os.path.join(env.server_dir, "htdocs", "fcgi_inc.shtml"),
                  "w") as fd:
            fd.write('@@<!--#include virtual="/inc/a/b" -->@@\n'
                     '@@<!--#include virtual="/inc/a%20b/c" -->@@\n')
        backend = FcgiEcho("127.0.0.1", env.http_port2)
        backend.start()
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port)
        conf.add([
            "SetEnvIf Request_URI ^/app/ proxy-fcgi-pathinfo=1",
            "SetEnvIf Request_URI ^/unesc/ proxy-fcgi-pathinfo=unescape",
            "ProxyFCGIBackendType GENERIC",
            f"ProxyPass /app/ fcgi://127.0.0.1:{env.http_port2}/",
            f"ProxyPass /unesc/ fcgi://127.0.0.1:{env.http_port2}/",
            # SetEnvIf does not run for subrequests, mod_rewrite does.
            "<Location /inc/>",
            "  RewriteEngine on",
            "  RewriteRule ^ - [E=proxy-fcgi-pathinfo:1]",
            "</Location>",
            f"ProxyPass /inc/ fcgi://127.0.0.1:{env.http_port2}/",
            "<Location /fcgi_inc.shtml>",
            "  Options +Includes",
            "  SetOutputFilter INCLUDES",
            "</Location>",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield
        backend.stop()

    @pytest.mark.parametrize("path, script_name, path_info", [
        ("/app/a/b", "/app", "/a/b"),
        ("/app/a/x%20y", "/app", "/a/x%20y"),
        ("/app/%C3%A9t%C3%A9/z", "/app", "/%C3%A9t%C3%A9/z"),
        ("/unesc/a/x%20y", "/unesc", "/a/x y"),
    ])
    def test_proxy_012_01(self, env, path, script_name, path_info):
        r = env.curl_get(env.mkurl("http", "test1", path))
        assert r.response["status"] == 200
        params = json.loads(r.response["body"])
        assert params["SCRIPT_NAME"] == script_name
        assert params["PATH_INFO"] == path_info

    def test_proxy_012_02(self, env):
        """An SSI include keeps the SCRIPT_NAME core gives "INCLUDED"
        subrequests, the whole URI, escaped or not."""
        r = env.curl_get(env.mkurl("http", "test1", "/fcgi_inc.shtml"))
        assert r.response["status"] == 200
        included = [json.loads(part) for part in
                    r.response["body"].decode().split("@@")[1::2]]
        assert [(p["SERVER_PROTOCOL"], p["SCRIPT_NAME"], p["PATH_INFO"])
                for p in included] == [
            ("INCLUDED", "/inc/a/b", "/a/b"),
            ("INCLUDED", "/inc/a b/c", "/a%20b/c"),
        ]
