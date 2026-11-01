import os

import pytest

from pyhttpd.conf import HttpdConf


# BZ 68527: fixup_dir() in modules/mappers/mod_dir.c crashed with a NULL
# dereference in strcmp(r->handler, ...) whenever it ran on a request whose
# r->handler is NULL. That happens once mod_rewrite's internal-redirect loop
# protection (LimitInternalRecursion, default 10) kicks in on a self-matching
# RewriteRule: each internal redirect gets a fresh request_rec, and by the
# time the loop is cut off, r->handler is no longer the one set by
# SetHandler earlier in the chain. mod_dir's own fixups never guarded
# against that, even though the very next check in the same function
# (REWRITE_REDIRECT_HANDLER_NAME) has the identical unguarded strcmp.
class TestDirNullHandler:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # must live under test1's own docroot (htdocs/test1), not the
        # parent htdocs dir, or the request below never reaches this
        # <Directory> block at all.
        docs_dir = os.path.join(env.server_docs_dir, "test1", "null-handler")
        os.makedirs(docs_dir, exist_ok=True)
        conf = HttpdConf(env)
        conf.add([
            # proxy_module is already loaded by the default test module set
            f"LoadModule proxy_fcgi_module \"{env.libexec_dir}/mod_proxy_fcgi.so\"",
            f"<Directory \"{docs_dir}\">",
            "    DirectoryIndex index.php",
            # a backend need not exist: the crash happens in the fixups
            # phase, before mod_proxy_fcgi ever tries to connect.
            "    SetHandler \"proxy:fcgi://127.0.0.1:1/\"",
            "    RewriteEngine On",
            "    RewriteBase /null-handler/",
            "    RewriteRule ^(.*)$ /null-handler/index.php [L,QSA]",
            "    Require all granted",
            "</Directory>",
        ])
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_core_013_01(self, env):
        url = env.mkurl("http", "test1", "/null-handler/")
        r = env.curl_get(url, options=["--max-time", "5"])
        assert r.response, \
            f"no response at all, httpd likely crashed: {r.stderr}"
        # the self-matching RewriteRule never terminates, so this must hit
        # the existing LimitInternalRecursion safety net (a clean 500),
        # not crash the worker thread.
        assert r.response["status"] == 500
        env.httpd_error_log.ignore_recent(
            lognos=["AH00124"]  # exceeded the limit of internal redirects
        )
