import os

import pytest

from pyhttpd.conf import HttpdConf


class TestCharsetLite:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_charset_lite_module, "mod_charset_lite not built",
                    dep="mod_charset_lite",
                    detected=f"not found in {env.libexec_dir}")
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            <Location "/cgi/">
                AddHandler cgi-script .py
                Options +ExecCGI
                CharsetSourceEnc UTF-8
                CharsetDefault ISO-8859-1
                CharsetOptions TranslateAllMimeTypes
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # The request body is translated from CharsetDefault to
    # CharsetSourceEnc for the methods that carry content to a script,
    # which includes QUERY (RFC 10008), and left alone for the others.
    @pytest.mark.parametrize(["method", "translated"], [
        ["POST", True],
        ["PUT", True],
        ["QUERY", True],
        ["DELETE", False],
    ])
    def test_filters_010_01(self, env, method, translated):
        latin1 = "caf\u00e9".encode("iso-8859-1")
        fpath = os.path.join(env.gen_dir, "charset-lite-body")
        with open(fpath, "wb") as fd:
            fd.write(latin1)
        r = env.curl_raw([env.mkurl("http", "test1", "/cgi/hexbody.py")],
                         options=["-X", method, "--data-binary", f"@{fpath}",
                                  "-H", "Content-Type: text/plain"])
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        expected = "caf\u00e9".encode("utf-8") if translated else latin1
        assert r.response["body"].decode().strip() == expected.hex()
