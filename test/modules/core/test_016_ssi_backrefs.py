import textwrap

import pytest

from pyhttpd.conf import HttpdConf


class TestSSIBackrefs:

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            "base": textwrap.dedent(f"""
            <Directory "{env.gen_dir}">
                Options +Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            """)
        })
        conf.install()
        assert env.apache_restart() == 0

    # The captures of a regex in an #if expr are available to a later #set.
    # A group that did not take part in the match is empty, and so is one
    # that the regex does not have.
    def test_core_016_01(self, env):
        url = env.mkurl("http", "htdocs", "/ssi/backref.shtml")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        assert r.response["body"].decode("utf-8").strip() == "[][backref][shtml]"

    # A later #if/#elif must not see captures left over from an earlier,
    # unrelated one on the same page: not from a regex with no capturing
    # groups of its own, and not from a regex with capturing groups that
    # failed to match. Referencing $1-$9 in either case logs AH01329
    # ("refers to no regex"), which is the expected, safe behavior -- the
    # bug this guards against was a stale/NULL re->source read crashing the
    # worker, or leaking the earlier match's captures, instead.
    def test_core_016_02(self, env):
        url = env.mkurl("http", "htdocs", "/ssi/scope.shtml")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        assert r.response["body"].decode("utf-8").strip() == (
            "[a][b][c]\n[][][]\n[][]")
        env.httpd_error_log.ignore_recent(lognos=["AH01329"])
