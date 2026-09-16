import os

import pytest

from pyhttpd.conf import HttpdConf

# SubstituteMaxLineLength caps the length of a line after substitution.  Each
# flag combination reaches a different branch of do_pattmatch(): regex or
# literal ('n'), flattened into one bucket or left as separate ones ('q').
MODES = {
    'regex_flatten': 'f',
    'regex_quick': 'q',
    'literal_flatten': 'nf',
    'literal_quick': 'nq',
}

MAXLEN = 10
# "x" expands to "yy", so each line grows by exactly one byte.
OVER = "x" + "a" * 9        # 10 bytes in, 11 out -- over the limit
OVER_MID = "aaaa" + "x" + "aaaaa"   # same, with the match off the start
OVER_END = "a" * 9 + "x"    # same again, but with no unmatched tail
EXACT = "x" + "a" * 8       # 9 bytes in, 10 out -- exactly at the limit


class TestSubstituteMaxLineLength:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        for name, text in [("over.html", OVER), ("over_mid.html", OVER_MID),
                           ("over_end.html", OVER_END), ("exact.html", EXACT)]:
            with open(os.path.join(doc_dir, name), "w") as f:
                f.write(text)
        # APLOGNO(01328) "Line too long" is the expected rejection.
        env.httpd_error_log.add_ignored_lognos(["AH01328"])

    def configure(self, env, flags):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            SubstituteMaxLineLength {MAXLEN}
            <Location "/">
                AddOutputFilterByType SUBSTITUTE text/html
                Substitute "s/x/yy/{flags}"
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, path):
        return env.curl_get(env.mkurl("http", "test1", path))

    # A line that would grow past the limit must be rejected, not truncated
    # and not returned over-length.
    @pytest.mark.parametrize("doc", ["over.html", "over_mid.html", "over_end.html"])
    @pytest.mark.parametrize("mode", list(MODES), ids=list(MODES))
    def test_filters_001_01(self, env, mode, doc):
        self.configure(env, MODES[mode])
        r = self.get(env, f"/{doc}")
        body = r.response["body"].decode() if r.response else None
        assert not (r.response and r.response["status"] == 200
                    and len(body) > MAXLEN), \
            f"{mode} {doc}: over-length line returned: " \
            f"{len(body) if body else None} bytes {body!r}"

    # A line that lands exactly on the limit is still served.
    @pytest.mark.parametrize("mode", list(MODES), ids=list(MODES))
    def test_filters_001_02(self, env, mode):
        self.configure(env, MODES[mode])
        r = self.get(env, "/exact.html")
        assert r.response, f"{mode}: no response"
        assert r.response["status"] == 200, f"{mode}: status {r.response['status']}"
        body = r.response["body"].decode()
        assert body == "yy" + "a" * 8, f"{mode}: body {body!r}"
        assert len(body) == MAXLEN
