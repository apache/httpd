"""mod_session_dbd writes the session cookie into both r->headers_out and
r->err_headers_out (session_dbd_save(), modules/session/mod_session_dbd.c).
merge_response_headers() (modules/http/http_filters.c) concatenates the two
tables for every response with apr_table_overlay(), which does not
deduplicate, so the identical Set-Cookie line is sent twice on an ordinary,
non-redirected response. mod_session_cookie had the same bug and was fixed
for it alone (r1843244, r1869785); mod_session_dbd was never updated to
match. BZ 68473.
"""

import re

from pyhttpd.conf import HttpdConf


class TestDbdCookie:

    def num_set_cookie_headers(self, env):
        args, headerfile = env.curl_complete_args(
            urls=[env.mkurl("http", "session", "/index.html")])
        r = env.run(args + [env.mkurl("http", "session", "/index.html")])
        assert r.exit_code == 0, f"{r}"
        with open(headerfile) as fd:
            text = fd.read()
        return len(re.findall(r'^set-cookie:', text, re.I | re.M))

    def test_session_001_01_no_duplicate_set_cookie(self, env):
        n = self.num_set_cookie_headers(env)
        assert n == 1, \
            f"expected exactly one Set-Cookie header for the DBD-backed " \
            f"session cookie, got {n}"
