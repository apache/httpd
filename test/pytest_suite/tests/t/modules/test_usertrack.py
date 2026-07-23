"""Translated from t/modules/usertrack.t -- mod_usertrack.

Run 100 iterations of a 4-request sequence (foo, bar, foo, bar), managing the
cookie manually. Only the 1st and 3rd request of an iteration get a fresh
Set-Cookie; that cookie is echoed back on the next requests. After the 2nd
request we corrupt the cookie, forcing a new cookie on the 3rd. Each generated
cookie must be unique, for a total of 2 per iteration. Finally, the opt-in
flags (Secure/HTTPonly/SameSite) must be absent.

Perl original used ``need 'mod_usertrack'``.
"""

import re

from apache_pytest import need_module, t_cmp

ITERS = 100
TESTCASES = [
    "/modules/usertrack/foo.html",
    "/modules/usertrack/bar.html",
    "/modules/usertrack/foo.html",
    "/modules/usertrack/bar.html",
]


@need_module("mod_usertrack")
def test_usertrack(http):
    cookiex = {}

    for _ in range(ITERS):
        cookie = ""
        for nb_req, url in enumerate(TESTCASES, start=1):
            # Manage the cookie manually (as the Perl test does): keep the
            # client's automatic cookie jar empty so only our explicit Cookie
            # header is sent.
            http._client.cookies.clear()
            r = http.GET(url, headers={"Cookie": cookie})
            assert t_cmp(r.status_code, 200), "Checking return code is '200'"

            setcookie = r.headers.get("Set-Cookie")

            # Only the 1st and 3rd requests must have a Set-Cookie.
            if nb_req in (1, 3) and setcookie is not None:
                assert setcookie is not None
                # Copy the cookie to send it back in the next requests.
                cookie = setcookie[: setcookie.index(";")]
                # This cookie must not have been seen before.
                assert cookie not in cookiex
                cookiex[cookie] = 1
            else:
                assert setcookie is None

            # After the 2nd request, lie and send a modified cookie so the 3rd
            # request gets a new one.
            if nb_req == 2:
                cookie = "X" + cookie

    # Overall number of unique cookies generated.
    assert len(cookiex) == ITERS * 2

    # Opt-in flags must not be set.
    http._client.cookies.clear()
    r = http.GET("/modules/usertrack/foo.html")
    assert t_cmp(r.status_code, 200), "Checking return code is '200'"
    setcookie = r.headers.get("Set-Cookie")
    assert setcookie is not None
    m = re.search(r"(Secure|HTTPonly|SameSite)", setcookie, re.IGNORECASE)
    assert t_cmp(m.group(1) if m else None, None)
