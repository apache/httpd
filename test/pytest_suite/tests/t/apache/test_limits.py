r"""Translated from t/apache/limits.t -- LimitRequestLine, LimitRequestFieldSize,
LimitRequestFields and LimitRequestBody directives.

For each condition there is a "succeed" case (within the limit -> 200) and a
"fail" case (exceeds the limit -> the directive's error code). The body-size
condition is exercised both with a chunked upload and a plain Content-Length
upload.

Needs: need_lwp.
"""

import pytest

from apache_pytest import need_lwp, t_cmp

LOC = "/apache/limits/"
LIMITREQUESTLINEX2 = 256  # vars["limitrequestlinex2"] default

CONDITIONS = ["requestline", "fieldsize", "fieldcount", "bodysize", "merged_fieldsize"]

PARAMS = {
    "requestline-succeed": LOC,
    "requestline-fail": LOC + "a" * LIMITREQUESTLINEX2,
    "fieldsize-succeed": "short value",
    "fieldsize-fail": "a" * 2048,
    "fieldcount-succeed": 1,
    "fieldcount-fail": 64,
    "bodysize-succeed": "a" * 1024,
    "bodysize-fail": "a" * 131072,
    "merged_fieldsize-succeed": "a" * 500,
    "merged_fieldsize-fail": "a" * 600,
}
XRCS = {
    "requestline-succeed": 200,
    "requestline-fail": 414,
    "fieldsize-succeed": 200,
    "fieldsize-fail": 400,
    "fieldcount-succeed": 200,
    "fieldcount-fail": 400,
    "bodysize-succeed": 200,
    "bodysize-fail": 413,
    "merged_fieldsize-succeed": 200,
    "merged_fieldsize-fail": 400,
}


def _xrc(http, key):
    rc = XRCS[key]
    if key == "merged_fieldsize-fail" and not http.have_min_apache_version("2.2.32"):
        return 200
    return rc


@need_lwp()
@pytest.mark.parametrize("cond", CONDITIONS)
@pytest.mark.parametrize("goodbad", ["succeed", "fail"])
def test_limits(http, cond, goodbad):
    key = f"{cond}-{goodbad}"
    param = PARAMS[key]
    expected_rc = _xrc(http, key)

    if cond == "fieldcount":
        fields = {f"X-Field-{i}": f"Testing field {i}" for i in range(1, int(param) + 1)}
        resp = http.GET(LOC, headers=fields)
        assert t_cmp(resp.status_code, expected_rc), key

    elif cond == "bodysize":
        # chunked upload
        def gen(data=param):
            yield data.encode()

        resp = http.GET(
            LOC, headers={"Content-Type": "text/plain"}, content=gen()
        )
        assert t_cmp(resp.status_code, expected_rc), f"{key} (chunked)"
        # plain Content-Length upload
        resp = http.GET(
            LOC, headers={"Content-Type": "text/plain"}, content=param.encode()
        )
        assert t_cmp(resp.status_code, expected_rc), f"{key} (content-length)"

    elif cond == "merged_fieldsize":
        # two copies of the same header name (merged)
        resp = http.GET(LOC, headers=[("X-overflow-field", param), ("X-overflow-field", param)])
        assert t_cmp(resp.status_code, expected_rc), key

    elif cond == "fieldsize":
        resp = http.GET(LOC, headers={"X-overflow-field": param})
        assert t_cmp(resp.status_code, expected_rc), key

    elif cond == "requestline":
        resp = http.GET(param)
        assert t_cmp(resp.status_code, expected_rc), key
