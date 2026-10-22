r"""Content-Type of a custom response body (PR 69430).

The custom_response C test module fails every request with 400 and a plain
text body. ap_custom_response() sends it as text/html, whatever Content-Type
is left on the request by ForceType, mod_mime or a handler that declined.
ap_custom_response_ct() sends it with the given type, and a later
ap_custom_response() for the same status takes that type away again. HEAD
must announce the same type as GET.

Needs: the custom_response C test module.
"""

import pytest

from apache_pytest import need_module, t_cmp

HTML = "text/html; charset=iso-8859-1"

CASES = [
    # type left on the request by ForceType
    ("/custom_response/plain", HTML, "<html>Bad request</html>"),
    # type registered together with the body
    ("/custom_response/ct", "application/json",
     '{"error":"bad request"}'),
    # body registered again without a type
    ("/custom_response/replaced", HTML, "second"),
    # type set by a handler that declined
    ("/custom_response/declined", HTML, "<html>Bad request</html>"),
]


@need_module("custom_response")
@pytest.mark.parametrize("path,ctype,body", CASES)
def test_custom_response_content_type(http, path, ctype, body):
    r = http.GET(path)
    assert t_cmp(r.status_code, 400), f"{path} GET code"
    assert t_cmp(r.headers.get("Content-Type"), ctype), f"{path} GET type"
    assert t_cmp(r.text, body), f"{path} GET body"

    r = http.HEAD(path)
    assert t_cmp(r.status_code, 400), f"{path} HEAD code"
    assert t_cmp(r.headers.get("Content-Type"), ctype), f"{path} HEAD type"
