"""Translated from t/modules/reflector.t -- mod_reflector (with mod_deflate).

POST a body (plus header2reflect/update/delete and gzip encoding headers) to
the no-deflate and deflate reflector locations. For no-deflate the body comes
back unchanged with no Content-Encoding; for deflate the body is changed and
Content-Encoding is gzip. Reflected/updated/deleted headers are checked.

Perl original used ``need 'mod_reflector', 'mod_deflate'``.
"""

import pytest

from apache_pytest import need_module, t_cmp

TESTCASES = [
    ("/apache/reflector_nodeflate/", "Text that will not reach the DEFLATE filter"),
    ("/apache/reflector_deflate/", "Text that should be gzipped"),
]

HEADERS = {
    "header2reflect": "1",
    "header2update": "1",
    "header2delete": "1",
    "Content-Encoding": "gzip",
    "Accept-Encoding": "gzip",
}


@need_module("mod_reflector", "mod_deflate")
@pytest.mark.parametrize("url,payload", TESTCASES, ids=lambda v: str(v))
def test_reflector(http, url, payload):
    # raw_response keeps the body undecoded: the deflate case must observe that
    # the gzip body differs from the payload, but httpx would auto-decompress
    # .text/.content back to the payload and mask the transformation.
    r = http.raw_response("POST", url, content=payload, headers=HEADERS)
    body = r.raw_content.decode("latin-1")

    assert t_cmp(r.status_code, 200), "Checking return code is '200'"

    if "_nodeflate" in url:
        # With no filter, we should receive what we have sent.
        assert t_cmp(body, payload)
        assert t_cmp(r.headers.get("Content-Encoding"), None), \
            "'Content-Encoding' has not been added because there was no filter"
    else:
        # With DEFLATE, input was updated and 'Content-Encoding' added.
        assert body != payload
        assert t_cmp(r.headers.get("Content-Encoding"), "gzip"), \
            "'Content-Encoding' has been added by the DEFLATE filter"

    assert t_cmp(r.headers.get("header2reflect"), "1"), "'header2reflect' is present"
    assert t_cmp(r.headers.get("header2update"), None), "'header2update' is absent"
    assert t_cmp(r.headers.get("header2updateUpdated"), "1"), \
        "'header2updateUpdated' is present"
    assert t_cmp(r.headers.get("header2delete"), None), "'header2delete' is absent"
