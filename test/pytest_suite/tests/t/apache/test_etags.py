r"""Translated from t/apache/etags.t -- the FileETag directive.

Each subdirectory under /apache/etags/ has a .htaccess setting FileETag with
various keyword combinations; the test HEADs a file in each and checks the ETag
response header has the expected number of components (or is absent). If the
feature is unsupported (a 500 on the probe), the whole test is skipped.
"""

import re

import pytest

X = r"[0-9a-fA-F]+"
TOKENS_1 = rf'^"{X}"$'
TOKENS_2 = rf'^"{X}-{X}"$'
TOKENS_3 = rf'^"{X}-{X}-{X}"$'


def _tests(http):
    tokens_default = TOKENS_2 if http.have_min_apache_version("2.3.15") else TOKENS_3
    return {
        "/default/": tokens_default,
        "/m/": TOKENS_1,
        "/i/": TOKENS_1,
        "/s/": TOKENS_1,
        "/mi/": TOKENS_2,
        "/ms/": TOKENS_2,
        "/is/": TOKENS_2,
        "/mis/": TOKENS_3,
        "/all/": TOKENS_3,
        "/none/": "",
        "/all/m/": TOKENS_1,
        "/all/i/": TOKENS_1,
        "/all/s/": TOKENS_1,
        "/all/mi/": TOKENS_2,
        "/all/ms/": TOKENS_2,
        "/all/is/": TOKENS_2,
        "/all/mis/": TOKENS_3,
        "/all/inherit/": TOKENS_3,
        "/none/m/": TOKENS_1,
        "/none/i/": TOKENS_1,
        "/none/s/": TOKENS_1,
        "/none/mi/": TOKENS_2,
        "/none/ms/": TOKENS_2,
        "/none/is/": TOKENS_2,
        "/none/mis/": TOKENS_3,
        "/none/inherit/": "",
        "/all/minus-m/": TOKENS_2,
        "/all/minus-i/": TOKENS_2,
        "/all/minus-s/": TOKENS_2,
        "/all/minus-mi/": TOKENS_1,
        "/all/minus-ms/": TOKENS_1,
        "/all/minus-is/": TOKENS_1,
        "/all/minus-mis/": "",
        "/none/plus-m/": TOKENS_1,
        "/none/plus-i/": TOKENS_1,
        "/none/plus-s/": TOKENS_1,
        "/none/plus-mi/": TOKENS_2,
        "/none/plus-ms/": TOKENS_2,
        "/none/plus-is/": TOKENS_2,
        "/none/plus-mis/": TOKENS_3,
        "/none/plus-mis/minus-m/": TOKENS_2,
        "/none/plus-mis/minus-i/": TOKENS_2,
        "/none/plus-mis/minus-s/": TOKENS_2,
        "/none/plus-mis/minus-mi/": TOKENS_1,
        "/none/plus-mis/minus-ms/": TOKENS_1,
        "/none/plus-mis/minus-is/": TOKENS_1,
        "/none/plus-mis/minus-mis/": "",
        "/m/plus-m/": TOKENS_1,
        "/m/plus-i/": TOKENS_2,
        "/m/plus-s/": TOKENS_2,
        "/m/plus-mi/": TOKENS_2,
        "/m/plus-ms/": TOKENS_2,
        "/m/plus-is/": TOKENS_3,
        "/m/plus-mis/": TOKENS_3,
        "/m/minus-m/": "",
        "/m/minus-i/": "",
        "/m/minus-s/": "",
        "/m/minus-mi/": "",
        "/m/minus-ms/": "",
        "/m/minus-is/": "",
        "/m/minus-mis/": "",
    }


def test_etags(http):
    probe = http.GET("/apache/etags/test.txt")
    if probe.status_code == 500:
        pytest.skip("FileETag feature not supported")

    for key, pattern in _tests(http).items():
        uri = "/apache/etags" + key + "test.txt"
        resp = http.HEAD(uri)
        etag = resp.headers.get("ETag")
        if etag is not None:
            assert re.search(pattern, etag), f"{uri}: {etag!r} !~ {pattern}"
        else:
            assert pattern == "", f"{uri}: ETag field was expected"
