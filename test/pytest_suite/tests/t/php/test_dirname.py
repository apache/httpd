r"""Translated from t/php/dirname.t -- need_php.

dirname.php prints "dirname(<path>) == <result>" for a list of paths. The
Windows-style paths contain literal backslashes, preserved here verbatim.
"""

from apache_pytest import need_php

EXPECTED = (
    "dirname(/foo/) == /\n"
    "dirname(/foo) == /\n"
    "dirname(/foo/bar) == /foo\n"
    "dirname(d:\\foo\\bar.inc) == .\n"
    "dirname(/) == /\n"
    "dirname(.../foo) == ...\n"
    "dirname(./foo) == .\n"
    "dirname(foobar///) == .\n"
    "dirname(c:\\foo) == .\n"
)


@need_php()
def test_dirname(http):
    result = http.GET_BODY("/php/dirname.php")
    assert result == EXPECTED
