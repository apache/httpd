"""Translated from t/php/arg.t -- need_php.

arg.php echoes "<n>: <arg>" for each query-string argument. The Perl test builds
a '+'-joined arg list and the matching expected output.
"""

from apache_pytest import need_php, t_cmp

TESTARGS = ["foo", "b@r", "testarg123-456-fu", "ARGV", "hello%20world"]


@need_php()
def test_arg(http):
    expected = ""
    parts = []
    for count, a in enumerate(TESTARGS):
        parts.append(a)
        expected += f"{count}: {a}\n"
    testargs = "+".join(parts)
    result = http.GET_BODY(f"/php/arg.php?{testargs}")
    assert t_cmp(result, expected), f"GET request for /php/arg.php?{testargs}"
