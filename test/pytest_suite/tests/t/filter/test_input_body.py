r"""Translated from t/filter/input_body.t -- input_body_filter C module.

Perl original (plan tests => 2, need 'input_body_filter'):
    for my $x (1,2) {
        my $expected = "ok $x";
        my $data = scalar reverse $expected;
        my $response = POST_BODY $location, content => $data;
        ok t_cmp($response, $expected, "Posted \"$data\"");
    }
The input_body_filter reverses the request body, so POSTing the reverse of
"ok N" yields "ok N".
"""

import pytest

from apache_pytest import need_module, t_cmp

LOCATION = "/input_body_filter"


@need_module("input_body_filter")
@pytest.mark.parametrize("x", [1, 2])
def test_input_body(http, x):
    expected = f"ok {x}"
    data = expected[::-1]
    response = http.POST_BODY(LOCATION, content=data)
    assert t_cmp(response, expected), f'Posted "{data}"'
