"""Translated from t/php/var1.t -- need_php.

var1.php echoes back the 'variable' parameter. Sent via POST and GET; the '+'
in the value is form-decoded to a space, which the expected value mirrors.
"""

from apache_pytest import need_php, t_cmp

PAGE = "/php/var1.php"
DATA = "blah1+blah2+FOO"
EXPECTED = DATA.replace("+", " ")


@need_php()
def test_var1_post(http):
    # PHP only populates $_POST from a form body when the request carries the
    # urlencoded Content-Type. The Perl harness/LWP set it implicitly; under
    # FPM it must be set explicitly or PHP leaves $_POST empty.
    ret = http.POST_BODY(
        PAGE,
        content=f"variable={DATA}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert t_cmp(ret, EXPECTED), (
        f'POST request for {PAGE}, content="variable={DATA}"'
    )


@need_php()
def test_var1_get(http):
    ret = http.GET_BODY(f"{PAGE}?variable={DATA}")
    assert t_cmp(ret, EXPECTED), f"GET request for {PAGE}?variable={DATA}"
