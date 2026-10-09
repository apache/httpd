"""Translated from t/php/var2.t -- need_php.

var2.php echoes "$v1 $v2". Sent via POST and GET; '+' in the values is
form-decoded to a space, mirrored in the expected output.
"""

from apache_pytest import need_php, t_cmp

PAGE = "/php/var2.php"
V1 = "blah1+blah2+FOO"
V2 = "this+is+v2"
DATA = f"v1={V1}&v2={V2}"
EXPECTED = f"{V1} {V2}".replace("+", " ")


@need_php()
def test_var2_post(http):
    # PHP only populates $_POST from a form body when the request carries the
    # urlencoded Content-Type. The Perl harness/LWP set it implicitly; under
    # FPM it must be set explicitly or PHP leaves $_POST empty.
    ret = http.POST_BODY(
        PAGE,
        content=DATA,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert t_cmp(ret, EXPECTED), f'POST request for {PAGE}, content="{DATA}"'


@need_php()
def test_var2_get(http):
    ret = http.GET_BODY(f"{PAGE}?{DATA}")
    assert t_cmp(ret, EXPECTED), f"GET request for {PAGE}?{DATA}"
