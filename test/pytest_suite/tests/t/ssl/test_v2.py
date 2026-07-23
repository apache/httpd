r"""Translated from t/ssl/v2.t.

The original forced SSLv2 (``$ENV{HTTPS_VERSION} = 2``) and only ran when the
server was *older* than 2.4.0::

    { "SSLv2 test(s) not applicable" => sub { !need_min_apache_version('2.4.0') } }

On any modern httpd (>= 2.4.0) the test is "not applicable" and is skipped.
SSLv2 is also unsupported by modern OpenSSL/CPython, so this is unreproducible
regardless -- we faithfully skip rather than fake a pass.
"""

import pytest

from apache_pytest import need_ssl


@need_ssl()
def test_sslv2(http):
    if http.have_min_apache_version("2.4.0"):
        pytest.skip("SSLv2 test(s) not applicable (httpd >= 2.4.0)")
    pytest.skip("SSLv2 unsupported by modern OpenSSL/CPython client")
