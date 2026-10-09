r"""Translated from t/ssl/ocsp.t.

The ssl_ocsp virtual host enables OCSP client-certificate validation
(SSLVerifyClient on + SSLOCSPEnable, with the ocsp.pl CGI acting as the OCSP
responder). Behaviour:

  * no client cert      -> handshake/transport failure (LWP surfaced as 500)
  * client_ok           -> 200 (OCSP says good)
  * client_revoked      -> OCSP says revoked -> handshake failure (500)

Gated on httpd >= 2.4.26 (SSLOCSPResponderCertificateFile) and on the openssl
CLI having the ``ocsp`` sub-command (the responder shells out to it).

The Perl original additionally inspected the LWP "Client-Warning" header and the
TLS-alert text; those are LWP-client specifics. We assert the status-code
contract, which is the substance of the test.
"""

import shutil
import subprocess

import pytest

from apache_pytest import need_ssl
from apache_pytest.testapi import t_cmp


def _openssl_has_ocsp() -> bool:
    openssl = shutil.which("openssl")
    if not openssl:
        return False
    try:
        out = subprocess.run(
            [openssl, "list", "-commands"], capture_output=True, text=True, check=False
        )
    except OSError:
        return False
    return "ocsp" in out.stdout.split()


@need_ssl()
def test_ocsp(http):
    if not http.have_min_apache_version("2.4.26") or not _openssl_has_ocsp():
        pytest.skip("No OpenSSL ocsp command or mod_ssl OCSP support")

    http.scheme("https")
    http.module("ssl_ocsp")
    url = "/index.html"

    assert http.GET_RC(url, cert=None) == 500, "no cert -> handshake failure"
    assert t_cmp(http.GET_RC(url, cert="client_ok"), 200), "client_ok -> OCSP good"
    assert http.GET_RC(url, cert="client_revoked") == 500, (
        "client_revoked -> OCSP revoked -> handshake failure"
    )
