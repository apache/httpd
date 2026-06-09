"""Local fixtures for the t/ssl/ tests.

Seeds the ``ssl.htpasswd`` file that the FakeBasicAuth tests (basicauth.t)
depend on. Apache::TestSSLCA::new_ca writes this at CA-generation time::

    writefile('ssl.htpasswd',
              join ':', dn_oneline('client_snakeoil'), $basic_auth_password);

The Python SSL CA generator (apache_pytest/sslca.py) does not emit it, so we
recreate it here. mod_ssl's FakeBasicAuth turns the client cert's subject DN
(legacy one-line ``/C=.../CN=.../`` form) into the Basic-auth username and uses
a fixed password "password" (crypt hash ``xxj31ZMTZzkVA``); the htpasswd entry
must therefore be the client_snakeoil DN. authn_file reads the file per request,
so writing it before the tests run is sufficient.
"""

import subprocess
from pathlib import Path

import pytest

# dn_oneline(client_snakeoil) in the non-RFC2253 (legacy) form mod_ssl's
# FakeBasicAuth produces: /C/ST/L/O/OU/CN/emailAddress. CN defaults to the cert
# name (client_snakeoil); email comes from the CA DN. Matches sslca.py CERT_DN.
_SNAKEOIL_DN = (
    "/C=AU/ST=Queensland/L=Mackay/O=Snake Oil, Ltd./OU=Staff"
    "/CN=client_snakeoil/emailAddress=test-dev@httpd.apache.org"
)
# crypt("password") -- the PASSWORD_CLEARTEXT=false hash from TestSSLCA.pm.
_BASIC_AUTH_HASH = "xxj31ZMTZzkVA"


def _ensure_crl_hash_symlink(sslca: Path) -> None:
    """Create the OpenSSL hash symlink for SSLProxyCARevocationPath (proxy.t).

    The proxy_https_https* front-ends in proxyssl.conf use
    ``SSLProxyCARevocationPath`` + ``SSLProxyCARevocationCheck chain``. OpenSSL 3
    locates CRLs in a path by the issuer-name hash (``<hash>.r0`` -> the CRL
    file). Apache::TestSSLCA's c_rehash-style setup created these; the Python SSL
    CA generator does not, so the chain CRL check fails (502/500) without it.
    """
    crl_dir = sslca / "crl"
    crl = crl_dir / "ca-bundle.crl"
    if not crl.exists():
        return
    try:
        out = subprocess.run(
            ["openssl", "crl", "-in", str(crl), "-noout", "-hash"],
            capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return
    crl_hash = out.stdout.strip()
    if not crl_hash:
        return
    link = crl_dir / f"{crl_hash}.r0"
    if not link.exists():
        link.symlink_to("ca-bundle.crl")


@pytest.fixture(scope="session", autouse=True)
def ssl_ca_extras(config):
    """Seed CA artefacts that the Python SSL CA generator omits.

    * ssl.htpasswd  -- for the FakeBasicAuth tests (basicauth.t).
    * crl/<hash>.r0 -- for path-based proxy CRL checks (proxy.t).
    """
    sslca = Path(config.vars["sslca"]) / "asf"
    if sslca.is_dir():
        htpasswd = sslca / "ssl.htpasswd"
        if not htpasswd.exists():
            htpasswd.write_text(f"{_SNAKEOIL_DN}:{_BASIC_AUTH_HASH}\n")
        _ensure_crl_hash_symlink(sslca)
    yield
