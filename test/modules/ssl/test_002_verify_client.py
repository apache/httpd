import os
from datetime import timedelta

import pytest

from pyhttpd.certs import CertificateSpec, HttpdTestCA
from pyhttpd.conf import HttpdConf

# Client credentials, each chosen so that verification fails with exactly one
# of the X509_V_ERR_* codes that "SSLVerifyClient <level> <accepted-errors>"
# can be told to accept.
CLIENT_SPECS = {
    # issued by the server's own CA, clientAuth EKU: verifies cleanly
    'good': CertificateSpec(name="good-client", client=True),
    # X509_V_ERR_CERT_HAS_EXPIRED
    'expired': CertificateSpec(name="expired-client", client=True,
                               valid_from=timedelta(days=-30),
                               valid_to=timedelta(days=-1)),
    # X509_V_ERR_CERT_NOT_YET_VALID
    'future': CertificateSpec(name="future-client", client=True,
                              valid_from=timedelta(days=1),
                              valid_to=timedelta(days=30)),
    # serverAuth EKU only -> X509_V_ERR_INVALID_PURPOSE
    'noeku': CertificateSpec(domains=["noteclient.example.org"]),
}


def client_creds(env, kind):
    """(cert_file, pkey_file) for one of the CLIENT_SPECS, or for the two
    kinds that need their own issuer."""
    store = os.path.join(env.gen_dir, "verify-clients")
    os.makedirs(store, exist_ok=True)
    if kind in ('untrusted', 'untrustedchain'):
        ca = HttpdTestCA.create_root(name="untrusted-ca",
                                     store_dir=os.path.join(store, "untrusted"))
        creds = ca.issue_cert(CertificateSpec(name="untrusted-client", client=True))
        if kind == 'untrustedchain':
            # Sending the issuer too turns "unable to verify the first
            # certificate" (21) into "unable to get local issuer
            # certificate" (20) -- different errors, different tokens.
            cert_file = os.path.join(store, "untrustedchain.cert.pem")
            pkey_file = os.path.join(store, "untrustedchain.pkey.pem")
            with open(cert_file, "wb") as fd:
                fd.write(creds.cert_pem)
                fd.write(ca.cert_pem)
            creds.save_pkey_pem(pkey_file)
            return cert_file, pkey_file
    elif kind == 'selfsigned':
        # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        creds = HttpdTestCA.create_root(name="selfsigned-client",
                                        store_dir=os.path.join(store, "selfsigned"))
    else:
        creds = env.ca.issue_cert(CLIENT_SPECS[kind])
    cert_file = os.path.join(store, f"{kind}.cert.pem")
    pkey_file = os.path.join(store, f"{kind}.pkey.pem")
    creds.save_cert_pem(cert_file)
    creds.save_pkey_pem(pkey_file)
    return cert_file, pkey_file


def ignore_verify_noise(env):
    env.httpd_error_log.add_ignored_lognos(["AH10373", "AH02261", "AH02275"])
    env.httpd_error_log.add_ignored_matches([
        r'.*certificate verify failed.*',
        r'.*Re-negotiation handshake failed.*',
        r'.*No acceptable peer certificate available.*',
        r'.*SSL Library Error.*',
        r'.*Certificate Verification:.*',
    ])


def install(env, verify_line):
    conf = HttpdConf(env, extras={
        f"test1.{env.http_tld}": f"""
        SSLCACertificateFile "{env.ca.cert_file}"
        {verify_line}
        SSLVerifyDepth 5
        """,
    })
    conf.add_vhost_test1()
    conf.install()


def get(env, kind=None):
    options = None
    if kind is not None:
        cert, key = client_creds(env, kind)
        options = ['--cert', cert, '--key', key]
    return env.curl_get(env.mkurl("https", "test1", "/index.html"),
                        options=options)


def accepted(r):
    return r.exit_code == 0 and r.response and r.response["status"] == 200


class TestVerifyClientBaseline:
    """No accepted-errors: the existing levels behave as before."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        ignore_verify_noise(env)
        install(env, "SSLVerifyClient require")
        assert env.apache_restart() == 0

    def test_ssl_002_01(self, env):
        assert accepted(get(env, 'good'))

    @pytest.mark.parametrize("kind", ['untrusted', 'untrustedchain',
                                      'selfsigned', 'expired',
                                      'future', 'noeku'])
    def test_ssl_002_02(self, env, kind):
        assert not accepted(get(env, kind)), \
            f"'{kind}' client cert accepted under plain 'require'"


class TestVerifyClientOptionalNoCA:
    """optional_no_ca keeps its documented meaning."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        ignore_verify_noise(env)
        install(env, "SSLVerifyClient optional_no_ca")
        assert env.apache_restart() == 0

    # the errors optional_no_ca has always waived
    @pytest.mark.parametrize("kind", ['untrusted', 'untrustedchain',
                                      'selfsigned', 'expired'])
    def test_ssl_002_03(self, env, kind):
        assert accepted(get(env, kind)), \
            f"'{kind}' rejected under optional_no_ca"

    # ...and no client certificate at all is still fine
    def test_ssl_002_04(self, env):
        assert accepted(get(env))

    # optional_no_ca never waived these, and must not start now
    @pytest.mark.parametrize("kind", ['future', 'noeku'])
    def test_ssl_002_05(self, env, kind):
        assert not accepted(get(env, kind)), \
            f"'{kind}' accepted under optional_no_ca"


# Each accepted-errors token, the client cert kind it is meant to waive, and
# the kinds it must NOT waive.
ACCEPT_CASES = [
    ('self-signed', 'selfsigned', ['expired', 'future', 'noeku']),
    ('expired-cert', 'expired', ['selfsigned', 'future', 'noeku']),
    ('purpose-mismatch', 'noeku', ['selfsigned', 'expired', 'future']),
    ('X509_V_ERR_INVALID_PURPOSE', 'noeku', ['selfsigned', 'expired']),
    ('X509_V_ERR_CERT_NOT_YET_VALID', 'future', ['selfsigned', 'expired']),
    ('X509_V_ERR_CERT_HAS_EXPIRED', 'expired', ['selfsigned', 'future']),
]


@pytest.mark.parametrize("token,waived,rejected", ACCEPT_CASES,
                         ids=[c[0] for c in ACCEPT_CASES])
class TestVerifyClientAcceptedErrors:
    """SSLVerifyClient require <accepted-errors> waives exactly the named
    error and nothing else."""

    def test_ssl_002_06(self, env, token, waived, rejected):
        ignore_verify_noise(env)
        install(env, f"SSLVerifyClient require {token}")
        assert env.apache_restart() == 0
        assert accepted(get(env, waived)), \
            f"'{waived}' rejected under 'require {token}'"

    def test_ssl_002_07(self, env, token, waived, rejected):
        ignore_verify_noise(env)
        install(env, f"SSLVerifyClient require {token}")
        assert env.apache_restart() == 0
        for kind in rejected:
            assert not accepted(get(env, kind)), \
                f"'{kind}' accepted under 'require {token}'"
        # a cert with no problem at all still verifies
        assert accepted(get(env, 'good'))


class TestVerifyClientAcceptedErrorsList:
    """A comma-separated list waives each of its members.

    A certificate issued by a CA the server does not know raises more than one
    error as the chain is walked -- the unknown issuer at depth 0 and the
    self-signed root above it -- and every one of them has to be waived before
    the handshake succeeds.  So no single token reproduces optional_no_ca; it
    takes the combination below.
    """

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        ignore_verify_noise(env)
        install(env, "SSLVerifyClient require "
                     "self-signed,untrusted-cert,invalid-signature,expired-cert")
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("kind", ['untrusted', 'untrustedchain',
                                      'selfsigned', 'expired', 'good'])
    def test_ssl_002_08(self, env, kind):
        assert accepted(get(env, kind)), f"'{kind}' rejected"

    # errors outside the list are still fatal
    @pytest.mark.parametrize("kind", ['future', 'noeku'])
    def test_ssl_002_09(self, env, kind):
        assert not accepted(get(env, kind)), f"'{kind}' accepted"


class TestVerifyClientAcceptedErrorsConfig:
    """Configuration errors are rejected at startup."""

    def test_ssl_002_10(self, env):
        install(env, "SSLVerifyClient require not-a-real-error")
        assert env.apache_fail() == 0

    def test_ssl_002_11(self, env):
        install(env, "SSLVerifyClient none untrusted-cert")
        assert env.apache_fail() == 0
