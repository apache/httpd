import os
import re

import pytest

from pyhttpd.certs import CertificateSpec
from pyhttpd.conf import HttpdConf

# SSLVerifyClient in a <Location> asks for the certificate once the handshake
# has finished, and the two protocol families do that quite differently:
# ssl_hook_Access_classic() renegotiates for TLSv1.2 and below, while
# ssl_hook_Access_modern() uses TLSv1.3 Post-Handshake Authentication
# (RFC 8446), logging AH10129 as it starts and AH10158 when it cannot proceed.
#
# What the enclosing virtual host asks for matters as much as the protocol:
# with "SSLVerifyClient optional" the certificate is requested during the
# initial handshake, which changes what is left for the per-directory setting
# to do.
PHA_STARTED = "AH10129"
VHOSTS = {"unset": "", "optional": "SSLVerifyClient optional"}


class TestVerifyClientPerDir:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1", "secure")
        os.makedirs(doc_dir, exist_ok=True)
        with open(os.path.join(doc_dir, "index.html"), "w") as f:
            f.write("secret\n")
        env.httpd_error_log.add_ignored_lognos(
            ["AH02261", "AH02262", "AH02263", "AH10158", "AH10373",
             "AH02040"])
        env.httpd_error_log.add_ignored_matches([
            r'.*SSL Library Error.*',
            r'.*certificate verify failed.*',
        ])

    def install(self, env, proto, vhost_verify, vhost_depth=5, loc_depth=None,
                loc_verify="SSLVerifyClient require"):
        loc_lines = loc_verify
        if loc_depth is not None:
            loc_lines += f"\n                SSLVerifyDepth {loc_depth}"
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            LogLevel ssl:debug
            SSLProtocol -all +{proto}
            SSLCACertificateFile "{env.ca.cert_file}"
            SSLVerifyDepth {vhost_depth}
            {vhost_verify}
            <Location "/secure">
                {loc_lines}
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, proto, version, vhost_verify="",
            path="/secure/index.html", with_cert=True,
            vhost_depth=5, loc_depth=None,
            loc_verify="SSLVerifyClient require"):
        self.install(env, proto, vhost_verify, vhost_depth, loc_depth,
                     loc_verify)
        env.httpd_error_log.clear_log()
        # Pin the version at both ends: "--tlsvX" alone is a floor, not a pin.
        # Force HTTP/1.1 because per-directory verification is refused outright
        # on an HTTP/2 secondary connection, which would look like a protocol
        # failure while proving nothing about the TLS version.
        options = ["-v", "--http1.1", f"--tlsv{version}", "--tls-max", version]
        if with_cert:
            creds = env.ca.issue_cert(
                CertificateSpec(name="perdir-client", client=True))
            options.extend(["--cert", creds.cert_file,
                            "--key", creds.pkey_file])
        r = env.curl_get(env.mkurl("https", "test1", path), options=options)
        if r.exit_code == 0:
            got = re.search(r'SSL connection using (TLSv[0-9.]+)', r.stderr or "")
            assert got and got.group(1) == proto, \
                f"negotiated {got and got.group(1)}, wanted {proto}"
        return r

    def logged(self, env, logno):
        with open(env.httpd_error_log.path) as fd:
            return any(logno in line for line in fd)

    # TLSv1.2 reaches the per-directory setting by renegotiating, whatever the
    # virtual host asked for.
    @pytest.mark.parametrize("vhost", list(VHOSTS), ids=list(VHOSTS))
    def test_ssl_003_01(self, env, vhost):
        r = self.get(env, "TLSv1.2", "1.2", VHOSTS[vhost])
        assert r.exit_code == 0, f"handshake failed: {r.stderr}"
        assert r.response["status"] == 200

    # On TLSv1.3 it uses Post-Handshake Authentication, and a client which
    # offers the extension is served just the same.
    def test_ssl_003_02(self, env):
        r = self.get(env, "TLSv1.3", "1.3", VHOSTS["unset"])
        assert r.exit_code == 0, f"handshake failed: {r.stderr}"
        assert r.response["status"] == 200
        assert self.logged(env, PHA_STARTED), \
            f"{PHA_STARTED} absent: the certificate was not requested " \
            "post-handshake, so this is not exercising PHA"

    # Without a certificate the location is refused, so the cases above are
    # really being verified rather than served unconditionally.
    @pytest.mark.parametrize("vhost", list(VHOSTS), ids=list(VHOSTS))
    def test_ssl_003_03(self, env, vhost):
        r = self.get(env, "TLSv1.3", "1.3", VHOSTS[vhost], with_cert=False)
        assert not (r.exit_code == 0 and r.response
                    and r.response["status"] == 200), \
            "resource served without a client certificate"

    # The rest of the virtual host is unaffected.
    def test_ssl_003_04(self, env):
        r = self.get(env, "TLSv1.3", "1.3", VHOSTS["unset"], path="/index.html")
        assert r.exit_code == 0, f"handshake failed: {r.stderr}"
        assert r.response["status"] == 200

    # A virtual host asking for an optional certificate has already collected
    # one during the handshake, so tightening to "require" for a location has
    # nothing left to ask for.  This used to attempt Post-Handshake
    # Authentication anyway, which OpenSSL refuses once a certificate was
    # requested in the handshake - SSL_R_INVALID_CONFIG, reported as AH10158
    # and turned into 403, even for a client which offered the
    # post_handshake_auth extension and presented a valid certificate.
    def test_ssl_003_05(self, env):
        r = self.get(env, "TLSv1.3", "1.3", VHOSTS["optional"])
        assert r.exit_code == 0, f"handshake failed: {r.stderr}"
        assert r.response["status"] == 200

    # SSLVerifyDepth 0 accepts only a self-signed certificate, so the CA
    # issued one used here is refused - which establishes that the depth is
    # applied at all, before asking where it is applied from.
    @pytest.mark.parametrize("proto,version", [("TLSv1.2", "1.2"),
                                               ("TLSv1.3", "1.3")])
    def test_ssl_003_06(self, env, proto, version):
        r = self.get(env, proto, version, VHOSTS["unset"], vhost_depth=0)
        assert not (r.exit_code == 0 and r.response
                    and r.response["status"] == 200), \
            "certificate accepted at SSLVerifyDepth 0"

    # Reducing the depth for a <Location> below what the virtual host allows
    # should refuse the same certificate.  It does not, on either protocol:
    # the depth is only consulted inside "if (vmode_inplace != vmode_needed)",
    # and vmode_needed is the union of the server and directory settings, so a
    # virtual host which already asks for a certificate makes the two equal
    # and the reduction is never reached.  This is the case the FIXME in
    # ssl_hook_Access_modern() asks about, and it is not TLSv1.3 specific.
    @pytest.mark.xfail(strict=True, reason="per-directory SSLVerifyDepth "
                       "reduction below the virtual host's is not applied")
    @pytest.mark.parametrize("proto,version", [("TLSv1.2", "1.2"),
                                               ("TLSv1.3", "1.3")])
    def test_ssl_003_07(self, env, proto, version):
        r = self.get(env, proto, version, "SSLVerifyClient require",
                     vhost_depth=9, loc_depth=0, loc_verify="")
        assert not (r.exit_code == 0 and r.response
                    and r.response["status"] == 200), \
            "certificate accepted despite SSLVerifyDepth 0 in the location"
