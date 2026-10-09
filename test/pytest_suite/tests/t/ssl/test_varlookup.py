r"""Translated from t/ssl/varlookup.t.

Exercises mod_test_ssl's /test_ssl_var_lookup handler, which echoes the value of
the mod_ssl variable named in the query string. The Perl original drives a big
__DATA__ table of ``VAR  expected`` pairs (only rows with an expected value are
actually tested) using the client_ok cert over https, comparing each looked-up
value against the expected string/regex.

Expected DN values are derived from apache_pytest/sslca.py (CA_DN / CERT_DN) in
RFC2253 one-line form (mod_ssl uses RFC2253 since httpd 2.3.11; OpenSSL >= 0.9.7
=> emailAddress attribute name). Version gating mirrors the original:
  _RAW         needs httpd >= 2.4.32
  _B64CERT     needs httpd >= 2.5.1
  _HANDSHAKE_RTT needs httpd >= 2.5.1 AND OpenSSL >= 3.2.0

Not reproducible here (skipped with reason):
  * HTTP_USER_AGENT / HTTP:User-Agent / HTTP_REFERER -- the Perl test asserts the
    LWP user-agent / script-name; the httpx client identifies differently.
  * SSL_CLIENT_SAN_OTHER_msUPN_0 / SSL_SERVER_SAN_OTHER_dnsSRV_0 -- these expect
    the cert to carry msUPN / dnsSRV otherName SANs, which the Python SSL CA
    generator (sslca.py) does not emit, so mod_ssl returns "NULL".
"""

import re

import pytest

from apache_pytest import need_module, need_ssl
from apache_pytest.testapi import t_cmp

EMAIL = "test-dev@httpd.apache.org"

# RFC2253 one-line DN (reverse field order); O is escaped only where it would
# contain special chars (client_ok's O=ASF needs none).
CLIENT_S_DN = (
    f"emailAddress={EMAIL},CN=client_ok,OU=httpd-test,O=ASF,"
    "L=San Francisco,ST=California,C=US"
)
CLIENT_I_DN = (
    f"emailAddress={EMAIL},CN=ca,OU=httpd-test,O=ASF,"
    "L=San Francisco,ST=California,C=US"
)
SERVER_I_DN = CLIENT_I_DN  # server cert is issued by the same CA

# client_ok subject attributes
CLIENT_S = {
    "C": "US", "ST": "California", "L": "San Francisco", "O": "ASF",
    "OU": "httpd-test", "CN": "client_ok", "Email": EMAIL,
}
CLIENT_I = {
    "C": "US", "ST": "California", "L": "San Francisco", "O": "ASF",
    "OU": "httpd-test", "CN": "ca", "Email": EMAIL,
}

CERT_DATEFMT = r"^\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \d{4} GMT$"

URL = "/test_ssl_var_lookup"


def _build(http):
    """Build the (key, expected) list mirroring the Perl __DATA__ table."""
    servername = http.servername
    port = str(http.vhost_port(http.vars("ssl_module_name") or "mod_ssl"))
    docroot = http.vars("documentroot")
    serveradmin = http.vars("serveradmin")
    remote_addr = http.vars("remote_addr") or "127.0.0.1"

    # server subject DN as a regex: OU is httpd-test/<key-type>, CN=servername.
    server_dn_re = (
        rf"^emailAddress={re.escape(EMAIL)},CN={re.escape(servername)},"
        rf"OU=httpd-test/[-\w]+,O=ASF,L=San Francisco,ST=California,C=US$"
    )

    table: list[tuple[str, object]] = [
        # standard CGI variables
        ("QUERY_STRING", "QUERY_STRING"),
        ("SERVER_SOFTWARE", re.compile(r"^Apache/")),
        ("SERVER_ADMIN", serveradmin),
        ("SERVER_PORT", port),
        ("SERVER_NAME", servername),
        ("SERVER_PROTOCOL", re.compile(r"^HTTP/1\.\d$")),
        ("REMOTE_ADDR", remote_addr),
        ("DOCUMENT_ROOT", docroot),
        ("REQUEST_METHOD", "GET"),
        ("REQUEST_URI", URL),
        # mod_ssl specific variables
        ("IS_SUBREQ", "false"),
        ("THE_REQUEST", re.compile(rf"^GET {re.escape(URL)}\?THE_REQUEST HTTP/1\.\d$")),
        ("REQUEST_SCHEME", "https"),
        ("HTTPS", "on"),
        ("ENV:THE_ARGS", "ENV:THE_ARGS"),
        ("SSL_CLIENT_M_VERSION", re.compile(r"^\d+$")),
        ("SSL_SERVER_M_VERSION", re.compile(r"^\d+$")),
        ("SSL_CLIENT_M_SERIAL", re.compile(r"^[0-9A-F]+$")),
        ("SSL_SERVER_M_SERIAL", re.compile(r"^[0-9A-F]+$")),
        ("SSL_PROTOCOL", re.compile(r"(TLS|SSL)v([1-3]|1\.[0-3])$")),
        ("SSL_CLIENT_V_START", re.compile(CERT_DATEFMT)),
        ("SSL_SERVER_V_START", re.compile(CERT_DATEFMT)),
        ("SSL_CLIENT_V_END", re.compile(CERT_DATEFMT)),
        ("SSL_SERVER_V_END", re.compile(CERT_DATEFMT)),
        ("SSL_CIPHER", re.compile(r"^[A-Z0-9_-]+$")),
        ("SSL_CIPHER_EXPORT", "false"),
        ("SSL_CIPHER_ALGKEYSIZE", re.compile(r"^\d+$")),
        ("SSL_CIPHER_USEKEYSIZE", re.compile(r"^\d+$")),
        ("SSL_SECURE_RENEG", re.compile(r"^(false|true)$")),
        # subject DNs
        ("SSL_CLIENT_S_DN", CLIENT_S_DN),
        ("SSL_SERVER_S_DN", re.compile(server_dn_re)),
        ("SSL_CLIENT_S_DN_C", CLIENT_S["C"]),
        ("SSL_SERVER_S_DN_C", "US"),
        ("SSL_CLIENT_S_DN_ST", CLIENT_S["ST"]),
        ("SSL_SERVER_S_DN_ST", "California"),
        ("SSL_CLIENT_S_DN_L", CLIENT_S["L"]),
        ("SSL_SERVER_S_DN_L", "San Francisco"),
        ("SSL_CLIENT_S_DN_O", CLIENT_S["O"]),
        ("SSL_SERVER_S_DN_O", "ASF"),
        ("SSL_CLIENT_S_DN_OU", CLIENT_S["OU"]),
        ("SSL_SERVER_S_DN_OU", re.compile(r"^httpd-test/[-\w]+")),
        ("SSL_CLIENT_S_DN_CN", CLIENT_S["CN"]),
        ("SSL_SERVER_S_DN_CN", servername),
        ("SSL_CLIENT_S_DN_Email", CLIENT_S["Email"]),
        ("SSL_SERVER_S_DN_Email", EMAIL),
        ("SSL_CLIENT_SAN_Email_0", EMAIL),
        ("SSL_SERVER_SAN_DNS_0", servername),
        # issuer DNs
        ("SSL_CLIENT_I_DN", CLIENT_I_DN),
        ("SSL_SERVER_I_DN", SERVER_I_DN),
        ("SSL_CLIENT_I_DN_C", CLIENT_I["C"]),
        ("SSL_SERVER_I_DN_C", "US"),
        ("SSL_CLIENT_I_DN_ST", CLIENT_I["ST"]),
        ("SSL_SERVER_I_DN_ST", "California"),
        ("SSL_CLIENT_I_DN_L", CLIENT_I["L"]),
        ("SSL_SERVER_I_DN_L", "San Francisco"),
        ("SSL_CLIENT_I_DN_O", CLIENT_I["O"]),
        ("SSL_SERVER_I_DN_O", "ASF"),
        ("SSL_CLIENT_I_DN_OU", CLIENT_I["OU"]),
        ("SSL_SERVER_I_DN_OU", "httpd-test"),
        ("SSL_CLIENT_I_DN_CN", CLIENT_I["CN"]),
        ("SSL_SERVER_I_DN_CN", "ca"),
        ("SSL_CLIENT_I_DN_Email", CLIENT_I["Email"]),
        ("SSL_SERVER_I_DN_Email", EMAIL),
        # signature / key algorithms
        ("SSL_CLIENT_A_SIG", "sha256WithRSAEncryption"),
        ("SSL_SERVER_A_SIG", "sha256WithRSAEncryption"),
        ("SSL_CLIENT_A_KEY", "rsaEncryption"),
        ("SSL_SERVER_A_KEY", re.compile(r"^[rd]saEncryption$")),
        # certs
        ("SSL_CLIENT_CERT", re.compile(r"^-----BEGIN CERTIFICATE-----")),
        ("SSL_SERVER_CERT", re.compile(r"^-----BEGIN CERTIFICATE-----")),
        ("SSL_CLIENT_VERIFY", "SUCCESS"),
    ]

    # _RAW vars need httpd >= 2.4.32
    if http.have_min_apache_version("2.4.32"):
        table += [
            ("SSL_SERVER_I_DN_CN_RAW", "ca"),
            ("SSL_SERVER_I_DN_CN_0_RAW", "ca"),
        ]
    # _B64CERT vars need httpd >= 2.5.1
    if http.have_min_apache_version("2.5.1"):
        table += [
            ("SSL_CLIENT_B64CERT", re.compile(r"^[a-zA-Z0-9+/]{64,}={0,2}$")),
            ("SSL_SERVER_B64CERT", re.compile(r"^[a-zA-Z0-9+/]{64,}={0,2}$")),
        ]
    return table


@need_ssl()
@need_module("test_ssl")
def test_var_lookup(http):
    http.scheme("https")
    if not http.have_min_apache_version("2.3.11"):
        pytest.skip("test assumes RFC2253 DN format (httpd >= 2.3.11)")

    for key, expected in _build(http):
        value = http.GET_BODY(f"{URL}?{key}", cert="client_ok").rstrip("\r\n")
        assert t_cmp(value, expected), f"{key}: expected {expected!r}, got {value!r}"
