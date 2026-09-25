import os
import select
import socket
import time

import pytest
from cryptography.hazmat.bindings.openssl.binding import Binding
from OpenSSL import SSL

from pyhttpd.certs import CertificateSpec
from pyhttpd.conf import HttpdConf

# mod_reqtimeout's "handshake" stage bounds how long a client may take over a
# TLS handshake.  A client certificate requested for a <Location> arrives in a
# second handshake - a renegotiation below TLSv1.3, Post-Handshake
# Authentication at TLSv1.3 - where a client can stall just as easily.
#
# The two timeouts are set far apart so that which one fired is never in
# doubt: the stage is much shorter than the core Timeout backstopping it.
HANDSHAKE_TIMEOUT = 2
CORE_TIMEOUT = 6
CAP = CORE_TIMEOUT + 6

VERSIONS = {"TLSv1.2": SSL.TLS1_2_VERSION, "TLSv1.3": SSL.TLS1_3_VERSION}

# What the virtual host asks for, which decides whether a certificate has
# already been collected by the time the <Location> asks for one.
VHOSTS = {"unset": "", "optional": "SSLVerifyClient optional"}

# pyOpenSSL exposes no post-handshake auth setting, so reach the one call
# needed through the same OpenSSL bindings pyhttpd already uses for its CA.
_LIB = Binding().lib

RRT = f"""RequestReadTimeout handshake={HANDSHAKE_TIMEOUT} header=8 body=8
            Timeout {CORE_TIMEOUT}"""


class TestReqTimeout:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1", "secure")
        os.makedirs(doc_dir, exist_ok=True)
        with open(os.path.join(doc_dir, "index.html"), "w") as f:
            f.write("secret\n")
        env.httpd_error_log.add_ignored_lognos(
            ["AH01991", "AH01992", "AH02261", "AH02262", "AH02263",
             "AH10158", "AH10373"])
        env.httpd_error_log.add_ignored_matches([
            r'.*SSL Library Error.*',
            r'.*certificate verify failed.*',
        ])

    def install(self, env, proto, vhost_verify=""):
        conf = HttpdConf(env, extras={
            "base": RRT,
            f"test1.{env.http_tld}": f"""
            SSLProtocol -all +{proto}
            SSLCACertificateFile "{env.ca.cert_file}"
            {vhost_verify}
            <Location "/secure">
                SSLVerifyClient require
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def connect(self, env):
        sock = socket.create_connection(("127.0.0.1", env.https_port),
                                        timeout=CAP)
        sock.settimeout(None)   # pyOpenSSL wants a blocking socket
        return sock

    def context(self, env, proto, creds=None):
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_min_proto_version(VERSIONS[proto])
        ctx.set_max_proto_version(VERSIONS[proto])
        ctx.set_verify(SSL.VERIFY_NONE)
        if creds:
            ctx.use_certificate_file(creds.cert_file)
            ctx.use_privatekey_file(creds.pkey_file)
        # offer RFC 8446 post_handshake_auth, or the server cannot ask for a
        # certificate at all on TLSv1.3 and there is nothing to stall over
        _LIB.SSL_CTX_set_post_handshake_auth(ctx._context, 1)
        return ctx

    def stalled_request(self, env, proto, vhost_verify=""):
        """Handshake, ask for a resource needing a client certificate, then
        stop reading - so the server's request for one is never answered."""
        self.install(env, proto, vhost_verify)
        creds = env.ca.issue_cert(
            CertificateSpec(name="reqtimeout-client", client=True))
        sock = self.connect(env)
        conn = SSL.Connection(self.context(env, proto, creds), sock)
        conn.set_tlsext_host_name(f"test1.{env.http_tld}".encode())
        conn.set_connect_state()
        conn.do_handshake()
        conn.sendall(f"GET /secure/index.html HTTP/1.1\r\n"
                     f"Host: test1.{env.http_tld}\r\n\r\n".encode())
        return conn, sock

    def close_delay(self, sock, cap=CAP):
        """Seconds until the server closes, read at the socket so that the
        TLS layer never answers anything and ends the stall by accident.

        Read with the socket rather than os.read(), which cannot take a
        socket handle on Windows and fails there at once."""
        start = time.monotonic()
        while time.monotonic() - start < cap:
            if not select.select([sock], [], [], 0.25)[0]:
                continue
            try:
                if sock.recv(65536) == b"":
                    return time.monotonic() - start
            except OSError:
                return time.monotonic() - start
        return None

    def sent_then_closed(self, sock, cap=CAP):
        """(bytes the server sent, whether it then closed the connection).

        Read at the socket, so nothing here can answer the server and end the
        stall by accident."""
        total = 0
        deadline = time.monotonic() + cap
        while time.monotonic() < deadline:
            if not select.select([sock], [], [], 0.25)[0]:
                continue
            try:
                data = sock.recv(65536)
            except OSError:
                return total, True
            if data == b"":
                return total, True
            total += len(data)
        return total, False

    def close_notify_then_eof(self, conn, sock, cap=CAP):
        """Drain at the TLS layer after a timeout has fired, reporting
        whether the server sent close_notify - which pyOpenSSL surfaces as
        ZeroReturnError - and whether the TCP connection then went away."""
        saw_close_notify = False
        ending = None
        deadline = time.monotonic() + cap
        while time.monotonic() < deadline:
            if not select.select([sock], [], [], 0.5)[0]:
                continue
            try:
                if conn.recv(16384) == b"":
                    ending = "eof"
                    break
            except SSL.ZeroReturnError:
                saw_close_notify = True
                break
            except Exception as exc:
                ending = f"{type(exc).__name__}: {exc}"
                break
        # the TLS shutdown should be followed by the connection closing
        tcp_closed = False
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not select.select([sock], [], [], 0.25)[0]:
                continue
            try:
                if sock.recv(65536) == b"":
                    tcp_closed = True
            except OSError:
                tcp_closed = True
            break
        return saw_close_notify, tcp_closed, ending

    # -- timing -----------------------------------------------------------

    # A client stalling in the first handshake is bounded by the stage.
    def test_ssl_004_01(self, env):
        self.install(env, "TLSv1.3")
        sock = self.connect(env)
        # Something must be sent or TCP_DEFER_ACCEPT leaves the connection
        # unaccepted, and the kernel rather than httpd decides when it ends.
        sock.sendall(bytes([0x16, 0x03, 0x01, 0x00, 0x50]))
        delay = self.close_delay(sock)
        sock.close()
        assert delay is not None, "connection was never closed"
        assert delay < HANDSHAKE_TIMEOUT + 2, \
            f"closed after {delay:.1f}s, expected the handshake stage " \
            f"({HANDSHAKE_TIMEOUT}s) not Timeout ({CORE_TIMEOUT}s)"

    # Stalling over a certificate requested for a <Location> is bounded by no
    # RequestReadTimeout stage at all, only by the core Timeout.
    @pytest.mark.xfail(strict=True, reason="no RequestReadTimeout stage "
                       "applies to a renegotiation or post-handshake auth")
    @pytest.mark.parametrize("vhost", list(VHOSTS), ids=list(VHOSTS))
    @pytest.mark.parametrize("proto", list(VERSIONS))
    def test_ssl_004_02(self, env, proto, vhost):
        conn, sock = self.stalled_request(env, proto, VHOSTS[vhost])
        delay = self.close_delay(sock)
        sock.close()
        assert delay is not None, "connection was never closed"
        assert delay < HANDSHAKE_TIMEOUT + 2, \
            f"closed after {delay:.1f}s, expected the handshake stage " \
            f"({HANDSHAKE_TIMEOUT}s) not Timeout ({CORE_TIMEOUT}s)"

    # -- what reaches the client -----------------------------------------

    # What matters on a timeout is that the connection is closed, so that a
    # client is not left waiting on a server which has already given up.
    # Whether anything precedes the close - an HTTP error, a TLS alert, or
    # nothing at all - is left to the server; the counts below are reported
    # only to make a change in that behaviour visible.
    def test_ssl_004_04(self, env):
        self.install(env, "TLSv1.3")
        sock = self.connect(env)
        sock.sendall(bytes([0x16, 0x03, 0x01, 0x00, 0x50]))
        sent, closed = self.sent_then_closed(sock)
        sock.close()
        assert closed, \
            f"connection still open after {CAP}s ({sent} bytes received)"

    @pytest.mark.parametrize("vhost", list(VHOSTS), ids=list(VHOSTS))
    @pytest.mark.parametrize("proto", list(VERSIONS))
    def test_ssl_004_05(self, env, proto, vhost):
        conn, sock = self.stalled_request(env, proto, VHOSTS[vhost])
        start = time.monotonic()
        sent, closed = self.sent_then_closed(sock)
        elapsed = time.monotonic() - start
        try:
            sock.close()
        except OSError:
            pass
        assert closed, \
            f"connection still open after {CAP}s ({sent} bytes received)"
        assert elapsed < CORE_TIMEOUT + 3, \
            f"closed after {elapsed:.1f}s, later than Timeout ({CORE_TIMEOUT}s)"

    # A timeout in the second handshake should be an orderly TLS shutdown:
    # close_notify, and then the connection goes away.  Without it a client
    # cannot distinguish the server giving up from the connection being cut.
    @pytest.mark.parametrize("vhost", list(VHOSTS), ids=list(VHOSTS))
    @pytest.mark.parametrize("proto", list(VERSIONS))
    def test_ssl_004_06(self, env, proto, vhost):
        conn, sock = self.stalled_request(env, proto, VHOSTS[vhost])
        time.sleep(CORE_TIMEOUT + 1)        # let the timeout fire
        notified, tcp_closed, ending = self.close_notify_then_eof(conn, sock)
        try:
            sock.close()
        except OSError:
            pass
        assert notified, \
            f"no close_notify from the server, stream ended with: {ending}"
        assert tcp_closed, "close_notify sent but the connection stayed open"
