from datetime import datetime, timedelta, timezone
import http.client
import os
import ssl
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
import pytest

from pyhttpd.conf import HttpdConf


CUSTOM_OID = "1.3.6.1.4.1.18060.12.0"
BUILTIN_OID = "2.5.29.17"
INVALID_OID = "not-a-valid-oid"
EXT_VALUE_DER = bytes.fromhex("0c064c656d6f6e73")  # UTF8String "Lemons"

ASAN_REQUESTS_PER_PATH = 1000
RELEASE_WARMUP_REQUESTS = 500
RELEASE_REQUESTS_PER_PATH = 50000
# Unpatched ssl_ext_list() leaks one dynamic ASN1_OBJECT (~50 bytes + malloc
# overhead, ~95 bytes/req in glibc) on every call when xs == NULL: 100,000
# requests across /ext-sslrequire and /ext-expr grow VmRSS by ~9,500 kB,
# while patched execution stays flat (< 512 kB allocator noise).
RELEASE_RSS_LIMIT_KB = 2048


def _built_with_asan(env):
    """Return True if httpd or mod_ssl.so is linked with AddressSanitizer."""
    candidates = [
        os.path.join(env.bin_dir, "httpd"),
        os.path.join(env.libexec_dir, "mod_ssl.so"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            with open(path, "rb") as fd:
                if b"__asan_init" in fd.read():
                    return True
    return False


def _children_rss_kb(ppid):
    """Sum VmRSS (kB) across direct child processes of httpd main pid."""
    total = 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="utf-8") as fd:
                stat_txt = fd.read()
            rparen = stat_txt.rfind(")")
            if rparen < 0:
                continue
            fields = stat_txt[rparen + 2:].split()
            if int(fields[1]) != ppid:
                continue
            with open(f"/proc/{entry}/status", encoding="utf-8") as fd:
                for line in fd:
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1])
                        break
        except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
            continue
    return total


def _issue_client_cert(ca, out_dir, name, custom_oid=None, ext_der=None):
    """Issue a client certificate signed by the test CA with an optional custom OID."""
    os.makedirs(out_dir, exist_ok=True)
    cert_path = os.path.join(out_dir, f"{name}.cert.pem")
    key_path = os.path.join(out_dir, f"{name}.pkey.pem")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apache Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    )
    if custom_oid is not None and ext_der is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier(custom_oid), ext_der),
            critical=False,
        )
    cert = builder.sign(ca.private_key, hashes.SHA256())
    with open(cert_path, "wb") as fd:
        fd.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fd:
        fd.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    return cert_path, key_path


def _send_keepalive_requests(env, host, path, count, expected_status,
                             cert_file=None, key_file=None):
    """Send count HTTP/1.1 requests over persistent HTTPS connection(s)."""
    ctx = ssl.create_default_context(cafile=env.ca.cert_file)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if cert_file is not None and key_file is not None:
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

    conn = http.client.HTTPSConnection("127.0.0.1", env.https_port,
                                       context=ctx, timeout=30)
    try:
        for _ in range(count):
            try:
                conn.request("GET", path, headers={
                    "Host": host,
                    "Connection": "keep-alive",
                })
                resp = conn.getresponse()
                resp.read()
            except (http.client.HTTPException, OSError):
                conn.close()
                conn = http.client.HTTPSConnection("127.0.0.1", env.https_port,
                                                   context=ctx, timeout=30)
                conn.request("GET", path, headers={
                    "Host": host,
                    "Connection": "keep-alive",
                })
                resp = conn.getresponse()
                resp.read()
            assert resp.status == expected_status, \
                f"{path}: expected HTTP {expected_status}, got {resp.status}"
    finally:
        conn.close()


class TestPeerExtListOidLeak:

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env, request):
        cert_dir = os.path.join(env.gen_dir, "peer_ext_list_certs")
        ok_cert, ok_key = _issue_client_cert(
            env.ca, cert_dir, "peer-ext-ok",
            custom_oid=CUSTOM_OID, ext_der=EXT_VALUE_DER,
        )
        plain_cert, plain_key = _issue_client_cert(
            env.ca, cert_dir, "peer-ext-plain",
        )
        request.cls.client_ok_cert = ok_cert
        request.cls.client_ok_key = ok_key
        request.cls.client_plain_cert = plain_cert
        request.cls.client_plain_key = plain_key

        index_file = os.path.join(env.server_docs_dir, "index.html")
        # Keep worker count pinned to 1 so Release VmRSS tracks one worker heap.
        mpm_pin = "StartServers 1\nServerLimit 1\nMaxRequestWorkers 4\n"
        if env.mpm_module in ("mpm_worker", "mpm_event"):
            mpm_pin += "ThreadsPerChild 4\nMinSpareThreads 1\nMaxSpareThreads 4\n"
        domain = f"test1.{env.http_tld}"
        conf = HttpdConf(env, extras={
            "base": f"""
            MaxKeepAliveRequests 0
            LogLevel ssl:debug
            {mpm_pin}
            """,
            domain: f"""
            SSLCACertificateFile "{env.ca.cert_file}"
            SSLVerifyClient optional
            SSLVerifyDepth 2
            Alias /ext-sslrequire "{index_file}"
            Alias /ext-expr "{index_file}"
            Alias /ext-builtin "{index_file}"
            Alias /ext-invalid "{index_file}"
            <Location "/ext-sslrequire">
                SSLRequire "Lemons" in PeerExtList("{CUSTOM_OID}")
            </Location>
            <Location "/ext-expr">
                Require expr "'Lemons' in PeerExtList('{CUSTOM_OID}')"
            </Location>
            <Location "/ext-builtin">
                SSLRequire "Lemons" in PeerExtList("{BUILTIN_OID}")
            </Location>
            <Location "/ext-invalid">
                SSLRequire "Lemons" in PeerExtList("{INVALID_OID}")
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        env.httpd_error_log.add_ignored_lognos(["AH02229", "AH01630"])
        env.httpd_error_log.clear_log()
        assert env.apache_restart() == 0, env.apachectl_stderr
        yield
        env.httpd_error_log.remove_ignored_lognos(["AH02229", "AH01630"])

    def test_ssl_ext_list_valid_client_cert_control(self, env):
        """Positive control: valid custom-OID client cert passes; non-matching,
        built-in OID, and invalid OID preserve expected behavior."""
        host = f"test1.{env.http_tld}"
        # Valid client cert carrying CUSTOM_OID="Lemons" succeeds on both directives.
        _send_keepalive_requests(
            env, host, "/ext-sslrequire", 5, 200,
            cert_file=self.client_ok_cert, key_file=self.client_ok_key,
        )
        _send_keepalive_requests(
            env, host, "/ext-expr", 5, 200,
            cert_file=self.client_ok_cert, key_file=self.client_ok_key,
        )
        # Valid client cert without CUSTOM_OID is rejected cleanly.
        _send_keepalive_requests(
            env, host, "/ext-sslrequire", 3, 403,
            cert_file=self.client_plain_cert, key_file=self.client_plain_key,
        )
        _send_keepalive_requests(
            env, host, "/ext-expr", 3, 403,
            cert_file=self.client_plain_cert, key_file=self.client_plain_key,
        )
        # Missing client cert with built-in OID and invalid OID both return 403;
        # invalid OID still logs AH01970 at debug level.
        _send_keepalive_requests(env, host, "/ext-builtin", 5, 403)
        _send_keepalive_requests(env, host, "/ext-invalid", 2, 403)
        with open(env.httpd_error_log.path, "r", encoding="utf-8", errors="replace") as fd:
            err_txt = fd.read()
        assert "AH01970" in err_txt, "expected AH01970 debug log for invalid OID"

    def test_ssl_ext_list_missing_peer_cert_reject_no_leak(self, env):
        """Negative regression test: evaluating PeerExtList() with a custom OID
        when no peer certificate is presented must reject with 403 and must not
        leak the ASN1_OBJECT allocated by OBJ_txt2obj()."""
        host = f"test1.{env.http_tld}"
        if _built_with_asan(env):
            env.httpd_error_log.clear_log()
            assert env.apache_restart() == 0, env.apachectl_stderr
            _send_keepalive_requests(
                env, host, "/ext-sslrequire", ASAN_REQUESTS_PER_PATH, 403,
            )
            _send_keepalive_requests(
                env, host, "/ext-expr", ASAN_REQUESTS_PER_PATH, 403,
            )
            # Clean shutdown flushes LeakSanitizer output from worker child stderr.
            assert env.apache_stop() == 0, env.apachectl_stderr
            leak_text = ""
            with open(env.httpd_error_log.path, "r", encoding="utf-8", errors="replace") as fd:
                leak_text += fd.read()
            for fname in sorted(os.listdir(env.server_logs_dir)):
                if fname.startswith("asan.") or fname.startswith("lsan."):
                    fpath = os.path.join(env.server_logs_dir, fname)
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fd:
                        leak_text += "\n" + fd.read()
            assert env.apache_restart() == 0, env.apachectl_stderr
            lsan_idx = -1
            for marker in (
                "ERROR: LeakSanitizer:",
                "Direct leak of",
                "Indirect leak of",
                "SUMMARY: AddressSanitizer:",
            ):
                idx = leak_text.find(marker)
                if idx >= 0 and (lsan_idx < 0 or idx < lsan_idx):
                    lsan_idx = idx
            lsan_report = leak_text[lsan_idx:] if lsan_idx >= 0 else ""
            assert lsan_report == "", (
                f"LeakSanitizer detected memory leak in ssl_ext_list:\n{lsan_report}"
            )
        else:
            # Pure Release build: check worker VmRSS remains bounded on Linux /proc.
            _send_keepalive_requests(
                env, host, "/ext-sslrequire", RELEASE_WARMUP_REQUESTS, 403,
            )
            _send_keepalive_requests(
                env, host, "/ext-expr", RELEASE_WARMUP_REQUESTS, 403,
            )
            if sys.platform.startswith("linux"):
                ppid = env.read_pid_file()
                assert ppid is not None and ppid > 0, "expected active httpd main pid"
                before_kb = _children_rss_kb(ppid)
                assert before_kb > 0, "expected active httpd worker child"
                _send_keepalive_requests(
                    env, host, "/ext-sslrequire", RELEASE_REQUESTS_PER_PATH, 403,
                )
                _send_keepalive_requests(
                    env, host, "/ext-expr", RELEASE_REQUESTS_PER_PATH, 403,
                )
                after_kb = _children_rss_kb(ppid)
                delta_kb = after_kb - before_kb
                assert delta_kb < RELEASE_RSS_LIMIT_KB, (
                    f"worker VmRSS grew by {delta_kb} kB ({before_kb} -> {after_kb} kB) "
                    f"across {2 * RELEASE_REQUESTS_PER_PATH} PeerExtList() requests "
                    f"without peer cert (limit {RELEASE_RSS_LIMIT_KB} kB)"
                )
                # Built-in static OID control must also stay bounded.
                ctrl_before_kb = _children_rss_kb(ppid)
                _send_keepalive_requests(
                    env, host, "/ext-builtin", RELEASE_REQUESTS_PER_PATH, 403,
                )
                ctrl_after_kb = _children_rss_kb(ppid)
                ctrl_delta_kb = ctrl_after_kb - ctrl_before_kb
                assert ctrl_delta_kb < RELEASE_RSS_LIMIT_KB, (
                    f"built-in OID control VmRSS grew by {ctrl_delta_kb} kB"
                )
            else:
                _send_keepalive_requests(env, host, "/ext-sslrequire", 100, 403)
                _send_keepalive_requests(env, host, "/ext-expr", 100, 403)
