r"""Translated from t/modules/proxy_fcgi.t -- mod_proxy_fcgi.

For each scenario the Perl test launches a short-lived FastCGI responder that
echoes its FastCGI params back as ``KEY=VALUE`` lines, hits the proxied URI, and
checks the resulting envvars (SCRIPT_FILENAME / SCRIPT_NAME / PATH_INFO /
PATH_TRANSLATED / QUERY_STRING / REDIRECT_URL etc.) for ProxyFCGISetEnvIf,
GENERIC backend type, rewrite path-info, Action invocation, and UDS.

Here we implement a minimal single-request FastCGI responder in Python
(``_FcgiEcho``) that speaks just enough of the protocol (BEGIN_REQUEST, PARAMS,
STDIN, then STDOUT/END_REQUEST) to echo the params. The php-fpm subtests are
skipped (they require a php-fpm binary, like the Perl ``$have_php_fpm`` gate).

The FCGI backend port is read from the generated ``t/conf/proxy.conf``
(``Define FCGI_PORT N``) -- the framework does not expose @NextAvailablePort@
values via vars (a known API gap), so we read the resolved config value.

Perl original: plan tests => ..., need 'mod_proxy_fcgi', 'FCGI', 'IO::Select'.
"""

import os
import re
import socket
import struct
import sys
import threading

import pytest

from apache_pytest import need_module, t_cmp

# FastCGI record types
FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_VERSION = 1


def _read_record(sock):
    header = _recv_exact(sock, 8)
    if not header:
        return None
    version, type_, req_id, content_len, padding_len = struct.unpack(
        "!BBHHBx", header)
    content = _recv_exact(sock, content_len) if content_len else b""
    if padding_len:
        _recv_exact(sock, padding_len)
    return type_, req_id, content


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _write_record(sock, type_, req_id, content=b""):
    sock.sendall(struct.pack("!BBHHBx", FCGI_VERSION, type_, req_id,
                             len(content), 0) + content)


def _parse_name_value_pairs(data):
    params = {}
    i = 0
    while i < len(data):
        name_len, i = _read_len(data, i)
        value_len, i = _read_len(data, i)
        name = data[i:i + name_len].decode("latin-1")
        i += name_len
        value = data[i:i + value_len].decode("latin-1")
        i += value_len
        params[name] = value
    return params


def _read_len(data, i):
    b = data[i]
    if b >> 7 == 0:
        return b, i + 1
    length = struct.unpack("!I", data[i:i + 4])[0] & 0x7FFFFFFF
    return length, i + 4


class _FcgiEcho:
    """A one-shot FastCGI responder echoing its params as KEY=VALUE lines."""

    def __init__(self, address):
        self.address = address
        if isinstance(address, str):
            try:
                os.unlink(address)
            except OSError:
                pass
            self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(address)
        self.srv.listen(10)
        self.srv.settimeout(15)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.srv.accept()
        except OSError:
            return
        params = {}
        req_id = 1
        try:
            while True:
                rec = _read_record(conn)
                if rec is None:
                    break
                type_, rid, content = rec
                req_id = rid
                if type_ == FCGI_PARAMS:
                    if content == b"":
                        pass  # end of params stream
                    else:
                        params.update(_parse_name_value_pairs(content))
                elif type_ == FCGI_STDIN:
                    if content == b"":
                        break  # end of stdin => respond
            body = "Content-Type: text/plain\r\n\r\n"
            for key in sorted(params):
                body += f"{key}={params[key]}\n"
            _write_record(conn, FCGI_STDOUT, req_id, body.encode("latin-1"))
            _write_record(conn, FCGI_STDOUT, req_id, b"")
            _write_record(conn, FCGI_END_REQUEST, req_id,
                          struct.pack("!IBxxx", 0, 0))
            conn.close()
        except OSError:
            pass
        finally:
            self.srv.close()
            if isinstance(self.address, str):
                try:
                    os.unlink(self.address)
                except OSError:
                    pass

    def join(self):
        self.thread.join(timeout=5)


def _fcgi_port(http):
    """Read the resolved FCGI_PORT from the generated proxy.conf."""
    conf = os.path.join(http.vars("serverroot"), "conf", "proxy.conf")
    with open(conf) as f:
        for line in f:
            m = re.match(r"\s*Define\s+FCGI_PORT\s+(\d+)", line)
            if m:
                return int(m.group(1))
    return None


def _run_echo_request(http, address, uri):
    """Launch the echo daemon (if address given), GET uri, return (resp, envs)."""
    daemon = None
    if address is not None:
        daemon = _FcgiEcho(address)
        daemon.start()
    r = http.GET(uri)
    envs = {}
    for line in r.text.split("\n"):
        if not line:
            continue
        parts = line.split("=", 1)
        envs[parts[0]] = parts[1] if len(parts) > 1 else ""
    if daemon is not None:
        daemon.join()
    return r, envs


@pytest.mark.skipif(sys.platform == "win32",
                    reason="mod_proxy_fcgi misparses drive-letter paths as port")
@need_module("proxy_fcgi")
def test_fcgi_setenvif(http):
    if not http.have_min_apache_version("2.4.26"):
        pytest.skip("ProxyFCGISetEnvIf requires httpd >= 2.4.26")
    http.module("proxy_fcgi")
    port = _fcgi_port(http)
    assert port, "could not determine FCGI_PORT"
    r, envs = _run_echo_request(http, ("127.0.0.1", port), "/fcgisetenv?query")
    assert t_cmp(r.status_code, 200), "proxy to FCGI backend works"
    assert t_cmp(envs.get("QUERY_STRING"), "test_value"), \
        "ProxyFCGISetEnvIf can override an existing variable"
    assert t_cmp(envs.get("TEST_NOT_SET"), None), \
        "ProxyFCGISetEnvIf does not set variables if condition is false"
    assert t_cmp(envs.get("TEST_EMPTY"), ""), \
        "ProxyFCGISetEnvIf can set empty values"
    assert t_cmp(envs.get("TEST_DOCROOT"), http.vars("documentroot")), \
        "ProxyFCGISetEnvIf can replace with request variables"
    assert t_cmp(envs.get("TEST_CGI_VERSION"), "v1.1"), \
        "ProxyFCGISetEnvIf can replace with backreferences"
    assert t_cmp(envs.get("REMOTE_ADDR"), None), "ProxyFCGISetEnvIf can unset var"


@pytest.mark.skipif(sys.platform == "win32",
                    reason="mod_proxy_fcgi misparses drive-letter paths as port")
@need_module("proxy_fcgi")
def test_fcgi_generic(http):
    if not http.have_min_apache_version("2.4.26"):
        pytest.skip("GENERIC backend type requires httpd >= 2.4.26")
    http.module("proxy_fcgi")
    port = _fcgi_port(http)
    docroot = http.vars("documentroot")
    r, envs = _run_echo_request(
        http, ("127.0.0.1", port), "/modules/proxy/fcgi-generic/index.php?query")
    assert t_cmp(envs.get("SCRIPT_FILENAME"),
                 docroot + "/modules/proxy/fcgi-generic/index.php"), \
        "GENERIC SCRIPT_FILENAME has neither query string nor proxy: prefix"


@pytest.mark.skipif(sys.platform == "win32",
                    reason="mod_proxy_fcgi misparses drive-letter paths as port")
@need_module("proxy_fcgi")
def test_fcgi_generic_rewrite(http):
    if not (http.have_min_apache_version("2.4.26") and http.have_module("rewrite")):
        pytest.skip("requires httpd >= 2.4.26 and mod_rewrite")
    http.module("proxy_fcgi")
    port = _fcgi_port(http)
    docroot = http.vars("documentroot")
    r, envs = _run_echo_request(
        http, ("127.0.0.1", port),
        "/modules/proxy/fcgi-generic-rewrite/index.php?query")
    assert t_cmp(envs.get("SCRIPT_FILENAME"),
                 docroot + "/modules/proxy/fcgi-generic-rewrite/index.php"), \
        "GENERIC SCRIPT_FILENAME (rewrite) is correct"


@pytest.mark.skipif(sys.platform == "win32",
                    reason="mod_proxy_fcgi misparses drive-letter paths as port")
@need_module("proxy_fcgi")
def test_fcgi_rewrite_path_info(http):
    if not http.have_module("rewrite"):
        pytest.skip("no mod_rewrite")
    http.module("proxy_fcgi")
    port = _fcgi_port(http)
    docroot = http.vars("documentroot")
    r, envs = _run_echo_request(
        http, ("127.0.0.1", port),
        "/modules/proxy/fcgi-rewrite-path-info/path/info?query")
    assert t_cmp(envs.get("SCRIPT_FILENAME"),
                 f"proxy:fcgi://127.0.0.1:{port}" + docroot
                 + "/modules/proxy/fcgi-rewrite-path-info/index.php"), \
        "Default SCRIPT_FILENAME has proxy:fcgi prefix for compatibility"
    assert t_cmp(envs.get("SCRIPT_NAME"),
                 "/modules/proxy/fcgi-rewrite-path-info/index.php"), \
        "Default SCRIPT_NAME uses actual path to script"
    assert t_cmp(envs.get("PATH_INFO"), "/path/info"), "Default PATH_INFO is correct"
    assert t_cmp(envs.get("PATH_TRANSLATED"), docroot + "/path/info"), \
        "Default PATH_TRANSLATED is correct"
    assert t_cmp(envs.get("QUERY_STRING"), "query"), "Default QUERY_STRING is correct"
    assert t_cmp(envs.get("REDIRECT_URL"),
                 "/modules/proxy/fcgi-rewrite-path-info/path/info"), \
        "Default REDIRECT_URL uses original client URL"


@pytest.mark.skipif(sys.platform == "win32",
                    reason="mod_proxy_fcgi misparses drive-letter paths as port")
@need_module("proxy_fcgi")
def test_fcgi_action(http):
    if not http.have_module("actions"):
        pytest.skip("no mod_actions")
    http.module("proxy_fcgi")
    port = _fcgi_port(http)
    docroot = http.vars("documentroot")
    r, envs = _run_echo_request(
        http, ("127.0.0.1", port),
        "/modules/proxy/fcgi-action/index.php/path/info?query")
    assert t_cmp(envs.get("SCRIPT_FILENAME"),
                 f"proxy:fcgi://127.0.0.1:{port}" + docroot
                 + "/fcgi-action-virtual"), \
        "Action SCRIPT_FILENAME has proxy:fcgi prefix and virtual action Location"
    assert t_cmp(envs.get("SCRIPT_NAME"), "/fcgi-action-virtual"), \
        "Action SCRIPT_NAME is the virtual action Location"
    assert t_cmp(envs.get("PATH_INFO"),
                 "/modules/proxy/fcgi-action/index.php/path/info"), \
        "Action PATH_INFO contains full URI path"
    assert t_cmp(envs.get("PATH_TRANSLATED"),
                 docroot + "/modules/proxy/fcgi-action/index.php/path/info"), \
        "Action PATH_TRANSLATED contains full URI path"
    assert t_cmp(envs.get("QUERY_STRING"), "query"), "Action QUERY_STRING is correct"
    assert t_cmp(envs.get("REDIRECT_URL"),
                 "/modules/proxy/fcgi-action/index.php/path/info"), \
        "Action REDIRECT_URL uses original client URL"


@pytest.mark.skipif(sys.platform == "win32",
                    reason="mod_proxy_fcgi misparses drive-letter paths as port")
@need_module("proxy_fcgi")
def test_fcgi_default(http):
    http.module("proxy_fcgi")
    port = _fcgi_port(http)
    r, envs = _run_echo_request(
        http, ("127.0.0.1", port), "/modules/proxy/fcgi/index.php")
    assert t_cmp(envs.get("SCRIPT_NAME"), "/modules/proxy/fcgi/index.php"), \
        "Server sets correct SCRIPT_NAME by default"


@need_module("proxy_fcgi")
@pytest.mark.skipif(sys.platform == "win32", reason="AF_UNIX not available on Windows")
@pytest.mark.parametrize("url", [
    "/modules/proxy/fcgi-uds/index.php",
    "/modules/proxy/fcgi-uds-sethandler/index.php",
])
def test_fcgi_uds(http, url):
    http.module("proxy_fcgi")
    r, envs = _run_echo_request(
        http, "/tmp/apache-test-builtinfcgi.sock", url)
    assert t_cmp(envs.get("SCRIPT_NAME"), url), \
        "Server sets correct SCRIPT_NAME by default"


@need_module("proxy_fcgi")
@pytest.mark.parametrize("path,pathinfo", [
    ("/modules/proxy/fcgi-balancer/index.php", None),
    ("/modules/proxy/fcgi-balancer/index.php/my/pi", "/my/pi"),
])
def test_fcgi_balancer(http, path, pathinfo):
    if not http.have_min_apache_version("2.4.62"):
        pytest.skip("fcgi balancer tests require httpd >= 2.4.62")
    if not http.have_module("proxy_balancer"):
        pytest.skip("no proxy_balancer")
    http.module("proxy_fcgi")
    port = _fcgi_port(http)
    r, envs = _run_echo_request(http, ("127.0.0.1", port), path)
    assert t_cmp(envs.get("PATH_INFO"), pathinfo), \
        "Server sets correct PATH_INFO by default"
