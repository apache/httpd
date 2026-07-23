r"""Translated from t/modules/remoteip.t -- mod_remoteip PROXY protocol.

Opens a raw socket to the remote_ip vhost, prepends a PROXY-protocol header
(human-readable TCP4/TCP6 and binary forms, plus a malformed one) to a normal
HTTP/1.1 request, and verifies the response. A valid PROXY header yields a 200
with body "PROXY-OK"; a malformed one causes httpd to drop the connection, so no
parseable response comes back.

Perl original:
    Apache::TestRequest::module("remote_ip");
    plan tests => 12, need(need_module('remoteip'), need_min_apache_version('2.4.30'));
"""

import socket

import pytest

from apache_pytest import need_min_apache_version, need_module, t_cmp

URL = "GET /index.html HTTP/1.1\r\nConnection: close\r\nHost: dummy\r\n\r\n"


def _parse_response(data):
    """Return (status_code, body) from a raw HTTP/1.x response, or (None, "")."""
    if not data:
        return None, ""
    head, _, body = data.partition("\r\n\r\n")
    first = head.split("\r\n", 1)[0]
    parts = first.split(" ", 2)
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        try:
            return int(parts[1]), body
        except ValueError:
            return None, body
    return None, body


def _request(http, proxy):
    sock = http.vhost_socket("remote_ip")
    assert sock.connected
    sock.print(proxy + URL)
    sock._sock.shutdown(socket.SHUT_WR)
    data = sock.read()
    sock.close()
    return _parse_response(data)


@need_module("remoteip")
@need_min_apache_version("2.4.30")
def test_proxy_tcp4(http):
    http.module("remote_ip")
    proxy = "PROXY TCP4 192.168.192.66 192.168.192.77 1111 2222\r\n"
    code, body = _request(http, proxy)
    assert t_cmp(code, 200), "PROXY human readable TCP4 protocol check"
    assert t_cmp(body.rstrip("\n"), "PROXY-OK"), "Content check"


@need_module("remoteip")
@need_min_apache_version("2.4.30")
def test_proxy_bad_format(http):
    http.module("remote_ip")
    # A bad PROXY format makes httpd drop the connection -- expect no response.
    proxy = "PROXY FOO 192.168.192.66 192.168.192.77 1111 2222\r\n"
    code, body = _request(http, proxy)
    assert t_cmp(code, None), "broken PROXY human readable protocol check"
    assert t_cmp(body.rstrip("\n"), ""), "Content check"


@need_module("remoteip")
@need_min_apache_version("2.4.30")
def test_proxy_tcp6(http):
    http.module("remote_ip")
    proxy = ("PROXY TCP6 2001:DB8::21f:5bff:febf:ce22:8a2e "
             "2001:DB8::12f:8baa:eafc:ce29:6b2e 3333 4444\r\n")
    code, body = _request(http, proxy)
    assert t_cmp(code, 200), "PROXY human readable TCP6 protocol check"
    assert t_cmp(body.rstrip("\n"), "PROXY-OK"), "Content check"


@need_module("remoteip")
@need_min_apache_version("2.4.30")
def test_proxy_binary(http):
    http.module("remote_ip")
    proxy = (
        b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"  # header
        b"\x21"  # protocol version and command (AF_INET STREAM)
        b"\x11"  # transport protocol and address family (TCP over IPv4)
        b"\x00\x0C"  # 12 bytes coming up
        b"\xC0\xA8\xC0\x42\xC0\xA8\xC0\x4D\x01\xF0\x01\xF1"  # IPs and ports
    )
    sock = http.vhost_socket("remote_ip")
    assert sock.connected
    sock.print(proxy)
    sock.print(URL)
    sock._sock.shutdown(socket.SHUT_WR)
    data = sock.read()
    sock.close()
    code, body = _parse_response(data)
    assert t_cmp(code, 200), "PROXY binary protocol TCP4 check"
    assert t_cmp(body.rstrip("\n"), "PROXY-OK"), "Content check"
