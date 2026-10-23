import difflib
import email.parser
import inspect
import json
import os
import socket
import sys

import pytest

from .env import H1Conf


class TestPost:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TestPost._local_dir = os.path.dirname(inspect.getfile(TestPost))
        H1Conf(env).add_vhost_cgi().install()
        assert env.apache_restart() == 0

    def local_src(self, fname):
        return os.path.join(TestPost._local_dir, fname)

    # upload and GET again using curl, compare to original content
    def curl_upload_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/upload.py")
        fpath = os.path.join(env.gen_dir, fname)
        r = env.curl_upload(url, fpath, options=options)
        assert r.exit_code == 0, f"{r}"
        assert 200 <= r.response["status"] < 300

        r2 = env.curl_get(r.response["header"]["location"])
        assert r2.exit_code == 0
        assert r2.response["status"] == 200
        with open(self.local_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r2.response["body"]
        return r

    def test_h1_004_01(self, env):
        self.curl_upload_and_verify(env, "data-1k", ["-vvv"])

    def test_h1_004_02(self, env):
        self.curl_upload_and_verify(env, "data-10k", [])

    def test_h1_004_03(self, env):
        self.curl_upload_and_verify(env, "data-100k", [])

    def test_h1_004_04(self, env):
        self.curl_upload_and_verify(env, "data-1m", [])

    def test_h1_004_05(self, env):
        r = self.curl_upload_and_verify(env, "data-1k", ["-vvv", "-H", "Expect: 100-continue"])

    @pytest.mark.parametrize("size", [
        "8000000000000000",
        "ffffffffffffffff",
        "00000000000000008000000000000000",
    ])
    def test_h1_004_chunk_size_overflow(self, env, size):
        request = (f"POST / HTTP/1.1\r\nHost: localhost\r\n"
                   f"Transfer-Encoding: chunked\r\n\r\n{size}\r\n0\r\n\r\n").encode("ascii")
        with socket.create_connection(("localhost", int(env.http_port))) as sock:
            sock.settimeout(5)
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            response = bytearray()
            while b"\r\n" not in response and len(response) < 256:
                data = sock.recv(256 - len(response))
                if not data:
                    break
                response.extend(data)
            status_line = response.split(b"\r\n", 1)[0]
        assert status_line.startswith(b"HTTP/1.1 413 "), status_line

    def test_h1_004_chunk_size_positive_boundary(self, env):
        url = env.mkurl("http", "cgi", "/h1test/echo")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        off_t_bits = int(r.response["header"]["x-h1test-offt-bits"])

        # The old -4 digit budget rejects this positive value on either
        # 32-bit or 64-bit apr_off_t builds. Only send a small initial part
        # of the declared chunk; the echo handler responds as it reads it.
        size = f"{1 << (off_t_bits - 4):x}"
        request = (f"POST /h1test/echo HTTP/1.1\r\n"
                   f"Host: cgi.{env.http_tld}\r\n"
                   f"Transfer-Encoding: chunked\r\n"
                   f"Connection: close\r\n\r\n{size}\r\n").encode("ascii")
        with socket.create_connection(("localhost", int(env.http_port))) as sock:
            sock.settimeout(5)
            sock.sendall(request + b"A" * 32768)
            response = bytearray()
            while b"\r\n" not in response and len(response) < 256:
                data = sock.recv(256 - len(response))
                if not data:
                    break
                response.extend(data)
            status_line = response.split(b"\r\n", 1)[0]
        assert status_line.startswith(b"HTTP/1.1 200 "), status_line
