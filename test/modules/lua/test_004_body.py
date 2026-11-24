import hashlib
import os
import socket
import textwrap
import time

import pytest

from pyhttpd.conf import HttpdConf


BODY = bytes(range(256)) * 4


class TestBody:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("lua"), "mod_lua not built",
                    dep="mod_lua")
        conf = HttpdConf(env, extras={
            'base': textwrap.dedent(f"""
            <Directory "{env.server_docs_dir}/test1/lua">
                SetHandler lua-script
            </Directory>
            """),
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def post(self, env, mode, body=BODY):
        url = env.mkurl("http", "test1", f"/lua/body.lua?{mode}")
        fpath = os.path.join(env.gen_dir, "lua-body.bin")
        with open(fpath, "wb") as f:
            f.write(body)
        r = env.curl_raw([url], options=[
            "-H", "Content-Type: application/octet-stream",
            "--data-binary", f"@{fpath}"])
        assert r.response["status"] == 200, r.response
        return r.response["body"].decode().strip()

    def test_lua_004_01_read(self, env):
        length, digest, _ = self.post(env, "read").split()
        assert length == str(len(BODY))
        assert digest == hashlib.md5(BODY).hexdigest()

    @staticmethod
    def max_child_rss(env) -> int:
        """The largest VmRSS of the server's children, in kB."""
        ppid = env.read_pid_file()
        assert ppid, "no httpd.pid"
        largest = 0
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                with open(f"/proc/{pid}/status") as f:
                    status = dict(line.split(":", 1) for line in f)
            except OSError:
                continue
            if int(status.get("PPid", "0")) == ppid and "VmRSS" in status:
                largest = max(largest, int(status["VmRSS"].split()[0]))
        return largest

    # Memory for the body is not allocated from the Content-Length
    # before the body arrives.
    @pytest.mark.skipif(not os.path.exists("/proc/self/status"),
                        reason="needs /proc/self/status")
    def test_lua_004_02_declared_length(self, env):
        before = self.max_child_rss(env)
        sock = socket.create_connection((env.http_addr, env.http_port),
                                        timeout=30)
        try:
            sock.sendall((f"POST /lua/body.lua?read HTTP/1.1\r\n"
                          f"Host: test1.{env.http_tld}:{env.http_port}\r\n"
                          f"Content-Length: {256 * 1024 * 1024}\r\n"
                          f"\r\n").encode() + b"x" * 10)
            # The handler is now waiting in r:requestbody() for the rest.
            time.sleep(1)
            growth = self.max_child_rss(env) - before
        finally:
            sock.close()
        assert growth < 64 * 1024, \
            f"child RSS grew {growth}kB on 10 bytes of a declared 256MB body"

    # A body over the limit is refused with nil and a message.
    def test_lua_004_03_read_max(self, env):
        assert self.post(env, "readmax") == \
            "nil|Request body was larger than the permitted size."
        assert self.post(env, "readmax", b"x" * 50) == "50|50"

    def test_lua_004_04_file(self, env):
        assert self.post(env, "file") == \
            f"{len(BODY)}|nil|{hashlib.md5(BODY).hexdigest()}"

    def test_lua_004_05_file_max(self, env):
        assert self.post(env, "filemax") == \
            "nil|Request body was larger than the permitted size.|-"

    # A shorter body replaces a longer file entirely.
    def test_lua_004_06_file_overwrite(self, env):
        self.post(env, "file")
        assert self.post(env, "fileover", b"abc") == \
            f"3|nil|{hashlib.md5(b'abc').hexdigest()}"
