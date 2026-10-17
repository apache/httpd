import socket
import struct

import pytest

from pyhttpd.conf import HttpdConf
from .env import TCPFaker

FCGI_VERSION_1 = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_MAX_RECORD = 65535


class _FCGIFaker(TCPFaker):
    # fastcgi backend. The query string of the request selects the headers
    # of the response:
    #   n=<len>      a header X-Big with a value of <len> characters
    #   count=<num>  <num> small headers X-Small-<i>

    @staticmethod
    def _recv_exact(c, size):
        data = b""
        while len(data) < size:
            chunk = c.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    @staticmethod
    def _parse_params(data):
        params = {}
        pos = 0
        while pos < len(data):
            lens = []
            for _ in range(2):
                if data[pos] >> 7:
                    lens.append(struct.unpack_from(">I", data, pos)[0] & 0x7fffffff)
                    pos += 4
                else:
                    lens.append(data[pos])
                    pos += 1
            name = data[pos:pos + lens[0]].decode("latin-1")
            pos += lens[0]
            params[name] = data[pos:pos + lens[1]].decode("latin-1")
            pos += lens[1]
        return params

    @staticmethod
    def _record(rtype, request_id, content):
        return struct.pack(">BBHHBx", FCGI_VERSION_1, rtype, request_id,
                           len(content), 0) + content

    def _read_request(self, c):
        # records up to the empty stdin, the end of the request
        request_id = 1
        params = b""
        while True:
            head = self._recv_exact(c, 8)
            if head is None:
                return None, None
            _, rtype, rid, clen, plen = struct.unpack(">BBHHBx", head)
            body = self._recv_exact(c, clen + plen) if clen + plen else b""
            if body is None:
                return None, None
            request_id = rid or request_id
            if rtype == FCGI_PARAMS:
                params += body[:clen]
            elif rtype == FCGI_STDIN and clen == 0:
                return request_id, self._parse_params(params)

    def _make_output(self, query):
        args = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        headers = [b"Status: 200 OK", b"Content-Type: text/plain"]
        if "n" in args:
            headers.append(b"X-Big: " + b"a" * int(args["n"]))
        for i in range(int(args.get("count", "0"))):
            headers.append(f"X-Small-{i}: value".encode())
        return b"\r\n".join(headers) + b"\r\n\r\nok"

    def _process(self):
        while not self._done:
            try:
                c, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                request_id, params = self._read_request(c)
                if request_id is None:
                    continue
                out = self._make_output(params.get("QUERY_STRING", ""))
                for pos in range(0, len(out), FCGI_MAX_RECORD):
                    c.sendall(self._record(FCGI_STDOUT, request_id,
                                           out[pos:pos + FCGI_MAX_RECORD]))
                c.sendall(self._record(FCGI_STDOUT, request_id, b""))
                c.sendall(self._record(FCGI_END_REQUEST, request_id,
                                       struct.pack(">IBxxx", 0, 0)))
            except OSError:
                pass
            finally:
                c.close()


def max_value(size):
    # A header line is read into a buffer of responsefieldsize bytes, which
    # is 8192 by default, and can be 3 bytes shorter than that.
    return size - 3 - len("X-Big: ")


class TestProxyFcgi:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("proxy_fcgi"), "mod_proxy_fcgi not available",
                    dep="mod_proxy_fcgi",
                    detected=f"no mod_proxy_fcgi.so in {env.libexec_dir}")
        faker = _FCGIFaker("127.0.0.1", env.http_port2)
        faker.start()
        backend = f"fcgi://127.0.0.1:{env.http_port2}"
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port)
        conf.add([
            f"ProxyPass /default/ {backend}/default/",
            f"ProxyPass /large/ {backend}/large/ responsefieldsize=32768",
            f"ProxyPass /small/ {backend}/small/ responsefieldsize=4096",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield faker
        faker.stop()

    def get(self, env, path, query):
        r = env.curl_get(env.mkurl("http", "test1", f"/{path}/?{query}"))
        if r.response["status"] == 500:
            # a header line which does not fit in the buffer
            env.httpd_error_log.ignore_recent(
                lognos=["AH01070", "AH01075"],
                matches=[".*Premature end of script headers"]
            )
        return r

    # small headers
    def test_proxy_007_01(self, env):
        r = self.get(env, "default", "n=100")
        assert r.response["status"] == 200
        assert r.response["header"]["x-big"] == "a" * 100
        assert r.response["body"] == b"ok"

    # a response header section larger than the buffer, of small lines
    def test_proxy_007_02(self, env):
        r = self.get(env, "default", "count=1000")
        assert r.response["status"] == 200
        assert r.response["header"]["x-small-999"] == "value"
        assert r.response["body"] == b"ok"

    # without responsefieldsize, a header line is limited to 8192 bytes
    @pytest.mark.parametrize("n, status", [
        [max_value(8192), 200],
        [max_value(8192) + 1, 500],
    ])
    def test_proxy_007_03(self, env, n, status):
        r = self.get(env, "default", f"n={n}")
        assert r.response["status"] == status

    # a larger responsefieldsize allows longer header lines, up to its size
    @pytest.mark.parametrize("n, status", [
        [20000, 200],
        [max_value(32768), 200],
        [max_value(32768) + 1, 500],
    ])
    def test_proxy_007_04(self, env, n, status):
        r = self.get(env, "large", f"n={n}")
        assert r.response["status"] == status
        if status == 200:
            assert r.response["header"]["x-big"] == "a" * n
            assert r.response["body"] == b"ok"

    # and a smaller one limits them
    @pytest.mark.parametrize("n, status", [
        [100, 200],
        [max_value(4096), 200],
        [max_value(4096) + 1, 500],
    ])
    def test_proxy_007_05(self, env, n, status):
        r = self.get(env, "small", f"n={n}")
        assert r.response["status"] == status
