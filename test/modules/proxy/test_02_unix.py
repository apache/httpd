import os
import re
import socket
from threading import Thread

import pytest

from pyhttpd.conf import HttpdConf
from pyhttpd.result import ExecResult


class UDSFaker:

    def __init__(self, path):
        self._uds_path = path
        self._done = False

    def start(self):
        def process(self):
            self._socket.listen(1)
            self._process()

        try:
            os.unlink(self._uds_path)
        except OSError:
            if os.path.exists(self._uds_path):
                raise
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(self._uds_path)
        self._thread = Thread(target=process, daemon=True, args=[self])
        self._thread.start()

    def stop(self):
        self._done = True
        self._socket.close()

    def _process(self):
        while self._done is False:
            try:
                c, client_address = self._socket.accept()
                try:
                    data = c.recv(16)
                    c.sendall("""HTTP/1.1 200 Ok
Server: UdsFaker
Content-Type: application/json
Content-Length: 19

{ "host": "faked" }""".encode())
                finally:
                    c.close()

            except ConnectionAbortedError:
                self._done = True


class TestProxyUds:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # setup 3 vhosts on https: for reverse, forward and
        # mixed proxying to a unix: domain socket
        # We setup a UDSFaker running that returns a fixed response
        UDS_PATH = f"{env.gen_dir}/proxy_02.sock"
        TestProxyUds.UDS_PATH = UDS_PATH
        faker = UDSFaker(path=UDS_PATH)
        faker.start()

        conf = HttpdConf(env)
        conf.add("ProxyPreserveHost on")
        conf.start_vhost(domains=[env.d_reverse], port=env.https_port)
        conf.add([
            f"ProxyPass / unix:{UDS_PATH}|http://127.0.0.1:{env.http_port}/"
        ])
        conf.end_vhost()

        conf.start_vhost(domains=[env.d_forward], port=env.https_port)
        conf.add([
            "ProxyRequests on"
        ])
        conf.end_vhost()

        conf.start_vhost(domains=[env.d_mixed], port=env.https_port)
        conf.add([
            f"ProxyPass / unix:{UDS_PATH}|http://127.0.0.1:{env.http_port}/",
            "ProxyRequests on"
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield
        faker.stop()

    @pytest.mark.parametrize(["via", "seen"], [
        ["reverse", "faked"],
        ["mixed", "faked"],
    ])
    def test_proxy_02_001(self, env, via, seen):
        # make requests to a reverse proxy https: vhost to the http: vhost
        # check that we see the document we expect there (host matching worked)
        r = env.curl_get(f"https://{via}.{env.http_tld}:{env.https_port}/alive.json", 5)
        assert r.response["status"] == 200
        assert r.json['host'] == seen

    @pytest.mark.parametrize(["via", "seen"], [
        ["forward", "generic"],
        ["mixed", "faked"],
    ])
    def test_proxy_02_002(self, env, via, seen):
        # make requests to a forward proxy https: vhost to the http: vhost
        # check that we see the document we expect there (host matching worked)
        # we need to explicitly provide a Host: header since mod_proxy cannot
        # resolve the name via DNS.
        if not env.curl_is_at_least('8.0.0'):
            pytest.skip(f'need at least curl v8.0.0 for this')
        domain = f"{via}.{env.http_tld}"
        r = env.curl_get(f"http://127.0.0.1:{env.http_port}/alive.json", 5, options=[
            '-H', f"Host: {domain}",
            '--proxy', f"https://{domain}:{env.https_port}/",
            '--resolve', f"{domain}:{env.https_port}:127.0.0.1",
            '--proxy-cacert', f"{env.get_ca_pem_file(domain)}",

        ])
        assert r.exit_code == 0, f"{r.stdout}{r.stderr}"
        assert r.response["status"] == 200
        assert r.json['host'] == seen

    @pytest.mark.parametrize(["via", "exp_status"], [
        ["reverse", 400],
        ["forward", 500],
        ["mixed", 500],
    ])
    def test_proxy_02_003(self, env, via, exp_status):
        # make requests to a forward proxy https: vhost and GET
        # a URL which carries the unix: domain socket.
        # This needs to fail.
        domain = f"{via}.{env.http_tld}"
        r = env.run(args=[
            'openssl', 's_client', '-connect', f"127.0.0.1:{env.https_port}",
            '-servername', domain,
            '-crlf', '-ign_eof',
            '-CAfile', env.get_ca_pem_file(domain)
        ], intext=f"""GET unix:{TestProxyUds.UDS_PATH}|http://127.0.0.1:{env.http_port}/alive.json HTTP/1.1
Host: {domain}

""")
        assert r.exit_code == 0, f"{r.stdout}{r.stderr}"
        lines = r.stdout.split('\n')
        rlines = None
        for idx, l in enumerate(lines):
            if l.startswith('HTTP/'):
                rlines = lines[idx:]
        assert rlines, f"No response found in: {r.stdout}"
        r2 = self.parse_response(rlines)
        assert r2.response
        assert r2.response['status'] == exp_status
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH01144"   #  No protocol handler was valid for the URL
            ]
        )

    def parse_response(self, lines) -> ExecResult:
        exp_body = False
        exp_stat = True
        r = ExecResult(args=[], exit_code=0, stdout=b'', stderr=b'')
        header = {}
        body = []
        for line in lines:
            if exp_stat:
                m = re.match(r'^(\S+) (\d+) (.*)$', line)
                assert m, f"first line no HTTP status line: {line}"
                r.add_response({
                    "protocol": m.group(1),
                    "status": int(m.group(2)),
                    "description": m.group(3),
                    "body": r.outraw
                })
                header = {}
                exp_stat = False
                exp_body = False
            elif re.match(r'^\r?$', line):
                exp_body = True
            elif exp_body:
                body.append(line)
            else:
                m = re.match(r'^([^:]+):\s*(.*)$', line)
                assert m, f"not a header line: {line}"
                header[m.group(1).lower()] = m.group(2)
        if r.response:
            r.response["header"] = header
            r.response["body"] = body
        return r
