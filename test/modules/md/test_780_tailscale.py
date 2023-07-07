import os
import re
import socket
import sys
from threading import Thread

import pytest

from .md_conf import MDConf


class TailscaleFaker:

    def __init__(self, env, path):
        self.env = env
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

    def send_error(self, c, status, reason):
        c.sendall(f"""HTTP/1.1 {status} {reason}\r
Server: TailscaleFaker\r
Content-Length: 0\r
Connection: close\r
\r
""".encode())

    def send_data(self, c, ctype: str, data: bytes):
        c.sendall(f"""HTTP/1.1 200 OK\r
Server: TailscaleFaker\r
Content-Type: {ctype}\r
Content-Length: {len(data)}\r
Connection: close\r
\r
""".encode() + data)

    def _process(self):
        # a http server written on a sunny afternooon
        while self._done is False:
            try:
                c, client_address = self._socket.accept()
                try:
                    data = c.recv(1024)
                    lines = data.decode().splitlines()
                    m = re.match(r'^(?P<method>\w+)\s+(?P<uri>\S+)\s+HTTP/1.1', lines[0])
                    if m is None:
                        self.send_error(c, 400, "Bad Request")
                        continue
                    uri = m.group('uri')
                    m = re.match(r'/localapi/v0/cert/(?P<domain>\S+)\?type=(?P<type>\w+)', uri)
                    if m is None:
                        self.send_error(c, 404, "Not Found")
                        continue
                    domain = m.group('domain')
                    cred_type = m.group('type')
                    creds = self.env.get_credentials_for_name(domain)
                    sys.stderr.write(f"lookup domain={domain}, type={cred_type} -> {creds}\n")
                    if creds is None or len(creds) == 0:
                        self.send_error(c, 404, "Not Found")
                        continue
                    if cred_type == 'crt':
                        self.send_data(c, "text/plain", creds[0].cert_pem)
                        pass
                    elif cred_type == 'key':
                        self.send_data(c, "text/plain", creds[0].pkey_pem)
                    else:
                        self.send_error(c, 404, "Not Found")
                        continue
                finally:
                    c.close()

            except ConnectionAbortedError:
                self._done = True


class TestTailscale:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        UDS_PATH = f"{env.gen_dir}/tailscale.sock"
        TestTailscale.UDS_PATH = UDS_PATH
        faker = TailscaleFaker(env=env, path=UDS_PATH)
        faker.start()
        env.APACHE_CONF_SRC = "data/test_auto"
        acme.start(config='default')
        env.clear_store()
        MDConf(env).install()
        assert env.apache_restart() == 0
        yield
        faker.stop()

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    def _write_res_file(self, doc_root, name, content):
        if not os.path.exists(doc_root):
            os.makedirs(doc_root)
        open(os.path.join(doc_root, name), "w").write(content)

    # create a MD using `tailscale` as protocol, wrong path
    def test_md_780_001(self, env):
        domain = env.tailscale_domain
        # generate config with one MD
        domains = [domain]
        socket_path = '/xxx'
        conf = MDConf(env, admin="admin@" + domain)
        conf.start_md(domains)
        conf.add([
            "MDCertificateProtocol tailscale",
            f"MDCertificateAuthority file://{socket_path}",
        ])
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        # restart and watch it fail due to wrong tailscale unix socket path
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['status-description'] == 'No such file or directory'
        assert md['renewal']['last']['detail'] == \
               f"tailscale socket not available, may not be up: {socket_path}"
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH10056"   # retrieving certificate from tailscale
            ]
        )

    # create a MD using `tailscale` as protocol, path to faker, should succeed
    def test_md_780_002(self, env):
        domain = env.tailscale_domain
        # generate config with one MD
        domains = [domain]
        socket_path = '/xxx'
        conf = MDConf(env, admin="admin@" + domain)
        conf.start_md(domains)
        conf.add([
            "MDCertificateProtocol tailscale",
            f"MDCertificateAuthority file://{self.UDS_PATH}",
        ])
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        # restart and watch it fail due to wrong tailscale unix socket path
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        assert env.apache_restart() == 0
        env.check_md_complete(domain)

    # create a MD using `tailscale` as protocol, but domain name not assigned by tailscale
    def test_md_780_003(self, env):
        domain = "test.not-correct.ts.net"
        # generate config with one MD
        domains = [domain]
        socket_path = '/xxx'
        conf = MDConf(env, admin="admin@" + domain)
        conf.start_md(domains)
        conf.add([
            "MDCertificateProtocol tailscale",
            f"MDCertificateAuthority file://{self.UDS_PATH}",
        ])
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        # restart and watch it fail due to wrong tailscale unix socket path
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['status-description'] == 'No such file or directory'
        assert md['renewal']['last']['detail'] == "retrieving certificate from tailscale"
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH10056"   # retrieving certificate from tailscale
            ]
        )
