import inspect
import logging
import os
import socket
from threading import Thread

from pyhttpd.certs import CertificateSpec

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class TCPFaker:
    # tcp backend for custom responses

    def __init__(self, host, port):
        self._thread = None
        self._socket = None
        self._host = host
        self._port = port
        self._done = False
        self._request = None

    def start(self):
        def process():
            self._socket.listen(1)
            self._socket.settimeout(0.5)
            self._process()

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self._host, self._port))
        self._thread = Thread(target=process, daemon=True)
        self._thread.start()

    def stop(self):
        self._done = True
        self._thread.join(timeout=5)
        self._socket.close()

    def _make_response(self, data):
        return """HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 5

Hello""".encode()

    def _process(self):
        while not self._done:
            try:
                c, client_address = self._socket.accept()
                try:
                    data = c.recv(4096)
                    # capture request to backend
                    self._request = data
                    c.sendall(self._make_response(data))
                finally:
                    c.close()
            except socket.timeout:
                pass
            except ConnectionAbortedError:
                self._done = True


class ProxyTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(ProxyTestSetup)))
        self.add_modules(["proxy", "proxy_http", "proxy_ajp", "proxy_balancer",
                          "proxy_connect", "proxy_uwsgi", "lbmethod_byrequests",
                          "remoteip"])


class ProxyTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_conf([
        ])
        self._d_reverse = f"reverse.{self.http_tld}"
        self._d_forward = f"forward.{self.http_tld}"
        self._d_mixed = f"mixed.{self.http_tld}"

        self.add_httpd_log_modules(
            ["proxy", "proxy_http", "proxy_balancer", "lbmethod_byrequests",
             "ssl"])
        self.add_cert_specs([
            CertificateSpec(domains=[
                self._d_forward, self._d_reverse, self._d_mixed
            ]),
            CertificateSpec(domains=[f"noh2.{self.http_tld}"],
                            key_type='rsa2048'),
        ])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=ProxyTestSetup(env=self))

    @property
    def d_forward(self):
        return self._d_forward

    @property
    def d_reverse(self):
        return self._d_reverse

    @property
    def d_mixed(self):
        return self._d_mixed
