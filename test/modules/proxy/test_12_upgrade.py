from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest

from pyhttpd.conf import HttpdConf


class UpgradeBackend(BaseHTTPRequestHandler):
    def do_GET(self):
        value = self.headers.get('Upgrade', '')
        body = value.encode('ascii')
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope='module')
def backend():
    server = HTTPServer(('127.0.0.1', 0), UpgradeBackend)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port
    server.shutdown()
    thread.join()
    server.server_close()


@pytest.mark.parametrize('configured,offered,forwarded', [
    ('websocket', 'websocket', True),
    ('websocket', 'WebSocket', True),
    ('websocket', 'websocket-admin', False),
    ('websocket', 'websock', False),
    ('TLS/1.3', 'TLS/1.3', True),
    ('TLS/1.3', 'TLS/1.2', False),
    ('TLS/1.3', 'TLS/1.2,TLS/1.1,TLS/1.0', False),
    ('ws,TLS/1.3', 'TLS/1.3', True),
    ('ws,TLS/1.3', 'TLS/1.2', False),
])
def test_proxy_upgrade_match(env, backend, configured, offered, forwarded):
    conf = HttpdConf(env)
    conf.start_vhost(domains=[env.d_reverse], port=env.http_port)
    conf.add(f'ProxyPass / http://127.0.0.1:{backend}/ upgrade={configured}')
    conf.end_vhost()
    conf.install()
    assert env.apache_restart() == 0
    result = env.curl_get(f'http://{env.d_reverse}:{env.http_port}/', options=[
        '-H', 'Connection: Upgrade', '-H', f'Upgrade: {offered}',
    ])
    assert result.exit_code == 0
    assert result.response['status'] == 200
    assert result.response['body'] == (offered.encode() if forwarded else b'')
