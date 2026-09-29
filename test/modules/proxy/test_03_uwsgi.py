
"""
Tests for mod_proxy_uwsgi fix.

Per PEP 3333, WSGI applications must not generate hop-by-hop
headers. Remove any such headers received from the backend.
"""

import re

import pytest

from pyhttpd.conf import HttpdConf
from .uwsgi_faker import UwsgiFaker


UWSGI_PORT = 5200


@pytest.fixture(autouse=True, scope="class")
def _proxy_uwsgi_setup(env):
    faker = UwsgiFaker(port=UWSGI_PORT)
    faker.start()

    conf = HttpdConf(env)
    conf.start_vhost(
        domains=[env.d_reverse],
        port=env.http_port,
        with_ssl=False,
    )
    conf.add([
        "LogLevel proxy_uwsgi:debug",
        f"ProxyPass / uwsgi://127.0.0.1:{UWSGI_PORT}/",
    ])
    conf.end_vhost()
    conf.install()

    assert env.apache_restart() == 0

    yield

    faker.stop()


class TestProxyUwsgi:

    def test_proxy_03_001(self, env):
        """uWSGI backend response is forwarded correctly."""
        r = env.curl_get(
            f"http://{env.d_reverse}:{env.http_port}/",
            5,
        )
        assert r.response["status"] == 200
        assert r.json["host"] == "uwsgi-faker"

    def test_proxy_03_002(self, env):
        """No Transfer-Encoding header reaches the client."""
        r = env.curl_get(
            f"http://{env.d_reverse}:{env.http_port}/",
            5,
        )
        assert r.response["status"] == 200
        assert "transfer-encoding" not in r.response["header"]

    def test_proxy_03_003(self, env):
        """Transfer-Encoding is stripped by mod_proxy_uwsgi."""
        r = env.curl_get(
            f"http://{env.d_reverse}:{env.http_port}/?te=1",
            5,
        )

        print("response =", r.response)
        print("stderr   =", getattr(r, "stderr", None))
        print("stdout   =", getattr(r, "stdout", None))
        print("exitcode =", getattr(r, "exit_code", None))
        print("json     =", getattr(r, "json", None))

        assert r.response is not None
        assert r.response["status"] == 200
        assert "transfer-encoding" not in r.response["header"]

        assert r.json["host"] == "uwsgi-faker"

        assert env.httpd_error_log.scan_recent(
            re.compile(
                r".*uwsgi: removing hop-by-hop header 'Transfer-Encoding'"
            )
        )
"""
Tests for mod_proxy_uwsgi fix.

Per PEP 3333, WSGI applications must not generate hop-by-hop
headers. Remove any such headers received from the backend.
"""

import re

import pytest

from pyhttpd.conf import HttpdConf
from .uwsgi_faker import UwsgiFaker


UWSGI_PORT = 5200


@pytest.fixture(autouse=True, scope="class")
def _proxy_uwsgi_setup(env):
    faker = UwsgiFaker(port=UWSGI_PORT)
    faker.start()

    conf = HttpdConf(env)
    conf.start_vhost(
        domains=[env.d_reverse],
        port=env.http_port,
        with_ssl=False,
    )
    conf.add([
        "LogLevel proxy_uwsgi:debug",
        f"ProxyPass / uwsgi://127.0.0.1:{UWSGI_PORT}/",
    ])
    conf.end_vhost()
    conf.install()

    assert env.apache_restart() == 0

    yield

    faker.stop()


class TestProxyUwsgi:

    def test_proxy_03_001(self, env):
        """uWSGI backend response is forwarded correctly."""
        r = env.curl_get(
            f"http://{env.d_reverse}:{env.http_port}/",
            5,
        )
        assert r.response["status"] == 200
        assert r.json["host"] == "uwsgi-faker"

    def test_proxy_03_002(self, env):
        """No Transfer-Encoding header reaches the client."""
        r = env.curl_get(
            f"http://{env.d_reverse}:{env.http_port}/",
            5,
        )
        assert r.response["status"] == 200
        assert "transfer-encoding" not in r.response["header"]

    def test_proxy_03_003(self, env):
        """Transfer-Encoding is stripped by mod_proxy_uwsgi."""
        r = env.curl_get(
            f"http://{env.d_reverse}:{env.http_port}/?te=1",
            5,
        )

        print("response =", r.response)
        print("stderr   =", getattr(r, "stderr", None))
        print("stdout   =", getattr(r, "stdout", None))
        print("exitcode =", getattr(r, "exit_code", None))
        print("json     =", getattr(r, "json", None))

        assert r.response is not None
        assert r.response["status"] == 200
        assert "transfer-encoding" not in r.response["header"]

        assert r.json["host"] == "uwsgi-faker"

        assert env.httpd_error_log.scan_recent(
            re.compile(
                r".*uwsgi: removing hop-by-hop header 'Transfer-Encoding'"
            )
        )