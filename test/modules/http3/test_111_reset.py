import pytest

from .env import H3Conf, data_bytes

H3_REQUEST_REJECTED = 0x10b
H3_REQUEST_CANCELLED = 0x10c


class TestRequestReset:
    """A request the client resets before its end is never processed
    (RFC 9114 4.1.2)."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    def _check_rejected(self, r):
        assert r.status is None, f"{r}"
        assert r.reset == H3_REQUEST_REJECTED, f"{r}"

    def test_h3_111_01_reset_upload(self, env):
        # without a content-length only the reset says the body is cut short
        r1, r2 = env.h3_client().requests([
            dict(method="POST", path="/cgi/raw-echo.py", body=data_bytes(10000),
                 reset=H3_REQUEST_CANCELLED),
            dict(path="/h3data-1k"),
        ], sequential=True)
        self._check_rejected(r1)
        assert r2.status == 200, f"{r2}"

    def test_h3_111_02_reset_upload_content_length(self, env):
        body = data_bytes(10000)
        r1, r2 = env.h3_client().requests([
            dict(method="POST", path="/cgi/raw-echo.py", body=body,
                 headers=[("content-length", str(2 * len(body)))],
                 reset=H3_REQUEST_CANCELLED),
            dict(path="/h3data-1k"),
        ], sequential=True)
        self._check_rejected(r1)
        assert r2.status == 200, f"{r2}"

    def test_h3_111_03_reset_after_headers(self, env):
        r1, r2 = env.h3_client().requests([
            dict(path="/h3data-1k", reset=H3_REQUEST_CANCELLED),
            dict(path="/h3data-1k"),
        ], sequential=True)
        self._check_rejected(r1)
        assert r2.status == 200, f"{r2}"

    def test_h3_111_04_reset_uploads_return_window(self, env):
        # more than the 1MB connection window in cancelled uploads
        body = data_bytes(200 * 1024)
        reqs = [dict(method="POST", path="/cgi/raw-echo.py", body=body,
                     reset=H3_REQUEST_CANCELLED)] * 8
        reqs.append(dict(method="POST", path="/cgi/raw-echo.py", body=body))
        rs = env.h3_client(timeout=30).requests(reqs, sequential=True)
        for r in rs[:-1]:
            self._check_rejected(r)
        assert rs[-1].status == 200, f"{rs[-1]}"
        assert rs[-1].body == body
