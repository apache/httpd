import os

from .env import H3Conf


class TestStreamLimit:

    def _setup(self, env):
        # the H3 certificate comes from mod_ssl, on the host with h3 in Protocols
        H3Conf(env).add_h3_vhost(with_certificate=False, directives=[
            "Protocols h3 http/1.1",
        ]).add("LogLevel http3:debug").install()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(env.https_port)

    @staticmethod
    def _log_path(env):
        return os.path.join(env.server_logs_dir, "error_log")

    # more requests than H3MaxConcurrentStreams (default 100) on one
    # connection, each with a PRIORITY_UPDATE: nghttp3 must accept the stream
    # IDs that MAX_STREAMS gave the client. Before, it rejected them with
    # H3_ID_ERROR and the server stopped reading the client control stream.
    def test_h3_015_01_priority_update_past_initial_limit(self, env):
        self._setup(env)
        start = os.path.getsize(self._log_path(env))
        client = env.h3_client()
        rs = client.requests([dict(path="/index.html", priority="u=2")
                              for _ in range(105)], sequential=True)
        for r in rs:
            assert r.terminated is None, f"{r}"
            assert r.status == 200, f"{r}"
        with open(self._log_path(env)) as f:
            f.seek(start)
            log = f.read()
        assert "nghttp3 error" not in log, log[-2000:]

    # an idle connection still gets its next request: the event loop skips
    # idle sessions, and a new packet must wake the session again
    def test_h3_015_02_request_after_idle(self, env):
        self._setup(env)
        client = env.h3_client()
        rs = client.requests([dict(path="/index.html"),
                              dict(path="/index.html", delay=1.5),
                              dict(path="/index.html", delay=0.2)],
                             sequential=True)
        for r in rs:
            assert r.terminated is None, f"{r}"
            assert r.status == 200, f"{r}"
