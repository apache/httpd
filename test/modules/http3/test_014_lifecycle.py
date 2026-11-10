import re

from .env import H3Conf, known_bug


class TestLifecycle:

    def test_h3_014_01_graceful_restart(self, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(env.https_port)
        for _ in range(3):
            assert env.apache_reload() == 0
            assert env.wait_udp_port(env.https_port)
            assert env.alt_svc() is not None

    def test_h3_014_02_graceful_stop(self, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(env.https_port)
        assert env.apache_graceful_stop() == 0
        assert env.wait_udp_port(env.https_port, in_use=False)

    def test_h3_014_03_owner_exits(self, env):
        H3Conf(env).add_h3_vhost().add("MaxConnectionsPerChild 2").install()
        log = env.httpd_error_log
        start = log.current_pos()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(env.https_port)
        for _ in range(40):
            r = env.curl_get(f"http://{env.http_tld}:{env.http_port}/")
            assert r.exit_code == 0, f"{r}"
        assert env.wait_udp_port(env.https_port)
        assert env.alt_svc() is not None
        # logged by each child that gets the port, at LogLevel http3:info
        listening = re.compile(r'.*mod_http3 loaded with version: .* on pid=(\d+)')
        with open(log.path) as fd:
            fd.seek(start)
            pids = {m.group(1) for m in map(listening.match, fd) if m}
        assert len(pids) >= 2, f"the port never changed hands: {pids}"

    def test_h3_014_04_stop_cleanly(self, env):
        H3Conf(env).add_h3_vhost().install()
        log = env.httpd_error_log
        start = log.current_pos()
        for _ in range(20):
            assert env.apache_restart() == 0
            assert env.wait_udp_port(env.https_port)
            assert env.apache_stop() == 0
        # crashed, or still there when the parent gave up waiting
        unclean = [log.RE_ERRLOG_CRASH.pattern, r'.*AH0004[56]: child process']
        asan = [log.RE_ERRLOG_ASAN.pattern]
        with open(log.path) as fd:
            fd.seek(start)
            content = fd.readlines()
        lines = [l for l in content if any(re.match(p, l) for p in unclean)]
        asan_lines = [l for l in content if any(re.match(p, l) for p in asan)]
        log.ignore_recent(matches=unclean + asan)
        known_bug(bool(lines) and env.mpm_module == "mpm_prefork",
                  "prefork children crash or fail to exit on stop")
        known_bug(bool(asan_lines),
                  "control-stream SSL* wrappers leak at child exit")
        assert not lines and not asan_lines, "".join(lines + asan_lines)
