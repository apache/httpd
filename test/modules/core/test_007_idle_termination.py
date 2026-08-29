import os
import re
import socket
import time

import pytest

from pyhttpd.conf import HttpdConf


# The directive is implemented by these MPMs only; another one rejects it
# as an unknown command rather than ignoring it.
MPMS_WITH_IDLE_TERMINATION = ['mpm_prefork', 'mpm_worker', 'mpm_event']


class TestIdleTermination:
    """IdleTerminationTimeout: the server terminates itself once no worker
    has anything to do, so that a socket-activated instance gives its
    listening socket back to the service manager instead of sitting idle.

    Liveness here is checked by watching the process, never by making a
    request: a request is exactly what resets the timer under test.
    """

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        if env.mpm_module not in MPMS_WITH_IDLE_TERMINATION:
            pytest.skip(f"{env.mpm_module} has no IdleTerminationTimeout")
        yield
        conf = HttpdConf(env)
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def start(self, env, extra=''):
        """Install a configuration, start the server, and return its pid."""
        conf = HttpdConf(env, extras={'base': extra})
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        pid = env.read_pid_file()
        assert pid, "no pid file after start"
        return pid

    @staticmethod
    def is_running(pid):
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    @classmethod
    def wait_for_exit(cls, pid, timeout):
        end = time.time() + timeout
        while time.time() < end:
            if not cls.is_running(pid):
                return True
            time.sleep(0.2)
        return False

    def test_core_007_01_terminates_when_idle(self, env):
        pid = self.start(env, 'IdleTerminationTimeout 2')
        assert self.wait_for_exit(pid, 15), \
            "the server was still running well after its idle timeout"
        assert env.httpd_error_log.scan_recent(
            re.compile(r'.*idle timeout reached, shutting down.*'), timeout=5), \
            "no log message explaining the shutdown"

    def test_core_007_02_stays_up_by_default(self, env):
        """Without the directive the server never terminates itself."""
        pid = self.start(env)
        assert not self.wait_for_exit(pid, 6), \
            "the server terminated with no IdleTerminationTimeout configured"

    def test_core_007_03_requests_reset_the_timer(self, env):
        """A server which is being used does not time out."""
        pid = self.start(env, 'IdleTerminationTimeout 3')
        for _ in range(6):
            r = env.curl_get(env.mkurl("http", "test1", "/"))
            assert r.response['status'] == 200, "the server went away early"
            time.sleep(1)
        assert self.is_running(pid), \
            "the server terminated while it was still serving requests"
        # Left alone, it goes away.
        assert self.wait_for_exit(pid, 15)

    def test_core_007_04_zero_terminates_at_once(self, env):
        """A zero timeout means the first idle moment is enough."""
        pid = self.start(env, 'IdleTerminationTimeout 0')
        assert self.wait_for_exit(pid, 10)

    def test_core_007_05_open_connection_holds_it_up(self, env):
        """A client which is connected but quiet keeps the server alive.

        KeepAliveTimeout has to outlast the wait below, or the server
        closes the connection itself and is then genuinely idle.
        """
        pid = self.start(env, 'IdleTerminationTimeout 2\nKeepAliveTimeout 30')
        with socket.create_connection((env.http_addr, env.http_port), 5) as c:
            c.sendall(b'GET / HTTP/1.1\r\nHost: test1.' +
                      env.http_tld.encode() + b'\r\n\r\n')
            assert c.recv(64).startswith(b'HTTP/1.1 200')
            assert not self.wait_for_exit(pid, 8), \
                "the server terminated with a connection still open"

    def test_core_007_06_rejects_a_bad_value(self, env):
        conf = HttpdConf(env, extras={'base': 'IdleTerminationTimeout burble'})
        conf.add_vhost_test1()
        conf.install()
        rv = env.apache_restart()
        env.httpd_error_log.ignore_recent()
        assert rv != 0, "a non-numeric timeout was accepted"

    def test_core_007_07_forgotten_on_reload(self, env):
        """Removing the directive and reloading stops the behaviour.

        A graceful reload keeps the same process, which is the point: a
        fresh one would start from the compiled-in default whether or not
        the MPM forgets the old value.
        """
        pid = self.start(env, 'IdleTerminationTimeout 20')
        # Rewritten in place rather than through HttpdConf, which stops the
        # server before installing and so would lose the process.
        conf_file = os.path.join(env.server_conf_dir, 'test.conf')
        with open(conf_file) as fd:
            kept = [l for l in fd if 'IdleTerminationTimeout' not in l]
        with open(conf_file, 'w') as fd:
            fd.writelines(kept)
        assert env.apache_reload() == 0
        assert env.read_pid_file() == pid, "the reload replaced the process"
        assert not self.wait_for_exit(pid, 25), \
            "the server still timed out after the directive was removed"
