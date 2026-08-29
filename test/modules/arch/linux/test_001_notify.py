import time

import pytest

from pyhttpd.conf import HttpdConf


class TestSystemdNotify:
    """The service notifications mod_systemd sends over $NOTIFY_SOCKET
    across the server lifecycle."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env)
        conf.add_vhost_test1()
        conf.install()
        # Each test drives startup itself, so leave the server down.
        assert env.apache_stop() == 0

    @staticmethod
    def index_of(messages, match):
        for i, msg in enumerate(messages):
            if match(msg):
                return i
        return -1

    def test_systemd_001_01_startup(self, env):
        """Startup reports configuration reading, then readiness, then that
        the MPM is serving."""
        env.notify.clear()
        assert env.apache_restart() == 0
        assert env.notify.wait_for_status(r'^Reading configuration\.\.\.$'), \
            f"no reload notification, got {env.notify.statuses()}"
        assert env.notify.wait_for_status(r'^Configuration loaded\.$'), \
            f"no ready notification, got {env.notify.statuses()}"
        assert env.notify.wait_for_status(r'^Processing requests\.\.\.$'), \
            f"no pre_mpm notification, got {env.notify.statuses()}"

    def test_systemd_001_02_reloading_before_ready(self, env):
        """RELOADING=1 is sent while the configuration is read, and READY=1
        only once it has been."""
        env.notify.clear()
        assert env.apache_restart() == 0
        assert env.notify.wait_for_status(r'^Configuration loaded\.$')
        msgs = env.notify.messages
        reloading = self.index_of(
            msgs, lambda m: m.get('RELOADING') == '1'
            and m.get('STATUS') == 'Reading configuration...')
        ready = self.index_of(
            msgs, lambda m: m.get('READY') == '1'
            and m.get('STATUS') == 'Configuration loaded.')
        assert reloading >= 0 and ready >= 0
        assert reloading < ready, \
            "READY=1 was reported before the configuration was read"

    def test_systemd_001_03_mainpid(self, env):
        """MAINPID is the pid of the parent process, the one httpd records
        in its pid file."""
        env.notify.clear()
        assert env.apache_restart() == 0
        msg = env.notify.wait_for_key('MAINPID')
        assert msg, f"no MAINPID reported, got {env.notify.messages}"
        assert msg.get('READY') == '1'
        assert msg.get('STATUS') == 'Processing requests...'
        assert int(msg['MAINPID']) == env.read_pid_file()

    def test_systemd_001_04_reload(self, env):
        """A graceful restart reports reading the configuration and then
        being ready again."""
        assert env.apache_restart() == 0
        pid = env.read_pid_file()
        env.notify.clear()
        assert env.apache_reload() == 0
        assert env.notify.wait_for_status(r'^Reading configuration\.\.\.$'), \
            f"no reload notification, got {env.notify.statuses()}"
        assert env.notify.wait_for_status(r'^Configuration loaded\.$'), \
            f"no ready notification, got {env.notify.statuses()}"
        # The parent survives a graceful restart, and the MPM is not started
        # over, so the pid systemd tracks neither changes nor is re-reported.
        assert env.read_pid_file() == pid
        for msg in env.notify.messages:
            assert 'MAINPID' not in msg or int(msg['MAINPID']) == pid

    def test_systemd_001_05_hard_restart(self, env):
        """An ungraceful restart starts the MPM over, and re-reports the
        main pid, which is still that of the surviving parent."""
        assert env.apache_restart() == 0
        pid = env.read_pid_file()
        env.notify.clear()
        assert env.apache_hard_restart() == 0
        assert env.notify.wait_for_status(r'^Configuration loaded\.$'), \
            f"no ready notification, got {env.notify.statuses()}"
        msg = env.notify.wait_for_key('MAINPID')
        assert msg, f"no MAINPID after restart, got {env.notify.messages}"
        assert int(msg['MAINPID']) == pid
        assert env.read_pid_file() == pid

    def test_systemd_001_06_notify_socket_kept(self, env):
        """mod_systemd leaves NOTIFY_SOCKET in the environment, so a second
        start after a stop is reported just like the first."""
        assert env.apache_restart() == 0
        assert env.apache_stop() == 0
        env.notify.clear()
        assert env.apache_restart() == 0
        assert env.notify.wait_for_status(r'^Configuration loaded\.$')

    def test_systemd_001_07_stopping(self, env):
        """Shutdown is announced before the process goes away."""
        assert env.apache_restart() == 0
        env.notify.clear()
        assert env.apache_stop() == 0
        # The server is already gone, so anything it sent has arrived.
        msg = env.notify.wait_for_key('STOPPING', timeout=1)
        assert msg, f"no STOPPING=1 on shutdown, got {env.notify.messages}"
        assert msg['STOPPING'] == '1'
        assert msg.get('STATUS') == 'Shutting down.' 

    def test_systemd_001_08_reloading_monotonic(self, env):
        assert env.apache_restart() == 0
        env.notify.clear()
        assert env.apache_reload() == 0
        msg = env.notify.wait_for(lambda m: m.get('RELOADING') == '1')
        assert msg, "no RELOADING=1 on graceful restart"
        assert 'MONOTONIC_USEC' in msg, \
            f"RELOADING=1 sent without MONOTONIC_USEC: {msg}"
        # systemd compares this against its own reading of the same clock.
        assert 0 < int(msg['MONOTONIC_USEC']) <= time.clock_gettime_ns(
            time.CLOCK_MONOTONIC) // 1000

    @pytest.mark.xfail(reason="mod_systemd implements no watchdog keepalive, "
                              "so a unit using WatchdogSec= would be killed")
    def test_systemd_001_09_watchdog(self, env):
        assert env.apache_stop() == 0
        env.set_httpd_env('WATCHDOG_USEC', '2000000')  # ping every 1s
        try:
            env.notify.clear()
            assert env.apache_restart() == 0
            assert env.notify.wait_for_key('WATCHDOG', timeout=4), \
                "no watchdog keepalive was sent"
        finally:
            env.set_httpd_env('WATCHDOG_USEC', None)
            assert env.apache_restart() == 0
