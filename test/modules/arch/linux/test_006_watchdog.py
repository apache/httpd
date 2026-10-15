import os
import re
import time

import pytest

from .env import (ForegroundServer, TransientService, MIN_WATCHDOG_SEC,
                  NO_MONITOR_TIMEOUT, WATCHDOG_TIMEOUT, is_watchdog_ping)


def watchdog_env(usec: int, pid: str = '$$') -> dict:
    """The environment a service manager sets for a watched service.

    $WATCHDOG_PID names the process expected to report; "$$" is the shell
    which exec's httpd, so it is the pid httpd will run as.
    """
    env = {'WATCHDOG_USEC': str(usec)}
    if pid is not None:
        env['WATCHDOG_PID'] = pid
    return env


class TestSystemdWatchdog:
    """The keep-alive ping of the systemd watchdog protocol.

    A service whose unit sets WatchdogSec= is started with $WATCHDOG_USEC
    holding that timeout in microseconds, and $WATCHDOG_PID holding the pid
    expected to report.  The service must then send "WATCHDOG=1" to the
    notification socket more often than the timeout, or systemd puts the
    unit into a failed state with Result=watchdog.  The timeout is armed
    once start-up completes and, as test_006_06 relies on, stays armed
    across a reload.

    Nothing here needs systemd: the ping goes to $NOTIFY_SOCKET like every
    other notification, so the same stand-in socket observes it.  Only the
    last test involves a service manager.
    """

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # These run their own servers on the second port; the shared one
        # would only add its notifications to the same socket.
        assert env.apache_stop() == 0
        yield
        assert env.apache_stop() == 0

    @pytest.fixture
    def server_factory(self, env):
        started = []

        def make(usec=None, pid='$$', extra='', name='watchdog'):
            setenv = watchdog_env(usec, pid) if usec is not None else {}
            srv = ForegroundServer(env, port=env.http_port2, name=name,
                                   extra=extra, setenv=setenv)
            started.append(srv)
            env.notify.clear()
            srv.start()
            assert srv.is_live(), \
                f"server did not come up: {srv.stderr!r}"
            return srv

        yield make
        for srv in started:
            srv.stop()

    def test_systemd_006_01_no_ping_when_unwatched(self, env, server_factory):
        """A server the service manager is not watching sends no keep-alive.

        The monitor hook still runs -- its status report is the evidence of
        that -- so the absence of a ping is a decision and not silence.
        """
        server_factory()
        assert env.notify.wait_for_status(r'^Total requests: ',
                                          timeout=WATCHDOG_TIMEOUT), \
            "the monitor hook never ran, so this proves nothing"
        assert not [m for m in env.notify.messages if is_watchdog_ping(m)], \
            "a keep-alive was sent with $WATCHDOG_USEC unset"

    def test_systemd_006_02_ping_when_watched(self, env, server_factory):
        """With the watchdog enabled the keep-alive is sent."""
        server_factory(usec=60 * 1000000)
        assert env.notify.wait_for(is_watchdog_ping,
                                   timeout=WATCHDOG_TIMEOUT), \
            f"no keep-alive within {WATCHDOG_TIMEOUT}s, " \
            f"got {env.notify.messages}"

    def test_systemd_006_03_ping_repeats(self, env, server_factory):
        """The keep-alive is periodic, which is the whole point of it: one
        ping would satisfy a test but not systemd."""
        server_factory(usec=60 * 1000000)
        for n in range(2):
            assert env.notify.wait_for(is_watchdog_ping,
                                       timeout=WATCHDOG_TIMEOUT), \
                f"only {n} keep-alives arrived, got {env.notify.messages}"
            env.notify.clear()

    def test_systemd_006_04_ping_without_extended_status(self, env,
                                                         server_factory):
        """The keep-alive does not depend on ExtendedStatus.

        The monitor hook declines early when it has no request counts to
        report (test_003_03), and a server whose status line is switched
        off must still be reported as alive.
        """
        server_factory(usec=60 * 1000000, extra='ExtendedStatus off')
        assert env.notify.wait_for_status(r'^Total requests: ',
                                          timeout=NO_MONITOR_TIMEOUT) is None, \
            "ExtendedStatus off did not stop the status report"
        assert env.notify.wait_for(is_watchdog_ping,
                                   timeout=WATCHDOG_TIMEOUT), \
            "no keep-alive with ExtendedStatus off"

    def test_systemd_006_05_no_ping_for_another_pid(self, env, server_factory):
        """$WATCHDOG_PID naming a different process means the variables were
        set for something further up the process tree, and must be ignored.
        """
        server_factory(usec=60 * 1000000, pid='1')
        assert env.notify.wait_for_status(r'^Total requests: ',
                                          timeout=WATCHDOG_TIMEOUT), \
            "the monitor hook never ran, so this proves nothing"
        assert not [m for m in env.notify.messages if is_watchdog_ping(m)], \
            "a keep-alive was sent although $WATCHDOG_PID was another process"

    def test_systemd_006_06_ping_across_reload(self, env, server_factory):
        """The keep-alive survives a graceful restart.

        The parent re-reads its configuration in the same process, but
        mod_systemd is unloaded and loaded again with it, so anything it
        remembered about the watchdog is gone by the time the monitor hook
        runs again.  systemd keeps the timeout armed throughout.
        """
        srv = server_factory(usec=60 * 1000000)
        assert env.notify.wait_for(is_watchdog_ping, timeout=WATCHDOG_TIMEOUT)
        env.notify.clear()
        assert srv.reload() == 0
        assert srv.is_live()
        assert env.notify.wait_for(is_watchdog_ping,
                                   timeout=WATCHDOG_TIMEOUT), \
            f"no keep-alive after a reload, got {env.notify.messages}"

    def test_systemd_006_07_ping_covers_the_reload_window(self, env,
                                                          server_factory):
        """A keep-alive is sent as the configuration is read, and again once
        it is loaded.

        Reading the configuration happens outside the parent's monitor loop,
        so nothing else reports during it.  The watchdog stays armed while
        the unit reloads, and a configuration which takes longer to parse
        than the timeout would otherwise be killed halfway through.
        """
        srv = server_factory(usec=60 * 1000000)
        assert env.notify.wait_for(is_watchdog_ping, timeout=WATCHDOG_TIMEOUT)
        env.notify.clear()
        assert srv.reload() == 0
        assert env.notify.wait_for(
            lambda m: 'RELOADING' in m and is_watchdog_ping(m),
            timeout=WATCHDOG_TIMEOUT), \
            f"no keep-alive as the configuration was read, " \
            f"got {env.notify.messages}"
        assert env.notify.wait_for(
            lambda m: m.get('READY') == '1' and is_watchdog_ping(m),
            timeout=WATCHDOG_TIMEOUT), \
            f"no keep-alive once the configuration was loaded, " \
            f"got {env.notify.messages}"

    def test_systemd_006_08_short_timeout_warned(self, env, server_factory):
        """A WatchdogSec the parent cannot meet is reported.

        The keep-alive is sent from the monitor hook, which runs once every
        ten turns of the parent's one second loop.  A timeout of a few
        seconds cannot be met however the module is written, and failing
        silently would leave the server being killed and restarted with
        nothing in the log to say why.
        """
        server_factory(usec=2 * 1000000)
        assert env.httpd_error_log.scan_recent(
            re.compile(r'.*AH10621: .*[Ww]atchdog.*'), timeout=10), \
            "no warning about a watchdog timeout that cannot be met"
        env.httpd_error_log.ignore_recent(lognos=['AH10621'])

    def test_systemd_006_09_workable_timeout_not_warned(self, env,
                                                        server_factory):
        """A timeout the parent can meet is not complained about."""
        server_factory(usec=MIN_WATCHDOG_SEC * 1000000)
        assert env.notify.wait_for(is_watchdog_ping, timeout=WATCHDOG_TIMEOUT)
        with pytest.raises(TimeoutError):
            env.httpd_error_log.scan_recent(
                re.compile(r'.*AH10621: .*'), timeout=1)

    @pytest.mark.skipif(not TransientService.is_available(),
                        reason="no per-user systemd manager")
    def test_systemd_006_10_service_keeps_watchdog_alive(self, env):
        """The real thing: systemd records each keep-alive it receives, and
        the unit stays active rather than failing with Result=watchdog."""
        with TransientService(env, port=env.http_port2,
                              properties=[f'WatchdogSec={MIN_WATCHDOG_SEC}s'],
                              name=f'httpd-wd-{os.getpid()}') as svc:
            assert svc.start().returncode == 0
            assert svc.wait_active()
            first = svc.show('WatchdogTimestampMonotonic')
            assert first and int(first) > 0, \
                "systemd recorded no keep-alive at all"
            end = time.time() + WATCHDOG_TIMEOUT
            while time.time() < end:
                if svc.show('WatchdogTimestampMonotonic') != first:
                    break
                time.sleep(0.5)
            assert svc.show('WatchdogTimestampMonotonic') != first, \
                "systemd received no further keep-alive"
            assert svc.show('ActiveState') == 'active'
            assert svc.show('Result') == 'success'
