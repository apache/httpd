import os
import time

import pytest

from .env import (NOTIFY_RELOAD_VERSION, TransientService, error_log_since,
                  error_log_size, http_responds, systemd_version)

pytestmark = [
    pytest.mark.skipif(
        not TransientService.is_available(),
        reason="no per-user systemd manager to run a transient service under"),
    pytest.mark.skipif(
        systemd_version() < NOTIFY_RELOAD_VERSION,
        reason=f"Type=notify-reload needs systemd {NOTIFY_RELOAD_VERSION}"),
]


class TestNotifyReload:
    """httpd as a Type=notify-reload unit.

    Under Type=notify a reload is only whatever ExecReload= does, and
    systemctl returns as soon as that command exits.  For "httpd -k
    graceful" that is as soon as the signal has been sent, long before the
    new configuration is in use, and it reports success however the restart
    turns out.  Type=notify-reload holds the reload job open until the
    service sends RELOADING=1 and then READY=1, which mod_systemd sends
    from pre_config and post_config, so the result is reported once it is
    known.

    The unit here keeps ExecReload= and sets ReloadSignal=SIGCONT, which
    httpd ignores.  The manager runs ExecReload= first and sends
    ReloadSignal= only once it has exited successfully, so:

      - "httpd -k graceful" stays the thing which restarts the server, and
        because it parses the new configuration in its own process before
        signalling, a configuration which does not parse fails the reload
        without the running server being signalled at all.  A bare
        ReloadSignal= has the running parent read the new configuration and
        exit if it does not parse.

      - the signal the manager then sends is redundant, so it is pointed at
        one httpd does not act on.  The default is SIGHUP, which httpd
        takes as an *ungraceful* restart.
    """

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        assert env.apache_stop() == 0
        yield
        assert env.apache_stop() == 0

    @pytest.fixture
    def service(self, env) -> TransientService:
        svc = TransientService(env, port=env.http_port2,
                               name=f'httpd-reload-{os.getpid()}',
                               service_type='notify-reload',
                               properties=['ReloadSignal=SIGCONT'])
        yield svc
        svc.stop()

    def test_systemd_007_01_reload_waits_for_the_new_config(self, env, service):
        """systemctl reload returns only once the reloaded server is
        serving: the port added to the configuration answers without the
        test waiting for it, because READY=1 is sent from post_config, by
        which point the listeners are open."""
        assert service.start().returncode == 0
        assert service.wait_active()
        assert http_responds(env.http_port2)

        service.rewrite_conf(extra=f'Listen {env.proxy_port}')
        r = service.reload()
        assert r.returncode == 0, f"reload failed: {r.stderr}"
        assert http_responds(env.proxy_port, timeout=10.0), \
            "reload returned before the newly configured port was served"
        assert http_responds(env.http_port2)

    def test_systemd_007_02_broken_config_fails_the_reload(self, env, service):
        """A configuration which does not parse fails the reload and leaves
        the running server alone.  ExecReload= reads it in a process of its
        own and exits without signalling, and the manager sends no reload
        signal of its own once that has failed, so the parent never reads
        it."""
        assert service.start().returncode == 0
        assert service.wait_active()
        pid = int(service.show('MainPID'))

        service.rewrite_conf(extra='ThisDirectiveDoesNotExist on')
        r = service.reload()
        assert r.returncode != 0, \
            "reload of an unparseable configuration reported success"
        assert service.show('ActiveState') == 'active', \
            "a failed reload took the unit out of active"
        # The parent exits when a restart re-reads a configuration which
        # does not parse, and its children go on serving for a while
        # afterwards, so answering a request is not on its own proof that
        # the server survived: check the process the manager tracks.
        assert int(service.show('MainPID')) == pid, \
            "the parent was restarted despite the configuration not parsing"
        assert http_responds(env.http_port2)

    def test_systemd_007_03_reload_restarts_gracefully_once(self, env, service):
        """One reload is one graceful restart, and no ungraceful one.
        Leaving ReloadSignal= at its SIGHUP default is what this catches:
        httpd restarts ungracefully on SIGHUP, dropping the connections a
        reload is supposed to keep."""
        if env.mpm_module not in ('mpm_event', 'mpm_worker'):
            pytest.skip(f"{env.mpm_module} does not log the graceful restart")
        assert service.start().returncode == 0
        assert service.wait_active()

        pos = error_log_size(env)
        assert service.reload().returncode == 0
        # The restart is logged before the configuration is re-read, so it
        # is written by the time READY=1 ends the reload; give the
        # redundant signal which follows a moment to land as well.
        time.sleep(2)
        log = error_log_since(env, pos)
        assert log.count("Attempting to restart") == 0, \
            f"the reload restarted the server ungracefully:\n{log}"
        assert log.count("Doing graceful restart") == 1, \
            f"expected one graceful restart, log said:\n{log}"

    def test_systemd_007_04_reload_repeats(self, env, service):
        """Reloading twice works.  The manager ignores a RELOADING=1 which
        is not stamped later than the reload it asked for, so a server
        which got MONOTONIC_USEC wrong could report the first reload and
        then leave the second to time out."""
        assert service.start().returncode == 0
        assert service.wait_active()
        pid = int(service.show('MainPID'))

        for i in range(2):
            r = service.reload()
            assert r.returncode == 0, f"reload {i + 1} failed: {r.stderr}"
            assert service.show('ActiveState') == 'active'
            assert int(service.show('MainPID')) == pid, \
                "a graceful restart replaced the parent process"
        assert http_responds(env.http_port2)
