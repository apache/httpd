import time

import pytest

from .env import MONITOR_STATUS, MONITOR_TIMEOUT, TransientService, http_responds

pytestmark = pytest.mark.skipif(
    not TransientService.is_available(),
    reason="no per-user systemd manager to run a transient service under")


class TestSystemdService:
    """httpd as a real systemd service, end to end.

    Everything else here checks what mod_systemd sends.  These check what
    systemd does with it: hold the unit in "activating" until httpd is
    ready, track the right process, and show the reported status text.
    """

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        assert env.apache_stop() == 0
        yield
        assert env.apache_stop() == 0

    @pytest.fixture
    def service(self, env) -> TransientService:
        svc = TransientService(env, port=env.http_port2)
        yield svc
        svc.stop()

    def test_systemd_005_01_type_notify(self, env, service):
        """systemd-run returns once the unit is active, which for a
        Type=notify service means READY=1 has been received, which
        mod_systemd sends only after the configuration is loaded."""
        r = service.start()
        assert r.returncode == 0, f"systemd-run failed: {r.stderr}"
        assert service.show('ActiveState') == 'active'
        assert http_responds(env.http_port2), \
            "the unit was active before the server would answer"

    def test_systemd_005_02_main_pid(self, env, service):
        """The process systemd tracks is the httpd parent."""
        assert service.start().returncode == 0
        assert service.wait_active()
        main_pid = int(service.show('MainPID'))
        assert main_pid > 0
        assert main_pid == service.read_pid()

    def test_systemd_005_03_status_text(self, env, service):
        """The status line "systemctl status" shows comes from the monitor
        hook, and is refreshed while the server runs."""
        assert service.start().returncode == 0
        assert service.wait_active()
        # First the post_config report, then the periodic one.
        assert service.show('StatusText') in ('Configuration loaded.',
                                              'Processing requests...')
        end = time.time() + MONITOR_TIMEOUT
        text = None
        while time.time() < end:
            text = service.show('StatusText')
            if MONITOR_STATUS.match(text):
                break
            time.sleep(0.5)
        assert MONITOR_STATUS.match(text), \
            f"status text was never refreshed by the monitor hook: {text!r}"

    def test_systemd_005_04_reload(self, env, service):
        """systemctl reload runs httpd -k graceful and the unit stays
        active throughout."""
        assert service.start().returncode == 0
        assert service.wait_active()
        pid = int(service.show('MainPID'))
        r = service.systemctl('reload', f'{service.unit}.service')
        assert r.returncode == 0, f"reload failed: {r.stderr}"
        assert service.show('ActiveState') == 'active'
        assert int(service.show('MainPID')) == pid
        assert http_responds(env.http_port2)

    def test_systemd_005_05_stop(self, env, service):
        """The unit stops cleanly, without systemd having to time out and
        kill it."""
        assert service.start().returncode == 0
        assert service.wait_active()
        r = service.systemctl('stop', f'{service.unit}.service')
        assert r.returncode == 0, f"stop failed: {r.stderr}"
        assert service.show('ActiveState') == 'inactive'
        assert service.show('Result') == 'success'
        assert not http_responds(env.http_port2)
