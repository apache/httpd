import pytest

from .env import ActivatedServer


class TestSystemdSocketActivation:
    """Listening sockets passed in by the service manager.

    mod_systemd exports the two optional functions server/listen.c uses to
    find them, so socket activation is enabled by loading the module and
    disabled by not loading it, whatever the environment says.

    apachectl cannot pass file descriptors, so these tests open the
    listening socket themselves and run httpd directly, in the foreground,
    with the descriptor and the environment a service manager would give
    it.  No systemd process is involved.
    """

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # The activated servers use the same server root; keep the one
        # started by other tests out of the way.
        assert env.apache_stop() == 0
        yield
        assert env.apache_stop() == 0

    def test_systemd_004_01_activated_listener(self, env):
        """httpd serves on a socket it never opened itself."""
        env.notify.clear()
        with ActivatedServer(env, port=env.http_port2) as server:
            assert server.is_live(), \
                f"server did not come up: {server.stderr}"
            r = env.curl_get(f"http://{env.http_addr}:{env.http_port2}/")
            assert r.response['status'] == 200
        # The notification handshake works the same way as when httpd opens
        # its own sockets.
        assert env.notify.wait_for_status(r'^Configuration loaded\.$', timeout=0)
        msg = env.notify.wait_for_key('MAINPID', timeout=0)
        assert msg, f"httpd sent no MAINPID, got {env.notify.messages}"
        assert msg['STATUS'] == 'Processing requests...' 

    def test_systemd_004_02_no_socket_for_port(self, env):
        """A Listen port the service manager did not pass is an error, not
        a port httpd quietly opens for itself."""
        server = ActivatedServer(env, port=env.http_port2,
                                 listen_port=env.proxy_port,
                                 name='activate-wrongport')
        with server:
            assert server.wait_exit() != 0, "httpd started without a socket"
        assert b'not configured in systemd' in server.stderr, \
            f"unexpected startup diagnostic: {server.stderr}"

    def test_systemd_004_03_disabled_without_module(self, env):
        """Without mod_systemd the passed sockets are ignored and httpd
        opens the configured port itself, the same arrangement that fails
        in the test above."""
        if not env.systemd_is_dso:
            pytest.skip("mod_systemd is linked statically and cannot be "
                        "left out of the configuration")
        modules_conf = ActivatedServer.modules_conf_without(env, 'systemd')
        server = ActivatedServer(env, port=env.http_port2,
                                 listen_port=env.proxy_port,
                                 name='activate-nomodule',
                                 modules_conf=modules_conf)
        with server:
            assert server.is_live(), \
                f"server did not come up: {server.stderr}"
            r = env.curl_get(f"http://{env.http_addr}:{env.http_port2}/")
            assert r.response['status'] == 200

    @pytest.mark.xfail(reason="ap_setup_listeners() clears LISTEN_FDS from "
                              "the environment after startup, so re-reading "
                              "the configuration finds no sockets")
    def test_systemd_004_04_graceful_restart(self, env):
        """An activated server survives a graceful restart."""
        with ActivatedServer(env, port=env.http_port2,
                             name='activate-reload') as server:
            assert server.is_live(), \
                f"server did not come up: {server.stderr}"
            server.reload()
            env.httpd_error_log.ignore_recent(lognos=['AH02487'])
            # Check the parent first: when it dies here its children carry
            # on holding the listening socket and answering, so a request
            # succeeding proves nothing on its own.
            assert server.is_running(), \
                "the parent exited on graceful restart"
            assert server.is_live(timeout=5), \
                "the server did not survive a graceful restart"
            r = env.curl_get(f"http://{env.http_addr}:{env.http_port2}/")
            assert r.response['status'] == 200
