import pytest

from pyhttpd.conf import HttpdConf


class TestRestart:
    """The server goes on serving across a restart, graceful or not.

    Whatever the MPM does with its children, what has to hold afterwards
    is that a request is answered.  A restart which leaves the listening
    socket open with nothing behind it is the failure this catches, and
    it is not visible from the exit status of "httpd -k restart".
    """

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env)
        conf.add_vhost_test1()
        conf.install()
        # Restarting is rough on mod_cgid, which is loaded for this
        # package: the daemon is signalled along with the rest of the
        # process group (AH01239), and restarting again before it has
        # unlinked its socket leaves the new one unable to bind
        # (AH01243).  Neither is what these tests are about.
        env.httpd_error_log.add_ignored_lognos(['AH01239', 'AH01243'])
        assert env.apache_restart() == 0

    def get(self, env, when):
        # --max-time, or a server which accepts the connection and then
        # says nothing hangs here rather than failing.
        r = env.curl_get(env.mkurl("http", "test1", "/"),
                         options=['--max-time', '10'])
        assert r.exit_code == 0, f"no answer {when}: {r.stderr}"
        assert r.response['status'] == 200, f"bad status {when}"

    def test_core_008_01_graceful(self, env):
        self.get(env, "before the reload")
        assert env.apache_reload() == 0
        self.get(env, "after a graceful reload")

    def test_core_008_02_ungraceful(self, env):
        """"httpd -k restart" keeps the same parent and serves again."""
        self.get(env, "before the restart")
        pid = env.read_pid_file()
        assert pid, "no pid file"
        assert env.apache_hard_restart() == 0
        assert env.read_pid_file() == pid, "the restart replaced the parent"
        self.get(env, "after an ungraceful restart")

    def test_core_008_03_repeated(self, env):
        """Restarting twice in a row is no different from once."""
        for _ in range(2):
            assert env.apache_hard_restart() == 0
            self.get(env, "after repeated restarts")
