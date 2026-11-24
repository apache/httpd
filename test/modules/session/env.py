import inspect
import logging
import os
import sqlite3

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup
from pyhttpd.result import ExecResult

log = logging.getLogger(__name__)


class SessionTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(SessionTestSetup)))
        self.add_modules(["cgid", "session", "session_cookie",
                          "dbd", "session_dbd"])


class SessionTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self._dbd_file = os.path.join(self.server_dir, "session_dbd.sqlite3")

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=SessionTestSetup(env=self))
        self._write_dbd_file()

    def _write_dbd_file(self):
        if os.path.exists(self._dbd_file):
            os.remove(self._dbd_file)
        con = sqlite3.connect(self._dbd_file)
        try:
            con.execute("CREATE TABLE sessions (key TEXT, value TEXT, "
                        "expiry INTEGER)")
            con.commit()
        finally:
            con.close()

    @property
    def dbd_file(self) -> str:
        return self._dbd_file

    def dbd_driver_check(self, driver: str) -> ExecResult:
        """Run `httpd -t` on a config that only loads the modules and the
        DBD `driver`, which DBDriver does while reading the configuration.
        """
        conf_path = os.path.join(self.gen_dir, "session-dbd-check.conf")
        modules_conf = os.path.join(self.server_conf_dir, "modules.conf")
        with open(conf_path, 'w') as fd:
            fd.write('\n'.join([
                f'ServerRoot "{self.server_dir}"',
                f'Include "{modules_conf}"',
                f'Listen {self.http_port2}',
                f'DBDriver {driver}',
            ]) + '\n')
        httpd_bin = os.path.join(self.bin_dir, 'httpd')
        return self.run([httpd_bin, '-t', '-f', conf_path])
