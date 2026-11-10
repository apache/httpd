import inspect
import logging
import os
import sqlite3

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class SessionTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(SessionTestSetup)))
        self.add_modules(["dbd", "session", "session_dbd"])


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
