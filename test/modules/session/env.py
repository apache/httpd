import inspect
import logging
import os

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class SessionTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(SessionTestSetup)))
        self.add_modules(["cgid", "session", "session_cookie"])


class SessionTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=SessionTestSetup(env=self))
