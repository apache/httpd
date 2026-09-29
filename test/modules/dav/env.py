import inspect
import logging
import os

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class DavTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(DavTestSetup)))
        self.add_modules(["dav", "dav_fs", "alias"])


class DavTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["dav", "dav_fs"])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=DavTestSetup(env=self))
