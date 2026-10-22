import inspect
import logging
import os

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class CacheTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(CacheTestSetup)))
        self.add_modules(["cache", "cache_disk"])
        self.add_cgi_module()


class CacheTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["cache", "cache_disk"])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=CacheTestSetup(env=self))
