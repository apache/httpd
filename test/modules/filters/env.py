import inspect
import logging
import os

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class FiltersTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(FiltersTestSetup)))
        self.add_modules(["substitute", "sed"])
        self.add_cgi_module()


class FiltersTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["substitute", "sed", "core"])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=FiltersTestSetup(env=self))
