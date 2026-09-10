import inspect
import logging
import os

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class MetadataTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(MetadataTestSetup)))
        self.add_modules(["mime", "mime_magic", "env", "include"])


class MetadataTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["mime_magic", "env", "include", "core"])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=MetadataTestSetup(env=self))
