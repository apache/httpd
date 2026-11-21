import inspect
import logging
import os
import subprocess

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class FiltersTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(FiltersTestSetup)))
        self.add_modules(["substitute", "sed", "buffer", "brotli", "ext_filter", "include", "deflate"])
        self.add_optional_modules(["charset_lite"])
        self.add_cgi_module()


class FiltersTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["substitute", "sed", "buffer", "brotli", "ext_filter", "core"])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=FiltersTestSetup(env=self))

    @property
    def has_charset_lite_module(self) -> bool:
        """Whether mod_charset_lite was built, shared or static."""
        if self.has_shared_module("charset_lite"):
            return True
        p = subprocess.run([os.path.join(self.bin_dir, "httpd"), "-l"],
                           capture_output=True, text=True)
        return "mod_charset_lite.c" in p.stdout
