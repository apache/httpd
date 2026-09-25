import inspect
import logging
import os
import subprocess

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class GeneratorsTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(GeneratorsTestSetup)))
        self.add_modules(["cgid", "include", "headers"])


class GeneratorsTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        # A LogLevel for an unloaded module is a fatal config error.
        log_modules = ["include", "core"]
        if self.has_cgid_module:
            log_modules.insert(0, "cgid")
        self.add_httpd_log_modules(log_modules)

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=GeneratorsTestSetup(env=self))

    @property
    def has_cgid_module(self) -> bool:
        """Whether mod_cgid was built, shared or static."""
        if self.has_shared_module("cgid"):
            return True
        p = subprocess.run([os.path.join(self.bin_dir, "httpd"), "-l"],
                           capture_output=True, text=True)
        return "mod_cgid.c" in p.stdout
