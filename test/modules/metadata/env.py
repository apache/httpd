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
        # mod_mime_libmagic needs libmagic at build time, so it must not
        # be a hard requirement; its tests skip when it is absent.
        self.add_optional_modules(["mime_libmagic"])


class MetadataTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        # Only raise the log level for mod_mime_libmagic when it is built:
        # a LogLevel for an unloaded module is a fatal config error, which
        # would break the whole suite (including the mod_mime_magic tests)
        # on platforms without libmagic, such as Windows.
        log_modules = ["mime_magic", "env", "include", "core"]
        if self.has_libmagic_module:
            log_modules.insert(1, "mime_libmagic")
        self.add_httpd_log_modules(log_modules)

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=MetadataTestSetup(env=self))

    @property
    def has_libmagic_module(self) -> bool:
        """Whether mod_mime_libmagic was built."""
        return self.has_shared_module("mime_libmagic")
