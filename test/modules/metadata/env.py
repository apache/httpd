import inspect
import logging
import os
import re
import subprocess

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class MetadataTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(MetadataTestSetup)))
        self.add_modules(["mime", "mime_magic"])
        # mod_mime_libmagic needs libmagic at build time, so it must not
        # be a hard requirement; its tests skip when it is absent.
        self.add_optional_modules(["mime_libmagic"])


class MetadataTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["mime_magic", "mime_libmagic", "core"])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=MetadataTestSetup(env=self))

    @property
    def has_libmagic_module(self) -> bool:
        """Whether mod_mime_libmagic is available, as a DSO or built in."""
        if os.path.isfile(os.path.join(self.libexec_dir, 'mod_mime_libmagic.so')):
            return True
        p = subprocess.run([self.httpd_bin, '-l'], capture_output=True,
                           text=True)
        return re.search(r'^\s+mod_mime_libmagic\.c$', p.stdout, re.M) is not None
