import inspect
import logging
import os
from typing import List

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup
from pyhttpd.result import ExecResult

log = logging.getLogger(__name__)


class FiltersTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(FiltersTestSetup)))
        self.add_modules(["substitute", "sed", "buffer", "brotli", "ext_filter", "include", "deflate"])
        self.add_cgi_module()
        self.add_optional_modules(["xml2enc", "proxy_html"])


class FiltersTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["substitute", "sed", "buffer", "brotli", "ext_filter", "core", "proxy_html"])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=FiltersTestSetup(env=self))

    def configtest(self, lines: List[str]) -> ExecResult:
        """Run `httpd -t` on a standalone config of the generated
        modules.conf plus `lines`, leaving the running server alone."""
        conf_path = os.path.join(self.gen_dir, "filters-configtest.conf")
        modules_conf = os.path.join(self.server_conf_dir, "modules.conf")
        with open(conf_path, 'w') as fd:
            fd.write('\n'.join([
                f'ServerRoot "{self.server_dir}"',
                f'Include "{modules_conf}"',
                f'DocumentRoot "{self.server_docs_dir}"',
                f'Listen {self.http_port2}',
            ] + lines) + '\n')
        return self.run([os.path.join(self.bin_dir, 'httpd'), '-t',
                         '-f', conf_path])
