import inspect
import logging
import os
import re
import subprocess
from typing import Dict, Any

from pyhttpd.certs import CertificateSpec
from pyhttpd.conf import HttpdConf
from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class H1TestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(H1TestSetup)))
        self.add_modules(["cgid", "autoindex", "ssl"])

    def make(self):
        super().make()
        self._setup_data_1k_1m()

    def _setup_data_1k_1m(self):
        s90 = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678\n"
        with open(os.path.join(self.env.gen_dir, "data-1k"), 'w') as f:
            for i in range(10):
                f.write(f"{i:09d}-{s90}")
        with open(os.path.join(self.env.gen_dir, "data-10k"), 'w') as f:
            for i in range(100):
                f.write(f"{i:09d}-{s90}")
        with open(os.path.join(self.env.gen_dir, "data-100k"), 'w') as f:
            for i in range(1000):
                f.write(f"{i:09d}-{s90}")
        with open(os.path.join(self.env.gen_dir, "data-1m"), 'w') as f:
            for i in range(10000):
                f.write(f"{i:09d}-{s90}")


class H1TestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["http", "http1", "core"])

        self.httpd_error_log.set_ignored_lognos([
        ])
        self.httpd_error_log.add_ignored_patterns([
        ])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=H1TestSetup(env=self))


class H1Conf(HttpdConf):

    def __init__(self, env: HttpdTestEnv, extras: Dict[str, Any] = None):
        super().__init__(env=env, extras=HttpdConf.merge_extras(extras, {
            "base": [
                "LogLevel http:trace4 http1:trace4",
            ],
            f"cgi.{env.http_tld}": [
                "SSLOptions +StdEnvVars",
                "AddHandler cgi-script .py",
            ]
        }))
