import inspect
import logging
import os
import subprocess
from shutil import copyfile
from typing import Dict, Any

from pyhttpd.certs import CertificateSpec
from pyhttpd.conf import HttpdConf
from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class H2TestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(H2TestSetup)))
        self.add_modules(["http2", "proxy_http2", "cgid", "autoindex", "ssl", "include"])

    def make(self):
        super().make()
        self._add_h2test()
        self._setup_data_1k_1m()

    def _add_h2test(self):
        local_dir = os.path.dirname(inspect.getfile(H2TestSetup))
        p = subprocess.run([self.env.apxs, '-c', 'mod_h2test.c'],
                           capture_output=True,
                           cwd=os.path.join(local_dir, 'mod_h2test'))
        rv = p.returncode
        if rv != 0:
            log.error(f"compiling md_h2test failed: {p.stderr}")
            raise Exception(f"compiling md_h2test failed: {p.stderr}")

        modules_conf = os.path.join(self.env.server_dir, 'conf/modules.conf')
        with open(modules_conf, 'a') as fd:
            # load our test module which is not installed
            fd.write(f"LoadModule h2test_module   \"{local_dir}/mod_h2test/.libs/mod_h2test.so\"\n")

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
        test1_docs = os.path.join(self.env.server_docs_dir, 'test1')
        self.env.mkpath(test1_docs)
        for fname in ["data-1k", "data-10k", "data-100k", "data-1m"]:
            src = os.path.join(self.env.gen_dir, fname)
            dest = os.path.join(test1_docs, fname)
            copyfile(src, dest)


class H2TestEnv(HttpdTestEnv):

    @classmethod
    @property
    def is_unsupported(cls):
        mpm_module = f"mpm_{os.environ['MPM']}" if 'MPM' in os.environ else 'mpm_event'
        return mpm_module == 'mpm_prefork'

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_conf([
            "H2MinWorkers 1",
            "H2MaxWorkers 64",
            "Protocols h2 http/1.1 h2c",
        ])
        self.add_httpd_log_modules(["http2", "proxy_http2", "h2test", "proxy", "proxy_http"])
        self.add_cert_specs([
            CertificateSpec(domains=[
                f"push.{self._http_tld}",
                f"hints.{self._http_tld}",
                f"ssl.{self._http_tld}",
                f"pad0.{self._http_tld}",
                f"pad1.{self._http_tld}",
                f"pad2.{self._http_tld}",
                f"pad3.{self._http_tld}",
                f"pad8.{self._http_tld}",
            ]),
            CertificateSpec(domains=[f"noh2.{self.http_tld}"], key_type='rsa2048'),
        ])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=H2TestSetup(env=self))


class H2Conf(HttpdConf):

    def __init__(self, env: HttpdTestEnv, extras: Dict[str, Any] = None):
        super().__init__(env=env, extras=HttpdConf.merge_extras(extras, {
            f"cgi.{env.http_tld}": [
                "SSLOptions +StdEnvVars",
                "AddHandler cgi-script .py",
                "<Location \"/h2test/echo\">",
                "    SetHandler h2test-echo",
                "</Location>",
                "<Location \"/h2test/delay\">",
                "    SetHandler h2test-delay",
                "</Location>",
                "<Location \"/h2test/error\">",
                "    SetHandler h2test-error",
                "</Location>",
            ]
        }))

    def start_vhost(self, domains, port=None, doc_root="htdocs", with_ssl=None,
                    ssl_module=None, with_certificates=None):
        super().start_vhost(domains=domains, port=port, doc_root=doc_root,
                            with_ssl=with_ssl, ssl_module=ssl_module,
                            with_certificates=with_certificates)
        if f"noh2.{self.env.http_tld}" in domains:
            protos = ["http/1.1"]
        elif port == self.env.https_port or with_ssl is True:
            protos = ["h2", "http/1.1"]
        else:
            protos = ["h2c", "http/1.1"]
        if f"test2.{self.env.http_tld}" in domains:
            protos = reversed(protos)
        self.add(f"Protocols {' '.join(protos)}")
        return self

    def add_vhost_noh2(self):
        domains = [f"noh2.{self.env.http_tld}", f"noh2-alias.{self.env.http_tld}"]
        self.start_vhost(domains=domains, port=self.env.https_port, doc_root="htdocs/noh2")
        self.add(["Protocols http/1.1", "SSLOptions +StdEnvVars"])
        self.end_vhost()
        self.start_vhost(domains=domains, port=self.env.http_port, doc_root="htdocs/noh2")
        self.add(["Protocols http/1.1", "SSLOptions +StdEnvVars"])
        self.end_vhost()
        return self

    def add_vhost_test1(self, proxy_self=False, h2proxy_self=False):
        return super().add_vhost_test1(proxy_self=proxy_self, h2proxy_self=h2proxy_self)

    def add_vhost_test2(self):
        return super().add_vhost_test2()
