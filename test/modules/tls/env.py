import inspect
import logging
import os
import re
import subprocess

from datetime import timedelta, datetime
from typing import List, Optional, Dict, Tuple, Union

from pyhttpd.certs import CertificateSpec
from pyhttpd.env import HttpdTestEnv, HttpdTestSetup
from pyhttpd.result import ExecResult

log = logging.getLogger(__name__)


class TlsTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(TlsTestSetup)))
        self.add_modules(["tls", "http2", "cgid", "watchdog", "proxy_http2"])


class TlsCipher:

    def __init__(self, id: int, name: str, flavour: str,
                 min_version: float, max_version: float = None,
                 openssl: str = None):
        self.id = id
        self.name = name
        self.flavour = flavour
        self.min_version = min_version
        self.max_version = max_version if max_version is not None else self.min_version
        if openssl is None:
            if name.startswith('TLS13_'):
                openssl = re.sub(r'^TLS13_', 'TLS_', name)
            else:
                openssl = re.sub(r'^TLS_', '', name)
                openssl = re.sub(r'_WITH_([^_]+)_', r'_\1_', openssl)
                openssl = re.sub(r'_AES_(\d+)', r'_AES\1', openssl)
                openssl = re.sub(r'(_POLY1305)_\S+$', r'\1', openssl)
                openssl = re.sub(r'_', '-', openssl)
        self.openssl_name = openssl
        self.id_name = "TLS_CIPHER_0x{0:04x}".format(self.id)

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name


class TlsTestEnv(HttpdTestEnv):

    CURL_SUPPORTS_TLS_1_3 = None

    @classmethod
    def curl_supports_tls_1_3(cls) -> bool:
        if cls.CURL_SUPPORTS_TLS_1_3 is None:
            # Unfortunately, there is no reliable, platform-independant
            # way to verify that TLSv1.3 is properly supported by curl.
            #
            # p = subprocess.run(['curl', '--tlsv1.3', 'https://shouldneverexistreally'],
            #                    stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            # return code 6 means the site could not be resolved, but the
            # tls parameter was recognized
            cls.CURL_SUPPORTS_TLS_1_3 = False
        return cls.CURL_SUPPORTS_TLS_1_3


    # current rustls supported ciphers in their order of preference
    # used to test cipher selection, see test_06_ciphers.py
    RUSTLS_CIPHERS = [
        TlsCipher(0x1303, "TLS13_CHACHA20_POLY1305_SHA256", "CHACHA", 1.3),
        TlsCipher(0x1302, "TLS13_AES_256_GCM_SHA384", "AES", 1.3),
        TlsCipher(0x1301, "TLS13_AES_128_GCM_SHA256", "AES", 1.3),
        TlsCipher(0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDSA", 1.2),
        TlsCipher(0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "RSA", 1.2),
        TlsCipher(0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDSA", 1.2),
        TlsCipher(0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDSA", 1.2),
        TlsCipher(0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "RSA", 1.2),
        TlsCipher(0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "RSA", 1.2),
    ]

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self._domain_a = "a.mod-tls.test"
        self._domain_b = "b.mod-tls.test"
        self.add_httpd_conf([
            f'<Directory "{self.server_dir}/htdocs/{self.domain_a}">',
            '    AllowOverride None',
            '    Require all granted',
            '    AddHandler cgi-script .py',
            '    Options +ExecCGI',
            '</Directory>',
            f'<Directory "{self.server_dir}/htdocs/{self.domain_b}">',
            '    AllowOverride None',
            '    Require all granted',
            '    AddHandler cgi-script .py',
            '    Options +ExecCGI',
            '</Directory>',
            f'<VirtualHost *:{self.http_port}>',
            '    ServerName localhost',
            '    DocumentRoot "htdocs"',
            '</VirtualHost>',
            f'<VirtualHost *:{self.http_port}>',
            f'    ServerName {self.domain_a}',
            '    DocumentRoot "htdocs/a.mod-tls.test"',
            '</VirtualHost>',
            f'<VirtualHost *:{self.http_port}>',
            f'    ServerName {self.domain_b}',
            '    DocumentRoot "htdocs/b.mod-tls.test"',
            '</VirtualHost>',
        ])
        self.add_cert_specs([
            CertificateSpec(domains=[self.domain_a]),
            CertificateSpec(domains=[self.domain_b], key_type='secp256r1', single_file=True),
            CertificateSpec(domains=[self.domain_b], key_type='rsa4096'),
            CertificateSpec(name="clientsX", sub_specs=[
                CertificateSpec(name="user1", client=True, single_file=True),
                CertificateSpec(name="user2", client=True, single_file=True),
                CertificateSpec(name="user_expired", client=True,
                                single_file=True, valid_from=timedelta(days=-91),
                                valid_to=timedelta(days=-1)),
            ]),
            CertificateSpec(name="clientsY", sub_specs=[
                CertificateSpec(name="user1", client=True, single_file=True),
            ]),
            CertificateSpec(name="user1", client=True, single_file=True),
        ])
        if not HttpdTestEnv.has_shared_module("tls"):
            self.add_httpd_log_modules(['ssl'])
        else:
            self.add_httpd_log_modules(['tls'])


    def setup_httpd(self, setup: TlsTestSetup = None):
        if setup is None:
            setup = TlsTestSetup(env=self)
        super().setup_httpd(setup=setup)

    @property
    def domain_a(self) -> str:
        return self._domain_a

    @property
    def domain_b(self) -> str:
        return self._domain_b

    def tls_get(self, domain, paths: Union[str, List[str]], options: List[str] = None, no_stdout_list = False) -> ExecResult:
        if isinstance(paths, str):
            paths = [paths]
        urls = [f"https://{domain}:{self.https_port}{path}" for path in paths]
        return self.curl_raw(urls=urls, options=options, no_stdout_list=no_stdout_list)

    def tls_get_json(self, domain: str, path: str, options=None):
        r = self.tls_get(domain=domain, paths=path, options=options)
        return r.json

    def run_diff(self, fleft: str, fright: str) -> ExecResult:
        return self.run(['diff', '-u', fleft, fright])

    def openssl(self, args: List[str]) -> ExecResult:
        return self.run(['openssl'] + args)

    def openssl_client(self, domain, extra_args: List[str] = None) -> ExecResult:
        args = ["s_client", "-CAfile", self.ca.cert_file, "-servername", domain,
                "-connect", "localhost:{port}".format(
                    port=self.https_port
                )]
        if extra_args:
            args.extend(extra_args)
        args.extend([])
        return self.openssl(args)

    OPENSSL_SUPPORTED_PROTOCOLS = None

    @staticmethod
    def openssl_supports_tls_1_3() -> bool:
        if TlsTestEnv.OPENSSL_SUPPORTED_PROTOCOLS is None:
            env = TlsTestEnv()
            r = env.openssl(args=["ciphers", "-v"])
            protos = set()
            ciphers = set()
            for line in r.stdout.splitlines():
                m = re.match(r'^(\S+)\s+(\S+)\s+(.*)$', line)
                if m:
                    ciphers.add(m.group(1))
                    protos.add(m.group(2))
            TlsTestEnv.OPENSSL_SUPPORTED_PROTOCOLS = protos
            TlsTestEnv.OPENSSL_SUPPORTED_CIPHERS = ciphers
        return "TLSv1.3" in TlsTestEnv.OPENSSL_SUPPORTED_PROTOCOLS
