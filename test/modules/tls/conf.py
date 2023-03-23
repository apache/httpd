import os
from typing import List, Dict, Any

from pyhttpd.conf import  HttpdConf
from pyhttpd.env import HttpdTestEnv


class TlsTestConf(HttpdConf):

    def __init__(self, env: HttpdTestEnv, extras: Dict[str, Any] = None):
        extras = extras if extras is not None else {}
        super().__init__(env=env, extras=extras)

    def start_tls_vhost(self, domains: List[str], port=None, ssl_module=None):
        if ssl_module is None:
            ssl_module = 'mod_tls'
        super().start_vhost(domains=domains, port=port, doc_root=f"htdocs/{domains[0]}", ssl_module=ssl_module)

    def end_tls_vhost(self):
        self.end_vhost()

    def add_tls_vhosts(self, domains: List[str], port=None, ssl_module=None):
        for domain in domains:
            self.start_tls_vhost(domains=[domain], port=port, ssl_module=ssl_module)
            self.end_tls_vhost()

    def add_md_vhosts(self, domains: List[str], port = None):
        self.add([
            f"LoadModule md_module       {self.env.libexec_dir}/mod_md.so",
            "LogLevel md:debug",
        ])
        for domain in domains:
            self.add(f"<MDomain {domain}>")
            for cred in self.env.ca.get_credentials_for_name(domain):
                cert_file = os.path.relpath(cred.cert_file, self.env.server_dir)
                pkey_file = os.path.relpath(cred.pkey_file, self.env.server_dir) if cred.pkey_file else cert_file
                self.add([
                    f"    MDCertificateFile {cert_file}",
                    f"    MDCertificateKeyFile {pkey_file}",
                    ])
            self.add("</MDomain>")
            super().add_vhost(domains=[domain], port=port, doc_root=f"htdocs/{domain}",
                              with_ssl=True, with_certificates=False, ssl_module='mod_tls')

    def add_md_base(self, domain: str):
        self.add([
            f"LoadModule md_module       {self.env.libexec_dir}/mod_md.so",
            "LogLevel md:debug",
            f"ServerName {domain}",
            "MDBaseServer on",
        ])
        self.add(f"TLSEngine {self.env.https_port}")
        self.add(f"<MDomain {domain}>")
        for cred in self.env.ca.get_credentials_for_name(domain):
            cert_file = os.path.relpath(cred.cert_file, self.env.server_dir)
            pkey_file = os.path.relpath(cred.pkey_file, self.env.server_dir) if cred.pkey_file else cert_file
            self.add([
                f"MDCertificateFile {cert_file}",
                f"MDCertificateKeyFile {pkey_file}",
            ])
        self.add("</MDomain>")
