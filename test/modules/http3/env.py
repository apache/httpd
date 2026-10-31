import inspect
import logging
import os
import re
import subprocess
from typing import Dict, Any, List, Optional

from pyhttpd.conf import HttpdConf
from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class H3TestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(H3TestSetup)))
        self.add_modules(["http3", "ssl", "setenvif", "headers"])
        self.add_cgi_module()


class H3TestEnv(HttpdTestEnv):

    def curl_has_http3(self) -> bool:
        """Whether the curl in use can speak HTTP/3."""
        try:
            p = subprocess.run([self.curl, "-V"],
                               capture_output=True, text=True)
        except OSError:
            return False
        m = re.search(r'^Features:(.*)$', p.stdout, re.MULTILINE)
        return m is not None and "HTTP3" in m.group(1).split()

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["http3"])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=H3TestSetup(env=self))

    @property
    def h3_port(self) -> int:
        # the QUIC listener shares the number of the TLS port, over UDP
        return self.https_port

    def h3_get(self, url: str, options: Optional[List[str]] = None):
        return self.curl_raw([url], options=["--http3-only"] + (options or []))


class H3Conf(HttpdConf):
    """A configuration with HTTP/3 on the https port of the test1 vhost.

    mod_http3 opens one UDP listener, with the certificate of the first
    virtual host that has one configured, so test1 carries the H3
    directives and every other vhost on the https port is reached through
    the same QUIC connection by its Host header. The default certificate
    covers all test domains.
    """

    def __init__(self, env: H3TestEnv, extras: Dict[str, Any] = None):
        super().__init__(env=env, extras=extras)

    def add_h3_vhosts(self, test1: List[str] = None, test2: List[str] = None,
                      cgi: List[str] = None):
        cred = self.env.get_credentials_for_name(f"test1.{self.env.http_tld}")[0]
        self.start_vhost(domains=[f"test1.{self.env.http_tld}"],
                         port=self.env.https_port, doc_root="htdocs/test1")
        self.add([
            "Protocols h3 http/1.1",
            f"H3CertificatePath {cred.cert_file}",
            f"H3CertificateKeyPath {cred.pkey_file}",
            f"H3Port {self.env.h3_port}",
        ])
        self.add(test1 or [])
        self.end_vhost()
        self.start_vhost(domains=[f"test2.{self.env.http_tld}"],
                         port=self.env.https_port, doc_root="htdocs/test2")
        self.add(test2 or [])
        self.end_vhost()
        self.start_vhost(domains=[f"cgi.{self.env.http_tld}"],
                         port=self.env.https_port, doc_root="htdocs/cgi")
        self.add(["AddHandler cgi-script .py"])
        self.add(cgi or [])
        self.end_vhost()
        return self
