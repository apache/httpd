import base64
import hashlib
import inspect
import logging
import os
import sqlite3
from typing import List, Optional

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup
from pyhttpd.result import ExecResult

log = logging.getLogger(__name__)


class AAATestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(AAATestSetup)))
        self.add_modules(["auth_digest", "authn_file", "authn_core",
                          "authz_core", "authz_user", "proxy", "proxy_http",
                          "dbd", "authn_dbd", "authn_socache", "auth_basic",
                          "socache_shmcb"])
        self.add_cgi_module()


class AAATestEnv(HttpdTestEnv):

    REALM = "AAA Digest Realm"
    DIGEST_USER = "digestuser"
    DIGEST_PASSWORD = "digestpass2617"
    DIGEST_USER2 = "otheruser"
    DIGEST_PASSWORD2 = "otherpass2617"
    # DIGEST_USER's password in the second file, for a vhost with its own
    # accounts under the same realm.
    DIGEST_PASSWORD_VHOST2 = "vhost2pass2617"

    DBD_USER = "dbduser"
    DBD_PASSWORD = "dbdpass2617"
    DBD_ROLE = "editor"

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["auth_digest", "authn_file", "authz_core",
                                    "authn_dbd", "dbd"])
        self._digest_pwfile = os.path.join(self.server_dir, "digest.passwd")
        self._digest_pwfile2 = os.path.join(self.server_dir, "digest2.passwd")
        self._dbd_file = os.path.join(self.server_dir, "authn_dbd.sqlite3")

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=AAATestSetup(env=self))
        self._write_digest_pwfile()
        self._write_dbd_file()

    def _write_dbd_file(self):
        if os.path.exists(self._dbd_file):
            os.remove(self._dbd_file)
        con = sqlite3.connect(self._dbd_file)
        try:
            con.execute("CREATE TABLE users (user TEXT, password TEXT, role TEXT)")
            # "{SHA}" + base64(sha1(password)): the format ap_password_validate()
            # checks itself, without depending on which crypt(3) algorithms the
            # host libc offers.
            digest = hashlib.sha1(self.DBD_PASSWORD.encode()).digest()
            pw_hash = "{SHA}" + base64.b64encode(digest).decode()
            con.execute("INSERT INTO users (user, password, role) VALUES (?, ?, ?)",
                       (self.DBD_USER, pw_hash, self.DBD_ROLE))
            con.commit()
        finally:
            con.close()

    @property
    def dbd_file(self) -> str:
        return self._dbd_file

    def _write_digest_pwfile(self):
        def ha1(user, password):
            return hashlib.md5(
                f"{user}:{self.REALM}:{password}".encode()).hexdigest()

        with open(self._digest_pwfile, 'w') as fd:
            fd.write(f"{self.DIGEST_USER}:{self.REALM}:"
                     f"{ha1(self.DIGEST_USER, self.DIGEST_PASSWORD)}\n")
            fd.write(f"{self.DIGEST_USER2}:{self.REALM}:"
                     f"{ha1(self.DIGEST_USER2, self.DIGEST_PASSWORD2)}\n")
        with open(self._digest_pwfile2, 'w') as fd:
            fd.write(f"{self.DIGEST_USER}:{self.REALM}:"
                     f"{ha1(self.DIGEST_USER, self.DIGEST_PASSWORD_VHOST2)}\n")

    @property
    def digest_pwfile(self) -> str:
        return self._digest_pwfile

    @property
    def digest_pwfile2(self) -> str:
        return self._digest_pwfile2

    def configtest(self, directory_lines: List[str], extra_top_lines: Optional[List[str]] = None
                    ) -> ExecResult:
        """Run `httpd -t` against a minimal, standalone config built from the
        already-generated modules.conf plus `directory_lines` wrapped in a
        <Directory> block over the shared docroot. Used to test directives
        that are rejected at config-check time (e.g. AuthDigestQop values
        other than 'auth') without touching the package's running server.
        """
        conf_path = os.path.join(self.gen_dir, "digest-configtest.conf")
        modules_conf = os.path.join(self.server_conf_dir, "modules.conf")
        lines = [
            f'ServerRoot "{self.server_dir}"',
            f'Include "{modules_conf}"',
            f'DocumentRoot "{self.server_docs_dir}"',
            f'Listen {self.http_port2}',
        ]
        if extra_top_lines:
            lines.extend(extra_top_lines)
        lines.append(f'<Directory "{self.server_docs_dir}">')
        lines.extend(f"    {l}" for l in directory_lines)
        lines.append('</Directory>')
        with open(conf_path, 'w') as fd:
            fd.write('\n'.join(lines))
            fd.write('\n')
        httpd_bin = os.path.join(self.bin_dir, 'httpd')
        return self.run([httpd_bin, '-t', '-f', conf_path])
