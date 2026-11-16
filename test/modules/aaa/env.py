import base64
import contextlib
import hashlib
import inspect
import logging
import os
from typing import Dict, List, Optional

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup
from pyhttpd.result import ExecResult

log = logging.getLogger(__name__)


class AAATestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(AAATestSetup)))
        self.add_modules(["auth_digest", "authn_file", "authn_core",
                          "authz_core", "authz_user", "proxy", "proxy_http",
                          "authn_socache"])


class AAATestEnv(HttpdTestEnv):

    REALM = "AAA Digest Realm"
    DIGEST_USER = "digestuser"
    DIGEST_PASSWORD = "digestpass2617"
    DIGEST_USER2 = "otheruser"
    DIGEST_PASSWORD2 = "otherpass2617"
    # DIGEST_USER's password in the second file, for a vhost with its own
    # accounts under the same realm.
    DIGEST_PASSWORD_VHOST2 = "vhost2pass2617"

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["auth_digest", "authn_file", "authz_core",
                                    "authn_socache"])
        self._digest_pwfile = os.path.join(self.server_dir, "digest.passwd")
        self._digest_pwfile2 = os.path.join(self.server_dir, "digest2.passwd")

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=AAATestSetup(env=self))
        self._write_digest_pwfile()

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

    @staticmethod
    def write_basic_pwfile(path: str, users: Dict[str, str]):
        """Write a Basic auth password file holding `users`, a dict of
        user name to password, replacing the file atomically.  The
        passwords are stored as {SHA} hashes, which need no htpasswd."""
        with open(path + ".tmp", 'w') as fd:
            for user, password in users.items():
                sha = base64.b64encode(
                    hashlib.sha1(password.encode()).digest()).decode()
                fd.write(f"{user}:{{SHA}}{sha}\n")
        os.replace(path + ".tmp", path)

    def write_digest_pwfile(self, path: str, users: Dict[str, str]):
        """As write_basic_pwfile(), for a Digest password file in REALM."""
        with open(path + ".tmp", 'w') as fd:
            for user, password in users.items():
                ha1 = hashlib.md5(
                    f"{user}:{self.REALM}:{password}".encode()).hexdigest()
                fd.write(f"{user}:{self.REALM}:{ha1}\n")
        os.replace(path + ".tmp", path)

    @contextlib.contextmanager
    def preserved_test_conf(self):
        """Put back the installed test configuration on exit and restart
        the server with it, for a test which installs its own while
        sharing the package's server."""
        with open(self._test_conf) as fd:
            saved = fd.read()
        try:
            yield
        finally:
            self.apache_stop()
            with open(self._test_conf, 'w') as fd:
                fd.write(saved)
            assert self.apache_restart() == 0

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
