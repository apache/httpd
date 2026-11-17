import inspect
import logging
import os

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class LdapTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(LdapTestSetup)))
        # mod_ldap/mod_authnz_ldap need libldap, so they may not have
        # been built; the tests skip when either is absent.
        self.add_optional_modules(["ldap", "authnz_ldap"])


class LdapTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["ldap", "authnz_ldap"])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=LdapTestSetup(env=self))
