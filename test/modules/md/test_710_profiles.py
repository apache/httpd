import datetime
import email.utils
import os
from datetime import timedelta

import pytest
from pyhttpd.certs import CertificateSpec

from pyhttpd.env import HttpdTestEnv
from .md_cert_util import MDCertUtil
from .md_env import MDTestEnv
from .md_conf import MDConf


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestProfiles:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        env.APACHE_CONF_SRC = "data/test_auto"
        acme.start(config='default')
        env.check_acme()
        env.clear_store()
        MDConf(env).install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    def _write_res_file(self, doc_root, name, content):
        if not os.path.exists(doc_root):
            os.makedirs(doc_root)
        open(os.path.join(doc_root, name), "w").write(content)

    # create a MD with 'default' profile, get cert
    def test_md_710_001(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain, "www." + domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.start_md(domains)
        conf.add(f'  MDProfile default')
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        #
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        assert env.await_completion(domains)
        stat = env.get_md_status(domain)
        assert stat["watched"] == 1
        assert stat["profile"] == "default", f'{stat}'
        assert stat['cert']['rsa']['valid']['until'], f'{stat}'
        ts = email.utils.parsedate_to_datetime(stat['cert']['rsa']['valid']['until'])
        valid = ts - datetime.datetime.now(datetime.timezone.utc)
        assert valid.days in [89, 90]

    # create a MD with 'shortlived' profile, get cert
    def test_md_710_002(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain, "www." + domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.start_md(domains)
        conf.add(f'  MDProfile shortlived')
        conf.add(f'  MDProfileMandatory on')
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        #
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        assert env.await_completion(domains)
        stat = env.get_md_status(domain)
        assert stat["watched"] == 1
        assert stat["profile"] == "shortlived", f'{stat}'
        assert stat['cert']['rsa']['valid']['until'], f'{stat}'
        ts = email.utils.parsedate_to_datetime(stat['cert']['rsa']['valid']['until'])
        valid = ts - datetime.datetime.now(datetime.timezone.utc)
        assert valid.days in [5, 6]

    # create a MD with unknown 'XXX' profile, get cert
    def test_md_710_003(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain, "www." + domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.start_md(domains)
        conf.add(f'  MDProfile XXX')
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        #
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        assert env.await_completion(domains)
        stat = env.get_md_status(domain)
        assert stat["watched"] == 1
        assert stat["profile"] == "XXX", f'{stat}'

    # create a MD with unknown 'XXX' profile, mandatory, fail
    def test_md_710_004(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain, "www." + domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.start_md(domains)
        conf.add(f'  MDProfile XXX')
        conf.add(f'  MDProfileMandatory on')
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        #
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        assert env.await_error(domain)
        stat = env.get_md_status(domain)
        assert stat["watched"] == 1
        assert stat["profile"] == "XXX", f'{stat}'
        assert len(stat['cert']) == 0, f'{stat}'
        assert stat['renewal']['errors'] > 0, f'{stat}'
        assert stat['renewal']['last']['activity'] == 'Creating new order', f'{stat}'
        MDConf(env).install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        env.httpd_error_log.ignore_recent(matches=[
            r'.*mandatory ACME profile \'XXX\' is not offered by CA.*',
        ], lognos=[
            "AH10056"  # processing failed
        ])
