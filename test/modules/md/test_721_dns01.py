# test the arguments mod_md invokes MDChallengeDns01 with
import os

import pytest

from .md_conf import MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestDns01:

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
        self.dnscmd = os.path.join(env.test_dir, "../modules/md/dns01_record.py")
        self.dnslog = os.path.join(env.gen_dir, "dns01.log")
        if os.path.isfile(self.dnslog):
            os.remove(self.dnslog)

    def configure_httpd(self, env, domain, version=None):
        conf = MDConf(env)
        conf.add("MDCAChallenges dns-01")
        conf.add(f"MDChallengeDns01 {self.dnscmd} {self.dnslog}")
        if version is not None:
            conf.add(f"MDChallengeDns01Version {version}")
        conf.add_md([domain])
        conf.add_vhost([domain])
        conf.install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'

    def calls(self, action):
        """The recorded argv of each invocation of the challenge command."""
        if not os.path.isfile(self.dnslog):
            return []
        with open(self.dnslog) as fd:
            argvs = [eval(line.strip()) for line in fd if line.startswith('[')]
        return [argv for argv in argvs if len(argv) > 2 and argv[2] == action]

    # the domain and the challenge token are separate arguments, whatever they
    # contain, and version 1 tears down with the domain alone
    def test_md_721_001(self, env):
        domain = self.test_domain
        self.configure_httpd(env, domain)
        assert env.await_completion([domain])
        setups = self.calls('setup')
        assert len(setups) == 1, f'{setups}'
        assert setups[0][0:4] == [self.dnscmd, self.dnslog, 'setup', domain]
        assert len(setups[0]) == 5, f'no separate challenge argument: {setups[0]}'
        teardowns = self.calls('teardown')
        assert len(teardowns) == 1, f'{teardowns}'
        assert teardowns[0] == [self.dnscmd, self.dnslog, 'teardown', domain]

    # version 2 tears down with the challenge token as a further argument
    def test_md_721_002(self, env):
        domain = self.test_domain
        self.configure_httpd(env, domain, version=2)
        assert env.await_completion([domain])
        setups = self.calls('setup')
        assert len(setups) == 1, f'{setups}'
        teardowns = self.calls('teardown')
        assert len(teardowns) == 1, f'{teardowns}'
        assert teardowns[0] == [self.dnscmd, self.dnslog, 'teardown', domain,
                                setups[0][4]]

    # an argument configured with quotes stays one argument
    def test_md_721_003(self, env):
        domain = self.test_domain
        dnslog = os.path.join(env.gen_dir, "dns01 with spaces.log")
        if os.path.isfile(dnslog):
            os.remove(dnslog)
        self.dnslog = dnslog
        conf = MDConf(env)
        conf.add("MDCAChallenges dns-01")
        conf.add(f'MDChallengeDns01 "{self.dnscmd}" "{dnslog}"')
        conf.add_md([domain])
        conf.add_vhost([domain])
        conf.install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        assert env.await_completion([domain])
        setups = self.calls('setup')
        assert len(setups) == 1, f'{setups}'
        assert setups[0][1] == dnslog
