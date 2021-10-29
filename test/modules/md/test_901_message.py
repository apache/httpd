# test mod_md message support

import json
import os
import time
import pytest

from .md_conf import MDConf, MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestMessage:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        env.APACHE_CONF_SRC = "data/test_auto"
        acme.start(config='default')
        env.check_acme()
        env.clear_store()
        MDConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)
        self.mcmd = os.path.join(env.test_dir, "../modules/md/message.py")
        self.mlog = os.path.join(env.gen_dir, "message.log")
        if os.path.isfile(self.mlog):
            os.remove(self.mlog)

    # test: signup with configured message cmd that is invalid
    def test_md_901_001(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = MDConf(env)
        conf.add("MDMessageCmd blablabla")
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_file(env.store_staged_file(domain, 'job.json'))
        stat = env.get_md_status(domain)
        # this command should have failed and logged an error
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10109:"

    # test: signup with configured message cmd that is valid but returns != 0
    def test_md_901_002(self, env):
        mcmd = os.path.join(env.test_dir, "../modules/md/notifail.py")
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = MDConf(env)
        conf.add(f"MDMessageCmd {mcmd} {self.mlog}")
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)
        stat = env.get_md_status(domain)
        # this command should have failed and logged an error
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10109:"

    # test: signup with working message cmd and see that it logs the right things
    def test_md_901_003(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = MDConf(env)
        conf.add(f"MDMessageCmd {self.mcmd} {self.mlog}")
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain], restart=False)
        time.sleep(1)
        stat = env.get_md_status(domain)
        # this command did not fail and logged itself the correct information
        assert stat["renewal"]["last"]["status"] == 0
        assert stat["renewal"]["log"]["entries"]
        assert stat["renewal"]["log"]["entries"][0]["type"] == "message-renewed"
        # shut down server to make sure that md has completed 
        assert env.apache_stop() == 0
        nlines = open(self.mlog).readlines()
        assert 3 == len(nlines)
        nlines = [s.strip() for s in nlines]
        assert "['{cmd}', '{logfile}', 'challenge-setup:http-01:{dns}', '{mdomain}']".format(
            cmd=self.mcmd, logfile=self.mlog, mdomain=domain, dns=domains[0]) in nlines
        assert "['{cmd}', '{logfile}', 'challenge-setup:http-01:{dns}', '{mdomain}']".format(
            cmd=self.mcmd, logfile=self.mlog, mdomain=domain, dns=domains[1]) in nlines
        assert nlines[2].strip() == "['{cmd}', '{logfile}', 'renewed', '{mdomain}']".format(
            cmd=self.mcmd, logfile=self.mlog, mdomain=domain)

    # test issue #145: 
    # - a server renews a valid certificate and is not restarted when recommended
    # - the job did not clear its next_run and was run over and over again
    # - the job logged the re-verifications again and again. which was saved.
    # - this eventually flushed out the "message-renew" log entry
    # - which caused the renew message handling to trigger again and again
    # the fix does:
    # - reset the next run
    # - no longer adds the re-validations to the log
    # - messages only once
    @pytest.mark.skipif(MDTestEnv.is_pebble(), reason="ACME server certs valid too long")
    def test_md_901_004(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = MDConf(env)
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        # force renew
        conf = MDConf(env)
        conf.add(f"MDMessageCmd {self.mcmd} {self.mlog}")
        conf.add("MDRenewWindow 120d")
        conf.add("MDActivationDelay -7d")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain], restart=False)
        env.get_md_status(domain)
        assert env.await_file(self.mlog)
        nlines = open(self.mlog).readlines()
        assert len(nlines) == 1
        assert nlines[0].strip() == f"['{self.mcmd}', '{self.mlog}', 'renewed', '{domain}']"
    
    def test_md_901_010(self, env):
        #  MD with static cert files, lifetime in renewal window, no message about renewal
        domain = self.test_domain
        domains = [domain, 'www.%s' % domain]
        testpath = os.path.join(env.gen_dir, 'test_901_010')
        # cert that is only 10 more days valid
        env.create_self_signed_cert(domains, {"notBefore": -70, "notAfter": 20},
                                    serial=901010, path=testpath)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        assert os.path.exists(cert_file)
        assert os.path.exists(pkey_file)
        conf = MDConf(env)
        conf.add(f"MDMessageCmd {self.mcmd} {self.mlog}")
        conf.start_md(domains)
        conf.add(f"MDCertificateFile {cert_file}")
        conf.add(f"MDCertificateKeyFile {pkey_file}")
        conf.end_md()
        conf.add_vhost(domain)
        conf.install()
        assert env.apache_restart() == 0
        assert not os.path.isfile(self.mlog)
        
    def test_md_901_011(self, env):
        # MD with static cert files, lifetime in warn window, check message
        domain = self.test_domain
        domains = [domain, f'www.{domain}']
        testpath = os.path.join(env.gen_dir, 'test_901_011')
        # cert that is only 10 more days valid
        env.create_self_signed_cert(domains, {"notBefore": -85, "notAfter": 5},
                                    serial=901011, path=testpath)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        assert os.path.exists(cert_file)
        assert os.path.exists(pkey_file)
        conf = MDConf(env)
        conf.add(f"MDMessageCmd {self.mcmd} {self.mlog}")
        conf.start_md(domains)
        conf.add(f"MDCertificateFile {cert_file}")
        conf.add(f"MDCertificateKeyFile {pkey_file}")
        conf.end_md()
        conf.add_vhost(domain)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_file(self.mlog)
        nlines = open(self.mlog).readlines()
        assert len(nlines) == 1
        assert nlines[0].strip() == f"['{self.mcmd}', '{self.mlog}', 'expiring', '{domain}']"
        # check that we do not get it resend right away again
        assert env.apache_restart() == 0
        time.sleep(1)
        nlines = open(self.mlog).readlines()
        assert len(nlines) == 1
        assert nlines[0].strip() == f"['{self.mcmd}', '{self.mlog}', 'expiring', '{domain}']"

    # MD, check messages from stapling
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_901_020(self, env):
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add(f"MDMessageCmd {self.mcmd} {self.mlog}")
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add("MDStapling on")
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        env.await_ocsp_status(domain)
        assert env.await_file(self.mlog)
        time.sleep(1)
        nlines = open(self.mlog).readlines()
        assert len(nlines) == 4
        assert nlines[0].strip() == \
               f"['{self.mcmd}', '{self.mlog}', 'challenge-setup:http-01:{domain}', '{domain}']"
        assert nlines[1].strip() == \
               f"['{self.mcmd}', '{self.mlog}', 'renewed', '{domain}']"
        assert nlines[2].strip() == \
               f"['{self.mcmd}', '{self.mlog}', 'installed', '{domain}']"
        assert nlines[3].strip() == \
               f"['{self.mcmd}', '{self.mlog}', 'ocsp-renewed', '{domain}']"

    # test: while testing gh issue #146, it was noted that a failed renew notification never
    # resets the MD activity.
    @pytest.mark.skipif(MDTestEnv.is_pebble(), reason="ACME server certs valid too long")
    def test_md_901_030(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = MDConf(env)
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        # set the warn window that triggers right away and a failing message command
        conf = MDConf(env)
        conf.add(f"MDMessageCmd {env.test_dir}../modules/md/notifail.py {self.mlog}")
        conf.add_md(domains)
        conf.add("""
            MDWarnWindow 100d
            """)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        env.get_md_status(domain)
        # this command should have failed and logged an error
        # shut down server to make sure that md has completed
        assert env.await_file(env.store_staged_file(domain, 'job.json'))
        while True:
            with open(env.store_staged_file(domain, 'job.json')) as f:
                job = json.load(f)
                if job["errors"] > 0:
                    assert job["errors"] > 0,  "unexpected job result: {0}".format(job)
                    assert job["last"]["problem"] == "urn:org:apache:httpd:log:AH10109:"
                    break
            time.sleep(0.1)
        env.httpd_error_log.ignore_recent()

        # reconfigure to a working notification command and restart
        conf = MDConf(env)
        conf.add(f"MDMessageCmd {self.mcmd} {self.mlog}")
        conf.add_md(domains)
        conf.add("""
            MDWarnWindow 100d
            """)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_file(self.mlog)
        # we see the notification logged by the command
        nlines = open(self.mlog).readlines()
        assert len(nlines) == 1
        assert nlines[0].strip() == f"['{self.mcmd}', '{self.mlog}', 'expiring', '{domain}']"
        # the error needs to be gone
        assert env.await_file(env.store_staged_file(domain, 'job.json'))
        with open(env.store_staged_file(domain, 'job.json')) as f:
            job = json.load(f)
            assert job["errors"] == 0

    # MD, check a failed challenge setup
    def test_md_901_040(self, env):
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        mcmd = os.path.join(env.test_dir, "../modules/md/msg_fail_on.py")
        conf.add(f"MDMessageCmd {mcmd} {self.mlog} challenge-setup")
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)
        assert env.await_file(self.mlog)
        time.sleep(1)
        nlines = open(self.mlog).readlines()
        assert len(nlines) == 2
        assert nlines[0].strip() == \
               f"['{mcmd}', '{self.mlog}', 'challenge-setup:http-01:{domain}', '{domain}']"
        assert nlines[1].strip() == \
               f"['{mcmd}', '{self.mlog}', 'errored', '{domain}']"
        stat = env.get_md_status(domain)
        # this command should have failed and logged an error
        assert stat["renewal"]["last"]["problem"] == "challenge-setup-failure"

