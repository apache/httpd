# test mod_md stapling support

import os
import time
from datetime import timedelta
import pytest
from pyhttpd.certs import CertificateSpec

from .md_conf import MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestStapling:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='default')
        env.check_acme()
        env.clear_store()
        domain = env.get_class_domain(self.__class__)
        mdA = "a-" + domain
        mdB = "b-" + domain
        self.configure_httpd(env, [mdA, mdB]).install()
        env.apache_stop()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        assert env.await_completion([mdA, mdB])
        env.check_md_complete(mdA)
        env.check_md_complete(mdB)

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        self.domain = env.get_class_domain(self.__class__)
        self.mdA = "a-" + self.domain
        self.mdB = "b-" + self.domain
        yield
        env.apache_stop()

    def configure_httpd(self, env, domains=None, add_lines="", ssl_stapling=False):
        if not isinstance(domains, list):
            domains = [domains] if domains else []
        conf = MDConf(env)
        conf.add("""
        <IfModule tls_module>
            LogLevel tls:trace4
        </IfModule>
        <IfModule ssl_module>
            LogLevel ssl:trace4
        </IfModule>
            """)
        if ssl_stapling:
            conf.add("""
            <IfModule ssl_module>
                SSLUseStapling On
                SSLStaplingCache shmcb:stapling_cache(128000)
            </IfModule>
                """)
        conf.add(add_lines)
        for domain in domains:
            conf.add_md([domain])
            conf.add_vhost(domain)
        return conf

    # MD with stapling on/off and mod_ssl stapling off
    # expect to only see stapling response when MD stapling is on
    def test_md_801_001(self, env):
        md = self.mdA
        self.configure_httpd(env, md).install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.get_ocsp_status(md)
        if MDTestEnv.lacks_ocsp():
            assert 'ocsp' not in stat or stat['ocsp'] == "no response sent", f'{stat}'
        else:
            assert stat['ocsp'] == "no response sent"
        stat = env.get_md_status(md)
        assert not stat["stapling"]
        #
        # turn stapling on, wait for it to appear in connections
        self.configure_httpd(env, md, """
            MDStapling on
            LogLevel md:trace5
            """).install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        if MDTestEnv.lacks_ocsp():
            stat = env.get_md_status(md)
            assert 'ocsp' not in stat or stat['ocsp'] == "no response sent", f'{stat}'
        else:
            stat = env.await_ocsp_status(md)
            assert stat['ocsp'] == "successful (0x0)"
            assert stat['verify'] == "0 (ok)"
        stat = env.get_md_status(md)
        if MDTestEnv.lacks_ocsp():
            assert stat["stapling"]
            pkey = 'rsa'
            assert 'ocsp' not in stat["cert"][pkey], f'{stat}'
        else:
            assert stat["stapling"]
            pkey = 'rsa'
            assert stat["cert"][pkey]["ocsp"]["status"] == "good"
            assert stat["cert"][pkey]["ocsp"]["valid"]
        #
        # turn stapling off (explicitly) again, should disappear
        self.configure_httpd(env, md, "MDStapling off").install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.get_ocsp_status(md)
        if MDTestEnv.lacks_ocsp():
            assert 'ocsp' not in stat or stat['ocsp'] == "no response sent", f'{stat}'
        else:
            assert stat['ocsp'] == "no response sent"
        stat = env.get_md_status(md)
        assert not stat["stapling"]
        
    # MD with stapling on/off and mod_ssl stapling on
    # expect to see stapling response in all cases
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_801_002(self, env):
        md = self.mdA
        self.configure_httpd(env, md, ssl_stapling=True).install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.get_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" if \
            env.ssl_module == "mod_ssl" else "no response sent"
        stat = env.get_md_status(md)
        assert not stat["stapling"]
        #
        # turn stapling on, wait for it to appear in connections
        self.configure_httpd(env, md, "MDStapling on", ssl_stapling=True).install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        stat = env.get_md_status(md)
        assert stat["stapling"]
        pkey = 'rsa'
        assert stat["cert"][pkey]["ocsp"]["status"] == "good"
        assert stat["cert"][pkey]["ocsp"]["valid"]
        #
        # turn stapling off (explicitly) again, should disappear
        self.configure_httpd(env, md, "MDStapling off", ssl_stapling=True).install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.get_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" if \
            env.ssl_module == "mod_ssl" else "no response sent"
        stat = env.get_md_status(md)
        assert not stat["stapling"]
        
    # 2 MDs, one with md stapling on, one with default (off)
    def test_md_801_003(self, env):
        md_a = self.mdA
        md_b = self.mdB
        conf = self.configure_httpd(env)
        conf.add("""
            <MDomain %s>
                MDStapling on
            </MDomain>
            <MDomain %s>
            </MDomain>
            """ % (md_a, md_b))
        conf.add_vhost(md_a)
        conf.add_vhost(md_b)
        conf.install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        # mdA has stapling
        if MDTestEnv.lacks_ocsp():
            stat = env.get_ocsp_status(md_a)
            assert 'ocsp' not in stat or stat['ocsp'] == "no response sent", f'{stat}'
        else:
            stat = env.await_ocsp_status(md_a)
            assert stat['ocsp'] == "successful (0x0)"
        assert stat['verify'] == "0 (ok)"
        stat = env.get_md_status(md_a)
        assert stat["stapling"]
        if not MDTestEnv.lacks_ocsp():
            pkey = 'rsa'
            assert stat["cert"][pkey]["ocsp"]["status"] == "good"
            assert stat["cert"][pkey]["ocsp"]["valid"]
        # mdB has no stapling
        if not MDTestEnv.lacks_ocsp():
            stat = env.get_ocsp_status(md_b)
            assert stat['ocsp'] == "no response sent"
        stat = env.get_md_status(md_b)
        assert not stat["stapling"]

    # 2 MDs, md stapling on+off, ssl stapling on
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_801_004(self, env):
        md_a = self.mdA
        md_b = self.mdB
        conf = self.configure_httpd(env, ssl_stapling=True)
        conf.add("""
            <MDomain %s>
                MDStapling on
            </MDomain>
            <MDomain %s>
            </MDomain>
            """ % (md_a, md_b))
        conf.add_vhost(md_a)
        conf.add_vhost(md_b)
        conf.install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        # mdA has stapling
        stat = env.await_ocsp_status(md_a)
        assert stat['ocsp'] == "successful (0x0)"
        assert stat['verify'] == "0 (ok)"
        stat = env.get_md_status(md_a)
        assert stat["stapling"]
        pkey = 'rsa'
        assert stat["cert"][pkey]["ocsp"]["status"] == "good"
        assert stat["cert"][pkey]["ocsp"]["valid"]
        # mdB has no md stapling, but mod_ssl kicks in
        stat = env.get_ocsp_status(md_b)
        assert stat['ocsp'] == "successful (0x0)" if \
            env.ssl_module == "mod_ssl" else "no response sent"
        stat = env.get_md_status(md_b)
        assert not stat["stapling"]

    # MD, check that restart leaves response unchanged, reconfigure keep interval, 
    # should remove the file on restart and get a new one
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_801_005(self, env):
        # TODO: mod_watchdog seems to have problems sometimes with fast restarts
        # turn stapling on, wait for it to appear in connections
        md = self.mdA
        self.configure_httpd(env, md, "MDStapling on").install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        # fine the file where the ocsp response is stored
        dirpath = os.path.join(env.store_dir, 'ocsp', md)
        files = os.listdir(dirpath)
        ocsp_file = None
        for name in files:
            if name.startswith("ocsp-"):
                ocsp_file = os.path.join(dirpath, name)
        assert ocsp_file
        mtime1 = os.path.getmtime(ocsp_file)
        # wait a sec, restart and check that file does not change
        time.sleep(1)
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        mtime2 = os.path.getmtime(ocsp_file)
        assert mtime1 == mtime2
        # configure a keep time of 1 second, restart, the file is gone
        # (which is a side effec that we load it before the cleanup removes it.
        #  since it was valid, no new one needed fetching
        self.configure_httpd(env, md, """
            MDStapling on
            MDStaplingKeepResponse 1s
            """).install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)"
        assert not os.path.exists(ocsp_file)
        # if we restart again, a new file needs to appear
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)"
        mtime3 = os.path.getmtime(ocsp_file)
        assert mtime1 != mtime3

    # MD, check that stapling renew window works. Set a large window
    # that causes response to be retrieved all the time.
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_801_006(self, env):
        # turn stapling on, wait for it to appear in connections
        md = self.mdA
        self.configure_httpd(env, md, "MDStapling on").install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        # fine the file where the ocsp response is stored
        dirpath = os.path.join(env.store_dir, 'ocsp', md)
        files = os.listdir(dirpath)
        ocsp_file = None
        for name in files:
            if name.startswith("ocsp-"):
                ocsp_file = os.path.join(dirpath, name)
        assert ocsp_file
        mtime1 = os.path.getmtime(ocsp_file)
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        # wait a sec, restart and check that file does not change
        time.sleep(1)
        mtime2 = os.path.getmtime(ocsp_file)
        assert mtime1 == mtime2
        # configure a renew window of 10 days, restart, larger than any life time.
        self.configure_httpd(env, md, """
            MDStapling on
            MDStaplingRenewWindow 10d
            """).install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)"
        # wait a sec, restart and check that file does change
        time.sleep(1)
        mtime3 = os.path.getmtime(ocsp_file)
        assert mtime1 != mtime3

    # MD, make a MDomain with static files, check that stapling works
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_801_007(self, env):
        # turn stapling on, wait for it to appear in connections
        md = self.mdA
        conf = self.configure_httpd(env)
        conf.add("""
            <MDomain %s>
                MDCertificateKeyFile %s
                MDCertificateFile %s
                MDStapling on
            </MDomain>
            """ % (md, env.store_domain_file(md, 'privkey.pem'),
                   env.store_domain_file(md, 'pubcert.pem')))
        conf.add_vhost(md)
        conf.install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        # fine the file where the ocsp response is stored
        dirpath = os.path.join(env.store_dir, 'ocsp', md)
        files = os.listdir(dirpath)
        ocsp_file = None
        for name in files:
            if name.startswith("ocsp-"):
                ocsp_file = os.path.join(dirpath, name)
        assert ocsp_file

    # Use certificate files in direct config, check that stapling works
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_801_008(self, env):
        # turn stapling on, wait for it to appear in connections
        md = self.mdA
        conf = self.configure_httpd(env)
        conf.add("MDStapling on")
        conf.start_vhost(md)
        conf.add_certificate(env.store_domain_file(md, 'pubcert.pem'),
                             env.store_domain_file(md, 'privkey.pem'))
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        # fine the file where the ocsp response is stored
        dirpath = os.path.join(env.store_dir, 'ocsp', 'other')
        files = os.listdir(dirpath)
        ocsp_file = None
        for name in files:
            if name.startswith("ocsp-"):
                ocsp_file = os.path.join(dirpath, name)
        assert ocsp_file

    # Turn on stapling for a certificate without OCSP responder and issuer
    # (certificates without issuer prevent mod_ssl asking around for stapling)
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_801_009(self, env):
        md = self.mdA
        domains = [md]
        testpath = os.path.join(env.gen_dir, 'test_801_009')
        env.mkpath(testpath)
        # cert that is 30 more days valid
        creds = env.create_self_signed_cert(CertificateSpec(domains=domains),
                                            valid_from=timedelta(days=-60),
                                            valid_to=timedelta(days=30),
                                            serial=801009)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        creds.save_cert_pem(cert_file)
        creds.save_pkey_pem(pkey_file)
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add("MDCertificateFile %s" % cert_file)
        conf.add("MDCertificateKeyFile %s" % pkey_file)
        conf.add("MDStapling on")
        conf.end_md()
        conf.add_vhost(md)
        conf.install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        time.sleep(1)
        stat = env.get_ocsp_status(md)
        assert stat['ocsp'] == "no response sent" 

    # Turn on stapling for an MDomain not used in any virtualhost
    # There was a crash in server-status in this case
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_801_010(self, env):
        env.clear_ocsp_store()
        md = self.mdA
        domains = [md]
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add("MDStapling on")
        conf.end_md()
        conf.install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.get_server_status()
        assert stat

    # add 7 mdomains that need OCSP stapling, once activated
    # we use at max 6 connections against the same OCSP responder and
    # this triggers our use of curl_multi_perform with iterative
    # scheduling.
    # This checks the mistaken assert() reported in
    # <https://bz.apache.org/bugzilla/show_bug.cgi?id=65567>
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_801_011(self, env):
        domains = [ f'test-801-011-{i}-{env.DOMAIN_SUFFIX}' for i in range(7)]
        self.configure_httpd(env, domains, """
            MDStapling on
            LogLevel md:trace2 ssl:warn
            """).install()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        assert env.await_completion(domains, restart=False, timeout=120)
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        # now the certs are installed and ocsp will be retrieved
        time.sleep(1)
        for domain in domains:
            stat = env.await_ocsp_status(domain)
            assert stat['ocsp'] == "successful (0x0)"
            assert stat['verify'] == "0 (ok)"
