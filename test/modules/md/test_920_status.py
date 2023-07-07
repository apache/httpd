# test mod_md status resources

import os
import re
import time

import pytest

from .md_conf import MDConf
from shutil import copyfile

from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestStatus:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='default')
        env.check_acme()
        env.clear_store()

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    # simple MD, drive it, check status before activation
    def test_md_920_001(self, env):
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add_md(domains)
        conf.add_vhost(domain)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain], restart=False)
        # we started without a valid certificate, so we expect /.httpd/certificate-status
        # to not give information about one and - since we waited for the ACME signup
        # to complete - to give information in 'renewal' about the new cert.
        status = env.get_certificate_status(domain)
        assert 'sha256-fingerprint' not in status
        assert 'valid' not in status
        assert 'renewal' in status
        assert 'valid' in status['renewal']['cert']
        assert 'sha256-fingerprint' in status['renewal']['cert']['rsa']
        # restart and activate
        # once activated, the staging must be gone and attributes exist for the active cert
        assert env.apache_restart() == 0
        status = env.get_certificate_status(domain)
        assert 'renewal' not in status
        assert 'sha256-fingerprint' in status['rsa']
        assert 'valid' in status['rsa']
        assert 'from' in status['rsa']['valid']

    # simple MD, drive it, manipulate staged credentials and check status
    def test_md_920_002(self, env):
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add_md(domains)
        conf.add_vhost(domain)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain], restart=False)
        # copy a real certificate from LE over to staging
        staged_cert = os.path.join(env.store_dir, 'staging', domain, 'pubcert.pem')
        real_cert = os.path.join(env.test_dir, '../modules/md/data', 'test_920', '002.pubcert')
        assert copyfile(real_cert, staged_cert)
        status = env.get_certificate_status(domain)
        # status shows the copied cert's properties as staged
        assert 'renewal' in status
        assert 'Thu, 29 Aug 2019 16:06:35 GMT' == status['renewal']['cert']['rsa']['valid']['until']
        assert 'Fri, 31 May 2019 16:06:35 GMT' == status['renewal']['cert']['rsa']['valid']['from']
        assert '03039C464D454EDE79FCD2CAE859F668F269' == status['renewal']['cert']['rsa']['serial']
        assert 'sha256-fingerprint' in status['renewal']['cert']['rsa']

    # test if switching status off has effect
    def test_md_920_003(self, env):
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add_md(domains)
        conf.add("MDCertificateStatus off")
        conf.add_vhost(domain)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain], restart=False)
        status = env.get_certificate_status(domain)
        assert not status

    def test_md_920_004(self, env):
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add_md(domains)
        conf.add("MDCertificateStatus off")
        conf.add_vhost(domain)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        status = env.get_md_status("")
        assert "version" in status
        assert "managed-domains" in status
        assert 1 == len(status["managed-domains"])

    # get the status of a domain on base server
    def test_md_920_010(self, env):
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env, std_vhosts=False, std_ports=False, text=f"""
MDBaseServer on
MDPortMap http:- https:{env.https_port}

ServerName {domain}
<IfModule ssl_module>
SSLEngine on
</IfModule>
<IfModule tls_module>
TLSListen {env.https_port}
TLSStrictSNI off
</IfModule>
Protocols h2 http/1.1 acme-tls/1

<Location "/server-status">
    SetHandler server-status
</Location>
<Location "/md-status">
    SetHandler md-status
</Location>
<VirtualHost *:{env.http_port}>
  SSLEngine off
</VirtualHost>
            """)
        conf.add_md(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain], restart=False,
                                    via_domain=env.http_addr, use_https=False)
        status = env.get_md_status("", via_domain=env.http_addr, use_https=False)
        assert "version" in status
        assert "managed-domains" in status
        assert 1 == len(status["managed-domains"])
        # get the html page
        status = env.get_server_status(via_domain=env.http_addr, use_https=False)
        assert re.search(r'<h3>Managed Certificates</h3>', status, re.MULTILINE)
        # get the ascii summary
        status = env.get_server_status(query="?auto", via_domain=env.http_addr, use_https=False)
        m = re.search(r'ManagedCertificatesTotal: (\d+)', status, re.MULTILINE)
        assert m, status
        assert int(m.group(1)) == 1
        m = re.search(r'ManagedCertificatesOK: (\d+)', status, re.MULTILINE)
        assert int(m.group(1)) == 0
        m = re.search(r'ManagedCertificatesRenew: (\d+)', status, re.MULTILINE)
        assert int(m.group(1)) == 1
        m = re.search(r'ManagedCertificatesErrored: (\d+)', status, re.MULTILINE)
        assert int(m.group(1)) == 0
        m = re.search(r'ManagedCertificatesReady: (\d+)', status, re.MULTILINE)
        assert int(m.group(1)) == 1

    def test_md_920_011(self, env):
        # MD with static cert files in base server, see issue #161
        domain = self.test_domain
        domains = [domain, 'www.%s' % domain]
        testpath = os.path.join(env.gen_dir, 'test_920_011')
        # cert that is only 10 more days valid
        env.create_self_signed_cert(domains, {"notBefore": -70, "notAfter": 20},
                                    serial=920011, path=testpath)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        assert os.path.exists(cert_file)
        assert os.path.exists(pkey_file)
        conf = MDConf(env, std_vhosts=False, std_ports=False, text=f"""
        MDBaseServer on
        MDPortMap http:- https:{env.https_port}

        ServerName {domain}
        <IfModule ssl_module>
        SSLEngine on
        </IfModule>
        <IfModule tls_module>
        TLSListen {env.https_port}
        TLSStrictSNI off
        </IfModule>
        Protocols h2 http/1.1 acme-tls/1

        <Location "/server-status">
            SetHandler server-status
        </Location>
        <Location "/md-status">
            SetHandler md-status
        </Location>
            """)
        conf.start_md(domains)
        conf.add(f"MDCertificateFile {cert_file}")
        conf.add(f"MDCertificateKeyFile {pkey_file}")
        conf.end_md()
        conf.start_vhost([env.http_addr], port=env.http_port)
        conf.add("SSLEngine off")
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        status = env.get_md_status(domain, via_domain=env.http_addr, use_https=False)
        assert status
        assert 'renewal' not in status
        print(status)
        assert status['state'] == env.MD_S_COMPLETE
        assert status['renew-mode'] == 1  # manual

    # MD with 2 certificates
    def test_md_920_020(self, env):
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDStapling on")
        conf.add("MDPrivateKeys secp256r1 RSA")
        conf.add_md(domains)
        conf.add_vhost(domain)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain], restart=False)
        # In the stats JSON, we expect 2 certificates under 'renewal'
        stat = env.get_md_status(domain)
        assert 'renewal' in stat
        assert 'cert' in stat['renewal']
        assert 'rsa' in stat['renewal']['cert']
        assert 'secp256r1' in stat['renewal']['cert']
        # In /.httpd/certificate-status 'renewal' we expect 2 certificates
        status = env.get_certificate_status(domain)
        assert 'renewal' in status
        assert 'cert' in status['renewal']
        assert 'secp256r1' in status['renewal']['cert']
        assert 'rsa' in status['renewal']['cert']
        # restart and activate
        # once activated, certs are listed in status
        assert env.apache_restart() == 0
        stat = env.get_md_status(domain)
        assert 'cert' in stat
        assert 'valid' in stat['cert']
        for ktype in ['rsa', 'secp256r1']:
            assert ktype in stat['cert']
            if env.acme_server == 'boulder':
                assert 'ocsp' in stat['cert'][ktype]
        #
        env.httpd_error_log.ignore_recent(
            matches = [
                r'.*certificate with serial \w+ has no OCSP responder URL.*'
            ]
        )
