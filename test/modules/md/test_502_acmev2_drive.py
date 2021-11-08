# test driving the ACMEv2 protocol

import base64
import json
import os.path
import re
import time

import pytest

from .md_conf import MDConf, MDConf
from .md_cert_util import MDCertUtil
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_a2md(), reason="no a2md available")
@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestDrivev2:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='default')
        env.check_acme()
        env.APACHE_CONF_SRC = "data/test_drive"
        MDConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        MDConf(env).install()
        self.test_domain = env.get_request_domain(request)

    # --------- invalid precondition ---------

    def test_md_502_000(self, env):
        # test case: md without contact info
        domain = self.test_domain
        name = "www." + domain
        assert env.a2md(["add", name]).exit_code == 0
        r = env.a2md(["drive", name])
        assert r.exit_code == 1
        assert re.search("No contact information", r.stderr)

    def test_md_502_001(self, env):
        # test case: md with contact, but without TOS
        domain = self.test_domain
        name = "www." + domain
        assert env.a2md(["add", name]).exit_code == 0
        assert env.a2md( 
            ["update", name, "contacts", "admin@test1.not-forbidden.org"]
            ).exit_code == 0
        r = env.a2md(["drive", name])
        assert r.exit_code == 1
        assert re.search("the CA requires you to accept the terms-of-service as specified in ", r.stderr)

    # test_102 removed, was based on false assumption
    def test_md_502_003(self, env):
        # test case: md with unknown protocol FOO
        domain = self.test_domain
        name = "www." + domain
        self._prepare_md(env, [name])
        assert env.a2md(
            ["update", name, "ca", env.acme_url, "FOO"]
            ).exit_code == 0
        r = env.a2md(["drive", name])
        assert r.exit_code == 1
        assert re.search("Unknown CA protocol", r.stderr)

    # --------- driving OK ---------

    def test_md_502_100(self, env):
        # test case: md with one domain
        domain = self.test_domain
        name = "www." + domain
        self._prepare_md(env, [name])
        assert env.apache_restart() == 0
        # drive
        prev_md = env.a2md(["list", name]).json['output'][0]
        r = env.a2md(["-vv", "drive", "-c", "http-01", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        env.check_md_credentials([name])
        self._check_account_key(env, name)

        # check archive content
        store_md = json.loads(open(env.store_archived_file(name, 1, 'md.json')).read())
        for f in ['name', 'ca', 'domains', 'contacts', 'renew-mode', 'renew-window', 'must-staple']:
            assert store_md[f] == prev_md[f]
        
        # check file system permissions:
        env.check_file_permissions(name)
        # check: challenges removed
        env.check_dir_empty(env.store_challenges())
        # check how the challenge resources are answered in sevceral combinations 
        r = env.get_meta(domain, "/.well-known/acme-challenge", False)
        assert r.exit_code == 0
        assert r.response['status'] == 404
        r = env.get_meta(domain, "/.well-known/acme-challenge/", False)
        assert r.exit_code == 0
        assert r.response['status'] == 404
        r = env.get_meta(domain, "/.well-known/acme-challenge/123", False)
        assert r.exit_code == 0
        assert r.response['status'] == 404
        assert r.exit_code == 0
        cdir = os.path.join(env.store_challenges(), domain)
        os.makedirs(cdir)
        open(os.path.join(cdir, 'acme-http-01.txt'), "w").write("content-of-123")
        r = env.get_meta(domain, "/.well-known/acme-challenge/123", False)
        assert r.exit_code == 0
        assert r.response['status'] == 200
        assert r.response['header']['content-length'] == '14'

    def test_md_502_101(self, env):
        # test case: md with 2 domains
        domain = self.test_domain
        name = "www." + domain
        self._prepare_md(env, [name, "test." + domain])
        assert env.apache_restart() == 0
        # drive
        r = env.a2md(["-vv", "drive", "-c", "http-01", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        env.check_md_credentials([name, "test." + domain])

    # test_502_102 removed, as accounts without ToS are not allowed in ACMEv2

    def test_md_502_103(self, env):
        # test case: md with one domain, ACME account and TOS agreement on server
        # setup: create md
        domain = self.test_domain
        name = "www." + domain
        assert env.a2md(["add", name]).exit_code == 0
        assert env.a2md(["update", name, "contacts", "admin@" + domain]).exit_code == 0
        assert env.apache_restart() == 0
        # setup: create account on server
        r = env.a2md(["-t", "accepted", "acme", "newreg", "admin@" + domain], raw=True)
        assert r.exit_code == 0
        acct = re.match("registered: (.*)$", r.stdout).group(1)
        # setup: link md to account
        assert env.a2md(["update", name, "account", acct]).exit_code == 0
        # drive
        r = env.a2md(["-vv", "drive", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        env.check_md_credentials([name])

    # test_502_104 removed, order are created differently in ACMEv2

    def test_md_502_105(self, env):
        # test case: md with one domain, local TOS agreement and ACME account that is deleted (!) on server
        # setup: create md
        domain = self.test_domain
        name = "www." + domain
        self._prepare_md(env, [name])
        assert env.apache_restart() == 0
        # setup: create account on server
        r = env.a2md(["-t", "accepted", "acme", "newreg", "test@" + domain], raw=True)
        assert r.exit_code == 0
        acct = re.match("registered: (.*)$", r.stdout).group(1)
        # setup: link md to account
        assert env.a2md(["update", name, "account", acct]).exit_code == 0
        # setup: delete account on server
        assert env.a2md(["acme", "delreg", acct]).exit_code == 0
        # drive
        r = env.a2md(["drive", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        env.check_md_credentials([name])

    def test_md_502_107(self, env):
        # test case: drive again on COMPLETE md, then drive --force
        # setup: prepare md in store
        domain = self.test_domain
        name = "www." + domain
        self._prepare_md(env, [name])
        assert env.apache_restart() == 0
        # drive
        r = env.a2md(["-vv", "drive", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        env.check_md_credentials([name])
        orig_cert = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))

        # drive again
        assert env.a2md(["-vv", "drive", name]).exit_code == 0
        env.check_md_credentials([name])
        cert = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
        # check: cert not changed
        assert cert.same_serial_as(orig_cert)

        # drive --force
        assert env.a2md(["-vv", "drive", "--force", name]).exit_code == 0
        env.check_md_credentials([name])
        cert = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
        # check: cert not changed
        assert not cert.same_serial_as(orig_cert)
        # check: previous cert was archived
        cert = MDCertUtil(env.store_archived_file(name, 2, 'pubcert.pem'))
        assert cert.same_serial_as(orig_cert)

    def test_md_502_108(self, env):
        # test case: drive via HTTP proxy
        domain = self.test_domain
        name = "www." + domain
        self._prepare_md(env, [name])
        conf = MDConf(env, proxy=True)
        conf.add('LogLevel proxy:trace8')
        conf.install()
        assert env.apache_restart() == 0

        # drive it, with wrong proxy url -> FAIL
        r = env.a2md(["-p", "http://localhost:1", "drive", name])
        assert r.exit_code == 1
        assert "Connection refused" in r.stderr

        # drive it, working proxy url -> SUCCESS
        proxy_url = f"http://localhost:{env.proxy_port}"
        r = env.a2md(["-vv", "-p", proxy_url, "drive", name])
        assert 0 == r.exit_code, "a2md failed: {0}".format(r.stderr)
        env.check_md_credentials([name])

    def test_md_502_109(self, env):
        # test case: redirect on SSL-only domain
        # setup: prepare config
        domain = self.test_domain
        name = "www." + domain
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md([name])
        conf.add_vhost(name, port=env.http_port, doc_root="htdocs/test")
        conf.add_vhost(name, doc_root="htdocs/test")
        conf.install()
        # setup: create resource files
        self._write_res_file(os.path.join(env.server_docs_dir, "test"), "name.txt", name)
        self._write_res_file(os.path.join(env.server_docs_dir), "name.txt", "not-forbidden.org")
        assert env.apache_restart() == 0

        # drive it
        assert env.a2md(["drive", name]).exit_code == 0
        assert env.apache_restart() == 0
        # test HTTP access - no redirect
        jdata = env.get_json_content(f"test1.{env.http_tld}", "/alive.json", use_https=False)
        assert jdata['host']== "test1"
        assert env.get_content(name, "/name.txt", use_https=False) == name
        r = env.get_meta(name, "/name.txt", use_https=False)
        assert int(r.response['header']['content-length']) == len(name)
        assert "Location" not in r.response['header']
        # test HTTPS access
        assert env.get_content(name, "/name.txt", use_https=True) == name

        # test HTTP access again -> redirect to default HTTPS port
        conf.add("MDRequireHttps temporary")
        conf.install()
        assert env.apache_restart() == 0
        r = env.get_meta(name, "/name.txt", use_https=False)
        assert r.response['status'] == 302
        exp_location = "https://%s/name.txt" % name
        assert r.response['header']['location'] == exp_location
        # should not see this
        assert 'strict-transport-security' not in r.response['header']
        # test default HTTP vhost -> still no redirect
        jdata = env.get_json_content(f"test1.{env.http_tld}", "/alive.json", use_https=False)
        assert jdata['host']== "test1"
        r = env.get_meta(name, "/name.txt", use_https=True)
        # also not for this
        assert 'strict-transport-security' not in r.response['header']

        # test HTTP access again -> redirect permanent
        conf.add("MDRequireHttps permanent")
        conf.install()
        assert env.apache_restart() == 0
        r = env.get_meta(name, "/name.txt", use_https=False)
        assert r.response['status'] == 301
        exp_location = "https://%s/name.txt" % name
        assert r.response['header']['location'] == exp_location
        assert 'strict-transport-security' not in r.response['header']
        # should see this
        r = env.get_meta(name, "/name.txt", use_https=True)
        assert r.response['header']['strict-transport-security'] == 'max-age=15768000'

    def test_md_502_110(self, env):
        # test case: SSL-only domain, override headers generated by mod_md 
        # setup: prepare config
        domain = self.test_domain
        name = "www." + domain
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add("MDRequireHttps permanent")
        conf.add_md([name])
        conf.add_vhost(name, port=env.http_port)
        conf.add_vhost(name)
        conf.install()
        assert env.apache_restart() == 0
        # drive it
        assert env.a2md(["drive", name]).exit_code == 0
        assert env.apache_restart() == 0

        # test override HSTS header
        conf.add('Header set Strict-Transport-Security "max-age=10886400; includeSubDomains; preload"')
        conf.install()
        assert env.apache_restart() == 0
        r = env.get_meta(name, "/name.txt", use_https=True)
        assert 'strict-transport-security' in r.response['header'], r.response['header']
        assert r.response['header']['strict-transport-security'] == \
               'max-age=10886400; includeSubDomains; preload'

        # test override Location header
        conf.add('  Redirect /a /name.txt')
        conf.add('  Redirect seeother /b /name.txt')
        conf.install()
        assert env.apache_restart() == 0
        # check: default redirect by mod_md still works
        exp_location = "https://%s/name.txt" % name
        r = env.get_meta(name, "/name.txt", use_https=False)
        assert r.response['status'] == 301
        assert r.response['header']['location'] == exp_location
        # check: redirect as given by mod_alias
        exp_location = "https://%s/a" % name
        r = env.get_meta(name, "/a", use_https=False)
        assert r.response['status'] == 301    # FAIL: mod_alias generates Location header instead of mod_md
        assert r.response['header']['location'] == exp_location

    def test_md_502_111(self, env):
        # test case: vhost with parallel HTTP/HTTPS, check mod_alias redirects
        # setup: prepare config
        domain = self.test_domain
        name = "www." + domain
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md([name])
        conf.add("  LogLevel alias:debug")
        conf.add_vhost(name, port=env.http_port)
        conf.add_vhost(name)
        conf.install()
        assert env.apache_restart() == 0
        # drive it
        r = env.a2md(["-v", "drive", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        assert env.apache_restart() == 0

        # setup: place redirect rules
        conf.add('  Redirect /a /name.txt')
        conf.add('  Redirect seeother /b /name.txt')
        conf.install()
        assert env.apache_restart() == 0
        # check: redirects on HTTP
        exp_location = "http://%s:%s/name.txt" % (name, env.http_port)
        r = env.get_meta(name, "/a", use_https=False)
        assert r.response['status'] == 302
        assert r.response['header']['location'] == exp_location
        r = env.get_meta(name, "/b", use_https=False)
        assert r.response['status'] == 303
        assert r.response['header']['location'] == exp_location
        # check: redirects on HTTPS
        exp_location = "https://%s:%s/name.txt" % (name, env.https_port)
        r = env.get_meta(name, "/a", use_https=True)
        assert r.response['status'] == 302
        assert r.response['header']['location'] == exp_location     # FAIL: expected 'https://...' but found 'http://...'
        r = env.get_meta(name, "/b", use_https=True)
        assert r.response['status'] == 303
        assert r.response['header']['location'] == exp_location

    def test_md_502_120(self, env):
        # test case: NP dereference reported by Daniel Caminada <daniel.caminada@ergon.ch>
        domain = self.test_domain
        name = "www." + domain
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md([name])
        conf.add_vhost(name)
        conf.install()
        assert env.apache_restart() == 0
        env.run(["openssl", "s_client",
                 f"-connect", "localhost:{env.https_port}",
                 "-servername", "example.com", "-crlf"
                 ], intext="GET https:// HTTP/1.1\nHost: example.com\n\n")
        assert env.apache_restart() == 0

    # --------- critical state change -> drive again ---------

    def test_md_502_200(self, env):
        # test case: add dns name on existing valid md
        # setup: create md in store
        domain = self.test_domain
        name = "www." + domain
        self._prepare_md(env, [name])
        assert env.apache_restart() == 0
        # setup: drive it
        r = env.a2md(["drive", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        old_cert = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
        # setup: add second domain
        assert env.a2md(["update", name, "domains", name, "test." + domain]).exit_code == 0
        # drive
        r = env.a2md(["-vv", "drive", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        # check new cert
        env.check_md_credentials([name, "test." + domain])
        new_cert = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
        assert not old_cert.same_serial_as(new_cert.get_serial)

    @pytest.mark.parametrize("renew_window,test_data_list", [
        ("14d", [
            {"valid": {"notBefore": -5,   "notAfter": 180}, "renew": False},
            {"valid": {"notBefore": -200, "notAfter": 15}, "renew": False},
            {"valid": {"notBefore": -200, "notAfter": 13}, "renew": True},
        ]),
        ("30%", [
            {"valid": {"notBefore": -0,   "notAfter": 180}, "renew": False},
            {"valid": {"notBefore": -120, "notAfter": 60}, "renew": False},
            {"valid": {"notBefore": -126, "notAfter": 53}, "renew": True},
        ])
    ])
    def test_md_502_201(self, env, renew_window, test_data_list):
        # test case: trigger cert renew when entering renew window 
        # setup: prepare COMPLETE md
        domain = self.test_domain
        name = "www." + domain
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_renew_window(renew_window)
        conf.add_md([name])
        conf.install()
        assert env.apache_restart() == 0
        assert env.a2md(["list", name]).json['output'][0]['state'] == env.MD_S_INCOMPLETE
        # setup: drive it
        r = env.a2md(["drive", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        cert1 = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
        assert env.a2md(["list", name]).json['output'][0]['state'] == env.MD_S_COMPLETE

        # replace cert by self-signed one -> check md status
        print("TRACE: start testing renew window: %s" % renew_window)
        for tc in test_data_list:
            print("TRACE: create self-signed cert: %s" % tc["valid"])
            env.create_self_signed_cert([name], tc["valid"])
            cert2 = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
            assert not cert2.same_serial_as(cert1)
            md = env.a2md(["list", name]).json['output'][0]
            assert md["renew"] == tc["renew"], \
                "Expected renew == {} indicator in {}, test case {}".format(tc["renew"], md, tc)

    @pytest.mark.parametrize("key_type,key_params,exp_key_length", [
        ("RSA", [2048], 2048),
        ("RSA", [3072], 3072),
        ("RSA", [4096], 4096),
        ("Default", [], 2048)
    ])
    def test_md_502_202(self, env, key_type, key_params, exp_key_length):
        # test case: specify RSA key length and verify resulting cert key 
        # setup: prepare md
        domain = self.test_domain
        name = "www." + domain
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_private_key(key_type, key_params)
        conf.add_md([name])
        conf.install()
        assert env.apache_restart() == 0
        assert env.a2md(["list", name]).json['output'][0]['state'] == env.MD_S_INCOMPLETE
        # setup: drive it
        r = env.a2md(["-vv", "drive", name])
        assert r.exit_code == 0, "drive for MDPrivateKeys {} {}: {}".format(key_type, key_params, r.stderr)
        assert env.a2md(["list", name]).json['output'][0]['state'] == env.MD_S_COMPLETE
        # check cert key length
        cert = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
        assert cert.get_key_length() == exp_key_length

    # test_502_203 removed, as ToS agreement is not really checked in ACMEv2

    # --------- non-critical state change -> keep data ---------

    def test_md_502_300(self, env):
        # test case: remove one domain name from existing valid md
        # setup: create md in store
        domain = self.test_domain
        name = "www." + domain
        self._prepare_md(env, [name, "test." + domain, "xxx." + domain])
        assert env.apache_restart() == 0
        # setup: drive it
        r = env.a2md(["drive", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        old_cert = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
        # setup: remove one domain
        assert env.a2md(["update", name, "domains"] + [name, "test." + domain]).exit_code == 0
        # drive
        assert env.a2md(["-vv", "drive", name]).exit_code == 0
        # compare cert serial
        new_cert = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
        assert old_cert.same_serial_as(new_cert)

    def test_md_502_301(self, env):
        # test case: change contact info on existing valid md
        # setup: create md in store
        domain = self.test_domain
        name = "www." + domain
        self._prepare_md(env, [name])
        assert env.apache_restart() == 0
        # setup: drive it
        r = env.a2md(["drive", name])
        assert r.exit_code == 0, "a2md drive failed: {0}".format(r.stderr)
        old_cert = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
        # setup: add second domain
        assert env.a2md(["update", name, "contacts", "test@" + domain]).exit_code == 0
        # drive
        assert env.a2md(["drive", name]).exit_code == 0
        # compare cert serial
        new_cert = MDCertUtil(env.store_domain_file(name, 'pubcert.pem'))
        assert old_cert.same_serial_as(new_cert)

    # --------- network problems ---------

    def test_md_502_400(self, env):
        # test case: server not reachable
        domain = self.test_domain
        name = "www." + domain
        self._prepare_md(env, [name])
        assert env.a2md(
            ["update", name, "ca", "http://localhost:4711/directory"]
            ).exit_code == 0
        # drive
        r = env.a2md(["drive", name])
        assert r.exit_code == 1
        assert r.json['status'] != 0
        assert r.json['description'] == 'Connection refused'

    # --------- _utils_ ---------

    def _prepare_md(self, env, domains):
        assert env.a2md(["add"] + domains).exit_code == 0
        assert env.a2md(
            ["update", domains[0], "contacts", "admin@" + domains[0]]
            ).exit_code == 0
        assert env.a2md( 
            ["update", domains[0], "agreement", env.acme_tos]
            ).exit_code == 0

    def _write_res_file(self, doc_root, name, content):
        if not os.path.exists(doc_root):
            os.makedirs(doc_root)
        open(os.path.join(doc_root, name), "w").write(content)

    RE_MSG_OPENSSL_BAD_DECRYPT = re.compile('.*\'bad decrypt\'.*')

    def _check_account_key(self, env, name):
        # read encryption key
        md_store = json.loads(open(env.path_store_json(), 'r').read())
        encrypt_key = base64.urlsafe_b64decode(str(md_store['key']))
        # check: key file is encrypted PEM
        md = env.a2md(["list", name]).json['output'][0]
        acc = md['ca']['account']
        MDCertUtil.validate_privkey(env.path_account_key(acc), lambda *args: encrypt_key)
