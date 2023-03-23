# test mod_md acme terms-of-service handling

from shutil import copyfile

import pytest

from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_a2md(), reason="no a2md available")
@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestRegAdd:

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env):
        env.clear_store()

    # test case: list empty store
    def test_md_120_000(self, env):
        assert env.a2md(["list"]).json == env.EMPTY_JOUT

    # test case: list two managed domains
    def test_md_120_001(self, env):
        domains = [ 
            ["test120-001.com", "test120-001a.com", "test120-001b.com"],
            ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        ]
        for dns in domains:
            assert env.a2md(["add"] + dns).exit_code == 0
        #
        # list all store content
        jout = env.a2md(["list"]).json
        assert len(jout['output']) == len(domains)
        domains.reverse()
        for i in range(0, len(jout['output'])):
            env.check_json_contains(jout['output'][i], {
                "name": domains[i][0],
                "domains": domains[i],
                "contacts": [],
                "ca": {
                    "urls": [env.acme_url],
                    "proto": "ACME"
                },
                "state": env.MD_S_INCOMPLETE
            })
        # list md by name
        for dns in ["test120-001.com", "greenbytes2.de"]:
            md = env.a2md(["list", dns]).json['output'][0]
            assert md['name'] == dns

    # test case: validate md state in store
    def test_md_120_002(self, env):
        # check: md without pkey/cert -> INCOMPLETE
        domain = f"test1.{env.http_tld}"
        assert env.a2md(["add", domain]).exit_code == 0
        assert env.a2md(["update", domain, "contacts", "admin@" + domain]).exit_code == 0
        assert env.a2md(["update", domain, "agreement", env.acme_tos]).exit_code == 0
        assert env.a2md(["list", domain]).json['output'][0]['state'] == env.MD_S_INCOMPLETE
        # check: valid pkey/cert -> COMPLETE
        cred = env.get_credentials_for_name(domain)[0]
        copyfile(cred.pkey_file, env.store_domain_file(domain, 'privkey.pem'))
        copyfile(cred.cert_file, env.store_domain_file(domain, 'pubcert.pem'))
        assert env.a2md(["list", domain]).json['output'][0]['state'] == env.MD_S_COMPLETE
        # check: expired cert -> EXPIRED
        cred = env.get_credentials_for_name(f"expired.{env.http_tld}")[0]
        copyfile(cred.pkey_file, env.store_domain_file(domain, 'privkey.pem'))
        copyfile(cred.cert_file, env.store_domain_file(domain, 'pubcert.pem'))
        out = env.a2md(["list", domain]).json['output'][0]
        assert out['state'] == env.MD_S_INCOMPLETE
        assert out['renew'] is True

    # test case: broken cert file
    def test_md_120_003(self, env):
        domain = f"test1.{env.http_tld}"
        assert env.a2md(["add", domain]).exit_code == 0
        assert env.a2md(["update", domain, "contacts", "admin@" + domain]).exit_code == 0
        assert env.a2md(["update", domain, "agreement", env.acme_tos]).exit_code == 0
        # check: valid pkey/cert -> COMPLETE
        cred = env.get_credentials_for_name(domain)[0]
        copyfile(cred.pkey_file, env.store_domain_file(domain, 'privkey.pem'))
        copyfile(cred.cert_file, env.store_domain_file(domain, 'pubcert.pem'))
        assert env.a2md(["list", domain]).json['output'][0]['state'] == env.MD_S_COMPLETE
        # check: replace cert by broken file -> ERROR
        with open(env.store_domain_file(domain, 'pubcert.pem'), 'w') as fd:
            fd.write("dummy\n")
        assert env.a2md(["list", domain]).json['output'][0]['state'] == env.MD_S_INCOMPLETE
