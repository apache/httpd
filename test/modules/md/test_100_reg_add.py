# test mod_md acme terms-of-service handling

import pytest

from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_a2md(), reason="no a2md available")
@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestRegAdd:

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env):
        env.purge_store()

    # test case: add a single dns managed domain
    def test_md_100_000(self, env):
        dns = "greenbytes.de"
        jout1 = env.a2md(["add", dns]).json
        env.check_json_contains(jout1['output'][0], {
            "name": dns,
            "domains": [dns],
            "contacts": [],
            "ca": {
                "urls": [env.acme_url],
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })
        assert env.a2md(["list"]).json == jout1

    # test case: add > 1 dns managed domain
    def test_md_100_001(self, env):
        dns = ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        jout1 = env.a2md(["add"] + dns).json
        env.check_json_contains(jout1['output'][0], {
            "name": dns[0],
            "domains": dns,
            "contacts": [],
            "ca": {
                "urls": [env.acme_url],
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })
        assert env.a2md(["list"]).json == jout1

    # test case: add second managed domain
    def test_md_100_002(self, env):
        dns1 = ["test100-002.com", "test100-002a.com", "test100-002b.com"]
        env.a2md(["add"] + dns1)
        # add second managed domain
        dns2 = ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        jout = env.a2md(["add"] + dns2).json
        # assert: output covers only changed md
        assert len(jout['output']) == 1
        env.check_json_contains(jout['output'][0], {
            "name": dns2[0],
            "domains": dns2,
            "contacts": [],
            "ca": {
                "urls": [env.acme_url],
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })
        assert len(env.a2md(["list"]).json['output']) == 2

    # test case: add existing domain 
    def test_md_100_003(self, env):
        dns = "greenbytes.de"
        assert env.a2md(["add", dns]).exit_code == 0
        assert env.a2md(["add", dns]).exit_code == 1

    # test case: add without CA URL
    def test_md_100_004(self, env):
        dns = "greenbytes.de"
        jout1 = env.run([env.a2md_bin, "-d", env.store_dir, "-j", "add", dns]).json
        assert len(jout1['output']) == 1
        env.check_json_contains(jout1['output'][0], {
            "name": dns,
            "domains": [dns],
            "contacts": [],
            "ca": {
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })
        assert env.a2md(["list"]).json == jout1

    # test case: add with invalid DNS
    @pytest.mark.parametrize("invalid_dns", [
        "tld", "white sp.ace", "invalid.*.wildcard.com", "k\xc3ller.idn.com"
    ])
    def test_md_100_005(self, env, invalid_dns):
        assert env.a2md(["add", invalid_dns]).exit_code == 1
        assert env.a2md(["add", "test-100.de", invalid_dns]).exit_code == 1

    # test case: add with invalid ACME URL
    @pytest.mark.parametrize("invalid_url", [
        "no.schema/path", "http://white space/path", "http://bad.port:-1/path"])
    def test_md_100_006(self, env, invalid_url):
        args = [env.a2md_bin, "-a", invalid_url, "-d", env.store_dir, "-j"]
        dns = "greenbytes.de"
        args.extend(["add", dns])
        assert env.run(args).exit_code == 1

    # test case: add overlapping dns names
    def test_md_100_007(self, env):
        assert env.a2md(["add", "test-100.com", "test-101.com"]).exit_code == 0
        # 1: alternate DNS exists as primary name
        assert env.a2md(["add", "greenbytes2.de", "test-100.com"]).exit_code == 1
        # 2: alternate DNS exists as alternate DNS
        assert env.a2md(["add", "greenbytes2.de", "test-101.com"]).exit_code == 1
        # 3: primary name exists as alternate DNS
        assert env.a2md(["add", "test-101.com"]).exit_code == 1

    # test case: add subdomains as separate managed domain
    def test_md_100_008(self, env):
        assert env.a2md(["add", "test-100.com"]).exit_code == 0
        assert env.a2md(["add", "sub.test-100.com"]).exit_code == 0

    # test case: add duplicate domain
    def test_md_100_009(self, env):
        dns1 = "test-100.com"
        dns2 = "test-101.com"
        jout = env.a2md(["add", dns1, dns2, dns1, dns2]).json
        # DNS is only listed once
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['domains'] == [dns1, dns2]

    # test case: add pnuycode name
    def test_md_100_010(self, env):
        assert env.a2md(["add", "xn--kller-jua.punycode.de"]).exit_code == 0

    # test case: don't sort alternate names
    def test_md_100_011(self, env):
        dns = ["test-100.com", "test-xxx.com", "test-aaa.com"]
        jout = env.a2md(["add"] + dns).json
        # DNS is only listed as specified
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['domains'] == dns

    # test case: add DNS wildcard
    @pytest.mark.parametrize("wild_dns", [
        "*.wildcard.com"
    ])
    def test_md_100_012(self, env, wild_dns):
        assert env.a2md(["add", wild_dns]).exit_code == 0
