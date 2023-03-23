# test mod_md ACMEv2 registrations

import re
import json
import pytest

from .md_conf import MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_a2md(), reason="no a2md available")
@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestAcmeAcc:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='default')
        env.check_acme()
        env.APACHE_CONF_SRC = "data/test_drive"
        MDConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env):
        env.check_acme()
        env.clear_store()

    # test case: register a new account, vary length to check base64 encoding
    @pytest.mark.parametrize("contact", [
        "x@not-forbidden.org", "xx@not-forbidden.org", "xxx@not-forbidden.org"
    ])
    def test_md_202_000(self, env, contact):
        r = env.a2md(["-t", "accepted", "acme", "newreg", contact], raw=True)
        assert r.exit_code == 0, r
        m = re.match("registered: (.*)$", r.stdout)
        assert m, "did not match: {0}".format(r.stdout)
        acct = m.group(1)
        print("newreg: %s" % m.group(1))
        self._check_account(env, acct, ["mailto:" + contact])

    # test case: register a new account without accepting ToS, must fail
    def test_md_202_000b(self, env):
        r = env.a2md(["acme", "newreg", "x@not-forbidden.org"], raw=True)
        assert r.exit_code == 1
        m = re.match(".*must agree to terms of service.*", r.stderr)
        if m is None:
            # the pebble variant
            m = re.match(".*account did not agree to the terms of service.*", r.stderr)
        assert m, "did not match: {0}".format(r.stderr)

    # test case: respect 'mailto:' prefix in contact url
    def test_md_202_001(self, env):
        contact = "mailto:xx@not-forbidden.org"
        r = env.a2md(["-t", "accepted", "acme", "newreg", contact], raw=True)
        assert r.exit_code == 0
        m = re.match("registered: (.*)$", r.stdout)
        assert m
        acct = m.group(1)
        self._check_account(env, acct, [contact])

    # test case: fail on invalid contact url
    @pytest.mark.parametrize("invalid_contact", [
        "mehlto:xxx@not-forbidden.org", "no.at.char", "with blank@test.com",
        "missing.host@", "@missing.localpart.de",
        "double..dot@test.com", "double@at@test.com"
    ])
    def test_md_202_002(self, env, invalid_contact):
        assert env.a2md(["acme", "newreg", invalid_contact]).exit_code == 1

    # test case: use contact list
    def test_md_202_003(self, env):
        contact = ["xx@not-forbidden.org", "aa@not-forbidden.org"]
        r = env.a2md(["-t", "accepted", "acme", "newreg"] + contact, raw=True)
        assert r.exit_code == 0
        m = re.match("registered: (.*)$", r.stdout)
        assert m
        acct = m.group(1)
        self._check_account(env, acct, ["mailto:" + contact[0], "mailto:" + contact[1]])

    # test case: validate new account
    def test_md_202_100(self, env):
        acct = self._prepare_account(env, ["tmp@not-forbidden.org"])
        assert env.a2md(["acme", "validate", acct]).exit_code == 0

    # test case: fail on non-existing account
    def test_md_202_101(self, env):
        assert env.a2md(["acme", "validate", "ACME-localhost-1000"]).exit_code == 1

    # test case: report fail on request signing problem
    def test_md_202_102(self, env):
        acct = self._prepare_account(env, ["tmp@not-forbidden.org"])
        with open(env.path_account(acct)) as f:
            acctj = json.load(f)
        acctj['url'] = acctj['url'] + "0"
        open(env.path_account(acct), "w").write(json.dumps(acctj))
        assert env.a2md(["acme", "validate", acct]).exit_code == 1

    # test case: register and try delete an account, will fail without persistence
    def test_md_202_200(self, env):
        acct = self._prepare_account(env, ["tmp@not-forbidden.org"])
        assert env.a2md(["delreg", acct]).exit_code == 1

    # test case: register and try delete an account with persistence
    def test_md_202_201(self, env):
        acct = self._prepare_account(env, ["tmp@not-forbidden.org"])
        assert env.a2md(["acme", "delreg", acct]).exit_code == 0
        # check that store is clean
        r = env.run(["find", env.store_dir])
        assert re.match(env.store_dir, r.stdout)

    # test case: delete a persisted account without specifying url
    def test_md_202_202(self, env):
        acct = self._prepare_account(env, ["tmp@not-forbidden.org"])
        assert env.run([env.a2md_bin, "-d", env.store_dir, "acme", "delreg", acct]).exit_code == 0

    # test case: delete, then validate an account
    def test_md_202_203(self, env):
        acct = self._prepare_account(env, ["test014@not-forbidden.org"])
        assert env.a2md(["acme", "delreg", acct]).exit_code == 0
        # validate on deleted account fails
        assert env.a2md(["acme", "validate", acct]).exit_code == 1

    def _check_account(self, env, acct, contact):
        with open(env.path_account(acct)) as f:
            acctj = json.load(f)
        assert acctj['registration']['contact'] == contact

    def _prepare_account(self, env, contact):
        r = env.a2md(["-t", "accepted", "acme", "newreg"] + contact, raw=True)
        assert r.exit_code == 0
        return re.match("registered: (.*)$", r.stdout).group(1)
