# test mod_md acme terms-of-service handling

import os
import pytest

from .md_conf import MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_a2md(), reason="no a2md available")
class TestStoreMigrate:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        MDConf(env).install()
        assert env.apache_restart() == 0

    # install old store, start a2md list, check files afterwards
    def test_md_010_000(self, env):
        domain = "7007-1502285564.org"
        env.replace_store(os.path.join(env.test_dir, "../modules/md/data/store_migrate/1.0/sample1"))
        #
        # use 1.0 file name for private key
        fpkey_1_0 = os.path.join(env.store_dir, 'domains', domain, 'pkey.pem')
        fpkey_1_1 = os.path.join(env.store_dir, 'domains', domain, 'privkey.pem')
        cert_1_0 = os.path.join(env.store_dir, 'domains', domain, 'cert.pem')
        cert_1_1 = os.path.join(env.store_dir, 'domains', domain, 'pubcert.pem')
        chain_1_0 = os.path.join(env.store_dir, 'domains', domain, 'chain.pem')
        #
        assert os.path.exists(fpkey_1_0)
        assert os.path.exists(cert_1_0)
        assert os.path.exists(chain_1_0)
        assert not os.path.exists(fpkey_1_1)
        assert not os.path.exists(cert_1_1)
        #
        md = env.a2md(["-vvv", "list", domain]).json['output'][0]
        assert domain == md["name"]
        #
        assert not os.path.exists(fpkey_1_0)
        assert os.path.exists(cert_1_0)
        assert os.path.exists(chain_1_0)
        assert os.path.exists(fpkey_1_1)
        assert os.path.exists(cert_1_1)
