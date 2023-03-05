import os
import time
from datetime import timedelta

import pytest

from .env import TlsTestEnv
from .conf import TlsTestConf


def mk_text_file(fpath: str, lines: int):
    t110 = 11 * "0123456789"
    with open(fpath, "w") as fd:
        for i in range(lines):
            fd.write("{0:015d}: ".format(i))  # total 128 bytes per line
            fd.write(t110)
            fd.write("\n")


class TestGet:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env)
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        docs_a = os.path.join(env.server_docs_dir, env.domain_a)
        mk_text_file(os.path.join(docs_a, "1k.txt"), 8)
        mk_text_file(os.path.join(docs_a, "10k.txt"), 80)
        mk_text_file(os.path.join(docs_a, "100k.txt"), 800)
        mk_text_file(os.path.join(docs_a, "1m.txt"), 8000)
        mk_text_file(os.path.join(docs_a, "10m.txt"), 80000)
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("fname, flen", [
        ("1k.txt", 1024),
        ("10k.txt", 10*1024),
        ("100k.txt", 100 * 1024),
        ("1m.txt", 1000 * 1024),
        ("10m.txt", 10000 * 1024),
    ])
    def test_tls_04_get(self, env, fname, flen):
        # do we see the correct json for the domain_a?
        docs_a = os.path.join(env.server_docs_dir, env.domain_a)
        r = env.tls_get(env.domain_a, "/{0}".format(fname))
        assert r.exit_code == 0
        assert len(r.stdout) == flen
        pref = os.path.join(docs_a, fname)
        pout = os.path.join(docs_a, "{0}.out".format(fname))
        with open(pout, 'w') as fd:
            fd.write(r.stdout)
        dr = env.run_diff(pref, pout)
        assert dr.exit_code == 0, "differences found:\n{0}".format(dr.stdout)

    @pytest.mark.parametrize("fname, flen", [
        ("1k.txt", 1024),
    ])
    def test_tls_04_double_get(self, env, fname, flen):
        # we'd like to check that we can do >1 requests on the same connection
        # however curl hides that from us, unless we analyze its verbose output
        docs_a = os.path.join(env.server_docs_dir, env.domain_a)
        r = env.tls_get(env.domain_a, paths=[
            "/{0}".format(fname),
            "/{0}".format(fname)
        ])
        assert r.exit_code == 0
        assert len(r.stdout) == 2*flen
