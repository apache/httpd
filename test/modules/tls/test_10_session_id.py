import re
from typing import List

import pytest

from pyhttpd.result import ExecResult
from .env import TlsTestEnv
from .conf import TlsTestConf


class TestSessionID:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env)
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    def find_openssl_session_ids(self, r: ExecResult) -> List[str]:
        ids = []
        for line in r.stdout.splitlines():
            m = re.match(r'^\s*Session-ID: (\S+)$', line)
            if m:
                ids.append(m.group(1))
        return ids

    def test_tls_10_session_id_12(self, env):
        r = env.openssl_client(env.domain_b, extra_args=[
            "-reconnect", "-tls1_2"
        ])
        session_ids = self.find_openssl_session_ids(r)
        assert 1 < len(session_ids), "expected several session-ids: {0}, stderr={1}".format(
            session_ids, r.stderr
        )
        assert 1 == len(set(session_ids)), "sesion-ids should all be the same: {0}".format(session_ids)

    @pytest.mark.skipif(True or not TlsTestEnv.openssl_supports_tls_1_3(),
                        reason="openssl TLSv1.3 session storage test incomplete")
    def test_tls_10_session_id_13(self, env):
        r = env.openssl_client(env.domain_b, extra_args=[
            "-reconnect", "-tls1_3"
        ])
        # openssl -reconnect closes connection immediately after the handhshake, so
        # the Session data in TLSv1.3 is not seen and not found in its output.
        # FIXME: how to check session data with TLSv1.3?
        session_ids = self.find_openssl_session_ids(r)
        assert 0 == len(session_ids), "expected no session-ids: {0}, stderr={1}".format(
            session_ids, r.stdout
        )
