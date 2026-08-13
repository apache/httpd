"""Config-time validation for directives whose *documented* syntax (see
docs/manual/mod/mod_auth_digest.xml) is broader than what this build's
mod_auth_digest.c actually implements: AuthDigestQop only accepts "auth"
(qop=none/auth-int are rejected -- the "Open Issues" comment in the source
notes MD5-sess and auth-int were removed as incomplete), AuthDigestAlgorithm
only accepts "MD5", and AuthDigestShmemSize enforces a minimum size. These
are all checked with `httpd -t` against a throwaway config so the shared
package server is never disturbed.
"""

from .env import AAATestEnv


class TestDigestConfigErrors:

    def test_digest_060_qop_none_rejected(self, env):
        r = env.configtest([
            'AuthType Digest',
            f'AuthName "{AAATestEnv.REALM}"',
            'AuthDigestProvider file',
            f'AuthUserFile "{env.digest_pwfile}"',
            'AuthDigestQop none',
            'Require valid-user',
        ])
        assert r.exit_code != 0
        assert "AuthDigestQop" in r.stderr

    def test_digest_061_qop_auth_int_rejected(self, env):
        r = env.configtest([
            'AuthType Digest',
            f'AuthName "{AAATestEnv.REALM}"',
            'AuthDigestProvider file',
            f'AuthUserFile "{env.digest_pwfile}"',
            'AuthDigestQop auth-int',
            'Require valid-user',
        ])
        assert r.exit_code != 0
        assert "AuthDigestQop" in r.stderr

    def test_digest_062_qop_auth_accepted(self, env):
        # the only value actually supported must still work.
        r = env.configtest([
            'AuthType Digest',
            f'AuthName "{AAATestEnv.REALM}"',
            'AuthDigestProvider file',
            f'AuthUserFile "{env.digest_pwfile}"',
            'AuthDigestQop auth',
            'Require valid-user',
        ])
        assert r.exit_code == 0

    def test_digest_063_algorithm_md5_sess_rejected(self, env):
        r = env.configtest([
            'AuthType Digest',
            f'AuthName "{AAATestEnv.REALM}"',
            'AuthDigestProvider file',
            f'AuthUserFile "{env.digest_pwfile}"',
            'AuthDigestAlgorithm MD5-sess',
            'Require valid-user',
        ])
        assert r.exit_code != 0
        assert "Unsupported algorithm" in r.stderr

    def test_digest_064_algorithm_md5_accepted(self, env):
        r = env.configtest([
            'AuthType Digest',
            f'AuthName "{AAATestEnv.REALM}"',
            'AuthDigestProvider file',
            f'AuthUserFile "{env.digest_pwfile}"',
            'AuthDigestAlgorithm MD5',
            'Require valid-user',
        ])
        assert r.exit_code == 0

    def test_digest_065_shmemsize_too_small_rejected(self, env):
        r = env.configtest([], extra_top_lines=["AuthDigestShmemSize 10"])
        assert r.exit_code != 0
        assert "AuthDigestShmemSize" in r.stderr

    def test_digest_066_shmemsize_valid_accepted(self, env):
        r = env.configtest([], extra_top_lines=["AuthDigestShmemSize 1000"])
        assert r.exit_code == 0

    def test_digest_067_shmemsize_units_accepted(self, env):
        r = env.configtest([], extra_top_lines=["AuthDigestShmemSize 64K"])
        assert r.exit_code == 0
