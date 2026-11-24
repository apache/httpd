"""AuthDigestProvider scenarios."""

from . import digest_client as dc
from .env import AAATestEnv


class TestDigestProvider:

    def url(self, env, path):
        return env.mkurl("http", "aaa", path)

    def test_digest_050_omitted_provider_defaults_to_file(self, env):
        # /digest/noprovider/ has no AuthDigestProvider directive at all;
        # mod_auth_digest falls back to the "file" provider (mod_authn_file)
        # by default (see get_hash() / AUTHN_DEFAULT_PROVIDER in mod_auth.h).
        path = "/digest/noprovider/secret.txt"
        r = env.curl_get(self.url(env, path))
        assert r.response["status"] == 401
        challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=path)
        r = env.curl_get(self.url(env, path), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 200
        assert r.response["body"].decode() == "digest-noprovider-secret\n"

    def test_digest_051_unknown_provider_rejected_at_config_time(self, env):
        r = env.configtest([
            'AuthType Digest',
            f'AuthName "{AAATestEnv.REALM}"',
            'AuthDigestProvider no-such-provider',
            f'AuthUserFile "{env.digest_pwfile}"',
            'Require valid-user',
        ])
        assert r.exit_code != 0
        assert "Unknown Authn provider" in r.stderr
