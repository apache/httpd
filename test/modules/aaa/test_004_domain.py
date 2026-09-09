"""AuthDigestDomain: presence, format, and inheritance of the domain=
attribute in the WWW-Authenticate challenge.
"""

from . import digest_client as dc
from .env import AAATestEnv


class TestDigestDomain:

    def url(self, env, path):
        return env.mkurl("http", "aaa", path)

    def test_digest_040_domain_attribute_present(self, env):
        r = env.curl_get(self.url(env, "/digest/domain/secret.txt"))
        assert r.response["status"] == 401
        challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        # set_uri_list() (mod_auth_digest.c) builds a single quoted,
        # space-separated list from the configured AuthDigestDomain URIs.
        assert challenge.domain == "/digest/domain/ https://mirror.example.org/other/"
        assert challenge.domain_list() == [
            "/digest/domain/", "https://mirror.example.org/other/"]

    def test_digest_041_no_domain_configured_omits_attribute(self, env):
        r = env.curl_get(self.url(env, "/digest/default/secret.txt"))
        assert r.response["status"] == 401
        challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert challenge.domain is None

    def test_digest_042_domain_location_still_authenticates(self, env):
        r = env.curl_get(self.url(env, "/digest/domain/secret.txt"))
        challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri="/digest/domain/secret.txt")
        r = env.curl_get(self.url(env, "/digest/domain/secret.txt"),
                          options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 200
        assert r.response["body"].decode() == "digest-domain-secret\n"

    def test_digest_043_domain_inherited_by_nested_path(self, env):
        # AuthDigestDomain is set on /digest/domain/; a path nested below it
        # inherits the same directory config (same realm/credentials/domain).
        r = env.curl_get(self.url(env, "/digest/domain/nested/secret.txt"))
        assert r.response["status"] == 401
        challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert challenge.realm == AAATestEnv.REALM
        assert challenge.domain == "/digest/domain/ https://mirror.example.org/other/"

        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri="/digest/domain/nested/secret.txt")
        r = env.curl_get(self.url(env, "/digest/domain/nested/secret.txt"),
                          options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 200
        assert r.response["body"].decode() == "digest-domain-nested-secret\n"
