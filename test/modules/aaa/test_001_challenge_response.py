"""RFC 2617 Digest challenge/response scenarios against mod_auth_digest's
default configuration (AuthDigestProvider file, AuthDigestQop auth (the only
supported value), AuthDigestNonceLifetime 300, no AuthDigestDomain).
"""

from . import digest_client as dc
from .env import AAATestEnv


class TestDigestChallengeResponse:

    def url(self, env, path="secret.txt", location="default"):
        return env.mkurl("http", "aaa", f"/digest/{location}/{path}")

    def challenge(self, env, location="default"):
        r = env.curl_get(self.url(env, location=location))
        assert r.response["status"] == 401
        return dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

    def test_digest_001_no_credentials(self, env):
        # No Authorization header at all -> 401 with a well-formed challenge.
        r = env.curl_get(self.url(env))
        assert r.response["status"] == 401
        auth = r.response["header"]["www-authenticate"]
        challenge = dc.DigestChallenge.parse(auth)
        assert challenge.realm == AAATestEnv.REALM
        assert challenge.algorithm == "MD5"
        assert challenge.qop == "auth"
        assert challenge.stale is False
        # no AuthDigestDomain configured for this Location -> no domain=
        assert challenge.domain is None
        # nonce-count checking is off and lifetime isn't 0 here, so the
        # server has no reason to track this client -> no opaque=
        assert challenge.opaque is None

    def test_digest_002_success(self, env):
        challenge = self.challenge(env)
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri="/digest/default/secret.txt")
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 200
        assert r.response["body"].decode() == "digest-default-secret\n"

    def test_digest_003_rspauth(self, env):
        # Authentication-Info's rspauth= must match what we independently
        # compute from the same HA1 -- proves the server round-trips the
        # session parameters (nonce/nc/cnonce/qop) correctly.
        challenge = self.challenge(env)
        nc = "00000001"
        cnonce = "test-cnonce-rspauth"
        uri = "/digest/default/secret.txt"
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=uri, nc=nc, cnonce=cnonce)
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 200
        ai = dc.parse_params(r.response["header"]["authentication-info"])
        h1 = dc.ha1(AAATestEnv.DIGEST_USER, challenge.realm, AAATestEnv.DIGEST_PASSWORD)
        expected = dc.rspauth_digest(h1, challenge.nonce, nc, cnonce, "auth", uri)
        assert ai["rspauth"] == expected
        assert ai["qop"] == "auth"
        assert ai["nc"] == nc
        assert ai["cnonce"] == cnonce

    def test_digest_004_wrong_password(self, env):
        challenge = self.challenge(env)
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, "not-the-password",
            method="GET", uri="/digest/default/secret.txt")
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01794"])

    def test_digest_005_unknown_user(self, env):
        challenge = self.challenge(env)
        auth = dc.build_authorization(
            "no-such-user", challenge, "whatever",
            method="GET", uri="/digest/default/secret.txt")
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01790"])

    def test_digest_006_second_user(self, env):
        # a distinct user in the same password file also works
        challenge = self.challenge(env)
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER2, challenge, AAATestEnv.DIGEST_PASSWORD2,
            method="GET", uri="/digest/default/secret.txt")
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 200

    def test_digest_007_wrong_realm(self, env):
        challenge = self.challenge(env)
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri="/digest/default/secret.txt",
            realm="Some Other Realm")
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01788"])

    def test_digest_008_bad_algorithm_token(self, env):
        # a client claiming an algorithm other than MD5 is rejected outright,
        # even though the response hash below is computed correctly for MD5.
        challenge = self.challenge(env)
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri="/digest/default/secret.txt",
            algorithm="MD5-sess")
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01789"])

    def test_digest_009_legacy_no_qop_rejected(self, env):
        # RFC 2069-style digest (no qop/cnonce/nc) is syntactically valid but
        # explicitly no longer supported by this module.
        challenge = self.challenge(env)
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri="/digest/default/secret.txt",
            qop=None, include_qop_fields=False)
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH10560"])

    def test_digest_010_malformed_header_missing_field(self, env):
        # missing "uri" entirely -> header is syntactically INVALID, so the
        # server issues a fresh (non-stale) challenge rather than evaluating
        # the (nonexistent) response hash.
        challenge = self.challenge(env)
        h1 = dc.ha1(AAATestEnv.DIGEST_USER, challenge.realm, AAATestEnv.DIGEST_PASSWORD)
        auth = ('Digest username="digestuser", '
                f'realm="{challenge.realm}", nonce="{challenge.nonce}", '
                f'response="{h1}", qop=auth, nc=00000001, cnonce="x"')
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 401
        new_challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert new_challenge.stale is False
        env.httpd_error_log.ignore_recent(lognos=["AH01782"])

    def test_digest_011_wrong_scheme(self, env):
        r = env.curl_get(self.url(env), options=[
            "-H", "Authorization: Basic ZGlnZXN0dXNlcjpkaWdlc3RwYXNz"])
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01781"])

    def test_digest_012_uri_mismatch(self, env):
        # The Authorization uri= must match the actual request-target; a
        # self-consistent response computed for a *different* uri than the
        # one actually requested is rejected as a bad request, before the
        # hash is even checked.
        challenge = self.challenge(env)
        other_uri = "/digest/default/other-secret.txt"
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=other_uri)
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 400
        env.httpd_error_log.ignore_recent(lognos=["AH01786"])

    def test_digest_013_invalid_opaque(self, env):
        challenge = self.challenge(env)
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri="/digest/default/secret.txt",
            opaque="not-a-hex-number")
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01787"])

    def test_digest_014_tampered_response_hash(self, env):
        challenge = self.challenge(env)
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri="/digest/default/secret.txt",
            response="0" * 32)
        r = env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01794"])
