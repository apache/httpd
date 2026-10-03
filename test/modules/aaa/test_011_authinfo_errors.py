"""Authentication-Info survives an error response.

The header is added at fixups, so unless it goes into err_headers_out it
is dropped when the response turns into an error, costing a one-time-nonce
client the nextnonce and forcing a stale re-challenge.  A 404 for a missing
file inside the protected area reaches the error path while fully
authenticated, so it exercises this without a handler like mod_dav.
"""

from . import digest_client as dc
from .env import AAATestEnv


class TestAuthInfoOnError:

    def url(self, env, location, path):
        return env.mkurl("http", "aaa", f"/digest/{location}/{path}")

    def uri(self, location, path):
        return f"/digest/{location}/{path}"

    def challenge(self, env, location, path="secret.txt"):
        r = env.curl_get(self.url(env, location, path))
        assert r.response["status"] == 401
        return dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

    def auth(self, env, location, path, challenge, nc="00000001"):
        return dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=self.uri(location, path), nc=nc,
            cnonce="authinfo-cnonce")

    def get(self, env, location, path, challenge, nc="00000001"):
        return env.curl_get(self.url(env, location, path), options=[
            "-H", f"Authorization: {self.auth(env, location, path, challenge, nc)}"])

    def test_digest_110_error_response_carries_authentication_info(self, env):
        # A 404 for an authenticated request still confirms the response to
        # the client: Authentication-Info with a valid rspauth.
        location = "default"
        challenge = self.challenge(env, location)
        r = self.get(env, location, "no-such-file.txt", challenge)
        assert r.response["status"] == 404
        assert "authentication-info" in r.response["header"], \
            "the error response dropped Authentication-Info"
        ai = dc.parse_params(r.response["header"]["authentication-info"])
        expect = dc.rspauth_digest(
            dc.ha1(AAATestEnv.DIGEST_USER, AAATestEnv.REALM,
                   AAATestEnv.DIGEST_PASSWORD),
            challenge.nonce, "00000001", "authinfo-cnonce", "auth",
            self.uri(location, "no-such-file.txt"))
        assert ai.get("rspauth") == expect, "rspauth wrong on the error response"

    def test_digest_111_onetime_client_continues_after_an_error(self, env):
        # Under one-time nonces the error must still hand back a nextnonce,
        # or the client's next request is stale-challenged.  Prove the client
        # can carry straight on to a real request with what the 404 gave it.
        location = "onetime"
        challenge = self.challenge(env, location)
        r = self.get(env, location, "no-such-file.txt", challenge)
        assert r.response["status"] == 404
        assert "authentication-info" in r.response["header"], \
            "the one-time-nonce error response dropped Authentication-Info"
        ai = dc.parse_params(r.response["header"]["authentication-info"])
        assert "nextnonce" in ai, "no nextnonce to continue with after the error"

        challenge.nonce = ai["nextnonce"]
        ok = self.get(env, location, "secret.txt", challenge)
        assert ok.response["status"] == 200, \
            "the nextnonce from the error response was not usable"

    def test_digest_112_challenge_has_no_authentication_info(self, env):
        # When the error is itself a 401, the challenge stands alone: the
        # client is not handed a nextnonce it could not use beside a fresh
        # nonce.  A wrong password reaches note_digest_auth_failure.
        location = "onetime"
        challenge = self.challenge(env, location)
        bad = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, "wrong-password",
            method="GET", uri=self.uri(location, "secret.txt"),
            cnonce="authinfo-cnonce")
        r = env.curl_get(self.url(env, location, "secret.txt"),
                         options=["-H", f"Authorization: {bad}"])
        env.httpd_error_log.ignore_recent(lognos=["AH01794"])  # password mismatch
        assert r.response["status"] == 401
        assert "authentication-info" not in r.response["header"], \
            "a 401 challenge carried an Authentication-Info header"
