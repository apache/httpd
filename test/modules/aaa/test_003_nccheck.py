"""AuthDigestNcCheck replay-detection scenarios.

Note the actual semantics here are stricter than a sliding replay window:
the server keeps its own count of authenticated requests seen for a client
(incremented on *every* request carrying that client's opaque, whether or
not it goes on to authenticate) and requires the client's nc to match it
*exactly* -- so both replays of an old nc and skipping ahead are rejected.
A failed nc check also resets the server's tracked count back to 0, as part
of issuing a fresh challenge for the client (see note_digest_auth_failure()
in mod_auth_digest.c: an existing, opaque-identified client always gets its
nonce_count reset when a new challenge is generated for it, regardless of
*why* the challenge is being reissued) -- so recovery after a rejected nc
means starting the sequence over at 00000001, not continuing where the
client left off.
"""

from . import digest_client as dc
from .env import AAATestEnv


class TestDigestNcCheck:

    def url(self, env, location, path="secret.txt"):
        return env.mkurl("http", "aaa", f"/digest/{location}/{path}")

    def challenge(self, env, location):
        r = env.curl_get(self.url(env, location))
        assert r.response["status"] == 401
        return dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

    def authenticate(self, env, location, challenge, nc, cnonce="ncc-test-cnonce",
                      include_opaque=True):
        uri = f"/digest/{location}/secret.txt"
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=uri, nc=nc, cnonce=cnonce,
            include_opaque=include_opaque)
        return env.curl_get(self.url(env, location), options=["-H", f"Authorization: {auth}"])

    def test_digest_030_nccheck_requires_opaque(self, env):
        # with AuthDigestNcCheck on, the server cannot verify nc without
        # having tracked this client via its opaque -- omitting the opaque
        # therefore fails the check outright, even with nc=00000001.
        challenge = self.challenge(env, "nccheck")
        assert challenge.opaque is not None
        r = self.authenticate(env, "nccheck", challenge, nc="00000001", include_opaque=False)
        assert r.response["status"] == 401
        new_challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert new_challenge.stale is False

    def test_digest_031_nccheck_sequential_ok(self, env):
        challenge = self.challenge(env, "nccheck")
        r1 = self.authenticate(env, "nccheck", challenge, nc="00000001")
        assert r1.response["status"] == 200
        r2 = self.authenticate(env, "nccheck", challenge, nc="00000002")
        assert r2.response["status"] == 200
        r3 = self.authenticate(env, "nccheck", challenge, nc="00000003")
        assert r3.response["status"] == 200

    def test_digest_032_nccheck_replay_rejected(self, env):
        challenge = self.challenge(env, "nccheck")
        r1 = self.authenticate(env, "nccheck", challenge, nc="00000001")
        assert r1.response["status"] == 200
        r2 = self.authenticate(env, "nccheck", challenge, nc="00000002")
        assert r2.response["status"] == 200

        # replay an already-used nc -> rejected, and NOT reported as stale
        # (this is a distinct failure mode from an invalid/expired nonce).
        r3 = self.authenticate(env, "nccheck", challenge, nc="00000001")
        assert r3.response["status"] == 401
        new_challenge = dc.DigestChallenge.parse(r3.response["header"]["www-authenticate"])
        assert new_challenge.stale is False
        env.httpd_error_log.ignore_recent(lognos=["AH01774"])

        # the rejected attempt reset the server's tracked count to 0 (a new
        # challenge was issued for this client), so recovery restarts the
        # sequence at 00000001 -- continuing from 00000003 would NOT work.
        r4 = self.authenticate(env, "nccheck", challenge, nc="00000001")
        assert r4.response["status"] == 200

    def test_digest_033_nccheck_skip_ahead_rejected(self, env):
        challenge = self.challenge(env, "nccheck")
        r1 = self.authenticate(env, "nccheck", challenge, nc="00000001")
        assert r1.response["status"] == 200

        # skipping ahead is rejected too: nc must match exactly, not just
        # be higher than what was last accepted.
        r2 = self.authenticate(env, "nccheck", challenge, nc="00000009")
        assert r2.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01774"])

    def test_digest_034_no_nccheck_allows_replay(self, env):
        # the "default" location has no AuthDigestNcCheck (Off by default),
        # so replaying the exact same nc is not detected or rejected.
        challenge = self.challenge(env, "default")
        r1 = self.authenticate(env, "default", challenge, nc="00000001")
        assert r1.response["status"] == 200
        r2 = self.authenticate(env, "default", challenge, nc="00000001")
        assert r2.response["status"] == 200
