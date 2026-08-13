"""AuthDigestNcCheck replay-detection scenarios.

The semantics are those of RFC 7616 3.4.3: the nonce-count is counted by
the client per-nonce, so the server tracks a count per (client, nonce) pair
and requires it to strictly increase. Within one nonce, an nc which has
already been seen is a replay and is rejected; a *higher* nc than expected
is not, since the client also counts the requests it sends to URIs in the
protection space which turn out not to need authentication, and the server
never sees those. Moving to a newer nonce starts a fresh count, and a nonce
the client has already moved on from is rejected.

The tracked count is only ever updated for a fully verified request, so a
failed request cannot disturb the count of the client whose opaque it
quotes; test_007_replay.py covers that property directly.
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
        # therefore fails, even with nc=00000001. It is rejected before the
        # nc check is even reached: the nonce hash is computed over the
        # opaque (gen_nonce_hash()), so a nonce quoted without the opaque it
        # was issued with does not verify, and that is reported as stale.
        challenge = self.challenge(env, "nccheck")
        assert challenge.opaque is not None
        r = self.authenticate(env, "nccheck", challenge, nc="00000001", include_opaque=False)
        assert r.response["status"] == 401
        new_challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert new_challenge.stale is True
        env.httpd_error_log.ignore_recent(lognos=["AH01776"])

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

        # recovery: the rejected attempt handed out a fresh challenge for
        # this client, and following it -- new nonce, so the count starts
        # over at 00000001 -- authenticates again.
        r4 = self.authenticate(env, "nccheck", new_challenge, nc="00000001")
        assert r4.response["status"] == 200

        # the superseded nonce is not usable any more, at any nc.
        r5 = self.authenticate(env, "nccheck", challenge, nc="00000003")
        assert r5.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01774"])

    def test_digest_033_nccheck_skip_ahead_allowed(self, env):
        challenge = self.challenge(env, "nccheck")
        r1 = self.authenticate(env, "nccheck", challenge, nc="00000001")
        assert r1.response["status"] == 200

        # skipping ahead is allowed: nc only has to be higher than the
        # highest already seen for this nonce, not exactly one more. A
        # client legitimately produces gaps by sending counted requests to
        # URIs in the protection space which don't need authentication, and
        # a higher nc is not a replay in any case.
        r2 = self.authenticate(env, "nccheck", challenge, nc="00000009")
        assert r2.response["status"] == 200

        # ...and the skipped-over counts are spent: they are no longer
        # accepted afterwards.
        r3 = self.authenticate(env, "nccheck", challenge, nc="00000005")
        assert r3.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01774"])

    def test_digest_034_no_nccheck_allows_replay(self, env):
        # the "default" location has no AuthDigestNcCheck (Off by default),
        # so replaying the exact same nc is not detected or rejected.
        challenge = self.challenge(env, "default")
        r1 = self.authenticate(env, "default", challenge, nc="00000001")
        assert r1.response["status"] == 200
        r2 = self.authenticate(env, "default", challenge, nc="00000001")
        assert r2.response["status"] == 200
