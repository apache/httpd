"""Nonce lifecycle scenarios: tampered nonces, AuthDigestNonceLifetime
expiry/reissue, a never-expiring nonce, and the one-time-nonce
(AuthDigestNonceLifetime 0) case.
"""

import time

from . import digest_client as dc
from .env import AAATestEnv


class TestDigestNonce:

    def url(self, env, location, path="secret.txt"):
        return env.mkurl("http", "aaa", f"/digest/{location}/{path}")

    def challenge(self, env, location):
        r = env.curl_get(self.url(env, location))
        assert r.response["status"] == 401
        return dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

    def authenticate(self, env, location, challenge, nc="00000001",
                      cnonce="nonce-test-cnonce", uri=None):
        uri = uri or f"/digest/{location}/secret.txt"
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=uri, nc=nc, cnonce=cnonce)
        return env.curl_get(self.url(env, location), options=["-H", f"Authorization: {auth}"])

    def test_digest_020_tampered_nonce_is_stale(self, env):
        challenge = self.challenge(env, "default")
        # flip a character in the middle of the opaque nonce blob: it stays
        # the right length but its embedded hash no longer verifies.
        bad = list(challenge.nonce)
        mid = len(bad) // 2
        bad[mid] = 'x' if bad[mid] != 'x' else 'y'
        challenge.nonce = ''.join(bad)
        r = self.authenticate(env, "default", challenge)
        assert r.response["status"] == 401
        new_challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert new_challenge.stale is True
        env.httpd_error_log.ignore_recent(lognos=["AH01776"])

    def test_digest_021_garbage_nonce_hash_is_stale(self, env):
        # A nonce must still look like "b64(time)+sha1hex(hash)" (VALID_NONCE
        # in mod_auth_digest.c checks length and the '=' padding boundary) to
        # even be considered for a hash check; something that doesn't match
        # that shape is instead rejected as a malformed header (see
        # test_digest_010). Here we keep the genuine time-prefix (so the
        # shape is valid) but replace the whole hash suffix with garbage, to
        # hit check_nonce()'s "hash is not %s" path distinctly from
        # test_digest_020's single-flipped-character tamper.
        challenge = self.challenge(env, "default")
        time_prefix = challenge.nonce[:-40]
        challenge.nonce = time_prefix + ("f" * 40)
        r = self.authenticate(env, "default", challenge)
        assert r.response["status"] == 401
        new_challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert new_challenge.stale is True
        env.httpd_error_log.ignore_recent(lognos=["AH01776"])

    def test_digest_022_short_lifetime_expires(self, env):
        # AuthDigestNonceLifetime 2 for this location.
        challenge = self.challenge(env, "shortlife")
        r = self.authenticate(env, "shortlife", challenge)
        assert r.response["status"] == 200

        time.sleep(3)
        # same nonce, now past its lifetime -> 401 stale=true
        r = self.authenticate(env, "shortlife", challenge)
        assert r.response["status"] == 401
        stale_challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert stale_challenge.stale is True
        env.httpd_error_log.ignore_recent(lognos=["AH01776"])

        # the fresh nonce from the stale challenge works again
        r = self.authenticate(env, "shortlife", stale_challenge)
        assert r.response["status"] == 200

    def test_digest_023_never_expiring_nonce(self, env):
        # AuthDigestNonceLifetime -1 for this location: no NcCheck is
        # configured, so the identical Authorization line can simply be
        # replayed after a delay and must still succeed both times.
        challenge = self.challenge(env, "neverexpire")
        r1 = self.authenticate(env, "neverexpire", challenge)
        assert r1.response["status"] == 200

        time.sleep(3)
        r2 = self.authenticate(env, "neverexpire", challenge)
        assert r2.response["status"] == 200

    def test_digest_024_one_time_nonce_rejects_reuse(self, env):
        # AuthDigestNonceLifetime 0: a successful request immediately
        # supersedes its nonce (the tracked "last_nonce" moves on to the
        # nextnonce from Authentication-Info), so replaying the very same
        # nonce right afterwards must fail as stale. Each request against
        # this client (success OR failure) advances the tracked nonce again,
        # so this test does exactly one success followed by exactly one
        # reuse -- no longer chain that would need to account for that.
        challenge = self.challenge(env, "onetime")
        assert challenge.opaque is not None, \
            "one-time-nonce tracking requires an opaque to identify the client"

        r1 = self.authenticate(env, "onetime", challenge)
        assert r1.response["status"] == 200
        ai1 = dc.parse_params(r1.response["header"]["authentication-info"])
        assert "nextnonce" in ai1
        assert ai1["nextnonce"] != challenge.nonce

        # reusing the exact same (now superseded) nonce fails as stale
        r2 = self.authenticate(env, "onetime", challenge)
        assert r2.response["status"] == 401
        stale_challenge = dc.DigestChallenge.parse(r2.response["header"]["www-authenticate"])
        assert stale_challenge.stale is True
        env.httpd_error_log.ignore_recent(lognos=["AH01776"])

    def test_digest_025_one_time_nonce_chain_continues(self, env):
        # Following the nextnonce handed out on a successful response lets
        # the client keep authenticating, one hop at a time.
        challenge = self.challenge(env, "onetime")
        r1 = self.authenticate(env, "onetime", challenge)
        assert r1.response["status"] == 200
        ai1 = dc.parse_params(r1.response["header"]["authentication-info"])

        challenge.nonce = ai1["nextnonce"]
        r2 = self.authenticate(env, "onetime", challenge)
        assert r2.response["status"] == 200
        ai2 = dc.parse_params(r2.response["header"]["authentication-info"])
        assert ai2["nextnonce"] != ai1["nextnonce"]
