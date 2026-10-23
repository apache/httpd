"""A realm with both a one-time-nonce location (AuthDigestNonceLifetime 0)
and a timed one, which nothing stops a configuration from having: there is
no directory merge for the directive, so every <Directory> starts from the
defaults.

The time field of a nonce is a timestamp at the timed location and a small
ordinal at the one-time one, and a one-time client records the last nonce
it used by that field. So a *timed* nonce, verified at the one-time
location, used to be recorded as the client's last ordinal -- some 1.7e15,
which the counter will never reach -- after which every genuine one-time
nonce that client was handed was "already used", and the client locked out
until its entry was garbage collected.

The nonce is bound to the opaque, so the timed nonce has to have been
minted for the one-time client's opaque; that just takes quoting the opaque
at the timed location, which issues one when it tracks clients
(AuthDigestNcCheck here). A browser does exactly this by itself: both
locations are one protection space, so it carries its current nonce and
opaque from one to the other. No attacker is needed to hit this, though
anybody with an account on the realm could do it to another client's
opaque.

A nonce now verifies only for the kind of lifetime it was minted under.
"""

from . import digest_client as dc
from .env import AAATestEnv

NONCE_HASH_INVALID = "AH01776"

ONETIME = "onetime"
TIMED = "nccheck"


class TestMixedLifetime:

    def url(self, env, location):
        return env.mkurl("http", "aaa", f"/digest/{location}/secret.txt")

    def challenge(self, env, location):
        r = env.curl_get(self.url(env, location))
        assert r.response["status"] == 401
        return dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

    def header(self, location, challenge):
        return dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=f"/digest/{location}/secret.txt")

    def send(self, env, location, auth):
        r = env.curl_get(self.url(env, location),
                         options=["-H", f"Authorization: {auth}"])
        return r

    def test_digest_140_timed_nonce_does_not_poison_onetime_client(self, env):
        # The client is established at the one-time location...
        onetime = self.challenge(env, ONETIME)
        assert onetime.opaque is not None

        # ...and roams to the timed one with that nonce and opaque. The
        # nonce is refused (it is not a timed nonce) and the challenge
        # carries a timed nonce minted for the same opaque.
        r = self.send(env, TIMED, self.header(TIMED, onetime))
        assert r.response["status"] == 401
        timed = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert timed.stale is True
        assert timed.opaque == onetime.opaque

        # Back at the one-time location with the timed nonce: this must
        # not verify, since that would record its timestamp as the
        # client's last one-time ordinal.
        r = self.send(env, ONETIME, self.header(ONETIME, timed))
        assert r.response["status"] == 401, \
            "a timed nonce was accepted at the one-time location"
        fresh = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert fresh.stale is True
        assert fresh.opaque == onetime.opaque

        # The client follows the challenge and is not locked out.
        r = self.send(env, ONETIME, self.header(ONETIME, fresh))
        env.httpd_error_log.ignore_recent(lognos=[NONCE_HASH_INVALID])
        assert r.response["status"] == 200, \
            "the client's one-time nonce state was poisoned"
