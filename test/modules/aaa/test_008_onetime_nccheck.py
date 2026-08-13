"""One-time nonces (AuthDigestNonceLifetime 0), alone and with AuthDigestNcCheck.

With a lifetime of 0 the server hands the client a nextnonce on every
successful response, and a nonce may be used once: it is accepted only if
it is newer than the last nonce that client used. The client counts from 1
again for each new nonce, so with AuthDigestNcCheck also on, every request
legitimately carries nc=00000001.

The security property here is the one from test_007_replay.py, applied to
the other piece of per-client state:

    A request which fails to authenticate MUST NOT invalidate the nonce
    which the legitimate client is holding.

It did, when the client's state was the last nonce *issued* to it:
note_digest_auth_failure() generates a fresh nonce and recorded it there,
and any request quoting the client's opaque can provoke a challenge. So an
eavesdropper who had captured one Authorization header could replay it at
will -- the replay itself was correctly rejected, but it moved the stored
nonce on, and the victim's next request was then refused. The opaque is in
the clear in every challenge and every request, and such a captured header
never goes stale for this purpose, since it works by failing.

This needed no credentials and, despite where it was first noticed, no
AuthDigestNcCheck: the tests below run against both locations to pin that
the defect was in the one-time-nonce path, not in the combination.

The state is now the last nonce the client actually *used*, which nothing
unauthenticated can move.
"""

import pytest

from . import digest_client as dc
from .env import AAATestEnv

BOTH = ["onetime", "onetime-nccheck"]

NC_FAILED = "AH01774"
NONCE_HASH_INVALID = "AH01776"
PASSWORD_MISMATCH = "AH01794"


class TestOneTimeNonce:

    def url(self, env, location):
        return env.mkurl("http", "aaa", f"/digest/{location}/secret.txt")

    def challenge(self, env, location):
        r = env.curl_get(self.url(env, location))
        assert r.response["status"] == 401
        challenge = dc.DigestChallenge.parse(
            r.response["header"]["www-authenticate"])
        assert challenge.opaque is not None, \
            "one-time nonces are tracked per client, so an opaque is required"
        return challenge

    def header(self, location, challenge, nc="00000001", cnonce="onetime-cnonce",
               response=None):
        """A correct Authorization header, unless response= overrides the
        digest -- an attacker can build that from an observed request
        without knowing the password."""
        return dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=f"/digest/{location}/secret.txt", nc=nc,
            cnonce=cnonce, response=response)

    def send(self, env, location, auth):
        return env.curl_get(self.url(env, location),
                            options=["-H", f"Authorization: {auth}"])

    def follow_nextnonce(self, r, challenge):
        """Advance the client to the nextnonce it was just handed."""
        ai = dc.parse_params(r.response["header"]["authentication-info"])
        assert "nextnonce" in ai
        assert ai["nextnonce"] != challenge.nonce
        challenge.nonce = ai["nextnonce"]

    def test_digest_080_nccheck_does_not_break_the_onetime_chain(self, env):
        # Each nonce is new, so the client's count restarts at 1 every time
        # and the nonce-count check must not object. (Before the nonce-count
        # was tracked per-nonce this alternated 200, 401, 200, 401, ...)
        challenge = self.challenge(env, "onetime-nccheck")
        for _ in range(4):
            r = self.send(env, "onetime-nccheck", self.header(
                "onetime-nccheck", challenge, nc="00000001"))
            assert r.response["status"] == 200
            self.follow_nextnonce(r, challenge)

    @pytest.mark.parametrize("location", BOTH)
    def test_digest_081_onetime_nonce_rejects_immediate_replay(self, env, location):
        challenge = self.challenge(env, location)
        captured = self.header(location, challenge)
        assert self.send(env, location, captured).response["status"] == 200

        r = self.send(env, location, captured)
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED])
        assert r.response["status"] == 401
        assert dc.DigestChallenge.parse(
            r.response["header"]["www-authenticate"]).stale is True

    @pytest.mark.parametrize("location", BOTH)
    def test_digest_082_onetime_nonce_rejects_replay_after_rotation(self, env, location):
        # The captured header stays rejected once the client has moved on
        # through the nextnonce chain.
        challenge = self.challenge(env, location)
        captured = self.header(location, challenge)
        r = self.send(env, location, captured)
        assert r.response["status"] == 200
        self.follow_nextnonce(r, challenge)

        r = self.send(env, location, self.header(location, challenge))
        assert r.response["status"] == 200
        self.follow_nextnonce(r, challenge)

        r = self.send(env, location, captured)
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED])
        assert r.response["status"] == 401

    @pytest.mark.parametrize("location", BOTH)
    def test_digest_083_replay_does_not_invalidate_the_clients_nonce(self, env, location):
        # The eavesdropper's version: no credentials, no forgery, just one
        # captured Authorization header replayed after the client has moved
        # on. Rejecting it is correct; denying the client's next request is
        # not.
        challenge = self.challenge(env, location)
        captured = self.header(location, challenge)
        r = self.send(env, location, captured)
        assert r.response["status"] == 200
        self.follow_nextnonce(r, challenge)

        replay_status = self.send(env, location, captured).response["status"]

        r = self.send(env, location, self.header(location, challenge))
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED])
        assert replay_status == 401
        assert r.response["status"] == 200, \
            "the replay moved the client's one-time nonce on and locked it out"

    @pytest.mark.parametrize("location", BOTH)
    def test_digest_084_bogus_request_does_not_invalidate_the_clients_nonce(
            self, env, location):
        # Same property with a forged digest rather than a captured one, so
        # it holds however the attacker's request comes to fail.
        challenge = self.challenge(env, location)
        r = self.send(env, location, self.header(location, challenge))
        assert r.response["status"] == 200
        self.follow_nextnonce(r, challenge)

        bogus = self.header(location, challenge, cnonce="bogus",
                            response="0" * 32)
        bogus_status = self.send(env, location, bogus).response["status"]

        r = self.send(env, location, self.header(location, challenge))
        env.httpd_error_log.ignore_recent(
            lognos=[NC_FAILED, NONCE_HASH_INVALID, PASSWORD_MISMATCH])
        assert bogus_status == 401
        assert r.response["status"] == 200, \
            "the bogus request moved the client's one-time nonce on and locked it out"

    @pytest.mark.parametrize("location", BOTH)
    def test_digest_085_replay_rejected_when_the_client_entry_is_gone(self, env,
                                                                      location):
        # The client table is small -- AuthDigestShmemSize defaults to 1000
        # bytes, "~ 12 entries" -- and a request with no credentials at all
        # allocates an entry, since the challenge it gets back has to carry an
        # opaque. An attacker can therefore make gc() discard a client's entry
        # for the price of a dozen bare requests.
        #
        # A captured request must still not be replayable once that has
        # happened. It used to be: check_nonce() skipped the one-time
        # comparison entirely when the client was unknown, so the nonce was
        # taken on trust and the replay served the protected resource.
        challenge = self.challenge(env, location)
        captured = self.header(location, challenge)
        assert self.send(env, location, captured).response["status"] == 200
        assert self.send(env, location, captured).response["status"] == 401

        for _ in range(40):
            env.curl_get(self.url(env, location))

        r = self.send(env, location, captured)
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED])
        assert r.response["status"] == 401, \
            "captured request replayed once the client entry was evicted"
