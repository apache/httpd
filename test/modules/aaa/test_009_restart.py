"""Per-client state across a server restart.

The client table lives in a shared memory segment created by post_config,
and that segment does not survive a restart: the restart loop in
server/main.c clears pconf, which destroys the segment, and post_config
then builds a new one, empty.

The nonce does survive, because the secret it is hashed with is kept in
retained data across restarts. So a client returning after a restart
presents a nonce which still verifies, naming per-client state which no
longer exists.

The right answer for such a client is a stale=true challenge: its
credentials were never in doubt, only the server-side state backing its
nonce is gone, so it should retry silently against the fresh nonce rather
than being told its authentication failed. mod_auth_digest does exactly
that when it finds the client unknown (AH10618).

It stopped doing it once the id had been handed to somebody else, which the
ids restarting from 1 made routine rather than exotic: the first clients
seen after a restart took exactly the ids the clients from before it were
still quoting. A returning client was then checked against a *different*
client's entry and reported as a nonce-count failure -- stale=false, which
a browser shows as a failed password.

With one-time nonces it was a replay hole rather than a wrong answer to the
user. Single use is enforced by remembering the last nonce each client
used, and that memory dies with the segment while the nonce does not; the
one-time counter restarts at 0, so a nonce from before the restart outranks
anything the new holder of its id has reached, and was accepted. An
eavesdropper who had captured one used request only had to wait for a
restart.

The ids are now seeded randomly for each segment, so a returning client's
opaque no longer names anybody, and it takes the unknown-client path above.
"""

from . import digest_client as dc
from .env import AAATestEnv

NC_FAILED = "AH01774"
CLIENT_UNKNOWN = "AH10618"
ONETIME_REUSED = "AH01779"


class TestDigestRestart:

    def url(self, env, location, path="secret.txt"):
        return env.mkurl("http", "aaa", f"/digest/{location}/{path}")

    def uri(self, location):
        return f"/digest/{location}/secret.txt"

    def challenge(self, env, location):
        r = env.curl_get(self.url(env, location))
        assert r.response["status"] == 401
        return dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

    def header(self, location, challenge, nc="00000001", cnonce="restart-cnonce"):
        return dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=self.uri(location), nc=nc, cnonce=cnonce)

    def send(self, env, location, auth):
        return env.curl_get(self.url(env, location),
                            options=["-H", f"Authorization: {auth}"])

    def reload(self, env):
        assert env.apache_reload() == 0, "graceful restart failed"

    def challenge_of(self, r):
        """The challenge carried by a 401 response."""
        return dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

    def follow_nextnonce(self, r, challenge):
        ai = dc.parse_params(r.response["header"]["authentication-info"])
        assert "nextnonce" in ai
        challenge.nonce = ai["nextnonce"]

    def test_digest_090_returning_client_is_challenged_as_stale(self, env):
        # A client which authenticated before a restart comes back afterwards
        # with the nonce it was holding. The state naming its opaque is gone,
        # so the request cannot be accepted -- but the client did nothing
        # wrong, and must be told to retry rather than that it failed.
        location = "nccheck"
        self.reload(env)
        challenge = self.challenge(env, location)
        assert self.send(env, location,
                         self.header(location, challenge)).response["status"] == 200

        self.reload(env)

        r = self.send(env, location, self.header(location, challenge, "00000002"))
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED, CLIENT_UNKNOWN])
        assert r.response["status"] == 401
        fresh = self.challenge_of(r)
        assert fresh.stale, \
            "a client returning after a restart was told its authentication " \
            "failed, rather than being asked to retry with a fresh nonce"

        # ...and the retry against that fresh challenge succeeds.
        assert self.send(env, location,
                         self.header(location, fresh)).response["status"] == 200

    def test_digest_091_returning_client_is_stale_even_if_its_id_was_reused(self, env):
        # Same property, but now the id space has caught up: after the restart
        # a new client is handed the id the returning client still quotes.
        # That is not an unlikely coincidence -- the counter restarts from 1,
        # so the first clients seen after a restart take exactly the ids the
        # clients from before it are holding.
        location = "nccheck"
        self.reload(env)
        challenge = self.challenge(env, location)
        assert self.send(env, location,
                         self.header(location, challenge)).response["status"] == 200

        self.reload(env)

        # A different client arrives first and is given the recycled id.
        # Today that newcomer is handed the returning client's id, because
        # the counter restarts at 1. The assertions below deliberately do not
        # require it: a server which stops recycling ids satisfies this
        # property by making the returning client simply unknown, which is
        # the outcome under test either way.
        newcomer = self.challenge(env, location)
        assert self.send(env, location,
                         self.header(location, newcomer)).response["status"] == 200

        r = self.send(env, location, self.header(location, challenge, "00000002"))
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED, CLIENT_UNKNOWN])
        assert r.response["status"] == 401
        assert self.challenge_of(r).stale, \
            "a returning client was reported as a possible replay attack " \
            "because its id had been given to somebody else"

    def test_digest_092_onetime_nonce_from_before_a_restart_is_not_accepted(self, env):
        # One-time nonces are ordered by a counter which restarts at 0 with
        # the segment, while the nonce itself stays verifiable. A client
        # holding an unused nonce from before the restart therefore presents
        # a counter value the new server has not reached yet.
        location = "onetime"
        self.reload(env)
        challenge = self.challenge(env, location)
        for _ in range(5):
            r = self.send(env, location, self.header(location, challenge))
            assert r.response["status"] == 200
            self.follow_nextnonce(r, challenge)
        # challenge.nonce is now an unused nonce, well ahead of the counter
        # that a restart will reset to 0.

        self.reload(env)

        newcomer = self.challenge(env, location)
        r = self.send(env, location, self.header(location, newcomer))
        assert r.response["status"] == 200
        self.follow_nextnonce(r, newcomer)

        # The nonce from the previous server generation must not be usable.
        stale_use = self.send(env, location, self.header(location, challenge))
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED, CLIENT_UNKNOWN,
                                                  ONETIME_REUSED])
        assert stale_use.response["status"] == 401, \
            "a one-time nonce issued before the restart was accepted after it"

        # ...and the client which legitimately owns that entry still works.
        assert self.send(env, location,
                         self.header(location, newcomer)).response["status"] == 200, \
            "the stale nonce locked out the client holding that id"

    def test_digest_093_onetime_request_cannot_be_replayed_across_a_restart(self, env):
        # The severity case. A one-time nonce is single-use because the server
        # remembers the last nonce each client used -- and that memory does
        # not survive a restart, while the nonce does. So an eavesdropper who
        # captured one *successfully used* request needs only to wait for a
        # restart: the counter it outranks has gone back to zero, and the id
        # it names is handed straight back out.
        location = "onetime"
        self.reload(env)
        challenge = self.challenge(env, location)
        for _ in range(5):
            r = self.send(env, location, self.header(location, challenge))
            assert r.response["status"] == 200
            captured = self.header(location, challenge)   # a used request
            self.follow_nextnonce(r, challenge)

        assert self.send(env, location, captured).response["status"] == 401, \
            "the captured request was not single-use before the restart"

        self.reload(env)

        # Somebody authenticates, so the recycled id names a live entry.
        newcomer = self.challenge(env, location)
        assert self.send(env, location,
                         self.header(location, newcomer)).response["status"] == 200

        replay = self.send(env, location, captured)
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED, CLIENT_UNKNOWN,
                                                  ONETIME_REUSED])
        assert replay.response["status"] == 401, \
            "a captured one-time request was replayed successfully after a restart"
