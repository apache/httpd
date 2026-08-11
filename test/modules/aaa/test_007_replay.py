"""Replay-attack scenarios against AuthDigestNcCheck.

AuthDigestNcCheck exists to detect replayed requests: the server tracks the
highest nonce-count it has accepted from a client (identified by its opaque)
for the nonce that client is using, and requires each request to raise it.

The security property under test here is not just "the replayed request is
rejected", but that rejecting it must not damage the legitimate client:

    With nonce-count checking enabled, a replay attack MUST NOT affect the
    original (legitimate) client by resetting its nonce count.

It used to. On a failed authentication mod_auth_digest issues a fresh
challenge via note_digest_auth_failure(), and for an already-known
(opaque-identified) client that path reset client->nonce_count to 0, while
the post_read_request hook re-incremented the count from 0 on the next
request carrying that opaque. An attacker who could make *any* request fail
for the victim's opaque therefore rewound the victim's counter, with two
consequences:

  * the legitimate client's next in-sequence nc no longer matched, so it
    was locked out (denial of service against the victim), and
  * the attacker's replayed request lined up with the rewound counter and
    was accepted -- 200, 401, 200, 401, ... for one captured header, or
    every time if the attacker rewound the counter deliberately first.

The count is now tracked per (client, nonce) and updated only for a request
which has been fully verified, so a request which fails to authenticate
leaves the victim's state untouched.
"""

import time

from . import digest_client as dc
from .env import AAATestEnv

# See the note in test_003_nccheck.py: a failed nc check is not reported as
# stale, since it is a distinct failure mode from an invalid/expired nonce.
NC_FAILED = "AH01774"
NONCE_HASH_INVALID = "AH01776"
PASSWORD_MISMATCH = "AH01794"


class TestDigestReplay:

    LOCATION = "nccheck"

    def url(self, env, path="secret.txt"):
        return env.mkurl("http", "aaa", f"/digest/{self.LOCATION}/{path}")

    @property
    def uri(self):
        return f"/digest/{self.LOCATION}/secret.txt"

    def challenge(self, env):
        r = env.curl_get(self.url(env))
        assert r.response["status"] == 401
        return dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

    def victim_header(self, challenge, nc, cnonce="victim-cnonce"):
        """A correct Authorization header from the legitimate client."""
        return dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=self.uri, nc=nc, cnonce=cnonce)

    def attacker_header(self, challenge, nc="00000001", cnonce="attacker-cnonce"):
        """A well-formed Digest header carrying the victim's opaque and nonce
        but a bogus response digest. An attacker who has merely *seen* one of
        the victim's requests can build this; no credentials are needed."""
        return dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, "not-the-password",
            method="GET", uri=self.uri, nc=nc, cnonce=cnonce,
            response="0" * 32)

    def send(self, env, auth):
        return env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])

    def test_digest_070_replay_does_not_lock_out_legit_client(self, env):
        # The legitimate client authenticates a few times, in sequence.
        challenge = self.challenge(env)
        for nc in ["00000001", "00000002", "00000003"]:
            assert self.send(env, self.victim_header(challenge, nc)).response["status"] == 200

        # An attacker replays a request captured earlier in that sequence.
        # Rejecting it is correct...
        replayed = self.victim_header(challenge, "00000002")
        replay_status = self.send(env, replayed).response["status"]

        # ...but it must not disturb the legitimate client, which knows
        # nothing of the replay and simply carries on with its next nc.
        r = self.send(env, self.victim_header(challenge, "00000004"))
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED])
        assert replay_status == 401
        assert r.response["status"] == 200, \
            "the replay reset the victim's nonce-count and locked it out"

    def test_digest_071_bogus_request_does_not_lock_out_legit_client(self, env):
        # Same property, but the attacker does not even need to have captured
        # a complete valid request: any well-formed Digest header quoting the
        # victim's opaque is enough to rewind the victim's counter.
        challenge = self.challenge(env)
        for nc in ["00000001", "00000002"]:
            assert self.send(env, self.victim_header(challenge, nc)).response["status"] == 200

        bogus_status = self.send(env, self.attacker_header(challenge)).response["status"]

        r = self.send(env, self.victim_header(challenge, "00000003"))
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED, PASSWORD_MISMATCH])
        assert bogus_status == 401
        assert r.response["status"] == 200, \
            "a bogus request reset the victim's nonce-count and locked it out"

    def test_digest_072_captured_request_is_never_accepted_twice(self, env):
        # The flip side of the same defect. One captured Authorization header
        # is replayed verbatim; the first send is the genuine request, so it
        # succeeds, and every later send must be rejected. Before the fix the
        # rejection rewound the counter, so the replay after it lined up
        # again: the observed pattern was 200, 401, 200, 401, ...
        challenge = self.challenge(env)
        captured = self.victim_header(challenge, "00000001", cnonce="captured-cnonce")

        assert self.send(env, captured).response["status"] == 200
        statuses = [self.send(env, captured).response["status"] for _ in range(4)]
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED])
        assert statuses == [401, 401, 401, 401], \
            f"replayed request was accepted again: {statuses}"

    def test_digest_073_attacker_cannot_force_replay_to_succeed(self, env):
        # Severity check: the attacker must not be able to line the counter
        # up on demand. Before the fix, sending a bogus request first rewound
        # the counter to 0, so the replay that followed succeeded every
        # single time.
        challenge = self.challenge(env)
        captured = self.victim_header(challenge, "00000001", cnonce="captured-cnonce")
        assert self.send(env, captured).response["status"] == 200

        statuses = []
        for _ in range(3):
            self.send(env, self.attacker_header(challenge))
            statuses.append(self.send(env, captured).response["status"])
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED, PASSWORD_MISMATCH])
        assert statuses == [401, 401, 401], \
            f"attacker replayed at will by forcing a counter reset: {statuses}"

    def test_digest_074_legit_client_recovers_via_fresh_challenge(self, env):
        # Invariant: a client whose nc is rejected is handed a fresh
        # challenge, and following that challenge -- new nonce, so the count
        # starts over at 1 -- gets it working again. Simply never resetting
        # the count, without tying it to the nonce it was counted for, would
        # break this.
        challenge = self.challenge(env)
        assert self.send(env, self.victim_header(challenge, "00000001")).response["status"] == 200

        # provoke the rejection with a replay of that first request
        r = self.send(env, self.victim_header(challenge, "00000001"))
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED])
        fresh = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert fresh.stale is False
        assert fresh.opaque == challenge.opaque, \
            "the client keeps its identity across a re-challenge"
        assert fresh.nonce != challenge.nonce

        r = self.send(env, self.victim_header(fresh, "00000001"))
        assert r.response["status"] == 200

    def test_digest_075_nonce_is_bound_to_opaque(self, env):
        # A captured header cannot be re-pointed at a *different* client
        # session to dodge that session's nonce-count: the nonce hash is
        # computed over the opaque (gen_nonce_hash()), so quoting one
        # client's nonce under another client's opaque fails the hash check
        # outright, and is reported as stale.
        victim = self.challenge(env)
        captured = self.victim_header(victim, "00000001", cnonce="captured-cnonce")
        assert self.send(env, captured).response["status"] == 200

        attacker = self.challenge(env)
        assert attacker.opaque != victim.opaque
        spliced = dc.build_authorization(
            AAATestEnv.DIGEST_USER, victim, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=self.uri, nc="00000001", cnonce="captured-cnonce",
            opaque=attacker.opaque)
        r = self.send(env, spliced)
        env.httpd_error_log.ignore_recent(lognos=[NONCE_HASH_INVALID])
        assert r.response["status"] == 401
        assert dc.DigestChallenge.parse(
            r.response["header"]["www-authenticate"]).stale is True


class TestDigestNcCheckExpiry:
    """AuthDigestNcCheck combined with an expiring nonce.

    The nonce is checked before the nonce-count, so that an expired nonce
    still produces a "stale=true" challenge rather than being reported as a
    replay -- the client then retries silently against the fresh nonce, with
    its count restarted at 1.
    """

    LOCATION = "nccheck-shortlife"   # AuthDigestNcCheck On, lifetime 2s

    def url(self, env):
        return env.mkurl("http", "aaa", f"/digest/{self.LOCATION}/secret.txt")

    def challenge(self, env):
        r = env.curl_get(self.url(env))
        assert r.response["status"] == 401
        return dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

    def send(self, env, challenge, nc):
        auth = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=f"/digest/{self.LOCATION}/secret.txt", nc=nc,
            cnonce="expiry-cnonce")
        return env.curl_get(self.url(env), options=["-H", f"Authorization: {auth}"])

    def test_digest_076_expired_nonce_restarts_the_count(self, env):
        challenge = self.challenge(env)
        assert self.send(env, challenge, "00000001").response["status"] == 200
        assert self.send(env, challenge, "00000002").response["status"] == 200

        time.sleep(3)

        # past its lifetime: reported as stale, not as a nonce-count failure
        r = self.send(env, challenge, "00000003")
        assert r.response["status"] == 401
        fresh = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert fresh.stale is True

        # the client restarts its count for the fresh nonce, which must not
        # collide with the count already tracked for the expired one
        assert self.send(env, fresh, "00000001").response["status"] == 200
        assert self.send(env, fresh, "00000002").response["status"] == 200

        # and the expired nonce stays unusable
        r = self.send(env, challenge, "00000004")
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01776", NC_FAILED])
