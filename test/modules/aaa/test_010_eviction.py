"""Which client entries are discarded when the table is full.

The client table is a fixed-size shared memory segment (AuthDigestShmemSize,
pinned small by conftest here), and gc() makes room by discarding one entry
from each bucket. An entry is allocated for any request which needs a
challenge, including one carrying no credentials at all, since the challenge
has to carry the identifier the client will be tracked by. An attacker can
therefore fill the table with bare requests as fast as it can send them.

What that costs the clients already using the server depends on which entry
gc() picks. Discarding a client which has authenticated costs it a request:
its nonce-count and last-used nonce go with the entry, so its next request
is answered with a fresh challenge (stale=true) and has to be retried.
Discarding a client which has never authenticated costs nothing at all --
the entry records nothing yet, and the client simply gets a new identifier
with its next challenge.

So gc() prefers the entries which have never been used to authenticate,
which are exactly the ones a flood of unauthenticated requests creates.

"Never used to authenticate" is last_nonce_time == 0, which is exact in both
of the configurations that track clients: an accepted request stores the
time its nonce was generated at, which is a wall-clock time for a nonce with
a lifetime and a counter which starts at 1 for a one-time nonce. Neither is
ever 0. The tests below run against both to pin that.
"""

import pytest

from . import digest_client as dc
from .env import AAATestEnv

NC_FAILED = "AH01774"
CLIENT_UNKNOWN = "AH10618"

# A location tracking clients for the nonce-count, and one tracking them for
# one-time nonces: the two put different kinds of value in last_nonce_time.
BOTH = ["nccheck", "onetime"]


class TestDigestEviction:

    def url(self, env, location):
        return env.mkurl("http", "aaa", f"/digest/{location}/secret.txt")

    def uri(self, location):
        return f"/digest/{location}/secret.txt"

    def challenge(self, env, location):
        r = env.curl_get(self.url(env, location))
        assert r.response["status"] == 401
        return dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])

    def header(self, location, challenge, nc="00000001", cnonce="eviction-cnonce"):
        return dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri=self.uri(location), nc=nc, cnonce=cnonce)

    def send(self, env, location, auth):
        return env.curl_get(self.url(env, location),
                            options=["-H", f"Authorization: {auth}"])

    def advance(self, r, challenge):
        """Prepare the client's next request, and return the nc to send with
        it. A one-time nonce is replaced by the nextnonce just handed out,
        and the count restarts at 1 for it; otherwise the nonce stays and the
        count goes up."""
        ai = r.response["header"].get("authentication-info")
        if ai:
            params = dc.parse_params(ai)
            if "nextnonce" in params:
                challenge.nonce = params["nextnonce"]
                return "00000001"
        return "00000002"

    def flood(self, env, location, count):
        """Bare requests, each of which allocates a client entry."""
        for _ in range(count):
            env.curl_get(self.url(env, location))

    @pytest.mark.parametrize("location", BOTH)
    def test_digest_100_authenticated_client_survives_a_flood(self, env, location):
        # The legitimate client authenticates, so its entry now records the
        # nonce it used.
        challenge = self.challenge(env, location)
        r = self.send(env, location, self.header(location, challenge))
        assert r.response["status"] == 200
        nc = self.advance(r, challenge)

        # An attacker fills the table several times over with requests which
        # carry no credentials at all.
        self.flood(env, location, 60)

        # The victim carries on. Its entry must still be there: it is the
        # only one in the table which is worth keeping.
        r = self.send(env, location, self.header(location, challenge, nc))
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED, CLIENT_UNKNOWN])
        assert r.response["status"] == 200, \
            "a flood of unauthenticated requests evicted an authenticated client"

    @pytest.mark.parametrize("location", BOTH)
    def test_digest_101_unused_entries_are_the_ones_discarded(self, env, location):
        # The counterpart: the entries a flood creates are themselves the
        # ones discarded, so a flood cannot fill the table permanently. The
        # opaque handed out at the start of one no longer names an entry by
        # the end, which the server reports by minting a new one rather than
        # echoing it back -- and as a stale challenge, since nothing was
        # wrong with the client's credentials.
        first = self.challenge(env, location)
        self.flood(env, location, 60)

        r = self.send(env, location, self.header(location, first))
        env.httpd_error_log.ignore_recent(lognos=[NC_FAILED, CLIENT_UNKNOWN])
        assert r.response["status"] == 401
        again = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert again.opaque != first.opaque, \
            "the unused entry should have been discarded by the flood"
        assert again.stale, \
            "a client whose unused entry was discarded should be re-challenged " \
            "as stale, not told its authentication failed"
