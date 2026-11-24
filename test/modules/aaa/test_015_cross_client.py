"""The per-client nonce state is updated only by requests which verify, so
nothing unauthenticated can move it (test_007, test_008). It is still keyed
by the opaque alone, and the opaque is public: in the clear in every
challenge and every request, and not covered by the response digest. So
anybody with an account on the realm can quote another client's opaque,
authenticate as themselves, and have that client's state updated with
their nonce-count or nonce.

For the victim this is a 401 on its next request -- a nonce-count that is
suddenly behind, or a one-time nonce that has suddenly been used -- with a
"possible replay attack" logged against it. Not a bypass, since the
attacker only ever authenticates as the account they hold, but a denial
the victim cannot defend against, and a false replay alarm.

An entry is now bound to the user who first used it, and a request from
anybody else quoting it is challenged afresh with an opaque of its own.

"User" here means within the origin server and realm: the same username
under the same realm on another server, with its own accounts, is somebody
else. The nonce is bound to the realm but not to the server, so it
verifies there. AuthDigestDomain is not part of it: a client keeps one
nonce and opaque per server and realm whatever domains it was given, so
it is the same user in every section of the realm, domain or no domain.
"""

from . import digest_client as dc
from .env import AAATestEnv

NC_FAILED = "AH01774"


class TestCrossClient:

    def url(self, env, location):
        return env.mkurl("http", "aaa", f"/digest/{location}/secret.txt")

    def challenge(self, env, location):
        r = env.curl_get(self.url(env, location))
        assert r.response["status"] == 401
        challenge = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert challenge.opaque is not None
        return challenge

    def header(self, location, challenge, user=AAATestEnv.DIGEST_USER,
               password=AAATestEnv.DIGEST_PASSWORD, nc="00000001",
               cnonce="victim-cnonce"):
        return dc.build_authorization(
            user, challenge, password, method="GET",
            uri=f"/digest/{location}/secret.txt", nc=nc, cnonce=cnonce)

    def intruder(self, location, challenge, nc="00000001"):
        """A correct Authorization header for the *other* account, quoting
        the victim's nonce and opaque -- both of which it has seen."""
        return self.header(location, challenge, user=AAATestEnv.DIGEST_USER2,
                           password=AAATestEnv.DIGEST_PASSWORD2, nc=nc,
                           cnonce="intruder-cnonce")

    def send(self, env, location, auth):
        return env.curl_get(self.url(env, location),
                            options=["-H", f"Authorization: {auth}"])

    def test_digest_150_other_user_cannot_move_nonce_count(self, env):
        location = "nccheck"
        victim = self.challenge(env, location)
        r = self.send(env, location, self.header(location, victim, nc="00000001"))
        assert r.response["status"] == 200

        # The other account quotes the victim's opaque with a nonce-count
        # well ahead of the victim's. It is not this client's entry, so it
        # is challenged with one of its own rather than served.
        r = self.send(env, location, self.intruder(location, victim, nc="00000005"))
        assert r.response["status"] == 401
        intruder = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert intruder.stale is True
        assert intruder.opaque != victim.opaque

        # The victim's count was left alone.
        r = self.send(env, location, self.header(location, victim, nc="00000002"))
        assert r.response["status"] == 200, \
            "another user's request moved the victim's nonce-count on"

    def test_digest_151_other_user_cannot_use_up_onetime_nonce(self, env):
        location = "onetime"
        victim = self.challenge(env, location)
        r = self.send(env, location, self.header(location, victim))
        assert r.response["status"] == 200
        ai = dc.parse_params(r.response["header"]["authentication-info"])
        victim.nonce = ai["nextnonce"]

        # The nextnonce went to the victim in the clear; the other account
        # presents it, with the victim's opaque, before the victim does.
        r = self.send(env, location, self.intruder(location, victim))
        assert r.response["status"] == 401
        intruder = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert intruder.stale is True
        assert intruder.opaque != victim.opaque

        # The victim's one-time nonce is still unused.
        r = self.send(env, location, self.header(location, victim))
        assert r.response["status"] == 200, \
            "another user's request used up the victim's one-time nonce"

    def test_digest_152_same_name_on_other_server_cannot_move_nonce_count(self, env):
        location = "nccheck"
        victim = self.challenge(env, location)
        r = self.send(env, location, self.header(location, victim, nc="00000001"))
        assert r.response["status"] == 200

        # The second server has a "digestuser" of its own, with a different
        # password, under the same realm. Its holder quotes the victim's
        # nonce and opaque there.
        url2 = f"http://aaa2.{env.http_tld}:{env.http_port2}/digest/{location}/secret.txt"
        auth = self.header(location, victim, password=AAATestEnv.DIGEST_PASSWORD_VHOST2,
                           nc="00000005", cnonce="intruder-cnonce")
        r = env.curl_get(url2, options=["-H", f"Authorization: {auth}"])
        assert r.response["status"] == 401
        intruder = dc.DigestChallenge.parse(r.response["header"]["www-authenticate"])
        assert intruder.stale is True
        assert intruder.opaque != victim.opaque

        r = self.send(env, location, self.header(location, victim, nc="00000002"))
        assert r.response["status"] == 200, \
            "a same-named user on another server moved the victim's nonce-count on"

    def test_digest_153_same_user_across_domains_keeps_entry(self, env):
        # A client established at a section without AuthDigestDomain
        # carries its nonce and opaque to a section of the same realm which
        # has one. It is the same user, so the entry is kept, not
        # challenged as somebody else's; and it is kept on the way back.
        client = self.challenge(env, "nccheck")
        r = self.send(env, "nccheck", self.header("nccheck", client, nc="00000001"))
        assert r.response["status"] == 200

        r = self.send(env, "nccheck-domain",
                      self.header("nccheck-domain", client, nc="00000002"))
        assert r.response["status"] == 200, \
            "the same user was challenged as another on crossing into a domain"

        r = self.send(env, "nccheck", self.header("nccheck", client, nc="00000003"))
        assert r.response["status"] == 200, \
            "the same user was challenged as another on crossing back"
