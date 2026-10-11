"""AuthDigestDomain on a reverse-proxied location.

Digest auth can run at a reverse proxy, for a location mapped by ProxyPass.
Such a request carries PROXYREQ_REVERSE, but its 401 is an ordinary
origin-style WWW-Authenticate (the client authenticates to this server, not
through it), so the configured AuthDigestDomain belongs in the challenge
just as for a non-proxied location.

The suppression test treated any proxy request alike and dropped domain=
for the reverse-proxied case, so clients re-authenticated per URI prefix
and sent the Authorization header outside the intended protection space.
"""

from . import digest_client as dc


class TestDigestProxyDomain:

    def test_digest_130_domain_sent_for_reverse_proxy(self, env):
        r = env.curl_get(env.mkurl("http", "aaa", "/pxdomain/secret.txt"))
        assert r.response["status"] == 401
        challenge = dc.DigestChallenge.parse(
            r.response["header"]["www-authenticate"])
        assert "/pxdomain/" in challenge.domain_list(), \
            "AuthDigestDomain was dropped from a reverse-proxied challenge"
