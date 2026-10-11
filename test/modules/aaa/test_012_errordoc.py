"""An ErrorDocument redirecting into a Digest-protected location.

A request which fails header validation -- e.g. an HTTP/1.1 request with no
Host header -- is rejected in ap_check_request_header, before
ap_post_read_request runs. The Digest module sets up its per-request record
in a post_read_request hook, so that record was never created for such a
request.

If ErrorDocument then redirects the failure into a Digest-protected
location, the auth hook runs for the redirect and walks back along ->prev
to the original request to find the shared record -- which is NULL here.
Dereferencing it crashes the child, so an unauthenticated client can take
down a worker with a single malformed request.
"""

from .env import AAATestEnv


class TestDigestErrorDocument:

    def test_digest_125_errordoc_into_digest_without_prr(self, env):
        # Send an HTTP/1.1 request with the Host header removed; the server
        # answers 400 before the Digest post_read_request hook runs, and the
        # ErrorDocument points into a Digest-protected location.
        url = env.mkurl("http", "aaa", "/anything")
        r = env.curl_get(url, options=["--http1.1", "-H", "Host:"])

        # The request must get an HTTP response, not a reset connection from
        # a crashed child.
        assert r.exit_code == 0, \
            f"no HTTP response (curl exit {r.exit_code}): the worker likely " \
            f"crashed handling the ErrorDocument"
        assert r.response["status"] in (400, 401)

        # The server is still serving afterwards.
        r = env.curl_get(env.mkurl("http", "aaa", "/digest/default/secret.txt"))
        assert r.response["status"] == 401
