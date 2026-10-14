"""A malformed Digest Authorization header must leak nothing.

test_001 covers that a malformed header is rejected with a 401 and a
fresh (non-stale) challenge. These tests watch what the rejection path
itself emits: parsing a header with bogus fields must not read
uninitialized memory into the error log, and the challenge carried by
the response must stay printable ASCII rather than echo raw bytes back
at the client.
"""

from . import digest_client as dc
from .env import AAATestEnv


class TestMalformedHeader:

    def url(self, env):
        return env.mkurl("http", "aaa", "/digest/default/secret.txt")

    def test_digest_170_no_leaked_fill_bytes_in_error_log(self, env):
        # When httpd processes a malformed Digest header, no fill-pattern
        # bytes (e.g. repeated 0x41 = 'A' from a valgrind malloc-fill)
        # should appear in the error log, which would indicate
        # uninitialized memory being read.
        #
        # Read the current end-of-log position, send the malformed
        # request, then check the new lines for the fill pattern.
        log_pos = env.httpd_error_log.current_pos()
        malformed_auth = (
            'Digest username, realm="' + AAATestEnv.REALM + '", '
            'nonce=a, uri=/digest/default/secret.txt, '
            'digest=a, cnonce=a, nonce_count=10, response=A'
        )
        r = env.curl_get(self.url(env),
                         options=["-H", f"Authorization: {malformed_auth}"])
        assert r.response["status"] == 401
        # Check the error log lines written since log_pos do not contain
        # a run of 'A' characters that would indicate leaked
        # uninitialized memory.
        with open(env.httpd_error_log.path) as fd:
            fd.seek(log_pos)
            for line in fd:
                assert "AAAA" not in line, \
                    f"possible uninitialized memory leak in error log: {line}"
        env.httpd_error_log.ignore_recent(lognos=["AH01782"])

    def test_digest_171_challenge_is_printable_ascii(self, env):
        # After a malformed Authorization, the response headers must not
        # contain raw or binary data outside the expected Digest challenge
        # parameters.
        malformed_auth = (
            'Digest username="x", realm="wrong", '
            'nonce="bad", uri="/digest/default/secret.txt", '
            'response="' + ("41" * 16) + '", qop=auth, '
            'nc=00000001, cnonce="test"'
        )
        r = env.curl_get(self.url(env),
                         options=["-H", f"Authorization: {malformed_auth}"])
        assert r.response["status"] == 401
        www_auth = r.response["header"]["www-authenticate"]
        # The WWW-Authenticate value must start with "Digest " and contain
        # only printable ASCII characters.
        assert www_auth.startswith("Digest ")
        assert all(32 <= ord(c) < 127 for c in www_auth), \
            f"non-printable characters in WWW-Authenticate: {www_auth!r}"
        env.httpd_error_log.ignore_recent(lognos=["AH01782", "AH01788",
                                                   "AH01776", "AH01794"])
