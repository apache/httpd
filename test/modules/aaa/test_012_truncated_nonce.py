import re

import pytest

from . import digest_client as dc
from .env import AAATestEnv

class TestDigestTruncatedNonce:

    def test_digest_012_01(self, env):
        url = env.mkurl("http", "aaa", "/digest/default/secret.txt")
        r1 = env.curl_get(url)
        assert r1.response["status"] == 401
        challenge = dc.DigestChallenge.parse(
            r1.response["header"]["www-authenticate"])
        # Truncate: take from the '=' onward, removing most of the base64 time prefix.
        eq_pos = challenge.nonce.index("=")
        truncated_nonce = challenge.nonce[eq_pos:]

        auth_header = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri="/digest/default/secret.txt",
            nonce_val=truncated_nonce)

        start_pos = env.httpd_error_log.current_pos()
        r2 = env.curl_get(url, options=['-H', f'Authorization: {auth_header}'])
        assert r2.response["status"] == 401

        env.httpd_error_log.ignore_recent(lognos=["AH01782"])

    def test_digest_012_02_time_not_base64(self, env):
        # A nonce of the right length, ending in the '=' the time field
        # must end in, whose time field is not base64 beyond its first
        # four characters. The decoder stops there, so the time is only
        # partly decoded; the nonce must be refused for that, before the
        # partial time is used for anything.
        url = env.mkurl("http", "aaa", "/digest/default/secret.txt")
        r1 = env.curl_get(url)
        assert r1.response["status"] == 401
        challenge = dc.DigestChallenge.parse(
            r1.response["header"]["www-authenticate"])
        eq_pos = challenge.nonce.index("=")
        bad_nonce = "AAAA" + "!" * (eq_pos - 4) + challenge.nonce[eq_pos:]
        assert len(bad_nonce) == len(challenge.nonce)

        auth_header = dc.build_authorization(
            AAATestEnv.DIGEST_USER, challenge, AAATestEnv.DIGEST_PASSWORD,
            method="GET", uri="/digest/default/secret.txt",
            nonce_val=bad_nonce)

        r2 = env.curl_get(url, options=['-H', f'Authorization: {auth_header}'])
        assert r2.response["status"] == 401
        stale = dc.DigestChallenge.parse(r2.response["header"]["www-authenticate"])
        assert stale.stale is True

        not_base64 = re.compile(r".*invalid nonce .* - time is not base64")
        assert env.httpd_error_log.scan_recent(not_base64)
        env.httpd_error_log.ignore_recent(matches=[not_base64.pattern])
