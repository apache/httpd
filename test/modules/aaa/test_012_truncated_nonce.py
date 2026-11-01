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
