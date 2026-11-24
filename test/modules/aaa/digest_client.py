"""Minimal hand-rolled RFC 2617 Digest auth client.

curl's own `--digest` handles the challenge/response handshake transparently,
which is no good for testing edge cases (tampered nonces, replayed
nonce-counts, wrong realms, bad algorithm tokens, ...). This module lets
tests parse a WWW-Authenticate challenge, compute the expected response by
hand, and build a (possibly deliberately broken) Authorization header.

mod_auth_digest here only implements qop="auth" (see modules/aaa/mod_auth_digest.c
Open Issues: "MD5-sess and auth-int are not yet implemented"), so this client
only implements the qop=auth request-digest/response-auth formulas from
RFC 2617 section 3.2.2.
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

_PARAM_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s,]+))\s*,?\s*')


def _md5hex(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def parse_params(value: str) -> Dict[str, str]:
    """Parse a comma-separated key=value / key="value" list, as used by
    both WWW-Authenticate and Authentication-Info header values."""
    params = {}
    for m in _PARAM_RE.finditer(value):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        params[key.lower()] = val
    return params


@dataclass
class DigestChallenge:
    realm: Optional[str]
    nonce: Optional[str]
    algorithm: Optional[str] = None
    opaque: Optional[str] = None
    domain: Optional[str] = None
    qop: Optional[str] = None
    stale: bool = False
    raw: str = ""

    @staticmethod
    def parse(www_authenticate: str) -> 'DigestChallenge':
        assert www_authenticate.startswith("Digest "), \
            f"not a Digest challenge: {www_authenticate}"
        params = parse_params(www_authenticate[len("Digest "):])
        return DigestChallenge(
            realm=params.get('realm'),
            nonce=params.get('nonce'),
            algorithm=params.get('algorithm'),
            opaque=params.get('opaque'),
            domain=params.get('domain'),
            qop=params.get('qop'),
            stale=params.get('stale', '').lower() == 'true',
            raw=www_authenticate,
        )

    def domain_list(self) -> List[str]:
        return self.domain.split() if self.domain else []


def ha1(username: str, realm: str, password: str) -> str:
    return _md5hex(f"{username}:{realm}:{password}")


def ha2(method: str, uri: str) -> str:
    return _md5hex(f"{method}:{uri}")


def request_digest(ha1_hex: str, nonce: str, nc: str, cnonce: str,
                    qop: str, ha2_hex: str) -> str:
    return _md5hex(f"{ha1_hex}:{nonce}:{nc}:{cnonce}:{qop}:{ha2_hex}")


def rspauth_digest(ha1_hex: str, nonce: str, nc: str, cnonce: str,
                    qop: str, uri: str) -> str:
    """Authentication-Info's rspauth uses A2 = ':' + uri (no method)."""
    ha2_hex = _md5hex(f":{uri}")
    return _md5hex(f"{ha1_hex}:{nonce}:{nc}:{cnonce}:{qop}:{ha2_hex}")


def build_authorization(username: str, challenge: DigestChallenge, password: str,
                         method: str, uri: str, nc: str = "00000001",
                         cnonce: str = "0a4f113b3c2e7a1d", qop: Optional[str] = "auth",
                         realm: Optional[str] = None, nonce_val: Optional[str] = None,
                         algorithm: Optional[str] = None, response: Optional[str] = None,
                         opaque: Optional[str] = None, include_opaque: bool = True,
                         include_qop_fields: bool = True, extra: Optional[List[str]] = None
                         ) -> str:
    """Build a Digest Authorization header value.

    By default this builds a *correct* response for the given challenge and
    credentials. Any of realm=/nonce_val=/algorithm=/response=/opaque= can be
    overridden to construct deliberately invalid headers, and qop=None with
    include_qop_fields=False builds a legacy RFC 2069-style header (no qop,
    cnonce, or nc) to prove that path is rejected.
    """
    eff_realm = challenge.realm if realm is None else realm
    eff_nonce = challenge.nonce if nonce_val is None else nonce_val
    if response is None:
        h1 = ha1(username, eff_realm, password)
        h2 = ha2(method, uri)
        if qop:
            response = request_digest(h1, eff_nonce, nc, cnonce, qop, h2)
        else:
            # legacy RFC 2069: MD5(HA1:nonce:HA2), no qop/cnonce/nc
            response = _md5hex(f"{h1}:{eff_nonce}:{h2}")

    parts = [
        f'username="{username}"',
        f'realm="{eff_realm}"',
        f'nonce="{eff_nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
    ]
    if algorithm is not None:
        parts.append(f'algorithm={algorithm}')
    if qop and include_qop_fields:
        parts.append(f'qop={qop}')
        parts.append(f'nc={nc}')
        parts.append(f'cnonce="{cnonce}"')
    eff_opaque = challenge.opaque if (opaque is None and include_opaque) else opaque
    if eff_opaque:
        parts.append(f'opaque="{eff_opaque}"')
    if extra:
        parts.extend(extra)
    return "Digest " + ", ".join(parts)
