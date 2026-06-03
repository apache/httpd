r"""Translated from t/modules/expires.t -- mod_expires.

Verifies the Expires header math for ExpiresDefault / ExpiresByType, both at the
server level (from extra.conf) and via a generated .htaccess that toggles
ExpiresActive On/Off and sets random A<seconds>/M<seconds> (and human-readable
"access plus ...") expirations. For each page the test parses Date / Expires /
Last-Modified / Content-Type and checks that Expires-base == the configured
offset (M = relative to Last-Modified, A = relative to Date/access), or that the
Expires header is absent when ExpiresActive is Off.

Perl original: plan tests => ..., have_module 'expires';
"""

import calendar
import os
import random
import re

import pytest

from apache_pytest import need_module

PAGES = ["index.html", "text.txt", "image.gif", "foo.jpg"]
TYPES = ["text/plain", "image/gif", "image/jpeg"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
MONTH_IDX = {m: i for i, m in enumerate(MONTHS)}

NAMES = {
    "Date": "access",
    "Expires": "expires",
    "Last-Modified": "modified",
    "Content-Type": "type",
}


def calculate_seconds(y, m, w, d, h, mi, s):
    return (y * 60 * 60 * 24 * 365 + m * 60 * 60 * 24 * 30
            + w * 60 * 60 * 24 * 7 + d * 60 * 60 * 24
            + h * 60 * 60 + mi * 60 + s)


EXPIRES_DEFAULT = calculate_seconds(10, 6, 2, 3, 12, 30, 19)


def default_exp():
    return {
        "default": f"M{EXPIRES_DEFAULT}",
        "text/plain": "M60",
        "image/gif": "A120",
        "image/jpeg": "A86400",
    }


def _htaccess_path(http):
    return os.path.join(http.vars("documentroot"), "modules", "expires",
                        "htaccess", ".htaccess")


def _write_htaccess(http, content):
    with open(_htaccess_path(http), "w") as f:
        f.write(content)


def _head_str(http, url):
    """Return a HEAD response rendered as a 'Header: value\\n' block."""
    r = http.HEAD(url)
    lines = [f"HTTP/1.1 {r.status_code} {r.reason_phrase}"]
    for k, v in r.headers.items():
        # httpx lowercases header names; re-title-case the ones we look at.
        lines.append(f"{k}: {v}")
    return "\n".join(lines) + "\n"


def convert_to_time(timestr):
    m = re.match(
        r"^\w{3}, (\d+) (\w{3}) (\d{4}) (\d{2}):(\d{2}):(\d{2}).*$", timestr)
    if not m:
        return None
    mday, mon, year, hours, minute, sec = m.groups()
    return calendar.timegm((
        int(year), MONTH_IDX[mon] + 1, int(mday),
        int(hours), int(minute), int(sec), 0, 0, 0))


def expires_test(expires_active, head_str, exp):
    headers = {}
    for header in head_str.split("\n"):
        m = re.match(r"^([\-\w]+): (.*)$", header)
        if m:
            name, value = m.group(1), m.group(2)
            # match the Perl %names keys case-insensitively (httpx lowercases)
            for k in NAMES:
                if name.lower() == k.lower():
                    headers[NAMES[k]] = value
    # Expires header should not exist if ExpiresActive is Off
    if not expires_active:
        return not headers.get("expires")

    for h in ("access", "expires", "modified"):
        if headers.get(h):
            headers[h] = convert_to_time(headers[h]) or 0
        else:
            headers[h] = 0

    type_ = headers.get("type")
    exp_conf = exp.get(type_) if type_ in exp and exp.get(type_) else exp["default"]

    if exp_conf == "0":
        return not headers.get("expires")

    m = re.match(r"^([AM])(\d+)$", exp_conf)
    if not m:
        return False
    exp_type, expected = m.group(1), int(m.group(2))
    if exp_type == "M" and headers["access"] > headers["modified"] + expected:
        expected = headers["access"] - headers["modified"]

    if exp_type == "M":
        actual = headers["expires"] - headers["modified"]
    else:
        actual = headers["expires"] - headers["access"]
    return actual == expected


def get_rand_time_str(rng, a_m):
    y = rng.randrange(2)
    m = rng.randrange(4)
    w = rng.randrange(3)
    d = rng.randrange(20)
    h = rng.randrange(9)
    mi = rng.randrange(50)
    s = rng.randrange(50)
    gmsec = calculate_seconds(y, m, w, d, h, mi, s)
    if rng.randrange(2):
        base = '"access plus' if a_m == "A" else '"modification plus'
        parts = [base]
        if y:
            parts.append(f"{y} years")
        if m:
            parts.append(f"{m} months")
        if w:
            parts.append(f"{w} weeks")
        if d:
            parts.append(f"{d} days")
        if h:
            parts.append(f"{h} hours")
        if mi:
            parts.append(f"{mi} minutes")
        if s:
            parts.append(f"{s} seconds")
        rand_str = " ".join(parts) + '"'
    else:
        rand_str = f"{a_m}{gmsec}"
    return gmsec, rand_str


@need_module("expires")
def test_expires(http):
    rng = random.Random(12345)  # deterministic for reproducibility

    # server-level (extra.conf) settings
    exp = default_exp()
    for page in PAGES:
        head = _head_str(http, f"/modules/expires/{page}")
        assert re.match(r"^HTTP/1\.[01] 200 OK", head), f"200 for {page}"
        assert expires_test(True, head, exp), f"server-level expires for {page}"

    # remove htaccess: everything inherited
    htaccess = _htaccess_path(http)
    if os.path.exists(htaccess):
        os.unlink(htaccess)
    for page in PAGES:
        head = _head_str(http, f"/modules/expires/htaccess/{page}")
        assert expires_test(True, head, default_exp()), \
            f"inherited expires for {page}"

    # with .htaccess
    for on_off in ("On", "Off"):
        active = on_off == "On"
        expires_active_str = f"ExpiresActive {on_off}\n"
        _write_htaccess(http, expires_active_str)
        for page in PAGES:
            head = _head_str(http, f"/modules/expires/htaccess/{page}")
            assert expires_test(active, head, default_exp()), \
                f"ExpiresActive {on_off}: {page}"

        for t in TYPES:
            # just ExpiresDefault
            a_m = rng.choice(["A", "M"])
            gmsec, expires_default = get_rand_time_str(rng, a_m)
            exp = default_exp()
            exp["default"] = f"{a_m}{gmsec}"
            ds = expires_active_str + f"ExpiresDefault {expires_default}\n"
            _write_htaccess(http, ds)
            for page in PAGES:
                head = _head_str(http, f"/modules/expires/htaccess/{page}")
                assert expires_test(active, head, exp), \
                    f"ExpiresDefault {on_off}/{t}/{page}"

            # just ExpiresByType
            a_m = rng.choice(["A", "M"])
            gmsec, expires_bytype = get_rand_time_str(rng, a_m)
            exp = default_exp()
            exp[t] = f"{a_m}{gmsec}"
            ds = expires_active_str + f"ExpiresByType {t} {expires_bytype}\n"
            _write_htaccess(http, ds)
            for page in PAGES:
                head = _head_str(http, f"/modules/expires/htaccess/{page}")
                assert expires_test(active, head, exp), \
                    f"ExpiresByType {on_off}/{t}/{page}"

            # both
            a_m = rng.choice(["A", "M"])
            gmsec, expires_default = get_rand_time_str(rng, a_m)
            exp = default_exp()
            exp["default"] = f"{a_m}{gmsec}"
            a_m = rng.choice(["A", "M"])
            gmsec, expires_bytype = get_rand_time_str(rng, a_m)
            exp[t] = f"{a_m}{gmsec}"
            ds = (expires_active_str
                  + f"ExpiresDefault {expires_default}\n"
                  + f"ExpiresByType {t} {expires_bytype}\n")
            _write_htaccess(http, ds)
            for page in PAGES:
                head = _head_str(http, f"/modules/expires/htaccess/{page}")
                assert expires_test(active, head, exp), \
                    f"both {on_off}/{t}/{page}"

    if os.path.exists(htaccess):
        os.unlink(htaccess)
