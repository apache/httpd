r"""Translated from t/apache/byterange5.t -- multi-byterange requests with
re-ordering allowed.

Writes a 8000-byte file, requests several multi-range sets, parses the
multipart/byteranges response, verifies each returned chunk matches the source
content, the final boundary is well-formed, and every wanted range is covered
by some returned range.

Needs: need_lwp.
"""

import re
from pathlib import Path

import pytest

from apache_pytest import need_lwp

URL = "/apache/chunked/byteranges.txt"
CONTENT = "".join(f"{i:04d}" for i in range(1, 2001))
CLEN = len(CONTENT)

TEST_CASES = [
    "0-1,1000-1001",
    "1000-1100,100-200",
    "1000-1100,100-200,2000-2200",
    "1000-1100,100-200,2000-",
    "3000-,100-200,2000-2200",
]


def _write_file(http):
    file = Path(http.vars("serverroot")) / ("htdocs" + URL)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(CONTENT)


def _wanted_ranges(spec):
    out = []
    for w in spec.split(","):
        m = re.match(r"(\d*)-(\d*)", w)
        start, end = m.group(1), m.group(2)
        if start == "":
            out.append((CLEN - int(end), CLEN - 1))
        elif end == "":
            out.append((int(start), CLEN - 1))
        else:
            out.append((int(start), int(end)))
    return out


@need_lwp()
@pytest.mark.parametrize("spec", TEST_CASES)
def test_byterange5(http, spec):
    _write_file(http)
    result = http.GET(URL, headers={"Range": f"bytes={spec}"})

    ctype = result.headers.get("Content-Type", "")
    m = re.match(r"multipart/byteranges; boundary=(.*)", ctype)
    assert m, f"Wrong Content-Type: {ctype}"
    boundary = m.group(1)

    want = _wanted_ranges(spec)

    got = []
    rcontent = result.text
    part_re = re.compile(
        r"^[\n\s]*--" + re.escape(boundary) + r"\s*?\n(.+?)\r\n\r\n", re.DOTALL
    )
    while True:
        pm = part_re.search(rcontent)
        if not pm:
            break
        headers = pm.group(1)
        rcontent = rcontent[pm.end():]
        hm = re.search(
            r"^Content-range: bytes (\d+)-(\d+)/\d*$", headers, re.IGNORECASE | re.MULTILINE
        )
        assert hm, f"Can't parse Content-range in {headers!r}"
        frm, to = int(hm.group(1)), int(hm.group(2))
        got.append((frm, to))
        chunk = rcontent[: to - frm + 1]
        rcontent = rcontent[to - frm + 1:]
        expect = CONTENT[frm : to + 1]
        assert chunk == expect, f"Wrong content in range {frm}-{to}"

    assert re.match(
        r"^[\s\n]*--" + re.escape(boundary) + r"--[\s\n]*$", rcontent
    ), f"error parsing final boundary: {rcontent!r}"

    for w in want:
        found = any(g[0] <= w[0] and g[1] >= w[1] for g in got)
        assert found, f"Data for {w[0]}-{w[1]} not found in response"
