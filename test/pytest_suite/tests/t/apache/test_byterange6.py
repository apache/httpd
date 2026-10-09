r"""Translated from t/apache/byterange6.t -- multi-byterange requests with
overlaps that the server merges.

For each case the request sends a set of (possibly overlapping) ranges and the
``actlike`` field describes the ranges the merged response is expected to look
like. Parses the multipart/byteranges response and verifies every actlike range
is covered.

Needs: need_lwp, need_min_apache_version('2.3.15').
"""

import re
from pathlib import Path

import pytest

from apache_pytest import need_lwp, need_min_apache_version

URL = "/apache/chunked/byteranges.txt"
CONTENT = "".join(f"{i:04d}" for i in range(1, 2001))
CLEN = len(CONTENT)

TEST_CASES = [
    {"h": "0-100,70-100,1000-1001", "actlike": "0-100,1000-1001"},
    {"h": "0-90,70-100,1000-1001", "actlike": "0-100,1000-1001"},
    {"h": "0-70,70-100,1000-1001", "actlike": "0-100,1000-1001"},
    {"h": "1-100,70-100,1000-1001", "actlike": "1-100,1000-1001"},
    {"h": "1-90,70-100,1000-1001", "actlike": "1-100,1000-1001"},
    {"h": "1-90,70-100,1000-1001", "actlike": "1-100,1000-1001"},
    {"h": "0-100,70-100,1000-1001,5-6", "actlike": "0-100,1000-1001,5-6"},
    {"h": "0-90,70-100,1000-1001,5-6", "actlike": "0-100,1000-1001,5-6"},
    {"h": "0-70,70-100,1000-1001,5-6", "actlike": "0-100,1000-1001,5-6"},
    {"h": "1-100,70-100,1000-1001,5-6", "actlike": "1-100,1000-1001,5-6"},
    {"h": "1-90,70-100,1000-1001,5-6", "actlike": "1-100,1000-1001,5-6"},
    {"h": "1-90,70-100,1000-1001,5-6", "actlike": "1-100,1000-1001,5-6"},
    {"h": "1-70,70-100,1000-1001", "actlike": "1-100,1000-1001"},
    {"h": "1-70,71-100,1000-1001", "actlike": "1-100,1000-1001"},
    {"h": "1-70,69-100,1000-1001", "actlike": "1-100,1000-1001"},
    {"h": "1-70,0-100,1000-1001", "actlike": "1-100,1000-1001"},
    {"h": "0-70,72-100,1000-1001", "actlike": "0-70,72-100,1000-1001"},
    {"h": "1-70,0-100,1000-1001", "actlike": "0-100,1000-1001"},
    {"h": "1-70,1-100,1000-1001", "actlike": "1-100,1000-1001"},
    {"h": "1-70,2-100,1000-1001", "actlike": "1-100,1000-1001"},
    {"h": "0-100,0-99,1000-1001", "actlike": "0-100,1000-1001"},
    {"h": "0-100,0-100,1000-1001", "actlike": "0-100,1000-1001"},
    {"h": "0-100,0-101,1000-1001", "actlike": "0-101,1000-1001"},
    {"h": "0-100,1-99,1000-1001", "actlike": "0-100,1000-1001"},
    {"h": "0-100,1-100,1000-1001", "actlike": "0-100,1000-1001"},
    {"h": "0-100,1-101,1000-1001", "actlike": "0-101,1000-1001"},
    {"h": "0-100,50-99,1000-1001", "actlike": "0-100,1000-1001"},
    {"h": "0-100,50-100,1000-1001", "actlike": "0-100,1000-1001"},
    {"h": "0-100,50-101,1000-1001", "actlike": "0-101,1000-1001"},
    {"h": "1-10,1-9,99-99", "actlike": "1-10,99-99"},
    {"h": "1-10,1-10,99-99", "actlike": "1-10,99-99"},
    {"h": "1-10,1-11,99-99", "actlike": "1-11,99-99"},
    {"h": "1-10,0-9,99-99", "actlike": "0-10,99-99"},
    {"h": "1-10,0-10,99-99", "actlike": "0-10,99-99"},
    {"h": "1-10,0-11,99-99", "actlike": "0-11,99-99"},
    {"h": "1-10,0-12,99-99", "actlike": "0-12,99-99"},
    {"h": "1-10,0-13,99-99", "actlike": "0-13,99-99"},
    {"h": "1-10,2-11,99-99", "actlike": "1-11,99-99"},
    {"h": "1-10,2-12,99-99", "actlike": "1-12,99-99"},
    {"h": "1-10,2-13,99-99", "actlike": "1-13,99-99"},
    {"h": "1-10,1-9,99-99", "actlike": "1-10,99-99"},
    {"h": "1-11,1-10,99-99", "actlike": "1-11,99-99"},
    {"h": "1-9,1-10,99-99", "actlike": "1-10,99-99"},
    {"h": "0-11,1-10,99-99", "actlike": "0-11,99-99"},
    {"h": "1-9,1-10,99-99", "actlike": "1-10,99-99"},
    {"h": "10-20,1-9,99-99", "actlike": "1-20,99-99"},
    {"h": "10-20,1-10,99-99", "actlike": "1-20,99-99"},
    {"h": "10-20,1-11,99-99", "actlike": "1-20,99-99"},
    {"h": "10-20,1-21,99-99", "actlike": "1-21,99-99"},
    {"h": "5-10,11-12,99-99", "actlike": "5-12,99-99"},
    {"h": "5-10,1-4,99-99", "actlike": "1-10,99-99"},
    {"h": "5-10,1-3,99-99", "actlike": "5-10,1-3,99-99"},
    {"h": "0-1,-1", "actlike": "0-1,-1"},  # PR 51748
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
@need_min_apache_version("2.3.15")
@pytest.mark.parametrize("case", TEST_CASES, ids=lambda c: c["h"])
def test_byterange6(http, case):
    _write_file(http)
    result = http.GET(URL, headers={"Range": "bytes=" + case["h"]})

    ctype = result.headers.get("Content-Type", "")
    m = re.match(r"multipart/byteranges; boundary=(.*)", ctype)
    assert m, f"Wrong Content-Type: {ctype}, for {case['h']}"
    boundary = m.group(1)

    want = _wanted_ranges(case["actlike"])

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
