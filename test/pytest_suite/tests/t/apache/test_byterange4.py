r"""Translated from t/apache/byterange4.t -- byterange boundaries near bucket
boundaries (uses mod_bucketeer to create 200-byte buckets).

Perl original built a 4000-byte file split into 200-byte buckets separated by
0x02 (the mod_bucketeer split marker), then requested every start/end pair drawn
from a set of range boundaries and checked the returned slice matches.

Needs: need_lwp, mod_bucketeer.
"""

from pathlib import Path

import pytest

from apache_pytest import need_lwp, need_module

URL = "/apache/chunked/byteranges.txt"
BLEN = 200
B = chr(0x02)

CONTENT = "".join(f"{i:04d}" for i in range(1, 2001))
CLEN = len(CONTENT)

RANGE_BOUNDARIES = [
    0, 1, 2,
    BLEN - 2, BLEN - 1, BLEN, BLEN + 1,
    3 * BLEN - 2, 3 * BLEN - 1, 3 * BLEN, 3 * BLEN + 1,
    CLEN - BLEN - 2, CLEN - BLEN - 1, CLEN - BLEN, CLEN - BLEN + 1,
    CLEN - 2, CLEN - 1,
]

TEST_CASES = [
    (start, end)
    for start in RANGE_BOUNDARIES
    for end in RANGE_BOUNDARIES
    if end >= start
]


def _write_bucketed_file(http):
    file = Path(http.vars("serverroot")) / ("htdocs" + URL)
    file.parent.mkdir(parents=True, exist_ok=True)
    buckets = [CONTENT[i : i + BLEN] for i in range(0, len(CONTENT), BLEN)]
    file.write_text(B.join(buckets))


@need_lwp()
@need_module("mod_bucketeer")
@pytest.mark.parametrize("start,end", TEST_CASES, ids=lambda v: str(v))
def test_byterange4(http, start, end):
    _write_bucketed_file(http)
    result = http.GET(URL, headers={"Range": f"bytes={start}-{end}"})
    expect = CONTENT[start : end + 1]
    assert result.text == expect
