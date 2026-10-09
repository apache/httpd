r"""Translated from t/apache/byterange7.t -- Content-Length on byterange
responses, and handling of invalid / unsatisfiable Range headers.

Writes a 40000-byte file then:
  * checks Content-Length matches the body for multi-range (206) responses;
  * checks invalid Range headers produce a full 200 (with or without "bytes=");
  * checks unsatisfiable ranges produce the expected 416/206/200.

Needs: need_lwp.
"""

from pathlib import Path

import pytest

from apache_pytest import need_lwp, t_cmp

URL = "/apache/chunked/byteranges.txt"
CONTENT = "".join(f"{i:04d}" for i in range(1, 10001))
REAL_CLEN = len(CONTENT)

TC_RANGES_CL = [1, 2, 10, 50, 100]
TC_INVALID = ["", ",", "7-1", "foo", "1-4,x", "1-4,5-2", "100000-110000,5-2"]
TC_416 = {
    "100000-110000": 416,
    "100000-110000,200000-": 416,
    "1000-200000": 206,  # truncated until end
    "100000-110000,1000-2000": 206,  # ignore unsatisfiable range
    "100000-110000,2000-1000": 200,  # invalid, ignore whole header
}


def _write_file(http):
    file = Path(http.vars("serverroot")) / ("htdocs" + URL)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(CONTENT)


@need_lwp()
@pytest.mark.parametrize("num", TC_RANGES_CL)
def test_content_length(http, num):
    _write_file(http)
    ranges = ",".join(f"{i * 100}-{i * 100 + 1}" for i in range(num))
    result = http.GET(URL, headers={"Range": f"bytes={ranges}"})
    assert result.status_code == 206, "did not get 206"
    body = result.content
    blen = len(body)
    assert blen != REAL_CLEN, "Did get full content, should have gotten only parts"
    clen = result.headers.get("Content-Length")
    if clen is not None:
        assert blen == int(clen), "Content-Length does not match body"


@need_lwp()
@pytest.mark.parametrize(
    "rng", TC_INVALID + ["bytes=" + r for r in TC_INVALID]
)
def test_invalid_ranges(http, rng):
    _write_file(http)
    result = http.GET(URL, headers={"Range": rng})
    code = result.status_code
    assert code != 206, f"got partial content for invalid range header {rng!r}"
    assert code == 200, f"unexpected code {code} for range {rng!r}"
    assert result.text == CONTENT, "Body did not match expected content"


@need_lwp()
@pytest.mark.parametrize("rng", sorted(TC_416))
def test_unsatisfiable(http, rng):
    _write_file(http)
    result = http.GET(URL, headers={"Range": f"bytes={rng}"})
    assert t_cmp(result.status_code, TC_416[rng])
