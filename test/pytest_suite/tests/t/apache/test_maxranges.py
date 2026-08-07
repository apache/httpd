r"""Translated from t/apache/maxranges.t -- MaxRanges directive.

Writes an 8000-byte file, then for various MaxRanges-configured locations
checks that a range request returns the expected status (206 when ranges are
honored, 200 when the configured limit causes the full body to be returned).

Needs: need_lwp, mod_alias, and (>= 2.3.15 or >= 2.2.21).
"""

from pathlib import Path

import pytest

from apache_pytest import need_lwp, need_module

URL = "/apache/chunked/byteranges.txt"
CONTENT = "".join(f"{i:04d}" for i in range(1, 2001))

_medrange = ""
_longrange = ""
for _i in range(51):
    _longrange += "0-1,3-4,0-1,3-4,"
    if _i % 2:
        _medrange += "0-1,3-4,0-1,3-4,"
MEDRANGE = _medrange
LONGRANGE = _longrange

TEST_CASES = [
    ("/maxranges/default/byteranges.txt", "0-100", "206"),
    ("/maxranges/default/byteranges.txt", MEDRANGE, "206"),
    ("/maxranges/default/byteranges.txt", LONGRANGE, "200"),
    ("/maxranges/default-explicit/byteranges.txt", "0-100", "206"),
    ("/maxranges/default-explicit/byteranges.txt", MEDRANGE, "206"),
    ("/maxranges/default-explicit/byteranges.txt", LONGRANGE, "200"),
    ("/maxranges/none/byteranges.txt", "0-100", "200"),
    ("/maxranges/none/byteranges.txt", MEDRANGE, "200"),
    ("/maxranges/none/byteranges.txt", LONGRANGE, "200"),
    ("/maxranges/1/merge/none/byteranges.txt", "0-100", "200"),
    ("/maxranges/1/merge/none/byteranges.txt", MEDRANGE, "200"),
    ("/maxranges/1/merge/none/byteranges.txt", LONGRANGE, "200"),
    ("/maxranges/1/byteranges.txt", "0-100", "206"),
    ("/maxranges/1/byteranges.txt", "0-100,200-300", "200"),
    ("/maxranges/2/byteranges.txt", "0-100,200-300", "206"),
    ("/maxranges/2/byteranges.txt", "0-100,200-300,400-500", "200"),
    ("/maxranges/unlimited/byteranges.txt", "0-100", "206"),
    ("/maxranges/unlimited/byteranges.txt", MEDRANGE, "206"),
    ("/maxranges/unlimited/byteranges.txt", LONGRANGE, "206"),
]


def _write_file(http):
    file = Path(http.vars("serverroot")) / ("htdocs" + URL)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(CONTENT)


@need_lwp()
@need_module("mod_alias")
@pytest.mark.parametrize(
    "url,rng,status",
    TEST_CASES,
    ids=[f"{c[0]}:{c[2]}" for c in TEST_CASES],
)
def test_maxranges(http, url, rng, status):
    if not (
        http.have_min_apache_version("2.3.15")
        or http.have_min_apache_version("2.2.21")
    ):
        pytest.skip("needs >= 2.3.15 or >= 2.2.21")
    _write_file(http)
    result = http.GET(url, headers={"Range": f"bytes={rng}"})
    assert str(result.status_code) == status, f"Wrong status code: {result.status_code}"
