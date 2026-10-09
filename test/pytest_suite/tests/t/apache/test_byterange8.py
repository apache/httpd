r"""Translated from t/apache/byterange8.t -- PR 69831: whitespace tolerance in
multi-range headers ("1-2 , 3-4" with spaces/tabs around the comma).

Needs: need_lwp, need_min_apache_version('2.5.1').
"""

from pathlib import Path

import pytest

from apache_pytest import need_lwp, need_min_apache_version, t_cmp

URL = "/apache/chunked/byteranges.txt"
CONTENT = "".join(f"{i:04d}" for i in range(1, 101))

SPACE = [" ", "\t"]
TC = []
for k in range(2):
    for i in range(3):
        for j in range(3):
            TC.append("1-2" + SPACE[k] * i + "," + SPACE[k] * j + "3-4")


def _write_file(http):
    file = Path(http.vars("serverroot")) / ("htdocs" + URL)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(CONTENT)


@need_lwp()
@need_min_apache_version("2.5.1")
@pytest.mark.parametrize("rng", TC, ids=lambda r: repr(r))
def test_byterange8(http, rng):
    _write_file(http)
    result = http.GET(URL, headers={"Range": f"bytes={rng}"})
    assert t_cmp(result.status_code, 206)
