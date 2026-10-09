"""Translated from t/apache/byterange.t -- run_files_test(verify, skip_other=1).

Walks each getfiles target in 8K windows using a `Range: bytes=start-end`
header, accumulating bytes reported back via Content-Range, and asserts the
whole file is retrieved. skip_other=1 means only the perl-pod files are used in
Perl; with no perlpod locally this typically has nothing to fetch, so we fall
back to the binary targets to exercise the range logic.
"""

import os
import re

import pytest

from apache_pytest import need_lwp

CHUNK = 8192
_CONTENT_RANGE = re.compile(r"^bytes\s+(\d+)-(\d+)/(\d+)")


def _targets(config):
    out = []
    for name in ("httpd", "perl"):
        path = config.vars.get(name)
        if path and os.path.isfile(path):
            out.append((f"/getfiles-binary-{name}", path))
    return out


def _walk(http, url, wanted):
    total = 0
    while total < wanted:
        end = min(total + CHUNK, wanted)
        r = http.GET(url, headers={"Range": f"bytes={total}-{end}"})
        cr = r.headers.get("Content-Range", "NONE")
        m = _CONTENT_RANGE.match(cr)
        if m:
            start, rng_end = int(m.group(1)), int(m.group(2))
            total += (rng_end - start) + 1
        elif total == 0 and end == wanted and cr == "NONE" and r.status_code == 200:
            total += wanted
        else:
            break
    return total


@need_lwp()
def test_byterange(http, config):
    targets = _targets(config)
    if not targets:
        pytest.skip("no getfiles targets available")
    for url, path in targets:
        wanted = os.path.getsize(path)
        assert _walk(http, url, wanted) == wanted
