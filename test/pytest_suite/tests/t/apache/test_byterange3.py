"""Translated from t/apache/byterange3.t -- merging of (overlapping) byte ranges.

Like byterange, but each request asks for several overlapping ranges
(bytes=t10-end,total-e1,t10-e20,total-e1) to exercise httpd's range coalescing.
Requires httpd >= 2.3.15.
"""

import os
import re

import pytest

from apache_pytest import need_lwp, need_min_apache_version

CHUNK = 8192
_CONTENT_RANGE = re.compile(r"^bytes\s+(\d+)-(\d+)/(\d+)")


def _targets(config):
    out = []
    for name in ("httpd", "perl"):
        path = config.vars.get(name)
        if path and os.path.isfile(path):
            out.append((f"/getfiles-binary-{name}", path))
    return out


def _walk_merged(http, url, wanted):
    total = 0
    while total < wanted:
        end = min(total + CHUNK, wanted)
        if end - total < 15:
            rng = f"bytes={total}-{end}"
        else:
            t10, e1, e20 = total + 5, end - 1, end - 10
            rng = f"bytes={t10}-{end},{total}-{e1},{t10}-{e20},{total}-{e1}"
        r = http.GET(url, headers={"Range": rng})
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
@need_min_apache_version("2.3.15")
def test_byterange3(http, config):
    targets = _targets(config)
    if not targets:
        pytest.skip("no getfiles targets available")
    for url, path in targets:
        wanted = os.path.getsize(path)
        assert _walk_merged(http, url, wanted) == wanted
