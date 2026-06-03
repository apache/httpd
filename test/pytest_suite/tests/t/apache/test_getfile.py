"""Translated from t/apache/getfile.t -- run_files_test(verify).

Downloads files served via the getfiles-* aliases and verifies the received
byte count equals the file size on disk. The Perl harness downloads perl pod
files (/getfiles-perl-pod/*) plus the httpd and perl binaries
(/getfiles-binary-{httpd,perl}); perlpod is typically absent, so the binary
downloads are the substantive cases.
"""

import os

import pytest

from apache_pytest import need_lwp, t_cmp


def _getfiles_targets(config):
    """(url, on-disk path) pairs for the configured getfiles-binary aliases."""
    targets = []
    for name in ("httpd", "perl"):
        path = config.vars.get(name)
        if path and os.path.isfile(path):
            targets.append((f"/getfiles-binary-{name}", path))
    return targets


@need_lwp()
def test_getfile(http, config):
    targets = _getfiles_targets(config)
    if not targets:
        pytest.skip("no getfiles-binary targets available")
    for url, path in targets:
        flen = os.path.getsize(path)
        received = len(http.GET(url).content)
        assert t_cmp(received, flen), f"download of {url}"
