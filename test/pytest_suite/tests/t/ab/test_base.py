"""Translated from t/ab/base.t -- smoke-test the `ab` benchmark tool.

Perl original (plan tests => 5 if ssl else 2):
    run `ab -B 127.0.0.1 -q -n 10 <http_url>`; ok status==0; ok no stderr.
    if ssl: same for the https URL; ok status==0; ok no stderr; and ok no
    SSL-failure-looking lines in stdout.

We invoke the `ab` binary that sits next to the httpd binary, mirroring the
Perl test's use of $vars->{bindir}/ab. Skips if `ab` is not present.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest


def _ab_path(http) -> Path:
    ab = Path(http.config.info.httpd).parent / "ab"
    if not ab.exists() and ab.with_suffix(".exe").exists():
        return ab.with_suffix(".exe")
    return ab


def _run_ab(ab: Path, url: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    return subprocess.run(
        [str(ab), "-B", "127.0.0.1", "-q", "-n", "10", url],
        capture_output=True,
        text=True,
        env=env,
    )


def test_ab_http(http):
    ab = _ab_path(http)
    if not ab.exists():
        pytest.skip("ab benchmark tool not present")
    http.scheme("http")
    res = _run_ab(ab, http.base_url + "/")
    assert res.returncode == 0
    assert res.stderr == ""


def test_ab_https(http):
    if not http.have_module("mod_ssl"):
        pytest.skip("mod_ssl not available")
    ab = _ab_path(http)
    if not ab.exists():
        pytest.skip("ab benchmark tool not present")
    ssl_name = http.vars("ssl_module_name") or "mod_ssl"
    https_url = f"https://{http.vars('servername')}:{http.vhost_port(ssl_name)}/"
    res = _run_ab(ab, https_url)
    assert res.returncode == 0, f"https had non-zero status:\n{res.stderr}"
    assert res.stderr == "", f"https had stderr output:\n{res.stderr}"
    # stderr sometimes lands in stdout; at least catch obvious SSL failures.
    alarming = [
        ln for ln in res.stdout.splitlines() if re.search(r"SSL.*(fail|err)", ln, re.I)
    ]
    assert alarming == [], f"https stdout had alarming content:\n{res.stdout}"
