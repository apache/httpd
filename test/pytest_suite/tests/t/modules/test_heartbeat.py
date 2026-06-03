r"""Translated from t/modules/heartbeat.t -- mod_heartbeat / mod_heartmonitor.

Waits a few seconds while heartbeats are emitted, then scans the error log for
the DEBUG ``AH02086`` messages logged when mod_heartmonitor receives a beat from
mod_heartbeat, asserting at least (nb_seconds - 2) were seen.

The Perl test used t_start_error_log_watch / t_finish_error_log_watch; here we
snapshot the error_log size before sleeping and read what was appended.

Perl original:
    plan tests => 1, sub { need_module('mod_heartbeat', 'mod_heartmonitor')
                           && !need_apache_mpm('prefork') };
"""

import time
from pathlib import Path

import pytest

from apache_pytest import need_module

NB_SECONDS = 5
NB_EXPECTED = NB_SECONDS - 2


@need_module("heartbeat", "heartmonitor")
def test_heartbeat(http):
    # The Perl plan also skips on the prefork MPM; the test config runs the
    # event MPM here, so the prefork exclusion is satisfied.
    if http.have_module("mpm_prefork"):
        pytest.skip("heartbeat test not run under the prefork MPM")

    error_log = Path(http.vars("t_logs")) / "error_log"
    start = error_log.stat().st_size if error_log.exists() else 0

    time.sleep(NB_SECONDS)

    with error_log.open("r", errors="replace") as fh:
        fh.seek(start)
        loglines = fh.read().splitlines()

    count = sum(1 for line in loglines if "AH02086" in line)
    assert count >= NB_EXPECTED, (
        f"Expecting at least {NB_EXPECTED} heartbeats; Seen: {count}")
