r"""Translated from t/apache/loglevel.t -- per-directory LogLevel configuration.

Requests a set of not-found URLs under directories whose LogLevel raises or
lowers logging; then scans the error log to confirm the "does not exist"
message appears for the directories where it is expected and is absent for the
others.

The Perl original used t_start_error_log_watch / t_finish_error_log_watch; here
we snapshot the error_log file position before the requests and read what was
appended afterwards.

Needs: need_min_apache_version('2.3.6').
"""

import re
from pathlib import Path

from apache_pytest import need_min_apache_version

BASE = "/apache/loglevel"

ERROR_EXPECTED = [
    "core_info",
    "info",
    "crit/core_info",
    "info/core_crit/info",
]
ERROR_NOT_EXPECTED = [
    "core_crit",
    "crit",
    "info/core_crit",
    "crit/core_info/crit",
]


@need_min_apache_version("2.3.6")
def test_loglevel(http):
    error_log = Path(http.vars("t_logs")) / "error_log"
    start = error_log.stat().st_size if error_log.exists() else 0

    for d in ERROR_EXPECTED:
        http.GET(f"{BASE}/{d}/not_found_error_expected")
    for d in ERROR_NOT_EXPECTED:
        http.GET(f"{BASE}/{d}/not_found_error_NOT_expected")

    with error_log.open("r", errors="replace") as fh:
        fh.seek(start)
        log = fh.read()

    for d in ERROR_EXPECTED:
        assert re.search(
            rf"does not exist.*?{re.escape(BASE)}/{re.escape(d)}/not_found_error_expected",
            log,
        ), f"expected error log entry for {d}"
    for d in ERROR_NOT_EXPECTED:
        assert not re.search(
            rf"does not exist.*?{re.escape(BASE)}/{re.escape(d)}/not_found_error_NOT_expected",
            log,
        ), f"unexpected error log entry for {d}"
