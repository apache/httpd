"""Error-log check for the classic (pytest_suite) tests.

Like the modules/ suite, an unexpected error or warning in the httpd error log
fails the test that was running (as a teardown error), and a crash or a
sanitizer report always does. The classic tests share one long-running server
and many of them provoke errors on purpose, so what counts as expected is
declared here, not in the test files, which stay identical to upstream's
httpd-tests:

* ``BACKGROUND_*`` -- logged by timers of the shared server (proxy health
  checks of a dead backend, mod_proxy_beacon announcements), whatever test
  happens to be running. Ignored everywhere.
* ``PER_FILE`` -- logged because a test file exercises that error path.
  Ignored in that file only, by AH number, or by regex for lines without one.

The log is read after each test and again when the file's last test is done.
A line logged just after a test returns is attributed to the next one, which
is why the lists are per file, not per test. What the server logs while it
starts, and while it stops after the last test (a child crashing on the way
out shows nowhere else), is checked by check_startup() and check_shutdown(),
which the classic suite's server fixture calls.

``--classic-elog-report=FILE`` measures instead of checking: no ignores, no
failures, one JSON line per test with what it was attributed, plus a summary.
That is how the tables below were built.
"""
import json
import os
import re
from collections import Counter

import pytest

from .log import HttpdErrorLog

# AH02683/AH02704: mod_ssl_ct's SCT maintenance daemon, every 30 seconds. Not
# built on macOS, found by a Linux run.
# AH01871: mod_optional_fn_export logs every request. At APLOG_DEBUG on trunk
# (git mirror c649960592) but at APLOG_ERR on a branch without that change,
# i.e. 2.4.x for now.
BACKGROUND_LOGNOS = ["AH10577", "AH10164", "AH10569", "AH02683", "AH02704",
                     "AH01871"]
BACKGROUND_MATCHES = [r".*\bHCOH: attempt to connect to .* failed"]

_SSL_NOEXT =r".*SSL Library Error: error:0A000117:SSL routines::extension not received"

# file name -> (AH numbers, regexes for lines without one)
PER_FILE = {
    "test_CVE_2005_2700.py": (["AH10158"], [_SSL_NOEXT]),
    "test_CVE_2008_2364.py": (["AH00898"], []),
    "test_CVE_2009_1195.py": (["AH01228", "AH01374"], []),
    "test_CVE_2019_0215.py": (["AH10158"], [_SSL_NOEXT]),
    "test_aaa.py": (["AH01617", "AH01631", "AH01794", "AH01807"], []),
    "test_acceptpathinfo.py": (["AH01266"], []),
    "test_access.py": (["AH01797"], []),
    "test_actions.py": (["AH01599"], []),
    "test_alias.py": (["AH00674", "AH01264"], []),
    "test_allowmethods.py": (["AH01623"], []),
    "test_authz_core.py": (["AH01630", "AH01631"], []),
    "test_basicauth.py": (["AH01618", "AH10096", "AH10158"], [_SSL_NOEXT]),
    "test_cgi.py": (["AH01215", "AH01266", "AH10599"], [
        r".*End of script output before headers: bogus",
        r".*malformed header from script 'bogus-sh.sh'"]),
    # 400: test_dav_mswdv_null_deref on a server without r1939426 (2.4.x)
    "test_dav.py": (["AH10484", "AH10619"], [
        r".*\[dav:error\].* \[(400|404|423), #0\]"]),
    "test_deflate.py": (["AH01387", "AH01392"], []),
    "test_digest.py": (["AH01786", "AH01794"], []),
    "test_dir.py": (["AH01276", "AH01599"], []),
    "test_expr.py": (["AH01630"], []),
    "test_ext_filter.py": (["AH01270"], []),  # LimitRequestBody 6: ENOSPC -> 413
    "test_fakeauth.py": (["AH10158"], [_SSL_NOEXT]),
    "test_hostcheck.py": (["AH10157"], []),
    "test_http_strict.py": (["AH00135", "AH01215", "AH02428", "AH02429", "AH02430"], [
        r".*malformed header from script 'send_hdr.pl'"]),
    "test_include.py": ([
        "AH01228", "AH01329", "AH01330", "AH01337", "AH01346", "AH01352",
        "AH01369", "AH01371", "AH01372", "AH01374", "AH01412"], [
        r".*\(20023\)The given path was above the root path:.*unable to include file",
        r".*\[include:error\].* unable to include \""]),
    "test_ldap.py": (["AH01617", "AH01631"], []),
    "test_mergeslashes.py": (["AH01630"], []),
    "test_negotiation.py": (["AH00690"], []),
    "test_ocsp.py": (["AH03239", "AH10373"], []),
    "test_pha.py": (["AH02018", "AH10158", "AH10228"], [_SSL_NOEXT]),
    "test_proxy.py": (["AH02229"], []),
    "test_proxy_balancer.py": ([
        "AH00957", "AH00959", "AH01114", "AH01170", "AH01171", "AH10187"], []),
    "test_proxy_beacon.py": (["AH01170"], []),
    "test_proxy_beacon_input.py": (["AH10187"], []),
    "test_proxy_hcheck.py": (["AH10187"], []),
    "test_remoteip.py": (["AH03499"], []),
    "test_require.py": (["AH02229", "AH02262", "AH10158"], [_SSL_NOEXT]),
    "test_rewrite.py": (["AH10410", "AH10411", "AH10508"], [
        r".*RewriteRule '.*' and URI '.*' exceeded maximum length"]),
    "test_session.py": (["AH01817"], []),
    "test_verify.py": (["AH02262", "AH10158"], [_SSL_NOEXT]),
}

_state = {"log": None, "tests": 0, "with_lines": 0, "counts": Counter(), "samples": {}}
_RE_LOGNO = re.compile(r'\[(?P<mod>[^:\]]+):(?P<level>error|warn)\].* (?P<logno>AH\d+):')
_RE_LEVEL = re.compile(r'\[(?P<mod>[^:\]]+):(?P<level>error|warn)\]')


def pytest_addoption(parser):
    parser.getgroup("httpd").addoption(
        "--classic-elog-report", action="store", default=None, metavar="FILE",
        help="instead of failing on unexpected errors/warnings in the error log "
             "during classic tests, write what each test was attributed to FILE "
             "(JSON lines, no ignores applied) and summarize it")


def pytest_configure(config):
    path = config.getoption("--classic-elog-report", default=None)
    if path:
        open(path, "w").close()


def _key(line: str) -> str:
    m = _RE_LOGNO.search(line)
    if m:
        return f"{m['mod']}:{m['level']} {m['logno']}"
    m = _RE_LEVEL.search(line)
    if m:
        return f"{m['mod']}:{m['level']} (no AH number)"
    return "other (crash/sanitizer)"


def _uses_server(item) -> bool:
    return "framework" in getattr(item, "fixturenames", ())


def _log_for(request) -> HttpdErrorLog:
    if _state["log"] is None:
        config = request.getfixturevalue("config")
        # starts at the end of the log: server start-up is not a test's doing
        _state["log"] = HttpdErrorLog(f"{config.vars['t_logs']}/error_log")
    return _state["log"]


def _fail_on(errors, warnings, what):
    if errors or warnings:
        lines = "\n".join(l.rstrip() for l in (errors + warnings)[:20])
        more = len(errors) + len(warnings) - 20
        pytest.fail(f"apache logged {len(errors)} errors and {len(warnings)} warnings "
                    f"during {what}:\n{lines}" + (f"\n... and {more} more" if more > 0 else ""),
                    pytrace=False)


@pytest.fixture(autouse=True, scope="module")
def _classic_elog_module(request):
    """Sets the module's ignores, and checks what is left when it is done."""
    module = request.module
    if not any(_uses_server(i) and getattr(i, "module", None) is module
               for i in request.session.items):
        yield
        return
    report = request.config.getoption("--classic-elog-report", default=None)
    log = _log_for(request)
    log.clear_ignored_matches()
    log.clear_ignored_lognos()
    if not report:
        nos, matches = PER_FILE.get(os.path.basename(module.__file__), ([], []))
        log.add_ignored_lognos(BACKGROUND_LOGNOS + nos)
        log.add_ignored_matches(BACKGROUND_MATCHES + matches)
    yield
    if not report:
        _fail_on(*log.get_missed(), f"the tests of {os.path.basename(module.__file__)}")


@pytest.fixture(autouse=True)
def _classic_elog(request):
    if not _uses_server(request.node):
        yield
        return
    path = request.config.getoption("--classic-elog-report", default=None)
    log = _log_for(request)
    yield
    errors, warnings = log.get_missed()
    if not path:
        _fail_on(errors, warnings, "this test")
        return
    _state["tests"] += 1
    if not (errors or warnings):
        return
    _state["with_lines"] += 1
    for line in errors + warnings:
        key = _key(line)
        _state["counts"][key] += 1
        _state["samples"].setdefault(key, line.rstrip())
    with open(path, "a") as fd:
        fd.write(json.dumps({"test": request.node.nodeid,
                             "errors": [l.rstrip() for l in errors],
                             "warnings": [l.rstrip() for l in warnings]}) + "\n")


def _check_window(config, log: HttpdErrorLog, what: str, warnings_count=True) -> None:
    path = config.getoption("--classic-elog-report", default=None)
    log.clear_ignored_matches()
    log.clear_ignored_lognos()
    if not path:
        log.add_ignored_lognos(BACKGROUND_LOGNOS)
        log.add_ignored_matches(BACKGROUND_MATCHES)
    errors, warnings = log.get_missed()
    if not path:
        _fail_on(errors, warnings if warnings_count else [], what)
    elif errors or warnings:
        with open(path, "a") as fd:
            fd.write(json.dumps({"test": f"<{what}>",
                                 "errors": [l.rstrip() for l in errors],
                                 "warnings": [l.rstrip() for l in warnings]}) + "\n")


def check_startup(config, error_log: str, since: int) -> None:
    """Fail on errors (and crashes) the server logged from *since*, its log
    size before it was started, up to now: its start. Call once it is
    serving. Not on warnings: the shared t/conf makes httpd warn at every
    start (a CRL without SSLCARevocationCheck, a revoked proxy client
    certificate, SSLRandomSeed with OpenSSL 3, ...), and which ones depends
    on the httpd and the TLS library."""
    log = HttpdErrorLog(error_log)
    log.start_at(since)
    _check_window(config, log, "the start of the server", warnings_count=False)


def check_shutdown(config) -> None:
    """Fail on what the server logged after the last test was checked: its
    shutdown. Call once it has stopped."""
    if _state["log"] is not None:
        _check_window(config, _state["log"], "the shutdown of the server")


def pytest_terminal_summary(terminalreporter, config):
    if not config.getoption("--classic-elog-report", default=None) or not _state["tests"]:
        return
    tr = terminalreporter
    total = sum(_state["counts"].values())
    tr.section("classic error-log report (report only)")
    tr.write_line(f"{_state['with_lines']} of {_state['tests']} classic tests were "
                  f"attributed {total} error/warning lines")
    for key, n in _state["counts"].most_common(25):
        tr.write_line(f"{n:6d}  {key}")
        tr.write_line(f"        e.g. {_state['samples'][key][:200]}")
