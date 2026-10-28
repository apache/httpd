"""Self-test for pyhttpd/classic_errorlog.py: what the shared server of the
classic suite logs while it starts and stops counts, not only what it logs
during the tests. Needs no built httpd: a fake 'framework' fixture writes
the error log. Run in a subprocess, as the plugin keeps session state."""
import os

import pytest

_SUITE = '''
import pytest
from pyhttpd.classic_errorlog import check_shutdown, check_startup

LINE = "[Wed Oct 28 12:00:00.000000 2026] [{0}] [pid 1] {1}\\n"

@pytest.fixture(scope="session")
def config(tmp_path_factory):
    class Config:
        vars = {"t_logs": str(tmp_path_factory.mktemp("logs"))}
    open(Config.vars["t_logs"] + "/error_log", "w").close()
    return Config

def log(config, level, msg):
    with open(config.vars["t_logs"] + "/error_log", "a") as fd:
        fd.write(LINE.format(level, msg))

@pytest.fixture(scope="session")
def framework(request, config):
    log(config, "mpm_event:notice", "AH00489: configured -- resuming normal operations")
    if "{start}":
        log(config, "ssl:warn", "AH01909: server certificate does not match")
    if "{start_error}":
        log(config, "md:error", "AH10046: setup store failed")
    check_startup(request.config, config.vars["t_logs"] + "/error_log", 0)
    yield config, None
    if "{stop}":
        log(config, "core:notice", "AH00052: child pid 2 exit signal Segmentation fault (11)")
    check_shutdown(request.config)

def test_one(framework):
    pass
'''


@pytest.fixture
def run(pytester, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", os.path.dirname(os.path.abspath(__file__)))

    def run(start="", start_error="", stop=""):
        pytester.makepyfile(_SUITE.replace("{start}", start)
                            .replace("{start_error}", start_error)
                            .replace("{stop}", stop))
        return pytester.runpytest_subprocess("-p", "pyhttpd.classic_errorlog",
                                             "-p", "no:cacheprovider")
    return run


def test_clean_start_and_stop_pass(run):
    run().assert_outcomes(passed=1)


def test_crash_while_stopping_fails(run):
    result = run(stop="yes")
    result.assert_outcomes(passed=1, errors=1)
    result.stdout.fnmatch_lines(["*during the shutdown of the server*",
                                 "*exit signal Segmentation fault*"])


def test_error_while_starting_fails(run):
    result = run(start_error="yes")
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*during the start of the server*", "*AH10046*"])


def test_warning_while_starting_passes(run):
    # the shared t/conf makes httpd warn at every start
    run(start="yes").assert_outcomes(passed=1)
