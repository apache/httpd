"""Self-test for the optional-dependency gating in pyhttpd/depends.py.

Runs a synthetic test file in a pytester subprocess, with and without
--strict-optional, and asserts skipped-vs-failed outcomes. The subprocess
loads the real plugin with '-p pyhttpd.depends' and nothing else, so this
needs no built httpd, no config.ini and no network.
"""
import os

import pytest

from pyhttpd.env import HttpdTestEnv

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

pytest_plugins = ["pytester"]


class _StubErrorLog:
    """Enough of HttpdErrorLog for the autouse _package_scope fixture."""

    def clear_ignored_matches(self):
        pass

    def clear_ignored_lognos(self):
        pass

    def add_ignored_lognos(self, lognos):
        pass


class _StubEnv:
    """Satisfies the autouse fixtures in test/conftest.py.

    Those are written for a test that drives a real httpd; this module
    drives a pytester subprocess instead, so every one of them is a no-op
    here. apache_stop() must report success, _package_scope asserts on it.
    """

    httpd_error_log = _StubErrorLog()

    def set_current_test_name(self, name):
        pass

    def check_error_log(self):
        pass

    def apache_stop(self):
        return 0


@pytest.fixture(scope="package")
def env():
    return _StubEnv()


SYNTHETIC = """
import pytest
from pyhttpd.depends import needs_dependency

# dependency missing: skip by default, fail when strict
@needs_dependency("frobnicator", False,
                  reason="frobnicator >= 2.0 not installed",
                  detected="frobnicator 1.0 at /usr/bin/frobnicator")
def test_dep_missing():
    assert False, "must never run"

# dependency present: always runs
@needs_dependency("widget", True, reason="widget not installed")
def test_dep_present():
    assert True

# not applicable: skips in both modes
@pytest.mark.skipif(True, reason="httpd too old")
def test_not_applicable():
    assert False, "must never run"

# both kinds of gate on one test: "not applicable" wins, even when strict
@pytest.mark.skipif(True, reason="STRESS_TEST not set in env")
@needs_dependency("frobnicator", False, reason="frobnicator not installed")
def test_not_applicable_beats_missing_dep():
    assert False, "must never run"

# an inactive skipif must not shield a missing dependency
@pytest.mark.skipif(False, reason="httpd too old")
@needs_dependency("frobnicator", False, reason="frobnicator not installed")
def test_inactive_skipif_does_not_shield():
    assert False, "must never run"

# two dependencies missing at once, both should be reported
@needs_dependency("OCSP responder", False, reason="no OCSP responder")
@needs_dependency("mod_ssl", False, reason="no mod_ssl available")
class TestStacked:
    def test_stacked(self):
        assert False, "must never run"

# a class-level marker must reach the method
@needs_dependency("a2md", False, reason="no a2md available")
class TestClassLevel:
    def test_class_level(self):
        assert False, "must never run"
"""

MODULE_LEVEL = """
import pytest
from pyhttpd.depends import needs_dependency

# module-level pytestmark, which a per-decorator scan would not see at all
pytestmark = [needs_dependency("nghttp", False, reason="nghttp not available")]

def test_module_gated():
    assert False, "must never run"
"""

LAZY = """
from pyhttpd.depends import needs_dependency

CALLS = []

def probe():
    CALLS.append(1)
    return False

@needs_dependency("lazy", probe, reason="lazy dep missing")
def test_lazy():
    assert False, "must never run"

def test_probe_ran_once():
    assert CALLS == [1]
"""

# test_dep_present is the only one that runs; of the rest, test_dep_missing,
# TestStacked and TestClassLevel are dependency gates and the other three
# are "not applicable" or shielded.
ALL_SKIPPED = dict(passed=1, skipped=6)
STRICT_SPLIT = dict(passed=1, skipped=2, errors=4)


@pytest.fixture
def synth(pytester, monkeypatch):
    # never inherit strict mode from the outer run
    monkeypatch.delenv("PYHTTPD_STRICT_OPTIONAL", raising=False)
    # let the subprocess import pyhttpd.depends
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(
        [TEST_DIR, os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep))
    pytester.makepyfile(test_synthetic=SYNTHETIC, test_modlevel=MODULE_LEVEL,
                        test_lazy=LAZY)
    return pytester


def _run(pytester, *args):
    return pytester.runpytest_subprocess("-p", "pyhttpd.depends",
                                         "test_synthetic.py", *args)


def test_flag_is_advertised(synth):
    r = synth.runpytest_subprocess("-p", "pyhttpd.depends", "--help")
    r.stdout.fnmatch_lines(["*--strict-optional*"])


def test_default_is_off_and_missing_dep_skips(synth):
    r = _run(synth)
    r.assert_outcomes(**ALL_SKIPPED)
    assert r.ret == 0


def test_default_skip_keeps_the_original_reason(synth):
    r = _run(synth, "-rs")
    r.stdout.fnmatch_lines(["*frobnicator >= 2.0 not installed*"])
    r.stdout.fnmatch_lines(["*no a2md available*"])


def test_strict_flag_fails_on_missing_dep(synth):
    r = _run(synth, "--strict-optional")
    r.assert_outcomes(**STRICT_SPLIT)
    assert r.ret != 0
    r.stdout.fnmatch_lines([
        "*[[]strict-optional[]] missing optional dependency: frobnicator*",
        "*reason:*frobnicator >= 2.0 not installed*",
        "*detected: frobnicator 1.0 at /usr/bin/frobnicator*",
        "*drop*--strict-optional*",
    ])


def test_strict_reports_every_missing_dep(synth):
    r = _run(synth, "--strict-optional")
    r.stdout.fnmatch_lines(["*missing optional dependency: OCSP responder*"])
    r.stdout.fnmatch_lines(["*missing optional dependency: mod_ssl*"])


def test_not_applicable_still_skips_when_strict(synth):
    r = _run(synth, "--strict-optional", "-rs")
    # a plain skipif carrying no dependency marker at all
    r.stdout.fnmatch_lines(["*httpd too old*"])
    # and one stacked on a missing dependency: the skipif wins, and the
    # reason reported is its own, not the dependency's
    r.stdout.fnmatch_lines(["*STRESS_TEST not set in env*"])


def test_env_var_enables_strict(synth, monkeypatch):
    monkeypatch.setenv("PYHTTPD_STRICT_OPTIONAL", "1")
    r = _run(synth)
    r.assert_outcomes(**STRICT_SPLIT)
    assert r.ret != 0


@pytest.mark.parametrize("val", ["", "0", "false", "no", "off"])
def test_env_var_falsey_values_keep_strict_off(synth, monkeypatch, val):
    monkeypatch.setenv("PYHTTPD_STRICT_OPTIONAL", val)
    r = _run(synth)
    r.assert_outcomes(**ALL_SKIPPED)
    assert r.ret == 0


def test_module_level_pytestmark_is_honoured(synth):
    r = synth.runpytest_subprocess("-p", "pyhttpd.depends", "test_modlevel.py")
    r.assert_outcomes(skipped=1)
    r = synth.runpytest_subprocess("-p", "pyhttpd.depends", "test_modlevel.py",
                                   "--strict-optional")
    r.assert_outcomes(errors=1)


def test_callable_available_is_evaluated_once_at_collection(synth):
    r = synth.runpytest_subprocess("-p", "pyhttpd.depends", "test_lazy.py")
    r.assert_outcomes(passed=1, skipped=1)


# --- env.require(), the in-test counterpart of the decorator ---------------
#
# Exercised against a stand-in rather than a real HttpdTestEnv, which would
# need a built httpd and a running server just to reach the one branch that
# matters here.

class _RequireEnv:
    require = HttpdTestEnv.require

    def __init__(self, strict):
        self._strict_optional = strict
        self.current_test_name = "unit::require"


def test_require_is_a_noop_when_the_dependency_is_present():
    _RequireEnv(strict=False).require(True, "need curl")
    _RequireEnv(strict=True).require(True, "need curl")


def test_require_skips_when_not_strict():
    with pytest.raises(BaseException) as exc:
        _RequireEnv(strict=False).require(
            False, "need at least curl v8.0.0 for this",
            dep="curl", detected="curl 7.88.1")
    assert exc.value.__class__.__name__ == "Skipped"
    assert "need at least curl v8.0.0 for this" in str(exc.value.args[0])


def test_require_reports_the_dependency_name_not_the_reason():
    """dep is what is missing; reason is why the test wanted it."""
    with pytest.raises(BaseException) as exc:
        _RequireEnv(strict=True).require(False, "no mod_ssl available")
    # no dep= given, so the reason stands in for the name
    assert "missing optional dependency: no mod_ssl available" in str(exc.value.args[0])


# --- the tool probes -------------------------------------------------------
#
# config.ini always names curl/nghttp/h2load, so the name alone says nothing
# about whether the tool is installed. Probing used to raise FileNotFoundError
# out of collection; it must report "absent" instead.

class _ProbeEnv:
    """Drives the curl probe without a config.ini or a built httpd."""

    _run_version = staticmethod(HttpdTestEnv._run_version)
    _versiontuple = HttpdTestEnv._versiontuple
    _probe_curl = HttpdTestEnv._probe_curl
    has_curl = HttpdTestEnv.has_curl
    curl_version_str = HttpdTestEnv.curl_version_str
    curl_is_at_least = HttpdTestEnv.curl_is_at_least
    curl_is_less_than = HttpdTestEnv.curl_is_less_than
    curl_is_8_1_x = HttpdTestEnv.curl_is_8_1_x

    def __init__(self, curl):
        self._curl = curl
        self._curl_version = None


@pytest.mark.parametrize("curl", ["/nonexistent/curl", "curl-does-not-exist", ""])
def test_absent_curl_probes_as_missing_rather_than_raising(curl):
    env = _ProbeEnv(curl)
    assert env.has_curl() is False
    assert env.curl_version_str() is None
    # every comparison answers False rather than blowing up collection
    assert env.curl_is_at_least('8.0.0') is False
    assert env.curl_is_less_than('8.0.0') is False
    assert env.curl_is_8_1_x() is False


def test_require_fails_when_strict_and_names_the_dependency():
    with pytest.raises(BaseException) as exc:
        _RequireEnv(strict=True).require(
            False, "need at least curl v8.0.0 for this",
            dep="curl", detected="curl 7.88.1")
    assert exc.value.__class__.__name__ == "Failed"
    msg = str(exc.value.args[0])
    assert "[strict-optional] missing optional dependency: curl" in msg
    assert "reason:   need at least curl v8.0.0 for this" in msg
    assert "detected: curl 7.88.1" in msg
    assert "unit::require" in msg
