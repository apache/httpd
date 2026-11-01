"""Self-test for pyhttpd/backport.py and its use by pyhttpd.gating: which
servers a not_backported mark expects a failure on, and what it turns into an
expected failure there. Needs no built httpd."""
from pathlib import Path

import pytest

from pyhttpd import backport, gating
from pyhttpd.build import HttpdInfo


@pytest.mark.parametrize("server,since,expected", [
    ("2.4.70", None, False),
    ("2.4.70-dev", None, False),
    ("2.4.70", "2.4.71", False),
    ("2.4.71-dev", "2.4.71", True),
    ("2.4.71", "2.4.71", True),
    ("2.4.72", "2.4.71", True),
    # numeric, not textual, comparison
    ("2.4.9", "2.4.10", False),
    ("2.4.10", "2.4.9", True),
    ("2.5.0", None, True),
    ("2.5.1-dev", None, True),
    ("2.5.1-dev", "2.4.71", True),
])
def test_has_change(server, since, expected):
    assert backport.has_change(server, since) is expected


def test_unparsable_version():
    with pytest.raises(ValueError):
        backport.has_change("trunk")


def test_marks_record_their_arguments():
    xfail = backport.not_backported("r1", "a change", backported_in="2.4.71",
                                    platform="win32").mark
    skip = backport.skip_not_backported("r1", "a change").mark
    assert xfail.name == "not_backported"
    assert xfail.args == ("r1", "a change")
    assert xfail.kwargs == {"backported_in": "2.4.71", "platform": "win32"}
    assert skip.name == "skip_not_backported"
    assert skip.kwargs == {}


@pytest.mark.parametrize("server,since,lacks", [
    ("2.4.70", None, True),
    ("2.4.70", "2.4.71", True),
    ("2.4.71-dev", "2.4.71", False),
    ("2.5.1-dev", None, False),
    # the classic suite hands over a tuple
    ((2, 4, 70), None, True),
    ((2, 5, 1), None, False),
])
def test_lacks_change(server, since, lacks):
    assert backport.lacks_change(server, since) is lacks


@pytest.mark.parametrize("server,platform,expected", [
    ("2.4.70", "win32", True),
    ("2.4.70", "linux", False),
    ("2.4.70", None, True),
    ("2.5.1-dev", "win32", False),
])
def test_platform(monkeypatch, server, platform, expected):
    monkeypatch.setattr(backport.sys, "platform", "win32")
    assert backport.lacks_change(server, platform=platform) is expected


_GATED = '''
import pytest
from pyhttpd.backport import not_backported

@pytest.fixture
def broken():
    raise RuntimeError("the server did not start")

@pytest.fixture
def broken_teardown():
    yield
    raise RuntimeError("the error log check failed")

@not_backported("r1", "a change")
def test_setup_error(broken):
    pass

@not_backported("r1", "a change")
def test_teardown_error(broken_teardown):
    pass

@not_backported("r1", "a change")
def test_fails():
    assert False

@not_backported("r1", "a change")
def test_passes():
    pass
'''


@pytest.fixture
def gated_run(pytester, monkeypatch):
    """Run _GATED, with pyhttpd.gating, as if against an httpd of *version*."""
    def run(version):
        info = HttpdInfo(httpd=Path("httpd"), version=version, mpm="event")
        monkeypatch.setattr(gating, "resolve_build", lambda config: info)
        pytester.makepyfile(_GATED)
        pytester.makeini("[pytest]\nmarkers =\n not_backported\n")
        return pytester.runpytest_inprocess("-p", "pyhttpd.gating", "-p", "no:cacheprovider")
    return run


def test_not_backported_is_an_xfail_of_the_test_only(gated_run):
    result = gated_run((2, 4, 70))
    # a broken fixture is an error, not an expected failure (the body of
    # test_teardown_error passes: XPASS, and an error)
    result.assert_outcomes(errors=2, xfailed=1, xpassed=2)


def test_not_backported_does_nothing_with_the_change(gated_run):
    result = gated_run((2, 5, 1))
    result.assert_outcomes(errors=2, failed=1, passed=2)
