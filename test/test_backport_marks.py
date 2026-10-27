"""Self-test for pyhttpd/backport.py: which servers a not_backported mark
expects a failure on. Needs no built httpd."""
import pytest

from pyhttpd import backport


class _StubErrorLog:
    """Enough of HttpdErrorLog for the autouse fixtures in test/conftest.py."""

    def clear_ignored_matches(self):
        pass

    def clear_ignored_lognos(self):
        pass

    def add_ignored_lognos(self, lognos):
        pass


class _StubEnv:
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


@pytest.mark.parametrize("server,since,xfails", [
    ("2.4.70", None, True),
    ("2.4.70", "2.4.71", True),
    ("2.4.71-dev", "2.4.71", False),
    ("2.5.1-dev", None, False),
])
def test_marks(monkeypatch, server, since, xfails):
    monkeypatch.setattr(backport, "_server_version", lambda: server)
    xfail = backport.not_backported("r1", "a change", backported_in=since).mark
    skip = backport.skip_not_backported("r1", "a change", backported_in=since).mark
    assert xfail.name == "xfail" and xfail.kwargs["condition"] is xfails
    assert skip.name == "skipif" and skip.args[0] is xfails


@pytest.mark.parametrize("server,platform,expected", [
    ("2.4.70", "win32", True),
    ("2.4.70", "linux", False),
    ("2.4.70", None, True),
    ("2.5.1-dev", "win32", False),
])
def test_platform(monkeypatch, server, platform, expected):
    monkeypatch.setattr(backport, "_server_version", lambda: server)
    monkeypatch.setattr(backport.sys, "platform", "win32")
    mark = backport.not_backported("r1", "a change", platform=platform).mark
    assert mark.kwargs["condition"] is expected
