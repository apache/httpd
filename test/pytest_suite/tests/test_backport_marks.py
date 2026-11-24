"""Self-test for the not_backported mark: which servers it expects a failure
on. Needs no httpd."""
import pytest

from apache_pytest.testapi import has_trunk_change, not_backported


@pytest.mark.parametrize("version,since,expected", [
    ((2, 4, 70), None, False),
    ((2, 4, 70), "2.4.71", False),
    ((2, 4, 71), "2.4.71", True),
    ((2, 4, 72), "2.4.71", True),
    # numeric, not textual, comparison
    ((2, 4, 9), "2.4.10", False),
    ((2, 4, 10), "2.4.9", True),
    ((2, 5, 0), None, True),
    ((2, 5, 1), None, True),
    ((2, 5, 1), "2.4.71", True),
])
def test_has_trunk_change(version, since, expected):
    assert has_trunk_change(version, since) is expected


def test_mark_carries_backported_in():
    mark = not_backported("r1", "a change", backported_in="2.4.71").mark
    assert mark.args == ("r1", "a change")
    assert mark.kwargs == {"backported_in": "2.4.71"}
