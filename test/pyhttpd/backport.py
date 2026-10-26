"""Marks for tests of changes the httpd under test does not have yet.

Trunk (2.5) gets a fix and its test first; the test is then carried over to
2.4.x before, or without, the fix. On 2.4.x such a test is an expected
failure, or has to be skipped outright when failing means hanging, crashing
the server or leaving errors in the error log. On trunk the marks do nothing.
Drop the mark when the change is backported.

    pytestmark = not_backported("r1939033", "nonce-count validation")

    @skip_not_backported("r1938487", "recursion limit in mod_sed")
    def test_...
"""

import functools

import pytest


@functools.lru_cache(maxsize=None)
def _has_trunk_changes() -> bool:
    from .env import HttpdTestEnv
    return HttpdTestEnv().httpd_is_at_least("2.5.0")


def not_backported(rev: str, what: str):
    """Expected to fail until *what* (trunk change *rev*) is backported.

    Not strict: a test that happens to pass is reported as XPASS."""
    return pytest.mark.xfail(
        condition=not _has_trunk_changes(), strict=False,
        reason=f"{what} ({rev}) not backported")


def skip_not_backported(rev: str, what: str):
    """Not run until *what* (trunk change *rev*) is backported. For tests
    which would hang, crash the server, or fail the error log check in their
    teardown, none of which an xfail contains."""
    return pytest.mark.skipif(
        not _has_trunk_changes(),
        reason=f"{what} ({rev}) not backported")
