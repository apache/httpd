"""Marks for tests of changes the httpd under test does not have yet.

Trunk (2.5) gets a fix and its test first; the test is then carried over to
2.4.x before, or without, the fix. On 2.4.x such a test is an expected
failure, or has to be skipped outright when failing means hanging, crashing
the server or leaving errors in the error log. On trunk the marks do nothing.

When the change is backported, add backported_in, the 2.4.x version it first
appears in, on trunk and copy the file over; older 2.4.x releases keep the
expectation.

    pytestmark = not_backported("r1939033", "nonce-count validation")

    @skip_not_backported("r1938487", "recursion limit in mod_sed",
                         backported_in="2.4.71")
    def test_...

platform limits the expectation to one sys.platform, for a failure on 2.4.x
which trunk does not have there.
"""

import functools
import re
import sys

import pytest


def _version_tuple(version: str):
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not m:
        raise ValueError(f"cannot parse httpd version {version!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def has_change(server_version: str, backported_in: str = None) -> bool:
    """Whether a server of this version has a trunk change: trunk always
    does, 2.4.x only from the version it was backported in. A -dev suffix
    counts as the release, a backport lands while the tree is -dev."""
    version = _version_tuple(server_version)
    if version >= (2, 5, 0):
        return True
    return backported_in is not None and version >= _version_tuple(backported_in)


@functools.lru_cache(maxsize=None)
def _server_version() -> str:
    from .env import HttpdTestEnv
    return HttpdTestEnv().get_httpd_version()


def _missing(backported_in, platform) -> bool:
    return (not has_change(_server_version(), backported_in)
            and (platform is None or sys.platform == platform))


def _reason(rev, what, platform) -> str:
    return (f"{what} ({rev}) not backported"
            + (f" [{platform}]" if platform else ""))


def not_backported(rev: str, what: str, backported_in: str = None,
                   platform: str = None):
    """Expected to fail until *what* (trunk change *rev*) is backported.

    Not strict: a test that happens to pass is reported as XPASS."""
    return pytest.mark.xfail(
        condition=_missing(backported_in, platform), strict=False,
        reason=_reason(rev, what, platform))


def skip_not_backported(rev: str, what: str, backported_in: str = None,
                        platform: str = None):
    """Not run until *what* (trunk change *rev*) is backported. For tests
    which would hang, crash the server, or fail the error log check in their
    teardown, none of which an xfail contains."""
    return pytest.mark.skipif(
        _missing(backported_in, platform),
        reason=_reason(rev, what, platform))
