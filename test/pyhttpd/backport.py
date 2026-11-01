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

The marks only record their arguments; pyhttpd.gating applies them at
collection, against the httpd that pyhttpd.build found. Both suites use these.
"""

import re
import sys

import pytest


def _version_tuple(version) -> tuple:
    if isinstance(version, tuple):
        return version + (0,) * (3 - len(version))
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", str(version))
    if not m:
        raise ValueError(f"cannot parse httpd version {version!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def has_change(server_version, backported_in: str = None) -> bool:
    """Whether a server of this version has a trunk change: trunk always
    does, 2.4.x only from the version it was backported in. A -dev suffix
    counts as the release, a backport lands while the tree is -dev.

    *server_version* is a string ("2.4.70-dev") or a (major, minor, patch)
    tuple."""
    version = _version_tuple(server_version)
    if version >= (2, 5, 0):
        return True
    return backported_in is not None and version >= _version_tuple(backported_in)


def lacks_change(server_version, backported_in: str = None,
                 platform: str = None) -> bool:
    """Whether the expectation of a not_backported mark holds here: the
    server lacks the change, and *platform* (if given) is this one."""
    return (not has_change(server_version, backported_in)
            and (platform is None or sys.platform == platform))


def reason(rev: str, what: str, platform: str = None) -> str:
    return f"{what} ({rev}) not backported" + (f" [{platform}]" if platform else "")


def _mark(name: str, rev: str, what: str, backported_in, platform):
    kwargs = {k: v for k, v in
              (("backported_in", backported_in), ("platform", platform))
              if v is not None}
    return getattr(pytest.mark, name)(rev, what, **kwargs)


def not_backported(rev: str, what: str, backported_in: str = None,
                   platform: str = None):
    """Expected to fail until *what* (trunk change *rev*) is backported.

    Only a failure of the test function counts; an error in the setup or
    teardown of its fixtures is reported as an error. Mark only the tests
    (or parameters, via pytest.param(..., marks=...)) that fail without the
    change: on the others the mark would hide a regression.

    Not strict: a test that happens to pass is reported as XPASS."""
    return _mark("not_backported", rev, what, backported_in, platform)


def skip_not_backported(rev: str, what: str, backported_in: str = None,
                        platform: str = None):
    """Not run until *what* (trunk change *rev*) is backported. For tests
    which would hang, crash the server, or fail the error log check in their
    teardown, none of which an xfail contains."""
    return _mark("skip_not_backported", rev, what, backported_in, platform)
