"""Test-facing helpers for translated httpd tests.

Phase 2 exposes a small, pytest-idiomatic surface that the translated ``.t``
files use. The Perl Apache::Test vocabulary maps as follows:

* ``plan tests => N``           -> dropped (pytest counts tests itself)
* ``ok $cond``                  -> ``assert cond``
* ``ok t_cmp($got, $exp, $d)``  -> ``assert t_cmp(got, exp), d`` (see :func:`t_cmp`)
* ``need_module 'x'`` (in plan) -> ``@need_module("x")`` marker on the test
* ``have_min_apache_version()`` -> :func:`have_min_apache_version` (runtime gate)
* ``GET`` / ``GET_BODY`` / ...  -> methods on the ``http`` fixture (client.py)

The requirement markers (need_*) are evaluated at collection time by a
``pytest_collection_modifyitems`` hook in conftest.py, which probes the target
httpd once and skips tests whose requirements aren't met -- the analog of
Apache::Test's plan-time skipping.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

# --------------------------------------------------------------------------- #
# Assertions / comparison
# --------------------------------------------------------------------------- #


def t_cmp(received: Any, expected: Any) -> bool:
    """Faithful port of Apache::TestUtil::t_cmp / t_is_equal.

    * If ``expected`` is a compiled regex (``re.Pattern``), return whether it
      matches ``received`` anywhere (Perl ``=~``, i.e. ``re.search``).
    * Lists/tuples compare element-wise; dicts compare key/value-wise.
    * ``None`` equals only ``None``.
    * Otherwise compare by string equality, mirroring Perl's ``eq`` (both sides
      stringified) so ``200 == "200"`` holds as in the Perl tests.

    Returns a bool so callers write ``assert t_cmp(got, exp), "desc"`` -- the
    description becomes the assertion message (the Perl 3rd arg / t_debug).
    """
    if isinstance(expected, re.Pattern):
        return expected.search(str(received)) is not None
    if isinstance(expected, (list, tuple)) and isinstance(received, (list, tuple)):
        return len(received) == len(expected) and all(
            t_cmp(r, e) for r, e in zip(received, expected)
        )
    if isinstance(expected, dict) and isinstance(received, dict):
        return received.keys() == expected.keys() and all(
            t_cmp(received[k], expected[k]) for k in expected
        )
    if received is None or expected is None:
        return received is None and expected is None
    # Perl `eq` is a string comparison; stringify both sides.
    return str(received) == str(expected)


# --------------------------------------------------------------------------- #
# Requirement markers (need_*) -- thin wrappers over pytest.mark
# --------------------------------------------------------------------------- #
# Each marker records its requirement as marker args; the collection hook in
# conftest.py reads them against the probed HttpdInfo and skips as needed.


def need_module(*names: str) -> pytest.MarkDecorator:
    """Skip unless every named httpd module is available (need_module)."""
    return pytest.mark.need_module(*names)


def need_min_apache_version(version: str) -> pytest.MarkDecorator:
    """Skip unless the server is at least ``version`` (need_min_apache_version)."""
    return pytest.mark.need_min_apache_version(version)


def need_cgi() -> pytest.MarkDecorator:
    """Skip unless a CGI module (mod_cgi or mod_cgid) is available (need_cgi)."""
    return pytest.mark.need_cgi()


def need_php() -> pytest.MarkDecorator:
    """Skip unless a PHP SAPI module is available (need_php)."""
    return pytest.mark.need_php()


def need_ssl() -> pytest.MarkDecorator:
    """Skip unless mod_ssl is available (need_ssl)."""
    return pytest.mark.need_ssl()


def need_lwp() -> pytest.MarkDecorator:
    """Always satisfied (the Perl need_lwp gated on the LWP client being present;
    the Python client -- httpx -- is always available)."""
    return pytest.mark.need_lwp()
