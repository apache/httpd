"""Collection time gating shared by both suites.

One vocabulary of markers, evaluated once per session against the httpd that
:func:`pyhttpd.build.resolve_build` found:

  need_module(*names)        every named module is available
  need_cgi()                 mod_cgi or mod_cgid
  need_php()                 a PHP SAPI module, or php-fpm via mod_proxy_fcgi
  need_ssl()                 mod_ssl
  need_lwp()                 always satisfied (kept from the Perl vocabulary)
  need_min_apache_version(v) httpd >= v
  not_backported(rev, what, backported_in=None, platform=None)
                             expected to fail on httpd without the trunk change
                             (the test itself: errors in fixtures stay errors)
  skip_not_backported(rev, what, backported_in=None, platform=None)
                             not run there (hangs, crashes, or leaves errors
                             in the error log)

and, from pyhttpd.depends, ``needs_dependency`` for everything that is not
httpd itself (a client tool, a python package, an ACME server, ...).

A missing module, CGI/PHP/SSL support or dependency is a *missing dependency*:
the test is skipped, or fails under --strict-optional. A test that does not
apply here (httpd too old, change not backported) always skips or xfails. The
"does not apply" gates are added first, so in strict mode they win, exactly as
for ``needs_dependency`` (see pyhttpd.depends).

On trunk the backport marks do nothing; see pyhttpd.backport for backported_in
and platform.

This is a pytest plugin, loaded from test/conftest.py. The markers themselves
are registered in test/pyproject.toml.
"""

import pytest

from .backport import lacks_change, reason
from .build import HttpdInfo, resolve_build
from .depends import apply_gate, strict_optional_enabled

GATE_MARKERS = (
    "need_module", "need_cgi", "need_php", "need_ssl", "need_lwp",
    "need_min_apache_version", "not_backported", "skip_not_backported",
)

_PHP_SAPI_MODULES = ("sapi_apache2", "mod_php4", "mod_php5", "mod_php7", "mod_php")

# callables (HttpdInfo) -> None that may add to info.modules, for modules the
# suite builds itself and which therefore exist at test time, not yet now
_module_providers = []
_augmented = []


def add_module_provider(provider) -> None:
    """Let a suite declare modules it will build before it runs its tests.

    The classic suite compiles its c-modules/ in a session fixture, so
    need_module("authany") has to be satisfied at collection time already.
    """
    if provider not in _module_providers:
        _module_providers.append(provider)


def _augment(info: HttpdInfo) -> None:
    if any(i is info for i in _augmented):
        return
    _augmented.append(info)
    for provider in _module_providers:
        provider(info)


def _parse_version(ver) -> tuple:
    parts = tuple(int(x) for x in str(ver).split("."))
    return parts + (0,) * (3 - len(parts))


def _applies(item, info: HttpdInfo) -> None:
    """Add the "does not apply to this httpd" skips and xfails."""
    for mark in item.iter_markers(name="need_min_apache_version"):
        ver = mark.args[0]
        if info.version < _parse_version(ver):
            item.add_marker(pytest.mark.skip(
                reason=f"httpd {info.version_str} < required {ver}"))
            return
    for mark in item.iter_markers(name="skip_not_backported"):
        if lacks_change(info.version, mark.kwargs.get("backported_in"),
                        mark.kwargs.get("platform")):
            rev, what = mark.args
            item.add_marker(pytest.mark.skip(
                reason=reason(rev, what, mark.kwargs.get("platform"))))
            return
    for mark in item.iter_markers(name="not_backported"):
        if lacks_change(info.version, mark.kwargs.get("backported_in"),
                        mark.kwargs.get("platform")):
            rev, what = mark.args
            item.stash[_EXPECTED_FAILURE] = reason(rev, what, mark.kwargs.get("platform"))
            return


# not_backported is an xfail of the test itself, not of its fixtures: a
# pytest.mark.xfail would also turn a broken server setup, a missing client or
# an error log check failing in teardown into an expected failure.
_EXPECTED_FAILURE = pytest.StashKey[str]()


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    rep = yield
    why = item.stash.get(_EXPECTED_FAILURE, None)
    if why is None or call.when != "call" or rep.skipped \
            or item.config.option.runxfail:
        return rep
    # what pytest reports for a non-strict xfail: XFAIL, or XPASS
    if rep.failed:
        rep.outcome = "skipped"
    rep.wasxfail = why
    return rep


def _missing(item, info: HttpdInfo, php_fpm: bool) -> list:
    """The unmet dependencies of *item* as (dep, reason, detected) tuples."""
    where = f"httpd {info.version_str}" + (f" in {info.prefix}" if info.prefix else "")
    missing = []
    for mark in item.iter_markers(name="need_module"):
        for name in mark.args:
            if not info.has_module(name):
                missing.append((f"module {name}", f"module {name} not available",
                                f"not built or loaded: {where}"))
    if any(item.iter_markers(name="need_cgi")) and not (
        info.has_module("mod_cgi") or info.has_module("mod_cgid")
    ):
        missing.append(("mod_cgi or mod_cgid",
                        "no CGI module (mod_cgi/mod_cgid) available", where))
    if any(item.iter_markers(name="need_php")):
        have_sapi = any(info.has_module(m) for m in _PHP_SAPI_MODULES)
        have_fpm = php_fpm and info.has_module("mod_proxy_fcgi")
        if not (have_sapi or have_fpm):
            missing.append(("PHP", "no PHP SAPI module or php-fpm available",
                            f"no SAPI module, no --php-fpm: {where}"))
    if any(item.iter_markers(name="need_ssl")) and not info.has_module("mod_ssl"):
        missing.append(("mod_ssl", "mod_ssl not available", where))
    # need_lwp is always satisfied (httpx is always present); no check.
    return missing


# Runs before pyhttpd.depends' hook: the skips added here are what "does not
# apply" means to it in strict mode.
@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    gated = [item for item in items
             if any(item.get_closest_marker(name) for name in GATE_MARKERS)]
    if not gated:
        return
    info = resolve_build(config)
    if info is None:
        # no httpd to evaluate against: leave the tests to fail or skip
        # naturally at fixture setup
        return
    _augment(info)
    strict = strict_optional_enabled(config)
    php_fpm = bool(config.getoption("--php-fpm", default=None))
    for item in gated:
        _applies(item, info)
        apply_gate(item, _missing(item, info, php_fpm), strict)
