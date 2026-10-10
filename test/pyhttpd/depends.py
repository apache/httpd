"""Optional-dependency gating for the httpd integration test suite.

Many test cases need something that is not part of httpd itself: the 'curl'
or 'nghttp' clients, the 'websockets' python package, an ACME test server,
a shared module that was not built, ... By default such a test is skipped
when its dependency is missing, which is the right thing for a developer
working on an unrelated part of the tree.

In a CI environment that is *supposed* to provide those dependencies, a skip
instead hides a broken configuration: the run stays green while the coverage
silently disappears. Strict mode exists for those environments. Enable it
with --strict-optional or PYHTTPD_STRICT_OPTIONAL=1 and a missing dependency
becomes a failure naming what was expected and what was found instead.

Only *missing dependencies* are affected. A test skipped because it does not
apply here - wrong mpm, httpd too old, STRESS_TEST not set - keeps skipping
in strict mode. Those keep using a plain pytest.mark.skipif, and when a test
carries both kinds of gate the "does not apply" one wins.

Usage:

    from pyhttpd.depends import needs_dependency

    @needs_dependency("a2md", MDTestEnv.has_a2md(), reason="no a2md available")
    class TestStore:
        ...

Note the polarity: skipif takes "skip when True", needs_dependency takes
"available when True".

This module is also a pytest plugin, loaded from test/conftest.py. It
deliberately imports nothing from pyhttpd.env so that it can be loaded on
its own with '-p pyhttpd.depends' by a test that has no httpd installed.
"""

import os

import pytest

STRICT_ENV_VAR = "PYHTTPD_STRICT_OPTIONAL"
MARKER_NAME = "needs_dependency"

_FALSEY = ("", "0", "false", "no", "off")

_HOWTO = (f"To go back to skipping missing optional dependencies, drop "
          f"--strict-optional and unset {STRICT_ENV_VAR}.")

# set at collection time on items that must hard-fail in strict mode
strict_fail_key = pytest.StashKey[str]()


def strict_optional_enabled(config=None) -> bool:
    """Whether a missing optional dependency must fail instead of skip.

    *config* may be a pytest Config, or None for an HttpdTestEnv built
    outside a pytest run. The environment variable wins when set to anything
    truthy, so that CI can enable strict mode without a command line.
    """
    if os.environ.get(STRICT_ENV_VAR, "").strip().lower() not in _FALSEY:
        return True
    if config is None:
        return False
    # passing a default keeps this quiet when the plugin is not registered
    return bool(config.getoption("strict_optional", False))


def strict_failure_message(dep, expected=None, detected=None, where=None) -> str:
    """Format a strict-optional failure. The one place that does so.

    The dependency name carries what was expected ("h2load >= 1.41.0"), so
    *expected* - the reason the test would otherwise have skipped - is
    labelled for what it is. Those reasons are worded as an absence ("no
    a2md available"), which under an "expected:" label read backwards.
    """
    lines = [f"[strict-optional] missing optional dependency: {dep}"]
    if expected:
        lines.append(f"    reason:   {expected}")
    if detected is not None:
        lines.append(f"    detected: {detected}")
    if where:
        lines.append(f"    test:     {where}")
    lines.append(f"    {_HOWTO}")
    return "\n".join(lines)


def needs_dependency(dep, available, reason=None, detected=None):
    """Declare that a test, class or module needs optional dependency *dep*.

    :param dep: short name for reports, e.g. "a2md", "h2load >= 1.41.0"
    :param available: truthy if the dependency was found. May be a zero-arg
        callable, evaluated once at collection rather than at import.
    :param reason: skip reason used in non-strict mode. Keep the wording of
        the skipif being replaced, so that -rs output does not change.
    :param detected: what was found instead, e.g. "curl 7.88.1". Only used
        in the strict-mode message. May also be a zero-arg callable.
    """
    return pytest.mark.needs_dependency(
        dep=dep, available=available, reason=reason, detected=detected,
    )


def _resolve(mark):
    """Return (dep, available, reason, detected) for one marker.

    Positional arguments are tolerated, so a bare
    pytest.mark.needs_dependency("x", cond) works as well.
    """
    if "dep" in mark.kwargs:
        dep = mark.kwargs["dep"]
    elif mark.args:
        dep = mark.args[0]
    else:
        dep = "<unnamed dependency>"

    if "available" in mark.kwargs:
        available = mark.kwargs["available"]
    elif len(mark.args) > 1:
        available = mark.args[1]
    else:
        # a marker carrying only a name is metadata, it never gates
        available = True
    if callable(available):
        available = available()

    detected = mark.kwargs.get("detected")
    if callable(detected):
        detected = detected()

    reason = mark.kwargs.get("reason") or f"missing optional dependency: {dep}"
    return dep, bool(available), reason, detected


def apply_gate(item, missing, strict):
    """Skip *item*, or arm it to fail, for the dependencies in *missing*.

    *missing* is a list of (dep, reason, detected) in the order the gates
    were declared. Shared by the needs_dependency marker below and by the
    whole-suite gates in test/conftest.py, so that a dependency of the
    framework itself reports exactly like a dependency of a single test,
    with the same "does not apply here" precedence.

    Calling this twice for one item accumulates, so a test missing two
    different dependencies is told about both.
    """
    if not missing:
        return
    skip_reason = "; ".join(r for _, r, _ in missing)

    if not strict:
        item.add_marker(pytest.mark.skip(reason=skip_reason))
        return

    gate = _other_gate(item)
    if gate is _GATE_ACTIVE:
        # does not apply here, let pytest skip it with its own reason
        return
    if gate is _GATE_UNKNOWN:
        # a string condition we cannot evaluate, keep the old behaviour
        item.add_marker(pytest.mark.skip(reason=skip_reason))
        return

    msg = "\n\n".join(
        strict_failure_message(dep, expected=reason, detected=detected,
                               where=item.nodeid)
        for dep, reason, detected in missing)
    previous = item.stash.get(strict_fail_key, None)
    item.stash[strict_fail_key] = (
        msg if previous is None else f"{previous}\n\n{msg}")


_GATE_ACTIVE = "active"
_GATE_UNKNOWN = "unknown"


def _other_gate(item):
    """Whether this item is already skipped by something else.

    That is the "does not apply here" case: an httpd version gate, an mpm
    gate, a STRESS_TEST gate, an unconditional skip. Those keep skipping in
    strict mode, so they take precedence over a missing dependency.

    Returns _GATE_ACTIVE when a skip is certain, _GATE_UNKNOWN for a string
    condition only pytest can eval() in the module namespace, and None when
    nothing else gates the item. This covers the marker forms the suite
    actually uses, without reaching into pytest's private skipping API.

    Must be called before we inject a skip marker of our own.
    """
    for mark in item.iter_markers():
        if mark.name == "skip":
            return _GATE_ACTIVE
        if mark.name != "skipif":
            continue
        if "condition" in mark.kwargs:
            conditions = [mark.kwargs["condition"]]
        else:
            conditions = list(mark.args)
        for cond in conditions:
            if isinstance(cond, str):
                return _GATE_UNKNOWN
            if cond:
                return _GATE_ACTIVE
    return None


def pytest_addoption(parser):
    group = parser.getgroup("httpd", "apache httpd test suite")
    group.addoption(
        "--strict-optional",
        dest="strict_optional",
        action="store_true",
        default=False,
        help="Fail instead of skip when an optional dependency declared with "
             "@needs_dependency() or env.require() is missing. Also enabled "
             f"by {STRICT_ENV_VAR}=1. Tests that do not apply here (mpm, "
             "httpd version, STRESS_TEST) keep skipping.",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "needs_dependency(dep, available, reason=None, detected=None): "
        "declare an optional dependency. Missing means skip by default and "
        "fail under --strict-optional. Use the needs_dependency() helper "
        "from pyhttpd.depends rather than this marker directly.",
    )


def pytest_collection_modifyitems(config, items):
    strict = strict_optional_enabled(config)
    for item in items:
        missing = [(dep, reason, detected)
                   for dep, ok, reason, detected
                   in (_resolve(m) for m in item.iter_markers(name=MARKER_NAME))
                   if not ok]
        if not missing:
            continue
        # markers arrive closest-first (function, class, module), report
        # them in the order they are written instead
        missing.reverse()
        apply_gate(item, missing, strict)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    """Fail before any fixture runs, so that a test about to fail for a
    missing dependency does not first go and start an httpd.

    Only ever armed for items carrying no active skip of their own, see
    pytest_collection_modifyitems, so this cannot race pytest's own skipping.
    """
    msg = item.stash.get(strict_fail_key, None)
    if msg is not None:
        pytest.fail(msg, pytrace=False)
