"""Pytest fixtures wiring the httpd test framework together.

Session scope: probe httpd -> generate config -> compile C modules -> start
server, then stop it at the end. Function scope: an HTTP client and a vhost
resolver. Mirrors the orchestration Apache::TestRun performs.

Requirement markers (need_module, need_min_apache_version, need_cgi, need_php,
need_ssl, need_lwp) declared via apache_pytest.testapi are evaluated at
collection time against a one-time probe of the target httpd, skipping tests
whose requirements aren't met -- the analog of Apache::Test's plan-time skips.

CLI options:
  --httpd   path to the httpd binary (default: derived from --apxs SBINDIR)
  --apxs    path to apxs (used to locate httpd + the inherited install conf,
            and to build the C modules)
  --defines space-separated extra -D defines (e.g. 'LDAP')
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pyhttpd.build import resolve_build as _resolve_build
from pyhttpd.build import why_no_build as _why_no_build
from pyhttpd.classic_errorlog import check_shutdown, check_startup
from pyhttpd.gating import add_module_provider

from apache_pytest import HttpdServer, TestClient, TestConfig, compile_all, probe
from apache_pytest.cmodules import clean_modules
from apache_pytest.probe import HttpdInfo

# The suite is self-contained: all assets it needs (t/conf templates, t/htdocs
# docroot, c-modules sources, auth files) live under this directory (python/).
# SUITE_ROOT is therefore this file's directory -- nothing outside it is read.
SUITE_ROOT = Path(__file__).resolve().parent
# Backwards-compatible alias (older code referenced REPO_ROOT).
REPO_ROOT = SUITE_ROOT


# --------------------------------------------------------------------------- #
# Collection-time requirement gating (need_* markers)
# --------------------------------------------------------------------------- #
# The markers are evaluated by pyhttpd.gating, against the build that
# pyhttpd.build found. The bundled C test modules (authany, echo_post,
# input_body_filter, ...) are compiled and LoadModule'd into the generated
# test config by the session fixture below, so need_module("authany") etc.
# should be satisfied at collection time too. Declare the C modules that WILL
# be built (honoring the same HTTPD_TEST_REQUIRE_APACHE gating discover()
# applies).


def _provide_cmodules(info: HttpdInfo) -> None:
    from apache_pytest.cmodules import discover

    cmods, _skipped = discover(REPO_ROOT / "c-modules", info)
    for mod in cmods:
        info.modules.add(f"mod_{mod.name}.c")


add_module_provider(_provide_cmodules)


# --------------------------------------------------------------------------- #
# Server lifecycle + client fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def framework(request: pytest.FixtureRequest):
    """Probe, configure, build C modules, start httpd; yield (config, server)."""
    # the httpd of the session, the one the need_* marks were evaluated for
    target = _resolve_build(request.config)
    if target is None:
        pytest.fail(_why_no_build())
    httpd, apxs = target.httpd, target.apxs
    inherited_conf, install_prefix = target.inherited_conf, target.prefix
    defines = target.extra_defines

    # probed again: gating added the c-modules/ that will be built to target
    info = probe(httpd, inherited_conf, install_prefix)

    perl_opt = request.config.getoption("--with-perl")
    if perl_opt:
        import os
        os.environ["APACHE_TEST_PERL"] = perl_opt

    # Optional PHP-FPM: if a php-fpm binary was given and mod_proxy_fcgi is
    # available, route htdocs/php/*.php to a managed FPM daemon. The php-fpm
    # path/port are the only PHP-specific inputs -- no version is assumed.
    php_fpm_opt = request.config.getoption("--php-fpm")
    fpm_port = int(request.config.getoption("--php-fpm-port"))
    fpm_mgr = None
    use_fpm = bool(php_fpm_opt) and info.has_module("mod_proxy_fcgi")

    config = TestConfig(
        info=info,
        top_dir=REPO_ROOT,
        defines=defines,
        apxs=apxs,
        fpm_port=fpm_port if use_fpm else None,
    )

    cmodule_loads: list[tuple[str, Path]] = []
    if apxs is not None:
        cmodules_dir = REPO_ROOT / "c-modules"
        if request.config.getoption("--clean-modules"):
            clean_modules(cmodules_dir)
        cmodule_loads, _skipped = compile_all(
            cmodules_dir, apxs, info, defines=["APACHE2", "APACHE2_4", *defines]
        )
    else:
        from apache_pytest.cmodules import discover
        modules_dir = (install_prefix / "modules") if install_prefix else httpd.parent
        cmods, _skipped = discover(REPO_ROOT / "c-modules", info)
        for mod in cmods:
            so = modules_dir / f"mod_{mod.name}.so"
            if so.exists():
                cmodule_loads.append((mod.symbol, so))

    config.generate(cmodule_loads=cmodule_loads)

    if use_fpm:
        from apache_pytest.fpm import PhpFpm

        fpm_mgr = PhpFpm(
            Path(php_fpm_opt),
            run_dir=Path(config.vars["t_logs"]) / "php-fpm",
            port=fpm_port,
        )
        fpm_mgr.start()

    # Record the error_log size right before this session's httpd starts.
    # error_log is opened in append mode and t_logs/ is not cleaned between
    # invocations, so it can carry entries from earlier, unrelated test runs
    # (possibly hours/days old, with different pids). Tests that need "since
    # this server session started" (as opposed to "since this individual
    # test started") must scope their log reads to this offset, not to
    # position 0 -- see test_proxy_beacon.py.
    error_log = Path(config.vars["t_logs"]) / "error_log"
    config.vars["session_log_start"] = str(
        error_log.stat().st_size if error_log.exists() else 0
    )

    server = HttpdServer(config)
    server.start()
    try:
        check_startup(request.config, str(error_log),
                      int(config.vars["session_log_start"]))
        yield config, server
    finally:
        server.stop()
        if fpm_mgr is not None:
            fpm_mgr.stop()
    check_shutdown(request.config)


@pytest.fixture(scope="session")
def config(framework) -> TestConfig:
    return framework[0]


@pytest.fixture(scope="session")
def server(framework) -> HttpdServer:
    return framework[1]


@pytest.fixture
def http(config: TestConfig):
    """Function-scoped HTTP client bound to the running server."""
    client = TestClient(config)
    try:
        yield client
    finally:
        client.close()
