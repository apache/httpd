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

import subprocess
from pathlib import Path

import pytest

from apache_pytest import HttpdServer, TestClient, TestConfig, compile_all, probe
from apache_pytest.probe import HttpdInfo

# The suite is self-contained: all assets it needs (t/conf templates, t/htdocs
# docroot, c-modules sources, auth files) live under this directory (python/).
# SUITE_ROOT is therefore this file's directory -- nothing outside it is read.
SUITE_ROOT = Path(__file__).resolve().parent
# Backwards-compatible alias (older code referenced REPO_ROOT).
REPO_ROOT = SUITE_ROOT


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("httpd")
    group.addoption("--httpd", action="store", default=None, help="path to httpd binary")
    group.addoption("--apxs", action="store", default=None, help="path to apxs")
    group.addoption(
        "--defines",
        action="store",
        default="",
        help="space-separated extra -D defines (e.g. 'LDAP')",
    )
    group.addoption(
        "--php-fpm",
        action="store",
        default=None,
        help="path to a php-fpm binary; enables the t/php tests via mod_proxy_fcgi "
        "(any version/location -- the path is the only PHP-specific input)",
    )
    group.addoption(
        "--php-fpm-port",
        action="store",
        type=int,
        default=8999,
        help="TCP port for the managed php-fpm pool (default 8999)",
    )


def pytest_configure(config: pytest.Config) -> None:
    for marker in (
        "need_module(*names): skip unless all named httpd modules are available",
        "need_min_apache_version(ver): skip unless server >= ver",
        "need_cgi(): skip unless a CGI module is available",
        "need_php(): skip unless a PHP SAPI module is available",
        "need_ssl(): skip unless mod_ssl is available",
        "need_lwp(): always satisfied (httpx client always present)",
    ):
        config.addinivalue_line("markers", marker)


def _apxs_query(apxs: Path, var: str) -> str:
    proc = subprocess.run(  # noqa: S603 - trusted path
        ["perl", str(apxs), "-q", var], capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


class _NoServerError(Exception):
    """Raised when neither --httpd nor --apxs was provided."""


def _resolve_paths(
    config: pytest.Config,
) -> tuple[Path, Path | None, Path | None, Path | None, list[str]]:
    """Resolve (httpd, apxs, inherited_conf, install_prefix, defines) from options.

    Raises :class:`_NoServerError` if neither --httpd nor --apxs is given. (A
    plain exception, not pytest.fail, so the collection-time probe can catch it
    without turning into an INTERNALERROR; the fixture converts it to a clean
    skip/fail at setup time.)
    """
    apxs_opt = config.getoption("--apxs")
    httpd_opt = config.getoption("--httpd")
    defines = [d for d in config.getoption("--defines").split() if d]

    apxs = Path(apxs_opt) if apxs_opt else None
    inherited_conf: Path | None = None
    install_prefix: Path | None = None
    if apxs is not None:
        sbindir = Path(_apxs_query(apxs, "SBINDIR"))
        sysconfdir = Path(_apxs_query(apxs, "SYSCONFDIR"))
        install_prefix = Path(_apxs_query(apxs, "PREFIX"))
        inherited_conf = sysconfdir / "httpd.conf"
        if httpd_opt is None:
            httpd_opt = str(sbindir / "httpd")
    if httpd_opt is None:
        raise _NoServerError("must pass --httpd or --apxs")
    return Path(httpd_opt), apxs, inherited_conf, install_prefix, defines


# --------------------------------------------------------------------------- #
# Collection-time requirement gating (need_* markers)
# --------------------------------------------------------------------------- #
_probe_cache: HttpdInfo | None = None


def _probed_info(config: pytest.Config) -> HttpdInfo | None:
    """Probe the target httpd once for collection-time requirement checks.

    Returns None if no httpd was specified (so requirement markers can't be
    evaluated -- tests are left to fail/skip naturally at fixture setup).
    """
    global _probe_cache  # noqa: PLW0603 - simple memo across the collection hook
    if _probe_cache is not None:
        return _probe_cache
    try:
        httpd, _apxs, inherited_conf, install_prefix, _defines = _resolve_paths(config)
    except Exception:
        return None
    info = probe(httpd, inherited_conf, install_prefix)
    # The bundled C test modules (authany, echo_post, input_body_filter, ...) are
    # compiled and LoadModule'd into the generated test config by the session
    # fixture, so need_module("authany") etc. should be satisfied at collection
    # time too. Augment the probed set with the C modules that WILL be built
    # (honoring the same HTTPD_TEST_REQUIRE_APACHE gating discover() applies).
    from apache_pytest.cmodules import discover

    cmods, _skipped = discover(REPO_ROOT / "c-modules", info)
    for mod in cmods:
        info.modules.add(f"mod_{mod.name}.c")
    _probe_cache = info
    return _probe_cache


def _unmet_requirement(
    item: pytest.Item, info: HttpdInfo, *, php_fpm: bool = False
) -> str | None:
    """Return a skip reason if any need_* marker on ``item`` is unmet, else None.

    ``php_fpm`` indicates a php-fpm binary was provided (and mod_proxy_fcgi is
    available), which satisfies need_php even without an in-process PHP SAPI.
    """
    for mark in item.iter_markers(name="need_module"):
        for name in mark.args:
            if not info.has_module(name):
                return f"module {name} not available"
    for mark in item.iter_markers(name="need_min_apache_version"):
        ver = mark.args[0]
        parts = tuple(int(x) for x in str(ver).split("."))
        parts += (0,) * (3 - len(parts))
        if info.version < parts:
            return f"httpd {info.version_str} < required {ver}"
    if any(item.iter_markers(name="need_cgi")) and not (
        info.has_module("mod_cgi") or info.has_module("mod_cgid")
    ):
        return "no CGI module (mod_cgi/mod_cgid) available"
    if any(item.iter_markers(name="need_php")):
        php_mods = ("sapi_apache2", "mod_php4", "mod_php5", "mod_php7", "mod_php")
        have_sapi = any(info.has_module(m) for m in php_mods)
        have_fpm = php_fpm and info.has_module("mod_proxy_fcgi")
        if not (have_sapi or have_fpm):
            return "no PHP SAPI module or php-fpm available"
    if any(item.iter_markers(name="need_ssl")) and not info.has_module("mod_ssl"):
        return "mod_ssl not available"
    # need_lwp is always satisfied (httpx is always present); no check.
    return None


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    info = _probed_info(config)
    if info is None:
        return
    php_fpm = bool(config.getoption("--php-fpm"))
    for item in items:
        reason = _unmet_requirement(item, info, php_fpm=php_fpm)
        if reason:
            item.add_marker(pytest.mark.skip(reason=reason))


# --------------------------------------------------------------------------- #
# Server lifecycle + client fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def framework(request: pytest.FixtureRequest):
    """Probe, configure, build C modules, start httpd; yield (config, server)."""
    try:
        httpd, apxs, inherited_conf, install_prefix, defines = _resolve_paths(request.config)
    except _NoServerError as exc:
        pytest.fail(str(exc))

    info = probe(httpd, inherited_conf, install_prefix)

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
        cmodule_loads, _skipped = compile_all(
            REPO_ROOT / "c-modules", apxs, info, defines=["APACHE2", "APACHE2_4", *defines]
        )

    config.generate(cmodule_loads=cmodule_loads)

    if use_fpm:
        from apache_pytest.fpm import PhpFpm

        fpm_mgr = PhpFpm(
            Path(php_fpm_opt),
            run_dir=Path(config.vars["t_logs"]) / "php-fpm",
            port=fpm_port,
        )
        fpm_mgr.start()

    server = HttpdServer(config)
    server.start()
    try:
        yield config, server
    finally:
        server.stop()
        if fpm_mgr is not None:
            fpm_mgr.stop()


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
