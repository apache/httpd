"""Build discovery: which httpd is under test, and what it can do.

One place answers that for both suites. ``resolve_build(config)`` finds the
httpd from, in order of precedence, ``--apxs``, ``--httpd`` (+ ``--conf``), or
the ``config.ini`` that the autoconf build generates for the modules/ suite,
probes it once per session, and returns an :class:`HttpdInfo`. The collection
time gating in :mod:`pyhttpd.gating` and the report header read it; the
classic framework builds its configuration on the same object.

The probing mirrors the discovery logic in Apache::TestConfigParse (perl-apache-test):
run ``httpd -v`` / ``-V`` / ``-l`` and parse the inherited install ``httpd.conf``
to learn the server version, MPM, compile-time ``-D`` defines, and the full set
of available modules (static + dynamically loaded).

The merged module set drives ``<IfModule>`` blocks, the module-name token
resolution in :mod:`apache_pytest.config`, and (eventually) the ``need_module``
test marks.
"""

from __future__ import annotations

import configparser
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# httpd -V emits lines like:  -D APACHE_MPM_DIR="server/mpm/prefork"
_DEFINE_RE = re.compile(r"^\s*-D\s+([A-Z0-9_]+)(?:=(.*))?\s*$")
# httpd -l / module conf lines end in ".c";  -l indents them two spaces.
_STATIC_MOD_RE = re.compile(r"^\s*(\w+\.c)\s*$")
# LoadModule foo_module modules/mod_foo.so  (optionally commented with leading #,
# the file optionally quoted)
_LOADMODULE_RE = re.compile(r'^\s*(#?)\s*LoadModule\s+(\S+)\s+(?:"([^"]+)"|(\S+))',
                            re.IGNORECASE)
# Include conf/extra/*.conf, IncludeOptional "conf.d/*.conf"
_INCLUDE_RE = re.compile(r'^\s*Include(?:Optional)?\s+(?:"([^"]+)"|(\S+))',
                         re.IGNORECASE)
_VERSION_RE = re.compile(r"Apache/(\d+)\.(\d+)\.(\d+)")


@dataclass
class LoadDirective:
    """One ``LoadModule symbol file`` mapping from an install conf."""

    symbol: str  # e.g. "session_module"
    so: str  # path as written, e.g. "modules/mod_session.so"
    active: bool  # False if the line was commented out

    @property
    def cname(self) -> str:
        """Module source name, e.g. "mod_session.c" (used as the modules-set key)."""
        stem = Path(self.so).name
        for suffix in (".so", ".dll"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        if stem.startswith("lib"):  # libphp.so -> mod_php.c
            stem = "mod_" + stem[3:]
        return f"{stem}.c"

    @property
    def is_mpm(self) -> bool:
        return self.symbol.startswith("mpm_") or "mpm_" in Path(self.so).name


@dataclass
class HttpdInfo:
    """Everything probed from an httpd binary + its inherited config."""

    httpd: Path
    version: tuple[int, int, int]
    mpm: str
    defines: dict[str, str | bool] = field(default_factory=dict)
    # Set of module source-file names, e.g. {"core.c", "mod_proxy.c", ...}.
    # This is the union of statically-compiled modules and the modules the
    # inherited httpd.conf loads (active LoadModule lines) — matching
    # Apache::Test's $self->{modules} hash keyed on "<name>.c". Membership here
    # means "the classic suite's server has this module", which is what drives
    # the <IfModule> blocks and the need_module marks. (The modules/ suite
    # writes its own LoadModule lines and asks HttpdTestEnv.has_shared_module.)
    modules: set[str] = field(default_factory=set)
    # Every LoadModule directive discovered in the inherited conf, with absolute
    # .so paths. Re-emitted into the generated httpd.conf so the test server
    # actually loads them (the generated conf does not Include the install conf).
    load_directives: list[LoadDirective] = field(default_factory=list)
    # TAKE1 directives inherited from the install conf (wanted_config in
    # TestConfigParse.pm:34): ServerAdmin, TypesConfig, DocumentRoot, ServerRoot.
    # Keyed by directive name (as written), value is the single argument.
    inherited: dict[str, str] = field(default_factory=dict)
    # Modules compiled into the binary (``httpd -l``), e.g. {"mod_so.c"}.
    static_modules: set[str] = field(default_factory=set)
    # Where the build was found: "apxs", "httpd" or "config.ini".
    source: str = ""
    # Install prefix, if known.
    prefix: Path | None = None
    # apxs of the build, if known: builds the test modules.
    apxs: Path | None = None
    # The install httpd.conf the LoadModule lines were inherited from.
    inherited_conf: Path | None = None
    # Where the build's shared modules are (apxs LIBEXECDIR).
    libexecdir: Path | None = None
    # Extra -D defines given with --defines.
    extra_defines: list[str] = field(default_factory=list)

    @property
    def version_str(self) -> str:
        return ".".join(str(p) for p in self.version)

    def has_module(self, name: str) -> bool:
        """True if module ``name`` is available.

        Accepts every form the Perl tests use: a bare name (``status``), a
        ``mod_``-prefixed name (``mod_status``), or any of those with a ``.c``/
        ``.so`` suffix. Modules are stored as source names (``mod_status.c``),
        so a bare name is also tried with the ``mod_`` prefix -- matching
        Apache::Test's need_module/have_module, which accept ``need_module 'status'``.
        """
        stem = name
        for suffix in (".c", ".so"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        candidates = {f"{stem}.c"}
        if not stem.startswith("mod_"):
            candidates.add(f"mod_{stem}.c")
        return bool(candidates & self.modules)

    def version_at_least(self, major: int, minor: int, patch: int = 0) -> bool:
        return self.version >= (major, minor, patch)


def _run(cmd: list[str]) -> str:
    """Run a probe command, returning combined stdout (httpd prints to stdout)."""
    proc = subprocess.run(  # noqa: S603 - trusted, caller-provided httpd path
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    # httpd -V can exit non-zero if it wants a config; we only need the banner.
    return proc.stdout + proc.stderr


def probe_version(httpd: Path) -> tuple[int, int, int]:
    out = _run([str(httpd), "-v"])
    m = _VERSION_RE.search(out)
    if not m:
        raise RuntimeError(f"could not parse version from `{httpd} -v`:\n{out}")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def probe_defines_and_mpm(httpd: Path) -> tuple[dict[str, str | bool], str]:
    """Parse ``httpd -V`` for ``-D`` defines, server MPM, and module magic info."""
    out = _run([str(httpd), "-V"])
    defines: dict[str, str | bool] = {}
    mpm = ""
    for line in out.splitlines():
        m = _DEFINE_RE.match(line)
        if m:
            key, val = m.group(1), m.group(2)
            defines[key] = val.strip('"') if val else True
            continue
        # "Server MPM:     event"  (2.4+/2.5)
        sm = re.match(r"\s*Server MPM:\s*(.+)", line, re.IGNORECASE)
        if sm:
            mpm = sm.group(1).strip().lower()
    if not mpm:
        # 2.0-era fallback: derive from APACHE_MPM_DIR=server/mpm/<name>
        mpm_dir = defines.get("APACHE_MPM_DIR")
        if isinstance(mpm_dir, str):
            mpm = Path(mpm_dir).name.lower()
    return defines, mpm


def probe_static_modules(httpd: Path) -> set[str]:
    """Modules compiled statically into the binary (``httpd -l``)."""
    out = _run([str(httpd), "-l"])
    mods: set[str] = set()
    for line in out.splitlines():
        m = _STATIC_MOD_RE.match(line)
        if m:
            mods.add(m.group(1))
    return mods


def parse_loadmodules(conf: Path, server_root: Path,
                      _seen: set | None = None) -> list[LoadDirective]:
    """Parse ``LoadModule`` lines (active and commented) from an install httpd.conf.

    The suite is built with ``--enable-load-all-modules`` upstream; locally the
    stock install conf lists most modules commented out. We capture both so the
    generated config can re-emit them and so module-presence checks succeed.
    Relative ``.so`` paths are resolved against ``server_root`` (the install
    prefix, ``apxs -q PREFIX``), and so are the files of active ``Include`` /
    ``IncludeOptional`` lines, which are followed (distributions load their
    modules from conf.d/ or mods-enabled/). Sections are not evaluated: a
    LoadModule in an ``<IfDefine>`` counts as active.
    """
    seen = set() if _seen is None else _seen
    directives: list[LoadDirective] = []
    if not conf.is_file() or conf.resolve() in seen:
        return directives
    seen.add(conf.resolve())
    for raw in conf.read_text(errors="replace").splitlines():
        inc = _INCLUDE_RE.match(raw)
        if inc:
            pattern = Path(inc.group(1) or inc.group(2))
            if not pattern.is_absolute():
                pattern = server_root / pattern
            if pattern.is_dir():
                pattern = pattern / "*"
            for path in sorted(pattern.parent.glob(pattern.name)):
                directives.extend(parse_loadmodules(path, server_root, seen))
            continue
        m = _LOADMODULE_RE.match(raw)
        if not m:
            continue
        commented, symbol, so = m.group(1), m.group(2), m.group(3) or m.group(4)
        so_path = Path(so)
        if not so_path.is_absolute():
            so_path = server_root / so_path
        directives.append(
            LoadDirective(symbol=symbol, so=str(so_path), active=(commented == ""))
        )
    return directives


# TAKE1 directives inherited from the install conf (wanted_config TAKE1).
# ServerRoot is intentionally NOT applied (spec_apply maps it to a no-op so the
# test serverroot wins); we still record it for completeness but config.py
# ignores it.
_INHERIT_TAKE1 = ("ServerAdmin", "TypesConfig", "DocumentRoot", "ServerRoot")
_TAKE1_RE = re.compile(
    r"^\s*(" + "|".join(_INHERIT_TAKE1) + r")\s+(.+?)\s*$"
)


def parse_inherited_take1(conf: Path) -> dict[str, str]:
    """Parse last-wins TAKE1 directives from an install conf (wanted_config)."""
    found: dict[str, str] = {}
    if not conf.is_file():
        return found
    for raw in conf.read_text(errors="replace").splitlines():
        if raw.lstrip().startswith("#"):
            continue
        m = _TAKE1_RE.match(raw)
        if m:
            found[m.group(1)] = m.group(2).strip().strip('"')
    return found


def probe(
    httpd: Path,
    inherited_conf: Path | None = None,
    server_root: Path | None = None,
) -> HttpdInfo:
    """Full probe of an httpd binary and (optionally) its install config.

    :param httpd: path to the httpd executable.
    :param inherited_conf: install ``httpd.conf`` to scan for LoadModule lines.
        Typically ``<prefix>/conf/httpd.conf`` derived from ``apxs -q SYSCONFDIR``.
    :param server_root: install prefix used to resolve relative ``.so`` paths
        (``apxs -q PREFIX``). Defaults to the parent of ``inherited_conf``'s dir.
    """
    version = probe_version(httpd)
    defines, mpm = probe_defines_and_mpm(httpd)
    static_modules = probe_static_modules(httpd)
    modules = set(static_modules)
    load_directives: list[LoadDirective] = []
    inherited: dict[str, str] = {}
    if inherited_conf is not None:
        root = server_root or inherited_conf.parent.parent
        inherited = parse_inherited_take1(inherited_conf)
        all_directives = parse_loadmodules(inherited_conf, root)
        # Inherit only ACTIVE LoadModule lines, matching Apache::Test's
        # inherit_load_module (which parses the live config, not commented
        # lines). A build intended for the suite activates all modules
        # (--enable-load-all-modules); locally the install conf is activated to
        # match. Commented lines are ignored entirely.
        # (once each: httpd itself warns about loading a module twice)
        symbols: set[str] = set()
        load_directives = [d for d in all_directives if d.active
                           and not (d.symbol in symbols or symbols.add(d.symbol))]
        for d in load_directives:
            if Path(d.so).exists():
                modules.add(d.cname)
    return HttpdInfo(
        httpd=httpd,
        version=version,
        mpm=mpm,
        defines=defines,
        modules=modules,
        load_directives=load_directives,
        inherited=inherited,
        static_modules=static_modules,
        inherited_conf=inherited_conf,
    )


# --------------------------------------------------------------------------- #
# Finding the build under test
# --------------------------------------------------------------------------- #


class NoServerError(Exception):
    """Raised when no httpd could be located from the options or config.ini.

    A plain exception, not pytest.fail, so the collection time callers can
    catch it without turning into an INTERNALERROR.
    """


class TargetError(NoServerError):
    """An httpd was named with --apxs or --httpd, and it is not usable.

    Never answered with another build: testing something other than what
    was asked for is worse than not testing.
    """


def apxs_query(apxs: Path, var: str) -> str:
    proc = subprocess.run(  # noqa: S603 - trusted path
        ["perl", str(apxs), "-q", var], capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


_apxs_cache: dict[str, dict[str, str]] = {}


def _apxs_vars(apxs: Path) -> dict[str, str]:
    """The apxs variables that locate a build; TargetError if apxs is unusable."""
    if str(apxs) in _apxs_cache:
        return _apxs_cache[str(apxs)]
    if not apxs.is_file():
        raise TargetError(f"apxs {apxs}: no such file")
    found = {}
    for var in ("SBINDIR", "SYSCONFDIR", "PREFIX", "LIBEXECDIR"):
        try:
            found[var] = apxs_query(apxs, var)
        except (OSError, subprocess.CalledProcessError) as exc:
            detail = getattr(exc, "stderr", None) or exc
            raise TargetError(f"apxs {apxs}: 'apxs -q {var}' failed: {detail}") from exc
    _apxs_cache[str(apxs)] = found
    return found


def resolve_paths(
    config,
) -> tuple[Path, Path | None, Path | None, Path | None, list[str]]:
    """Resolve (httpd, apxs, inherited_conf, install_prefix, defines) from options.

    --httpd, --conf and --prefix win over what --apxs reports. Raises
    :class:`NoServerError` if neither --httpd nor --apxs is given, and
    :class:`TargetError` if what was given is not usable.
    """
    apxs_opt = config.getoption("--apxs")
    httpd_opt = config.getoption("--httpd")
    defines = [d for d in config.getoption("--defines").split() if d]

    apxs = Path(apxs_opt) if apxs_opt else None
    inherited_conf: Path | None = None
    install_prefix: Path | None = None
    if apxs is not None:
        found = _apxs_vars(apxs)
        install_prefix = Path(found["PREFIX"])
        inherited_conf = Path(found["SYSCONFDIR"]) / "httpd.conf"
        if httpd_opt is None:
            httpd_opt = str(Path(found["SBINDIR"]) / "httpd")

    conf_opt = config.getoption("--conf")
    prefix_opt = config.getoption("--prefix")
    if conf_opt is not None:
        inherited_conf = Path(conf_opt)
    if prefix_opt is not None:
        install_prefix = Path(prefix_opt)
    elif inherited_conf is not None and install_prefix is None:
        install_prefix = inherited_conf.parent.parent

    if httpd_opt is None:
        raise NoServerError("must pass --httpd or --apxs")
    if not Path(httpd_opt).is_file():
        given = "--httpd" if config.getoption("--httpd") else f"the httpd of apxs {apxs}"
        raise TargetError(f"{given} {httpd_opt}: no such file")
    if inherited_conf is not None and not inherited_conf.is_file():
        given = "--conf" if conf_opt is not None else f"the httpd.conf of apxs {apxs}"
        raise TargetError(f"{given} {inherited_conf}: no such file")
    return Path(httpd_opt), apxs, inherited_conf, install_prefix, defines


def config_ini_path() -> Path:
    """The autoconf generated config.ini of the modules/ suite."""
    return Path(os.getenv("PYHTTPD_CONFIG", Path(__file__).resolve().parent / "config.ini"))


def _probe_target(httpd: Path, apxs: Path | None, inherited_conf: Path | None,
                  prefix: Path | None, libexecdir: Path | None,
                  defines: list[str], source: str) -> HttpdInfo:
    try:
        info = probe(httpd, inherited_conf, prefix)
    except (OSError, RuntimeError) as exc:
        raise TargetError(f"{httpd}: {exc}") from exc
    info.source = source
    info.prefix = prefix
    info.apxs = apxs
    info.libexecdir = libexecdir
    info.extra_defines = defines
    return info


def _probe_options(config) -> HttpdInfo:
    """The build named by --apxs / --httpd (+ --conf, --prefix)."""
    httpd, apxs, inherited_conf, prefix, defines = resolve_paths(config)
    if apxs is not None:
        libexecdir = Path(_apxs_vars(apxs)["LIBEXECDIR"])
    else:
        # <prefix>/bin/httpd and <prefix>/modules, the layout of Windows too
        libexecdir = (prefix if prefix is not None
                      else httpd.resolve().parent.parent) / "modules"
    return _probe_target(httpd, apxs, inherited_conf, prefix, libexecdir, defines,
                         "apxs" if apxs is not None else "httpd")


def _probe_config_ini(path: Path, defines: list[str]) -> HttpdInfo:
    """Probe the build described by a generated config.ini.

    Through its apxs when it has one, exactly as if that had been passed with
    --apxs, so both suites see the build the way they do in a
    ``make check-all-pytest`` run.
    """
    ini = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    ini.read(path)
    apxs: Path | None = Path(ini.get("global", "apxs", fallback="") or "")
    if apxs is not None and apxs.name and apxs.is_file():
        found = _apxs_vars(apxs)
        httpd = Path(found["SBINDIR"]) / "httpd"
        conf = Path(found["SYSCONFDIR"]) / "httpd.conf"
        prefix = Path(found["PREFIX"])
        libexecdir = Path(found["LIBEXECDIR"])
    else:
        apxs = None
        name = ini.get("httpd", "name", fallback="httpd")
        if sys.platform == "win32":
            httpd = Path(ini.get("global", "bindir")) / f"{name}.exe"
        else:
            httpd = Path(ini.get("global", "sbindir",
                                 fallback=ini.get("global", "bindir"))) / name
        prefix = Path(ini.get("global", "prefix"))
        conf = prefix / "conf" / "httpd.conf"
        libexecdir = Path(ini.get("global", "libexecdir", fallback=str(prefix / "modules")))
    if not httpd.is_file():
        raise NoServerError(f"{path}: no httpd binary at {httpd}")
    return _probe_target(httpd, apxs, conf if conf.is_file() else None, prefix,
                         libexecdir, defines, "config.ini")


_BUILD_KEY = None
# The build of the session, for code without a pytest config to ask: an
# HttpdTestEnv() created at import time to evaluate a skipif condition.
_current: HttpdInfo | None = None
_why_none = ""


def current() -> HttpdInfo | None:
    """The build resolve_build() found for this session; None before, or without."""
    return _current


def why_no_build() -> str:
    """Why resolve_build() found no httpd, for the failure of a fixture needing one."""
    return _why_none or "no httpd: pass --apxs or --httpd, or configure the tree"


def resolve_build(config) -> HttpdInfo | None:
    """Probe the httpd under test, once per session; None if there is none.

    Precedence: ``--apxs``, then ``--httpd`` (+ ``--conf``), then the
    config.ini generated by the build. An httpd named on the command line
    that is not usable raises :class:`TargetError`; it is never replaced by
    the build of config.ini. None (nothing named, no usable config.ini) is
    not an error here: callers that need a server fail with why_no_build().

    pyhttpd.plugin calls this in pytest_configure, so that everything after
    it - the HttpdTestEnv of modules/, collection time gating, the classic
    suite's fixture, the report header - tests and gates the same build.
    """
    global _BUILD_KEY, _current, _why_none  # noqa: PLW0603
    import pytest

    if _BUILD_KEY is None:
        _BUILD_KEY = pytest.StashKey[HttpdInfo | None]()
    if _BUILD_KEY in config.stash:
        return config.stash[_BUILD_KEY]

    info: HttpdInfo | None = None
    _why_none = ""
    if config.getoption("--apxs") or config.getoption("--httpd"):
        info = _probe_options(config)
    else:
        ini = config_ini_path()
        defines = [d for d in config.getoption("--defines").split() if d]
        if ini.is_file():
            try:
                info = _probe_config_ini(ini, defines)
            except NoServerError as exc:
                _why_none = f"no httpd: {exc}"
        else:
            _why_none = f"no httpd: pass --apxs or --httpd, or configure the tree ({ini})"
    config.stash[_BUILD_KEY] = info
    _current = info
    return info
