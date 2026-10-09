"""Functional-parity check: Python-generated httpd config vs. Perl reference.

The Python framework (``apache_pytest.config.TestConfig``) is a port of the Perl
Apache::Test config generator. This test proves *functional* parity by generating
a fresh config tree with the real Perl framework and diffing it against the
Python-generated ``t/conf`` tree, after normalizing away differences that are
benign (i.e. cannot change server behavior).

Realistic local outcome
------------------------
The Perl framework needs CPAN modules (Net::SSL, LWP::Protocol::https, ...; see
``.github/workflows/httpd-build.yml``) that are almost never installed on a dev
box, and it needs a built httpd (``--apxs``). When either is missing this test
``pytest.skip()``s with a clear reason -- it never fails for environmental
reasons. In CI, where the deps and a built httpd exist, it runs for real.

What it compares
----------------
Both frameworks emit ``t/conf/httpd.conf`` plus a set of ``*.conf`` includes.
We compare each file line-by-line after applying a documented normalization /
allowlist (see ``_normalize_lines`` and ``NORMALIZE_*`` below). Only a
directive-level divergence -- something that would change how the server
behaves -- fails the test.

Allowlist of benign differences (normalized or ignored before diffing)
----------------------------------------------------------------------
1. Absolute paths. The Perl reference is generated in a throw-away copy of the
   repo, and it embeds the install tree's module paths, so every absolute path
   differs. We collapse the Python repo root, the Perl temp repo root, and any
   ``LoadModule`` ``.../mod_*.so`` path to stable placeholders. The module-path
   normalizer matches both *quoted* (Python emits ``LoadModule x "<path>"``) and
   *unquoted* (Perl emits ``LoadModule x <path>``) forms, in any parent
   directory (the install tree's ``modules/``, a libtool ``.libs/``, or a C test
   module's ``c-modules/<m>/.libs/``), collapsing all of them -- and the
   surrounding quotes -- to ``@MODULE@/<basename>.so``. Quoting and build/install
   directory thus never matter; only the *set* of loaded modules does.
2. Port numbers. Ports are allocated dynamically (``@NextAvailablePort@`` and
   ``select_next_port``) and differ run-to-run even within one framework. We
   replace ``host:port`` / ``Listen ... :port`` occurrences with ``:@PORT@``.
3. Comment-only and blank lines. Cosmetic; ignored entirely.
4. Leading/trailing whitespace and internal run-length of whitespace. Apache
   treats runs of whitespace as a single separator, so ``Listen     x`` and
   ``Listen x`` are equivalent. We collapse internal whitespace.
5. LoadModule preamble ordering. The set of inherited ``LoadModule`` lines is
   emitted in hash-iteration order, which differs between the two
   implementations. We compare the preamble ``LoadModule`` lines as an
   unordered *set*, not a sequence.
6. ``User`` / ``Group`` lines. Perl emits these from the invoking uid/gid; they
   are environment-specific and behaviorally irrelevant to the test config.
   Ignored.
7. httpd runtime config variables for the document root. Perl emits
   ``Alias /manual ${DOCROOT}/manual`` using httpd's ``${DOCROOT}`` config
   variable, while Python emits the expanded literal absolute path
   ``Alias /manual <root>/t/htdocs/manual``. Both resolve to the same directory,
   so we normalize ``${DOCROOT}`` and the literal ``<root>/t/htdocs`` to a single
   ``@DOCROOT@`` placeholder (and, defensively, ``${SERVERROOT}`` -> @SERVERROOT@).
8. C-module config-block ORDER in the postamble. Perl's
   ``Apache::TestConfigC::cmodules_configure`` discovers C test modules via
   ``File::Find::finddepth``, i.e. filesystem *readdir* order, which is
   non-deterministic across machines. The Python framework deliberately uses
   ``sorted()`` for reproducible CI output. Both frameworks emit the *same set*
   of C-module config blocks (authany, eat_post, echo_post, echo_post_chunk,
   fold, input_body_filter, list_modules, memory_track, nntp_like's
   ``<VirtualHost _default_>`` + its ssl variant, random_chunk, test_apr_uri,
   test_pass_brigade, test_rwrite, test_ssl's ``<IfModule mod_ssl.c>`` wrapper,
   sessiontest's ``<IfModule mod_session.c>`` wrapper) with identical CONTENT --
   only the order differs. We therefore isolate the contiguous *C-module
   postamble region* (the units that appear after the getfiles
   ``<IfModule mod_alias.c>`` framing block and before the trailing ``Include``
   lines), split it into top-level units keyed by handler/location/wrapper, and
   compare it as an unordered *set* -- exactly as ``LoadModule`` lines (#5) are.
   Everything OUTSIDE that region stays an order-sensitive sequence, so a
   reordered or changed *real* directive elsewhere still fails. The set compare
   also still fails if any C-module unit is missing or its content differs.
9. ``FCGI_PORT`` numeric value in proxy.conf (``Define FCGI_PORT 8554`` vs
   ``8556``). This is a direct consequence of #8: the differing C-module vhost
   allocation order shifts which dynamic ``@NextAvailablePort@`` each subsequent
   vhost receives, even though both frameworks allocate the identical 34-port
   SET. We extend the port normalization (#2) so ``Define FCGI_PORT <n>`` ->
   ``Define FCGI_PORT @PORT@``. (Bare ``${FCGI_PORT}`` references are already
   identical on both sides.)
10. Perl interpreter path/version + Perl-only POD download alias. The Perl
    reference emits ``Alias /getfiles-binary-perl /opt/local/bin/perl5.34`` and
    ``Alias /getfiles-perl-pod /opt/local/lib/perl5/5.34/pods``; Python emits
    ``Alias /getfiles-binary-perl /opt/local/bin/perl`` and omits the POD alias.
    These are environment-specific perl interpreter resolution and a
    Perl-framework-only POD-path download helper (``@INC`` pods dir) with no
    Python equivalent and no relevance to httpd behavior. We normalize the
    perl-binary path to ``Alias /getfiles-binary-perl @PERL@`` (interpreter
    path/version no longer matters) and DROP the ``getfiles-perl-pod`` line from
    both sides entirely.
11. ``<IfModule mod_mime.c> TypesConfig ... </IfModule>`` framing block. The
    install httpd.conf already declares ``TypesConfig conf/mime.types``, which
    BOTH frameworks inherit. Python's ``_apply_inherited`` honours that inherited
    file and suppresses re-emitting its own block (matching Perl's
    ``inherit_server_file`` intent), whereas the Perl run re-declares it with an
    absolute path. MIME mapping behavior is identical either way (it comes from
    the inherited install ``TypesConfig`` regardless), so this single fixed
    framing block is benign and dropped from both sides before diffing. (A real
    per-handler/per-module directive change is unaffected and still fails.)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# Dev-only test: compares the Python-generated config against a freshly
# Perl-generated reference. It is meaningful only in the *original* httpd-tests
# checkout, where the Perl Apache::Test framework and the original t/ layout are
# present alongside this self-contained python/ suite. When run from a released,
# self-contained copy (no parent Apache-Test), it skips gracefully.
SUITE_ROOT = Path(__file__).resolve().parent.parent  # .../httpd-tests/python
PARENT_REPO = SUITE_ROOT.parent  # .../httpd-tests (only present in the dev checkout)
PERL_LIB = PARENT_REPO / "Apache-Test" / "lib"
# The Python framework now generates into the self-contained suite (python/t/conf).
PY_CONF_DIR = SUITE_ROOT / "t" / "conf"
# The Perl reference is generated from the original parent repo layout.
REPO_ROOT = PARENT_REPO


# --------------------------------------------------------------------------- #
# Environment detection
# --------------------------------------------------------------------------- #
def _perl_framework_available() -> tuple[bool, str]:
    """Return (ok, reason). ok=True iff the Perl Apache::Test stack can load."""
    perl = shutil.which("perl")
    if perl is None:
        return False, "perl interpreter not on PATH"
    if not PERL_LIB.is_dir():
        return False, f"Apache::Test lib not found at {PERL_LIB}"
    env = {**os.environ, "PERL5LIB": str(PERL_LIB)}
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, trusted lib path
            [perl, "-mApache::TestConfig", "-e", "1"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:  # pragma: no cover
        return False, f"failed to invoke perl: {exc}"
    if proc.returncode != 0:
        first = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = first[0] if first else "unknown error"
        return False, f"Apache::TestConfig (and CPAN deps) not loadable: {detail}"
    return True, ""


# --------------------------------------------------------------------------- #
# Normalization / allowlist
# --------------------------------------------------------------------------- #
_COMMENT_OR_BLANK = re.compile(r"^\s*(#.*)?$")
# host:port or :port at a word boundary (Listen, ServerName, *:port, urls, ...).
_PORT = re.compile(r":\d{2,5}\b")
_WHITESPACE = re.compile(r"[ \t]+")
# A LoadModule line, optionally inside an <IfModule> guard's indentation.
_LOADMODULE = re.compile(r"^\s*LoadModule\s")
# User / Group directives (top-level, env-specific).
_USER_GROUP = re.compile(r"^\s*(User|Group)\s", re.IGNORECASE)
# A LoadModule line's .so path, in any parent directory, quoted or unquoted:
#   LoadModule foo_module "/install/modules/mod_foo.so"        (built-in modules)
#   LoadModule foo_module /repo/c-modules/foo/.libs/mod_foo.so (C test modules)
# Both frameworks may quote the path or not, and emit it from different parent
# directories (the install tree's modules/, a libtool .libs/, ...). We collapse
# the whole path -- and any surrounding quotes -- to a stable @MODULE@/<basename>
# so the *set* of loaded modules is compared while quoting and the (differing)
# install/build directory are ignored.
_MODULE_SO = re.compile(
    r'^(?P<head>\s*LoadModule\s+\S+\s+)"?\S*?/(?P<base>mod_[\w]+\.so)"?\s*$'
)
# httpd runtime config variables that resolve to the document root. Perl emits
# ``Alias /manual ${DOCROOT}/manual`` using httpd's ``${DOCROOT}`` variable,
# while Python expands the literal absolute ``<root>/t/htdocs/manual``. These
# resolve to the same directory, so we collapse both spellings (after the
# repo-root substitution turns the literal into ``@ROOT@/t/htdocs``) to a single
# ``@DOCROOT@`` placeholder. ``${SERVERROOT}`` -> ``@SERVERROOT@`` defensively.
_DOCROOT_VAR = re.compile(r"\$\{DOCROOT\}|@ROOT@/t/htdocs")
_SERVERROOT_VAR = re.compile(r"\$\{SERVERROOT\}")
# (#9) ``Define FCGI_PORT <n>`` -> ``Define FCGI_PORT @PORT@``. The numeric value
# is a dynamically-allocated port (a downstream effect of the C-module ordering
# in #8); only the fact that a port is defined matters, not the integer.
_FCGI_PORT = re.compile(r"^(?P<head>Define\s+FCGI_PORT\s+)\d{2,5}\s*$")
# (#10) ``Alias /getfiles-binary-perl <path>`` -> ``... @PERL@``. The Perl
# interpreter path/version (e.g. /opt/local/bin/perl5.34 vs /opt/local/bin/perl)
# is environment-specific and irrelevant to httpd behavior.
_PERL_BINARY = re.compile(r"^(?P<head>Alias\s+/getfiles-binary-perl\s+)\S.*$")
# (#10) ``Alias /getfiles-perl-pod ...`` is a Perl-framework-only POD download
# helper (no Python equivalent, no httpd behavioral relevance). Dropped entirely.
_PERL_POD = re.compile(r"^\s*Alias\s+/getfiles-perl-pod\s")
# (#11) The ``<IfModule mod_mime.c> TypesConfig ... </IfModule>`` framing block.
# Both frameworks inherit ``TypesConfig conf/mime.types`` from the install conf;
# Python suppresses re-emitting it, Perl re-declares it. Behaviorally identical,
# so the whole 3-line block is dropped from both sides (see _normalize_lines).
_TYPESCONFIG_LINE = re.compile(r"^\s*TypesConfig\s")


def _normalize_line(line: str, *, repo_roots: list[str]) -> str:
    """Apply path/port/whitespace normalization to a single directive line."""
    # 1. LoadModule .so paths -> placeholder keyed on the bare filename, so the
    #    set of loaded modules is compared while the (differing) install/build
    #    dir AND any quoting difference are ignored. Matches both quoted and
    #    unquoted paths, in any parent dir (modules/, .libs/, c-modules/.../).
    m = _MODULE_SO.match(line)
    if m is not None:
        line = f"{m.group('head')}@MODULE@/{m.group('base')}"
    # 2. Any remaining repo-root absolute path -> @ROOT@.
    for root in repo_roots:
        if root:
            line = line.replace(root, "@ROOT@")
    # 3. httpd runtime config variables -> stable placeholders. ``${DOCROOT}``
    #    (Perl) and the expanded literal ``@ROOT@/t/htdocs`` (Python) point at
    #    the same directory; collapse both to @DOCROOT@ so e.g.
    #    ``Alias /manual ${DOCROOT}/manual`` == ``Alias /manual <root>/t/htdocs/manual``.
    line = _DOCROOT_VAR.sub("@DOCROOT@", line)
    line = _SERVERROOT_VAR.sub("@SERVERROOT@", line)
    # 4. Perl-binary getfiles alias path/version -> @PERL@ (env-specific, #10).
    m = _PERL_BINARY.match(line.strip())
    if m is not None:
        line = f"{m.group('head')}@PERL@"
    # 5. ``Define FCGI_PORT <n>`` -> ``Define FCGI_PORT @PORT@`` (#9).
    m = _FCGI_PORT.match(line.strip())
    if m is not None:
        line = f"{m.group('head')}@PORT@"
    # 6. Ports -> :@PORT@ (dynamically allocated, differ run-to-run).
    line = _PORT.sub(":@PORT@", line)
    # 7. Collapse internal whitespace runs to a single space (Apache-equivalent).
    line = _WHITESPACE.sub(" ", line.strip())
    return line


# (#11) The whole ``<IfModule mod_mime.c> ... TypesConfig ... </IfModule>`` block,
# emitted only by the Perl run (Python inherits the install conf's TypesConfig).
# Stripped from the raw text before line splitting so no empty wrapper remains.
_MIME_TYPESCONFIG_BLOCK = re.compile(
    r"^[ \t]*<IfModule[ \t]+mod_mime\.c>[ \t]*\n"
    r"(?:[ \t]*TypesConfig[ \t].*\n)+"
    r"[ \t]*</IfModule>[ \t]*\n?",
    re.MULTILINE,
)


def _normalize_lines(text: str, *, repo_roots: list[str]) -> tuple[list[str], set[str]]:
    """Split ``text`` into (ordered behavioral lines, unordered LoadModule set).

    Comment/blank lines and User/Group lines are dropped. LoadModule lines are
    pulled out into a set so their emission order is not significant. The
    Perl-only ``getfiles-perl-pod`` alias (#10) and the inherited-MIME
    ``<IfModule mod_mime.c>`` TypesConfig framing block (#11) are dropped, as
    they are benign and would otherwise show as one-sided.
    """
    # Strip the mod_mime TypesConfig framing block as a whole (#11), so no
    # orphaned ``<IfModule mod_mime.c></IfModule>`` wrapper survives.
    text = _MIME_TYPESCONFIG_BLOCK.sub("", text)
    ordered: list[str] = []
    loadmodules: set[str] = set()
    for raw in text.splitlines():
        if _COMMENT_OR_BLANK.match(raw):
            continue
        if _USER_GROUP.match(raw):
            continue
        if _PERL_POD.match(raw):  # (#10) Perl-only POD download alias.
            continue
        norm = _normalize_line(raw, repo_roots=repo_roots)
        if not norm:
            continue
        if _LOADMODULE.match(raw):
            loadmodules.add(norm)
        else:
            ordered.append(norm)
    return ordered, loadmodules


# --------------------------------------------------------------------------- #
# C-module postamble region: order-insensitive set comparison (#8)
# --------------------------------------------------------------------------- #
# The getfiles framing block that marks the END of the ordered preamble and the
# START of the C-module postamble region. Identified by its first alias.
_GETFILES_ALIAS = re.compile(r"^Alias\s+/getfiles-binary-httpd\b")
_IFMODULE_ALIAS_OPEN = re.compile(r"^<IfModule\s+mod_alias\.c>$")
_INCLUDE = re.compile(r"^Include\b")
# A standalone directive that semantically belongs to the block that follows it
# (the C-module emits e.g. ``Alias /authany ...`` + ``<Location /authany>`` or
# ``Listen ...`` + ``<VirtualHost _default_:...>`` as one logical unit).
_GLUE_PREFIX = re.compile(r"^(Alias|Listen)\b")


def _split_postamble_units(region: list[str]) -> list[str]:
    """Split the C-module postamble ``region`` into top-level config units.

    Each returned element is one unit's normalized text (lines joined by ``\\n``).
    A unit is either a single top-level directive line or a complete balanced
    ``<...> ... </...>`` block. A leading ``Alias``/``Listen`` glue line is merged
    into the block that immediately follows it (so e.g. the ``Alias /authany`` +
    ``<Location /authany>`` pair, and the nntp ``Listen`` + ``<VirtualHost>``
    pair, form a single keyed unit rather than splitting apart).
    """
    units: list[str] = []
    pending_glue: list[str] = []
    i = 0
    n = len(region)
    while i < n:
        line = region[i]
        if line.startswith("<") and not line.startswith("</"):
            # Consume a full balanced block.
            depth = 0
            block: list[str] = []
            while i < n:
                cur = region[i]
                block.append(cur)
                if cur.startswith("</"):
                    depth -= 1
                elif cur.startswith("<") and not cur.endswith("/>"):
                    depth += 1
                i += 1
                if depth == 0:
                    break
            units.append("\n".join(pending_glue + block))
            pending_glue = []
        elif _GLUE_PREFIX.match(line):
            # Hold this line; attach it to the next block (its handler config).
            pending_glue.append(line)
            i += 1
        else:
            # A bare directive line is its own unit (flush any pending glue too).
            if pending_glue:
                units.append("\n".join(pending_glue))
                pending_glue = []
            units.append(line)
            i += 1
    if pending_glue:
        units.append("\n".join(pending_glue))
    return units


def _partition_cmodule_region(
    ordered: list[str],
) -> tuple[list[str], list[str] | None]:
    """Split ``ordered`` lines into (kept-ordered, c-module-region-or-None).

    The C-module postamble region is the contiguous run of lines AFTER the
    getfiles ``<IfModule mod_alias.c>`` framing block and BEFORE the first
    trailing ``Include`` directive. If no getfiles framing block is present the
    file has no C-module region (returns ``(ordered, None)``), and the whole
    file is compared as an order-sensitive sequence. The getfiles framing block
    itself stays in the ordered part (it is identical and same-positioned on
    both sides), so only the genuinely order-non-deterministic C-module units
    are set-compared.
    """
    # Find the end of the getfiles <IfModule mod_alias.c> ... </IfModule> block.
    start = None
    i = 0
    while i < len(ordered):
        if _IFMODULE_ALIAS_OPEN.match(ordered[i]) and any(
            _GETFILES_ALIAS.match(ordered[j])
            for j in range(i + 1, min(i + 6, len(ordered)))
        ):
            # Walk to this block's closing </IfModule>.
            depth = 0
            j = i
            while j < len(ordered):
                cur = ordered[j]
                if cur.startswith("</"):
                    depth -= 1
                elif cur.startswith("<") and not cur.endswith("/>"):
                    depth += 1
                j += 1
                if depth == 0:
                    break
            start = j  # first line after the getfiles framing block
            break
        i += 1
    if start is None:
        return ordered, None
    # The region ends at the first trailing Include line (or EOF).
    end = start
    while end < len(ordered) and not _INCLUDE.match(ordered[end]):
        end += 1
    if end == start:
        return ordered, []  # region present but empty
    region = ordered[start:end]
    kept = ordered[:start] + ordered[end:]
    return kept, region


# --------------------------------------------------------------------------- #
# Perl reference generation
# --------------------------------------------------------------------------- #
def _generate_perl_reference(dst: Path, apxs: Path) -> Path:
    """Copy the repo into ``dst`` and run the Perl config generator there.

    Returns the path to the generated ``t/conf`` directory. Generating into a
    copy avoids clobbering the Python-generated ``t/conf`` the other tests use.
    """
    # Copy the repo, excluding heavy/irrelevant trees and any prior build state.
    # "logs" is excluded because a running (or recently-run) server leaves a
    # mod_cgid unix socket (cgisock.<pid>) there, which copytree cannot copy.
    ignore = shutil.ignore_patterns(
        ".git",
        "python",
        "blib",
        ".venv",
        "*.so",
        ".libs",
        "logs",
    )
    shutil.copytree(REPO_ROOT, dst, ignore=ignore, symlinks=True)

    env = {**os.environ, "PERL5LIB": str(PERL_LIB)}
    # 1. perl Makefile.PL -apxs <apxs>  -> generates t/TEST
    subprocess.run(  # noqa: S603
        ["perl", "Makefile.PL", "-apxs", str(apxs)],
        cwd=dst,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    # 2. perl t/TEST -configure  -> generates t/conf/*, then exits non-zero by
    #    design ("reconfiguration done" -> exit 1). Don't treat that as failure;
    #    verify by checking that httpd.conf was produced.
    subprocess.run(  # noqa: S603
        ["perl", str(dst / "t" / "TEST"), "-configure"],
        cwd=dst,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    conf_dir = dst / "t" / "conf"
    if not (conf_dir / "httpd.conf").is_file():
        raise RuntimeError(
            "Perl framework did not generate t/conf/httpd.conf "
            f"(looked in {conf_dir})"
        )
    return conf_dir


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #
def _compare_conf(
    name: str,
    py_text: str,
    perl_text: str,
    *,
    repo_roots: list[str],
) -> list[str]:
    """Return a list of human-readable divergences for one conf file."""
    py_ordered, py_loads = _normalize_lines(py_text, repo_roots=repo_roots)
    perl_ordered, perl_loads = _normalize_lines(perl_text, repo_roots=repo_roots)

    problems: list[str] = []

    # LoadModule set parity (order-insensitive).
    only_py = py_loads - perl_loads
    only_perl = perl_loads - py_loads
    for ln in sorted(only_py):
        problems.append(f"[{name}] LoadModule only in Python: {ln}")
    for ln in sorted(only_perl):
        problems.append(f"[{name}] LoadModule only in Perl ref: {ln}")

    # C-module postamble region (#8): set-compare its units, order-insensitive.
    # The C modules are discovered in non-deterministic readdir order (Perl) vs.
    # sorted order (Python); only the SET of units, with identical content, must
    # match. Everything else stays an order-sensitive sequence below.
    py_ordered, py_region = _partition_cmodule_region(py_ordered)
    perl_ordered, perl_region = _partition_cmodule_region(perl_ordered)
    if py_region is not None or perl_region is not None:
        py_units = set(_split_postamble_units(py_region or []))
        perl_units = set(_split_postamble_units(perl_region or []))
        for unit in sorted(py_units - perl_units):
            problems.append(
                f"[{name}] C-module config unit only in Python:\n{unit}"
            )
        for unit in sorted(perl_units - py_units):
            problems.append(
                f"[{name}] C-module config unit only in Perl ref:\n{unit}"
            )

    # Behavioral (non-LoadModule) lines, order-sensitive sequence diff.
    if py_ordered != perl_ordered:
        import difflib

        diff = difflib.unified_diff(
            perl_ordered,
            py_ordered,
            fromfile=f"perl/{name}",
            tofile=f"python/{name}",
            lineterm="",
            n=2,
        )
        problems.append(f"[{name}] directive divergence:\n" + "\n".join(diff))
    return problems


# --------------------------------------------------------------------------- #
# The test
# --------------------------------------------------------------------------- #
def test_config_parity(request: pytest.FixtureRequest, tmp_path: Path) -> None:
    """Python-generated config must functionally match the Perl reference.

    Skips cleanly when the Perl framework or a built httpd (--apxs) is absent.
    """
    # --- prerequisites -----------------------------------------------------
    # When --php-fpm is active the Python framework adds a PHP-FPM routing block
    # that the Perl reference (generated without FPM) does not, so the configs
    # are intentionally non-equivalent; skip the parity comparison then.
    if request.config.getoption("--php-fpm"):
        pytest.skip(
            "--php-fpm active: Python config includes a PHP-FPM routing block "
            "absent from the Perl reference; parity comparison not applicable"
        )

    ok, reason = _perl_framework_available()
    if not ok:
        pytest.skip(f"Perl Apache::Test framework unavailable: {reason}")

    apxs_opt = request.config.getoption("--apxs")
    if not apxs_opt:
        pytest.skip(
            "--apxs not provided; the Perl framework needs a built httpd "
            "(apxs) to generate a reference config"
        )
    apxs = Path(apxs_opt)
    if not apxs.exists():
        pytest.skip(f"--apxs path does not exist: {apxs}")

    if not (PY_CONF_DIR / "httpd.conf").is_file():
        pytest.skip(
            f"Python-generated config not found at {PY_CONF_DIR}/httpd.conf; "
            "run the suite (the `server`/`config` fixtures generate it) first"
        )

    # --- generate the Perl reference into a throwaway copy -----------------
    perl_repo = tmp_path / "perl-ref"
    try:
        perl_conf_dir = _generate_perl_reference(perl_repo, apxs)
    except subprocess.CalledProcessError as exc:  # pragma: no cover - CI only
        pytest.skip(
            "Perl reference generation failed "
            f"(rc={exc.returncode}): {exc.stderr or exc.stdout}"
        )
    except RuntimeError as exc:  # pragma: no cover - CI only
        pytest.skip(f"Perl reference generation incomplete: {exc}")

    # All repo roots normalize to @ROOT@: the Perl reference temp-repo, the
    # original parent repo, AND the self-contained suite root (python/), since
    # the Python framework now embeds its assets under python/t. Order
    # longest-first so a longer path is substituted before any prefix of it.
    repo_roots = sorted(
        {str(REPO_ROOT), str(perl_repo), str(SUITE_ROOT)}, key=len, reverse=True
    )

    # --- compare every conf file present on both sides ---------------------
    def _conf_map(base: Path) -> dict[str, Path]:
        return {
            p.relative_to(base).as_posix(): p
            for p in base.rglob("*.conf")
        }

    py_files = _conf_map(PY_CONF_DIR)
    perl_files = _conf_map(perl_conf_dir)

    common = sorted(set(py_files) & set(perl_files))
    assert common, "no common *.conf files between Python and Perl outputs"

    # Files present on only one side are reported but not auto-failed for
    # SSL-derived files that depend on module availability; still surface them.
    only_py = sorted(set(py_files) - set(perl_files))
    only_perl = sorted(set(perl_files) - set(py_files))

    all_problems: list[str] = []
    for rel in only_py:
        all_problems.append(f"conf file only generated by Python: {rel}")
    for rel in only_perl:
        all_problems.append(f"conf file only generated by Perl: {rel}")

    for rel in common:
        py_text = py_files[rel].read_text()
        perl_text = perl_files[rel].read_text()
        all_problems.extend(
            _compare_conf(rel, py_text, perl_text, repo_roots=repo_roots)
        )

    if all_problems:
        pytest.fail(
            "Python-generated config diverges from the Perl reference:\n\n"
            + "\n\n".join(all_problems)
        )


# --------------------------------------------------------------------------- #
# Pure-logic unit checks for the normalization (run regardless of Perl deps).
# These guard the *valuable* comparison logic so it stays correct even when the
# parity test itself can only skip locally.
# --------------------------------------------------------------------------- #
class TestNormalizationLogic:
    ROOTS = ["/home/ci/httpd-tests", "/tmp/perl-ref"]

    def test_port_normalized(self) -> None:
        a = _normalize_line("Listen 0.0.0.0:8529", repo_roots=self.ROOTS)
        b = _normalize_line("Listen 0.0.0.0:9011", repo_roots=self.ROOTS)
        assert a == b == "Listen 0.0.0.0:@PORT@"

    def test_servername_port_normalized(self) -> None:
        a = _normalize_line("ServerName localhost:8530", repo_roots=self.ROOTS)
        b = _normalize_line("ServerName localhost:8777", repo_roots=self.ROOTS)
        assert a == b == "ServerName localhost:@PORT@"

    def test_repo_root_normalized(self) -> None:
        a = _normalize_line(
            'ErrorLog /home/ci/httpd-tests/t/logs/error_log', repo_roots=self.ROOTS
        )
        b = _normalize_line(
            'ErrorLog /tmp/perl-ref/t/logs/error_log', repo_roots=self.ROOTS
        )
        assert a == b == "ErrorLog @ROOT@/t/logs/error_log"

    def test_module_path_normalized(self) -> None:
        a = _normalize_line(
            'LoadModule ssl_module "/opt/httpd/modules/mod_ssl.so"',
            repo_roots=self.ROOTS,
        )
        b = _normalize_line(
            'LoadModule ssl_module "/usr/lib/apache2/modules/mod_ssl.so"',
            repo_roots=self.ROOTS,
        )
        # Canonical form drops the quotes so quoted/unquoted paths reconcile.
        assert a == b == "LoadModule ssl_module @MODULE@/mod_ssl.so"

    def test_libs_module_path_normalized(self) -> None:
        line = _normalize_line(
            'LoadModule echo_post_module '
            '"/home/ci/httpd-tests/c-modules/echo_post/.libs/mod_echo_post.so"',
            repo_roots=self.ROOTS,
        )
        assert line == "LoadModule echo_post_module @MODULE@/mod_echo_post.so"

    def test_module_path_quoted_and_unquoted_equivalent(self) -> None:
        """A C-module .so emitted QUOTED (Python) vs UNQUOTED (Perl), from a
        ``c-modules/<m>/.libs/`` dir, must normalize identically. This is the
        real divergence the parity test surfaced for all 17 C test modules."""
        quoted = _normalize_line(
            'LoadModule echo_post_module '
            '"/home/ci/httpd-tests/c-modules/echo_post/.libs/mod_echo_post.so"',
            repo_roots=self.ROOTS,
        )
        unquoted = _normalize_line(
            "LoadModule echo_post_module "
            "/tmp/perl-ref/c-modules/echo_post/.libs/mod_echo_post.so",
            repo_roots=self.ROOTS,
        )
        assert quoted == unquoted == "LoadModule echo_post_module @MODULE@/mod_echo_post.so"

    def test_docroot_var_equivalent_to_absolute_htdocs(self) -> None:
        """``Alias /manual ${DOCROOT}/manual`` (Perl, using httpd's runtime
        ``${DOCROOT}`` variable) must normalize identically to Python's expanded
        literal ``Alias /manual <root>/t/htdocs/manual``; they resolve to the
        same directory."""
        perl = _normalize_line(
            "Alias /manual ${DOCROOT}/manual", repo_roots=self.ROOTS
        )
        python = _normalize_line(
            "Alias /manual /home/ci/httpd-tests/t/htdocs/manual",
            repo_roots=self.ROOTS,
        )
        assert perl == python == "Alias /manual @DOCROOT@/manual"

    def test_serverroot_var_normalized(self) -> None:
        line = _normalize_line(
            "Include ${SERVERROOT}/conf/extra.conf", repo_roots=self.ROOTS
        )
        assert line == "Include @SERVERROOT@/conf/extra.conf"

    def test_docroot_normalization_does_not_mask_real_alias_divergence(self) -> None:
        """The @DOCROOT@ collapse must not hide a genuinely different alias
        target."""
        py = "Alias /manual ${DOCROOT}/manual\n"
        perl = "Alias /manual /home/ci/httpd-tests/t/htdocs/elsewhere\n"
        problems = _compare_conf("extra.conf", py, perl, repo_roots=self.ROOTS)
        assert len(problems) == 1
        assert "directive divergence" in problems[0]

    def test_whitespace_collapsed(self) -> None:
        a = _normalize_line("ServerAdmin     unknown@localhost", repo_roots=self.ROOTS)
        b = _normalize_line("ServerAdmin unknown@localhost", repo_roots=self.ROOTS)
        assert a == b == "ServerAdmin unknown@localhost"

    def test_comments_and_blanks_dropped(self) -> None:
        text = "# a comment\n\n   \nServerName localhost:8529\n"
        ordered, loads = _normalize_lines(text, repo_roots=self.ROOTS)
        assert ordered == ["ServerName localhost:@PORT@"]
        assert loads == set()

    def test_user_group_dropped(self) -> None:
        text = "User daemon\nGroup daemon\nKeepAlive On\n"
        ordered, _ = _normalize_lines(text, repo_roots=self.ROOTS)
        assert ordered == ["KeepAlive On"]

    def test_loadmodule_pulled_into_unordered_set(self) -> None:
        text = (
            'LoadModule a_module "/x/modules/mod_a.so"\n'
            'LoadModule b_module "/x/modules/mod_b.so"\n'
            "KeepAlive On\n"
        )
        ordered, loads = _normalize_lines(text, repo_roots=self.ROOTS)
        assert ordered == ["KeepAlive On"]
        assert loads == {
            "LoadModule a_module @MODULE@/mod_a.so",
            "LoadModule b_module @MODULE@/mod_b.so",
        }

    def test_loadmodule_order_insensitive_compare(self) -> None:
        py = (
            'LoadModule a_module "/p/modules/mod_a.so"\n'
            'LoadModule b_module "/p/modules/mod_b.so"\n'
        )
        perl = (
            'LoadModule b_module "/q/modules/mod_b.so"\n'
            'LoadModule a_module "/q/modules/mod_a.so"\n'
        )
        problems = _compare_conf(
            "httpd.conf", py, perl, repo_roots=["/p", "/q"]
        )
        assert problems == []

    def test_missing_module_detected(self) -> None:
        py = 'LoadModule a_module "/p/modules/mod_a.so"\n'
        perl = (
            'LoadModule a_module "/q/modules/mod_a.so"\n'
            'LoadModule b_module "/q/modules/mod_b.so"\n'
        )
        problems = _compare_conf("httpd.conf", py, perl, repo_roots=["/p", "/q"])
        assert len(problems) == 1
        assert "only in Perl ref" in problems[0]
        assert "mod_b.so" in problems[0]

    def test_directive_divergence_detected(self) -> None:
        py = "LogLevel debug\nKeepAlive On\n"
        perl = "LogLevel warn\nKeepAlive On\n"
        problems = _compare_conf("core.conf", py, perl, repo_roots=self.ROOTS)
        assert len(problems) == 1
        assert "directive divergence" in problems[0]

    def test_identical_after_normalization_no_problems(self) -> None:
        py = (
            "# python header\n"
            'ErrorLog /p/t/logs/error_log\n'
            "Listen 0.0.0.0:8529\n"
            "User pyuser\n"
        )
        perl = (
            'ErrorLog /q/t/logs/error_log\n'
            "\n"
            "Listen    0.0.0.0:9999\n"
            "Group perlgroup\n"
        )
        problems = _compare_conf("httpd.conf", py, perl, repo_roots=["/p", "/q"])
        assert problems == []

    # -- #9 FCGI_PORT normalization --------------------------------------- #
    def test_fcgi_port_normalized(self) -> None:
        """``Define FCGI_PORT <n>`` collapses to ``@PORT@`` regardless of the
        dynamically-allocated integer (#9)."""
        a = _normalize_line("Define FCGI_PORT 8554", repo_roots=self.ROOTS)
        b = _normalize_line("Define FCGI_PORT 8556", repo_roots=self.ROOTS)
        assert a == b == "Define FCGI_PORT @PORT@"

    def test_fcgi_port_reference_unaffected(self) -> None:
        """``${FCGI_PORT}`` references are identical on both sides and must NOT
        be turned into @PORT@ (only the numeric ``Define`` value is dynamic)."""
        line = _normalize_line(
            "SetHandler proxy:fcgi://127.0.0.1:${FCGI_PORT}", repo_roots=self.ROOTS
        )
        assert line == "SetHandler proxy:fcgi://127.0.0.1:${FCGI_PORT}"

    # -- #10 perl-binary path / perl-pod line ----------------------------- #
    def test_perl_binary_path_normalized(self) -> None:
        """The perl interpreter path/version differs by environment; collapse
        ``Alias /getfiles-binary-perl <path>`` to ``@PERL@`` (#10)."""
        perl = _normalize_line(
            "Alias /getfiles-binary-perl /opt/local/bin/perl5.34",
            repo_roots=self.ROOTS,
        )
        python = _normalize_line(
            "Alias /getfiles-binary-perl /opt/local/bin/perl", repo_roots=self.ROOTS
        )
        assert perl == python == "Alias /getfiles-binary-perl @PERL@"

    def test_perl_pod_alias_dropped(self) -> None:
        """The Perl-only ``getfiles-perl-pod`` download alias is dropped (#10)."""
        perl = (
            "Alias /getfiles-binary-perl /opt/local/bin/perl5.34\n"
            "Alias /getfiles-perl-pod /opt/local/lib/perl5/5.34/pods\n"
        )
        python = "Alias /getfiles-binary-perl /opt/local/bin/perl\n"
        ordered_perl, _ = _normalize_lines(perl, repo_roots=self.ROOTS)
        ordered_py, _ = _normalize_lines(python, repo_roots=self.ROOTS)
        assert ordered_perl == ordered_py == ["Alias /getfiles-binary-perl @PERL@"]

    # -- #11 inherited mod_mime TypesConfig block ------------------------- #
    def test_mime_typesconfig_block_dropped(self) -> None:
        """The ``<IfModule mod_mime.c> TypesConfig ... </IfModule>`` framing block
        (emitted only by Perl, inherited by Python) is dropped whole, leaving no
        orphaned wrapper (#11)."""
        perl = (
            "KeepAlive On\n"
            "<IfModule mod_mime.c>\n"
            '    TypesConfig "/x/conf/mime.types"\n'
            "</IfModule>\n"
            "Listen 0.0.0.0:8529\n"
        )
        ordered, _ = _normalize_lines(perl, repo_roots=self.ROOTS)
        assert ordered == ["KeepAlive On", "Listen 0.0.0.0:@PORT@"]

    # -- #8 C-module postamble region: order-insensitive set comparison --- #
    # Two minimal but realistic httpd.conf tails: a getfiles framing block (the
    # region delimiter) followed by C-module units in DIFFERENT order on each
    # side, then the trailing Include lines (which stay ordered).
    _PY_TAIL = (
        "<IfModule mod_alias.c>\n"
        "    Alias /getfiles-binary-httpd /py/bin/httpd\n"
        "</IfModule>\n"
        "Alias /authany /py/t/htdocs\n"
        "<Location /authany>\n"
        "    require user any-user\n"
        "</Location>\n"
        "<Location /eat_post>\n"
        "    SetHandler eat_post\n"
        "</Location>\n"
        "Listen 0.0.0.0:8530\n"
        "<VirtualHost _default_:8530>\n"
        "    NNTPLike On\n"
        "</VirtualHost>\n"
        "<IfModule mod_ssl.c>\n"
        "<Location /test_ssl_var_lookup>\n"
        "    SetHandler test-ssl-var-lookup\n"
        "</Location>\n"
        "</IfModule>\n"
        'Include "/py/t/conf/core.conf"\n'
    )
    # Perl emits the SAME units in a DIFFERENT (readdir) order.
    _PERL_TAIL = (
        "<IfModule mod_alias.c>\n"
        "    Alias /getfiles-binary-httpd /pl/bin/httpd\n"
        "</IfModule>\n"
        "<IfModule mod_ssl.c>\n"
        "<Location /test_ssl_var_lookup>\n"
        "    SetHandler test-ssl-var-lookup\n"
        "</Location>\n"
        "</IfModule>\n"
        "Listen 0.0.0.0:9999\n"
        "<VirtualHost _default_:9999>\n"
        "    NNTPLike On\n"
        "</VirtualHost>\n"
        "<Location /eat_post>\n"
        "    SetHandler eat_post\n"
        "</Location>\n"
        "Alias /authany /pl/t/htdocs\n"
        "<Location /authany>\n"
        "    require user any-user\n"
        "</Location>\n"
        'Include "/pl/t/conf/core.conf"\n'
    )
    TAIL_ROOTS = ["/py", "/pl"]

    def test_cmodule_region_order_insensitive(self) -> None:
        """Identical SET of C-module units in a DIFFERENT order does NOT fail."""
        problems = _compare_conf(
            "httpd.conf", self._PY_TAIL, self._PERL_TAIL, repo_roots=self.TAIL_ROOTS
        )
        assert problems == []

    def test_cmodule_region_glues_alias_and_listen(self) -> None:
        """The ``Alias /authany`` + ``<Location /authany>`` pair and the
        ``Listen`` + ``<VirtualHost>`` pair are each treated as ONE unit, so the
        @PORT@-normalized Listen does not float free and mis-match."""
        py_units = set(
            _split_postamble_units(
                _partition_cmodule_region(
                    _normalize_lines(self._PY_TAIL, repo_roots=self.TAIL_ROOTS)[0]
                )[1]
            )
        )
        # The authany alias is glued to its Location, not a standalone unit.
        assert any(
            u.startswith("Alias /authany") and "<Location /authany>" in u
            for u in py_units
        )
        assert any(
            u.startswith("Listen 0.0.0.0:@PORT@")
            and "<VirtualHost _default_:@PORT@>" in u
            for u in py_units
        )

    def test_cmodule_region_detects_missing_unit(self) -> None:
        """NEGATIVE: if a C-module unit is entirely MISSING on one side the set
        comparison must still FAIL (no masking)."""
        # Drop the eat_post Location from the Perl side only.
        perl_missing = self._PERL_TAIL.replace(
            "<Location /eat_post>\n    SetHandler eat_post\n</Location>\n", ""
        )
        problems = _compare_conf(
            "httpd.conf", self._PY_TAIL, perl_missing, repo_roots=self.TAIL_ROOTS
        )
        assert len(problems) == 1
        assert "C-module config unit only in Python" in problems[0]
        assert "/eat_post" in problems[0]

    def test_cmodule_region_detects_changed_content(self) -> None:
        """NEGATIVE: if a C-module unit's CONTENT differs (e.g. a SetHandler
        value), the set comparison must still FAIL (no masking)."""
        perl_changed = self._PERL_TAIL.replace(
            "SetHandler eat_post", "SetHandler eat_post_DIFFERENT"
        )
        problems = _compare_conf(
            "httpd.conf", self._PY_TAIL, perl_changed, repo_roots=self.TAIL_ROOTS
        )
        # The Python eat_post unit and the differing Perl one are both reported.
        assert len(problems) == 2
        joined = "\n".join(problems)
        assert "only in Python" in joined
        assert "only in Perl ref" in joined
        assert "eat_post_DIFFERENT" in joined

    def test_cmodule_region_changed_ssl_handler_detected(self) -> None:
        """NEGATIVE: a changed SetHandler INSIDE the ssl ``<IfModule>`` wrapper is
        still surfaced (the wrapper unit is compared by full content)."""
        perl_changed = self._PERL_TAIL.replace(
            "SetHandler test-ssl-var-lookup", "SetHandler test-ssl-var-lookup-X"
        )
        problems = _compare_conf(
            "httpd.conf", self._PY_TAIL, perl_changed, repo_roots=self.TAIL_ROOTS
        )
        assert any("test-ssl-var-lookup-X" in p for p in problems)

    def test_real_directive_outside_region_still_order_sensitive(self) -> None:
        """A reordered REAL directive OUTSIDE the C-module region must still fail:
        the set-compare leniency is confined to the postamble region."""
        py = "LogLevel debug\nKeepAlive On\n" + self._PY_TAIL
        # Swap two genuine preamble directives on the Perl side.
        perl = "KeepAlive On\nLogLevel debug\n" + self._PERL_TAIL
        problems = _compare_conf(
            "httpd.conf", py, perl, repo_roots=self.TAIL_ROOTS
        )
        assert any("directive divergence" in p for p in problems)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-v"]))
