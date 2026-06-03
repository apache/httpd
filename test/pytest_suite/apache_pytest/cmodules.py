"""Compile the bundled C test modules via apxs.

Port of the build half of Apache::TestConfigC. For each ``c-modules/<name>/`` dir
containing ``mod_<name>.c``, this:

1. generates ``c-modules/apache_httpd_test.h`` (the shared header every test
   module ``#include``s, including the ``APACHE_HTTPD_TEST_MODULE`` macro and the
   per-phase/per-config ``#ifndef ... NULL`` fallbacks);
2. honors ``#define HTTPD_TEST_REQUIRE_APACHE <ver>`` gating in each source,
   skipping modules that require a different/newer httpd;
3. invokes apxs to build each ``.so``;
4. returns ``(symbol, so_path)`` load pairs for the config preamble.

The C sources are NOT ported — they compile exactly as the Perl framework builds
them (custom C modules need only be compiled, per the migration requirement). The
generated header is reproduced functionally (the C preprocessor is insensitive to
the macro's internal whitespace), and correctness is proven by the modules
actually compiling and loading in the smoke test.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .probe import HttpdInfo

_LIB_SUBDIR = ".libs"  # apxs output dir for Apache 2.x (TestConfigC %lib_dir)

# Hook phases registered by APACHE_HTTPD_TEST_MODULE for Apache 2.x
# (TestConfigC @cmodule_phases).
_HOOK_PHASES = [
    "post_read_request",
    "translate_name",
    "header_parser",
    "access_checker",
    "check_user_id",
    "auth_checker",
    "type_checker",
    "fixups",
    "handler",
    "log_transaction",
    "child_init",
]
# Module-struct config slots (TestConfigC @cmodule_config_names).
_CONFIG_NAMES = [
    "per_dir_create",
    "per_dir_merge",
    "per_srv_create",
    "per_srv_merge",
    "commands",
]

# Static portion of the header (TestConfigC __DATA__), verbatim.
_HEADER_PRELUDE = """\
#ifndef APACHE_HTTPD_TEST_H
#define APACHE_HTTPD_TEST_H

/* headers present in both 1.x and 2.x */
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "ap_config.h"

#ifdef APACHE1
#define AP_METHOD_BIT  1
typedef size_t apr_size_t;
typedef array_header apr_array_header_t;
#define APR_OFF_T_FMT "ld"
#define APR_SIZE_T_FMT "lu"
#endif /* APACHE1 */

#ifdef APACHE2
#ifndef APACHE_HTTPD_TEST_HOOK_ORDER
#define APACHE_HTTPD_TEST_HOOK_ORDER APR_HOOK_MIDDLE
#endif
#include "ap_compat.h"
#endif /* APACHE2 */

#endif /* APACHE_HTTPD_TEST_H */
"""

_REQUIRE_RE = re.compile(
    r"^\s*#define\s+HTTPD_TEST_REQUIRE_APACHE\s+(\d+(?:\.\d+){0,2})", re.MULTILINE
)


@dataclass
class CModule:
    name: str  # e.g. "echo_post"
    src_dir: Path
    src: Path

    @property
    def symbol(self) -> str:
        # APACHE_HTTPD_TEST_MODULE(name) registers <name>_module; LoadModule wants
        # the bare module name as the symbol (TestConfigC: sym => "${name}_module").
        return self.name

    @property
    def so(self) -> Path:
        return self.src_dir / _LIB_SUBDIR / f"mod_{self.name}.so"


def _define_name(token: str) -> str:
    # Perl cmodule_define_name uppercases the token: "APACHE_HTTPD_TEST_\U$name"
    # (TestConfigC.pm:340-343). The module sources #define the UPPERCASE form
    # (e.g. APACHE_HTTPD_TEST_COMMANDS), so the header's #ifndef guards and the
    # module-struct macro must use the same case or every per-module override
    # (commands/handler/...) silently falls through to the NULL fallback.
    return token if token == "NULL" else f"APACHE_HTTPD_TEST_{token.upper()}"


def _ifndef_null(token: str) -> str:
    h = _define_name(token)
    return f"#ifndef {h}\n#define {h} NULL\n#endif\n"


def generate_header(dest: Path) -> None:
    """Write ``apache_httpd_test.h`` (cmodules_generate_include, Apache 2.x)."""
    parts: list[str] = [_HEADER_PRELUDE]
    # per-phase + per-config NULL fallbacks
    parts += [_ifndef_null(p) for p in _HOOK_PHASES]
    parts += [_ifndef_null(c) for c in _CONFIG_NAMES]
    # EXTRA_HOOKS fallback
    parts.append(
        "#ifndef APACHE_HTTPD_TEST_EXTRA_HOOKS\n"
        "#define APACHE_HTTPD_TEST_EXTRA_HOOKS(p) do { } while (0)\n"
        "#endif\n"
    )
    # APACHE_HTTPD_TEST_MODULE(name) macro (backslash-continued).
    config_hooks = ", ".join(_define_name(c) for c in _CONFIG_NAMES)
    hook_calls = "".join(
        f"    if ({_define_name(p)} != NULL) "
        f"ap_hook_{p}({_define_name(p)}, NULL, NULL, APACHE_HTTPD_TEST_HOOK_ORDER); "
        for p in _HOOK_PHASES
    )
    macro_body = (
        f"static void name ## _register_hooks(apr_pool_t *p) {{ "
        f"{hook_calls}APACHE_HTTPD_TEST_EXTRA_HOOKS(p); }} "
        f"module AP_MODULE_DECLARE_DATA name ## _module = {{ "
        f"STANDARD20_MODULE_STUFF, {config_hooks}, "
        f"name ## _register_hooks }}"
    )
    macro = "#define APACHE_HTTPD_TEST_MODULE(name) \\\n    " + macro_body + "\n"
    parts.append(macro)
    dest.write_text("\n".join(parts))


def _module_requirement(src: Path) -> str | None:
    m = _REQUIRE_RE.search(src.read_text(errors="replace"))
    return m.group(1) if m else None


def _meets_requirement(req: str, info: HttpdInfo) -> bool:
    """True if the running httpd satisfies a HTTPD_TEST_REQUIRE_APACHE value.

    A bare integer ("1"/"2") means "major version must equal"; a dotted value
    ("2.1", "2.4.49") means "version must be >=" (TestConfigC::cmodule_find).
    """
    if "." not in req:
        return info.version[0] == int(req)
    parts = tuple(int(x) for x in req.split("."))
    parts = parts + (0,) * (3 - len(parts))
    return info.version >= parts


def discover(cmodules_dir: Path, info: HttpdInfo) -> tuple[list[CModule], dict[str, str]]:
    """Find buildable modules; return (modules, {skipped_name: reason})."""
    mods: list[CModule] = []
    skipped: dict[str, str] = {}
    if not cmodules_dir.is_dir():
        return mods, skipped
    for sub in sorted(p for p in cmodules_dir.iterdir() if p.is_dir()):
        src = sub / f"mod_{sub.name}.c"
        if not src.is_file():
            continue
        req = _module_requirement(src)
        if req and not _meets_requirement(req, info):
            skipped[sub.name] = f"requires Apache {req}"
            continue
        mods.append(CModule(name=sub.name, src_dir=sub, src=src))
    return mods, skipped


def _apxs_cmd(apxs: Path, defines: list[str], include_dir: Path, src: Path) -> list[str]:
    # apxs is a Perl script; invoke via perl to sidestep exec-bit issues.
    # Mirrors: $(APXS) -D APACHE2 -D APACHE2_4 -I<cmodules_dir> -c mod_NAME.c
    cmd = ["perl", str(apxs)]
    for d in defines:
        cmd += ["-D", d]
    cmd += ["-I", str(include_dir), "-c", str(src)]
    return cmd


def compile_all(
    cmodules_dir: Path,
    apxs: Path,
    info: HttpdInfo,
    *,
    defines: list[str] | None = None,
    force: bool = False,
) -> tuple[list[tuple[str, Path]], dict[str, str]]:
    """Generate the header, build each eligible module, return load pairs + skips.

    :param defines: extra ``-D`` flags (default ``["APACHE2", "APACHE2_4"]``).
    :raises RuntimeError: if apxs fails for a module (captured output included).
    """
    defines = defines if defines is not None else ["APACHE2", "APACHE2_4"]
    generate_header(cmodules_dir / "apache_httpd_test.h")

    mods, skipped = discover(cmodules_dir, info)
    loads: list[tuple[str, Path]] = []
    for mod in mods:
        needs = force or not mod.so.exists() or (
            mod.so.stat().st_mtime < mod.src.stat().st_mtime
        )
        if needs:
            cmd = _apxs_cmd(apxs, defines, cmodules_dir, mod.src)
            proc = subprocess.run(  # noqa: S603 - trusted paths
                cmd, cwd=mod.src_dir, capture_output=True, text=True, check=False
            )
            if proc.returncode != 0 or not mod.so.exists():
                raise RuntimeError(
                    f"apxs failed building mod_{mod.name} (exit {proc.returncode}):\n"
                    f"$ {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}"
                )
        loads.append((mod.symbol, mod.so))
    return loads, skipped
