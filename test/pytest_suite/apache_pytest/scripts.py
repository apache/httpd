"""Generate helper scripts from ``*.PL`` templates.

The suite ships ``*.PL`` files (CGI scripts, rewrite-map programs, passphrase
helpers) that the httpd config references by their generated name (``foo.pl``
from ``foo.pl.PL``). Apache::TestMM::generate_script / write_perlscript produce
these by prepending a perl shebang and marking the file executable.

Only the bare ``write_perlscript`` behavior is needed for the htdocs/conf
helpers (no ``$Apache::TestConfig::Argv`` injection — that is specific to the
top-level t/TEST runner, which the pytest framework replaces).
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

# Match make_shebang(): a short perlpath gets a plain shebang.
PERL = os.environ.get("APACHE_TEST_PERL", "/usr/bin/perl")


def _shebang() -> str:
    perl = PERL
    if len(perl) < 62:
        return f"#!{perl}\n"
    # Long-path eval workaround (rare); mirrors the $Config{startperl} fallback.
    return (
        "#!/bin/sh\n"
        f"    eval 'exec {perl} -S $0 ${{1+\"$@\"}}'\n"
        "        if $running_under_some_shell;\n"
    )


def generate_pl_scripts(root: Path, *, perl: str | None = None) -> list[Path]:
    """For every ``*.PL`` under ``root``, write the generated script executable.

    ``foo.pl.PL`` -> ``foo.pl`` (shebang + body, mode 0755). Returns the list of
    generated paths. Skips emacs lock files (``.#name``), matching the finddepth
    filter used in Makefile.PL.
    """
    global PERL  # noqa: PLW0603 - simple module-level default override
    if perl:
        PERL = perl
    generated: list[Path] = []
    for pl in sorted(root.rglob("*.PL")):
        if pl.name.startswith(".#"):
            continue
        target = pl.with_suffix("")  # strip ".PL" -> "...pl"
        body = pl.read_text()
        target.write_text(_shebang() + body, newline="\n")
        target.chmod(target.stat().st_mode | stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
        generated.append(target)
    return generated


def default_perl() -> str:
    """Best-effort path to a perl interpreter for the generated shebangs."""
    from shutil import which

    path = PERL or which("perl") or sys.executable
    return path.replace("\\", "/")
