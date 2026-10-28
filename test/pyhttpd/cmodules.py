"""Build the C modules the tests load, with apxs.

Both suites carry small modules that are not part of httpd: mod_aptest,
mod_h1test and mod_h2test of the modules/ suite, and the c-modules/ of
pytest_suite. They are built in place, ``mod_x.c`` in a directory of its own
giving ``.libs/mod_x.so``, and built once: next to the result goes a stamp
recording what the build depended on, and a module is rebuilt when

* the .so is missing,
* a source or header of the module changed,
* the httpd it is built against changed: another apxs, or the same apxs after
  the httpd it belongs to was rebuilt with another module magic number or
  version (a module built for 2.4 is refused by 2.5 with "expected signature
  41503234 but saw 41503235"), or
* the defines or include directories differ.

``--clean-modules`` removes the results, see clean_module_dir().
"""

import hashlib
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Union

log = logging.getLogger(__name__)

LIB_SUBDIR = ".libs"      # where apxs/libtool leave the result

_include_fingerprints: Dict[str, str] = {}


def _sha256_files(paths: Iterable[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.name.encode())
        try:
            h.update(p.read_bytes())
        except OSError:
            h.update(b"<missing>")
    return h.hexdigest()


def _apxs_command(apxs: Union[str, Path]) -> List[str]:
    # apxs is a script; run it directly when it can be, as its shebang names
    # the perl it was built for, else through the perl on the PATH.
    apxs = str(apxs)
    return [apxs] if os.access(apxs, os.X_OK) else ["perl", apxs]


def apxs_query(apxs: Union[str, Path], var: str) -> str:
    proc = subprocess.run([*_apxs_command(apxs), "-q", var],
                          capture_output=True, text=True, check=True)
    return proc.stdout.strip()


def httpd_fingerprint(apxs: Union[str, Path]) -> str:
    """Identifies the httpd that modules built with *apxs* are made for."""
    key = os.path.realpath(str(apxs))
    if key not in _include_fingerprints:
        try:
            include_dir = Path(apxs_query(apxs, "INCLUDEDIR"))
            sha = _sha256_files([include_dir / "ap_mmn.h",
                                 include_dir / "ap_release.h"])
        except (OSError, subprocess.CalledProcessError):
            sha = "unknown"
        _include_fingerprints[key] = f"{key}:{sha}"
    return _include_fingerprints[key]


def module_so(src_dir: Union[str, Path], name: str) -> Path:
    return Path(src_dir) / LIB_SUBDIR / f"mod_{name}.so"


def _stamp_data(src_dir: Path, apxs, defines: Sequence[str],
                include_dirs: Sequence[Path], extra_inputs: Sequence[Path]) -> dict:
    sources = [p for p in src_dir.iterdir()
               if p.is_file() and p.suffix in (".c", ".h")]
    return {
        "httpd": httpd_fingerprint(apxs),
        "sources": _sha256_files(sources),
        "extra": _sha256_files(extra_inputs),
        "defines": list(defines),
        "includes": [str(p) for p in include_dirs],
    }


def ensure_built(src_dir: Union[str, Path], name: str, apxs: Union[str, Path], *,
                 defines: Sequence[str] = (),
                 include_dirs: Sequence[Union[str, Path]] = (),
                 extra_inputs: Sequence[Union[str, Path]] = (),
                 force: bool = False) -> Path:
    """Build ``mod_<name>.c`` in *src_dir* unless the result is up to date.

    :param defines: ``-D`` flags for the compile
    :param include_dirs: ``-I`` directories
    :param extra_inputs: further files the result depends on, e.g. a generated
        header in one of *include_dirs*
    :returns: the path of the .so
    :raises RuntimeError: if apxs fails, with its output
    """
    src_dir = Path(src_dir)
    so = module_so(src_dir, name)
    stamp_file = so.with_suffix(".stamp")
    include_dirs = [Path(p) for p in include_dirs]
    stamp = _stamp_data(src_dir, apxs, defines, include_dirs,
                        [Path(p) for p in extra_inputs])
    if not force and so.is_file() and stamp_file.is_file():
        try:
            if json.loads(stamp_file.read_text()) == stamp:
                return so
        except (OSError, ValueError):
            pass
    cmd = _apxs_command(apxs)
    for d in defines:
        cmd += ["-D", d]
    for d in include_dirs:
        cmd += ["-I", str(d)]
    cmd += ["-c", f"mod_{name}.c"]
    log.debug("building mod_%s: %s", name, cmd)
    stamp_file.unlink(missing_ok=True)
    proc = subprocess.run(cmd, cwd=src_dir, capture_output=True, text=True,
                          check=False)
    if proc.returncode != 0 or not so.is_file():
        raise RuntimeError(
            f"apxs failed building mod_{name} (exit {proc.returncode}):\n"
            f"$ {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}")
    stamp_file.write_text(json.dumps(stamp, indent=1))
    return so


def clean_module_dir(src_dir: Union[str, Path]) -> None:
    """Remove the build results of the module in *src_dir*, like ``make clean``:
    the ``.libs`` directory and libtool's intermediates."""
    src_dir = Path(src_dir)
    libs = src_dir / LIB_SUBDIR
    if libs.is_dir():
        shutil.rmtree(libs)
    for pattern in ("*.o", "*.lo", "*.slo", "*.la"):
        for f in src_dir.glob(pattern):
            f.unlink(missing_ok=True)


def clean_test_modules(test_dir: Union[str, Path]) -> None:
    """Clean every module of the modules/ suite under test/: mod_aptest of the
    framework, and the mod_* directories next to the tests."""
    test_dir = Path(test_dir)
    for pattern in ("pyhttpd/mod_*", "modules/*/mod_*"):
        for d in test_dir.glob(pattern):
            if d.is_dir() and any(d.glob("mod_*.c")):
                clean_module_dir(d)
