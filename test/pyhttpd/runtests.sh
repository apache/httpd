#!/bin/sh
#
# runtests.sh -- run the pyhttpd modules/ test suite.
#
# Manages a local .venv under pyhttpd/ so that pytest and the CGI helper scripts
# (which httpd forks) both use the same Python with all required packages
# (cryptography, python-multipart, websockets, etc.) available.
#
# Usage:
#    ./runtests.sh                    # run all modules/ tests
#    ./runtests.sh modules/http1      # run a specific suite
#    ./runtests.sh -k post -v         # any pytest args pass through
#
# Environment:
#   PYHTTPD_TARGETS  space-separated list of test paths (default: modules)
#
set -eu

here="$(cd "$(dirname "$0")" && pwd)"

# --- ensure the venv exists and is current ----------------------------------
# We invoke .venv/bin/pytest directly rather than `uv run` so the suite works
# even where `uv run` is shimmed/unavailable.
#
# Create $here/.venv on first run, and rebuild it when pyproject.toml is newer
# than the venv (i.e. dependencies changed). Prefer uv (which reads
# pyproject.toml + uv.lock); otherwise fall back to python3 -m venv + pip,
# taking the dependency list straight from pyproject.toml so there is no second
# copy to keep in sync. Absolute paths throughout, so this behaves identically
# regardless of the caller's cwd. This block is kept byte-for-byte identical in
# pytest_suite/runtests.sh and pyhttpd/runtests.sh -- edit both together.
PYTEST="$here/.venv/bin/pytest"
if [ ! -x "$PYTEST" ] || [ "$here/pyproject.toml" -nt "$here/.venv" ]; then
    if command -v uv >/dev/null 2>&1; then
        echo "runtests.sh: (re)creating $here/.venv via 'uv sync'..." >&2
        uv sync --project "$here"
    elif command -v python3 >/dev/null 2>&1; then
        echo "runtests.sh: (re)creating $here/.venv via python3 + pip..." >&2
        python3 -m venv "$here/.venv"
        # Read [project].dependencies from pyproject.toml (one entry per line,
        # double-quoted) so the install list never drifts from the manifest.
        deps=$(awk -F'"' '/^dependencies = \[/{f=1; next} f && /^\]/{f=0} f && NF>=2 {print $2}' "$here/pyproject.toml")
        # shellcheck disable=SC2086  # deps is an intentional word-split list
        "$here/.venv/bin/pip" install --quiet $deps
    else
        echo "runtests.sh: ERROR: $PYTEST not found and neither 'uv' nor 'python3' is installed." >&2
        exit 1
    fi
    # Mark the venv as freshly built so the staleness check above won't retrigger
    # until pyproject.toml changes again.
    touch "$here/.venv"
fi

# Prepend the venv's bin dir so that CGI scripts forked by httpd also resolve
# python3 to the venv's interpreter (which has all packages installed), and so
# that any shim wrappers earlier on PATH are shadowed.
export PATH="$here/.venv/bin:$PATH"

# The modules/ test suite lives in test/, a sibling of this script's directory
# (test/pyhttpd/) -- cd there so both the default target and any
# PYHTTPD_TARGETS/positional path the caller supplies resolve the same way
# regardless of where runtests.sh was invoked from.
cd "$(dirname "$here")"

# Only fall back to the "modules" default when the caller gave no positional
# test path of their own -- otherwise it would always tag along after theirs
# (`pytest modules modules/http1`), silently widening any subset selection
# back out to the full suite. A positional path is recognized by actually
# existing on disk (relative to test/, our cwd at this point) -- this avoids
# both having to enumerate every pytest flag that takes a separate-word value
# (-k, -m, -p, --tb, --maxfail, -n from pytest-xdist, ...) and misdetecting a
# -k/-m expression that happens to contain '/' (this suite's own parametrize
# IDs look like "/006/006.css", so "-k 006/006" is a realistic selector, and
# it does not exist as a path).
have_path=0
for arg in "$@"; do
    case "$arg" in
        -*) ;;
        # Strip a trailing ::nodeid (pytest's file::Class::test node-selector
        # syntax) before checking existence -- only the file/dir part is real.
        *) [ -e "${arg%%::*}" ] && have_path=1 ;;
    esac
done

if [ -n "${PYHTTPD_TARGETS:-}" ]; then
    targets="$PYHTTPD_TARGETS"
elif [ "$have_path" = 1 ]; then
    targets=""
else
    targets="modules"
fi

echo "runtests.sh: $PYTEST $targets $*" >&2
# shellcheck disable=SC2086  # $targets is an intentional word-split path list
exec "$PYTEST" $targets "$@"
