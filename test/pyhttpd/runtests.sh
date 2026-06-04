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

PYTEST="$here/.venv/bin/pytest"
if [ ! -x "$PYTEST" ]; then
    if command -v uv >/dev/null 2>&1; then
        echo "runtests.sh: .venv not found; running 'uv sync' to create it..." >&2
        uv sync --project "$here"
    elif command -v python3 >/dev/null 2>&1; then
        echo "runtests.sh: .venv not found; creating with python3 + pip..." >&2
        python3 -m venv "$here/.venv"
         # Keep this list in sync with pyproject.toml [project].dependencies
         "$here/.venv/bin/pip" install --quiet \
             "pytest>=7.0" cryptography filelock "python-multipart" pyopenssl packaging websockets
    else
        echo "runtests.sh: ERROR: $PYTEST not found and neither 'uv' nor 'python3' is on PATH." >&2
        exit 1
    fi
fi

# Prepend the venv's bin dir so that CGI scripts forked by httpd also resolve
# python3 to the venv's interpreter (which has all packages installed), and so
# that any shim wrappers earlier on PATH are shadowed.
export PATH="$here/.venv/bin:$PATH"

targets="${PYHTTPD_TARGETS:-modules}"

# shellcheck disable=SC2086
echo "runtests.sh: $PYTEST $targets $*" >&2
exec "$PYTEST" $targets "$@"
