#!/bin/sh
#
# runtests.sh -- run the Apache httpd pytest suite.
#
# This is the self-contained Python/pytest port of the Apache httpd test suite.
# It needs a built Apache httpd (the server under test) located via apxs, and
# optionally a php-fpm binary to run the PHP tests.
#
# Usage:
#   ./runtests.sh                       # auto-detect apxs/httpd/php-fpm on PATH
#   ./runtests.sh --apxs /path/to/apxs  # point at a specific build
#   ./runtests.sh tests/t/modules       # run a subset (any pytest args pass through)
#   ./runtests.sh -k status -v          # extra pytest args pass through too
#
# Environment overrides (used when the matching --flag is not supplied):
#   APXS       path to apxs        (default: first 'apxs' on PATH)
#   HTTPD      path to httpd       (default: derived from apxs, i.e. apxs -q SBINDIR/httpd)
#   PHP_FPM    path to php-fpm     (default: first 'php-fpm'/'php-fpm8*'/'php-fpm83' on PATH; PHP tests skip if none)
#
# Examples:
#   APXS=$HOME/root/httpd/bin/apxs ./runtests.sh
#   PHP_FPM=/opt/local/sbin/php-fpm83 ./runtests.sh tests/t/php
#
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

# --- locate the virtualenv's pytest -----------------------------------------
# We invoke .venv/bin/pytest directly rather than `uv run` so the suite works
# even where `uv run` is shimmed/unavailable. Create the venv with `uv sync`
# (or `python -m venv .venv && .venv/bin/pip install -e .`) if it's missing.
PYTEST="$here/.venv/bin/pytest"
if [ ! -x "$PYTEST" ]; then
    if command -v uv >/dev/null 2>&1; then
        echo "runtests.sh: .venv not found; running 'uv sync' to create it..." >&2
        uv sync
    elif command -v python3 >/dev/null 2>&1; then
        echo "runtests.sh: .venv not found; creating it with python3 + pip..." >&2
        python3 -m venv .venv
        .venv/bin/pip install --quiet -e .
    else
        echo "runtests.sh: ERROR: $PYTEST not found and neither 'uv' nor 'python3' is installed." >&2
        exit 1
    fi
fi

# --- discover apxs / httpd / php-fpm ----------------------------------------
# Any of these may be overridden by passing the matching --flag through to
# pytest (those take precedence); here we only fill in defaults via env/PATH.
discover() {
    # discover VAR cmd1 cmd2 ...  -> echo first one found on PATH
    shift
    for c in "$@"; do
        if command -v "$c" >/dev/null 2>&1; then command -v "$c"; return 0; fi
    done
    return 1
}

APXS="${APXS:-$(discover APXS apxs || true)}"
PHP_FPM="${PHP_FPM:-$(discover PHP_FPM php-fpm php-fpm8.3 php-fpm83 php-fpm8.2 php-fpm82 || true)}"

# Build the default flag set only for values the user did not pass explicitly.
auto_args=""
case " $* " in
    *" --apxs"*|*" --httpd"*) : ;;  # user specified a server; don't auto-add
    *)
        if [ -n "${APXS:-}" ]; then
            auto_args="--apxs=$APXS"
        elif [ -n "${HTTPD:-}" ]; then
            auto_args="--httpd=$HTTPD"
        else
            echo "runtests.sh: ERROR: no apxs/httpd found." >&2
            echo "  Pass --apxs=/path/to/apxs, or set APXS=... or HTTPD=..." >&2
            exit 1
        fi
        ;;
esac

case " $* " in
    *" --php-fpm"*) : ;;            # user specified php-fpm; don't auto-add
    *)
        if [ -n "${PHP_FPM:-}" ]; then
            auto_args="$auto_args --php-fpm=$PHP_FPM"
        else
            echo "runtests.sh: note: no php-fpm found; PHP tests will skip." >&2
            echo "  Set PHP_FPM=/path/to/php-fpm (any version) to run them." >&2
        fi
        ;;
esac

# A stale mod_cgid socket in t/logs can break a fresh run; clear it first.
rm -f "$here/t/logs/cgisock"* 2>/dev/null || true

# --- run --------------------------------------------------------------------
# shellcheck disable=SC2086  # auto_args is an intentional word-split flag list
echo "runtests.sh: $PYTEST $auto_args $*" >&2
exec "$PYTEST" $auto_args "$@"
