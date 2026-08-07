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

# --- ensure the venv exists and is current ----------------------------------
# The suite baselines on uv (https://docs.astral.sh/uv/) as its dependency and
# venv manager: it reads pyproject.toml + uv.lock, so there is a single source
# of truth for dependencies. We invoke .venv/bin/pytest directly rather than
# `uv run` so the suite works even where `uv run` is shimmed/unavailable.
#
# Create $here/.venv on first run, and rebuild it when pyproject.toml is newer
# than the venv (i.e. dependencies changed). Absolute paths throughout, so this
# behaves identically regardless of the caller's cwd. This block is kept
# byte-for-byte identical in pytest_suite/runtests.sh and pyhttpd/runtests.sh
# -- edit both together.
PYTEST="$here/.venv/bin/pytest"
if [ ! -x "$PYTEST" ] || [ "$here/pyproject.toml" -nt "$here/.venv" ]; then
    if ! command -v uv >/dev/null 2>&1; then
        echo "runtests.sh: ERROR: 'uv' is required but not installed." >&2
        echo "  Install it from https://docs.astral.sh/uv/ and re-run." >&2
        exit 1
    fi
    echo "runtests.sh: (re)creating $here/.venv via 'uv sync'..." >&2
    uv sync --project "$here"
    # Mark the venv as freshly built so the staleness check above won't retrigger
    # until pyproject.toml changes again.
    touch "$here/.venv"
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
echo "runtests.sh: $PYTEST $auto_args $*" >&2
# shellcheck disable=SC2086  # auto_args is an intentional word-split flag list
exec "$PYTEST" $auto_args "$@"
