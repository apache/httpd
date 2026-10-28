#!/bin/sh
#
# runtests.sh -- run the Python test suites: modules/ (HTTP/2, mod_md, HTTP/1,
# proxy, core, ...) and pytest_suite/ (the classic Apache::Test port), in one
# pytest session against one built httpd.
#
# It makes sure the venv exists and is current (via uv), puts the venv's bin/
# first on PATH (CGI scripts forked by httpd must use the same Python and
# packages as pytest), fills in --apxs and --php-fpm when they can be found,
# and runs pytest from test/. Everything else goes straight to pytest.
#
# Usage:
#   ./runtests.sh                        # both suites, build found via APXS/config.ini/PATH
#   ./runtests.sh --apxs /path/to/apxs   # a specific build
#   ./runtests.sh modules                # only the modules/ suites
#   ./runtests.sh pytest_suite/tests     # only the classic suite
#   ./runtests.sh modules/http2 -k 003 -v
#   ./runtests.sh -m "not slow"          # markers and -k select across both
#
# A path relative to pytest_suite/ (tests/t/php, how the classic suite always
# printed them) is accepted as well.
#
# Environment (each used when the matching --flag is not given):
#   APXS     path to apxs      (default: the build of this tree, named by the
#                               configure-generated pyhttpd/config.ini or by
#                               PYHTTPD_CONFIG; without one, the first 'apxs'
#                               on PATH)
#   HTTPD    path to httpd     (when there is no apxs)
#   PHP_FPM  path to php-fpm   (default: first php-fpm on PATH; PHP tests skip if none)
#
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

# --- ensure the venv exists and is current ----------------------------------
# uv (https://docs.astral.sh/uv/) manages the dependencies: it reads
# pyproject.toml + uv.lock, the single source for both suites. We call
# .venv/bin/pytest directly rather than `uv run`, so this also works where
# `uv run` is shimmed or unavailable.
#
# Create .venv on first run, and rebuild it when pyproject.toml or uv.lock is
# newer than the venv (i.e. the dependencies changed).
PYTEST="$here/.venv/bin/pytest"
if [ ! -x "$PYTEST" ] || [ "$here/pyproject.toml" -nt "$here/.venv" ] \
        || [ "$here/uv.lock" -nt "$here/.venv" ]; then
    if ! command -v uv >/dev/null 2>&1; then
        echo "runtests.sh: ERROR: 'uv' is required but not installed." >&2
        echo "  Install it from https://docs.astral.sh/uv/ and re-run." >&2
        exit 1
    fi
    echo "runtests.sh: (re)creating $here/.venv via 'uv sync'..." >&2
    uv sync --project "$here"
    # Mark the venv as freshly built so the staleness check above won't
    # retrigger until pyproject.toml or uv.lock changes again.
    touch "$here/.venv"
fi

# CGI scripts forked by httpd resolve python3 to the venv's interpreter, and
# any shim wrappers earlier on PATH are shadowed.
export PATH="$here/.venv/bin:$PATH"

# --- discover apxs / php-fpm ---------------------------------------------------
discover() {
    # discover cmd1 cmd2 ...  -> echo the first one found on PATH
    for c in "$@"; do
        if command -v "$c" >/dev/null 2>&1; then command -v "$c"; return 0; fi
    done
    return 1
}

# A configured tree tests its own build: an apxs on PATH may well be another
# httpd (a distribution's), so it is only looked for when there is none.
config_ini="${PYHTTPD_CONFIG:-$here/pyhttpd/config.ini}"
if [ -z "${APXS:-}" ] && [ -z "${HTTPD:-}" ] && [ ! -f "$config_ini" ]; then
    APXS="$(discover apxs || true)"
fi
PHP_FPM="${PHP_FPM:-$(discover php-fpm php-fpm8.3 php-fpm83 php-fpm8.2 php-fpm82 || true)}"

# Arguments: a path that does not exist relative to test/ but does relative to
# pytest_suite/ is a classic-suite path. Everything else is passed on as is,
# the values of options included (`-k tests` must stay `-k tests`).
# (A ::nodeid suffix is not part of the path.)
have_server=0
have_php=0
for arg in "$@"; do
    case "$arg" in
        --apxs|--apxs=*|--httpd|--httpd=*) have_server=1 ;;
        --php-fpm|--php-fpm=*) have_php=1 ;;
    esac
done

# Build the argument list in "$@" form, so that spaces survive.
n=$#
while [ "$n" -gt 0 ]; do
    arg="$1"; shift; n=$((n - 1))
    case "$arg" in
        # `--apxs PATH` would make pytest take PATH for a test path and look
        # for conftest.py there instead of here, so join option and value.
        --apxs|--httpd|--conf|--php-fpm|--with-perl|--prefix)
            if [ "$n" -gt 0 ]; then arg="$arg=$1"; shift; n=$((n - 1)); fi ;;
        # options of pytest and of the suites that take a separate value:
        # pass the value on untouched
        -k|-m|-p|-o|-c|-W|-n|--tb|--deselect|--ignore|--ignore-glob|--rootdir|\
        --basetemp|--junitxml|--junit-xml|--maxfail|--durations|--log-level|\
        --log-file|--confcutdir|--import-mode|--color|--capture|--defines|\
        --php-fpm-port|--base-port|--classic-elog-report|--archive|--repeat)
            if [ "$n" -gt 0 ]; then
                set -- "$@" "$arg"; arg="$1"; shift; n=$((n - 1))
            fi ;;
        -*) ;;
        *)  p="${arg%%::*}"
            if [ ! -e "$p" ] && [ -e "pytest_suite/$p" ]; then
                arg="pytest_suite/$arg"
            fi
            ;;
    esac
    set -- "$@" "$arg"
done

if [ "$have_server" = 0 ]; then
    if [ -n "${APXS:-}" ]; then
        set -- "--apxs=$APXS" "$@"
    elif [ -n "${HTTPD:-}" ]; then
        set -- "--httpd=$HTTPD" "$@"
    elif [ -f "$config_ini" ]; then
        echo "runtests.sh: testing the build of $config_ini" >&2
    else
        # the framework self-tests need none; the suites fail and say why
        echo "runtests.sh: note: no httpd to test: no apxs on PATH and no" >&2
        echo "  $config_ini (configure the tree)." >&2
        echo "  Pass --apxs=/path/to/apxs, or set APXS=... or HTTPD=..." >&2
    fi
fi

if [ "$have_php" = 0 ]; then
    if [ -n "${PHP_FPM:-}" ]; then
        set -- "--php-fpm=$PHP_FPM" "$@"
    else
        echo "runtests.sh: note: no php-fpm found; PHP tests will skip." >&2
        echo "  Set PHP_FPM=/path/to/php-fpm (any version) to run them." >&2
    fi
fi

# A stale mod_cgid socket in the classic suite's t/logs can break a fresh run.
rm -f "$here"/pytest_suite/t/logs/cgisock* 2>/dev/null || true

echo "runtests.sh: $PYTEST $*" >&2
exec "$PYTEST" "$@"
