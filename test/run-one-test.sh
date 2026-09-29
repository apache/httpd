#!/bin/sh
#
# run-one-test.sh -- re-run a single test (file, directory or ::nodeid) via
# run-all-tests.sh, picking the right suite from the path.
#
# Usage:
#   ./run-one-test.sh PATH[::nodeid] [pytest args...]
#
# PATH may be given as printed in the run-all-tests.sh output, or as a real
# filesystem path from anywhere, e.g.:
#   ./run-one-test.sh tests/t/apache/test_404.py            # pytest_suite
#   ./run-one-test.sh tests/t/apache/test_404.py::test_x -v
#   ./run-one-test.sh modules/http2/test_003_get.py         # pyhttpd
#   ./run-one-test.sh test/modules/http2/test_003_get.py
#
set -eu

here="$(cd "$(dirname "$0")" && pwd)"

if [ $# -lt 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

arg="$1"; shift
file="${arg%%::*}"
node=""
[ "$file" != "$arg" ] && node="::${arg#*::}"

# Absolute path of an existing file or directory.
abspath() {
    d=$(cd "$(dirname "$1")" 2>/dev/null && pwd) || return 1
    echo "$d/$(basename "$1")"
}

# Try the path as given, then relative to each suite's root (how the test
# output prints them), then relative to the source tree root (test/...).
abs=""
for cand in "$file" "$here/pytest_suite/$file" "$here/$file" \
            "$(dirname "$here")/$file"; do
    if [ -e "$cand" ]; then abs=$(abspath "$cand"); break; fi
done
if [ -z "$abs" ]; then
    echo "run-one-test.sh: no such test path: $file" >&2
    exit 2
fi

case "$abs" in
    "$here/pytest_suite/"*)
        exec "$here/run-all-tests.sh" --only=pysuite "$@" \
            "${abs#"$here/pytest_suite/"}$node"
        ;;
    "$here/modules/"*)
        # pyhttpd paths are taken from PYHTTPD_TARGETS, relative to test/.
        PYHTTPD_TARGETS="${abs#"$here/"}$node"
        export PYHTTPD_TARGETS
        exec "$here/run-all-tests.sh" --only=pyhttpd "$@"
        ;;
    *)
        echo "run-one-test.sh: $abs is not under pytest_suite/ or modules/" >&2
        exit 2
        ;;
esac
