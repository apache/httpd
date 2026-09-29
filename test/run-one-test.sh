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
# With no arguments, lists all test files (one PATH per line) for grepping;
# with -l, lists every individual test (PATH::nodeid) instead:
#   ./run-one-test.sh | grep -i status
#   ./run-one-test.sh -l | grep -i status
#
set -eu

here="$(cd "$(dirname "$0")" && pwd)"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

# No arguments: list every test file as a PATH accepted above; -l: list every
# test as PATH::nodeid. This is a static scan (no pytest collection, so no
# built httpd needed); parametrized tests are listed once, without their
# [param] suffix.
if [ $# -eq 0 ] || { [ $# -eq 1 ] && [ "$1" = "-l" ]; }; then
    cd "$here"
    exec python3 - "${1:-}" pytest_suite modules <<'EOF'
import ast, os, sys, warnings
warnings.simplefilter("ignore", SyntaxWarning)

def tests(body, prefix):
    for n in body:
        if isinstance(n, ast.ClassDef) and n.name.startswith("Test"):
            yield from tests(n.body, prefix + n.name + "::")
        elif (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name.startswith("test")):
            yield prefix + n.name

per_test = sys.argv[1] == "-l"
for root in sys.argv[2:]:
    paths = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if not x.startswith((".", "__"))]
        paths += [os.path.join(d, f) for f in files
                  if f.startswith("test_") and f.endswith(".py")]
    for p in sorted(paths):
        rel = os.path.relpath(p, root) if root == "pytest_suite" else p
        if not per_test:
            print(rel)
            continue
        try:
            with open(p) as f:
                tree = ast.parse(f.read(), p)
        except (OSError, SyntaxError) as e:
            print(f"run-one-test.sh: skipping {p}: {e}", file=sys.stderr)
            continue
        for t in tests(tree.body, rel + "::"):
            print(t)
EOF
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
