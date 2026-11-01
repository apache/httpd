#!/bin/sh
#
# Sanity-check the CI inputs: the GitHub Actions workflow files must
# parse as YAML, and the scripts those workflows run must pass a shell
# syntax check.  Neither is exercised by the build, so run this before
# pushing a change to either.

cd "`dirname "$0"`/.." || exit 1

rv=0

if python3 -c 'import yaml' 2>/dev/null; then
    for f in .github/workflows/*.yml; do
        if python3 -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' "$f"; then
            echo "PASS: $f"
        else
            echo "FAIL: $f"
            rv=1
        fi
    done
else
    echo "SKIP: .github/workflows/*.yml, python3 has no yaml module"
fi

for f in test/travis*.sh test/gha*.sh; do
    if bash -n "$f"; then
        echo "PASS: $f"
    else
        echo "FAIL: $f"
        rv=1
    fi
done

exit $rv
