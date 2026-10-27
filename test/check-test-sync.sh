#!/bin/sh
# Fail if test/ differs between trunk and 2.4.x.
#
# usage: check-test-sync.sh [trunk-ref [2.4.x-ref]]
#
# Run from anywhere in a git checkout of apache/httpd that has both refs;
# they default to origin/trunk and origin/2.4.x.  The comparison is of the
# committed trees, so uncommitted changes do not count.
set -e

a=${1:-origin/trunk}
b=${2:-origin/2.4.x}

for ref in "$a" "$b"; do
    if ! git rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then
        echo "check-test-sync: no such ref: $ref" >&2
        exit 2
    fi
done

top=$(git rev-parse --show-toplevel)
if git -C "$top" diff --quiet "$a" "$b" -- test; then
    echo "test/ is identical on $a and $b"
else
    echo "test/ differs between $a and $b:" >&2
    git -C "$top" diff --stat "$a" "$b" -- test >&2
    exit 1
fi
