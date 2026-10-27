#!/bin/sh
#
# Check the XML sources of the manual: every file must be well-formed,
# and every file with a DOCTYPE must be valid against its DTD.  Pass
# file names to check only those, otherwise all of docs/ is checked.
#
# The DTDs pull in the XHTML entity sets by public identifier, so these
# must be resolvable from an XML catalog (on Debian/Ubuntu, install
# w3c-sgml-lib; on Fedora, xhtml1-dtds, or point XML_CATALOG_FILES at
# a catalog); nothing is fetched from the network.

cd "`dirname "$0"`/.." || exit 1

if ! command -v xmllint >/dev/null; then
    echo "FAIL: xmllint not found"
    exit 1
fi

if [ $# -eq 0 ]; then
    set -- `find docs -name '*.xml' -o -name '*.xml.*' | sort`
fi

rv=0
count=0

for f in "$@"; do
    count=$((count + 1))
    # The language files use lang.dtd only to define entities, and
    # declare no elements, so can only be checked for well-formedness.
    if grep -q '<!DOCTYPE' "$f" && ! grep -q '<!DOCTYPE language ' "$f"; then
        mode=--valid
    else
        mode=--loaddtd
    fi
    # An unresolvable entity set is only a warning; treat it as fatal.
    if ! out=`xmllint --noout --nonet $mode "$f" 2>&1` \
       || echo "$out" | grep -q 'failed to load external entity'; then
        echo "$out"
        echo "FAIL: $f"
        rv=1
    fi
done

[ $rv -eq 0 ] && echo "PASS: $count files checked"

exit $rv
