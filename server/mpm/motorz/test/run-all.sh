#!/bin/sh
#
# Run the full motorz MPM test suite (HTTP/1.1 + HTTP/2). Exits non-zero if
# any sub-suite reports a failure. The HTTP/2 suite self-skips (exit 0) when
# ssl/http2/openssl/h2-curl are unavailable.
#
# Usage: server/mpm/motorz/test/run-all.sh

here="$(dirname "$0")"
rc=0

sh "$here/smoke.sh" || rc=1
echo
sh "$here/run-http1.sh" || rc=1
echo
sh "$here/run-http2.sh" || rc=1

echo
if [ "$rc" -eq 0 ]; then
    echo "######## motorz: ALL SUITES PASSED ########"
else
    echo "######## motorz: FAILURES PRESENT ########"
fi
exit $rc
