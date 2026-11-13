#!/bin/sh
#
# setup.sh -- configure and build httpd so the motorz MPM test suite can run.
#
# The motorz tests (smoke.sh / run-http1.sh / run-http2.sh / run-all.sh, and the
# bench.sh comparison) drive a real httpd built from THIS tree against a
# throwaway config. They need:
#   - the motorz MPM, built as a shared module (mod_mpm_motorz.so)
#   - the event MPM too (bench.sh compares against it)
#   - these shared modules: unixd, authz_core, authz_host, log_config, mime,
#     dir, and -- for the HTTP/2 suite -- socache_shmcb, ssl, http2
#   - bundled APR/APR-Util (--with-included-apr), so no system APR is required
#
# This script runs buildconf (only if ./configure is missing), ./configure with
# the right flags, and make. It is idempotent: re-running reconfigures + rebuilds.
#
# Usage (from anywhere):
#   server/mpm/motorz/test/setup.sh                 # configure (if needed) + build
#   server/mpm/motorz/test/setup.sh --reconfigure   # force re-run ./configure
#   server/mpm/motorz/test/setup.sh --jobs N         # parallel make (default: CPUs)
#
# After it succeeds:
#   server/mpm/motorz/test/run-all.sh                # run the test suite
#
# It does NOT install httpd; the tests run the freshly built ./httpd in place.

set -u

# --- locate the build tree (this script lives in <top>/server/mpm/motorz/test) -
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
TOP="$(cd "$SELF_DIR/../../../.." && pwd)"
cd "$TOP" || { echo "ERROR: cannot cd to build top $TOP" >&2; exit 1; }

RECONFIGURE=0
JOBS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --reconfigure) RECONFIGURE=1 ;;
        --jobs) shift; JOBS="$1" ;;
        --jobs=*) JOBS="${1#--jobs=}" ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^#//;s/^ //'; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$JOBS" ]; then
    JOBS="$( (command -v nproc >/dev/null && nproc) \
             || sysctl -n hw.ncpu 2>/dev/null || echo 2 )"
fi

say()  { printf '\n==== %s ====\n' "$*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- 1. prerequisites -------------------------------------------------------
say "checking prerequisites"
have make || die "make not found"
have cc || have gcc || have clang || die "no C compiler (cc/gcc/clang) found"
echo "  compiler: $(command -v cc gcc clang 2>/dev/null | head -1)"
echo "  make:     $(command -v make)"

# buildconf (regenerates ./configure) is only needed for a fresh git checkout.
if [ ! -x "$TOP/configure" ]; then
    say "no ./configure -- running buildconf (fresh checkout)"
    have autoconf   || die "autoconf required to run buildconf (install autoconf)"
    have python3    || die "python3 required by buildconf"
    # buildconf wants libtoolize OR glibtoolize (macOS names it glibtoolize)
    if ! have libtoolize && ! have glibtoolize; then
        die "libtoolize/glibtoolize required by buildconf (install libtool)"
    fi
    [ -d "$TOP/srclib/apr" ] || die "srclib/apr missing: fetch bundled APR \
(svn co/ git submodule) or use a release tarball that includes it"
    "$TOP/buildconf" || die "buildconf failed"
fi

# --- 2. configure -----------------------------------------------------------
# Enable motorz AND event as shared MPMs, and explicitly enable the modules the
# tests load (rather than relying on the 'most' default), plus bundled APR.
CONFIGURE_ARGS='--with-included-apr
--enable-mpms-shared=event motorz
--enable-so
--enable-unixd
--enable-authz_core
--enable-authz_host
--enable-log_config
--enable-mime
--enable-dir
--enable-socache_shmcb
--enable-ssl
--enable-http2'

if [ "$RECONFIGURE" -eq 1 ] || [ ! -f "$TOP/config.status" ]; then
    say "configuring"
    # shellcheck disable=SC2086  # intentional word-splitting of the arg list
    set -f; IFS='
'; set -- $CONFIGURE_ARGS; unset IFS; set +f
    echo "  ./configure $*"
    "$TOP/configure" "$@" || die "./configure failed (see config.log). If mod_ssl \
or mod_http2 failed, install their dev libs: OpenSSL headers and libnghttp2."
else
    echo "  config.status present; skipping ./configure (use --reconfigure to force)"
fi

# --- 3. build ---------------------------------------------------------------
say "building (make -j$JOBS)"
make "-j$JOBS" || die "make failed"

# --- 4. verify the bits the tests need --------------------------------------
say "verifying build outputs"
rc=0
[ -x "$TOP/httpd" ] && echo "  httpd binary: ok" || { echo "  httpd binary: MISSING"; rc=1; }

check_mod() {
    if find "$TOP/modules" "$TOP/server/mpm" -name "$1" -path '*/.libs/*' 2>/dev/null \
         | grep -q .; then
        echo "  $1: ok"
    else
        echo "  $1: MISSING${2:+  ($2)}"
        [ -n "${3:-}" ] && rc=1   # required modules fail the verify; optional just warn
    fi
}
# required for the HTTP/1.1 suite + smoke
check_mod mod_mpm_motorz.so "" required
check_mod mod_unixd.so "" required
check_mod mod_authz_core.so "" required
check_mod mod_authz_host.so "" required
check_mod mod_log_config.so "" required
check_mod mod_mime.so "" required
check_mod mod_dir.so "" required
# needed by bench.sh (event comparison)
check_mod mod_mpm_event.so "bench.sh needs this"
# needed by the HTTP/2 suite (otherwise it self-skips)
check_mod mod_socache_shmcb.so "HTTP/2 suite will skip without it"
check_mod mod_ssl.so "HTTP/2 suite will skip without it"
check_mod mod_http2.so "HTTP/2 suite will skip without it"

# --- 5. external tools used by the tests ------------------------------------
say "external test tools (not built here)"
for t in openssl curl ab h2load nghttp; do
    if have "$t"; then echo "  $t: $(command -v $t)"; else echo "  $t: not found"; fi
done
have openssl || echo "  NOTE: openssl CLI absent -> HTTP/2 suite self-skips"
if have curl && ! curl -V 2>/dev/null | grep -qi http2; then
    echo "  NOTE: curl lacks HTTP/2 -> HTTP/2 suite self-skips"
fi
have h2load || echo "  NOTE: h2load (nghttp2) absent -> h2load load tests skip"
have ab     || echo "  NOTE: ab (apache2-utils) absent -> HTTP/1.1 uses curl fallback"

# --- done -------------------------------------------------------------------
echo
if [ "$rc" -eq 0 ]; then
    echo "######## setup OK -- now run: server/mpm/motorz/test/run-all.sh ########"
else
    echo "######## setup INCOMPLETE -- a REQUIRED module is missing (see above) ########"
fi
exit $rc
