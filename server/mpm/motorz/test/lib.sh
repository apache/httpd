# Shared helpers for the motorz MPM test harness.
#
# Sourced by run-http1.sh and run-http2.sh. Not executable on its own.
#
# Resolves the httpd build tree, locates the shared MPM/module .so files,
# generates a throwaway ServerRoot under a temp dir, and provides start/stop
# plus a tiny assertion API. Everything lives under a per-run temp dir that is
# removed on exit unless KEEP=1 is set in the environment.

set -u

# --- locate the build tree -------------------------------------------------
# This script lives in <builddir>/server/mpm/motorz/test/. The top of the
# build tree is four levels up.
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOP="$(cd "$TEST_DIR/../../../.." && pwd)"

HTTPD="$TOP/httpd"
PORT="${PORT:-8099}"        # http1 default; http2 suite overrides to 8443
TLS_PORT="${TLS_PORT:-8443}"

PASS=0
FAIL=0
RUNDIR=""

fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }
pass() { echo "  ok:   $*"; PASS=$((PASS + 1)); }

# assert_eq <expected> <actual> <label>
assert_eq() {
    if [ "$1" = "$2" ]; then pass "$3 ($2)"; else fail "$3: expected '$1', got '$2'"; fi
}

# assert_gt <actual> <floor> <label> -- passes when actual > floor (integers)
assert_gt() {
    if [ "$1" -gt "$2" ] 2>/dev/null; then pass "$3 ($1 > $2)";
    else fail "$3: expected > '$2', got '$1'"; fi
}

# Locate a built shared module by basename, searching the usual subtrees.
# Aborts the run if not found (the suite cannot proceed without it).
find_so() {
    local name="$1" hit
    hit="$(find "$TOP/modules" "$TOP/server/mpm" -name "$name" -path '*/.libs/*' 2>/dev/null | head -1)"
    if [ -z "$hit" ]; then
        echo "ERROR: required module '$name' not built under $TOP" >&2
        echo "       (re)build with: ./configure --enable-mpms-shared='event motorz' && make" >&2
        exit 2
    fi
    printf '%s' "$hit"
}

# LoadModule <directive-name> <so-basename> -> emits a LoadModule line
load() { printf 'LoadModule %s %s\n' "$1" "$(find_so "$2")"; }

require_httpd() {
    if [ ! -x "$HTTPD" ]; then
        echo "ERROR: httpd binary not found/executable at $HTTPD" >&2
        echo "       build it first: make" >&2
        exit 2
    fi
}

# Create the per-run ServerRoot. Sets $RUNDIR.
make_rundir() {
    RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/motorz-test.XXXXXX")"
    mkdir -p "$RUNDIR/htdocs" "$RUNDIR/logs"
    printf 'hello-motorz\n' > "$RUNDIR/htdocs/index.html"
    # ~200KB body to force multi-frame / write-completion cycling
    head -c 200000 /dev/zero | tr '\0' 'A' > "$RUNDIR/htdocs/big.txt"
}

start_httpd() {
    "$HTTPD" -f "$RUNDIR/httpd.conf" -k start
    local rc=$?
    [ $rc -eq 0 ] || { echo "ERROR: httpd failed to start (rc=$rc)" >&2; tail -20 "$RUNDIR/logs/error_log" 2>/dev/null >&2; exit 3; }
    # wait for the listener
    local i
    for i in $(seq 1 20); do
        if lsof -iTCP -sTCP:LISTEN -a -p "$(cat "$RUNDIR/httpd.pid" 2>/dev/null || echo 0)" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.3
    done
    return 0
}

graceful() { "$HTTPD" -f "$RUNDIR/httpd.conf" -k graceful 2>/dev/null; sleep 1; }

# Switch the running server's log level and gracefully restart. Rewrites the
# LogLevel line that immediately follows a "# @LOGLEVEL@" marker comment in
# httpd.conf (httpd does not accept inline trailing comments, so the marker
# lives on its own line above the directive). Used to keep heavy load phases at
# a quiet level (so the trace8 error_log does not balloon to gigabytes) while
# still capturing state traces for the light trace phase.
# $1 = new LogLevel argument (e.g. "info" or "trace8").
set_loglevel() {
    local lvl="$1"
    awk -v L="$lvl" '
        prev ~ /# @LOGLEVEL@$/ { print "LogLevel " L; prev=""; next }
        { print; prev=$0 }
    ' "$RUNDIR/httpd.conf" > "$RUNDIR/httpd.conf.new" \
        && mv "$RUNDIR/httpd.conf.new" "$RUNDIR/httpd.conf"
    graceful
}

stop_httpd() {
    [ -n "$RUNDIR" ] && [ -f "$RUNDIR/httpd.conf" ] && "$HTTPD" -f "$RUNDIR/httpd.conf" -k stop 2>/dev/null
    # bounded wait for the parent to exit
    local pid i
    pid="$(cat "$RUNDIR/httpd.pid" 2>/dev/null || true)"
    [ -n "$pid" ] || return 0
    for i in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.3; done
}

# Drive the CONN_STATE_ASYNC_WAITIO path: open an h2 connection, send only the
# HTTP/2 preface + an empty SETTINGS frame (no request -> emitted_count==0 ->
# mod_http2 returns CONN_STATE_ASYNC_WAITIO), pause (server arms WAITIO), send
# another empty SETTINGS to wake the socket (forcing the waitio->processing
# re-dispatch), then we kill the client.  $1 = TLS port.
#
# IMPORTANT: the feeder is piped DIRECTLY into openssl so `$!` is openssl's own
# PID -- we kill that exact process. (Wrapping the pipe in an extra subshell
# would make `$!` the subshell and leave openssl running, blocked reading from
# a connection the server legitimately parks in ASYNC_WAITIO for the whole
# Timeout -- which previously hung the suite.) The feeder subshell on the left
# self-terminates: once openssl dies its next write gets SIGPIPE, and its last
# action is a bounded sleep regardless.
trigger_async_waitio() {
    local port="$1" pf i
    pf='PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\000\000\000\004\000\000\000\000\000'
    { printf "$pf"; sleep 2; printf '\000\000\000\004\000\000\000\000\000'; sleep 1; } \
        | openssl s_client -connect localhost:"$port" -alpn h2 -quiet >/dev/null 2>&1 &
    local op=$!   # PID of openssl (right-most command in the pipe)
    # Bounded wait for the feed to play out, then kill openssl directly.
    for i in $(seq 1 10); do
        kill -0 "$op" 2>/dev/null || break
        sleep 0.5
    done
    kill "$op" 2>/dev/null
    wait "$op" 2>/dev/null
    return 0
}

# Parse one statistic out of h2load's summary output.
#   h2load_stat "<h2load output>" "<key regex>"
# e.g. h2load_stat "$out" 'requests:'  -> "1000 total, 1000 started, ..."
# Returns the matching line (caller extracts the field).
h2load_stat() { printf '%s\n' "$1" | grep -E "$2" | head -1; }

# Fail the run if the error log shows anything alarming.
scan_log_clean() {
    local bad
    bad="$(grep -iE 'segfault|crash|core dump|exit signal|\[crit\]|\[emerg\]|assert|deadlock' \
           "$RUNDIR/logs/error_log" 2>/dev/null | grep -v 'resuming normal' || true)"
    if [ -n "$bad" ]; then
        fail "error log contains alarming entries:"
        echo "$bad" | sed 's/^/      /'
    else
        pass "error log clean (no crash/crit/emerg/assert/deadlock)"
    fi
}

cleanup() {
    stop_httpd
    if [ "${KEEP:-0}" = "1" ]; then
        echo "KEEP=1 set; leaving run dir: $RUNDIR"
    elif [ -n "$RUNDIR" ]; then
        rm -rf "$RUNDIR"
    fi
}

summary() {
    echo
    echo "==== $(basename "$0"): $PASS passed, $FAIL failed ===="
    [ "$FAIL" -eq 0 ]
}
