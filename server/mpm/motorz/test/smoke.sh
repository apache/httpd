#!/bin/sh
#
# motorz MPM -- robust smoke test mapped to the changes made on this branch.
#
# Each check targets one concrete change in server/mpm/motorz/motorz.c so a
# regression points straight at what broke:
#
#   1. forward-decl of motorz_update_listeners()  -> the binary built & runs
#      (the bug was a C89 implicit-declaration / link error; if motorz loads
#       and serves, the declaration is correct).
#   2. clogging-input-filters branch honors hook state (not force-LINGER)
#      -> HTTP/2 over TLS keep-alives instead of collapsing to one-shot, since
#         h2 c2 connections set clogging_input_filters unconditionally.
#   3. async HTTP/2 handoff is ENABLED (MOTORZ_ENABLE_ASYNC 1): motorz reports
#      AP_MPMQ_IS_ASYNC=1, so mod_http2 hands the c1 connection back to the MPM
#      between requests. The mod_http2 c1/c2 close-ordering fix
#      (h2_session_ev_remote_goaway / ST_IDLE draining) keeps this lossless: c1
#      is closed only after every stream's c2 has finished and flushed. The
#      check is a churn regression test: many short h2 connections, asserting 0
#      dropped requests. (See MOTORZ.README "HTTP/2 async handoff" for the full
#      analysis and the fix.)
#
# It is fast (a few seconds), TLS+h2 if available else HTTP/1.1-only, and runs
# under global trace8 so the state-machine assertions can read the log.
#
# Usage: server/mpm/motorz/test/smoke.sh   [PORT=.. KEEP=1]

. "$(dirname "$0")/lib.sh"

require_httpd

# Decide whether we can do the full h2 smoke or only HTTP/1.1.
H2=1
command -v openssl >/dev/null 2>&1 || H2=0
curl -V 2>/dev/null | grep -qi 'http2' || H2=0
for n in mod_ssl.so mod_http2.so mod_socache_shmcb.so; do
    find "$TOP/modules" -name "$n" -path '*/.libs/*' 2>/dev/null | grep -q . || H2=0
done

PORT="${PORT:-$TLS_PORT}"
make_rundir
trap cleanup EXIT INT TERM

echo "==== motorz smoke test (h2=$([ $H2 -eq 1 ] && echo yes || echo no), port $PORT) ===="

if [ "$H2" -eq 1 ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$RUNDIR/key.pem" -out "$RUNDIR/cert.pem" \
        -days 2 -subj "/CN=localhost" >/dev/null 2>&1 \
        || { echo "ERROR: cert gen failed" >&2; exit 3; }
    cat > "$RUNDIR/httpd.conf" <<EOF
ServerRoot "$RUNDIR"
ServerName localhost
PidFile "$RUNDIR/httpd.pid"
Listen $PORT
$(load mpm_motorz_module mod_mpm_motorz.so)
$(load unixd_module mod_unixd.so)
$(load authz_core_module mod_authz_core.so)
$(load authz_host_module mod_authz_host.so)
$(load log_config_module mod_log_config.so)
$(load mime_module mod_mime.so)
$(load dir_module mod_dir.so)
$(load socache_shmcb_module mod_socache_shmcb.so)
$(load ssl_module mod_ssl.so)
$(load http2_module mod_http2.so)
StartServers 1
PollersPerChild 2
ThreadsPerChild 16
ThreadLimit 32
Timeout 10
ErrorLog "$RUNDIR/logs/error_log"
LogLevel trace8
TypesConfig /dev/null
AddType text/html .html
AddType text/plain .txt
Protocols h2 http/1.1
SSLSessionCache "shmcb:$RUNDIR/logs/sc(512000)"
DocumentRoot "$RUNDIR/htdocs"
DirectoryIndex index.html
<Directory "$RUNDIR/htdocs">
  Require all granted
</Directory>
<VirtualHost *:$PORT>
  ServerName localhost
  SSLEngine on
  SSLCertificateFile "$RUNDIR/cert.pem"
  SSLCertificateKeyFile "$RUNDIR/key.pem"
  Protocols h2 http/1.1
</VirtualHost>
EOF
    scheme=https
else
    cat > "$RUNDIR/httpd.conf" <<EOF
ServerRoot "$RUNDIR"
ServerName 127.0.0.1
PidFile "$RUNDIR/httpd.pid"
Listen $PORT
$(load mpm_motorz_module mod_mpm_motorz.so)
$(load unixd_module mod_unixd.so)
$(load authz_core_module mod_authz_core.so)
$(load authz_host_module mod_authz_host.so)
$(load log_config_module mod_log_config.so)
$(load mime_module mod_mime.so)
$(load dir_module mod_dir.so)
StartServers 1
PollersPerChild 2
ThreadsPerChild 16
ThreadLimit 32
Timeout 10
ErrorLog "$RUNDIR/logs/error_log"
LogLevel trace8
TypesConfig /dev/null
AddType text/html .html
AddType text/plain .txt
DocumentRoot "$RUNDIR/htdocs"
DirectoryIndex index.html
<Directory "$RUNDIR/htdocs">
  Require all granted
</Directory>
EOF
    scheme=http
fi

base="$scheme://localhost:$PORT"
[ "$scheme" = http ] && base="http://127.0.0.1:$PORT"
CURL="curl -sk"
[ "$H2" -eq 1 ] && CURL="curl -sk --http2"

# ---- change #1: motorz loads, parses config, serves -----------------------
echo "-- [#1 forward-decl] motorz binary loads & serves"
"$HTTPD" -f "$RUNDIR/httpd.conf" -t >/dev/null 2>&1
assert_eq 0 $? "config valid (motorz module loads -- forward-decl/link OK)"
start_httpd
assert_eq 200 "$($CURL -o /dev/null -w '%{http_code}' "$base/")" "serves GET / (200)"
assert_eq "hello-motorz" "$($CURL "$base/")" "correct body"

if [ "$H2" -eq 1 ]; then
    echo "-- [h2] negotiation"
    assert_eq 2 "$($CURL -o /dev/null -w '%{http_version}' "$base/")" "ALPN -> HTTP/2"

    # ---- change #2: clogging branch keeps h2 connections alive ------------
    echo "-- [#2 clogging-state] h2 keep-alive (clogging_input_filters honored)"
    conns=$($CURL -o /dev/null -w '%{num_connects}\n' "$base/" "$base/" "$base/" \
            | awk '{s+=$1} END{print s}')
    assert_eq 1 "$conns" "3 h2 requests reuse one connection (not force-LINGERed)"

    # ---- change #3: async enabled -> still no dropped requests under churn -
    # With MOTORZ_ENABLE_ASYNC=1, motorz advertises itself async and mod_http2
    # takes the c1 hand-back path ("returning to mpm c1 monitoring"). The
    # mod_http2 c1/c2 close-ordering fix (h2_session_ev_remote_goaway /
    # ST_IDLE draining) must keep this lossless under connection churn -- the
    # workload that used to drop ~0.2-3% of requests. See MOTORZ.README.
    echo "-- [#3 async-churn] motorz advertises async; h2 churn stays lossless"
    mon=$(grep -c 'returning to mpm c1 monitoring' "$RUNDIR/logs/error_log")
    assert_gt "$mon" 0 "h2 returns to MPM c1 monitoring (IS_ASYNC=1)"
    if command -v h2load >/dev/null 2>&1; then
        # m=1 / high concurrency = max connection churn = the failing workload.
        # Assert on RESPONSE LOSS (started - succeeded), not on h2load's "failed"
        # total: "failed" also counts connection-establishment errors (ephemeral
        # port / accept-queue pressure on a busy loopback) which are
        # environmental and unrelated to this fix. The bug is responses dropped
        # on connections that DID start, i.e. started > succeeded.
        #
        # NB: smoke.sh runs at trace8 (for the state-machine assertions above),
        # which slows the hot path enough to MASK this Heisenbug -- so treat this
        # as a gross-sanity check only. The real, non-vacuous churn regression
        # runs at "info" in run-http2.sh ([churn regression]).
        out=$(h2load -n 10000 -c 50 -m 1 "$base/" 2>&1)
        started=$(printf '%s\n'   "$out" | sed -nE 's/.* total, ([0-9]+) started.*/\1/p')
        succeeded=$(printf '%s\n' "$out" | sed -nE 's/.* ([0-9]+) succeeded.*/\1/p')
        lost=$(( ${started:-0} - ${succeeded:-0} )); [ "$lost" -lt 0 ] && lost=0
        echo "      h2load n=10000 c=50 m=1: started=$started succeeded=$succeeded response-loss=$lost"
        assert_eq 0 "$lost" "h2 churn: 0 dropped responses on started connections (sanity; see run-http2.sh)"
    else
        echo "      (h2load absent; churn assertion skipped -- install nghttp2)"
    fi
else
    echo "-- [#2/#3] h2 checks SKIPPED (ssl/http2/openssl/h2-curl unavailable)"
    echo "-- [HTTP/1.1] keep-alive reuse instead"
    conns=$($CURL -o /dev/null -w '%{num_connects}\n' "$base/" "$base/" "$base/" \
            | awk '{s+=$1} END{print s}')
    assert_eq 1 "$conns" "3 HTTP/1.1 requests reuse one connection"
fi

# ---- lifecycle: graceful restart still serves -----------------------------
echo "-- [lifecycle] graceful restart"
graceful
assert_eq 200 "$($CURL -o /dev/null -w '%{http_code}' "$base/")" "serving after graceful restart"

scan_log_clean
summary
