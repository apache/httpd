#!/bin/sh
#
# motorz MPM -- HTTP/2-over-TLS suite (mod_http2 + mod_ssl on motorz).
#
# Confirms h2 ALPN negotiation, request multiplexing over a single connection,
# a large multi-frame body, and h2load load (incl. high-churn n=.. c=50 m=1)
# with zero dropped requests. Also asserts that the async HTTP/2 handoff is
# ENABLED (MOTORZ_ENABLE_ASYNC 1): CONN_STATE_ASYNC_WAITIO arms and c1 is
# returned to MPM monitoring, while churn stays lossless thanks to the mod_http2
# c1/c2 close-ordering fix -- see MOTORZ.README "HTTP/2 async handoff". With
# global trace8 it inspects the motorz connection state-machine traces.
#
# Usage:   server/mpm/motorz/test/run-http2.sh
# Env:     TLS_PORT=NNNN   KEEP=1
#
# Requires: motorz + unixd + authz_core/host + log_config + mime + dir
#           + socache_shmcb + ssl + http2, an `openssl` CLI, and a curl built
#           with HTTP/2 (`curl -V | grep -i http2`). The suite self-skips with
#           a clear message if any prerequisite is missing.

. "$(dirname "$0")/lib.sh"

PORT="$TLS_PORT"

require_httpd

# -- prerequisite checks (skip, don't fail, if the build lacks h2/ssl) -------
need_skip=""
command -v openssl >/dev/null 2>&1 || need_skip="openssl CLI not found"
if ! curl -V 2>/dev/null | grep -qi 'http2'; then
    need_skip="${need_skip:+$need_skip; }curl lacks HTTP/2 support"
fi
for n in mod_ssl.so mod_http2.so mod_socache_shmcb.so; do
    find "$TOP/modules" -name "$n" -path '*/.libs/*' 2>/dev/null | grep -q . \
        || need_skip="${need_skip:+$need_skip; }$n not built"
done
if [ -n "$need_skip" ]; then
    echo "==== motorz HTTP/2 suite: SKIPPED ($need_skip) ===="
    exit 0
fi

make_rundir
trap cleanup EXIT INT TERM

# self-signed cert
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$RUNDIR/key.pem" -out "$RUNDIR/cert.pem" \
    -days 2 -subj "/CN=localhost" >/dev/null 2>&1 \
    || { echo "ERROR: openssl cert generation failed" >&2; exit 3; }

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
# Start quiet: the h2load phase below pushes thousands of requests, and at
# trace8 the error_log would balloon to gigabytes (and make the log greps
# crawl). We switch to trace8 via set_loglevel() only for the light trace
# phase. The "# LOGLEVEL" marker is what set_loglevel() rewrites.
# (Global trace8 is required to see the motorz_io_process() state traces; a
# per-module "mpm_motorz:trace8 ... info" spec does NOT emit them on this build.)
# @LOGLEVEL@
LogLevel info
TypesConfig /dev/null
AddType text/html .html
AddType text/plain .txt

Protocols h2 http/1.1
SSLSessionCache "shmcb:$RUNDIR/logs/ssl_scache(512000)"

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

echo "==== motorz HTTP/2-over-TLS suite (port $PORT) ===="

echo "-- config syntax"
"$HTTPD" -f "$RUNDIR/httpd.conf" -t >/dev/null 2>&1
assert_eq 0 $? "httpd -t (motorz + ssl + http2)"

start_httpd

base="https://localhost:$PORT"
C="curl -sk --http2"

echo "-- h2 negotiation"
ver=$($C -o /dev/null -w '%{http_version}' "$base/")
assert_eq 2 "$ver" "ALPN negotiates HTTP/2"
assert_eq 200 "$($C -o /dev/null -w '%{http_code}' "$base/")" "h2 GET / returns 200"
assert_eq "hello-motorz" "$($C "$base/")" "h2 GET / body"

echo "-- large body over h2 (200KB)"
assert_eq 200000 "$($C -o /dev/null -w '%{size_download}' "$base/big.txt")" "h2 GET /big.txt full body"

echo "-- multiplexing: 10 streams, 1 connection"
urls=""; i=1; while [ $i -le 10 ]; do urls="$urls $base/?q=$i"; i=$((i+1)); done
conns=$($C -o /dev/null -w '%{num_connects}\n' $urls | awk '{s+=$1} END{print s}')
assert_eq 1 "$conns" "10 h2 requests over a single connection"

# --- h2load: real HTTP/2 load with concurrent clients & multiplexed streams.
# This is the robust smoke test -- it pounds motorz with genuine multiplexed
# h2 traffic (not curl's one-request-per-fetch) and verifies zero failures,
# which exercises the WRITE_COMPLETION / keep-alive / stream-handling paths
# under real concurrency. Skipped (not failed) if h2load is unavailable.
if command -v h2load >/dev/null 2>&1; then
    echo "-- h2load: 5000 requests / 20 clients / 25 streams (small body)"
    out=$(h2load -n 5000 -c 20 -m 25 "$base/" 2>&1)
    req_line=$(h2load_stat "$out" '^requests:')
    sc_line=$(h2load_stat "$out" '^status codes:')
    echo "      $req_line"
    echo "      $sc_line"
    # "requests: N total, N started, N done, N succeeded, N failed, ..."
    succeeded=$(printf '%s' "$req_line" | sed -nE 's/.* ([0-9]+) succeeded.*/\1/p')
    failed=$(printf '%s'    "$req_line" | sed -nE 's/.* ([0-9]+) failed.*/\1/p')
    errored=$(printf '%s'   "$req_line" | sed -nE 's/.* ([0-9]+) errored.*/\1/p')
    twoxx=$(printf '%s'     "$sc_line"  | sed -nE 's/.* ([0-9]+) 2xx.*/\1/p')
    assert_eq 5000 "${succeeded:-0}" "h2load: all 5000 requests succeeded"
    assert_eq 0    "${failed:-x}"    "h2load: 0 failed"
    assert_eq 0    "${errored:-x}"   "h2load: 0 errored"
    assert_eq 5000 "${twoxx:-0}"     "h2load: all 5000 responses were 2xx"

    echo "-- h2load: 1000 requests / 10 clients / 50 streams (200KB body, flow control)"
    out=$(h2load -n 1000 -c 10 -m 50 "$base/big.txt" 2>&1)
    req_line=$(h2load_stat "$out" '^requests:')
    echo "      $req_line"
    succeeded=$(printf '%s' "$req_line" | sed -nE 's/.* ([0-9]+) succeeded.*/\1/p')
    failed=$(printf '%s'    "$req_line" | sed -nE 's/.* ([0-9]+) failed.*/\1/p')
    assert_eq 1000 "${succeeded:-0}" "h2load: 1000 large-body requests succeeded"
    assert_eq 0    "${failed:-x}"    "h2load: 0 failed (large body / flow control)"

    echo "-- h2load: rate-limited connections (idle gaps between streams)"
    # -r2 opens 2 new connections/sec with brief inactivity, nudging sessions
    # toward the idle/keepalive paths between bursts.
    out=$(h2load -n 600 -c 12 -m 5 -r 2 "$base/" 2>&1)
    req_line=$(h2load_stat "$out" '^requests:')
    echo "      $req_line"
    failed=$(printf '%s' "$req_line" | sed -nE 's/.* ([0-9]+) failed.*/\1/p')
    assert_eq 0 "${failed:-x}" "h2load: 0 failed (rate-limited / idle connections)"

    # --- churn regression: NO RESPONSE LOSS under max connection churn -------
    # This is the workload the mod_http2 c1/c2 close-ordering fix targets
    # (MOTORZ.README "HTTP/2 async handoff"): many short connections, one stream
    # each (-m 1), so each client sends a graceful GOAWAY right after its single
    # request -- the exact path that used to abort a just-finished c2 and drop
    # its response.
    #
    # We assert on RESPONSE LOSS (started - succeeded), NOT on h2load's "failed"
    # total. Those are different: failed = (total - started) + (started -
    # succeeded). The first term is connection-ESTABLISHMENT error (ephemeral
    # port / accept-queue pressure on a busy loopback) -- environmental, seen
    # with AND without the fix, and not what this fix is about. The original bug
    # is response loss on connections that DID start: started > succeeded. That
    # is what must be zero, and it is the precise, non-flaky signal for this fix.
    #
    # NB: run at the current "info" level, NOT the trace8 phase below. The bug
    # is a Heisenbug; trace8 slows the hot path enough to hide it, which would
    # make this assertion pass vacuously (verified: a deliberately broken fix
    # still showed 0 response loss under trace8). info keeps the path hot.
    echo "-- [churn regression] h2 connection churn must not drop responses"
    resp_lost_total=0; started_total=0
    for _crun in 1 2 3; do
        out=$(h2load -n 10000 -c 50 -m 1 "$base/" 2>&1)
        rl=$(h2load_stat "$out" '^requests:')
        started=$(printf '%s' "$rl"   | sed -nE 's/.* total, ([0-9]+) started.*/\1/p')
        succeeded=$(printf '%s' "$rl" | sed -nE 's/.* ([0-9]+) succeeded.*/\1/p')
        lost=$(( ${started:-0} - ${succeeded:-0} ))
        [ "$lost" -lt 0 ] && lost=0
        echo "      run $_crun: started=${started:-?} succeeded=${succeeded:-?} response-loss=$lost"
        resp_lost_total=$(( resp_lost_total + lost ))
        started_total=$(( started_total + ${started:-0} ))
    done
    echo "      total response-loss=$resp_lost_total over started=$started_total (expected 0)"
    assert_eq 0 "$resp_lost_total" "h2 churn: 0 dropped responses on started connections (close-ordering fix)"
else
    echo "-- h2load: SKIPPED (h2load not on PATH; install nghttp2 for full load coverage)"
fi

# ---- trace phase: switch to trace8 for light, instrumented traffic only ----
# (Heavy load above ran at "info" so the log stayed small.) From here on the
# error_log only grows by a handful of trace8 lines per request, so the greps
# below stay fast. We mark the switch point and scan only past it.
echo "-- switching to LogLevel trace8 for state-machine inspection"
phase_marker="##TRACE-PHASE-$$##"
echo "$phase_marker" >> "$RUNDIR/logs/error_log"
set_loglevel trace8

echo "-- motorz state-machine traces while serving h2"
# A couple of completed h2 requests (curl drives keepalive=1) exercise these.
$C -o /dev/null "$base/" "$base/big.txt" "$base/" >/dev/null 2>&1
sleep 0.3
states=$(awk -v m="$phase_marker" '$0~m{f=1} f' "$RUNDIR/logs/error_log" \
         | grep -oE "motorz_io_process\(\): [a-z][a-z ->]*[a-z]" | sort -u)
echo "$states" | sed 's/^/      seen: /'
echo "$states" | grep -q "processing"        && pass "saw CONN_STATE_PROCESSING"        || fail "no PROCESSING trace"
# NOTE: with async enabled (MOTORZ_ENABLE_ASYNC 1) and CAN_WAITIO, mod_http2
# hands an idle c1 back as CONN_STATE_ASYNC_WAITIO rather than via
# WRITE_COMPLETION, so motorz's "write completion" state is still not exercised
# by h2. (It is covered for HTTP/1.1 in run-http1.sh.) Only PROCESSING is
# asserted here.

echo "-- async HTTP/2 handoff is ENABLED (MOTORZ_ENABLE_ASYNC 1)"
# motorz reports AP_MPMQ_IS_ASYNC=1 / AP_MPMQ_CAN_WAITIO=1, so mod_http2 takes
# the async c1 hand-back path. This is only safe because of the mod_http2
# c1/c2 close-ordering fix (h2_session_ev_remote_goaway / ST_IDLE draining):
# the c1 connection is closed only after every secondary connection (c2) has
# finished and flushed, so connection churn stays lossless (asserted above and
# in smoke.sh). See MOTORZ.README "HTTP/2 async handoff". Consequences asserted
# here, inverted from the async-off era:
#   - the CONN_STATE_ASYNC_WAITIO arm trace (AH10557) DOES appear when a client
#     opens an h2 connection and then idles: mod_http2 requests WAITIO of an
#     async MPM and motorz arms it.
#   - mod_http2 DOES return the c1 connection to the MPM ("returning to mpm c1
#     monitoring") between requests.
marker="##WAITIO-$$##"
echo "$marker" >> "$RUNDIR/logs/error_log"
trigger_async_waitio "$PORT"
waitio_arm=$(awk -v m="$marker" '$0~m{f=1} f' "$RUNDIR/logs/error_log" | grep -c 'AH10557')
mon=$(grep -c 'returning to mpm c1 monitoring' "$RUNDIR/logs/error_log")
echo "      waitio-arm(AH10557)=$waitio_arm   mpm-c1-monitoring=$mon  (both expected > 0)"
assert_gt "$waitio_arm" 0 "CONN_STATE_ASYNC_WAITIO armed (async enabled)"
assert_gt "$mon" 0        "h2 returns to MPM c1 monitoring (IS_ASYNC=1)"

echo "-- h2 graceful restart"
graceful
assert_eq 2 "$($C -o /dev/null -w '%{http_version}' "$base/")" "h2 still negotiated after graceful restart"

scan_log_clean

summary
