#!/bin/sh
#
# motorz MPM -- HTTP/1.1 functional + lifecycle regression suite.
#
# Launches httpd with the motorz MPM (2 pollers) and exercises the connection
# state machine that server/mpm/motorz/motorz.c implements: basic requests,
# keep-alive reuse, the non-blocking lingering-close path, concurrency, a
# slow/partial-request client (read-wait), and the graceful restart / stop /
# restart-churn lifecycle that this branch hardened.
#
# Usage:   server/mpm/motorz/test/run-http1.sh
# Env:     PORT=NNNN   KEEP=1 (keep the temp ServerRoot for inspection)
#
# Requires only: motorz, unixd, authz_core, authz_host, log_config, mime, dir.
# Uses `ab` if present for load; falls back to parallel curl otherwise.

. "$(dirname "$0")/lib.sh"

require_httpd
make_rundir
trap cleanup EXIT INT TERM

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
ThreadsPerChild 8
ThreadLimit 16

ErrorLog "$RUNDIR/logs/error_log"
LogLevel info
TypesConfig /dev/null
AddType text/html .html
AddType text/plain .txt
DocumentRoot "$RUNDIR/htdocs"
DirectoryIndex index.html
<Directory "$RUNDIR/htdocs">
  Require all granted
</Directory>
EOF

echo "==== motorz HTTP/1.1 suite (port $PORT) ===="

echo "-- config syntax"
"$HTTPD" -f "$RUNDIR/httpd.conf" -t >/dev/null 2>&1
assert_eq 0 $? "httpd -t (config valid, motorz loads)"

start_httpd

base="http://127.0.0.1:$PORT"

echo "-- basic request"
code=$(curl -s -o /dev/null -w '%{http_code}' "$base/")
assert_eq 200 "$code" "GET / returns 200"
body=$(curl -s "$base/")
assert_eq "hello-motorz" "$body" "GET / body"
assert_eq 404 "$(curl -s -o /dev/null -w '%{http_code}' "$base/nope")" "GET /nope returns 404"

echo "-- keep-alive reuse (5 requests, 1 connection)"
# curl prints %{num_connects} once per URL; with keep-alive only the first
# request opens a connection, so the values are 1,0,0,0,0 and the sum is 1.
conns=$(curl -s -o /dev/null -w '%{num_connects}\n' "$base/" "$base/" "$base/" "$base/" "$base/" \
        | awk '{s+=$1} END{print s}')
assert_eq 1 "$conns" "5 keep-alive requests reuse a single connection"

echo "-- large body (200KB, write-completion cycling)"
sz=$(curl -s -o /dev/null -w '%{size_download}' "$base/big.txt")
assert_eq 200000 "$sz" "GET /big.txt full body"

echo "-- concurrency / load"
if command -v ab >/dev/null 2>&1; then
    # Keep-alive correctness is verified with curl, not ab: curl parses HTTP
    # status reliably, whereas ab miscounts a server-closed keep-alive
    # connection's final read as a "Non-2xx"/"Length" failure (a known ab
    # artifact, more frequent with MOTORZ_ENABLE_ASYNC=0 because idle keep-alive
    # connections close via the blocking path). 3000 reused requests, all 200.
    n_ok=$(seq 1 50 | xargs -P 20 -I{} sh -c \
             'curl -s -o /dev/null -w "%{http_code}\n" $(for j in $(seq 1 60); do echo "'"$base"'/"; done)' \
           | grep -c '^200$')
    assert_eq 3000 "$n_ok" "curl keep-alive: 3000/3000 reused requests returned 200"

    # ab still used for raw completion count + the non-keep-alive linger path
    # (no -k => fresh connection per request => no keep-alive close artifact).
    out=$(ab -n 2000 -c 20 -k -q "$base/" 2>&1)
    complete=$(printf '%s\n' "$out" | awk '/Complete requests:/{print $3}')
    assert_eq 2000 "$complete" "ab: 2000 keep-alive requests completed"

    out=$(ab -n 1000 -c 30 -q "$base/" 2>&1)   # no -k: exercises lingering close
    assert_eq 0 "$(printf '%s\n' "$out" | awk '/Failed requests:/{print $3}')" \
              "ab: 0 failed (non-keepalive / linger path)"
else
    echo "  (ab not found; using parallel curl)"
    n_ok=$(seq 1 200 | xargs -P 20 -I{} curl -s -o /dev/null -w '%{http_code}\n' "$base/" \
           | grep -c '^200$')
    assert_eq 200 "$n_ok" "parallel curl: 200/200 returned 200"
fi

echo "-- slow client (partial request line, then complete: read-wait path)"
resp=$( ( printf 'GET / HTTP/1.1\r\nHost: x\r\n'; sleep 2; printf '\r\n'; sleep 1 ) \
        | nc 127.0.0.1 "$PORT" 2>/dev/null | head -1 | tr -d '\r' )
assert_eq "HTTP/1.1 200 OK" "$resp" "partial-then-complete request served"

echo "-- graceful restart under load"
( command -v ab >/dev/null 2>&1 && ab -n 3000 -c 20 -k -q "$base/" >/dev/null 2>&1 ) &
lpid=$!
graceful
wait $lpid 2>/dev/null
assert_eq 200 "$(curl -s -o /dev/null -w '%{http_code}' "$base/")" "serving after graceful restart"

echo "-- restart churn (5 gracefuls under continuous load)"
( for _ in 1 2 3 4 5 6; do
    command -v ab >/dev/null 2>&1 && ab -n 1000 -c 20 -k -q "$base/" >/dev/null 2>&1 \
        || curl -s -o /dev/null "$base/"
  done ) &
lpid=$!
for _ in 1 2 3 4 5; do graceful; done
wait $lpid 2>/dev/null
assert_eq 200 "$(curl -s -o /dev/null -w '%{http_code}' "$base/")" "serving after 5x restart churn"

scan_log_clean

summary
