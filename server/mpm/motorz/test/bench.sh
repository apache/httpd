#!/bin/sh
#
# motorz vs event -- head-to-head MPM performance comparison.
#
# Runs identical workloads against the SAME httpd build configured first with
# the event MPM, then the motorz MPM, with matched tunables (one child,
# ThreadsPerChild 16, quiet logging) so the only variable is the MPM.
#
# Workloads:
#   - HTTP/1.1 keep-alive          (ab -k)        small body
#   - HTTP/1.1 no keep-alive       (ab)           small body  (accept/linger cost)
#   - HTTP/2 multiplexed           (h2load)       small body
#   - HTTP/2 large body            (h2load)       200 KB      (write/flow control)
#
# Reports req/s and mean latency for each, side by side. NOT a rigorous
# microbenchmark -- it's a practical apples-to-apples smoke of relative
# throughput on this machine. Run it a couple of times; numbers vary.
#
# Usage:  server/mpm/motorz/test/bench.sh   [REQS=50000 CONC=50 DUR=...]
# Env:    PORT (TLS+plain reuse one port per run), KEEP=1

. "$(dirname "$0")/lib.sh"

require_httpd

REQS="${REQS:-50000}"      # ab request count (keep-alive run)
REQS_NOKA="${REQS_NOKA:-20000}"
CONC="${CONC:-50}"
H2_REQS="${H2_REQS:-50000}"
H2_CONC="${H2_CONC:-50}"
H2_STREAMS="${H2_STREAMS:-25}"
H2_BIG_REQS="${H2_BIG_REQS:-5000}"
# Worker threads MUST exceed the peak concurrent CONNECTION count: under HTTP/2
# each connection holds a worker for its lifetime (the h2 c1 connection is
# dispatched to a worker), so fewer workers than connections starves the pool
# and h2load reports spurious failures/resets on BOTH MPMs -- making any req/s
# number meaningless. Size generously above max(CONC, H2_CONC).
THREADS="${THREADS:-128}"
PORT="${PORT:-8551}"

have_ab=0;     command -v ab >/dev/null 2>&1 && have_ab=1
have_h2load=0; command -v h2load >/dev/null 2>&1 && have_h2load=1
have_ssl=1
for n in mod_ssl.so mod_http2.so mod_socache_shmcb.so; do
    find "$TOP/modules" -name "$n" -path '*/.libs/*' 2>/dev/null | grep -q . || have_ssl=0
done
[ "$have_h2load" -eq 1 ] && [ "$have_ssl" -eq 1 ] && do_h2=1 || do_h2=0

make_rundir
trap cleanup EXIT INT TERM
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$RUNDIR/key.pem" \
    -out "$RUNDIR/cert.pem" -days 2 -subj "/CN=localhost" >/dev/null 2>&1

# Result accumulators (one column per MPM), kept as text rows we print at the end.
RESULTS_FILE="$RUNDIR/results.txt"
: > "$RESULTS_FILE"
record() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS_FILE"; }  # workload, mpm, "val"

# --- write a config for the given MPM ($1 = event|motorz) -------------------
write_conf() {
    local mpm="$1" mpm_line tune
    if [ "$mpm" = event ]; then
        mpm_line="$(load mpm_event_module mod_mpm_event.so)"
        tune="StartServers 1
ServerLimit 1
ThreadLimit $THREADS
ThreadsPerChild $THREADS
MinSpareThreads $THREADS
MaxSpareThreads $THREADS
MaxRequestWorkers $THREADS"
    else
        mpm_line="$(load mpm_motorz_module mod_mpm_motorz.so)"
        tune="StartServers 1
ThreadLimit $THREADS
ThreadsPerChild $THREADS
PollersPerChild 2"
    fi
    # Both MPMs run ONE child with $THREADS worker threads, sized above the peak
    # connection concurrency so neither starves under h2 (see THREADS note).
    {
        echo "ServerRoot \"$RUNDIR\""
        echo "ServerName localhost"
        echo "PidFile \"$RUNDIR/httpd.pid\""
        echo "Listen $PORT"
        echo "$mpm_line"
        load unixd_module mod_unixd.so
        load authz_core_module mod_authz_core.so
        load authz_host_module mod_authz_host.so
        load log_config_module mod_log_config.so
        load mime_module mod_mime.so
        load dir_module mod_dir.so
        if [ "$do_h2" -eq 1 ]; then
            load socache_shmcb_module mod_socache_shmcb.so
            load ssl_module mod_ssl.so
            load http2_module mod_http2.so
        fi
        echo "$tune"
        echo "ErrorLog \"$RUNDIR/logs/error_log\""
        echo "LogLevel error"          # quiet: logging must not skew the numbers
        echo "TypesConfig /dev/null"
        echo "AddType text/html .html"
        echo "AddType text/plain .txt"
        echo "EnableSendfile On"
        echo "DocumentRoot \"$RUNDIR/htdocs\""
        echo "DirectoryIndex index.html"
        echo "<Directory \"$RUNDIR/htdocs\">"
        echo "  Require all granted"
        echo "</Directory>"
        if [ "$do_h2" -eq 1 ]; then
            echo "Protocols h2 http/1.1"
            echo "SSLSessionCache \"shmcb:$RUNDIR/logs/sc(512000)\""
            echo "<VirtualHost *:$PORT>"
            echo "  ServerName localhost"
            echo "  SSLEngine on"
            echo "  SSLCertificateFile \"$RUNDIR/cert.pem\""
            echo "  SSLCertificateKeyFile \"$RUNDIR/key.pem\""
            echo "  Protocols h2 http/1.1"
            echo "</VirtualHost>"
        fi
    } > "$RUNDIR/httpd.conf"
}

# extract "Requests per second" and "Time per request (mean)" from ab output
ab_rps()  { printf '%s\n' "$1" | awk '/Requests per second/{print $4; exit}'; }
ab_mean() { printf '%s\n' "$1" | awk '/Time per request/ && /\(mean\)/{print $4; exit}'; }
# h2load: "finished in Xs, NNN.NN req/s, ..." and the req mean from the table
h2_rps()  { printf '%s\n' "$1" | awk -F',' '/req\/s/{for(i=1;i<=NF;i++) if($i ~ /req\/s/){gsub(/[^0-9.]/,"",$i); print $i; exit}}'; }
# Warn loudly if an h2load run had ANY failed/errored requests -- the req/s of
# such a run is not a valid throughput figure (it raced a starved pool or a
# crash). $1=output $2=workload $3=mpm.
h2_check_clean() {
    local f e
    f=$(printf '%s\n' "$1" | sed -nE 's/.* ([0-9]+) failed.*/\1/p')
    e=$(printf '%s\n' "$1" | sed -nE 's/.* ([0-9]+) errored.*/\1/p')
    if [ "${f:-0}" -ne 0 ] || [ "${e:-0}" -ne 0 ]; then
        echo "     !! WARNING: $2/$3 had $f failed / $e errored -- req/s is NOT valid"
        record "${2}-FAILED" "$mpm" "$f/$e"
    fi
}

run_mpm() {
    local mpm="$1" base out rps mean
    echo
    echo "######## $mpm ########"
    write_conf "$mpm"
    "$HTTPD" -f "$RUNDIR/httpd.conf" -t >/dev/null 2>&1 \
        || { echo "  config invalid for $mpm; skipping"; return; }
    start_httpd
    # confirm which MPM is actually serving
    sleep 0.5

    if [ "$have_ab" -eq 1 ]; then
        base="http://127.0.0.1:$PORT"
        echo "-- HTTP/1.1 keep-alive  ($REQS req, c=$CONC)"
        out=$(ab -n "$REQS" -c "$CONC" -k -q "$base/" 2>&1)
        rps=$(ab_rps "$out"); mean=$(ab_mean "$out")
        echo "     req/s=$rps  mean(ms/req-across-conc)=$mean"
        record "h1-keepalive" "$mpm" "$rps"

        echo "-- HTTP/1.1 no keep-alive  ($REQS_NOKA req, c=$CONC)"
        out=$(ab -n "$REQS_NOKA" -c "$CONC" -q "$base/" 2>&1)
        rps=$(ab_rps "$out")
        echo "     req/s=$rps"
        record "h1-no-keepalive" "$mpm" "$rps"
    else
        echo "-- ab not found; skipping HTTP/1.1 throughput"
    fi

    if [ "$do_h2" -eq 1 ]; then
        base="https://localhost:$PORT"
        echo "-- HTTP/2  ($H2_REQS req, c=$H2_CONC, m=$H2_STREAMS, small body)"
        out=$(h2load -n "$H2_REQS" -c "$H2_CONC" -m "$H2_STREAMS" "$base/" 2>&1)
        rps=$(h2_rps "$out"); h2_check_clean "$out" "h2-small" "$mpm"
        echo "     req/s=$rps  ($(h2load_stat "$out" '^requests:'))"
        record "h2-small" "$mpm" "$rps"

        echo "-- HTTP/2 large body  ($H2_BIG_REQS req, c=$H2_CONC, m=$H2_STREAMS, 200KB)"
        out=$(h2load -n "$H2_BIG_REQS" -c "$H2_CONC" -m "$H2_STREAMS" "$base/big.txt" 2>&1)
        rps=$(h2_rps "$out"); h2_check_clean "$out" "h2-large" "$mpm"
        echo "     req/s=$rps"
        record "h2-large" "$mpm" "$rps"
    else
        echo "-- h2load/ssl unavailable; skipping HTTP/2 throughput"
    fi

    stop_httpd
}

echo "==== motorz vs event MPM benchmark ===="
echo "host: $(uname -sm), cpus: $(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null)"
echo "settings: 1 child, ThreadsPerChild=$THREADS, LogLevel error"
echo "tools: ab=$have_ab h2load=$have_h2load ssl=$have_ssl"

run_mpm event
run_mpm motorz

# ---- comparison table ------------------------------------------------------
echo
echo "==== req/s comparison (higher is better) ===="
awk -F'\t' '
    { v[$1"|"$2]=$3; if(!seen[$1]++) order[++n]=$1 }
    END {
        printf "%-18s %12s %12s %10s\n", "workload", "event", "motorz", "motorz/event"
        printf "%-18s %12s %12s %10s\n", "--------", "-----", "------", "-----------"
        for(i=1;i<=n;i++){
            w=order[i]; e=v[w"|event"]; m=v[w"|motorz"]
            ratio = (e+0>0 && m+0>0) ? sprintf("%.2fx", m/e) : "n/a"
            printf "%-18s %12s %12s %10s\n", w, (e==""?"-":e), (m==""?"-":m), ratio
        }
    }
' "$RESULTS_FILE"
echo
echo "(req/s; ratio = motorz relative to event. Re-run a few times -- single"
echo " runs are noisy. LogLevel was 'error' so logging did not skew results.)"
