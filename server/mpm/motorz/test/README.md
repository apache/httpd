# motorz MPM test harness

Self-contained smoke / regression tests for the **motorz** MPM
(`server/mpm/motorz/motorz.c`). These drive a real `httpd` built from this tree
against a throwaway `ServerRoot` in a temp dir; nothing is installed and no
existing config is touched.

## Build & configure (do this first)

The tests run a real `httpd` built from this tree. The easiest way to get a
correctly-configured build is the bootstrap script — it runs `buildconf` (only
if `./configure` is missing), `./configure` with the right flags, `make`, and
then verifies every module the tests need is present:

```sh
server/mpm/motorz/test/setup.sh                # configure (if needed) + build + verify
server/mpm/motorz/test/setup.sh --reconfigure  # force a fresh ./configure
server/mpm/motorz/test/setup.sh --jobs 8        # control make parallelism
```

It does **not** install httpd; the tests use the freshly built `./httpd` in
place. On success it prints `setup OK` and the run-all command.

### Doing it by hand instead

```sh
# from the build top. (Run ./buildconf first only on a fresh git checkout that
# has no ./configure; needs autoconf + libtool + python3.)
./configure --with-included-apr \
    --enable-mpms-shared='event motorz' \
    --enable-so --enable-unixd \
    --enable-authz_core --enable-authz_host --enable-log_config \
    --enable-mime --enable-dir \
    --enable-socache_shmcb --enable-ssl --enable-http2
make
```

`--with-included-apr` uses the bundled APR/APR-Util (no system APR needed).
`event` is built alongside `motorz` because `bench.sh` compares against it.
(`mod_ssl`/`mod_http2` are also part of the default `most` module set, so a
plain `./configure --enable-mpms-shared='event motorz' --with-included-apr`
usually yields them too; the explicit flags above just make it deterministic.)

### What the tests need

The harness finds the `httpd` binary at the top of the build tree and locates
the shared module `.so` files under `modules/` and `server/mpm/`. Required for
the HTTP/1.1 suite + smoke: `mod_mpm_motorz`, `mod_unixd`, `mod_authz_core`,
`mod_authz_host`, `mod_log_config`, `mod_mime`, `mod_dir`. The HTTP/2 suite
additionally needs `mod_ssl`, `mod_http2`, `mod_socache_shmcb` (building these
requires OpenSSL headers and `libnghttp2`), plus an `openssl` CLI and a `curl`
built with HTTP/2 — it **self-skips** (exit 0) with a clear message if any are
missing. If [`h2load`](https://nghttp2.org/) (from nghttp2) is on `PATH`, the
HTTP/2 suite adds real multiplexed load tests; otherwise those are skipped (not
failed). `bench.sh` needs `mod_mpm_event` and `ab`/`h2load`.

## Running

```sh
server/mpm/motorz/test/run-all.sh      # smoke + both suites
server/mpm/motorz/test/smoke.sh        # fast change-mapped smoke test only
server/mpm/motorz/test/run-http1.sh    # HTTP/1.1 only
server/mpm/motorz/test/run-http2.sh    # HTTP/2-over-TLS only
server/mpm/motorz/test/bench.sh        # motorz vs event throughput comparison
```

### bench.sh — motorz vs event

Runs identical `ab` (HTTP/1.1) and `h2load` (HTTP/2) workloads against the same
build configured first with the event MPM, then motorz, with matched tunables,
and prints a req/s comparison table.

**Critical:** worker threads must exceed peak connection concurrency — under
HTTP/2 each connection holds a worker for its lifetime, so too few workers
starves the pool and h2load reports spurious failures on *both* MPMs. `bench.sh`
defaults `THREADS=128` (≥ the c=50 default) and **flags any run with
failed/errored requests** (its req/s is then not a valid figure). Env knobs:
`REQS CONC H2_REQS H2_CONC H2_STREAMS H2_BIG_REQS THREADS PORT`.

Observed (12-core arm64, 1 child, adequate workers): motorz tracks event within
~1–2% on all four workloads. Note: motorz shows an *intermittent* small h2
failure rate under rapid connection churn at high concurrency that event does
not — see the project memory note; not a throughput issue.

Environment knobs:

- `PORT` / `TLS_PORT` — listen ports (default 8099 / 8443).
- `KEEP=1` — keep the temp `ServerRoot` after the run for inspection
  (path is printed); otherwise it is removed on exit.

Exit status is non-zero if any assertion fails.

## What is covered

**`smoke.sh`** — fast (~10 s) robust smoke test whose checks map one-to-one to
the changes made on this branch, so a failure points straight at what broke:

1. **forward-decl of `motorz_update_listeners()`** — motorz loads, parses
   config, and serves (the bug was a C89 implicit-declaration / link error);
2. **clogging-input-filters branch honors hook state** — h2 keep-alive reuses
   one connection instead of collapsing to one-shot (h2 c2 connections set
   `clogging_input_filters` unconditionally);
3. **async HTTP/2 handoff is enabled** (`MOTORZ_ENABLE_ASYNC 1`) — asserts
   motorz *does* return the c1 connection to MPM monitoring (async hand-back)
   and that HTTP/2 connection churn (`h2load -n 10000 -c 50 -m 1`) still drops
   **0** requests. This is the regression test for the dropped-request bug,
   which is now fixed in mod_http2 (c1 is closed only after every c2 is done and
   flushed); see MOTORZ.README "HTTP/2 async handoff" for the close-ordering
   issue and the fix.

Runs h2-over-TLS when ssl/http2/openssl/h2-curl are present, else an
HTTP/1.1-only subset.

**`run-http1.sh`** — exercises the connection state machine in
`motorz_io_process()`:

- basic GET / 404 / body correctness
- **keep-alive reuse** (5 requests, asserts a single TCP connection) — the
  KEEPALIVE → WRITE_COMPLETION path
- 200KB body (write-completion cycling)
- concurrency / load: keep-alive correctness is checked with **curl** (3000
  reused requests, all 200) because `ab` miscounts a server-closed keep-alive
  connection's final read as a non-2xx failure — a known `ab` artifact, more
  frequent with `MOTORZ_ENABLE_ASYNC=0` since idle keep-alive closes via the
  blocking path; `ab` is still used for the completion count and the
  non-keep-alive lingering-close path (no `-k`, so no artifact)
- slow client: a partial request line completed after a pause (read-wait path)
- **lifecycle**: graceful restart under load, and 5× restart churn under
  continuous load — the skiplist/worker-drain scenario this branch hardened
- error-log scan for crash/crit/emerg/assert/deadlock

**`run-http2.sh`** — mod_http2 + mod_ssl on motorz:

- h2 ALPN negotiation (`http_version == 2`)
- request multiplexing over a single connection (10 streams, 1 connect)
- large multi-frame body
- **`h2load` load tests** (when available): 5000 req / 20 clients / 25 streams,
  1000 req of the 200KB body / 50 streams (flow control), and a rate-limited
  run with idle gaps — each asserting **zero** failed/errored and all-2xx
- inspects the `motorz_io_process()` state traces, asserting PROCESSING is
  driven (with async on, an idle c1 is handed back as `CONN_STATE_ASYNC_WAITIO`
  rather than via WRITE_COMPLETION; HTTP/1.1 still covers WRITE_COMPLETION)
- **asserts async is enabled**: the `CONN_STATE_ASYNC_WAITIO` arm (`AH10557`)
  appears and h2 logs "returning to mpm c1 monitoring" (see below)
- h2 still negotiated after a graceful restart
- error-log scan

### Two-phase logging (why)

The state traces require global `LogLevel trace8`, but the `h2load` phase
pushes thousands of requests — at trace8 the error_log would balloon to
**gigabytes** and make the log greps crawl. So the suite runs the load phase at
`LogLevel info` (quiet) and only switches to `trace8` (via `set_loglevel()`,
which rewrites the marked LogLevel line and gracefully restarts) for the light
trace phase. Trace scans read only past a marker line written at the switch,
keeping them fast.

### Async is enabled; the suite asserts it is on

motorz reports `AP_MPMQ_IS_ASYNC = 1` (`MOTORZ_ENABLE_ASYNC 1` in `motorz.c`).
The HTTP/2 churn bug it used to expose is fixed in mod_http2 (a graceful client
GOAWAY no longer tears the session down while a stream's c2 is still finishing;
see MOTORZ.README "HTTP/2 async handoff"). Consequences the suite asserts:
mod_http2 requests `CONN_STATE_ASYNC_WAITIO` of an async MPM, so the WAITIO arm
trace `AH10557` **does** appear, and h2 **does** log "returning to mpm c1
monitoring" — while the churn run stays at 0 dropped requests. The suite drives
the WAITIO path (an idle raw-h2 `openssl s_client` connection — preface + empty
`SETTINGS`, no request) via `trigger_async_waitio()` in `lib.sh` and confirms it
arms ≥ 1 time.

This positively exercises the branch added in this work. The suite also
confirms (via the `info`-level log) that motorz's `AP_MPMQ_IS_ASYNC = 1` drives
mod_http2's async idle-return ("returning to mpm c1 monitoring"), rather than
the prefork-style blocking poll.

## Layout

```
setup.sh         configure + build httpd with the modules the tests need
lib.sh           shared helpers (build-tree discovery, config gen, assert API,
                 set_loglevel, trigger_async_waitio, h2load_stat)
smoke.sh         fast change-mapped smoke test
run-http1.sh     HTTP/1.1 functional + lifecycle suite
run-http2.sh     HTTP/2-over-TLS suite (+ h2load load tests)
run-all.sh       runs smoke + both suites, aggregates pass/fail
bench.sh         motorz vs event throughput comparison (not in run-all)
```
