# Apache httpd — `trunk` (2.5.x/2.6) vs `2.4.x`: Functional Difference Analysis

**Date:** 2026-06-08
**Repository:** `apache/httpd` git mirror (local clone)
**Branches compared:** `trunk` (`2.5.1-dev`, MMN `20211221:31`) vs `2.4.x` (`2.4.68-dev`, MMN `20120211:142`)
**Merge base:** r-level divergence at commit `5405226ae2` (2011-11-10). Since divergence:
~12,560 commits trunk-only, ~11,446 commits 2.4.x-only. The vast majority of 2.4.x work is
back-ported trunk work; this document isolates what is genuinely *new in trunk only*.

> Note: trunk is the development line that will become **2.6 / 2.5.x**. The bundled APR (1.7.x in
> `srclib/`) is the other big structural difference but is a build-time matter, not a runtime
> feature, so it is noted only where it gates a feature.

---

## Methodology

Differences were derived mechanically from the two branches, not from CHANGES prose (CHANGES is an
unreliable signal because most entries are later back-ported):

1. **Module/file set diff** — `git ls-tree` of `modules/`, `server/`, `include/` across both branches.
2. **Directive diff** — every `AP_INIT_*` directive name extracted from all `.c` files in each branch
   and compared (`trunk` 709 directives vs `2.4.x` 637).
3. **Reverse check** — directives/modules present in **2.4.x but absent in trunk** were individually
   investigated to prove they are intentional removals, not regressions.
4. **Maturity dating** — last-commit date per trunk-only module as a back-port-readiness signal.

---

## Part 1 — Confirmation: nothing in 2.4.x is missing from trunk

The directive reverse-diff surfaced exactly **three** names present in 2.4.x but not trunk. All three
are **deliberate removals or obsolete code in trunk**, not regressions or missing capabilities:

| 2.4.x-only item | Verdict | Evidence |
|-----------------|---------|----------|
| `ContentDigest` directive (+ `Content-MD5` header, `ap_md5digest()`, `ap_md5contextTo64()`) | **Intentionally removed** in trunk | trunk commit `6bf5bd6cb2`: *"core: Remove support for the Content-MD5 header, removed in RFC 7231 … and ContentDigest directive."* |
| `AuthDigestNonceFormat` (`mod_auth_digest`) | **Intentionally removed** in trunk | trunk commit `29b83f42e6`: *"Remove undocumented and unimplemented AuthDigestNonceFormat directive."* In 2.4.x it is a stub that returns `"AuthDigestNonceFormat is not implemented"`. |
| `DAVGenericLockDB` / `mod_dav_lock` module (`modules/dav/lock/`) | **Module removed** in trunk | trunk commit `f9ea103580`: *"Remove mod_dav_lock, which was useful only to provide drop-in locking for mod_dav_svn from Subversion older than 1.2.0."* Generic FS locking lives in `modules/dav/fs/` (`DAVLockDB`/`DAVLockDBType`) on both branches. |

**Conclusion:** There is **no feature, module, directive, or capability in 2.4.x that is absent from
trunk** except by design. Trunk is a strict functional superset of 2.4.x modulo these three
deliberate deprecations. ✅

---

## Part 2 — New in trunk, NOT in 2.4.x

### 2A. New modules (source files present only in trunk)

| Module | Area | Purpose | Last touched | Back-port suitability |
|--------|------|---------|--------------|------------------------|
| `mod_proxy_beacon` | proxy | UDP datagram channel: backend reverse-proxy servers announce themselves and are auto-added to a front-end balancer (`ProxyBeacon*` directives). | 2026-06 | **Candidate** (actively developed; self-contained, new directives only — low ABI risk). The author is the local committer. |
| `mod_autht_jwt` + `mod_autht_core` | aaa | New **"authentication token" (autht) provider framework** — JWT signing/verification (`AuthtJwt*`) sitting alongside the existing authn/authz provider stacks. | 2024-03 | **Candidate, with care** — introduces a new provider category; needs the autht hook infrastructure. Pairs with `mod_auth_bearer`. |
| `mod_auth_bearer` | aaa | RFC 6750 **Bearer token** auth front-end (`AuthBearer*`), analogous to `mod_auth_basic`/`_form`. | 2023-12 | **Candidate, with care** — depends on the autht framework above. |
| `mod_crypto` | filters | Encrypt/decrypt request & response bodies as input/output filters (`Crypto*` directives). | 2024-07 | **Candidate** — self-contained filter; needs APR crypto driver (build-gated). |
| `mod_log_json` | loggers | Structured JSON access logging. | 2021-03 | **Candidate** — self-contained logger. |
| `mod_journald` | loggers | Log to systemd `journald`. | 2020-04 | **Candidate** (Linux-only; already advertised in the 2.6 new-features doc). |
| `mod_syslog` | loggers | Log to syslog as a provider. | 2017-02 | **Candidate** (already advertised in the 2.6 new-features doc). |
| `mod_allowhandlers` | aaa | Restrict which handlers may run in a context (`AllowHandlers`). | 2012-11 | **Candidate** — small, stable, self-contained. |
| `mod_policy` (`modules/test/`) | test | Enforce outgoing-request policies / cache-correctness (`Policy*` directives). | 2026-06 | **Hold** — lives under `modules/test/`; experimental. |
| `mod_noloris` (`modules/experimental/`) | experimental | Slowloris mitigation (`MaxClientConnections`, `TrustedProxy`, `ClientRecheckTime`). | 2018-08 | **Hold** — experimental tree; not maintained recently. |
| `mod_ssl_ct` + `ssl_ct_*` | ssl | Certificate Transparency (RFC 6962) — SCT handling (`CT*` directives). | 2024-04 | **Hold / do-not-backport** — rejects OpenSSL 3.x (must be `--disable`d on modern builds); largely superseded by CA-side CT. |
| `mod_serf` | proxy | Proxy backend built on the Apache Serf library (`SerfCluster`, `SerfPass`). | 2020-04 | **Hold** — niche; external libserf dependency. |
| `mod_firehose` (`modules/debugging/`) | debugging | Capture full connection/request I/O streams to fifos for debugging (`Firehose*`). | 2016-01 | **Optional** — debugging aid; stable but rarely needed. |
| `mod_lbmethod_rr` (`modules/proxy/examples/`) | proxy | Round-robin LB method **example**. | 2017-07 | **Do-not-backport** — sample code. |
| `dav/fs/quota.c` (`DAVquota`) + `dav/main/ms_wdv.c` (`DAVMSext`) | dav | WebDAV quota support and Microsoft WebDAV extensions / `DAVHonorMtimeHeader`. | 2026-02 / 2026-04 | **Candidate** — actively developed; adds DAV directives. |

### 2B. New MPMs (trunk-only)

| MPM | Status | Notes |
|-----|--------|-------|
| `mpm_motorz` (`server/mpm/motorz/`) | **Actively reworked** (2026-06) | Single-process async event MPM; recently given multi-poller scale-out (`PollersPerChild`) and async keep-alive / HTTP/2 hand-off. **Good** for backport. |
| `mpm_simple` (`server/mpm/simple/`) | Experimental | `SimpleProcCount`, `SimpleThreadCount`. **Do-not-backport** — long-dormant proof-of-concept. |

### 2C. Core architectural changes (trunk-only, structural — NOT simple backports)

These are deep refactors that change the engine. They are the reason trunk's MMN major number is
different and are generally **not cherry-pick candidates** — they would have to be ported as a
coordinated effort and would break module ABI.

1. **Core / HTTP module split.** Large bodies of code were moved out of `modules/http/` into the
   core server so the server can run "closer to working without the HTTP module" (commit
   `3eeeb76fb4` and follow-ups). The default handler, default input/output filters, and all core
   config directives now live in core.
   - `ap_set_etag()` moved from `mod_http` to core → **new `server/util_etag.c`** (2.4.x still has
     `modules/http/http_etag.c`).
2. **Generic HTTP vs HTTP/1.x filter split** (commit `4442201e61`):
   - New metadata **bucket types `REQUEST`, `RESPONSE`, `HEADERS`** in the API → new
     **`server/headers_bucket.c`**.
   - `HTTP_IN` filter split into a generic-HTTP filter and an HTTP/1.x-specific `HTTP1_BODY_IN`.
   - Chunked-input simulation removed from `mod_http2`.
   - New `body_indeterminate` flag on `request_rec`; new helper methods for formatting HTTP/1.x
     headers/chunks reusable by `mod_proxy`; new method for setting standard `Date`/`Server`
     response headers.
3. **`ap_method_mask_t`** — method bitmasks widened to a dedicated type (was a fixed-width int),
   touching `ap_method_list_t`, `AP_METHOD_BIT`, `request_rec.allowed`, `cmd_parms.limited`. **ABI
   break** — cannot be back-ported without an MMN bump 2.4.x will not take.
4. **`mod_ssl.h` optional-function API change** — `ssl_var_lookup` now takes `const char *name` and
   returns `const char *`, and requires a non-NULL pool. **ABI/source break for consumers.**
5. **New request_rec "binary notes"** (`AP_REQUEST_STRONG_ETAG`) — lets modules force a strong ETag
   (needed for WebDAV RFC compliance); `ap_make_etag_ex()` / `ap_set_etag_fd()` added.

### 2D. New directives in trunk (selected, grouped by subsystem)

Full set: 72 directive names exist in trunk but not 2.4.x. The non-experimental, user-facing ones
most worth tracking for backport:

**Core (`server/core.c`)**
- `AsyncFilter` — declare which filter types support asynchronous handling.
- `LogLevelOverride` — per-client-IP loglevel override.
- `HttpExpectStrict` — return 417 if client omits 100-Continue.
- `HttpContentLengthHeadZero` — HEAD `Content-Length` compatibility control.
- `DefaultStateDir` — common directory for persistent state (already in the 2.6 doc).

**Async proxy / websockets (`mod_proxy`, `mod_proxy_wstunnel`)**
- `ProxyAsyncDelay`, `ProxyAsyncIdleTimeout`, `ProxyWebsocketAsyncDelay`, `ProxyWebsocketIdleTimeout`
  — asynchronous write-completion / Upgrade(d)-protocol handling under async MPMs.

**mod_ssl** — `SSLPolicy` (apply a named bundle of SSL settings; `SSLPolicy*` family).

**Other modules**
- `mod_mime`: `MimeOptions`.
- `mod_mime_magic`: `MimeMagicDecompression` (explicitly NOT RFC-compliant; off by default).
- `mod_autoindex`: `IndexForbiddenReturn404`.
- `mod_session_cookie`: `SessionCookieMaxAge`.
- `mod_dav_fs`: `DAVLockDBType`, `DAVHonorMtimeHeader`; `mod_dav` MS ext: `DAVMSext`, `DAVquota`.
- `mod_cache`: `Warning` handling.

### 2E. Other trunk-only core/build features (already on the live 2.6 page)

- `Listen options=...` per-listener socket options (incl. `multipathtcp`, PR 69292).
- **systemd socket activation** (build-time enable, run-time toggle via `mod_systemd`).
- **IPv6 zone/scope** support in `Listen`/`VirtualHost` (requires APR ≥ 1.7.0 — gated by trunk's
  bundled APR).
- `mod_cgid`: `--enable-cgid-fdpassing` stderr handling parity with `mod_cgi`.
- `htpasswd`: SHA-256/SHA-512 `crypt()` hashes.
- New Python support scripts: `apxs-ng`, `dbmmanage-ng`, `log_server_status-ng`, `logresolve.py`,
  `phf_abuse_log-ng.cgi`, `split-logfile-ng`.

---

## Part 3 — Back-port / cherry-pick recommendation summary

**Tier 1 — good cherry-pick candidates (self-contained, new directives/modules only, low ABI risk):**
- `mod_log_json`, `mod_syslog`, `mod_journald` (loggers — additive)
- `mod_allowhandlers` (small, stable)
- `mod_crypto` (filter; build-gated on APR crypto)
- `mod_proxy_beacon` (actively developed; new directives only)
- Discrete core directives that don't depend on the engine refactor: `LogLevelOverride`,
  `HttpExpectStrict`, `HttpContentLengthHeadZero`, `IndexForbiddenReturn404`, `SessionCookieMaxAge`,
  `MimeOptions`, `MimeMagicDecompression`, `SSLPolicy`, DAV `DAVLockDBType`/`DAVHonorMtimeHeader`.

**Tier 2 — feasible but bundled (need a small framework or careful dependency ordering):**
- `mod_autht_core` + `mod_autht_jwt` + `mod_auth_bearer` (the new "autht" provider category — port
  as a set).
- Async proxy / websocket directives (`ProxyAsync*`, `ProxyWebsocket*`) — depend on async
  write-completion plumbing; verify the underlying core support exists in 2.4.x first.
- `mod_dav` quota / MS extensions (`DAVquota`, `DAVMSext`).

**Tier 3 — do NOT back-port (experimental, obsolete, ABI-breaking, or sample code):**
- The engine refactors in §2C (core/http split, generic-HTTP filter split, `ap_method_mask_t`,
  bucket REQUEST/RESPONSE/HEADERS types, `ssl_var_lookup` signature change) — these are the *defining*
  2.6 ABI changes and intentionally cannot go to a stable line.
- Experimental MPMs `motorz`, `simple`.
- `mod_noloris`, `mod_policy` (experimental/test trees), `mod_ssl_ct` (OpenSSL-3-incompatible),
  `mod_serf`, `mod_lbmethod_rr` (example).
