# Google Patch Rewards — Apache httpd local draft notes

**Date:** 2026-09-11 (America/Chicago)  
**Do not claim yet:** need upstream merge + ≥30 days, then https://bughunters.google.com/report/patch_rewards

## Chosen target + why

- **Project:** Apache HTTP Server (httpd) (Tier-1 · High-profile web and mail servers — Google Patch Rewards memory-safety track)
- **Upstream:** https://github.com/apache/httpd (mirror of https://svn.apache.org/repos/asf/httpd/httpd/; prefer `trunk`)
- **Local clone:** `/workspace/google-patch-httpd`
- **Branch:** `local/varbuf-fbounds-safety` (from `trunk`)
- **Why this target:**
  1. Widely deployed HTTP server; `ap_varbuf` backs config getline, expr eval, authz/groupfile, proxy_html, substitute, and related paths that grow buffers from untrusted / config / request-derived input.
  2. Clear, mergeable first-CL scope: **one** buffer+capacity pair — `struct ap_varbuf` (`buf` ↔ `avail`) — textbook `__sized_by`, not a whole-tree sweep.
  3. Same pattern as libpng / libwebp / giflib / lz4 / zstd / libzip / lighttpd: **inert macros** when the flag is off; experimental Clang `-fbounds-safety` only when explicitly enabled.
  4. Stable layout preserved (no field reorder); annotation links `buf` to its **byte capacity** (`avail + 1`, because `avail` is documented as allocated size minus the final NUL).
  5. Not already done upstream (no `__sized_by` / `-fbounds-safety` in tree; GitHub issue/PR search for fbounds/sized_by/counted_by/bounds-safety on `apache/httpd` returned **0** on 2026-09-11).
  6. AI CONTRIBUTING gate clear (no CONTRIBUTING.md; no AI ban in README / SECURITY.md / STATUS / ABOUT_APACHE / `.github/workflows`).

**Why `buf`/`avail` over `strlen` or other containers:** `avail` is the allocation companion (capacity minus one for the trailing NUL); `strlen` is the live length (or `AP_VARBUF_UNKNOWN`) and is not the correct sized_by companion. APR buckets / brigade buffers are natural follow-ups.

**ABI / layout note:** Field order is preserved (`buf` remains before `avail`). Small-grow path already assigned **capacity then pointer**; this CL flips the **large-grow** path (and init/free) to the same order. No `ap_mmn.h` bump — annotations are type sugar / empty macros and do not change layout or ABI.

## Security benefit

`struct ap_varbuf` is the shared resizable buffer used across config parsing (`ap_varbuf_cfg_getline`), expression evaluation, and several modules. Callers already track capacity in `avail`, but the compiler cannot see that `buf` is bounded by that field (+1 for the NUL byte the API always reserves).

This draft:

1. Introduces `include/ap_bounds_safety.h` with `AP_SIZED_BY` / `AP_SIZED_BY_OR_NULL` / `AP_COUNTED_BY*` (empty by default).
2. Annotates **only** `ap_varbuf.buf` → `AP_SIZED_BY_OR_NULL(avail + 1)` (byte capacity; OR_NULL for `ap_varbuf_free()`'s NULL).
3. Keeps existing field order. Makes large-grow (and init/free) assign **capacity before pointer**; documents small-grow already did.
4. Wires optional CMake `ENABLE_FBOUNDS_SAFETY` / autotools `--enable-fbounds-safety` (default **OFF**) → `-DAP_SUPPORT_FBOUNDS_SAFETY` + `-fbounds-safety`.

**Default builds are unchanged:** macros expand to nothing; no new runtime checks without the experimental flag. New header installs with `include/*.h` (same as other public headers); macros remain inert unless the opt-in is enabled.

## Files changed

| File | Change |
|------|--------|
| `include/ap_bounds_safety.h` | **New** — inert / Clang bounds macros |
| `include/util_varbuf.h` | Include header; annotate `ap_varbuf.buf` |
| `server/util.c` | Capacity-first assign in large-grow / init / free; comment on small-grow |
| `CMakeLists.txt` | `ENABLE_FBOUNDS_SAFETY` option OFF + apply flags when ON |
| `configure.in` | `--enable-fbounds-safety` (default no) |
| `NOTES.md` | This file |

## Verified locally 2026-09-11

| Check | Result |
|-------|--------|
| Default `--enable-fbounds-safety` unset (OFF) `./configure` + `make -j` (httpd + modules) | **PASS** (gcc; `httpd` + `server/libmain.a`; configure printed `ENABLE_FBOUNDS_SAFETY disabled`) |
| `ENABLE_FBOUNDS_SAFETY=ON` / `--enable-fbounds-safety` | **Not feasible on this box** — needs Clang with `-fbounds-safety` / `ptrcheck.h` |

## How to build / test

Default (macros inert — must stay green):

```sh
# Autotools (primary Unix path)
./buildconf
./configure --enable-fbounds-safety=no
make -j
# or CMake (primarily Windows / documented in README.cmake):
cmake -S . -B build -DENABLE_FBOUNDS_SAFETY=OFF
cmake --build build -j
```

With experimental bounds-safety toolchain (maintainers / CI; **not** available on this box — no Clang/`ptrcheck.h`):

```sh
./configure --enable-fbounds-safety \
  CC=<clang-with-fbounds-safety>
make -j
# or:
cmake -S . -B build-fbs -DENABLE_FBOUNDS_SAFETY=ON \
  -DCMAKE_C_COMPILER=<clang-with-fbounds-safety>
cmake --build build-fbs -j
```

## Upstream submit plan

1. Open a focused GitHub PR against `apache/httpd` branch **`trunk`** (or send to `dev@httpd.apache.org` per project preference / GitBox).
2. Proposed title: `varbuf: add optional -fbounds-safety annotations for struct ap_varbuf`
3. Frame as secure-by-design / Safe Buffers-style systematization of the existing buf+avail pair; cite libwebp/libpng/lz4/zstd/libzip prior art and Google Patch Rewards memory-safety goals.
4. Emphasize: default build behavior unchanged; flag OFF; no PoC / no CVE claim; public layout field order unchanged; no MMN bump.
5. Do **not** claim on https://bughunters.google.com/report/patch_rewards until **merge + ≥30 days**.

## Follow-ups (separate CLs)

- Other core buffer+size pairs on request/config paths as diagnostics under a real `-fbounds-safety` build dictate
- Module-local growable buffers that mirror `ap_varbuf` patterns
- APR brigade / bucket data pointers where a stable capacity companion exists (coordinate with APR)

## AI gate

- **No `CONTRIBUTING.md`** in upstream tree.
- Searched README, SECURITY.md, STATUS, ABOUT_APACHE, `.github/workflows/` — **no AI / LLM / Copilot ban**.
- **AI gate: CLEAR** (no ban found).

## Overlap check

- In-tree: no `__sized_by` / `-fbounds-safety` / `ptrcheck.h` references.
- GitHub `apache/httpd` search (fbounds / sized_by / counted_by / bounds-safety): **0** issues/PRs (2026-09-11).
- **PARK ON OVERLAP:** if an overlapping annotation PR appears before submit, do not race — coordinate or defer.

## Status

**LOCAL DRAFT ONLY** — commit on `local/varbuf-fbounds-safety`. Do **not** push/PR from this agent run. Still **no claim** until merge + ≥30 days unreverted.
