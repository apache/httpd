# Apache httpd test suite — Python / pytest

> **Provenance / how this fits in `test/`.** This `pytest_suite/` is a
> self-contained snapshot ported from the `httpd-tests` repository (the Python
> port of the classic Perl `Apache::Test` suite). It **coexists alongside**
> `test/pyhttpd/` and `test/modules/` — it does *not* use pyhttpd's framework
> or its root `conftest.py`. It has its own `conftest.py` and `pyproject.toml`,
> so pytest treats this directory as its own rootdir; run it from here (or via
> `test/run-all-tests.sh`), never by pointing pytest at `test/` as a whole.
> The two suites are complementary: this one covers the classic core/modules/
> security/SSL/PHP tests; pyhttpd covers HTTP/2, mod_md (ACME), HTTP/1 and proxy.
> To re-sync from upstream, re-copy the source tree (source files only — exclude
> `.venv/`, caches, and generated artifacts; see `.gitignore`).

A self-contained [pytest](https://pytest.org) port of the Apache httpd
integration test suite (historically the Perl `Apache::Test` framework). It
generates an httpd configuration, compiles the bundled C test modules, starts a
private httpd instance (and optionally PHP-FPM), exercises it over HTTP/HTTPS,
and shuts everything down — all driven by ordinary pytest test functions.

Everything the suite needs at runtime lives under this directory; it
does not read anything from the rest of the repository. The only external
inputs are the **Apache httpd build under test** (located via `apxs`) and,
optionally, a **`php-fpm`** binary for the PHP tests.


## Quick start

```sh
# 1. Create the virtualenv (pytest + httpx). Needs `uv` (https://docs.astral.sh/uv/),
#    or substitute a plain venv -- see "Environment" below.
uv sync

# 2. Run the whole suite against your httpd build.
./runtests.sh --apxs /path/to/your/httpd/bin/apxs

# ...or let it auto-detect apxs / httpd / php-fpm from $PATH or env vars:
APXS=$HOME/root/httpd/bin/apxs PHP_FPM=/usr/sbin/php-fpm8.3 ./runtests.sh
```

`runtests.sh` is the self-evident entry point: it locates the venv's `pytest`,
fills in `--apxs` / `--php-fpm` from environment variables or `$PATH`, clears a
stale CGI socket, and forwards any extra arguments to pytest.

```sh
./runtests.sh tests/t/modules            # run one category
./runtests.sh tests/t/modules/test_alias.py   # run one file
./runtests.sh -k rewrite -v              # any pytest args pass through
./runtests.sh --php-fpm /opt/local/sbin/php-fpm83 tests/t/php   # PHP tests
```


## What you need

| Requirement | How it's provided | Notes |
|---|---|---|
| Python ≥ 3.11 + pytest + httpx | `uv sync` (uses `pyproject.toml` / `uv.lock`) | The only Python deps. |
| A built Apache httpd | `--apxs` / `--httpd` (or `APXS` / `HTTPD` env) | The server under test. Built with shared modules so the suite can load them. |
| `php-fpm` (optional) | `--php-fpm` (or `PHP_FPM` env) | Any PHP 7/8 version. Without it, the PHP tests skip. |
| `openssl` CLI | auto (on `$PATH`) | Used to generate the test SSL CA/certs. |

The suite probes the httpd build (`httpd -v/-V/-l` and its installed
`httpd.conf`) to learn its version, MPM, and available modules, then **skips**
any test whose required module/version isn't present. A passing run therefore
reports a mix of `passed` and `skipped` — skips are expected and fine.


## Command-line options

These are added on top of pytest's own options:

| Option | Meaning |
|---|---|
| `--apxs PATH` | Path to `apxs`. Used to locate `httpd`, the inherited `httpd.conf`, the install prefix, and to compile the C test modules. |
| `--httpd PATH` | Path to the `httpd` binary (defaults to `apxs -q SBINDIR`/httpd). |
| `--php-fpm PATH` | Path to a `php-fpm` binary. Enables the PHP tests by routing `*.php` to a managed FPM pool via `mod_proxy_fcgi`. Version/location-agnostic. |
| `--php-fpm-port N` | TCP port for the managed php-fpm pool (default `8999`). |
| `--defines "A B"` | Extra `-D` defines passed to httpd (e.g. `LDAP`). |


## Layout

```
python/
├── runtests.sh          # entry point (this is how you run the suite)
├── pyproject.toml       # deps + pytest config
├── conftest.py          # fixtures: server lifecycle, the `http` client, need_* gating
├── apache_pytest/       # the framework (port of Apache::Test internals)
│   ├── probe.py         #   inspect the httpd build (version, MPM, modules)
│   ├── config.py        #   generate httpd.conf from t/conf/*.conf.in
│   ├── cmodules.py      #   compile c-modules/ via apxs
│   ├── sslca.py         #   generate the SSL test CA + certs
│   ├── fpm.py           #   manage a php-fpm daemon
│   ├── server.py        #   start/stop httpd
│   ├── client.py        #   the `http` fixture (HTTP/HTTPS + raw sockets)
│   ├── rawsocket.py     #   raw-socket helper for protocol tests
│   └── testapi.py       #   t_cmp() + need_* markers used by tests
├── tests/
│   ├── test_framework_smoke.py   # framework self-tests
│   ├── test_config_parity.py     # dev-only: diff vs the Perl reference (skips if absent)
│   └── t/               # the translated suite, mirroring the historical t/ layout
│       ├── apache/      #   core HTTP/protocol tests
│       ├── modules/     #   per-module tests (proxy, rewrite, headers, ...)
│       ├── ssl/         #   TLS / client-cert tests
│       ├── security/    #   CVE regression tests
│       ├── php/         #   PHP tests (need --php-fpm)
│       ├── http11/ filter/ protocol/ apr/ ab/
│       └── ...
├── t/                   # runtime assets (self-contained copy)
│   ├── conf/            #   *.conf.in templates + ssl/
│   ├── htdocs/          #   document root served by the test server
│   └── php-fpm/         #   php-fpm pool assets
└── c-modules/           # C test-module sources, compiled via apxs at runtime
```

Generated files (`t/conf/*.conf`, `t/logs/`, `t/conf/ssl/ca/`) are produced at
run time and are safe to delete between runs.


## Adding a new test

Tests are plain pytest functions. They receive the running server through the
`http` fixture and assert on its responses. Put a test in the category
directory that matches what it exercises, in a file named `test_<name>.py`, with
functions named `test_*`.

### 1. Minimal example

`tests/t/modules/test_status.py`:

```python
import re
from apache_pytest import need_module

@need_module("status")               # skip unless mod_status is loaded
def test_server_status(http):
    servername = http.vars("servername")
    body = http.GET_BODY("/server-status")
    assert re.search(f"Apache Server Status for {servername}", body, re.I)
```

That's the whole pattern:

* **`http`** is the fixture giving you the running server. Request methods return
  an [`httpx.Response`](https://www.python-httpx.org/api/#response).
* **`@need_module("x")`** (and friends, below) gate the test — if the
  requirement isn't met, the test is skipped at collection time. This is the
  Python equivalent of the Perl `plan tests => N, need_module 'x'`.
* Use plain `assert`. Add a message for context: `assert cond, "what failed"`.

### 2. The `http` fixture API

Requests (bare paths are resolved against the running server; absolute URLs pass
through):

| Method | Returns | Notes |
|---|---|---|
| `http.GET(path, **kw)` | `Response` | also `HEAD`, `OPTIONS`, `PUT`, `POST` |
| `http.POST(path, content=b"...", **kw)` | `Response` | `content=` is the request body |
| `http.GET_BODY(path)` | `str` | response text |
| `http.GET_RC(path)` | `int` | status code (returns `500` on a transport/TLS error, like LWP) |
| `http.POST_BODY(path, content=...)` | `str` | |

Useful keyword args (forwarded to httpx): `headers={...}`, `redirect_ok=True`
(follow 3xx — off by default), `cert="client_ok"` (present a client certificate;
see SSL below), `auth=httpx.BasicAuth(u, p)`.

Server introspection / configuration:

| Call | Purpose |
|---|---|
| `http.vars("servername")` | a value from the generated config's vars table (`servername`, `port`, `documentroot`, `t_logs`, ...) |
| `http.have_module("rewrite")` | is a module loaded? (runtime check, in addition to the `@need_module` gate) |
| `http.have_min_apache_version("2.4.50")` | runtime version gate |
| `http.apxs("INCLUDEDIR")` | query the build's `apxs` |
| `http.scheme("https")` | switch subsequent requests to HTTPS (the mod_ssl vhost) |
| `http.module("proxy_http_reverse")` | target a specific configured virtual host by module name |
| `http.vhost_url("mod_headers", "/x")` / `http.hostport("mod_ssl")` | build a URL / host:port for a named vhost |

Comparison helper (a faithful port of Perl's `t_cmp`): `t_cmp(received,
expected)` returns a bool. If `expected` is a compiled regex it does a
`re.search`; otherwise it compares by string equality. Use it when you want the
regex-or-equal behavior:

```python
from apache_pytest import t_cmp
assert t_cmp(r.status_code, 200), "status"
assert t_cmp(r.headers.get("Allow", ""), re.compile("OPTIONS")), "Allow header"
```

### 3. Requirement markers (skip gating)

Import from `apache_pytest` and apply as decorators. A test is skipped (at
collection time) unless every marker is satisfied by the probed httpd build:

```python
from apache_pytest import (
    need_module, need_min_apache_version, need_cgi, need_ssl, need_php, need_lwp,
)

@need_module("proxy", "setenvif")       # all named modules must be loaded
@need_min_apache_version("2.4.49")      # server must be >= this version
def test_something(http):
    ...
```

| Marker | Satisfied when |
|---|---|
| `need_module("x", ...)` | every named module is loaded (bare name, `mod_x`, or `mod_x.c` all accepted; bundled C test modules count) |
| `need_min_apache_version("2.4.x")` | server version ≥ given |
| `need_cgi()` | `mod_cgi` or `mod_cgid` present |
| `need_ssl()` | `mod_ssl` present |
| `need_php()` | a PHP SAPI module **or** `--php-fpm` (with `mod_proxy_fcgi`) is available |
| `need_lwp()` | always (kept for 1:1 readability with the Perl originals) |

For *conditional* logic inside a test (not whole-test gating), use the runtime
checks and `pytest.skip`:

```python
def test_versioned(http):
    if not http.have_min_apache_version("2.4.60"):
        pytest.skip("needs >= 2.4.60")
    ...
```

### 4. Parametrizing (loops in the Perl original)

Where a Perl test looped over cases, use `@pytest.mark.parametrize`:

```python
import pytest
from apache_pytest import need_module, t_cmp

CASES = [("/index.html", 200), ("/missing", 404)]

@need_module("alias")
@pytest.mark.parametrize(("path", "code"), CASES, ids=lambda c: str(c))
def test_alias(http, path, code):
    assert t_cmp(http.GET(path).status_code, code), path
```

### 5. SSL / client certificates

Switch the client to HTTPS and (optionally) present one of the generated test
client certs (`client_ok`, `client_snakeoil`, `client_revoked`, `client_colon`):

```python
from apache_pytest import need_ssl

@need_ssl()
def test_client_cert(http):
    http.scheme("https")
    assert http.GET_RC("/require/asf/index.html", cert="client_ok") == 200
    assert http.GET_RC("/require/asf/index.html", cert=None) != 200
```

The framework generates the CA/server/client certificates automatically and the
client trusts the test CA. TLS 1.3 post-handshake auth works.

### 6. Raw sockets (protocol-level tests)

For tests that send hand-crafted (often malformed) requests and read the raw
response — e.g. many CVE regressions:

```python
import re
from apache_pytest import need_module, t_cmp

@need_module("proxy")
def test_bad_request(http):
    http.module("cve_2011_3368")           # select the vhost
    sock = http.vhost_socket()             # raw socket to that vhost's port
    try:
        sock.print(
            "GET @localhost/foo HTTP/1.1\r\n"
            f"Host: {http.hostport()}\r\n\r\n"
        )
        line = sock.getline() or ""
        assert t_cmp(line, re.compile(r"^HTTP/1\.. 400")), "rejected"
    finally:
        sock.close()
```

`VhostSocket` offers `.print(data)`, `.getline()`, `.read()`, `.connected`,
`.socket_trace(True)`, and `.close()`; it's also a context manager.

> **Tip for HTTP/1.1 raw requests:** after sending, half-close the write side
> (`sock._sock.shutdown(socket.SHUT_WR)`) so a keep-alive connection doesn't
> block on the read timeout.

### 7. Server-side config and document root

If a test needs server configuration or files served from disk:

* **Static files / scripts** go under `t/htdocs/` (the document root). A request
  for `/foo/bar.html` is served from `t/htdocs/foo/bar.html`.
* **Per-module httpd config** lives in the `t/conf/*.conf.in` templates, which
  use `@TOKEN@` placeholders (`@SERVERROOT@`, `@DOCUMENTROOT@`, `@PORT@`,
  `@SSL_MODULE@`, ...) and `<VirtualHost module_name>` blocks that the framework
  rewrites to allocated ports. Add config to the relevant `.conf.in` (most
  general-purpose config is in `t/conf/extra.conf.in`); a request can target a
  named vhost with `http.module("name")` / `http.vhost_url("name")`.
* **CGI / helper scripts** can be shipped as `*.PL` templates under `t/htdocs/`;
  they're generated into executable scripts at run time.

### 8. Conventions

* Mirror the historical layout: a test for `t/<category>/<name>.t` becomes
  `tests/t/<category>/test_<name>.py` (hyphens in the name → underscores, e.g.
  `CVE-2011-3368.t` → `test_CVE_2011_3368.py`).
* Keep a short module docstring noting what's tested (and, for ports, the Perl
  original). If the docstring quotes Perl containing backslashes, make it a raw
  string (`r"""..."""`).
* A new test must end **passing or skipping** — never erroring. If it can't run
  in some environment, gate it with a `need_*` marker or `pytest.skip` with a
  clear reason rather than letting it fail.


## Notes & gotchas

* **`uv run` vs the venv.** `runtests.sh` invokes `.venv/bin/pytest` directly so
  it works in environments where `uv run` is shimmed/unavailable. If you call
  pytest yourself, use `.venv/bin/pytest` (or activate the venv).
* **Same-named test modules** across categories (e.g. `ssl/test_all.py` and
  `php/test_all.py`) coexist thanks to `--import-mode=importlib` +
  `pythonpath=["."]` in `pyproject.toml`.
* **Stale CGI socket.** A killed run can leave `t/logs/cgisock*`, which breaks a
  fresh start; `runtests.sh` removes it automatically.
* **No orphans.** The server is launched in its own process group and reaped on
  teardown (including after a failed start); php-fpm is stopped likewise. After
  a run, `pgrep -f 'bin/httpd'` and `pgrep -f php-fpm` should be empty.
* **`test_config_parity.py`** is a development-only check that diffs the
  generated config against a freshly Perl-generated reference. It skips cleanly
  when the Perl `Apache::Test` framework isn't present, so it's inert in a
  released, standalone copy of this directory.
