r"""Translated from t/apache/expr_string.t -- ap_expr string interpolation,
exercised through mod_log_debug's LogMessage directive.

For each (expr, expected) a per-directory ``.htaccess`` with ``LogMessage EXPR``
is written, the page is fetched, and the error log is scanned for the resulting
``log_debug:info`` line; the interpolated result is extracted and compared. An
undefined expectation means the request should produce a 500 (parse error). The
log is also checked for the absence of evaluation errors / scanner-jammed
messages.

The Perl original used t_start/t_finish_error_log_watch; here we snapshot the
error_log file position around each request.

Needs: need_lwp, mod_log_debug.
"""

import re
import time
from pathlib import Path

import httpx

from apache_pytest import need_lwp, need_module, t_cmp

# (expr-as-written-in-config, expected interpolated value or None for parse error)
STATIC_CASES = [
    ("foo", "foo"),
    ("%{req:SomeHeader}", "SomeValue"),
    ("%{", None),
    ("%", "%"),
    ("}", "}"),
    (r"\"", '"'),
    (r"\'", "'"),
    (r'"\%{req:SomeHeader}"', "%{req:SomeHeader}"),
    ("%{tolower:IDENT}", "ident"),
    ("%{tolower:%{REQUEST_METHOD}}", "get"),
]


def _build_cases(http):
    cases = list(STATIC_CASES)
    if http.have_min_apache_version("2.5"):
        san_one = (
            "email:<redacted1>, email:<redacted2>, "
            "IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1, "
            "IP Address:192.168.169.170"
        )
        san_tuple = (
            "'email:<redacted1>', 'email:<redacted2>', "
            "'IP Address:127.0.0.1', 'IP Address:0:0:0:0:0:0:0:1', "
            "'IP Address:192.168.169.170'"
        )
        san_list_one = "{ '" + san_one + "' }"
        san_list_tuple = "{ " + san_tuple + " }"
        cases += [
            ('"%{tolower:%{:toupper(%{REQUEST_METHOD}):}}"', "get"),
            (f'"%{{: join {san_list_one} :}}"', san_one),
            (f'"%{{: join({san_list_tuple}, \', \') :}}"', san_one),
            ("'%{tolower:\"IDENT\"}'", '"ident"'),
            (
                f'"%{{: \'IP Address:%{{REMOTE_ADDR}}\' -in split/, /, join {san_list_one} :}}"',
                "true",
            ),
        ]
    return cases


def _write_htaccess(http, expr):
    file = Path(http.vars("serverroot")) / "htdocs" / "apache" / "expr" / ".htaccess"
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(f"LogMessage {expr}\n")


# Extract the LogMessage'd value out of an error-log line. Mirrors the Perl
# regex: skip 4 bracketed fields ([time] [level] [pid] [client]) then capture
# the message up to a trailing ", referer" or " (log_transaction".
_MSG_RE = re.compile(
    r"^(?:\[[^\]]+\]\ ){4}(.*?)(?:,\ referer|\ \(log_transaction)",
    re.VERBOSE,
)


@need_lwp()
@need_module("mod_log_debug")
def test_expr_string(http):
    error_log = Path(http.vars("t_logs")) / "error_log"

    for expr, expect in _build_cases(http):
        _write_htaccess(http, expr)

        start = error_log.stat().st_size if error_log.exists() else 0
        req_headers = {
            "SomeHeader": "SomeValue",
            "User-Agent": "SomeAgent",
            "Referer": "SomeReferer",
        }
        try:
            response = http.GET("/apache/expr/index.html", headers=req_headers)
        except httpx.TransportError:
            # A prior 500 (parse error) response may set Connection: close,
            # leaving a stale pooled socket; retry once on a fresh connection.
            response = http.GET("/apache/expr/index.html", headers=req_headers)
        time.sleep(0.25)
        with error_log.open("r", errors="replace") as fh:
            fh.seek(start)
            loglines = fh.read().splitlines()

        evalerrors = [
            ln
            for ln in loglines
            if re.search(r"internal evaluation error|flex scanner jammed", ln, re.IGNORECASE)
        ]
        assert not evalerrors, f"eval errors for {expr!r}: {evalerrors}"

        rc = response.status_code
        if expect is None:
            assert rc == 500, f'Should get parse error (500) for "{expr}", got {rc}'
        else:
            assert rc == 200, f"Expected 200, got {rc} for {expr!r}"
            msgs = [ln for ln in loglines if "log_debug:info" in ln]
            assert len(msgs) == 1, f"expected 1 message, got {len(msgs)}: {msgs}"
            m = _MSG_RE.match(msgs[0])
            assert m, f"Can't extract expr result from log message: {msgs}"
            result = m.group(1)
            assert t_cmp(result, expect), f"log message {msgs} didn't match"
