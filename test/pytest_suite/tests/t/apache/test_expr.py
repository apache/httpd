r"""Translated from t/apache/expr.t -- the ap_expr expression parser.

For each expression a per-directory ``.htaccess`` is written containing::

    <If "EXPR">
        Require all denied
    </If>

and ``/apache/expr/index.html`` is fetched: a 403 means the expression
evaluated true, 200 means false, 500 means a parse error. Expectations: 1 ->
true (403), 0 -> false (200), None -> parse error (500). After all cases the
error log is scanned to confirm there were no "internal evaluation error"
entries.

Needs: need_lwp, mod_authz_core, need_min_apache_version('2.3.9').
"""

import re
from pathlib import Path

import httpx

from apache_pytest import need_lwp, need_min_apache_version, need_module

# (expression, expected) where expected is 1 (true/403), 0 (false/200) or
# None (parse error/500).
STATIC_CASES = [
    ("true", 1),
    ("false", 0),
    ("foo", None),
    # integer comparison
    ("1 -eq 01", 1),
    ("1 -eq  2", 0),
    ("1 -ne  2", 1),
    ("1 -ne  1", 0),
    ("1 -lt 02", 1),
    ("1 -lt  1", 0),
    ("1 -le  2", 1),
    ("1 -le  1", 1),
    ("2 -gt  1", 1),
    ("1 -gt  1", 0),
    ("2 -ge  1", 1),
    ("1 -ge  1", 1),
    ("1 -gt -1", 1),
    # string comparison
    ("'aa' == 'aa'", 1),
    ("'aa' == 'b'", 0),
    ("'aa' =  'aa'", 1),
    ("'aa' =  'b'", 0),
    ("'aa' != 'b'", 1),
    ("'aa' != 'aa'", 0),
    ("'aa' <  'b'", 1),
    ("'aa' <  'aa'", 0),
    ("'aa' <= 'b'", 1),
    ("'aa' <= 'aa'", 1),
    ("'b'  >  'aa'", 1),
    ("'aa' >  'aa'", 0),
    ("'b'  >= 'aa'", 1),
    ("'aa' >= 'aa'", 1),
    # string operations/whitespace handling
    ("'a' . 'b' . 'c' = 'abc'", 1),
    ("'a' .'b'. 'c' = 'abc'", 1),
    (" 'a' .'b'. 'c'='abc' ", 1),
    ("'a1c' = 'a'. 1. 'c'", 1),
    ("req('foo') . 'bar' = 'bar'", 1),
    ("%{req:foo} . 'bar' = 'bar'", 1),
    ("'x'.%{req:foo} . 'bar' = 'xbar'", 1),
    ("%{req:User-Agent} . 'bar' != 'bar'", 1),
    ("'%{req:User-Agent}' . 'bar' != 'bar'", 1),
    ("'%{TIME}' . 'bar' != 'bar'", 1),
    ("%{TIME} != ''", 1),
    # string lists
    ("'a' -in { 'b', 'a' } ", 1),
    ("'a' -in { 'b', 'c' } ", 0),
    # regexps
    (" 'abc' =~ /bc/ ", 1),
    (" 'abc' =~ /BC/i ", 1),
    (" 'abc' !~ m!bc! ", 0),
    (" 'abc' !~ m!BC!i ", 0),
    (" $0 == '' ", 1),
    (" $1 == '' ", 1),
    (" $9 == '' ", 1),
    (" '$0' == '' ", 1),
    (" 'abc' =~ /(bc)/ && $0 == 'bc' ", 1),
    (" 'abc' =~ /(bc)/ && $1 == 'bc' ", 1),
    (" 'abc' =~ /b(.)/ && $1 == 'c' ", 1),
    (" 'abc' =~ /bc/ && $0 == '' ", 1),
    (" 'abc' =~ /(bc)/ && 'xy' =~ /x/ && $0 == 'bc' ", 1),
    (" 'abcdefghijklm' =~ /(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)(l)/ && $2 == 'c' ", 1),
    # variables
    (r"%{TIME_YEAR} =~ /^\d{4}$/", 1),
    (r"%{TIME_YEAR} =~ /^\d{3}$/", 0),
    ("%{TIME_MON}  -gt 0 && %{TIME_MON}  -le 12 ", 1),
    ("%{TIME_DAY}  -gt 0 && %{TIME_DAY}  -le 31 ", 1),
    ("%{TIME_HOUR} -ge 0 && %{TIME_HOUR} -lt 24 ", 1),
    ("%{TIME_MIN}  -ge 0 && %{TIME_MIN}  -lt 60 ", 1),
    ("%{TIME_SEC}  -ge 0 && %{TIME_SEC}  -lt 60 ", 1),
    (r"%{TIME} =~ /^\d{14}$/", 1),
    ("%{API_VERSION} -gt 20101001 ", 1),
    ("%{REQUEST_METHOD} == 'GET' ", 1),
    ("'x%{REQUEST_METHOD}' == 'xGET' ", 1),
    ("'x%{REQUEST_METHOD}y' == 'xGETy' ", 1),
    ("%{REQUEST_SCHEME} == 'http' ", 1),
    ("%{HTTPS} == 'off' ", 1),
    ("%{REQUEST_URI} == '/apache/expr/index.html' ", 1),
    # request headers
    ("%{req:referer}     = 'SomeReferer' ", 1),
    ("req('Referer')     = 'SomeReferer' ", 1),
    ("http('Referer')    = 'SomeReferer' ", 1),
    ("%{HTTP_REFERER}    = 'SomeReferer' ", 1),
    ("req('User-Agent')  = 'SomeAgent'   ", 1),
    ("%{HTTP_USER_AGENT} = 'SomeAgent'   ", 1),
    ("req('SomeHeader')  = 'SomeValue'   ", 1),
    ("req('SomeHeader2') = 'SomeValue'   ", 0),
    # functions
    ("toupper('abC12d') = 'ABC12D' ", 1),
    ("tolower('abC12d') = 'abc12d' ", 1),
    ("escape('?')       = '%3f' ", 1),
    ("unescape('%3f')   = '?' ", 1),
    ("toupper(escape('?')) = '%3F' ", 1),
    ("tolower(toupper(escape('?'))) = '%3f' ", 1),
    ("%{toupper:%{escape:?}} = '%3F' ", 1),
    # unary operators
    ("-n ''", 0),
    ("-z ''", 1),
    ("-n '1'", 1),
    ("-z '1'", 0),
    # IP match
    ("-R 'abc'", None),
    ("-R %{REMOTE_ADDR}", None),
    ("-R '240.0.0.0'", 0),
    ("-R '240.0.0.0/8'", 0),
    ("-R 'ff::/8'", 0),
    ("-R '127.0.0.1' || -R '::1'", 1),
    ("'127.0.0.1' -ipmatch 'abc'", None),
    ("'127.0.0.1' -ipmatch %{REMOTE_ADDR}", None),
    ("'127.0.0.1' -ipmatch '240.0.0.0'", 0),
    ("'127.0.0.1' -ipmatch '240.0.0.0/8'", 0),
    ("'127.0.0.1' -ipmatch 'ff::/8'", 0),
    ("'127.0.0.1' -ipmatch '127.0.0.0/8'", 1),
    # fn/strmatch
    ("'foo' -strmatch '*o'", 1),
    ("'fo/o' -strmatch 'f*'", 1),
    ("'foo' -strmatch 'F*'", 0),
    ("'foo' -strcmatch 'F*'", 1),
    ("'foo' -strmatch 'g*'", 0),
    ("'foo' -strcmatch 'g*'", 0),
    ("'a/b' -fnmatch 'a*'", 0),
    ("'a/b' -fnmatch 'a/*'", 1),
    # error handling
    ("'%{foo:User-Agent}' != 'bar'", None),
    ("%{foo:User-Agent} != 'bar'", None),
    ("foo('bar') = 'bar'", None),
    ("%{FOO} != 'bar'", None),
    ("'bar' = bar", None),
]


_PYOP = {"||": "or", "&&": "and"}


def _neg(v):
    return 0 if v else 1


def _bool_cases():
    """Reproduce the Perl bool-logic case generation (0..2 operators, with '!')."""
    bool_base = [("true", 1)]
    # Perl appends '!'-prefixed variants of bool_base to bool_base.
    bool_base = bool_base + [(f"!{e}", _neg(r)) for e, r in bool_base]

    cases = []
    for e1, r1 in bool_base:
        cases.append((e1, r1))
        for e2, r2 in bool_base:
            cases.append((f"{e1} && {e2}", 1 if (r1 and r2) else 0))
            cases.append((f"{e1} || {e2}", 1 if (r1 or r2) else 0))
            for e3, r3 in bool_base:
                for op1 in ("||", "&&"):
                    for op2 in ("||", "&&"):
                        # Perl evaluates `r1 op1 r2 op2 r3` with `&&` binding
                        # tighter than `||` (same precedence as ap_expr); map
                        # || -> `or`, && -> `and` and let Python honor it.
                        py = f"{r1} {_PYOP[op1]} {r2} {_PYOP[op2]} {r3}"
                        r = eval(py)  # noqa: S307 - operands are literal 0/1
                        cases.append((f"{e1} {op1} {e2} {op2} {e3}", 1 if r else 0))
    return cases


def _build_cases(http):
    cases = list(STATIC_CASES)

    bool_cases = _bool_cases()
    cases += bool_cases
    cases += [(f"!({e})", _neg(r)) for e, r in bool_cases]

    serverroot = http.vars("serverroot")
    file_foo = f"{serverroot}/htdocs/expr/index.html"
    dir_foo = f"{serverroot}/htdocs/expr"
    file_notexist = f"{serverroot}/htdocs/expr/none"
    file_zero = f"{serverroot}/htdocs/expr/zero"
    url_foo = "/apache/"
    url_notexist = "/apache/expr/none"

    cases.append((rf"file('{file_foo}') = 'foo\n' ", 1))

    if http.have_min_apache_version("2.3.13"):
        cases += [
            (f"filesize('{file_foo}') = 4 ", 1),
            (f"filesize('{file_notexist}') = 0 ", 1),
            (f"filesize('{file_zero}') = 0 ", 1),
            (f"-d '{file_foo}' ", 0),
            (f"-e '{file_foo}' ", 1),
            (f"-f '{file_foo}' ", 1),
            (f"-s '{file_foo}' ", 1),
            (f"-d '{file_zero}' ", 0),
            (f"-e '{file_zero}' ", 1),
            (f"-f '{file_zero}' ", 1),
            (f"-s '{file_zero}' ", 0),
            (f"-d '{dir_foo}' ", 1),
            (f"-e '{dir_foo}' ", 1),
            (f"-f '{dir_foo}' ", 0),
            (f"-s '{dir_foo}' ", 0),
            (f"-d '{file_notexist}' ", 0),
            (f"-e '{file_notexist}' ", 0),
            (f"-f '{file_notexist}' ", 0),
            (f"-s '{file_notexist}' ", 0),
            (f"-F '{file_foo}' ", 1),
            (f"-F '{file_notexist}' ", 0),
            (f"-U '{url_foo}' ", 1),
            (f"-U '{url_notexist}' ", 0),
        ]

    if http.have_min_apache_version("2.4.5"):
        cases += [
            ("sha1('foo') = '0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33' ", 1),
            ("md5('foo') = 'acbd18db4cc2f85cedef654fccc4a4d8' ", 1),
            ("base64('foo') = 'Zm9v' ", 1),
            ("unbase64('Zm9vMg==') = 'foo2' ", 1),
        ]

    return cases


def _write_htaccess(http, expr):
    file = Path(http.vars("serverroot")) / "htdocs" / "apache" / "expr" / ".htaccess"
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(f'<If "{expr}">\n    Require all denied\n</If>\n')


@need_lwp()
@need_module("mod_authz_core")
@need_min_apache_version("2.3.9")
def test_expr(http):
    error_log = Path(http.vars("t_logs")) / "error_log"
    start = error_log.stat().st_size if error_log.exists() else 0

    rc_map = {500: "parse error", 403: "true", 200: "false"}
    for expr, expect in _build_cases(http):
        _write_htaccess(http, expr)
        req_headers = {
            "SomeHeader": "SomeValue",
            "User-Agent": "SomeAgent",
            "Referer": "SomeReferer",
        }
        try:
            response = http.GET("/apache/expr/index.html", headers=req_headers)
        except httpx.TransportError:
            # A prior parse-error (500) response may set Connection: close,
            # leaving a stale pooled socket; retry once on a fresh connection.
            response = http.GET("/apache/expr/index.html", headers=req_headers)
        rc = response.status_code
        if expect is None:
            assert rc == 500, f'Should get parse error for "{expr}", got {rc_map.get(rc, rc)}'
        elif expect:
            assert rc == 403, f'"{expr}" should evaluate to true, got {rc_map.get(rc, rc)}'
        else:
            assert rc == 200, f'"{expr}" should evaluate to false, got {rc_map.get(rc, rc)}'

    with error_log.open("r", errors="replace") as fh:
        fh.seek(start)
        log = fh.read()
    evalerrors = [ln for ln in log.splitlines() if re.search(r"internal evaluation error", ln, re.IGNORECASE)]
    assert not evalerrors, f"found internal evaluation errors: {evalerrors}"
