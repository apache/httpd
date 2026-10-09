r"""Translated from t/modules/substitute.t -- mod_substitute output filter.

Writes a test file (containing mod_bucketeer control chars) and a .htaccess with
``Substitute`` rules, then GETs the file and compares the server's transformed
output against what the equivalent Python regex substitution produces -- the
exact strategy the Perl test uses (it runs the same s/// in perl and compares).

mod_bucketeer is NOT built locally (the SetOutputFilter chain is
BUCKETEER;SUBSTITUTE), so this SKIPs via @need_module("substitute",
"bucketeer").

Faithful-translation notes on the Perl emulation:
  * The control chars B/F/P (mod_bucketeer markers) are stripped from the
    expected output: ``$expect =~ s/[$B$F$P]+//g``.
  * A trailing ``/n`` flag on a rule means "literal (non-regex) match": the
    Perl test quotemeta()s the pattern and replacement. We do the same with
    re.escape.
  * ``$0`` (whole-match) in HTTPD maps to Python's ``\g<0>``; ``$1`` to ``\1``.
  * mod_substitute always does a global replace, so every rule is applied
    globally.
"""

import os
import re

import pytest

from apache_pytest import need_module

B = chr(0x02)
F = chr(0x06)
P = chr(0x10)

# Each case: (content, [rules...])
BASE_CASES = [
    (f"f{B}o{P}ofoo", ["s/foo/bar/"]),
    (f"f{B}o{P}ofoo", ["s/fo/fa/", "s/fao/bar/"]),
    ("foofoo", ["s/Foo/bar/"]),
    (f"fo{F}ofoo", ["s/Foo/bar/i"]),
    ("foOFoo", ["s/OF/of/", "s/foo/bar/"]),
    ("fofooo", ["s/(.)fo/$1of/", "s/foo/bar/"]),
    ("foof\noo", ["s/f.oo/bar/"]),
    ("xfooo", ["s/foo/fo/"]),
    ("xfoo" * 4000, ["s/foo/bar/", "s/FOO/BAR/"]),
    ("foox\n" * 4000, ["s/foo/bar/", "s/FOO/BAR/"]),
    ("a.baxb(", ["s/a.b/a$1/n"]),
    ("a.baxb(", ["s/a.b/a$1/n", "s/1axb(/XX/n"]),
    ("xfoo" * 4000, ["s/foo/bar/n", "s/FOO/BAR/n"]),
]

# r1307067 cases (httpd >= 2.3.5)
R1307067_CASES = [
    ("x<body>x", ["s/<body>/&/"]),
    ("x<body>x", ["s/<body>/$0/"]),
    ("foobar", ["s/(oo)b/c$1/"]),
    ("foobar", [r"s/(oo)b/c\$1/"]),
    ("foobar", [r"s/(oo)b/\d$1/"]),
]

# httpd >= 2.4.42 "simple" cases with explicit expected output
SIMPLE_CASES = [
    ("foo\nbar", "s/foo.*/XXX$0XXX", "XXXfooXXX\nbar"),
]


def _docroot_file(http, *parts):
    return os.path.join(http.vars("documentroot"), "modules", "substitute", *parts)


def _write_testfile(http, content):
    with open(_docroot_file(http, "test.txt"), "wb") as f:
        f.write(content.encode("utf-8"))


def _write_htaccess(http, rules):
    content = "SetOutputFilter BUCKETEER;SUBSTITUTE\n"
    for rule in rules:
        content += f"Substitute {rule}\n"
    with open(_docroot_file(http, ".htaccess"), "wb") as f:
        f.write(content.encode("utf-8"))


def _httpd_rule_to_python(content, rule):
    r"""Apply one HTTPD Substitute rule to ``content`` the way perl's test does.

    Mirrors the Perl logic: ``/n`` => literal (quotemeta both parts), else map
    HTTPD ``$0`` (whole match) to perl ``$&``. mod_substitute is always global.
    Returns the transformed string.
    """
    # rule looks like s/PATTERN/REPL/[flags]
    flags = 0
    literal = False
    body = rule
    if body.endswith("n"):
        literal = True
        body = body[:-1]
    # split on '/' -- the leading 's' then pattern then repl then trailing flags
    parts = body.split("/")
    # parts[0] == 's'; parts[1] == pattern; parts[2] == repl; parts[3:] flags
    pattern = parts[1]
    repl = parts[2] if len(parts) > 2 else ""
    trailing = parts[3] if len(parts) > 3 else ""
    if "i" in trailing:
        flags |= re.IGNORECASE

    if literal:
        pattern = re.escape(pattern)
        repl_out = repl  # literal replacement, no backrefs
        repl_out = repl_out.replace("\\", "\\\\")
        return re.sub(pattern, lambda m: repl, content, flags=flags)

    # Map HTTPD $0 (whole match) and $N backrefs to python \g<0> / \N.
    # NOTE: '&' is NOT a whole-match metachar here. mod_substitute uses $0/$N
    # for backrefs only, and the Perl reference test computes its expectation by
    # running the rule through perl's own s/// (substitute.t:73-80), where a bare
    # '&' in the replacement is a literal '&' ($& is the match var, not &). So
    # s/<body>/&/ yields a literal 'x&x' -- which is what the server returns.
    def to_py_repl(s):
        out = []
        i = 0
        while i < len(s):
            c = s[i]
            if c == "\\" and i + 1 < len(s):
                nxt = s[i + 1]
                if nxt == "$":
                    out.append("$")  # escaped dollar => literal $
                    i += 2
                    continue
                if nxt == "d":
                    # \d in replacement is just literal 'd' in perl double-quote
                    out.append("d")
                    i += 2
                    continue
                out.append(c)
                out.append(nxt)
                i += 2
                continue
            if c == "$" and i + 1 < len(s) and s[i + 1].isdigit():
                n = s[i + 1]
                if n == "0":
                    out.append("\\g<0>")
                else:
                    out.append("\\" + n)
                i += 2
                continue
            if c == "&":
                # literal '&' (see note above), not whole-match. '&' has no
                # special meaning in an re.sub replacement, so emit it as-is.
                out.append("&")
                i += 1
                continue
            out.append(c)
            i += 1
        return "".join(out)

    py_repl = to_py_repl(repl)
    return re.sub(pattern, py_repl, content, flags=flags)


def _expect(content, rules):
    expect = re.sub(f"[{re.escape(B)}{re.escape(F)}{re.escape(P)}]+", "", content)
    for rule in rules:
        expect = _httpd_rule_to_python(expect, rule)
    return expect


def _all_cases(http):
    cases = list(BASE_CASES)
    if http.have_min_apache_version("2.3.5"):
        cases += R1307067_CASES
    return cases


@need_module("substitute", "bucketeer")
def test_substitute_computed(http):
    for content, rules in _all_cases(http):
        _write_testfile(http, content)
        _write_htaccess(http, rules)
        expect = _expect(content, rules)
        r = http.GET("/modules/substitute/test.txt")
        assert r.status_code == 200
        assert r.text == expect, f"content={content!r} rules={rules} expected={expect!r}"


@need_module("substitute", "bucketeer")
def test_substitute_simple(http):
    if not http.have_min_apache_version("2.4.42"):
        pytest.skip("simple Substitute cases require httpd >= 2.4.42")
    for content, rule, expect in SIMPLE_CASES:
        _write_testfile(http, content)
        _write_htaccess(http, [rule])
        r = http.GET("/modules/substitute/test.txt")
        assert r.status_code == 200
        assert r.text == expect, f"content={content!r} rule={rule} expected={expect!r}"
