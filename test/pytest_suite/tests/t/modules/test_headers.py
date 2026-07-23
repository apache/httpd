r"""Translated from t/modules/headers.t -- mod_headers.

Two parts:

1. ``test_header``: exhaustively writes .htaccess files combining the directives
   set/append/add/unset (every 1..4-length sequence), each with a unique random
   value, computes the expected resulting Test-Header value(s), HEADs the page
   and confirms the actual headers match.

2. ``test_header2``: a table of (.htaccess content, request headers, expected
   response headers) exercising echo/edit/edit*/merge/setifempty/env=/expr=
   (plus lookbehind / empty-match cases on >= 2.5.1).

Perl original: plan tests => ..., have_module 'headers';
"""

import os
import random

import pytest

from apache_pytest import need_module, t_cmp

HEADER_TYPES = ["set", "append", "add", "unset"]
TEST_HEADER = "Test-Header"


def _htaccess_path(http):
    return os.path.join(http.vars("documentroot"), "modules", "headers",
                        "htaccess", ".htaccess")


def _head_headers(http, path, request_headers=None):
    """HEAD ``path`` and return the list of values for Test-Header (in order)."""
    r = http.HEAD(path, headers=request_headers or {})
    return r.headers.get_list(TEST_HEADER)


def _compute_expected(rng, directives):
    """Replicate the Perl expected-value bookkeeping for a directive sequence.

    Returns the list of expected Test-Header values (order-insensitive compare)
    and the .htaccess content to write.
    """
    expected_value = []   # @expected_value (list)
    expected_scalar = 0   # $expected_value (scalar; 0 == false/none)
    expected_exists = 0
    lines = []
    for d in directives:
        r = rng.randrange(9999)
        test_value = f"mod_headers test header value {r}"
        if d == "unset":
            lines.append(f"Header {d} {TEST_HEADER}")
            expected_value = []
            expected_exists = 0
            expected_scalar = 0
        else:
            lines.append(f'Header {d} {TEST_HEADER} "{test_value}"')
            if d == "set":
                expected_value = []
                expected_exists = 1
                expected_scalar = test_value
            elif d == "append":
                if expected_value:
                    expected_value[0] += f", {test_value}"
                elif expected_scalar:
                    expected_scalar += f", {test_value}"
                else:
                    expected_scalar = test_value
                if not expected_exists:
                    expected_exists = 1
            elif d == "add":
                if expected_scalar:
                    expected_value.append(expected_scalar)
                    expected_scalar = 0
                expected_scalar = test_value
                expected_exists += 1
    if expected_scalar:
        expected_value.append(expected_scalar)
    content = "\n".join(lines) + ("\n" if lines else "")
    return expected_value, content


def _check(rng, http, directives):
    expected_value, content = _compute_expected(rng, directives)
    with open(_htaccess_path(http), "w") as f:
        f.write(content)
    actual_value = _head_headers(http, "/modules/headers/htaccess/")

    # ok if nothing expected and nothing present
    if not actual_value and not expected_value:
        return True
    if len(actual_value) != len(expected_value):
        return False
    remaining = list(expected_value)
    for av in actual_value:
        if av in remaining:
            remaining.remove(av)
        else:
            return False
    return True


@need_module("headers")
def test_header_combinations(http):
    rng = random.Random(98765)
    for h1 in HEADER_TYPES:
        assert _check(rng, http, [h1]), f"[{h1}]"
        for h2 in HEADER_TYPES:
            assert _check(rng, http, [h1, h2]), f"[{h1},{h2}]"
            for h3 in HEADER_TYPES:
                assert _check(rng, http, [h1, h2, h3]), f"[{h1},{h2},{h3}]"
                for h4 in HEADER_TYPES:
                    assert _check(rng, http, [h1, h2, h3, h4]), \
                        f"[{h1},{h2},{h3},{h4}]"


# (htaccess content, [request header pairs], [expected response header pairs],
#  [optional expected status; defaults to 200])
TESTCASES = [
    # echo
    ("Header echo Test-Header\nHeader echo ^Aaa$\nHeader echo ^Aa$",
     ["Test-Header", "value", "Aaa", "b", "Aa", "bb"],
     ["Test-Header", "value", "Aaa", "b", "Aa", "bb"]),
    ("Header echo Test-Header\nHeader echo XXX\nHeader echo ^Aa$",
     ["Test-Header", "foo", "aaa", "b", "aa", "bb"],
     ["Test-Header", "foo", "aa", "bb"]),
    ("Header echo Test-Header.*",
     ["Test-Header", "foo", "Test-Header1", "value1", "Test-Header2", "value2"],
     ["Test-Header", "foo", "Test-Header1", "value1", "Test-Header2", "value2"]),
    # edit
    ("Header echo Test-Header\nHeader edit Test-Header foo bar",
     ["Test-Header", "foofoo"], ["Test-Header", "barfoo"]),
    ("Header echo Test-Header\nHeader edit Test-Header foo2 bar",
     ["Test-Header", "foo2foo2"], ["Test-Header", "barfoo2"]),
    ("Header echo Test-Header\nHeader edit Test-Header foo bar2",
     ["Test-Header", "foofoo"], ["Test-Header", "bar2foo"]),
    # edit*
    ("Header echo Test-Header\nHeader edit* Test-Header foo bar",
     ["Test-Header", "foofoo"], ["Test-Header", "barbar"]),
    ("Header echo Test-Header\nHeader edit* Test-Header foo2 bar",
     ["Test-Header", "foo2foo2"], ["Test-Header", "barbar"]),
    ("Header echo Test-Header\nHeader edit* Test-Header foo bar2",
     ["Test-Header", "foofoo"], ["Test-Header", "bar2bar2"]),
    # merge
    ("Header merge Test-Header foo",
     [], ["Test-Header", "foo"]),
    ("Header echo Test-Header\nHeader merge Test-Header foo",
     ["Test-Header", "foo"], ["Test-Header", "foo"]),
    ("Header echo Test-Header\nHeader merge Test-Header foo",
     ["Test-Header", '"foo"'], ["Test-Header", '"foo", foo']),
    ("Header echo Test-Header\nHeader merge Test-Header bar",
     ["Test-Header", "foo"], ["Test-Header", "foo, bar"]),
    # setifempty
    ("Header echo Test-Header\nHeader setifempty Test-Header bar",
     ["Test-Header", "foo"], ["Test-Header", "foo"]),
    ("Header echo Test-Header\nHeader setifempty Test-Header2 bar",
     ["Test-Header", "foo"], ["Test-Header", "foo", "Test-Header2", "bar"]),
    # env=
    ("SetEnv MY_ENV\nHeader set Test-Header foo env=MY_ENV",
     [], ["Test-Header", "foo"]),
    ("Header set Test-Header foo env=!MY_ENV",
     [], ["Test-Header", "foo"]),
    # expr=
    ('Header set Test-Header foo "expr=%{REQUEST_URI} =~ m#htaccess#"',
     [], ["Test-Header", "foo"]),
    # 500 error test - malformed regex (unmatched parenthesis)
    ("Header edit Test-Header (unclosed bar",
     [], [], 500),
]

TESTCASES_251 = [
    ("Header echo Test-Header\nHeader edit* Test-Header (?<=a)(ba) cd",
     ["Test-Header", "ababa"], ["Test-Header", "acdcd"]),
    ("Header echo Test-Header\nHeader edit* Test-Header ^ foo",
     ["Test-Header", "bar"], ["Test-Header", "foobar"]),
    ("Header echo Test-Header\nHeader edit* Test-Header ^(.*)$ $1;httpOnly;secure",
     ["Test-Header", ""], ["Test-Header", ";httpOnly;secure"]),
]


def _canonical_header(name):
    """Title-case a header name the way Perl's HTTP::Headers does on the wire.

    LWP canonicalises request header names to ``Title-Case`` (e.g. ``aa`` =>
    ``Aa``, ``test-header`` => ``Test-Header``). mod_headers' ``Header echo``
    regex match is case-sensitive, so the test depends on this canonicalisation
    (the .htaccess uses ``^Aa$`` etc.). httpx preserves whatever case we give
    it, so we replicate HTTP::Headers' rule here.
    """
    return "-".join(part[:1].upper() + part[1:].lower() for part in name.split("-"))


def _pairs_to_dict(pairs):
    d = {}
    for i in range(0, len(pairs), 2):
        d[_canonical_header(pairs[i])] = pairs[i + 1]
    return d


@need_module("headers")
def test_header_directives(http):
    cases = list(TESTCASES)
    if http.have_min_apache_version("2.4.68"):
        # file() is not permitted in an .htaccess expr context -> 500.
        htaccess = _htaccess_path(http)
        cases.append((
            f'Header set Test-Header "expr=%{{base64:%{{file:{htaccess}}}}}"',
            [], [], 500))
    if http.have_min_apache_version("2.5.1"):
        cases += TESTCASES_251

    for case in cases:
        htaccess, req_pairs, exp_pairs = case[0], case[1], case[2]
        # Optional 4th element is the expected status; defaults to 200.
        expected_status = case[3] if len(case) > 3 else 200
        with open(_htaccess_path(http), "w") as f:
            f.write(htaccess)
        req_headers = _pairs_to_dict(req_pairs)
        r = http.GET("/modules/headers/htaccess/", headers=req_headers)
        assert t_cmp(r.status_code, expected_status), \
            f"Checking return code is '{expected_status}' [htaccess: {htaccess!r}]"

        # Only validate response headers for successful responses.
        if expected_status != 200:
            continue

        for i in range(0, len(exp_pairs), 2):
            name, expected = exp_pairs[i], exp_pairs[i + 1]
            received = r.headers.get(name)
            assert received is not None and received == expected, (
                f"header {name}: expected '{expected}', got "
                f"'{received if received is not None else '<undefined>'}' "
                f"[htaccess: {htaccess!r}]")
