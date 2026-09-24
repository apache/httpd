import os
import re

import pytest

from pyhttpd.conf import HttpdConf

# mod_sed implements the Solaris 10 sed language over the response (OutputSed)
# or the request body (InputSed).  Almost none of it was covered before, so
# these tests walk the commands the module documents plus the paths mod_sed.c
# itself has: the 8000-byte output buffer, the transient-bucket flush, the
# empty-body short circuit and the error path.

# The document most tests run against.  Three lines, trailing newline.
DOC = "one monday two\nthree sunday four\nmonday monday monday\n"

# huge.html: enough ordinary lines to push mod_sed past MAX_TRANSIENT_BUCKETS
# (50 buckets of MODSED_OUTBUF_SIZE, so 400000 bytes) and make it flush what it
# has to the client, then a single line past the 8 MB (MAX_BUF_SIZE) a line may
# grow to, which fails the evaluation.
HUGE_HEAD_LINES = 500
HUGE_LINE_LEN = 900
HUGE_HEAD_LEN = HUGE_HEAD_LINES * (HUGE_LINE_LEN + 1)
HUGE_TAIL_LEN = 9 * 1024 * 1024

# For a test whose failure mode is "never answers" rather than "answers
# wrongly".  pyhttpd only gives curl --connect-timeout.
BOUNDED = ["--max-time", "30"]


class TestSed:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        self.docdir = os.path.join(env.server_dir, "htdocs", "test1")
        self.write(env, "sed.html", DOC)
        # Same text with no newline after the last line.
        self.write(env, "nonl.html", DOC[:-1])
        self.write(env, "empty.html", "")
        # One line per 4 KB, well past MODSED_OUTBUF_SIZE and past the 50
        # transient buckets mod_sed flushes at.
        self.write(env, "big.html",
                   "".join(f"line {i:06d} monday {'x' * 4000}\n"
                           for i in range(500)))
        # A byte from each interesting class for the l command: printable,
        # tab, DEL and three high-bit bytes.
        self.write_bytes(env, "bytes.html", b"a\tb\x7fc\xffd\x80e\xa9f\n")
        self.write(env, "insert.txt", "INSERTED\n")
        # First line has nothing for \(a*\) to capture, second has "aa".
        self.write(env, "backref.html", "b\naab\n")
        head = "".join(
            f"line {i:06d} monday ".ljust(HUGE_LINE_LEN, "y") + "\n"
            for i in range(HUGE_HEAD_LINES))
        assert len(head) == HUGE_HEAD_LEN
        self.write(env, "huge.html", head + "z" * HUGE_TAIL_LEN + "\n")

    @staticmethod
    def write(env, name, text):
        TestSed.write_bytes(env, name, text.encode())

    @staticmethod
    def write_bytes(env, name, data):
        path = os.path.join(env.server_dir, "htdocs", "test1", name)
        with open(path, "wb") as f:
            f.write(data)

    @staticmethod
    def sed_path(env, name):
        """The path of a document as an "r" command has to spell it: sed
        reads a backslash in a filename as an escape and drops it, so a
        Windows path only survives with forward slashes."""
        return os.path.join(env.server_dir, "htdocs", "test1",
                            name).replace(os.sep, "/")

    def configure(self, env, exprs, extra="", input_sed=False):
        if isinstance(exprs, str):
            exprs = [exprs]
        directive = "InputSed" if input_sed else "OutputSed"
        lines = "\n".join(f'            {directive} "{e}"' for e in exprs)
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            <Location "/">
                AddOutputFilterByType SED text/html
                AddInputFilter SED py
                AddHandler cgi-script .py
                Options +ExecCGI
{lines}
            </Location>
            {extra}
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, path="/sed.html", options=None):
        return env.curl_get(env.mkurl("http", "test1", path), options=options)

    def body(self, env, exprs, path="/sed.html", **kwargs):
        self.configure(env, exprs, **kwargs)
        r = self.get(env, path)
        assert r.response, f"no response for {exprs}"
        assert r.response["status"] == 200, \
            f"{exprs}: status {r.response['status']}"
        return r.response["body"]

    # --- substitution -----------------------------------------------------

    # s/// replaces the first match on each line and nothing else.
    def test_filters_003_01(self, env):
        assert self.body(env, "s/monday/MON/").decode() == \
            "one MON two\nthree sunday four\nMON monday monday\n"

    # s///g replaces every match on the line.
    def test_filters_003_02(self, env):
        assert self.body(env, "s/monday/MON/g").decode() == \
            "one MON two\nthree sunday four\nMON MON MON\n"

    # s///2 replaces only the second match.
    def test_filters_003_03(self, env):
        assert self.body(env, "s/monday/MON/2").decode() == \
            "one monday two\nthree sunday four\nmonday MON monday\n"

    # Several OutputSed directives accumulate into one script, applied in the
    # order they appear.  This is the configuration the manual shows.
    def test_filters_003_04(self, env):
        assert self.body(env, ["s/monday/MON/g", "s/sunday/SUN/g"]).decode() \
            == "one MON two\nthree SUN four\nMON MON MON\n"

    # A back reference in the replacement.
    def test_filters_003_05(self, env):
        assert self.body(env, r"s/\(mon\)day/[\1]/g").decode() == \
            "one [mon] two\nthree sunday four\n[mon] [mon] [mon]\n"

    # & in the replacement is the whole match.
    def test_filters_003_06(self, env):
        assert self.body(env, "s/monday/<&>/").decode() == \
            "one <monday> two\nthree sunday four\n<monday> monday monday\n"

    # --- addresses --------------------------------------------------------

    # A line-number address.
    def test_filters_003_07(self, env):
        assert self.body(env, "2d").decode() == \
            "one monday two\nmonday monday monday\n"

    # $ is the last line.
    def test_filters_003_08(self, env):
        assert self.body(env, "$d").decode() == \
            "one monday two\nthree sunday four\n"

    # A regex range.
    def test_filters_003_09(self, env):
        assert self.body(env, "/sunday/,$d").decode() == "one monday two\n"

    # A negated address.
    def test_filters_003_10(self, env):
        assert self.body(env, "/sunday/!d").decode() == "three sunday four\n"

    # = writes the line number ahead of the line.
    def test_filters_003_11(self, env):
        assert self.body(env, "=").decode() == \
            "1\none monday two\n2\nthree sunday four\n3\nmonday monday monday\n"

    # --- hold space -------------------------------------------------------

    # G appends the hold space, which starts empty: classic double spacing.
    def test_filters_003_12(self, env):
        assert self.body(env, "G").decode() == \
            "one monday two\n\nthree sunday four\n\nmonday monday monday\n\n"

    # h saves, then x swaps: every line is replaced by the one before it.
    def test_filters_003_13(self, env):
        assert self.body(env, "x").decode() == \
            "\none monday two\nthree sunday four\n"

    # H;$!d;x collects the whole document in the hold space and prints it once.
    def test_filters_003_14(self, env):
        assert self.body(env, ["H", "$!d", "x"]).decode() == "\n" + DOC

    # --- transliteration --------------------------------------------------

    def test_filters_003_15(self, env):
        assert self.body(env, "y/aeiou/AEIOU/").decode() == \
            "OnE mOndAy twO\nthrEE sUndAy fOUr\nmOndAy mOndAy mOndAy\n"

    # --- line handling ----------------------------------------------------

    # A document whose last line has no newline gets one: documented Solaris
    # sed behaviour, and the reason mod_sed drops Content-Length.
    def test_filters_003_16(self, env):
        assert self.body(env, "s/monday/MON/g", path="/nonl.html").decode() \
            == "one MON two\nthree sunday four\nMON MON MON\n"

    # An empty body stays empty; mod_sed must not invent a line.
    def test_filters_003_17(self, env):
        assert self.body(env, "s/monday/MON/", path="/empty.html") == b""

    # mod_sed drops the handler's Content-Length because the body it produces
    # is a different size.  The length that reaches the client must be the one
    # after filtering -- ap_content_length_filter recomputes it -- and never
    # the file's own.
    def test_filters_003_18(self, env):
        self.configure(env, "s/monday/MONDAYMONDAY/g")
        r = self.get(env)
        assert r.response["status"] == 200
        grown = len(DOC) + 4 * len("MONDAY")
        assert len(r.response["body"]) == grown
        assert r.response["header"]["content-length"] == str(grown), \
            r.response["header"]

    # The handler still generates a body for HEAD -- the protocol filters
    # discard it -- so the filter runs and HEAD must announce the same
    # Content-Length the matching GET returns, not the file's own.
    def test_filters_003_19(self, env):
        self.configure(env, "s/monday/MONDAYMONDAY/g")
        r = self.get(env, options=["-I"])
        assert r.response, "no response to HEAD"
        assert r.response["status"] == 200
        grown = len(DOC) + 4 * len("MONDAY")
        assert r.response["header"]["content-length"] == str(grown), \
            r.response["header"]

    # A handler which produces headers and no body reaches mod_sed as a lone
    # EOS.  There is nothing to evaluate, so the filter takes itself out of
    # the chain without touching the response.
    def test_filters_003_20(self, env):
        self.configure(env, "s/monday/MON/")
        r = self.get(env, "/cgi/nobody.py")
        assert r.response, "no response"
        assert r.response["status"] == 200
        assert r.response["body"] == b""

    # A body far larger than the 8000-byte output buffer, and with more than
    # the 50 transient buckets mod_sed flushes at, comes back intact.
    def test_filters_003_21(self, env):
        body = self.body(env, "s/monday/MON/", path="/big.html")
        assert len(body) == 500 * (len("line 000000 MON ") + 4000 + 1)
        lines = body.decode().splitlines()
        assert len(lines) == 500
        assert lines[0] == "line 000000 MON " + "x" * 4000
        assert lines[499] == "line 000499 MON " + "x" * 4000

    # --- the l command ----------------------------------------------------

    # l writes the line in a printable form: control characters as the escapes
    # in trans[], everything else non-printable as a three-digit octal escape.
    # Bytes with the top bit set used to come out as nonsense ("\/77" for 0xff)
    # because the shift was done on a signed char.
    def test_filters_003_22(self, env):
        body = self.body(env, "l;d", path="/bytes.html")
        assert body == b"a\\11b\\177c\\377d\\200e\\251f\n", body

    # --- error handling ---------------------------------------------------

    # A branch to a label that is never defined compiles -- the label could
    # still arrive from a later OutputSed -- and fails at the first byte of
    # every response instead.  Nothing has been written at that point, so the
    # failure can and must still become a 500.
    def test_filters_003_23(self, env):
        env.httpd_error_log.add_ignored_lognos(["AH02998", "AH10394"])
        self.configure(env, "b nolabel")
        r = self.get(env)
        assert r.response, "no response at all"
        assert r.response["status"] == 500, r.response["status"]
        assert env.httpd_error_log.scan_recent(
            re.compile(r'.*undefined label: nolabel'))

    # The same failure once the response is already on its way.  huge.html is
    # 450 KB of ordinary lines -- enough for mod_sed to hit MAX_TRANSIENT_BUCKETS
    # and flush the start of the response to the client -- followed by one line
    # over the 8 MB a line may grow to, which fails the evaluation.
    #
    # The response cannot become a 500 any more, so it has to be terminated as
    # what it is: a truncated 200.  mod_sed used to skip both the final flush
    # and the pass because of the error status, dropping the EOS with them, and
    # the client was left waiting on a response that never ended.
    def test_filters_003_24(self, env):
        env.httpd_error_log.add_ignored_lognos(["AH02998", "AH10394"])
        self.configure(env, "s/monday/MON/")
        r = self.get(env, "/huge.html")
        assert r.exit_code == 0, \
            f"curl failed ({r.exit_code}): the response was never terminated"
        assert r.response["status"] == 200
        body = r.response["body"]
        # Truncated: the lines evaluated before the failure, and no more.
        assert 0 < len(body) < HUGE_HEAD_LEN + 1024, len(body)
        assert body.startswith(b"line 000000 MON ")
        assert env.httpd_error_log.scan_recent(
            re.compile(r'.*error evaluating sed on output'))

    # SED_ABUFSIZE is the size of the append/read queue a line may build up.
    # Filling it exactly used to write the terminating NULL one past the end
    # of eval->abuf, over eval->aptr itself, and the next line then wrote
    # through that NULL pointer.
    def test_filters_003_25(self, env):
        env.httpd_error_log.add_ignored_lognos(["AH02998"])
        path = self.sed_path(env, "insert.txt")
        self.configure(env, [f"r {path}"] * 20)
        r = self.get(env)
        assert r.response, "no response: the server died"
        assert r.response["status"] == 200
        # 19 of the 20 fit; the last is refused, and says so.
        assert r.response["body"].count(b"INSERTED") == 3 * 19
        assert env.httpd_error_log.scan_recent(
            re.compile(r'.*too many reads after line'))

    # One below the limit has always worked and must keep working.
    def test_filters_003_26(self, env):
        path = self.sed_path(env, "insert.txt")
        body = self.body(env, [f"r {path}"] * 19)
        assert body.count(b"INSERTED") == 3 * 19

    # --- backreferences ---------------------------------------------------

    # A starred backreference whose capture matched nothing repeats a
    # zero-length match: the matcher steps the input pointer by the capture
    # length, so it has to stop rather than repeat it, and the star can only
    # ever match once.  Both lines reduce to their first match plus the rest.
    #
    # --max-time because a regression here does not return an error, it stops
    # answering: pyhttpd gives curl --connect-timeout but no overall limit, so
    # without one of our own a failure hangs the whole run rather than failing
    # it.  Note the worker keeps spinning after curl gives up.
    def test_filters_003_27(self, env):
        self.configure(env, r"s/\(a*\)\1*/X/")
        r = self.get(env, "/backref.html", options=BOUNDED)
        assert r.exit_code == 0, f"curl failed ({r.exit_code}): no response"
        assert r.response["status"] == 200
        assert r.response["body"] == b"Xb\nXb\n"

    # --- input filter -----------------------------------------------------

    # The same expression on a request body, which runs the same matcher.
    def test_filters_003_28(self, env):
        self.configure(env, r"s/\(a*\)\1*/X/", input_sed=True)
        r = env.curl_post_data(env.mkurl("http", "test1", "/cgi/echo.py"),
                               data="b\naab\n", options=list(BOUNDED))
        assert r.exit_code == 0, f"curl failed ({r.exit_code}): no response"
        assert r.response["status"] == 200
        assert r.response["body"] == b"Xb\nXb\n"

    # InputSed rewrites the request body before the handler sees it.
    def test_filters_003_29(self, env):
        self.configure(env, "s/monday/MON/g", input_sed=True)
        r = env.curl_post_data(env.mkurl("http", "test1", "/cgi/echo.py"),
                               data="one monday two\nmonday monday\n")
        assert r.response, "no response"
        assert r.response["status"] == 200
        assert r.response["body"] == b"one MON two\nMON MON\n"

    # A request body with no trailing newline gets one, as the manual warns.
    def test_filters_003_30(self, env):
        self.configure(env, "s/monday/MON/g", input_sed=True)
        r = env.curl_post_data(env.mkurl("http", "test1", "/cgi/echo.py"),
                               data="one monday two")
        assert r.response, "no response"
        assert r.response["body"] == b"one MON two\n"
