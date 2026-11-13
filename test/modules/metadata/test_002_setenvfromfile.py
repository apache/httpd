import os
import re
import pytest

from pyhttpd.backport import skip_not_backported
from pyhttpd.conf import HttpdConf

pytestmark = skip_not_backported("r1938506", "SetEnvFromFile")


def _write_ssi_echo(path, names, encoding="entity"):
    """An SSI page echoing each variable as NAME=[value].  An unset
    variable echoes the default "(none)", so a set-but-empty variable
    ("[]") is distinguishable from one that never made it into the table.
    """
    with open(path, "w") as f:
        for name in names:
            f.write(f'{name}=[<!--#echo encoding="{encoding}" var="{name}" -->]\n')


class TestSetEnvFromFile:
    """Parsing behaviour of a well-formed file."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # A plain name=value pair, an explicitly empty value, a line with
        # no '=' (also empty), a backslash line continuation, and a line
        # padded with surrounding whitespace that must be stripped.
        env_file = os.path.join(env.gen_dir, "setenv.env")
        with open(env_file, "w") as f:
            f.write("# metadata SetEnvFromFile happy-path fixture\n")
            f.write("\n")
            f.write("ENV_SIMPLE=simple value\n")
            f.write("ENV_EMPTY=\n")
            f.write("ENV_NOEQ\n")
            f.write("ENV_CONT=first \\\n")
            f.write("second\n")
            f.write("   ENV_WS=trimmed value   \n")

        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        os.makedirs(doc_dir, exist_ok=True)
        _write_ssi_echo(os.path.join(doc_dir, "fromfile.shtml"),
                        ["ENV_SIMPLE", "ENV_EMPTY", "ENV_NOEQ", "ENV_CONT",
                         "ENV_WS", "ENV_UNDEFINED"])

        conf = HttpdConf(env, extras={
            'base': f"""
            SetEnvFromFile "{env_file}"
            <Directory "{doc_dir}">
                Options +Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_metadata_002_01_parsing(self, env):
        url = env.mkurl("http", "test1", "/fromfile.shtml")
        r = env.curl_get(url)
        assert r.response, "no response: server may have crashed"
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")
        # a plain name=value pair
        assert "ENV_SIMPLE=[simple value]" in body
        # an explicitly empty value is set, not absent
        assert "ENV_EMPTY=[]" in body
        # a line with no '=' yields an empty value
        assert "ENV_NOEQ=[]" in body
        # a backslash continues the value on the next line (no space added
        # by the join; the space here is the one before the backslash)
        assert "ENV_CONT=[first second]" in body
        # leading/trailing whitespace on the line is stripped, from both
        # the name (else the echo would be "(none)") and the value (else a
        # trailing space would remain)
        assert "ENV_WS=[trimmed value]" in body
        # a variable never named in the file is left unset
        assert "ENV_UNDEFINED=[(none)]" in body


class TestSetEnvFromFileMalformed:
    """A line with no variable name is skipped with a warning, and later
    lines are still parsed."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env_file = os.path.join(env.gen_dir, "setenv-malformed.env")
        with open(env_file, "w") as f:
            f.write("# a line beginning with '=' has an empty name\n")
            f.write("=orphan value\n")
            f.write("ENV_OK=present\n")

        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        os.makedirs(doc_dir, exist_ok=True)
        _write_ssi_echo(os.path.join(doc_dir, "malformed.shtml"), ["ENV_OK"])

        conf = HttpdConf(env, extras={
            'base': f"""
            SetEnvFromFile "{env_file}"
            <Directory "{doc_dir}">
                Options +Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_metadata_002_02_malformed_line(self, env):
        # The malformed line is skipped with an AH10632 warning.  Where that
        # warning surfaces is MPM-dependent: when the config is parsed before
        # the error log is open (e.g. the event MPM on Unix) it goes to
        # apachectl's stderr; with mpm_winnt the config is parsed again by the
        # child with the error log already open, so it lands in the error log
        # instead (and possibly more than once).  apachectl_stderr is also
        # None on the winnt startup path, so guard it.  Accept the warning in
        # either place.
        stderr = env.apachectl_stderr or ""
        warn_re = re.compile(
            r'.*AH10632: SetEnvFromFile: Skipping malformed line.*')
        found = "AH10632" in stderr
        if not found:
            try:
                found = env.httpd_error_log.scan_recent(warn_re)
            except TimeoutError:
                found = False
        assert found, "AH10632 warning not found in stderr or error log"
        # The warning is expected here; keep it from failing the teardown log
        # check (it may appear in the error log several times under winnt).
        env.httpd_error_log.ignore_recent(lognos=["AH10632"])
        # ... and the well-formed line after it is still applied
        url = env.mkurl("http", "test1", "/malformed.shtml")
        r = env.curl_get(url)
        assert r.response, "no response: server may have crashed"
        assert r.response["status"] == 200
        assert "ENV_OK=[present]" in r.response["body"].decode("utf-8")


class TestSetEnvFromFileHtaccess:
    """SetEnvFromFile is not permitted in .htaccess (RSRC_CONF|ACCESS_CONF),
    even where AllowOverride FileInfo would allow SetEnv itself."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        ht_dir = os.path.join(env.server_dir, "htdocs", "test1", "htaccess")
        os.makedirs(ht_dir, exist_ok=True)
        with open(os.path.join(ht_dir, "index.html"), "w") as f:
            f.write("hello\n")
        # SetEnv (FileInfo) would be accepted here; SetEnvFromFile must not.
        with open(os.path.join(ht_dir, ".htaccess"), "w") as f:
            f.write('SetEnvFromFile "conf/whatever.env"\n')

        conf = HttpdConf(env, extras={
            'base': f"""
            <Directory "{ht_dir}">
                AllowOverride FileInfo
            </Directory>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        # the server starts fine; .htaccess is parsed per request
        assert env.apache_restart() == 0

    def test_metadata_002_03_htaccess_rejected(self, env):
        url = env.mkurl("http", "test1", "/htaccess/index.html")
        r = env.curl_get(url)
        assert r.response, "no response: server may have crashed"
        # the illegal directive makes .htaccess processing fail -> 500
        assert r.response["status"] == 500
        # logged (at alert level, so check_error_log does not flag it, but
        # guard anyway) with the config parser's context rejection
        assert env.httpd_error_log.scan_recent(
            re.compile(r'.*SetEnvFromFile not allowed here.*'))
        env.httpd_error_log.ignore_recent(matches=[r'.*SetEnvFromFile not allowed here.*'])


class TestSetEnvFromFileMissing:
    """Pointing at a file that cannot be opened is a fatal config error."""

    def test_metadata_002_04_missing_file(self, env):
        missing = os.path.join(env.gen_dir, "does-not-exist.env")
        conf = HttpdConf(env, extras={
            'base': f'SetEnvFromFile "{missing}"',
        })
        conf.add_vhost_test1()
        conf.install()
        # httpd must refuse to start ...
        assert env.apache_fail() == 0
        # ... reporting why.  The message is emitted at config-parse time;
        # apachectl_stderr only captures it on the non-winnt start path (it is
        # None under mpm_winnt), so only assert on it where it was captured.
        if env.apachectl_stderr:
            assert "Could not open file" in env.apachectl_stderr

        # restore a working, running server so the log check and package
        # teardown are clean
        env.httpd_error_log.clear_log()
        good = HttpdConf(env)
        good.add_vhost_test1()
        good.install()
        assert env.apache_restart() == 0


class TestSetEnvFromFileConfig:

    def check_config(self, env, contents):
        env_file = os.path.join(env.gen_dir, "setenv-read.env")
        with open(env_file, "w", newline="") as f:
            f.write(contents)

        conf = HttpdConf(env, extras={
            'base': f'SetEnvFromFile "{env_file}"',
        })
        conf.add_vhost_test1()
        conf.install()
        return env.run([os.path.join(env.bin_dir, "httpd"),
                        "-t", "-d", env.server_dir,
                        "-f", os.path.join(env.server_dir, "conf", "httpd.conf")])

    @pytest.mark.parametrize("line_length", [8191, 8192, 16384])
    @pytest.mark.parametrize("ending", ["\n", ""], ids=["newline", "eof"])
    def test_metadata_002_05_long_line(self, env, line_length, ending):
        line = "ENV_LONG=" + "x" * (line_length - len("ENV_LONG="))
        contents = "ENV_BEFORE=before\n" + line + ending
        if ending:
            contents += "ENV_AFTER=after\n"
        r = self.check_config(env, contents)
        assert r.exit_code != 0, "oversized line was accepted"
        assert "setenv-read.env at line 2: Line too long" in r.stderr

    def test_metadata_002_06_long_continuation(self, env):
        r = self.check_config(
            env, "ENV_BEFORE=before\nENV_LONG=" + "x" * 4096
            + "\\\n" + "y" * 4096 + "\nENV_AFTER=after\n")
        assert r.exit_code != 0, "oversized continued line was accepted"
        assert "setenv-read.env at line 3: Line too long" in r.stderr

    # The 8192-byte buffer needs room for a newline and the terminating NUL.
    @pytest.mark.parametrize("contents", [
        pytest.param("", id="empty-file"),
        pytest.param("ENV_OK=present", id="no-final-newline"),
        pytest.param("ENV_OK=present\n", id="final-newline"),
        pytest.param("ENV_LONG=" + "x" * (8190 - len("ENV_LONG=")),
                     id="max-line-no-newline"),
        pytest.param("ENV_LONG=" + "x" * (8190 - len("ENV_LONG=")) + "\n",
                     id="max-line-with-newline"),
        pytest.param("ENV_LONG=" + "x" * 4096 + "\\\n"
                     + "y" * (8190 - len("ENV_LONG=") - 4096) + "\n",
                     id="max-continued-line"),
    ])
    def test_metadata_002_07_normal_eof(self, env, contents):
        r = self.check_config(env, contents)
        assert r.exit_code == 0, r.stderr

    @pytest.mark.parametrize("value, message", [
        pytest.param('"unfinished', "Unterminated quoted value",
                     id="unclosed-double"),
        pytest.param("'unfinished", "Unterminated quoted value",
                     id="unclosed-single"),
        pytest.param('"', "Unterminated quoted value", id="double-quote-only"),
        pytest.param("'", "Unterminated quoted value", id="single-quote-only"),
        pytest.param(r'"escaped\"', "Unterminated quoted value",
                     id="escaped-double-closer"),
        pytest.param(r"'escaped\'", "Unterminated quoted value",
                     id="escaped-single-closer"),
        pytest.param('"closed"extra', "Unexpected text after quoted value",
                     id="adjacent-text"),
        pytest.param("'closed' extra", "Unexpected text after quoted value",
                     id="separate-text"),
        pytest.param('"" "extra"', "Unexpected text after quoted value",
                     id="extra-quoted-token"),
        pytest.param(' \t"unfinished', "Unterminated quoted value",
                     id="unclosed-after-whitespace"),
    ])
    def test_metadata_002_11_malformed_quotes(self, env, value, message):
        r = self.check_config(
            env, f"ENV_BEFORE=before\nENV_BAD={value}\nENV_AFTER=after\n")
        assert r.exit_code != 0, "malformed quoted value was accepted"
        assert f"setenv-read.env at line 2: {message}" in r.stderr


class TestSetEnvFromFileQuoted:

    def check_value(self, env, file_value, expected):
        env_file = os.path.join(env.gen_dir, "setenv-quoted.env")
        with open(env_file, "w", newline="") as f:
            f.write(f"ENV_FILE={file_value}\nENV_AFTER=present\n")

        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        os.makedirs(doc_dir, exist_ok=True)
        _write_ssi_echo(os.path.join(doc_dir, "quoted.shtml"),
                        ["ENV_FILE", "ENV_DIRECT", "ENV_AFTER"], encoding="none")

        direct_value = expected.replace("\\", "\\\\").replace('"', '\\"')
        conf = HttpdConf(env, extras={
            'base': f"""
            SetEnvFromFile "{env_file}"
            SetEnv ENV_DIRECT "{direct_value}"
            <Directory "{doc_dir}">
                Options +Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

        r = env.curl_get(env.mkurl("http", "test1", "/quoted.shtml"))
        assert r.response, "no response: server may have crashed"
        assert r.response["status"] == 200
        assert r.response["body"].decode("utf-8").splitlines() == [
            f"ENV_FILE=[{expected}]",
            f"ENV_DIRECT=[{expected}]",
            "ENV_AFTER=[present]",
        ]

    @pytest.mark.parametrize("quote", ['"', "'"], ids=["double", "single"])
    @pytest.mark.parametrize("expected", [
        pytest.param("hello", id="plain"),
        pytest.param("hello ", id="trailing-space"),
        pytest.param(" hello", id="leading-space"),
        pytest.param(" hello ", id="surrounding-spaces"),
        pytest.param("", id="empty"),
        pytest.param(" \t ", id="whitespace-only"),
        pytest.param("hello world", id="embedded-space"),
        pytest.param('say "hello" and \'bye\'', id="quote-escaping"),
        pytest.param('"unfinished', id="literal-double-quote-prefix"),
        pytest.param("'unfinished", id="literal-single-quote-prefix"),
        pytest.param('"hello"', id="literal-double-quotes"),
        pytest.param("'hello'", id="literal-single-quotes"),
        pytest.param(r"C:\app\file", id="backslash-escaping"),
        pytest.param("C:\\app\\", id="trailing-backslash"),
        pytest.param(r"\n\t", id="literal-escapes"),
        pytest.param("key=value # literal", id="equals-and-hash"),
    ])
    def test_metadata_002_08_quoted(self, env, quote, expected):
        value = expected.replace("\\", "\\\\").replace(quote, "\\" + quote)
        self.check_value(env, quote + value + quote, expected)

    @pytest.mark.parametrize("quote", ['"', "'"], ids=["double", "single"])
    def test_metadata_002_09_quoted_whitespace(self, env, quote):
        self.check_value(env, f" \t{quote} hello {quote} \t", " hello ")

    @pytest.mark.parametrize("quote", ['"', "'"], ids=["double", "single"])
    def test_metadata_002_10_quoted_continuation(self, env, quote):
        self.check_value(env, f"{quote}first \\\nsecond {quote}", "first second ")

    @pytest.mark.parametrize("file_value, expected", [
        pytest.param("hello world", "hello world", id="embedded-space"),
        pytest.param("  hello world  ", "  hello world", id="whitespace"),
        pytest.param(r"C:\app\file", r"C:\app\file", id="literal-backslashes"),
        pytest.param(r"a\\b", r"a\\b", id="doubled-backslash"),
        pytest.param('hello "world"', 'hello "world"', id="embedded-quotes"),
        pytest.param("", "", id="empty"),
        pytest.param("   ", "", id="whitespace-only"),
    ])
    def test_metadata_002_12_unquoted(self, env, file_value, expected):
        self.check_value(env, file_value, expected)

    @pytest.mark.parametrize("quote", ['"', "'"], ids=["double", "single"])
    def test_metadata_002_13_literal_escapes(self, env, quote):
        value = r"C:\app\n\t"
        self.check_value(env, quote + value + quote, value)
