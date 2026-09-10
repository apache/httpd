import os
import re
import pytest

from pyhttpd.conf import HttpdConf


def _write_ssi_echo(path, names):
    """An SSI page echoing each variable as NAME=[value].  An unset
    variable echoes the default "(none)", so a set-but-empty variable
    ("[]") is distinguishable from one that never made it into the table.
    """
    with open(path, "w") as f:
        for name in names:
            f.write(f'{name}=[<!--#echo var="{name}" -->]\n')


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
        # The malformed line is skipped with a warning.  The file is read
        # while the configuration is parsed, before the error log is open,
        # so the AH10624 warning goes to stderr rather than the error log.
        assert "AH10624" in env.apachectl_stderr
        assert "Skipping malformed line" in env.apachectl_stderr
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
        # ... reporting why
        assert "Could not open file" in env.apachectl_stderr

        # restore a working, running server so the log check and package
        # teardown are clean
        env.httpd_error_log.clear_log()
        good = HttpdConf(env)
        good.add_vhost_test1()
        good.install()
        assert env.apache_restart() == 0
