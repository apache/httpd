import os
import re
import signal
import sys
import textwrap
import time

import pytest

from pyhttpd.conf import HttpdConf


SSI_ERROR = "[an error occurred while processing this directive]"


@pytest.mark.skipif(sys.platform == "win32", reason="mod_cgid is Unix-only")
class TestCgid:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        if not env.has_cgid_module:
            pytest.skip("mod_cgid not built")
        conf = HttpdConf(env, extras={
            'base': textwrap.dedent(f"""
            LogLevel cgid:trace1
            <Directory "{env.server_docs_dir}/cgi/ssi">
                Options +Includes
                AcceptPathInfo On
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            <Files "exec_noexec.shtml">
                Options -Includes +IncludesNOEXEC
            </Files>
            <LocationMatch "^/ssi/$">
                SetHandler cgi-script
            </LocationMatch>
            """),
            f"cgi.{env.http_tld}": textwrap.dedent("""
            ScriptLog logs/cgid_script.log
            Header always set X-Cgid-Test on early
            <LocationMatch "^/sleep">
                CGIDScriptTimeout 1
            </LocationMatch>
            """),
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

    def script_log(self, env):
        return os.path.join(env.server_logs_dir, "cgid_script.log")

    def get(self, env, host, path, options=None):
        r = env.curl_get(env.mkurl("http", host, path),
                         options=['--max-time', '15'] + (options or []))
        assert r.exit_code == 0, r.stderr
        return r

    @pytest.mark.parametrize(["query", "argv"], [
        ["foo+bar%20baz", ["foo", "bar baz"]],
        ["a%3Bb", ["a\\;b"]],
        ["x=1", []],
    ])
    def test_generators_001_01_isindex_args(self, env, query, argv):
        """A query string without '=' is split on '+' into argv,
        unescaped and then shell-escaped."""
        r = self.get(env, "cgi", f"/argv.py?{query}")
        assert r.response["status"] == 200
        assert r.response["body"].decode().splitlines() == argv

    def test_generators_001_02_script_log(self, env):
        """ScriptLog set in a vhost records the script's stderr, then the
        request headers, request body and err_headers_out."""
        log = self.script_log(env)
        if os.path.exists(log):
            os.unlink(log)
        r = env.curl_post_data(env.mkurl("http", "cgi", "/stderr_fail.py"),
                               data="posted-body-marker")
        assert r.response["status"] == 500
        with open(log) as fd:
            content = fd.read()
        assert "%error\ncgid-stderr-marker\n" in content
        assert "%% 500 " in content
        assert "%request\n" in content
        assert "\nposted-body-marker\n" in content
        assert "%response\nX-Cgid-Test: on\n" in content
        env.httpd_error_log.ignore_recent(
            lognos=["AH01215", "AH10599"],
            matches=[r".*End of script output before headers: stderr_fail\.py"])

    def test_generators_001_03_timeout(self, env):
        """CGIDScriptTimeout gives 504 for a script which says nothing."""
        start = time.time()
        r = self.get(env, "cgi", "/sleep.py")
        assert r.response["status"] == 504
        assert time.time() - start < 4
        env.httpd_error_log.ignore_recent(
            lognos=["AH01220"],
            matches=[r".*Script timed out before returning headers: sleep\.py"])

    def test_generators_001_04_timeout_sigkill(self, env):
        """A timed-out script which ignores SIGTERM is sent SIGKILL."""
        r = self.get(env, "cgi", "/sleep_trap.py")
        assert r.response["status"] == 504
        self.wait_for_log(env, "AH01259")
        env.httpd_error_log.ignore_recent(
            lognos=["AH01220", "AH01259"],
            matches=[r".*Script timed out before returning headers: sleep_trap\.py"])

    def test_generators_001_05_redirect(self, env):
        """An absolute Location from a script with no Status is a 302."""
        r = self.get(env, "cgi", "/redirect.py")
        assert r.response["status"] == 302
        assert r.response["header"]["location"] == "http://example.invalid/target"

    def test_generators_001_06_directory(self, env):
        """A directory mapped to cgi-script is refused."""
        r = self.get(env, "cgi", "/ssi/")
        assert r.response["status"] == 403
        env.httpd_error_log.ignore_recent(lognos=["AH01265"])

    @pytest.mark.xfail(reason="the script's socket is reset when it exits "
                       "with unread input, discarding its output")
    def test_generators_001_07_body_not_read(self, env):
        """A script which exits without reading its request body
        still has its response delivered."""
        r = env.curl_post_data(env.mkurl("http", "cgi", "/noread.py"),
                               data="unread")
        env.httpd_error_log.ignore_recent(lognos=["AH02651", "AH10599"])
        assert r.exit_code == 0, r.stderr
        assert r.response["status"] == 200
        assert r.response["body"].decode() == "not reading\n"

    def test_generators_001_10_ssi_exec_cgi(self, env):
        """#exec cgi= runs the script with the document's query string."""
        r = self.get(env, "cgi", "/ssi/exec_cgi.shtml?hello+world")
        assert r.response["status"] == 200
        assert r.response["body"].decode().split() == ["hello", "world"]

    def test_generators_001_11_ssi_exec_cgi_redirect(self, env):
        """#exec cgi= of a redirecting script inserts a link."""
        r = self.get(env, "cgi", "/ssi/exec_cgi_redirect.shtml")
        assert r.response["status"] == 200
        assert r.response["body"].decode().strip() == \
            '<a href="http://example.invalid/target">' \
            'http://example.invalid/target</a>'

    @pytest.mark.parametrize(["path", "lognos"], [
        ["/ssi/exec_cgi_query.shtml", ["AH01230"]],
        ["/ssi/exec_cgi_missing.shtml", ["AH01230"]],
        ["/ssi/exec_bogus.shtml", ["AH01231"]],
        ["/ssi/exec_noexec.shtml", ["AH01228"]],
    ])
    def test_generators_001_12_ssi_exec_errors(self, env, path, lognos):
        r = self.get(env, "cgi", path)
        assert r.response["status"] == 200
        assert SSI_ERROR in r.response["body"].decode()
        env.httpd_error_log.ignore_recent(lognos=lognos)

    def test_generators_001_14_ssi_exec_cgi_nph(self, env):
        """#exec cgi= refuses an NPH script; the sub-request's failure
        leaves the directive's output empty, not an error message."""
        r = self.get(env, "cgi", "/ssi/exec_cgi_nph.shtml")
        assert r.response["status"] == 200
        assert r.response["body"].decode().strip() == ""
        env.httpd_error_log.ignore_recent(lognos=["AH01263"])

    def test_generators_001_13_ssi_exec_cmd_path_info(self, env):
        """#exec cmd= sees the document's PATH_INFO."""
        r = self.get(env, "cgi", "/ssi/exec_path_info.shtml/extra/path")
        assert r.response["status"] == 200
        assert r.response["body"].decode().strip() == "PI=/extra/path"

    def test_generators_001_20_daemon_killed(self, env):
        """CGI requests are served again once the cgid daemon which died
        unexpectedly has been restarted."""
        pids = self.daemon_pids(env)
        assert pids, "cgid daemon pid not logged"
        os.kill(pids[-1], signal.SIGKILL)
        end = time.time() + 10
        while len(self.daemon_pids(env)) == len(pids):
            assert time.time() < end, "cgid daemon not restarted"
            time.sleep(0.2)
        r = self.get(env, "cgi", "/argv.py?alive")
        assert r.response["status"] == 200
        assert r.response["body"].decode().split() == ["alive"]
        env.httpd_error_log.ignore_recent(lognos=["AH01239"])

    def daemon_pids(self, env):
        """The pids of the cgid daemons started so far, oldest first."""
        with open(env.httpd_error_log.path) as fd:
            return [int(pid) for pid in re.findall(
                r"cgid daemon listening on \S+, pid (\d+)", fd.read())]

    def wait_for_log(self, env, logno, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            with open(env.httpd_error_log.path) as fd:
                if f" {logno}: " in fd.read():
                    return
            time.sleep(0.2)
        assert False, f"{logno} not logged within {timeout}s"
