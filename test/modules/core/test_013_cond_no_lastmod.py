import email.utils
import textwrap

import pytest

from pyhttpd.conf import HttpdConf

# withdate.cgi sends "Last-Modified: Thu, 01 Jan 2015 00:00:00 GMT"
BEFORE = "Fri, 01 Jan 2010 00:00:00 GMT"
AFTER = "Fri, 01 Jan 2016 00:00:00 GMT"


class TestConditionalNoLastModified:
    """RFC 9110, sections 13.1.3 and 13.1.4: If-Modified-Since and
    If-Unmodified-Since must be ignored when the resource has no
    modification date."""

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            "base": textwrap.dedent(f"""
            <Directory "{env.server_docs_dir}/condreq">
                Options +ExecCGI
                <FilesMatch "\\.cgi$">
                    ForceType application/x-httpd-cgi
                </FilesMatch>
            </Directory>
            """)
        })
        conf.install()
        assert env.apache_restart() == 0

    def _req(self, env, name, header, options=None):
        url = env.mkurl("http", "htdocs", f"/condreq/{name}")
        return env.curl_get(url, options=(options or []) + ["-H", header])

    def _assert_full(self, r):
        assert r.response["status"] == 200
        assert r.response["body"].decode("utf-8") == "hi\n"

    @pytest.mark.parametrize("name", ["nodate.cgi", "baddate.cgi"])
    def test_core_013_01(self, env, name):
        """If-Modified-Since is ignored without a modification date."""
        # a date of the current second used to be taken as not modified,
        # try a few times to not depend on a second boundary
        for _ in range(3):
            now = email.utils.formatdate(usegmt=True)
            self._assert_full(
                self._req(env, name, f"If-Modified-Since: {now}"))

    @pytest.mark.parametrize("name", ["nodate.cgi", "baddate.cgi"])
    def test_core_013_02(self, env, name):
        """If-Unmodified-Since is ignored without a modification date."""
        self._assert_full(
            self._req(env, name, f"If-Unmodified-Since: {BEFORE}"))

    def test_core_013_03(self, env):
        """HEAD ignores both conditions without a modification date."""
        now = email.utils.formatdate(usegmt=True)
        for header in (f"If-Modified-Since: {now}",
                       f"If-Unmodified-Since: {BEFORE}"):
            r = self._req(env, "nodate.cgi", header, options=["-I"])
            assert r.response["status"] == 200

    def test_core_013_04(self, env):
        """With a Last-Modified header the conditions are evaluated."""
        r = self._req(env, "withdate.cgi", f"If-Modified-Since: {AFTER}")
        assert r.response["status"] == 304
        r = self._req(env, "withdate.cgi", f"If-Modified-Since: {AFTER}",
                      options=["-I"])
        assert r.response["status"] == 304
        self._assert_full(
            self._req(env, "withdate.cgi", f"If-Modified-Since: {BEFORE}"))
        r = self._req(env, "withdate.cgi", f"If-Unmodified-Since: {BEFORE}")
        assert r.response["status"] == 412
        self._assert_full(
            self._req(env, "withdate.cgi", f"If-Unmodified-Since: {AFTER}"))
