import os

import pytest

from pyhttpd.conf import HttpdConf

# A substitution may legitimately produce zero bytes.  Later rules must still
# see the (now empty) line and continue to work on the following lines.
MODES = {
    'regex_default': '',
    'regex_flatten': 'f',
    'regex_quick': 'q',
}

DOC = "## remove this completely\nfoo\n"


class TestSubstituteEmptyResult:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        # Binary, so that no CRLF conversion happens on Windows.
        with open(os.path.join(doc_dir, "doc.html"), "wb") as f:
            f.write(DOC.encode())

    def configure(self, env, rules):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            <Location "/">
                AddOutputFilterByType SUBSTITUTE text/html
                {rules}
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, path):
        return env.curl_get(env.mkurl("http", "test1", path))

    # A rule that empties a whole line, followed by another rule.
    @pytest.mark.parametrize("mode", list(MODES), ids=list(MODES))
    def test_filters_004_01(self, env, mode):
        flags = MODES[mode]
        self.configure(env, f"""
                Substitute "s/^##.*//{flags}"
                Substitute "s/foo/bar/{flags}"
        """)
        r = self.get(env, "/doc.html")
        assert r.response, f"{mode}: no response"
        assert r.response["status"] == 200
        assert r.response["body"].decode() == "\nbar\n"

    # The same with a literal (non-regex) pattern.
    @pytest.mark.parametrize("flags", ["nf", "nq"], ids=["literal_flatten", "literal_quick"])
    def test_filters_004_05(self, env, flags):
        self.configure(env, f"""
                Substitute "s/## remove this completely//{flags}"
                Substitute "s/foo/bar/{flags}"
        """)
        r = self.get(env, "/doc.html")
        assert r.response, f"{flags}: no response"
        assert r.response["status"] == 200
        assert r.response["body"].decode() == "\nbar\n"

    # Control: the emptying rule on its own.
    def test_filters_004_02(self, env):
        self.configure(env, 'Substitute "s/^##.*//"')
        r = self.get(env, "/doc.html")
        assert r.response, "no response"
        assert r.response["body"].decode() == "\nfoo\n"

    # Control: the first rule does not match, the second one does.
    def test_filters_004_03(self, env):
        self.configure(env, """
                Substitute "s/^nomatch.*//"
                Substitute "s/foo/bar/"
        """)
        r = self.get(env, "/doc.html")
        assert r.response, "no response"
        assert r.response["body"].decode() == "## remove this completely\nbar\n"

    # Control: the first rule replaces the line with something non-empty.
    def test_filters_004_04(self, env):
        self.configure(env, """
                Substitute "s/^##.*/xx/"
                Substitute "s/foo/bar/"
        """)
        r = self.get(env, "/doc.html")
        assert r.response, "no response"
        assert r.response["body"].decode() == "xx\nbar\n"
