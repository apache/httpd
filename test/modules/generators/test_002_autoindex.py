import calendar
import os
import textwrap

import pytest

from pyhttpd.conf import HttpdConf

# A modification time before the 1970 epoch, to check that mod_autoindex
# does not clamp it when sorting by last-modified (BZ 66182).
OLD_MTIME = calendar.timegm((1958, 1, 1, 0, 0, 0, 0, 0, 0))


class TestAutoindex:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        domain = f"autoindex.{env.http_tld}"
        conf = HttpdConf(env, extras={
            'base': textwrap.dedent(f"""
            LogLevel autoindex:trace1
            <Directory "{env.server_docs_dir}/autoindex/listing">
                Options +Indexes
                IndexOptions FancyIndexing ScanHTMLTitles
            </Directory>
            <Directory "{env.server_docs_dir}/autoindex/oldmtime">
                Options +Indexes
                IndexOptions FancyIndexing
            </Directory>
            """),
        })
        conf.add_vhost(domains=[domain], port=env.http_port,
                       doc_root="htdocs/autoindex")
        conf.install()

        oldmtime_dir = os.path.join(env.server_docs_dir, "autoindex", "oldmtime")
        os.makedirs(oldmtime_dir, exist_ok=True)
        oldfile = os.path.join(oldmtime_dir, "oldfile.txt")
        with open(oldfile, "w") as f:
            f.write("old file\n")
        os.utime(oldfile, (OLD_MTIME, OLD_MTIME))

        assert env.apache_restart() == 0

    def test_generators_002_01_scan_title_bare_amp(self, env):
        """A ScanHTMLTitles description ending in a bare '&' (no ';'), as in
        an "AT&T" <title>, must be rendered without reading past the end of
        the description.  Before the fix this walked one byte past the
        terminating NUL, which ASAN flags as a heap over-read."""
        r = env.curl_get(env.mkurl("http", "autoindex", "/listing/"))
        assert r.response["status"] == 200
        assert "AT&T" in r.response["body"].decode()

    def test_generators_002_02_old_mtime_not_clamped_when_sorted(self, env):
        """A file modified before 1970 keeps its real date when the listing
        is explicitly sorted by last-modified (?C=M). Before the fix,
        make_autoindex_entry() clamped any negative apr_time_t to 0 when
        keyid == K_LAST_MOD, displaying 1970-01-01 instead of the real
        1958 date -- even though the unsorted, default-order listing (which
        does not hit that code path) already showed it correctly."""
        unsorted = env.curl_get(env.mkurl("http", "autoindex", "/oldmtime/"))
        assert unsorted.response["status"] == 200
        unsorted_body = unsorted.response["body"].decode()
        assert "1958-01-01" in unsorted_body

        sorted_by_date = env.curl_get(
            env.mkurl("http", "autoindex", "/oldmtime/?C=M;O=A"))
        assert sorted_by_date.response["status"] == 200
        sorted_body = sorted_by_date.response["body"].decode()
        assert "1958-01-01" in sorted_body
        assert "1970-01-01" not in sorted_body
