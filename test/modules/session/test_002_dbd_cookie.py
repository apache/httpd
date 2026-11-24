"""mod_session_dbd writes the session cookie into both r->headers_out and
r->err_headers_out (session_dbd_save(), modules/session/mod_session_dbd.c).
merge_response_headers() (modules/http/http_filters.c) concatenates the two
tables for every response with apr_table_overlay(), which does not
deduplicate, so the identical Set-Cookie line is sent twice on an ordinary,
non-redirected response. mod_session_cookie had the same bug and was fixed
for it alone (r1843244, r1869785); mod_session_dbd was never updated to
match. BZ 68473.
"""

import os
import re

import pytest

from pyhttpd.conf import HttpdConf


class TestDbdCookie:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        # DBDriver loads the driver while reading the configuration, so an
        # apr-util without the sqlite3 driver (e.g. vcpkg's on Windows)
        # would fail the whole server: check it alone first.
        driver = "sqlite3"
        r = env.dbd_driver_check(driver)
        env.require(r.exit_code == 0 or driver not in r.stderr,
                    f"no {driver} DBD driver in apr-util",
                    dep=f"apr_dbd_{driver}", detected=r.stderr.strip())
        assert r.exit_code == 0, r.stderr
        docs = os.path.join(env.server_docs_dir, "dbd")
        os.makedirs(docs, exist_ok=True)
        with open(os.path.join(docs, "index.html"), 'w') as fd:
            fd.write("dbd session\n")
        # An anonymous, DBD-backed session (mirrors the reporter's own config
        # in BZ 68473), so that a plain GET already exercises
        # session_dbd_save() on every response.
        conf = HttpdConf(env)
        conf.add([
            'DBDriver sqlite3',
            f'DBDParams "{env.dbd_file}"',
            'DBDPrepareSQL "SELECT value FROM sessions WHERE key = %s '
            'AND (expiry = 0 OR expiry > %lld)" selectsession',
            'DBDPrepareSQL "DELETE FROM sessions WHERE key = %s" deletesession',
            'DBDPrepareSQL "INSERT INTO sessions (value, expiry, key) '
            'VALUES (%s, %lld, %s)" insertsession',
            'DBDPrepareSQL "UPDATE sessions SET value = %s, expiry = %lld, '
            'key = %s WHERE key = %s" updatesession',
            f'<Directory "{docs}">',
            '    Session On',
            '    SessionMaxAge 300',
            '    SessionDBDCookieName session path=/',
            '    SessionDBDSelectLabel selectsession',
            '    SessionDBDInsertLabel insertsession',
            '    SessionDBDUpdateLabel updatesession',
            '    SessionDBDDeleteLabel deletesession',
            '</Directory>',
        ])
        conf.install()
        assert env.apache_restart() == 0

    def num_set_cookie_headers(self, env):
        url = env.mkurl("http", "session", "/dbd/index.html")
        args, headerfile = env.curl_complete_args(urls=[url])
        r = env.run(args + [url])
        assert r.exit_code == 0, f"{r}"
        with open(headerfile) as fd:
            text = fd.read()
        assert re.search(r'^HTTP/\S+ 200', text, re.M), text
        return len(re.findall(r'^set-cookie:', text, re.I | re.M))

    def test_session_002_01_no_duplicate_set_cookie(self, env):
        n = self.num_set_cookie_headers(env)
        assert n == 1, \
            f"expected exactly one Set-Cookie header for the DBD-backed " \
            f"session cookie, got {n}"
