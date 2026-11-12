"""ap_send_error_response() (modules/http/http_protocol.c) prints an
"Additionally, a <N> error was encountered while trying to use an
ErrorDocument to handle the request" paragraph whenever ap_die_r()'s
recursive_error is non-zero. ap_die_r() sets recursive_error = type (the
status of whatever short-circuited the ErrorDocument's own internal
request) unconditionally, even when that status is not an error at all,
e.g. a 2xx produced by mod_alias's "Redirect <status> <path>" trick (used,
as here, to force an ErrorDocument target to report 200 for monitoring
purposes). The resulting page then falsely claims a "200 OK error" was
encountered. PR 69101.

A genuine recursive error (the ErrorDocument target itself not found) must
still be reported correctly; that behavior must not regress.
"""

import pytest

from pyhttpd.conf import HttpdConf


class TestErrdocRecursiveText:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        docs = env.server_docs_dir
        conf = HttpdConf(env)
        conf.add([
            f'<Location "/errdoc_redirect/missing.html">',
            '    ErrorDocument 404 /errdoc_redirect/custom404.html',
            '</Location>',
            'Redirect 200 /errdoc_redirect/custom404.html',
            f'<Location "/errdoc_recursive/missing.html">',
            '    ErrorDocument 404 /errdoc_recursive/also-missing.html',
            '</Location>',
        ])
        conf.install()
        assert env.apache_restart() == 0

    def test_core_015_01_success_redirect_not_shown_as_error(self, env):
        r = env.curl_get(env.mkurl("http", "core",
                                    "/errdoc_redirect/missing.html"))
        assert r.response["status"] == 404, f"{r}"
        body = r.response["body"].decode()
        assert "error was encountered" not in body, \
            f"ErrorDocument's own 200 (from mod_alias's Redirect trick) " \
            f"must not be reported as an error: {body}"

    def test_core_015_02_genuine_recursive_error_still_reported(self, env):
        r = env.curl_get(env.mkurl("http", "core",
                                    "/errdoc_recursive/missing.html"))
        assert r.response["status"] == 404, f"{r}"
        body = r.response["body"].decode()
        assert "Additionally, a 404 Not Found" in body, \
            f"a genuine recursive error (ErrorDocument target also " \
            f"missing) must still be reported: {body}"
