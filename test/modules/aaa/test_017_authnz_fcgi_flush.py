import re
import textwrap

import pytest

from pyhttpd.conf import HttpdConf
from pyhttpd.depends import needs_dependency

from .env import AAATestEnv
from .fcgi_authorizer import BODY_MARKER
from .fcgi_authorizer import start as start_fake_authorizer

NON200_RESPONSE_BUF_LEN = 8192


@needs_dependency("mod_authnz_fcgi", AAATestEnv.has_shared_module("authnz_fcgi"),
                  reason="mod_authnz_fcgi not available")
class TestAuthnzFcgiFlush:
    """BZ 65984: handle_response() in mod_authnz_fcgi.c only collected the
    non-200 response body into rspbuf the one time it first saw the end
    of the FastCGI authenticator's headers. If the authenticator flushed
    its output between the headers and the body -- sending them as two
    separate FCGI_STDOUT records, exactly as any FastCGI library that
    streams output does -- the body arriving in the later record was
    silently dropped, and Apache's generic default error page was shown
    instead of the authenticator's own 401 body."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        domain = f"authnzfcgiflush.{env.http_tld}"
        srv, port = start_fake_authorizer()

        conf = HttpdConf(env, extras={
            'base': textwrap.dedent(f"""
            AuthnzFcgiDefineProvider authn fake-flush-auth fcgi://127.0.0.1:{port}/
            """),
        })
        conf.start_vhost(domains=[domain], port=env.http_port,
                         doc_root="htdocs/test1")
        conf.add([
            '<Location "/">',
            'AuthType Basic',
            'AuthName "flush-test"',
            'AuthnzFcgiCheckAuthnProvider fake-flush-auth UserExpr "\'test-user\'"',
            'Require valid-user',
            '</Location>',
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield
        srv.close()

    def _url(self, env):
        return env.mkurl("http", "authnzfcgiflush", "/")

    def _get(self, env, case, status=401, bodylen=None, extra_options=None):
        options = [
            "-H", f"X-Test-Case: {case}",
            "-H", f"X-Test-Status: {status}",
        ]
        if bodylen is not None:
            options += ["-H", f"X-Test-Bodylen: {bodylen}"]
        if extra_options:
            options += extra_options
        return env.curl_get(self._url(env), options=options)

    @pytest.mark.parametrize("case", [
        "one-record",         # headers and body in the same FCGI_STDOUT record
        "split-headers-body", # headers and body in separate records (BZ 65984)
        "multi-chunk-body",   # body split across several records
        "split-headers",      # header block itself split across records
    ])
    def test_aaa_017_01_body_shapes(self, env, case):
        r = self._get(env, case, status=401)
        assert r.response["status"] == 401
        body = r.response["body"].decode()
        assert BODY_MARKER.decode() in body, (
            f"case {case!r}: expected the authenticator's own body to reach "
            f"the client, got: {body!r}")

    @pytest.mark.parametrize("status", [401, 403])
    def test_aaa_017_02_custom_status_and_body(self, env, status):
        r = self._get(env, "split-headers-body", status=status)
        assert r.response["status"] == status
        assert BODY_MARKER.decode() in r.response["body"].decode()

    @pytest.mark.parametrize("bodylen", [
        NON200_RESPONSE_BUF_LEN - 1,  # fits with a byte to spare
        NON200_RESPONSE_BUF_LEN,      # exactly fills rspbuf
        NON200_RESPONSE_BUF_LEN + 1,  # one byte too many: must be truncated,
                                       # not dropped or left corrupting the
                                       # brigade for later records
    ])
    def test_aaa_017_03_body_at_rspbuf_boundary(self, env, bodylen):
        r = self._get(env, "split-headers-body", status=401, bodylen=bodylen)
        assert r.response["status"] == 401
        body = r.response["body"]
        expected_len = min(bodylen, NON200_RESPONSE_BUF_LEN)
        assert len(body) == expected_len, (
            f"bodylen={bodylen}: expected {expected_len} bytes delivered, "
            f"got {len(body)}")
        # the fixed marker was placed at the tail of the generated body, so
        # it only survives truncation when the whole body fit.
        if bodylen <= NON200_RESPONSE_BUF_LEN:
            assert body.endswith(BODY_MARKER)
        if bodylen >= NON200_RESPONSE_BUF_LEN:
            # apr_brigade_flatten() can't tell "exactly filled" from
            # "truncated" apart, so rspbuf == NON200_RESPONSE_BUF_LEN
            # always logs this pre-existing, unrelated warning.
            env.httpd_error_log.ignore_recent(matches=[r'.*AH02523.*'])

    def test_aaa_017_04_200_response_body_is_ignored(self, env):
        r = self._get(env, "ignored-200", status=200, bodylen=64)
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "mod_h2 test site" in body, (
            "expected the real docroot content on a 200 authorizer "
            f"response, got: {body!r}")
        assert BODY_MARKER.decode() not in body

    def test_aaa_017_05_repeated_requests_are_independent(self, env):
        r1 = self._get(env, "split-headers-body", status=401)
        r2 = self._get(env, "multi-chunk-body", status=403)
        r3 = self._get(env, "split-headers-body", status=401)
        assert r1.response["status"] == 401
        assert r2.response["status"] == 403
        assert r3.response["status"] == 401
        for r in (r1, r2, r3):
            assert BODY_MARKER.decode() in r.response["body"].decode()

    def test_aaa_017_06_warns_on_full_rspbuf(self, env):
        env.httpd_error_log.clear_log()
        r = self._get(env, "split-headers-body", status=401,
                      bodylen=NON200_RESPONSE_BUF_LEN + 1)
        assert r.response["status"] == 401
        assert env.httpd_error_log.scan_recent(
            pattern=re.compile(".*AH02523.*"))
        env.httpd_error_log.ignore_recent(matches=[r'.*AH02523.*'])
