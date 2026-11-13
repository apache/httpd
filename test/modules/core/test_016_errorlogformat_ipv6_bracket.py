"""ErrorLogFormat's %a/%A print an IPv6 address and port as
"address:port" -- e.g. "::1:34567" -- which is ambiguous: a log consumer
cannot tell where the address ends and the port begins, since both use
':' as a separator (BZ 65696). %{b}a/%{b}A opt into the RFC 5952,
section 6 bracket notation instead: "[::1]:34567", matching the
convention other HTTP libraries (e.g. Netty, OkHttp) already use for
the same host:port ambiguity.
"""
import re
import socket

import pytest

from pyhttpd.conf import HttpdConf


IPV6_PORT = 5221


def _has_ipv6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(('::1', 0))
        s.close()
        return True
    except (socket.error, OSError):
        return False


@pytest.fixture(autouse=True, scope='class')
def _class_scope(env):
    if not _has_ipv6():
        pytest.skip('IPv6 (::1) not available in this environment')

    conf = HttpdConf(env)
    conf.add([
        f'Listen [::1]:{IPV6_PORT}',
        'ErrorLogFormat "a=%a ba=%{b}a A=%A bA=%{b}A %M"',
    ])
    conf.start_vhost(domains=[f'ipv6.{env.http_tld}'], port=IPV6_PORT,
                      with_ssl=False)
    conf.add(['<Location "/missing">', 'Require all denied', '</Location>'])
    conf.end_vhost()
    conf.install()
    assert env.apache_restart() == 0


class TestErrorLogFormatIPv6Bracket:

    def test_core_016_01_default_format_unchanged(self, env):
        """%a/%A keep their existing, unbracketed "address:port" output
        -- this must not regress for any consumer already parsing it."""
        start = env.httpd_error_log.current_pos()
        r = env.curl_get(f'http://[::1]:{IPV6_PORT}/missing', insecure=True)
        assert r.response['status'] == 403

        env.httpd_error_log.add_ignored_matches([r'.*AH01630.*'])
        line = env.httpd_error_log.wait_for(
            re.compile(r'.*a=::1:\d+ .*A=::1:\d+ .*'), start, timeout=10)
        assert line, 'expected unbracketed a=::1:<port> and A=::1:<port>'

    def test_core_016_02_b_flag_adds_brackets(self, env):
        """%{b}a/%{b}A bracket the same IPv6 address per RFC 5952."""
        start = env.httpd_error_log.current_pos()
        r = env.curl_get(f'http://[::1]:{IPV6_PORT}/missing', insecure=True)
        assert r.response['status'] == 403

        env.httpd_error_log.add_ignored_matches([r'.*AH01630.*'])
        line = env.httpd_error_log.wait_for(
            re.compile(r'.*ba=\[::1\]:\d+ .*bA=\[::1\]:\d+ .*'), start,
            timeout=10)
        assert line, 'expected bracketed ba=[::1]:<port> and bA=[::1]:<port>'
