r"""Translated from t/protocol/nntp-like.t -- server speaks before client.

Tests that the server can respond immediately after the client connects, before
the client sends any request data (mod_nntp_like emits a "200 localhost - ready"
banner, then echoes commands).

The Perl test gates on a deferred-accept condition: the test only runs when the
httpd is older than 2.1.0 OR the OS is neither Linux nor macOS -- because with
deferred accept() the kernel withholds the connection from the server until the
client sends data, so the server can't send its banner first. On a modern
(>=2.1.0) Linux/Darwin build this requirement is not met and the test SKIPS.

Perl original:
    plan tests => 5 (x2 if have_ssl & !http2), need('mod_nntp_like', {msg => sub {
        !have_min_apache_version('2.1.0') || ($^O ne "linux" && $^O ne "darwin")}});
    for my $module (@modules) {
        my $sock = Apache::TestRequest::vhost_socket($module);
        ok $sock;
        my $response = getline($sock);  $response =~ s/[\r\n]+$//;
        ok t_cmp($response, '200 localhost - ready', 'welcome response');
        for my $data ('LIST', 'GROUP dev.httpd.apache.org', 'ARTICLE 401') {
            $sock->print("$data\n");
            $response = getline($sock); chomp $response;
            ok t_cmp($response, $data, 'echo');
        }
    }
"""

import sys

import pytest

from apache_pytest import need_module, t_cmp


@need_module("nntp_like")
def test_nntp_like(http):
    # Deferred accept() prohibits this test on >=2.1.0 with Linux/Darwin.
    deferred_accept_ok = (not http.have_min_apache_version("2.1.0")) or (
        not sys.platform.startswith("linux") and sys.platform != "darwin"
    )
    if not deferred_accept_ok:
        pytest.skip(
            "deferred accept() prohibits testing with >=2.1.0 on this OS"
        )

    modules = ["mod_nntp_like"]
    if (
        http.have_module("ssl")
        and not http.have_module("http2")
        and "mod_nntp_like_ssl" in http.config.vhosts
    ):
        modules.insert(0, "mod_nntp_like_ssl")

    for module in modules:
        if module not in http.config.vhosts:
            pytest.skip(f"no {module} virtual host configured")

        sock = http.vhost_socket(module)
        assert sock

        response = (sock.getline() or "").rstrip("\r\n")
        assert t_cmp(response, "200 localhost - ready"), "welcome response"

        for data in ("LIST", "GROUP dev.httpd.apache.org", "ARTICLE 401"):
            sock.print(f"{data}\n")
            response = sock.getline()
            if response is not None:
                response = response.rstrip("\r\n")
            assert t_cmp(response, data), "echo"
        sock.close()
