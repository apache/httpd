r"""Translated from t/protocol/echo.t -- mod_echo line echoing.

Connects to the mod_echo vhost (ProtocolEcho On) and verifies each line sent is
echoed back verbatim. The Perl test echoed $0 / $^X / ($$ x 5); we use
equivalent distinctive strings. SSL variant (mod_echo_ssl) is exercised when an
SSL vhost is configured.

Perl original:
    my @test_strings = ($0, $^X, $$ x 5);
    plan tests => 1 + @test_strings (x2 if have_ssl), ['mod_echo'];
    for my $module (@modules) {
        my $sock = Apache::TestRequest::vhost_socket($module);
        ok $sock;
        for my $data (@test_strings) {
            $sock->print("$data\n");
            chomp(my $response = Apache::TestRequest::getline($sock));
            ok t_cmp($response, $data, 'echo');
        }
    }
"""

import pytest

from apache_pytest import need_module, t_cmp

TEST_STRINGS = [
    "/path/to/protocol/echo.t",
    "/usr/bin/perl",
    "1234512345123451234512345",
]


@need_module("echo")
def test_echo(http):
    modules = ["mod_echo"]
    if http.have_module("ssl") and "mod_echo_ssl" in http.config.vhosts:
        modules.insert(0, "mod_echo_ssl")

    for module in modules:
        if module not in http.config.vhosts:
            pytest.skip(f"no {module} virtual host configured")

        sock = http.vhost_socket(module)
        assert sock

        for data in TEST_STRINGS:
            sock.print(f"{data}\n")
            response = (sock.getline() or "").rstrip("\r\n")
            assert t_cmp(response, data), "echo"
        sock.close()
