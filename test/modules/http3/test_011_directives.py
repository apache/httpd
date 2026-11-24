import re

import pytest

from .env import H3Conf

# (directive, smallest, largest) accepted value
NUMERIC = [
    ("H3Port", 1, 65535),
    ("H3MaxConcurrentStreams", 1, 65535),
    ("H3MaxConnections", 1, 10000),
    ("H3StreamBufferSize", 1, 1048576),
    ("H3MaxRequestBodySize", 1, 1073741824),
    ("H3MaxResponseBodySize", 1, 2147483648),
    ("H3AltSvcMaxAge", 1, 604800),
    ("H3HandshakeTimeout", 1, 600),
    ("H3IdleTimeout", 1, 86400),
    ("H3SocketBufferSize", 1, 67108864),
    ("H3StreamTimeout", 1, 86400),
    ("H3MaxStreamErrors", 1, 10000),
    ("H3QpackTableCapacity", 0, 1048576),
    ("H3QpackBlockedStreams", 0, 1000),
    ("H3MinWorkers", 1, 4096),
    ("H3MaxWorkers", 1, 4096),
    ("H3MaxWorkerIdleSeconds", 1, 86400),
]

FLAGS = ["H3AltSvc", "H3AddressValidation", "H3SessionTickets"]


def configtest(env, directives):
    H3Conf(env).add_h3_vhost(directives=directives).install()
    return env.instance.configtest()


class TestDirectives:

    @pytest.mark.parametrize("name,lo,hi", NUMERIC)
    def test_h3_011_01_accepted(self, env, name, lo, hi):
        for value in (lo, hi):
            r = configtest(env, [f"{name} {value}"])
            assert r.returncode == 0, f"{name} {value}: {r.stderr}"

    @pytest.mark.parametrize("name,lo,hi", NUMERIC)
    def test_h3_011_02_out_of_range(self, env, name, lo, hi):
        values = [hi + 1] if lo == 0 else [lo - 1, hi + 1]
        for value in values:
            r = configtest(env, [f"{name} {value}"])
            assert r.returncode != 0, f"{name} {value} accepted"
            assert f"{name}: '{value}' is out of allowed range" in r.stderr

    @pytest.mark.parametrize("name,lo,hi", NUMERIC)
    @pytest.mark.parametrize("value", ["abc", "10x", "-1"])
    def test_h3_011_03_not_a_number(self, env, name, lo, hi, value):
        r = configtest(env, [f"{name} {value}"])
        assert r.returncode != 0, f"{name} {value} accepted"
        assert f"{name}: '{value}'" in r.stderr

    @pytest.mark.parametrize("name", FLAGS)
    def test_h3_011_04_flags(self, env, name):
        for value in ("on", "off", "On", "OFF"):
            r = configtest(env, [f"{name} {value}"])
            assert r.returncode == 0, f"{name} {value}: {r.stderr}"
        r = configtest(env, [f"{name} maybe"])
        assert r.returncode != 0
        assert f"{name} must be On or Off" in r.stderr

    @pytest.mark.parametrize("name", [n for n, _, _ in NUMERIC] + FLAGS)
    def test_h3_011_05_not_in_directory(self, env, name):
        r = configtest(env, [
            "<Location /h3>",
            f"  {name} 1" if name not in FLAGS else f"  {name} on",
            "</Location>",
        ])
        assert r.returncode != 0, f"{name} accepted in <Location>"
        assert f"{name} not allowed in <Location> context" in r.stderr

    def test_h3_011_06_workers_min_above_max(self, env):
        H3Conf(env).add_h3_vhost(directives=[
            "H3MinWorkers 8",
            "H3MaxWorkers 4",
        ]).install()
        assert env.apache_restart() == 0
        warning = r'.*H3MaxWorkers \(4\) is below H3MinWorkers \(8\); raising it'
        assert env.httpd_error_log.scan_recent(re.compile(warning), timeout=5)
        env.httpd_error_log.ignore_recent(matches=[warning])
