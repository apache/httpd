import os

import pytest

from pyhttpd.conf import HttpdConf

# size and time directives parsed with ap_size_parameter_parse(), which can
# not be negative
DIRECTIVES = [
    "LimitRequestBody", "LimitXMLRequestBody",
    "ScriptLogLength", "ScriptLogBuffer",
    "CacheMinFileSize", "CacheMaxFileSize", "CacheReadSize", "CacheReadTime",
    "CacheSocacheMaxTime", "CacheSocacheMinTime", "CacheSocacheReadSize",
    "CacheSocacheReadTime",
]


class TestConfigOffT:

    # have httpd parse the configuration, like "httpd -t" does
    def check_config(self, env, directive, value):
        conf = HttpdConf(env)
        conf.add(f"{directive} {value}")
        conf.add_vhost_test1()
        conf.install()
        return env.run([os.path.join(env.bin_dir, 'httpd'),
                        "-t", "-d", env.server_dir,
                        "-f", os.path.join(env.server_dir, 'conf', 'httpd.conf')])

    @pytest.mark.parametrize("directive", DIRECTIVES)
    @pytest.mark.parametrize("value", ["0", "1", "123", "1000000", "00123",
                                       "512b", "512B", "1k", "1K", "2m", "2M",
                                       "1g", "1G"])
    def test_core_012_001(self, env, directive, value):
        r = self.check_config(env, directive, value)
        assert r.exit_code == 0, f"{r.stderr}"

    # only a whole decimal number is valid
    @pytest.mark.parametrize("directive", DIRECTIVES)
    @pytest.mark.parametrize("value", [
        "abc", "abc123", "123abc", "123foo456", "12.3", "0x10", "1kb", "k",
        "+", "-",
    ])
    def test_core_012_002(self, env, directive, value):
        r = self.check_config(env, directive, value)
        assert r.exit_code != 0, f"{value} was accepted"
        assert directive in r.stderr, f"{r.stderr}"

    # a number the directive does not accept, or too large to be stored
    @pytest.mark.parametrize("directive", DIRECTIVES)
    @pytest.mark.parametrize("value", ["-1", "9223372036854775808", "9" * 40,
                                       "8589934592g"])
    def test_core_012_003(self, env, directive, value):
        r = self.check_config(env, directive, value)
        assert r.exit_code != 0, f"{value} was accepted"
        assert directive in r.stderr, f"{r.stderr}"

    # this one has a lower limit as well
    @pytest.mark.parametrize("value, valid", [
        ["1024", True], ["102400", True], ["1023", False], ["0", False],
        ["1024abc", False], ["abc", False], ["9" * 40, False],
    ])
    def test_core_012_004(self, env, value, valid):
        r = self.check_config(env, "CacheSocacheMaxSize", value)
        if valid:
            assert r.exit_code == 0, f"{r.stderr}"
        else:
            assert r.exit_code != 0, f"{value} was accepted"
            assert "CacheSocacheMaxSize" in r.stderr, f"{r.stderr}"

    # LimitRequestBody reports invalid syntax (APR_EINVAL) and a number
    # which does not fit (APR_ERANGE) differently. A value without digits
    # is invalid syntax regardless of the status returned by the
    # underlying strto*() implementation: FreeBSD and musl set EINVAL
    # there, glibc does not.
    @pytest.mark.parametrize("value, error", [
        ["abc", "requires a non-negative integer"],
        ["+", "requires a non-negative integer"],
        ["-", "requires a non-negative integer"],
        ["abc123", "requires a non-negative integer"],
        ["123abc", "requires a non-negative integer"],
        ["12.3", "requires a non-negative integer"],
        ["9223372036854775808", "argument is not parsable"],
        ["-9223372036854775809", "argument is not parsable"],
        ["9" * 40, "argument is not parsable"],
    ])
    def test_core_012_005(self, env, value, error):
        r = self.check_config(env, "LimitRequestBody", value)
        assert r.exit_code != 0, f"{value} was accepted"
        assert f"LimitRequestBody {error}" in r.stderr, f"{r.stderr}"
