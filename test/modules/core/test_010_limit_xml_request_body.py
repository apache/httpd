import os

import pytest

from pyhttpd.conf import HttpdConf


class TestLimitXMLRequestBody:

    # have httpd parse the configuration, like "httpd -t" does
    def check_config(self, env, value):
        conf = HttpdConf(env)
        conf.add(f"LimitXMLRequestBody {value}")
        conf.add_vhost_test1()
        conf.install()
        return env.run([os.path.join(env.bin_dir, 'httpd'),
                        "-t", "-d", env.server_dir,
                        "-f", os.path.join(env.server_dir, 'conf', 'httpd.conf')])

    @pytest.mark.parametrize("value", ["0", "1", "123", "1000000"])
    def test_core_010_001(self, env, value):
        r = self.check_config(env, value)
        assert r.exit_code == 0, f"{r.stderr}"

    # only a whole non-negative decimal number is a valid limit
    @pytest.mark.parametrize("value", [
        "abc123", "123abc", "123foo456", "-1", "1.5", "0x10", "+", "-",
    ])
    def test_core_010_002(self, env, value):
        r = self.check_config(env, value)
        assert r.exit_code != 0, f"{value} was accepted"
        assert "LimitXMLRequestBody requires a non-negative integer" in r.stderr

    # more than can be stored or than the directive permits
    @pytest.mark.parametrize("value", [
        "9223372036854775807", "9223372036854775808", "9" * 40,
    ])
    def test_core_010_003(self, env, value):
        r = self.check_config(env, value)
        assert r.exit_code != 0, f"{value} was accepted"
        assert "LimitXMLRequestBody" in r.stderr
