import os

import pytest

from pyhttpd.conf import HttpdConf


class TestConfigQuota:

    # have httpd parse the configuration, like "httpd -t" does
    def check_config(self, env, value):
        conf = HttpdConf(env)
        conf.add(f"DavQuota {value}")
        conf.add_vhost_test1()
        conf.install()
        return env.run([os.path.join(env.bin_dir, 'httpd'),
                        "-t", "-d", env.server_dir,
                        "-f", os.path.join(env.server_dir, 'conf', 'httpd.conf')])

    @pytest.mark.parametrize("value", [
        "Off", "None", "0", "1", "123", "1000000", "00123",
    ])
    def test_dav_003_01(self, env, value):
        r = self.check_config(env, value)
        assert r.exit_code == 0, f"{r.stderr}"

    # not Off, None or a size, in particular no negative number, which would
    # be taken for one of the first two
    @pytest.mark.parametrize("value", [
        "abc", "123abc", "12.3", "0x10", "-1", "-2", "9" * 40,
    ])
    def test_dav_003_02(self, env, value):
        r = self.check_config(env, value)
        assert r.exit_code != 0, f"{value} was accepted"
        assert "DAVquota must be Off, None, or a size in bytes" in r.stderr
