import os

import pytest

from pyhttpd.backport import not_backported
from pyhttpd.conf import HttpdConf


class TestBufferSize:

    # have httpd parse the configuration, like "httpd -t" does
    def check_config(self, env, value):
        conf = HttpdConf(env)
        conf.add(["<Location \"/buffer\">", f"    BufferSize {value}", "</Location>"])
        conf.add_vhost_test1()
        conf.install()
        return env.run([os.path.join(env.bin_dir, 'httpd'),
                        "-t", "-d", env.server_dir,
                        "-f", os.path.join(env.server_dir, 'conf', 'httpd.conf')])

    @pytest.mark.parametrize("value", ["1", "123", "131072", "00123"])
    def test_filters_004_01(self, env, value):
        r = self.check_config(env, value)
        assert r.exit_code == 0, f"{r.stderr}"

    @pytest.mark.parametrize("value", [
        "abc", "123abc", "12.3", "0x10", "0", "-1", "9" * 40,
    ])
    @not_backported("r1939129", "strict BufferSize parsing")
    def test_filters_004_02(self, env, value):
        r = self.check_config(env, value)
        assert r.exit_code != 0, f"{value} was accepted"
        assert "BufferSize must be a size in bytes" in r.stderr
