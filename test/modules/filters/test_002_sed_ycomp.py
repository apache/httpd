import sys

import pytest

from pyhttpd.conf import HttpdConf

# ycomp() reports "transform strings not the same size" when the two halves of
# a y/// command differ in length, but used to carry on afterwards: the loop
# kept advancing tsp, past the closing delimiter and past the NUL terminating
# the config line, reading whatever followed until it happened to stop.  The
# error eventually reported was therefore the wrong one, "ending delimiter
# missing", raised once the walk fell off the end of the string.
TOO_SHORT = "transform strings not the same size"
FELL_OFF_THE_END = "ending delimiter missing"


# On Windows the "apachectl" pyhttpd drives is httpd.exe itself, where
# "-k start" means "start the installed service" and fails with AH00436
# before the configuration is ever read, so there is no compile error to
# assert on.
@pytest.mark.skipif(sys.platform == "win32",
                    reason="httpd -k start is service control on Windows")
class TestSedYComp:

    def install(self, env, expr):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            <Location "/">
                AddOutputFilterByType SED text/html
                OutputSed "{expr}"
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        return env._run_apachectl("start")

    # Source longer than destination: rejected, naming the real problem.
    @pytest.mark.parametrize("expr", ["y/abc/de/", "y/abcdef/de/",
                                      "y/abcdefgh/x/"])
    def test_filters_002_01(self, env, expr):
        r = self.install(env, expr)
        assert r.exit_code != 0, f"httpd started with bad expression {expr}"
        assert TOO_SHORT in r.stderr, \
            f"{expr}: expected '{TOO_SHORT}', got: {r.stderr.strip()}"
        assert FELL_OFF_THE_END not in r.stderr, \
            f"{expr}: parser walked off the end: {r.stderr.strip()}"

    # Destination longer than source is caught by the trailing check and has
    # always reported the right error; keep it that way.
    def test_filters_002_02(self, env):
        r = self.install(env, "y/ab/abc/")
        assert r.exit_code != 0
        assert TOO_SHORT in r.stderr, r.stderr

    # A well-formed y/// still compiles and the server starts.
    def test_filters_002_03(self, env):
        r = self.install(env, "y/abc/xyz/")
        assert r.exit_code == 0, f"valid expression rejected: {r.stderr}"
        assert env.is_live(), "httpd did not come up"
