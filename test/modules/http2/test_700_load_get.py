import pytest

from h2_conf import HttpdConf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        HttpdConf(env).add_vhost_cgi().add_vhost_test1().install()
        assert env.apache_restart() == 0

    def check_h2load_ok(self, env, r, n):
        assert 0 == r.exit_code
        r = env.h2load_status(r)
        assert n == r.results["h2load"]["requests"]["total"]
        assert n == r.results["h2load"]["requests"]["started"]
        assert n == r.results["h2load"]["requests"]["done"]
        assert n == r.results["h2load"]["requests"]["succeeded"]
        assert n == r.results["h2load"]["status"]["2xx"]
        assert 0 == r.results["h2load"]["status"]["3xx"]
        assert 0 == r.results["h2load"]["status"]["4xx"]
        assert 0 == r.results["h2load"]["status"]["5xx"]
    
    # test load on cgi script, single connection, different sizes
    @pytest.mark.parametrize("start", [
        1000, 80000
    ])
    def test_700_10(self, env, start):
        text = "X"
        chunk = 32
        for n in range(0, 5):
            args = [env.h2load, "-n", "%d" % chunk, "-c", "1", "-m", "10",
                    f"--base-uri={env.https_base_url}"]
            for i in range(0, chunk):
                args.append(env.mkurl("https", "cgi", ("/mnot164.py?count=%d&text=%s" % (start+(n*chunk)+i, text))))
            r = env.run(args)
            self.check_h2load_ok(env, r, chunk)

    # test load on cgi script, single connection
    @pytest.mark.parametrize("conns", [
        1, 2, 16, 32
    ])
    def test_700_11(self, env, conns):
        text = "X"
        start = 1200
        chunk = 64
        for n in range(0, 5):
            args = [env.h2load, "-n", "%d" % chunk, "-c", "%d" % conns, "-m", "10",
                    f"--base-uri={env.https_base_url}"]
            for i in range(0, chunk):
                args.append(env.mkurl("https", "cgi", ("/mnot164.py?count=%d&text=%s" % (start+(n*chunk)+i, text))))
            r = env.run(args)
            self.check_h2load_ok(env, r, chunk)
