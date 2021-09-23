import pytest
import os

from h2_conf import HttpdConf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.setup_data_1k_1m()
        HttpdConf(env).add_vhost_test1().install()
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
    
    # test POST on static file, slurped in by server
    def test_710_00(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        n = 10
        m = 1
        conn = 1
        fname = "data-10k"
        args = [env.h2load, "-n", "%d" % n, "-c", "%d" % conn, "-m", "%d" % m,
                f"--base-uri={env.https_base_url}",
                "-d", os.path.join(env.gen_dir, fname), url]
        r = env.run(args)
        self.check_h2load_ok(env, r, n)

    def test_710_01(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        n = 1000
        m = 100
        conn = 1
        fname = "data-1k"
        args = [env.h2load, "-n", "%d" % n, "-c", "%d" % conn, "-m", "%d" % m,
                f"--base-uri={env.https_base_url}",
                "-d", os.path.join(env.gen_dir, fname), url]
        r = env.run(args)
        self.check_h2load_ok(env, r, n)

    def test_710_02(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        n = 100
        m = 50
        conn = 1
        fname = "data-100k"
        args = [env.h2load, "-n", "%d" % n, "-c", "%d" % conn, "-m", "%d" % m,
                f"--base-uri={env.https_base_url}",
                "-d", os.path.join(env.gen_dir, fname), url]
        r = env.run(args)
        self.check_h2load_ok(env, r, n)
