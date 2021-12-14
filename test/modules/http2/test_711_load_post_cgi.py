import pytest
import os

from .env import H2Conf


class TestLoadCgi:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_cgi(proxy_self=True, h2proxy_self=True).install()
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
    
    # test POST on cgi, where input is read
    def test_h2_711_10(self, env):
        url = env.mkurl("https", "test1", "/echo.py")
        n = 100
        m = 5
        conn = 1
        fname = "data-100k"
        args = [
            env.h2load, "-n", str(n), "-c", str(conn), "-m", str(m),
            f"--base-uri={env.https_base_url}",
            "-d", os.path.join(env.gen_dir, fname), url
        ]
        r = env.run(args)
        self.check_h2load_ok(env, r, n)

    # test POST on cgi via http/1.1 proxy, where input is read
    def test_h2_711_11(self, env):
        url = env.mkurl("https", "test1", "/proxy/echo.py")
        n = 100
        m = 5
        conn = 1
        fname = "data-100k"
        args = [
            env.h2load, "-n", str(n), "-c", str(conn), "-m", str(m),
            f"--base-uri={env.https_base_url}",
            "-d", os.path.join(env.gen_dir, fname), url
        ]
        r = env.run(args)
        self.check_h2load_ok(env, r, n)

    # test POST on cgi via h2proxy, where input is read
    def test_h2_711_12(self, env):
        url = env.mkurl("https", "test1", "/h2proxy/echo.py")
        n = 100
        m = 5
        conn = 1
        fname = "data-100k"
        args = [
            env.h2load, "-n", str(n), "-c", str(conn), "-m", str(m),
            f"--base-uri={env.https_base_url}",
            "-d", os.path.join(env.gen_dir, fname), url
        ]
        r = env.run(args)
        self.check_h2load_ok(env, r, n)
