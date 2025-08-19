import inspect
import json
import os
import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
@pytest.mark.skipif(not H2TestEnv().h2load_is_at_least('1.41.0'), reason="h2load misses --connect-to option")
class TestTiming:

    LOGFILE = ""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TestTiming.LOGFILE = os.path.join(env.server_logs_dir, "test_009")
        if os.path.isfile(TestTiming.LOGFILE):
            os.remove(TestTiming.LOGFILE)
        conf = H2Conf(env=env)
        conf.add([
            "CustomLog logs/test_009 combined"
        ])
        conf.add_vhost_cgi()
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # check that we get a positive time_taken reported on a simple GET
    def test_h2_009_01(self, env):
        path = '/002.jpg'
        url = env.mkurl("https", "test1", f'{path}?01')
        args = [
            env.h2load, "-n", "1", "-c", "1", "-m", "1",
            f"--connect-to=localhost:{env.https_port}",
            f"--base-uri={url}", url
        ]
        r = env.run(args)
        # Restart for logs to be flushed out
        assert env.apache_restart() == 0
        found = False
        for line in open(TestTiming.LOGFILE).readlines():
            e = json.loads(line)
            if e['request'] == f'GET {path}?01 HTTP/2.0':
                assert e['time_taken'] > 0
                found = True
        assert found, f'request not found in {TestTiming.LOGFILE}'

    # test issue #253, where time_taken in a keepalive situation is not
    # reported until the next request arrives
    def test_h2_009_02(self, env):
        baseurl = env.mkurl("https", "test1", '/')
        tscript = os.path.join(env.gen_dir, 'h2load-timing-009_02')
        with open(tscript, 'w') as fd:
            fd.write('\n'.join([
                f'0.0\t/002.jpg?02a',        # 1st request right away
                f'1000.0\t/002.jpg?02b',     # 2nd a second later
            ]))
        args = [
            env.h2load,
            f'--timing-script-file={tscript}',
            f"--connect-to=localhost:{env.https_port}",
            f"--base-uri={baseurl}"
        ]
        r = env.run(args)
        # Restart for logs to be flushed out
        assert env.apache_restart() == 0
        found = False
        for line in open(TestTiming.LOGFILE).readlines():
            e = json.loads(line)
            if e['request'] == f'GET /002.jpg?02a HTTP/2.0':
                assert e['time_taken'] > 0
                assert e['time_taken'] < 500 * 1000, f'time for 1st request not reported correctly'
                found = True
        assert found, f'request not found in {TestTiming.LOGFILE}'
