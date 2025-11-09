import os
import re
import time
from datetime import datetime, timedelta
from threading import Thread

import pytest

from .env import CoreTestEnv
from pyhttpd.conf import HttpdConf


class Loader:

    def __init__(self, env, url: str, clients: int, req_per_client: int = 10):
        self.env = env
        self.url = url
        self.clients = clients
        self.req_per_client = req_per_client
        self.result = None
        self.total_request = 0
        self._thread = None

    def run(self):
        self.total_requests = self.clients * self.req_per_client
        conn_per_client = 5
        args = [self.env.h2load, f"--connect-to=localhost:{self.env.https_port}",
                "--h1",                                 # use only http/1.1
                "-n", str(self.total_requests),              # total # of requests to make
                "-c", str(conn_per_client * self.clients),   # total # of connections to make
                "-r", str(self.clients),                     # connections at a time
                "--rate-period", "2",                   # create conns every 2 sec
                self.url,
                ]
        self.result = self.env.run(args)

    def start(self):
        self._thread = Thread(target=self.run)
        self._thread.start()

    def join(self):
        self._thread.join()


class ChildDynamics:

    RE_DATE_TIME = re.compile(r'\[(?P<date_time>[^\]]+)\] .*')
    RE_TIME_FRAC = re.compile(r'(?P<dt>.* \d\d:\d\d:\d\d)(?P<frac>.(?P<micros>.\d+)) (?P<year>\d+)')
    RE_CHILD_CHANGE = re.compile(r'\[(?P<date_time>[^\]]+)\] '
                                 r'\[mpm_event:\w+\]'
                                 r' \[pid (?P<main_pid>\d+):tid \w+\] '
                                 r'.* Child (?P<child_no>\d+) (?P<action>\w+): '
                                 r'pid (?P<pid>\d+), gen (?P<generation>\d+), .*')

    def __init__(self, env: CoreTestEnv):
        self.env = env
        self.changes = list()
        self._start = None
        for l in open(env.httpd_error_log.path):
            m = self.RE_CHILD_CHANGE.match(l)
            if m:
                self.changes.append({
                    'pid': int(m.group('pid')),
                    'child_no': int(m.group('child_no')),
                    'gen': int(m.group('generation')),
                    'action': m.group('action'),
                    'rtime' : self._rtime(m.group('date_time'))
                })
                continue
            if self._start is None:
                m = self.RE_DATE_TIME.match(l)
                if m:
                    self._rtime(m.group('date_time'))

    def _rtime(self, s: str) -> timedelta:
        micros = 0
        m = self.RE_TIME_FRAC.match(s)
        if m:
            micros = int(m.group('micros'))
            s = f"{m.group('dt')} {m.group('year')}"
        d = datetime.strptime(s, '%a %b %d %H:%M:%S %Y') + timedelta(microseconds=micros)
        if self._start is None:
            self._start = d
        delta = d - self._start
        return f"{delta.seconds:+02d}.{delta.microseconds:06d}"



@pytest.mark.skipif(condition='STRESS_TEST' not in os.environ,
                    reason="STRESS_TEST not set in env")
@pytest.mark.skipif(condition=not CoreTestEnv().h2load_is_at_least('1.41.0'),
                    reason="h2load unavailable or misses --connect-to option")
class TestRestarts:

    def test_core_002_01(self, env):
        # Lets make a tight config that triggers dynamic child behaviour
        conf = HttpdConf(env, extras={
            'base': f"""
        StartServers            1
        ServerLimit             3
        ThreadLimit             4
        ThreadsPerChild         4
        MinSpareThreads         4
        MaxSpareThreads         6
        MaxRequestWorkers       12
        MaxConnectionsPerChild  0

        LogLevel mpm_event:trace6
                """,
        })
        conf.add_vhost_cgi()
        conf.install()

        # clear logs and start server, start load
        env.httpd_error_log.clear_log()
        assert env.apache_restart() == 0
        # we should see a single child started
        cd = ChildDynamics(env)
        assert len(cd.changes) == 1, f"{cd.changes}"
        assert cd.changes[0]['action'] == 'started'
        # This loader simulates 6 clients, each making 10 requests.
        # delay.py sleeps for 1sec, so this should run for about 10 seconds
        loader = Loader(env=env, url=env.mkurl("https", "cgi", "/delay.py"),
                        clients=6, req_per_client=10)
        loader.start()
        # Expect 2 more children to have been started after half time
        time.sleep(5)
        cd = ChildDynamics(env)
        assert len(cd.changes) == 3, f"{cd.changes}"
        assert len([x for x in cd.changes if x['action'] == 'started']) == 3, f"{cd.changes}"

        # Trigger a server reload
        assert env.apache_reload() == 0
        # a graceful reload lets ongoing requests continue, but
        # after a while all gen 0 children should have stopped
        time.sleep(3)  # FIXME: this pbly depends on the runtime a lot, do we have expectations?
        cd = ChildDynamics(env)
        gen0 = [x for x in cd.changes if x['gen'] == 0]
        assert len([x for x in gen0 if x['action'] == 'stopped']) == 3

        # wait for the loader to finish and stop the server
        loader.join()
        env.apache_stop()

        # Similar to before the reload, we expect 3 children to have
        # been started and stopped again on server stop
        cd = ChildDynamics(env)
        gen1 = [x for x in cd.changes if x['gen'] == 1]
        assert len([x for x in gen1 if x['action'] == 'started']) == 3
        assert len([x for x in gen1 if x['action'] == 'stopped']) == 3
