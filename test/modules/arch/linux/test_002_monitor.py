import re

import pytest

from pyhttpd.conf import HttpdConf

from .env import MONITOR_STATUS, MONITOR_TIMEOUT


class TestSystemdMonitor:
    """The periodic STATUS= line the monitor hook reports, which is what
    "systemctl status httpd" shows below the unit description."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            'base': """
        <Location "/server-status">
            SetHandler server-status
        </Location>
        """
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    @staticmethod
    def wait_report(env, above=-1):
        """Wait for a report from the monitor hook accounting for more than
        `above` requests, and return its fields."""
        msg = env.notify.wait_for(
            lambda m: 'STATUS' in m
            and (g := MONITOR_STATUS.match(m['STATUS'])) is not None
            and int(g.group('requests')) > above,
            timeout=MONITOR_TIMEOUT)
        assert msg, f"no monitor report within {MONITOR_TIMEOUT}s, " \
                    f"server {'up' if env.is_live() else 'down'}, " \
                    f"got {env.notify.messages}"
        return MONITOR_STATUS.match(msg['STATUS'])

    @pytest.fixture(scope='class')
    def reports(self, env, _class_scope):
        """Two consecutive reports with requests served between them, and
        the mod_status report as of the second.

        The hook runs once every ten turns of the parent's one second
        loop, so waiting for a report costs up to ten seconds.  The tests
        below share one pair rather than each waiting for its own.
        """
        env.notify.clear()
        first = self.wait_report(env)
        for _ in range(10):
            r = env.curl_get(env.mkurl("http", "test1", "/"))
            assert r.response['status'] == 200
        second = self.wait_report(env, above=int(first.group('requests')))
        r = env.curl_get(env.mkurl("http", "test1", "/server-status?auto"))
        assert r.response['status'] == 200
        auto = {}
        for line in r.response['body'].decode().splitlines():
            key, sep, value = line.partition(':')
            if sep and key not in auto:
                auto[key] = value.strip()
        return {'first': first, 'second': second, 'auto': auto}

    def test_systemd_002_01_report_format(self, reports):
        m = reports['first']
        assert int(m.group('requests')) >= 0
        assert m.group('bps')

    def test_systemd_002_02_requests_counted(self, reports):
        """The request count reported to systemd tracks requests served."""
        before = int(reports['first'].group('requests'))
        after = int(reports['second'].group('requests'))
        assert after >= before + 10, \
            f"{after - before} requests reported, at least 10 were served"

    def test_systemd_002_03_rates_are_finite(self, reports):
        """Neither rate is inf or nan.

        systemd_monitor() divides by an uptime in whole seconds, which is
        zero for a report arriving in the first second after the scoreboard
        records a restart.
        """
        for which in ('first', 'second'):
            m = reports[which]
            rate = m.group('rate')
            assert re.match(r'^-?\d', rate), f"{which} request rate is {rate!r}"
            assert float(rate) >= 0
            assert 'inf' not in m.group('bps') and 'nan' not in m.group('bps'), \
                f"{which} byte rate is {m.group('bps')!r}"

    def test_systemd_002_04_report_repeats(self, env, reports):
        """The status line keeps being refreshed while the server runs."""
        assert reports['first'].group(0) != reports['second'].group(0)

    def test_systemd_002_05_worker_percentages(self, reports):
        """Idle and busy are percentages of the workers available, and are
        reported as such."""
        m, auto = reports['second'], reports['auto']
        idle, busy = int(m.group('idle')), int(m.group('busy'))
        assert 0 <= idle <= 100 and 0 <= busy <= 100
        # Integer division loses at most one point between the two.
        assert 99 <= idle + busy <= 100
        # Busy workers are a minority of a mostly idle test server, which
        # is what mod_status reports over the same scoreboard.
        assert int(auto['IdleWorkers']) > int(auto['BusyWorkers'])
        assert idle > busy
