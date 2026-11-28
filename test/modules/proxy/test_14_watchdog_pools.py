"""Watchdog callbacks must not allocate from pconf or the process pool at
run time: other threads of the child use them too, without a common lock
(balancers' workers arrays grow in pconf from mod_proxy_beacon and the
balancer-manager), and children crashed on the corrupted pool.

mod_aptest's aptest-pool-probe tells how many bytes something else took from
either pool in its child since child_init.
"""

import re
import time

import pytest

from pyhttpd.backport import not_backported
from pyhttpd.conf import HttpdConf
from pyhttpd.depends import needs_dependency

from .env import ProxyTestEnv

# One child where the MPM has threads, so that the probes reach the
# watchdog's; a few under prefork, which must not reach MaxRequestWorkers.
CONFIG = [
    'Define APTEST_POOL_PROBE',
    '<IfModule mpm_prefork_module>',
    '    StartServers 2',
    '    MinSpareServers 1',
    '    MaxSpareServers 4',
    '    MaxRequestWorkers 4',
    '</IfModule>',
    '<IfModule !mpm_prefork_module>',
    '    StartServers 1',
    '    ServerLimit 1',
    '<IfModule !mpm_motorz_module>',
    '    ThreadsPerChild 25',
    '    MaxRequestWorkers 25',
    '    MinSpareThreads 1',
    '    MaxSpareThreads 25',
    '</IfModule>',
    '</IfModule>',
    '<Location "/pool-probe">',
    '    SetHandler aptest-pool-probe',
    '</Location>',
]


def start(env, lines):
    conf = HttpdConf(env)
    conf.add(CONFIG)
    conf.add(lines)
    conf.install()
    pos = env.httpd_error_log.current_pos()
    assert env.apache_restart() == 0
    return pos


def log_lines(env, pos):
    with open(env.httpd_error_log.path, errors="replace") as fd:
        fd.seek(pos)
        return fd.readlines()


def wait_pids(env, pos, pattern, count, timeout=15):
    """The pids of the first count lines matching pattern."""
    rx = re.compile(r'.*\[pid (\d+)[:\]].*' + pattern)
    deadline = time.time() + timeout
    while time.time() < deadline:
        pids = [m.group(1) for m in map(rx.match, log_lines(env, pos)) if m]
        if len(pids) >= count:
            return pids[:count]
        time.sleep(0.2)
    return None


def probe(env, pos, pid):
    """(pconf, process): bytes something else took from either pool in child
    pid.  Any value but 0 means something did: a negative or very large one
    means the pool moved to another block because of it."""
    rx = re.compile(r'.*\[pid ' + pid + r'[:\]].*aptest-pool-probe: '
                    r'pconf=(-?\d+) process=(-?\d+)')
    for _ in range(50):
        r = env.curl_get(env.mkurl("http", "test1", "/pool-probe"))
        if r.response and r.response["status"] == 501:
            pytest.skip("APR pool debugging: allocations are not contiguous")
        assert r.response and r.response["status"] == 200, r
        for line in log_lines(env, pos):
            m = rx.match(line)
            if m:
                return tuple(int(v) for v in m.groups())
    pytest.fail(f"no probe reached the watchdog's child, pid {pid}")


def measure(env, lines, pattern, count):
    """Pool deltas in the child that logged pattern count times."""
    pos = start(env, lines)
    pids = wait_pids(env, pos, pattern, count)
    assert pids, f"never logged {count} times: {pattern}"
    assert len(set(pids)) == 1, pids
    return probe(env, pos, pids[0])


HCHECK_MEMBERS = 20    # past the 16 buckets a hash starts with: it grows


@needs_dependency("mod_proxy_hcheck", ProxyTestEnv.has_shared_module("proxy_hcheck"),
                  reason="mod_proxy_hcheck not available")
class TestHcheckPools:

    @not_backported("9faada15d6", "mod_proxy_hcheck allocating from pconf at run time")
    def test_proxy_14_01_hcheck(self, env):
        lines = ['LogLevel proxy_hcheck:debug', '<Proxy "balancer://hcpool">']
        lines += [f'    BalancerMember "http://127.0.0.1:{env.http_port}/m{i:02d}/" '
                  'hcmethod=TCP hcinterval=1' for i in range(HCHECK_MEMBERS)]
        lines += ['</Proxy>']
        pconf, process = measure(env, lines, r'AH03248: Creating hc worker',
                                 HCHECK_MEMBERS)
        assert (pconf, process) == (0, 0), \
            f"pconf {pconf}, process pool {process} bytes taken by the health checks"


@needs_dependency("mod_proxy_beacon", ProxyTestEnv.has_shared_module("proxy_beacon"),
                  reason="mod_proxy_beacon not available")
class TestBeaconPools:

    @not_backported("6e5c70b9d8", "mod_proxy_beacon allocating from the process pool")
    def test_proxy_14_02_beacon_inherited_listen(self, env):
        if env.mpm_module == "mpm_prefork":
            # SIGTERM can land on the watchdog thread, and the child crashes
            # in its exit cleanup: often enough to make this test noise.
            pytest.skip("prefork children with a beacon watchdog can crash on stop")
        # No address: it is taken from the server's listener.
        lines = [
            'ProxyBeaconListen',
            'ProxyBeaconBalancer bpool',
            'ProxyBeaconSecret test-pools-shared-secret',
            '<Proxy "balancer://bpool">',
            '    ProxySet growth=5',
            '</Proxy>',
        ]
        pconf, process = measure(env, lines, r'AH10570: mod_proxy_beacon: listening', 1)
        assert (pconf, process) == (0, 0), \
            f"pconf {pconf}, process pool {process} bytes taken by the beacon"
