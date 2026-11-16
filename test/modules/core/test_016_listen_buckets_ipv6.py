import os
import re
import socket
from collections import Counter

import pytest

from pyhttpd.conf import HttpdConf


def listening_families(port: int):
    """Address families of all sockets in LISTEN state on *port*, read
    straight from the kernel instead of trusting what httpd logged."""
    families = []
    for family, path in [(socket.AF_INET, "/proc/net/tcp"),
                         (socket.AF_INET6, "/proc/net/tcp6")]:
        if not os.path.isfile(path):
            continue
        with open(path) as fd:
            next(fd)  # header line
            for line in fd:
                fields = line.split()
                local_addr, state = fields[1], fields[3]
                local_port = int(local_addr.split(':')[1], 16)
                if local_port == port and state == '0A':  # TCP_LISTEN
                    families.append(family)
    return families


class TestListenBucketsIPv6:
    # ListenCoresBucketsRatio only kicks in with SO_REUSEPORT and more than
    # one bucket worth of online cores; on anything else it logs a warning
    # and keeps a single bucket, in which case there is nothing to check.
    RE_BUCKETS = re.compile(r'.*AH02819: Using (?P<n>\d+) listeners bucket.*')

    def test_core_016_01(self, env):
        # Target 2-3 buckets regardless of how many cores this host has;
        # a ratio of 1 would spawn one bucket (and child process) per core,
        # needlessly heavy on a many-core CI runner.
        cpu_count = os.cpu_count() or 1
        ratio = max(1, cpu_count // 3)
        conf = HttpdConf(env, extras={
            'base': f"""
            ListenCoresBucketsRatio {ratio}
            """,
        })
        conf.install()

        start_pos = env.httpd_error_log.current_pos()
        assert env.apache_restart() == 0
        m = None
        if env.httpd_error_log.wait_for(self.RE_BUCKETS, start_pos, timeout=5):
            with open(env.httpd_error_log.path) as fd:
                fd.seek(start_pos)
                for line in fd:
                    m = self.RE_BUCKETS.match(line)
                    if m:
                        break
        if m is None or int(m.group('n')) <= 1:
            pytest.skip("ListenCoresBucketsRatio did not create multiple "
                        "listener buckets on this host (no SO_REUSEPORT "
                        "or too few online cores)")
        num_buckets = int(m.group('n'))

        families = listening_families(env.http_port)
        if socket.AF_INET6 not in families:
            pytest.skip("no IPv6 support on this host")
        # The "Listen <port>" directive has no address, so it resolves to
        # one or more wildcard sockets (one per address family that
        # open_listeners() keeps: on Linux with the default
        # --enable-v4-mapped that is a single dual-stack IPv6 socket; a
        # build configured --disable-v4-mapped would keep a separate IPv4
        # socket too). Whichever families the *original* bucket ends up
        # with, every other bucket must duplicate the same set: none of
        # them may silently gain or lose a family relative to the others.
        counts = Counter(families)
        for family, count in counts.items():
            assert count == num_buckets, (
                f"{family!s} appears in {count} of the {num_buckets} "
                f"listener buckets for port {env.http_port}, expected all "
                f"of them to have it: {families}"
            )
