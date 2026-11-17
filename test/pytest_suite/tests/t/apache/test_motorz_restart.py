r"""mpm_motorz: a hard restart (SIGHUP) starts over from the new configuration,
but keeps the scoreboard that was sized when the server started.

- Listener buckets beyond ServerLimit after a restart must not start more
  children than the scoreboard has slots for.
- A directive removed before a restart goes back to its default.  Only a
  statically linked MPM can fail this one, as a shared one is reloaded.
"""

import os
import re
import time

import pytest

from apache_pytest.private_server import (PrivateServer, child_pids,
                                          load_module_lines)

MOTORZ_MAX_POLLERS = 8
THREADS_PER_CHILD = 10      # what PrivateServer configures


def online_cpus():
    try:
        return os.sysconf("SC_NPROCESSORS_ONLN")
    except (AttributeError, ValueError, OSError):
        return os.cpu_count() or 1


def skip_unless_motorz(server):
    if server.config.info.mpm != "motorz":
        pytest.skip("motorz only")


def test_restart_with_more_buckets_than_server_limit(server, tmp_path):
    skip_unless_motorz(server)
    cpus = online_cpus()
    if cpus < 3:
        pytest.skip("needs 3 or more online CPUs for 3 listener buckets")
    # Start with one bucket, but with a ratio set: only then are the
    # listeners, which a restart keeps, opened with SO_REUSEPORT.
    with PrivateServer(server.config, tmp_path,
                       extra=["ServerLimit 2",
                              f"ListenCoresBucketsRatio {cpus}"]) as srv:
        assert srv.restart(extra=["ServerLimit 2", "ListenCoresBucketsRatio 1"])
        log = srv.error_log()
        buckets = re.findall(r"AH02819: Using (\d+) listeners bucket", log)
        if not buckets or int(buckets[-1]) <= 2:
            pytest.skip("no SO_REUSEPORT listener buckets on this system")
        assert "AH10680" in log, log
        assert srv.small_ok(10)
        time.sleep(2)
        assert len(child_pids(srv.proc.pid)) <= 2


def pollsets_since(srv, pos):
    return srv.error_log()[pos:].count("motorz_setup_pollset: Using")


def wait_pollsets(srv, pos, want, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        n = pollsets_since(srv, pos)
        if n >= want:
            time.sleep(0.5)
            return pollsets_since(srv, pos)
        time.sleep(0.1)
    return pollsets_since(srv, pos)


def test_removed_directive_is_reset_by_restart(server, tmp_path):
    skip_unless_motorz(server)
    if any("mpm_motorz_module" in line
           for line in load_module_lines(server.config)):
        pytest.skip("a shared MPM is reloaded on restart, so this cannot fail")
    auto = min(online_cpus(), MOTORZ_MAX_POLLERS, THREADS_PER_CHILD)
    if auto < 2:
        pytest.skip("PollersPerChild 1 is also the default here")
    with PrivateServer(server.config, tmp_path,
                       extra=["LogLevel debug", "PollersPerChild 1"]) as srv:
        assert wait_pollsets(srv, 0, 1) == 1
        pos = len(srv.error_log())
        assert srv.restart(extra=["LogLevel debug"])
        assert wait_pollsets(srv, pos, auto) == auto
