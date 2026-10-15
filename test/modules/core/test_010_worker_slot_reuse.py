import os
import re
import time
from threading import Thread

import pytest

from pyhttpd.conf import HttpdConf

# One process slot, so that every new child has to take over the slot of the
# one before it.
SLOT_CONF = [
    "ServerLimit 1",
    "ThreadLimit 4",
    "StartServers 1",
    "ThreadsPerChild 4",
    "MaxRequestWorkers 4",
    # more than there can be, so that the parent looks at the number of
    # active threads on every maintenance round
    "MinSpareThreads 5",
    "MaxSpareThreads 100",
    "ExtendedStatus On",
    "LogLevel mpm_worker:debug",
    '<Location "/server-status">',
    "    SetHandler server-status",
    "</Location>",
]


def pid_is_gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def wait_until(cond, timeout: float, interval: float = 0.1) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(interval)
    return False


class TestWorkerSlotReuse:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        if os.environ.get('MPM') != 'worker':
            pytest.skip("specific to the worker MPM")
        # Logged by the parent when it finds fewer idle threads than
        # MinSpareThreads and has no scoreboard slot to start a child in.
        # Expected while the children are handing the slot over.
        env.httpd_error_log.add_ignored_lognos(
            ['AH00287', 'AH00288', 'AH01239', 'AH01243'])

    def status(self, env):
        r = env.curl_get(env.mkurl("http", "cgi", "/server-status?auto"))
        return dict(l.split(": ", 1) for l in r.stdout.splitlines()
                    if ": " in l)

    def workers(self, env):
        st = self.status(env)
        return int(st.get('BusyWorkers', 0)) + int(st.get('IdleWorkers', 0))

    # A child which lost its scoreboard slot to a newer one, and which still
    # has a thread busy, must not write into the scoreboard entries of the
    # child which owns the slot by the time that thread ends.
    #
    # Child A has a request in progress when it is replaced by B, which
    # takes over its process slot. When B is replaced by C, the parent
    # marks all the entries of the slot dead, including the one of the
    # still running thread of A, and C starts a thread there. When the
    # thread of A then ends, it must leave that entry alone: otherwise
    # the parent sees an idle thread of C less than there are.
    def test_core_010_01(self, env, tmp_path):
        conf = HttpdConf(env, extras={'base': SLOT_CONF})
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

        flag = str(tmp_path / "release")
        url = env.mkurl("http", "cgi", f"/wait_for_file.py?file={flag}")
        result = {}
        blocked = Thread(target=lambda: result.update(r=env.curl_get(url)))
        blocked.start()
        # the blocked request and the status request are both busy
        assert wait_until(
            lambda: int(self.status(env).get('BusyWorkers', 0)) >= 2, 10)

        # B replaces A and takes over its slot, A stays around for its request
        log_pos = env.httpd_error_log.current_pos()
        assert env.apache_reload() == 0
        assert env.httpd_error_log.wait_for(
            re.compile(r'.*AH00263: pid \d+ taking over scoreboard slot.*'),
            log_pos, timeout=15)
        with open(env.httpd_error_log.path) as f:
            taken = re.findall(r'AH00263: pid (\d+) taking over scoreboard '
                               r'slot from (\d+)', f.read())
        pid_b, pid_a = (int(x) for x in taken[-1])

        # C replaces B, once B has ended the entries of the slot are free
        assert env.apache_reload() == 0
        assert wait_until(lambda: pid_is_gone(pid_b), 30)
        assert not pid_is_gone(pid_a), "the old child ended with its request"
        # C is up with all of its threads, A is still blocked on its request
        assert wait_until(lambda: self.workers(env) == 4, 15)
        assert not pid_is_gone(pid_a)

        # let A finish and end, then leave the parent some maintenance
        # rounds, which are once per second, without any request to
        # the server, as that would set the entry right again.
        log_pos = env.httpd_error_log.current_pos()
        open(flag, "w").close()
        blocked.join()
        assert result['r'].response['status'] == 200
        assert wait_until(lambda: pid_is_gone(pid_a), 30)
        time.sleep(3)

        # All four threads of C are active, which the parent reports as
        # being at MaxRequestWorkers (AH00287, only once). With an entry of
        # C set dead it finds the scoreboard not full instead (AH00288).
        with open(env.httpd_error_log.path) as f:
            f.seek(log_pos)
            log = f.read()
        assert "AH00288" not in log, \
            f"parent sees fewer threads of C after the old child ended: {log}"
