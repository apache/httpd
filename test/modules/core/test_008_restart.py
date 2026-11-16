import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

import pytest

from pyhttpd.conf import HttpdConf
from pyhttpd.instance import port_open, signal_group
from pyhttpd.log import HttpdErrorLog


class TestRestart:
    """The server goes on serving across a restart, graceful or not.

    Whatever the MPM does with its children, what has to hold afterwards
    is that a request is answered.  A restart which leaves the listening
    socket open with nothing behind it is the failure this catches, and
    it is not visible from the exit status of "httpd -k restart".
    """

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        conf = HttpdConf(env)
        conf.add_vhost_test1()
        conf.install()
        # Restarting is rough on mod_cgid, which is loaded for this
        # package: the daemon is signalled along with the rest of the
        # process group (AH01239), and restarting again before it has
        # unlinked its socket leaves the new one unable to bind
        # (AH01243).  Neither is what these tests are about.
        env.httpd_error_log.add_ignored_lognos(['AH01239', 'AH01243'])
        assert env.apache_restart() == 0

    def get(self, env, when):
        # --max-time, or a server which accepts the connection and then
        # says nothing hangs here rather than failing.
        r = env.curl_get(env.mkurl("http", "test1", "/"),
                         options=['--max-time', '10'])
        assert r.exit_code == 0, f"no answer {when}: {r.stderr}"
        assert r.response['status'] == 200, f"bad status {when}"

    def test_core_008_01_graceful(self, env):
        self.get(env, "before the reload")
        assert env.apache_reload() == 0
        self.get(env, "after a graceful reload")

    def test_core_008_02_ungraceful(self, env):
        """"httpd -k restart" keeps the same parent and serves again."""
        self.get(env, "before the restart")
        pid = env.read_pid_file()
        assert pid, "no pid file"
        assert env.apache_hard_restart() == 0
        assert env.read_pid_file() == pid, "the restart replaced the parent"
        self.get(env, "after an ungraceful restart")

    @pytest.mark.xfail(sys.platform == "win32", reason=
                        "mpm_winnt restart does not wait for child exit, "
                        "rapid restarts cause AH02322 socket errors")
    def test_core_008_03_repeated(self, env):
        """Restarting twice in a row is no different from once."""
        for _ in range(2):
            assert env.apache_hard_restart() == 0
            self.get(env, "after repeated restarts")


# How long an ungraceful restart or stop with busy connections may take as a
# whole (reading the configuration again and the new generation included).
# The parent's log tells whether the children were woken up (it resends
# SIGTERM after 3 seconds, "still did not exit"); this only bounds the rest,
# below the SIGKILL after 9 seconds, with room for slow runners.
EXIT_BOUND = 8.0

# Whatever the parent logs when a child does not exit when asked to
RE_STILL_RUNNING = "still did not exit"


def _log_since(env, pos):
    with open(env.httpd_error_log.path, errors='replace') as fd:
        fd.seek(pos)
        return fd.read()


class _Sockets:
    """Client connections of a test, closed whatever happens."""

    def __init__(self, env):
        self.env = env
        self.host = f"test1.{env.http_tld}"
        self.socks = []
        self.threads = []
        self.done = threading.Event()

    def connect(self, rcvbuf=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socks.append(s)
        if rcvbuf:
            # before connect(), so that the window stays small and the
            # server blocks writing the response
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        s.settimeout(10)
        s.connect(('127.0.0.1', self.env.http_port))
        return s

    def partial_request(self):
        """A request whose headers never end: a worker waits for the rest."""
        s = self.connect()
        s.sendall(f"GET / HTTP/1.1\r\nHost: {self.host}\r\n".encode())
        return s

    def slow_reader(self):
        """A large response read no further than its first bytes: a worker
        is stuck writing the rest."""
        s = self.connect(rcvbuf=4096)
        s.sendall(f"GET /big.bin HTTP/1.1\r\nHost: {self.host}\r\n\r\n".encode())
        first = s.recv(1024)
        assert first.startswith(b"HTTP/1.1 200"), f"bad response: {first!r}"
        return s

    def lingering(self):
        """A client which goes on sending after a response telling it the
        connection is closed: the server keeps reading, in its lingering
        close, for as long as it does."""
        s = self.connect()
        s.sendall(f"GET / HTTP/1.1\r\nHost: {self.host}\r\n"
                  f"Connection: close\r\n\r\n".encode())
        s.settimeout(0.1)

        def run():
            while not self.done.is_set():
                try:
                    s.sendall(b"x" * 16)
                except OSError:
                    return
                try:
                    s.recv(65536)
                except (socket.timeout, BlockingIOError):
                    pass
                except OSError:
                    return
                time.sleep(0.1)

        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.threads.append(t)
        return s

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.done.set()
        for t in self.threads:
            t.join(timeout=5)
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass
        return False


@pytest.mark.skipif(sys.platform == "win32", reason="signals and process groups")
class TestUngracefulExit:
    """An ungraceful restart or stop does not wait for busy connections.

    The children are told to exit at once, and the connections their workers
    are busy with have to be cut for them to do so: with mpm_worker a request
    being read, a response being written or a lingering close each hold a
    worker; with mpm_event the request being read does (the responses and
    the lingering closes are mostly the listener's then).  What is checked is
    the parent's own log: it resends SIGTERM and SIGKILL to children which
    still did not exit ("still did not exit"), and the test has no use for a
    server which got there that way; and, loosely, the time it all takes.
    """

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        threads = """
            StartServers            2
            ServerLimit             4
            ThreadLimit             4
            ThreadsPerChild         4
            MinSpareThreads         4
            MaxSpareThreads         12
            MaxRequestWorkers       16
        """
        conf = HttpdConf(env, extras={
            'base': f"""
        <IfModule mpm_event_module>
        {threads}
        </IfModule>
        <IfModule mpm_worker_module>
        {threads}
        </IfModule>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        env.httpd_error_log.add_ignored_lognos(['AH01239', 'AH01243'])
        # a large file the server cannot write at once; sparse
        big = os.path.join(env.server_docs_dir, 'test1', 'big.bin')
        with open(big, 'wb') as fd:
            fd.truncate(64 * 1024 * 1024)
        assert env.apache_restart() == 0
        yield
        os.unlink(big)

    @pytest.fixture(autouse=True)
    def _serving(self, env):
        # each test starts and leaves a running server
        if not env.instance.is_running():
            assert env.apache_restart() == 0
        yield
        if not env.instance.is_running():
            assert env.apache_restart() == 0

    def get(self, env, when):
        r = env.curl_get(env.mkurl("http", "test1", "/"),
                         options=['--max-time', '10'])
        assert r.exit_code == 0, f"no answer {when}: {r.stderr}"
        assert r.response['status'] == 200, f"bad status {when}"

    def check_log(self, env, pos, what):
        text = _log_since(env, pos)
        assert RE_STILL_RUNNING not in text, \
            f"{what}: the parent resent signals:\n{text}"
        for line in text.splitlines():
            assert not HttpdErrorLog.RE_ERRLOG_CRASH.match(line), \
                f"{what}: crash: {line}"
            assert not HttpdErrorLog.RE_ERRLOG_ASAN.match(line), \
                f"{what}: sanitizer: {line}"

    def ungraceful(self, env, how):
        """Restart or stop the server, ungracefully, and time it.  A restart
        is over when the new generation is serving, which the parent logs
        once the old children are gone."""
        pos = env.httpd_error_log.current_pos()
        t0 = time.monotonic()
        if how == 'restart':
            assert env.instance.restart(graceful=False, timeout=20), \
                "no restart"
        else:
            assert env.instance.stop(timeout=20), "the server did not stop"
        elapsed = time.monotonic() - t0
        return pos, elapsed

    def after(self, env, how, pos, elapsed, pid):
        what = f"ungraceful {how}"
        self.check_log(env, pos, what)
        assert elapsed < EXIT_BOUND, \
            f"{what}: took {elapsed:.1f}s (bound {EXIT_BOUND}s)"
        if how == 'restart':
            assert env.read_pid_file() == pid, "the restart replaced the parent"
        else:
            assert not env.instance.is_running()
            assert not port_open(env.http_port), "the port is still open"
            assert env.apache_restart() == 0
        self.get(env, f"after an {what}")

    @pytest.mark.parametrize("how", ["restart", "stop"])
    def test_core_008_04_busy(self, env, how):
        """Busy connections: a request not yet complete (holding a worker
        with either MPM), a response being written (holding a worker with
        mpm_worker, mostly in write completion with mpm_event)."""
        if env.mpm_module == 'mpm_motorz':
            pytest.skip("mpm_motorz doesn't wake a child reading a request "
                        "on an ungraceful stop or restart")
        pid = env.read_pid_file()
        with _Sockets(env) as c:
            c.partial_request()
            c.partial_request()
            c.slow_reader()
            c.slow_reader()
            time.sleep(1)       # for the server to be on them
            pos, elapsed = self.ungraceful(env, how)
        self.after(env, how, pos, elapsed, pid)

    @pytest.mark.parametrize("how", ["restart", "stop"])
    def test_core_008_05_lingering(self, env, how):
        """Connections in their lingering close (a worker's with mpm_worker,
        mostly the listener's with mpm_event)."""
        pid = env.read_pid_file()
        with _Sockets(env) as c:
            c.lingering()
            c.lingering()
            time.sleep(1)       # for the responses to be sent and read on
            pos, elapsed = self.ungraceful(env, how)
        self.after(env, how, pos, elapsed, pid)

    def test_core_008_06_one_process(self, env):
        """The server exits cleanly from SIGTERM in one-process mode (-X):
        the status is 0 and nothing crashes while it cleans up."""
        inst = env.instance
        assert env.apache_stop() == 0
        pos = env.httpd_error_log.current_pos()
        with tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(
                inst.argv('-X'), env=inst.env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=err, start_new_session=True)
            try:
                deadline = time.monotonic() + 30
                ready = False
                while time.monotonic() < deadline and proc.poll() is None:
                    # no "resuming normal operations" in this mode
                    if inst.all_ports_open():
                        ready = True
                        break
                    time.sleep(0.1)
                err.seek(0)
                assert ready, f"-X did not come up: {proc.poll()}: {err.read()!r}"
                for _ in range(3):
                    self.get(env, "in one-process mode")
                proc.send_signal(signal.SIGTERM)
                try:
                    rc = proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    pytest.fail("-X did not exit on SIGTERM")
            finally:
                if proc.poll() is None:
                    signal_group(proc.pid, signal.SIGKILL)
                    proc.wait()
                # whatever it started and outlived it (e.g. mod_cgid's
                # daemon) would hold the ports for the next start
                inst._reap_group(proc.pid)
            err.seek(0)
            stderr = err.read().decode(errors='replace')
        assert rc == 0, f"-X exited with {rc}: {stderr}"
        for bad in ('double free', 'corruption', 'exit signal',
                    'Segmentation', 'Abort', 'Sanitizer'):
            assert bad not in stderr, f"-X: {bad!r} on stderr: {stderr}"
        self.check_log(env, pos, "-X")
