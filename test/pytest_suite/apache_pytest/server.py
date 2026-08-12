"""Launch and stop the httpd test server.

Port of the lifecycle bits of Apache::TestServer. Builds the same command line
(``httpd -d <serverroot> -f <conf> -D APACHE2 -D APACHE2_4 <defines>``), starts
the server, waits for its port to accept connections, and stops it cleanly.

Orphan/stale-state handling mirrors Apache::TestServer's ``sub start`` (which
calls ``sub stop`` up front to clear any prior server) and ``sub stop`` (which
reads the pid file, sends ``SIGTERM``, polls, and finally unlinks the pid
file). Because the event MPM parent forks children, we launch httpd in its own
session (``start_new_session=True``/``setsid``) so the whole process group can
be signalled with ``os.killpg`` -- escalating to ``SIGKILL`` if needed -- and
no children are left holding ports after a failed or interrupted run.
"""

from __future__ import annotations

import contextlib
import errno
import os
import sys
import signal
import socket
import subprocess
import time
from pathlib import Path

from .config import TestConfig


def _pid_alive(pid: int) -> bool:
    """Return True if a process with ``pid`` exists (``kill(0)`` probe).

    Mirrors Apache::TestServer's ``kill 0, $pid`` liveness check in ``sub
    ping``/``sub stop``.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as exc:
        # ESRCH: no such process. EPERM: exists but not ours (still alive).
        return exc.errno == errno.EPERM
    return True


def _read_pid(pid_file: Path) -> int:
    """Read the PID from ``pid_file``; return 0 if missing/empty/garbage.

    Mirrors Apache::TestServer ``sub pid``, including tolerance for a pid file
    that exists but has not been written to yet (returns 0).
    """
    try:
        text = pid_file.read_text().strip()
    except OSError:
        return 0
    try:
        return int(text)
    except ValueError:
        return 0


def _killpg_or_pid(pid: int, sig: int) -> None:
    """Send ``sig`` to the process group led by ``pid``, falling back to ``pid``.

    Children of an httpd parent launched with ``start_new_session=True`` share
    the parent's process group id (== parent pid), so signalling the group with
    ``os.killpg`` reaches the parent and all its workers. If the process is not
    a group leader (no such pgid) we fall back to signalling the bare pid.

    On Windows there are no process groups; use ``os.kill`` directly.
    """
    if pid <= 0:
        return
    if sys.platform == "win32":
        with contextlib.suppress(OSError):
            os.kill(pid, sig)
        return
    try:
        os.killpg(pid, sig)
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return  # already gone
        # Not a group leader (or no permission for the group): try the pid.
        with contextlib.suppress(OSError):
            os.kill(pid, sig)


class HttpdServer:
    def __init__(self, config: TestConfig) -> None:
        self.config = config
        self.proc: subprocess.Popen[bytes] | None = None

    # -- command line -----------------------------------------------------

    def dversion_defines(self) -> list[str]:
        """Version defines for .conf conditionals (TestServer::dversion).

        rev 2 always gets ``APACHE2``; the 2.4+ line keeps ``APACHE2_4`` (the
        ``<IfVersion>`` blocks handle finer-grained 2.5 gating). User ``-D``
        defines are appended.
        """
        v = self.config.info.version
        defs = [f"APACHE{v[0]}"]
        if v[0] == 2 and v[1] >= 4:
            defs.append("APACHE2_4")
        defs += self.config.defines
        return defs

    def args(self) -> list[str]:
        vars_ = self.config.vars
        argv = [
            str(self.config.info.httpd),
            "-d",
            vars_["serverroot"],
            "-f",
            vars_["t_conf_file"],
            "-DFOREGROUND",
        ]
        for d in self.dversion_defines():
            argv += ["-D", d]
        return argv

    # -- syntax check -----------------------------------------------------

    def configtest(self) -> subprocess.CompletedProcess[str]:
        """Run ``httpd ... -t`` to validate the generated config before launch."""
        return subprocess.run(  # noqa: S603 - trusted paths
            [*self.args(), "-t"], capture_output=True, text=True, check=False
        )

    # -- lifecycle --------------------------------------------------------

    @property
    def port(self) -> int:
        return int(self.config.vars["port"])

    @property
    def _pid_file(self) -> Path:
        return Path(self.config.vars["t_pid_file"])

    def _port_open(self) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.25)
            return s.connect_ex(("127.0.0.1", self.port)) == 0

    @classmethod
    def kill_stale(cls, pid_file: Path, *, timeout: float = 10.0) -> int:
        """Defensively clear a server left behind by a prior/crashed run.

        Mirrors the up-front ``$self->stop`` that Apache::TestServer's ``sub
        start`` performs: if ``pid_file`` names a live process, signal its
        process group with ``SIGTERM`` (escalating to ``SIGKILL`` after
        ``timeout``), then unlink the (now stale) pid file. Targets only the
        PID recorded in the file and that PID's process group -- never a broad
        pattern match. Safe to call when no pid file exists.

        Returns the PID that was found in the file (0 if none).
        """
        pid = _read_pid(pid_file)
        if pid and _pid_alive(pid):
            _killpg_or_pid(pid, signal.SIGTERM)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if not _pid_alive(pid):
                    break
                time.sleep(0.1)
            if _pid_alive(pid):
                kill_sig = signal.SIGTERM if sys.platform == "win32" else signal.SIGKILL
                _killpg_or_pid(pid, kill_sig)
                if sys.platform != "win32":
                    with contextlib.suppress(OSError):
                        os.waitpid(pid, 0)  # reap if it happens to be our child
        if pid_file.exists():
            with contextlib.suppress(OSError):
                pid_file.unlink()
        return pid

    def start(self, *, timeout: float = 30.0) -> None:
        # Like Apache::TestServer::start, clear any server (and stale pid file)
        # left over from a prior run before launching a new one.
        self.kill_stale(self._pid_file)

        check = self.configtest()
        if check.returncode != 0:
            raise RuntimeError(
                f"httpd config test failed:\n{check.stdout}\n{check.stderr}"
            )
        # start_new_session=True (setsid) puts httpd in its own process group so
        # the parent and all forked MPM children can be signalled together via
        # os.killpg, guaranteeing no orphaned children survive a failed start.
        popen_kwargs = {}
        if sys.platform != "win32":
            popen_kwargs["start_new_session"] = True
        self.proc = subprocess.Popen(  # noqa: S603 - trusted paths
            self.args(), **popen_kwargs
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                code = self.proc.returncode
                self.stop()  # reap any children that did spawn
                raise RuntimeError(
                    f"httpd exited early (code {code}); "
                    f"see {self.config.vars['t_logs']}/error_log"
                )
            if self._port_open():
                return
            time.sleep(0.1)
        self.stop()
        raise TimeoutError(f"httpd did not start within {timeout}s on port {self.port}")

    def stop(self, *, timeout: float = 10.0) -> None:
        """Stop the server, reaping the whole process group, idempotently.

        Mirrors Apache::TestServer ``sub stop``: ``SIGTERM`` the server, wait,
        then unlink the pid file. We signal the launched process *group* so the
        event MPM children die with the parent, escalating to ``SIGKILL`` if
        the group does not exit within ``timeout``. Safe to call when the
        server was never started; also clears any matching stale pid file.
        """
        proc = self.proc
        if proc is not None and proc.poll() is None:
            pgid_pid = proc.pid
            _killpg_or_pid(pgid_pid, signal.SIGTERM)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                kill_sig = signal.SIGTERM if sys.platform == "win32" else signal.SIGKILL
                _killpg_or_pid(pgid_pid, kill_sig)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=timeout)
        elif proc is not None:
            # Process exited on its own; reap it (no-op if already reaped).
            with contextlib.suppress(Exception):
                proc.wait(timeout=0)

        # Whether or not we had a live Popen handle, defensively clear anything
        # the pid file still points at and remove the file.
        self.kill_stale(self._pid_file, timeout=timeout)
        self.proc = None
