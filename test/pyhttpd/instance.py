"""One running httpd: start, stop, restart, reap.

The server-control core shared by both suites: HttpdTestEnv (modules/),
HttpdServer (pytest_suite) and PrivateServer (throwaway servers) all drive an
HttpdInstance, and differ only in how they build the command line.

The server runs in the foreground (``-DFOREGROUND``) under our control, in its
own session on Unix, so that

* the whole process group, MPM children included, can be signalled and no
  child is left holding a port after a failed or interrupted run,
* startup problems show on the stderr we captured, whether the configuration
  is rejected or a module fails in post_config,
* graceful and hard restarts are the signals ``httpd -k`` would send to the
  parent, and we wait for the new generation to be serving: "httpd -k
  restart" only sends the signal, and a request answered straight afterwards
  may have been served by the old generation, with the old config, about to
  be killed.

On Windows there are no process groups and no signals; the parent is told to
shut down or restart through the named events of the winnt MPM.

An instance knows nothing about tests, curl or certificates. Callers that
want a stricter notion of "live" than "the ports accept connections" check
it themselves once start() returns.
"""

import contextlib
import errno
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Union

from .log import HttpdErrorLog

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"

# Logged by every MPM once the new generation is serving. The startup flag
# makes it appear whatever the LogLevel is.
RE_RESUMING = re.compile(r'.* configured -- resuming normal operations$')


class HttpdStartError(RuntimeError):
    """httpd did not come up. ``returncode`` is its exit code, or -1 when it
    was still running but never became ready; ``stderr`` is what it wrote."""

    def __init__(self, message: str, returncode: int = -1, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


def _win_pid_alive(pid: int) -> bool:
    # os.kill(pid, 0) is no probe on Windows: 0 is CTRL_C_EVENT, which it
    # sends. Ask for the exit code instead.
    import ctypes
    from ctypes import wintypes
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    ERROR_ACCESS_DENIED = 5
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        # exists, but is not ours to query
        return ctypes.get_last_error() == ERROR_ACCESS_DENIED
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def pid_alive(pid: int) -> bool:
    """Whether a process with this pid exists (``kill(0)``)."""
    if pid <= 0:
        return False
    if IS_WINDOWS:
        return _win_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except OSError as exc:
        # ESRCH: no such process. EPERM: exists but not ours, still alive.
        return exc.errno == errno.EPERM
    return True


def read_pid(pid_file: Union[str, Path]) -> int:
    """The pid in a pid file; 0 if missing, empty or garbage."""
    try:
        return int(Path(pid_file).read_text().strip())
    except (OSError, ValueError):
        return 0


def signal_group(pid: int, sig: int) -> None:
    """Send *sig* to the process group led by *pid*, else to *pid* alone.

    Children of an httpd started with start_new_session share the parent's
    group id (== its pid), so signalling the group reaches the parent and
    all its workers. On Windows there are no groups; signal the pid.
    """
    if pid <= 0:
        return
    if IS_WINDOWS:
        with contextlib.suppress(OSError):
            os.kill(pid, sig)
        return
    try:
        os.killpg(pid, sig)
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return
        with contextlib.suppress(OSError):
            os.kill(pid, sig)


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.25) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def free_port() -> int:
    """A port nobody listens on right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class HttpdInstance:
    """A single httpd, started, stopped and restarted by the test code.

    :param httpd: the httpd executable
    :param args: the command line after the executable, e.g.
        ``["-d", root, "-f", conf, "-DFOREGROUND"]``. -DFOREGROUND is added
        when missing.
    :param ports: ports that must accept connections once started
    :param error_log: the ErrorLog of the server, as a path or an
        HttpdErrorLog. Needed to wait for restarts to complete.
    :param pid_files: pid files that may name a server left behind by an
        earlier run; whatever they name is stopped before a start.
    :param env: environment of the server, default is ours
    :param stderr_file: where the stderr of the server goes (default: a
        temporary file)
    :param configtest_first: run ``httpd -t`` before starting. Costs a
        second parse; the foreground start reports the same errors.
    """

    def __init__(self, httpd: Union[str, Path], args: Sequence[str], *,
                 ports: Iterable[int] = (),
                 error_log: Union[None, str, Path, HttpdErrorLog] = None,
                 pid_files: Iterable[Union[str, Path]] = (),
                 env: Optional[Dict[str, str]] = None,
                 stderr_file: Union[None, str, Path] = None,
                 configtest_first: bool = False):
        self.httpd = str(httpd)
        self.args: List[str] = list(args)
        if "-DFOREGROUND" not in self.args:
            self.args.append("-DFOREGROUND")
        self.ports: List[int] = list(ports)
        if isinstance(error_log, (str, Path)):
            error_log = HttpdErrorLog(str(error_log))
        self.error_log: Optional[HttpdErrorLog] = error_log
        self.pid_files = [Path(p) for p in pid_files]
        self.env = env
        self._stderr_file = Path(stderr_file) if stderr_file else None
        self.configtest_first = configtest_first
        self.proc: Optional[subprocess.Popen] = None

    # -- state ------------------------------------------------------------

    @property
    def pid(self) -> int:
        """Pid of the parent process, 0 if not running."""
        return self.proc.pid if self.is_running() else 0

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def all_ports_open(self) -> bool:
        return all(port_open(p) for p in self.ports)

    def stderr_text(self) -> str:
        """What the server wrote to stderr since it was last started."""
        if self._stderr_file is None:
            return ""
        try:
            return self._stderr_file.read_text(errors="replace")
        except OSError:
            return ""

    # -- command line -----------------------------------------------------

    def argv(self, *extra: str) -> List[str]:
        return [self.httpd, *self.args, *extra]

    def configtest(self) -> subprocess.CompletedProcess:
        """Run ``httpd ... -t``."""
        return subprocess.run(self.argv("-t"), capture_output=True, text=True,
                              env=self.env, check=False)

    # -- stale servers ----------------------------------------------------

    def kill_stale(self, timeout: float = 10.0) -> None:
        """Stop whatever the pid files name: a server left behind by a crashed
        or interrupted run. Only those pids and their groups are touched."""
        for pid_file in self.pid_files:
            pid = read_pid(pid_file)
            if pid and pid_alive(pid) and not (self.proc and pid == self.proc.pid):
                # the parent first, as "httpd -k stop" does: it shuts down its
                # children, and whatever they started, in order
                with contextlib.suppress(OSError):
                    os.kill(pid, signal.SIGTERM)
                if not self._wait_gone(pid, timeout):
                    signal_group(pid, signal.SIGTERM if IS_WINDOWS else signal.SIGKILL)
                    self._wait_gone(pid, timeout)
                self._reap_group(pid)
            with contextlib.suppress(OSError):
                if pid_file.exists() and not pid_alive(pid):
                    pid_file.unlink()

    @staticmethod
    def _reap_group(pgid: int, timeout: float = 2.0) -> None:
        """Make sure nothing of the process group of a stopped parent is left:
        a helper that outlived it would hold ports or files. Normally the
        group is empty by now and this does nothing."""
        if IS_WINDOWS or pgid <= 0:
            return
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(pgid, 0)          # any member left?
            except OSError:
                return
            signal_group(pgid, sig)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    os.killpg(pgid, 0)
                except OSError:
                    return
                time.sleep(0.05)

    @staticmethod
    def _wait_gone(pid: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not pid_alive(pid):
                return True
            time.sleep(0.05)
        return not pid_alive(pid)

    # -- start ------------------------------------------------------------

    def start(self, timeout: float = 30.0) -> None:
        """Start the server and wait until it is serving.

        Raises HttpdStartError if it does not come up, with its exit code
        and the stderr it wrote; nothing is left running in that case.
        """
        self.stop()
        self.kill_stale()
        if self.configtest_first:
            check = self.configtest()
            if check.returncode != 0:
                raise HttpdStartError(
                    f"httpd config test failed:\n{check.stdout}\n{check.stderr}",
                    check.returncode, check.stderr)

        if self._stderr_file is None:
            fd, name = tempfile.mkstemp(prefix="httpd-stderr-")
            os.close(fd)
            self._stderr_file = Path(name)
        log_pos = self.error_log.current_pos() if self.error_log else 0
        popen_kwargs = {}
        if not IS_WINDOWS:
            popen_kwargs["start_new_session"] = True
        argv = self.argv()
        log.debug("starting httpd: %s", argv)
        with open(self._stderr_file, "wb") as err:
            self.proc = subprocess.Popen(  # noqa: S603 - trusted paths
                argv, env=self.env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=err, **popen_kwargs)

        deadline = time.monotonic() + timeout
        resumed = self.error_log is None
        while time.monotonic() < deadline:
            rc = self.proc.poll()
            if rc is not None:
                self.stop()
                raise HttpdStartError(
                    f"httpd exited early (code {rc})", rc, self.stderr_text())
            if not resumed:
                resumed = self.error_log.wait_for(RE_RESUMING, log_pos, timeout=0.1)
            if resumed and self.all_ports_open():
                return
            if resumed:
                time.sleep(0.05)
        stderr = self.stderr_text()
        self.stop()
        raise HttpdStartError(
            f"httpd not serving {self.ports or ''} within {timeout}s", -1, stderr)

    # -- stop -------------------------------------------------------------

    def stop(self, timeout: float = 10.0) -> bool:
        """Stop the server, the whole process group, now. Idempotent. Returns
        True when nothing of it is left, and its ports are closed."""
        proc = self.proc
        if proc is not None:
            if IS_WINDOWS:
                self._win_shutdown(proc, timeout)
            elif proc.poll() is None:
                # The parent only, as "httpd -k stop" does: it shuts down its
                # children, and the processes they started (mod_md runs
                # commands, for one), in order. Signalling the whole group at
                # once makes such helpers die with SIGTERM and report errors.
                with contextlib.suppress(OSError):
                    os.kill(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    signal_group(proc.pid, signal.SIGKILL)
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        proc.wait(timeout=timeout)
            else:
                with contextlib.suppress(Exception):
                    proc.wait(timeout=0)
            if not IS_WINDOWS:
                self._reap_group(proc.pid)
            self.proc = None
        self.kill_stale(timeout)
        return self._wait_ports_closed(timeout)

    def graceful_stop(self, timeout: float = 30.0) -> bool:
        """Ask the parent to stop once its children are done, and wait for
        that. Escalates to a hard stop when it takes longer than *timeout*."""
        proc = self.proc
        if proc is None or proc.poll() is not None:
            return self.stop(timeout)
        if not IS_WINDOWS:   # there is no graceful stop signal on Windows
            with contextlib.suppress(OSError):
                os.kill(proc.pid, signal.SIGWINCH)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=timeout)
        # reaps the group, and hard-stops when the wait above ran out
        return self.stop(timeout)

    def _wait_ports_closed(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while any(port_open(p) for p in self.ports):
            if time.monotonic() > deadline:
                log.warning("ports %s still open after stop", self.ports)
                return False
            time.sleep(0.05)
        return True

    # -- restart ----------------------------------------------------------

    def restart(self, graceful: bool = True, timeout: float = 10.0) -> bool:
        """Have the running parent restart and wait for the new generation to
        be serving. Graceful lets in-flight requests finish; otherwise the
        MPM starts over. False if there is no server, or the restart did not
        show up in the error log within *timeout*."""
        if not self.is_running():
            log.error("no httpd process to restart")
            return False
        log_pos = self.error_log.current_pos() if self.error_log else 0
        if IS_WINDOWS:
            if not self._win_signal(f"ap{self.proc.pid}_restart"):
                return False
        else:
            os.kill(self.proc.pid, signal.SIGUSR1 if graceful else signal.SIGHUP)
        if self.error_log is not None and not self.error_log.wait_for(
                RE_RESUMING, log_pos, timeout=timeout):
            log.warning("no restart logged after %s within %ss",
                        "graceful" if graceful else "restart", timeout)
            return False
        deadline = time.monotonic() + timeout
        while not self.all_ports_open():
            if time.monotonic() > deadline:
                return False
            time.sleep(0.05)
        return True

    def send_signal(self, sig: int) -> None:
        """Signal the parent process only."""
        if self.is_running():
            os.kill(self.proc.pid, sig)

    # -- Windows ----------------------------------------------------------

    @staticmethod
    def _win_signal(event_name: str) -> bool:
        import ctypes
        handle = ctypes.windll.kernel32.OpenEventW(0x0002, False, event_name)
        if not handle:
            log.error("cannot open event %s", event_name)
            return False
        ctypes.windll.kernel32.SetEvent(handle)
        ctypes.windll.kernel32.CloseHandle(handle)
        return True

    def _win_shutdown(self, proc: subprocess.Popen, timeout: float) -> None:
        if proc.poll() is not None:
            return
        log.debug("stopping httpd (signal shutdown event)")
        if not self._win_signal(f"ap{proc.pid}_shutdown"):
            log.warning("falling back to terminate")
            proc.terminate()
        try:
            proc.wait(timeout=max(timeout, 30))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
