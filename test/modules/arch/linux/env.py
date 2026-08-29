import inspect
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from datetime import timedelta
from typing import Callable, Dict, List, Optional

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class SystemdTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(SystemdTestSetup)))
        # mod_systemd is only built with --enable-systemd, so it must not be
        # a hard requirement; the tests skip when it is absent.
        self.add_optional_modules(["systemd"])


class SystemdTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["core"])
        self._notify = None

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=SystemdTestSetup(env=self))

    @property
    def systemd_is_dso(self) -> bool:
        return os.path.isfile(os.path.join(self.libexec_dir, 'mod_systemd.so'))

    @property
    def has_systemd_module(self) -> bool:
        """Whether mod_systemd is available, however it was built:
        --enable-systemd links it statically, --enable-systemd=shared
        builds the DSO."""
        if self.systemd_is_dso:
            return True
        p = subprocess.run([self.httpd_bin, '-l'], capture_output=True,
                           text=True)
        return re.search(r'^\s+mod_systemd\.c$', p.stdout, re.M) is not None

    @property
    def notify(self) -> 'NotifyListener':
        """The stand-in notification socket httpd reports to."""
        return self._notify

    def start_notify_listener(self) -> 'NotifyListener':
        """Bind the notification socket and point httpd's $NOTIFY_SOCKET at it.

        This must happen before the server is first started, since libsystemd
        reads $NOTIFY_SOCKET from the environment of the httpd process.
        """
        assert self._notify is None
        self._notify = NotifyListener(
            os.path.join(self.server_dir, 'systemd-notify.sock'))
        self.set_httpd_env('NOTIFY_SOCKET', self._notify.path)
        return self._notify

    def stop_notify_listener(self):
        if self._notify is not None:
            self._notify.close()
            self._notify = None

    def server_env(self) -> Dict[str, str]:
        """The environment httpd is started with, as apachectl gets it."""
        return self._clean_path_env()

    @property
    def httpd_bin(self) -> str:
        return os.path.join(self.bin_dir, 'httpd')

    def apache_hard_restart(self) -> int:
        """Restart without the "graceful" flag, so the MPM starts over."""
        r = self._run_apachectl("restart")
        if r.exit_code == 0:
            return 0 if self.is_live(self._http_base, timeout=timedelta(seconds=10)) else -1
        return r.exit_code

    def read_pid_file(self, name: str = 'httpd.pid') -> Optional[int]:
        # Where PidFile lands depends on how the httpd under test resolves
        # a relative path against DefaultRuntimeDir, which has differed
        # between versions; look in both places rather than assume.
        for d in (self.server_logs_dir, self.server_dir):
            try:
                with open(os.path.join(d, name)) as fd:
                    return int(fd.read().strip())
            except (OSError, ValueError):
                continue
        return None


class NotifyListener:
    """A stand-in for the systemd notification socket.

    sd_notify(3) does nothing more than send a datagram to the AF_UNIX
    socket named by $NOTIFY_SOCKET, so an unconnected datagram socket is
    enough to observe everything mod_systemd reports, with no systemd
    instance and no privileges involved.

    Datagrams are drained by a background thread so that the periodic
    notifications from the monitor hook cannot fill the socket buffer
    while a test is doing something else.
    """

    def __init__(self, path: str):
        # sockaddr_un is limited to 108 bytes; well within reach for a
        # source tree in a home directory, but check rather than fail
        # obscurely inside bind().
        assert len(path) < 100, f"notification socket path too long: {path}"
        if os.path.exists(path):
            os.unlink(path)
        self.path = path
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._sock.bind(path)
        self._sock.settimeout(0.1)
        self._lock = threading.Lock()
        self._messages: List[Dict[str, str]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self):
        while not self._stop.is_set():
            try:
                data = self._sock.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = self.parse(data)
            except Exception as ex:
                # Never let one unreadable datagram stop the listener: the
                # tests would then see silence rather than a failure.
                log.warning(f"undecodable notification {data!r}: {ex}")
                continue
            log.debug(f"notify: {msg}")
            with self._lock:
                self._messages.append(msg)

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()
        if os.path.exists(self.path):
            os.unlink(self.path)

    @staticmethod
    def parse(data: bytes) -> Dict[str, str]:
        """Split one notification datagram into its NAME=VALUE assignments.

        The last line carries no trailing newline in the MAINPID
        notification, and a value may itself contain '='.
        """
        msg = {}
        for line in data.decode(errors='replace').split('\n'):
            name, sep, value = line.partition('=')
            if sep:
                msg[name] = value
        return msg

    @property
    def messages(self) -> List[Dict[str, str]]:
        with self._lock:
            return list(self._messages)

    def clear(self):
        with self._lock:
            self._messages.clear()

    def wait_for(self, match: Callable[[Dict[str, str]], bool],
                 timeout: float = 5.0) -> Optional[Dict[str, str]]:
        """Return the first message satisfying `match`, waiting for it to
        arrive if it has not already.  Returns None on timeout."""
        end = time.time() + timeout
        seen = 0
        while True:
            with self._lock:
                pending = self._messages[seen:]
                seen = len(self._messages)
            for msg in pending:
                if match(msg):
                    return msg
            if time.time() >= end:
                return None
            time.sleep(0.05)

    def wait_for_key(self, key: str, timeout: float = 5.0) \
            -> Optional[Dict[str, str]]:
        return self.wait_for(lambda m: key in m, timeout=timeout)

    def wait_for_status(self, pattern: str, timeout: float = 5.0) \
            -> Optional[Dict[str, str]]:
        rx = re.compile(pattern)
        return self.wait_for(lambda m: 'STATUS' in m and rx.search(m['STATUS']),
                             timeout=timeout)

    def statuses(self) -> List[str]:
        return [m['STATUS'] for m in self.messages if 'STATUS' in m]


# The STATUS= line the monitor hook reports, from systemd_monitor() in
# modules/arch/unix/mod_systemd.c.  Idle and busy are the percentages
# ap_get_sload() computes, and are -1 when there are no workers at all.
MONITOR_STATUS = re.compile(
    r'^Total requests: (?P<requests>\d+);\s*'
    r'Idle/Busy workers (?P<idle>-?\d+)%/(?P<busy>-?\d+)%;\s*'
    r'Requests/sec: (?P<rate>\S+);\s*'
    r'Bytes served/sec: (?P<bps>.*)B/sec$')

# ap_run_monitor() is called every INTERVAL_OF_WRITABLE_PROBES (10) turns of
# the ~1s parent loop in ap_wait_or_timeout(), so a status update is up to
# roughly 10 seconds away.  Waiting for one costs that; waiting to be sure
# none is coming costs the whole timeout, so keep it to a small multiple.
MONITOR_TIMEOUT = 25.0

# Showing that no report is coming costs the whole wait, so it only has to
# comfortably outlast one turn of that cycle.
NO_MONITOR_TIMEOUT = 15.0


# A configuration for a server run directly rather than through apachectl,
# sharing the server root, module list and error log with the rest of the
# suite but with its own pid file and port.
STANDALONE_CONF = """
ServerRoot "${server_dir}"
DefaultRuntimeDir logs
PidFile "${pidfile}"
Include "conf/${modules_conf}"
ServerName standalone.test
ErrorLog "logs/error_log"
LogLevel ${loglevel}
DocumentRoot "${server_dir}/htdocs"
<Directory "${server_dir}/htdocs">
    Require all granted
</Directory>
<IfModule mod_ssl.c>
    SSLSessionCache "shmcb:ssl_gcache_data(32000)"
</IfModule>
${extra}
Listen ${port}
"""


def write_server_conf(env: SystemdTestEnv, name: str, port: int,
                      modules_conf: str = 'modules.conf',
                      extra: str = '') -> str:
    """Write a standalone configuration and return its path."""
    path = os.path.join(env.server_conf_dir, f'{name}.conf')
    with open(path, 'w') as fd:
        fd.write(STANDALONE_CONF
                 .replace('${server_dir}', env.server_dir)
                 .replace('${pidfile}',
                          os.path.join(env.server_logs_dir, f'{name}.pid'))
                 .replace('${loglevel}', 'debug' if env.verbosity else 'warn')
                 .replace('${modules_conf}', modules_conf)
                 .replace('${extra}', extra)
                 .replace('${port}', str(port)))
    return path


def http_responds(port: int, timeout: float = 2.0) -> bool:
    """One HTTP request, without curl, so that a listening socket which
    nothing is serving cannot be mistaken for a running server: under socket
    activation the listener exists before httpd does."""
    try:
        with socket.create_connection(('127.0.0.1', port), 1.0) as c:
            c.settimeout(timeout)
            c.sendall(b'GET / HTTP/1.0\r\nHost: standalone.test\r\n\r\n')
            return c.recv(64).startswith(b'HTTP/1.')
    except OSError:
        return False


class ActivatedServer:
    """An httpd handed a listening socket the way a service manager does.

    The protocol is only $LISTEN_FDS descriptors starting at 3, and
    $LISTEN_PID naming the process they were meant for, so the test opens
    the socket and speaks it directly.  systemd-socket-activate would do
    the same, but its --now option is too recent to rely on, and this
    needs no systemd tooling at all.

    apachectl cannot pass descriptors, so httpd is run directly, in the
    foreground: LISTEN_PID has to be the process which calls
    sd_listen_fds(), and a daemonised parent would not be it.
    """

    def __init__(self, env: SystemdTestEnv, port: int, name: str = 'activate',
                 extra: str = '', listen_port: int = None,
                 modules_conf: str = 'modules.conf'):
        self.env = env
        self.port = port
        # The port systemd-socket-activate binds, which is the same as the
        # configured one unless a test wants them to disagree.
        self.listen_port = port if listen_port is None else listen_port
        self.name = name
        self.pid_file = os.path.join(env.server_logs_dir, f'{name}.pid')
        self.proc = None
        self.stdout = None
        self.stderr = None
        self.conf_file = write_server_conf(env, name, port,
                                           modules_conf=modules_conf,
                                           extra=extra)

    @staticmethod
    def modules_conf_without(env: SystemdTestEnv, module: str) -> str:
        """Write a copy of the generated module list with one module left
        out, to check what happens when it is not loaded."""
        name = f'modules-no-{module}.conf'
        src = os.path.join(env.server_conf_dir, 'modules.conf')
        rx = re.compile(rf'^\s*LoadModule\s+{module}_module\b')
        with open(src) as fd:
            lines = [l for l in fd if not rx.match(l)]
        with open(os.path.join(env.server_conf_dir, name), 'w') as fd:
            fd.writelines(lines)
        return name

    def args(self, fd: int) -> List[str]:
        # The shell moves the inherited socket to descriptor 3 and names
        # itself in LISTEN_PID before exec'ing httpd in its place, which is
        # the one thing this cannot do from the parent: the pid has to be
        # the one which will call sd_listen_fds().  bash rather than sh
        # because dash parses only one digit in a redirection, and the
        # socket lands well above descriptor 9.
        return [
            'bash', '-c',
            f'exec 3<&{fd}; export LISTEN_FDS=1 LISTEN_FDNAMES=activate '
            'LISTEN_PID=$$; exec "$0" "$@"',
            self.env.httpd_bin, '-DFOREGROUND',
            '-d', self.env.server_dir, '-f', self.conf_file,
        ]

    def start(self) -> 'ActivatedServer':
        lsock = socket.create_server(('', self.listen_port),
                                     family=socket.AF_INET6,
                                     dualstack_ipv6=True, backlog=128)
        try:
            # A new session so that the whole group can be signalled on the
            # way out.
            self.proc = subprocess.Popen(
                self.args(lsock.fileno()), env=self.env.server_env(),
                start_new_session=True, pass_fds=(lsock.fileno(),),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        finally:
            # The child holds it now; keeping a copy here would leave the
            # port bound after the server is gone.
            lsock.close()
        return self

    def _reap(self):
        """Collect the output of a server which has exited."""
        if self.stderr is None and self.proc.poll() is not None:
            self.stdout, self.stderr = self.proc.communicate()

    def wait_exit(self, timeout: float = 10.0) -> int:
        """Wait for a server which is expected to fail to start."""
        self.stdout, self.stderr = self.proc.communicate(timeout=timeout)
        return self.proc.returncode

    def is_live(self, timeout: float = 10.0) -> bool:
        end = time.time() + timeout
        while True:
            if self.proc.poll() is not None:
                # Collect its diagnostics, so that a test reporting the
                # server did not come up can say why.
                self._reap()
                return False
            if http_responds(self.port):
                return True
            if time.time() >= end:
                return False
            time.sleep(0.2)

    def is_running(self, settle: float = 2.0) -> bool:
        """Whether the server is still up once it has had time to fail.

        A restart which cannot find its sockets takes a few milliseconds to
        bring the parent down, and its old children go on serving after it,
        so neither an immediate check nor a request proves anything.
        """
        end = time.time() + settle
        while time.time() < end:
            if self.proc.poll() is not None:
                return False
            time.sleep(0.1)
        return True

    def reload(self) -> int:
        """Ask the running server to restart gracefully."""
        r = self.env.run([self.env.httpd_bin, '-d', self.env.server_dir,
                          '-f', self.conf_file, '-k', 'graceful'],
                         env=self.env.server_env())
        return r.exit_code

    def _signal_group(self, sig: int) -> bool:
        """Signal every process still in the server's group, reporting
        whether any remained.  start_new_session() made the process we
        launched the group leader, so its pid is the group id whether or
        not it is still alive."""
        try:
            os.killpg(self.proc.pid, sig)
            return True
        except OSError:
            return False

    def stop(self):
        if self.proc is None:
            return
        self._signal_group(signal.SIGTERM)
        if self.proc.poll() is None:
            try:
                self.stdout, self.stderr = self.proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self._signal_group(signal.SIGKILL)
                self.stdout, self.stderr = self.proc.communicate()
        # A parent which died during a failed restart leaves its children
        # behind, still holding the listening socket and still answering.
        # They have to go too, or the next test finds the port taken.
        end = time.time() + 5
        while self._signal_group(0):
            if time.time() >= end:
                self._signal_group(signal.SIGKILL)
                break
            time.sleep(0.1)

    def __enter__(self) -> 'ActivatedServer':
        return self.start()

    def __exit__(self, *args):
        self.stop()


class TransientService:
    """httpd run as a real transient systemd unit, with systemd-run.

    This is the only harness here which exercises the notification protocol
    against systemd itself rather than a stand-in socket: systemd provides
    NOTIFY_SOCKET, holds the service in "activating" until READY=1 arrives,
    tracks MAINPID, and shows the reported STATUS= as the unit's status
    text.  It needs a per-user service manager, which a login session has
    but a bare CI container does not.
    """

    def __init__(self, env: SystemdTestEnv, port: int,
                 name: str = None, extra: str = ''):
        self.env = env
        self.port = port
        self.unit = name or f'httpd-test-{os.getpid()}'
        self.conf_file = write_server_conf(env, 'transient', port, extra=extra)
        self.pid_file = os.path.join(env.server_logs_dir, 'transient.pid')

    def read_pid(self) -> Optional[int]:
        try:
            with open(self.pid_file) as fd:
                return int(fd.read().strip())
        except (OSError, ValueError):
            return None

    @staticmethod
    def is_available() -> bool:
        """Whether this user has a systemd manager to run services under."""
        if shutil.which('systemd-run') is None:
            return False
        if not os.environ.get('XDG_RUNTIME_DIR'):
            return False
        # Talking to the manager at all is the test: without a login
        # session, or with lingering off, there is none to talk to.
        try:
            return subprocess.run(['systemctl', '--user', 'show', '-p',
                                   'Version'], capture_output=True,
                                  timeout=15).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def systemctl(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(['systemctl', '--user', *args],
                              capture_output=True, text=True)

    def show(self, prop: str) -> str:
        r = self.systemctl('show', '-p', prop, '--value', f'{self.unit}.service')
        return r.stdout.strip()

    def start(self, timeout: float = 20.0) -> subprocess.CompletedProcess:
        httpd = self.env.httpd_bin
        r = subprocess.run([
            'systemd-run', '--user', '--collect', '--quiet',
            '--unit', self.unit,
            '--service-type=notify',
            '--property=KillMode=mixed',
            f'--property=ExecReload={httpd} -d {self.env.server_dir} '
            f'-f {self.conf_file} -k graceful',
            httpd, '-DFOREGROUND',
            '-d', self.env.server_dir, '-f', self.conf_file,
        ], capture_output=True, text=True, timeout=timeout)
        return r

    def wait_active(self, timeout: float = 20.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if self.show('ActiveState') == 'active':
                return True
            time.sleep(0.2)
        return False

    def stop(self):
        self.systemctl('stop', f'{self.unit}.service')
        self.systemctl('reset-failed', f'{self.unit}.service')

    def __enter__(self) -> 'TransientService':
        return self

    def __exit__(self, *args):
        self.stop()
