"""PHP-FPM daemon lifecycle for PHP tests.

mod_php is not built in the test httpd, so the PHP tests (t/php/*.php) are served
by routing requests to a PHP-FPM daemon over mod_proxy_fcgi. This module manages
that daemon: it generates an FPM config (a single static pool on a chosen port,
with the test's htdocs as the document root) and starts/stops ``php-fpm``.

The corresponding httpd config (a ``SetHandler proxy:fcgi://...`` for
``htdocs/php``) is emitted by :class:`apache_pytest.config.TestConfig` when a
PHP-FPM port is configured.
"""

from __future__ import annotations

import signal
import socket
import subprocess
import time
from pathlib import Path


class PhpFpm:
    """Generates an FPM pool config and runs the php-fpm daemon."""

    def __init__(
        self,
        php_fpm: Path,
        *,
        run_dir: Path,
        port: int = 9001,
        listen_addr: str = "127.0.0.1",
    ) -> None:
        self.php_fpm = php_fpm
        self.run_dir = run_dir
        self.port = port
        self.listen_addr = listen_addr
        self.proc: subprocess.Popen[bytes] | None = None
        self.conf = run_dir / "php-fpm.conf"
        self.pid_file = run_dir / "php-fpm.pid"
        self.error_log = run_dir / "php-fpm.log"

    # -- config -----------------------------------------------------------

    def generate_conf(self) -> Path:
        """Write a minimal single-static-pool FPM config under run_dir."""
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.conf.write_text(
            "[global]\n"
            f"pid = {self.pid_file}\n"
            f"error_log = {self.error_log}\n"
            "daemonize = no\n"
            "\n"
            "[www]\n"
            f"listen = {self.listen_addr}:{self.port}\n"
            "pm = static\n"
            "pm.max_children = 4\n"
            # Let httpd's ProxyFCGIBackendType FPM pass SCRIPT_FILENAME through;
            # accept .php scripts from anywhere under the test docroot.
            "security.limit_extensions = .php\n"
            # Surface PHP errors/warnings to the response for test visibility.
            "catch_workers_output = yes\n"
            "clear_env = no\n"
            # t/php/arg.php et al require argc/argv in $_SERVER. Under mod_php
            # this came from extra.conf.in's php_admin_flag, but that's inside
            # an <IfModule> keyed on a mod_php variant that's never loaded when
            # running under FPM, so it never applied -- set it here instead.
            "php_admin_value[register_argc_argv] = On\n"
        )
        return self.conf

    # -- lifecycle --------------------------------------------------------

    def _port_open(self) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.25)
            return s.connect_ex((self.listen_addr, self.port)) == 0

    def start(self, *, timeout: float = 15.0) -> None:
        self.generate_conf()
        # -F = foreground (so we own the process), -y = config file.
        self.proc = subprocess.Popen(  # noqa: S603 - trusted php-fpm path
            [str(self.php_fpm), "-F", "-y", str(self.conf)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"php-fpm exited early (code {self.proc.returncode}); "
                    f"see {self.error_log}"
                )
            if self._port_open():
                return
            time.sleep(0.1)
        self.stop()
        raise TimeoutError(f"php-fpm did not start within {timeout}s on {self.port}")

    def stop(self, *, timeout: float = 10.0) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None


def php_fpm_available(php_fpm: Path | None) -> bool:
    """True if a usable php-fpm binary was provided and exists."""
    return php_fpm is not None and php_fpm.exists()
