"""Launch and stop the httpd test server.

Port of the lifecycle bits of Apache::TestServer. Builds the same command line
(``httpd -d <serverroot> -f <conf> -D APACHE2 -D APACHE2_4 <defines>``), starts
the server, waits for it to serve, and stops it cleanly.

The process handling -- stale servers cleared up front like Apache::TestServer's
``sub start`` does via ``sub stop``, its own session so the whole process group
can be signalled and no children are left holding ports after a failed or
interrupted run -- is :class:`pyhttpd.instance.HttpdInstance`, shared with the
modules/ suite. This class only knows the command line of the generated config.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from pyhttpd.instance import HttpdInstance, HttpdStartError

from .config import TestConfig


class HttpdServer:
    def __init__(self, config: TestConfig) -> None:
        self.config = config
        self._instance: HttpdInstance | None = None

    @property
    def instance(self) -> HttpdInstance:
        if self._instance is None:
            vars_ = self.config.vars
            self._instance = HttpdInstance(
                self.config.info.httpd,
                [
                    "-d",
                    vars_["serverroot"],
                    "-f",
                    vars_["t_conf_file"],
                    "-DFOREGROUND",
                    *[a for d in self.dversion_defines() for a in ("-D", d)],
                ],
                ports=[int(vars_["port"])],
                error_log=Path(vars_["t_logs"]) / "error_log",
                pid_files=[Path(vars_["t_pid_file"])],
                stderr_file=Path(vars_["t_logs"]) / "httpd.stderr",
                # Like Apache::TestServer, validate the config before launch
                configtest_first=True,
            )
        return self._instance

    @property
    def proc(self) -> subprocess.Popen[bytes] | None:
        return self.instance.proc

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
        return self.instance.argv()

    # -- syntax check -----------------------------------------------------

    def configtest(self) -> subprocess.CompletedProcess[str]:
        """Run ``httpd ... -t`` to validate the generated config before launch."""
        return self.instance.configtest()

    # -- lifecycle --------------------------------------------------------

    @property
    def port(self) -> int:
        return int(self.config.vars["port"])

    def start(self, *, timeout: float = 30.0) -> None:
        try:
            self.instance.start(timeout=timeout)
        except HttpdStartError as exc:
            raise RuntimeError(
                f"{exc}; see {self.config.vars['t_logs']}/error_log\n{exc.stderr}"
            ) from exc

    def stop(self, *, timeout: float = 10.0) -> None:
        """Stop the server, reaping the whole process group, idempotently.

        Safe to call when the server was never started; also clears any
        matching stale pid file.
        """
        self.instance.stop(timeout=timeout)
