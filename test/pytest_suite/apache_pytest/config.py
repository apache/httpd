"""httpd configuration generation.

Faithful Python port of the runtime behavior of Apache::TestConfig (plus the
vhost bits of Apache::TestConfigPerl). Responsibilities:

* hold the ``vars`` table (paths, ports, tuning) with the same defaults/derivation
  as ``TestConfig.pm:280-383``;
* resolve module-name tokens (``@CGI_MODULE@`` etc.) against the probed module set
  (``TestConfig.pm:435-462``);
* expand ``@token@`` placeholders, dying on unknown tokens (``TestConfig.pm:1204``);
* allocate ports for ``<VirtualHost module_name>`` blocks and rewrite them, building
  a vhost registry the HTTP client uses to resolve ``module("name")``
  (``TestConfig.pm:1245-1351`` + ``TestConfigPerl::new_vhost``);
* generate ``t/conf/httpd.conf`` in the exact section order of
  ``generate_httpd_conf`` (``TestConfig.pm:1609-1690``).

Only the exercised subset is ported: no Apache 1.3, parrot, mod_perl-build, or
Win/AIX paths.
"""

from __future__ import annotations

import re
import socket
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .probe import HttpdInfo

DEFAULT_PORT = 8529


def _find_perl_pods(perl: str) -> str:
    """Locate perl's 'pods' directory, like Apache::TestConfig's
    find_in_inc('pods') (TestConfig.pm:297): the first 'pods' dir under @INC.

    Returns the absolute path, or "" if perl is unavailable or has no pods dir
    (e.g. a perl without perl-doc installed). Used for the /getfiles-perl-pod
    alias that t/filter/case.t downloads from.
    """
    if not perl:
        return ""
    import subprocess

    code = "for (@INC){ if (-d qq($_/pods)){ print qq($_/pods); last } }"
    try:
        out = subprocess.run(
            [perl, "-e", code], capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""
    return out if out and Path(out).is_dir() else ""

# @CGI_MODULE@ etc. -> first candidate that is actually loaded, else first candidate.
# Mirrors the default_module() calls in TestConfig.pm:435-440.
MODULE_NAME_CANDIDATES: dict[str, list[str]] = {
    "cgi": ["mod_cgi", "mod_cgid"],
    "thread": ["worker", "threaded"],
    "ssl": ["mod_ssl"],
    "access": ["mod_access", "mod_authz_host"],
    "auth": ["mod_auth", "mod_auth_basic"],
    "php": ["sapi_apache2", "mod_php4", "mod_php5", "mod_php7", "mod_php"],
}

_VHOST_RE = re.compile(
    r"^(\s*)<VirtualHost\s+(?:_default_:|([^:]+):(?!:))?(.*?)\s*>\s*$",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"@(\w+)@")

# Directives that, inside a C-module config block, are emitted straight to the
# postamble as "directive rest" rather than being treated as bare leftover args
# (TestConfigPerl.pm:328-332 %outside_container).
_OUTSIDE_CONTAINER = frozenset(
    {
        "Alias",
        "AliasMatch",
        "AddType",
        "PerlChildInitHandler",
        "PerlTransHandler",
        "PerlPostReadRequestHandler",
        "PerlSwitches",
        "PerlRequire",
        "PerlModule",
    }
)

# Container tags whose open/close tags are dropped while their content is kept
# (TestConfigPerl.pm:334 %strip_tags). Compared lower-cased.
_STRIP_TAGS = frozenset({"base", "noautoconfig"})

# Matches a container open tag, capturing the tag word, e.g. "VirtualHost" in
# "<VirtualHost mod_x>" (TestConfigPerl.pm:369,432 m/^<(\w+)/ / m/^\s*<(\w+)/).
_CONTAINER_OPEN_RE = re.compile(r"^\s*<(\w+)")

# The base httpd.conf body, captured verbatim from the Perl __DATA__ section of
# TestConfig.pm. Tokens are expanded at generation time. Kept as a literal so the
# generated config is byte-comparable to the Perl output (modulo token values).
BASE_TEMPLATE = """\
Listen     0.0.0.0:@Port@

ServerRoot   "@ServerRoot@"
DocumentRoot "@DocumentRoot@"

PidFile     @t_pid_file@
ErrorLog    @t_logs@/error_log
LogLevel    debug

<IfModule mod_version.c>
<IfVersion > 2.4.1>
    DefaultRunTimeDir "@t_logs@"
    LogLevel trace8
</IfVersion>
<IfVersion > 2.4.34>
<IfDirective DefaultStateDir>
    DefaultStateDir "@t_state@"
</IfDirective>
</IfVersion>
</IfModule>

<IfModule mod_log_config.c>
    TransferLog @t_logs@/access_log
</IfModule>

<IfModule mod_cgid.c>
    ScriptSock @t_logs@/cgisock
</IfModule>

ServerAdmin @ServerAdmin@

#needed for http/1.1 testing
KeepAlive       On

HostnameLookups Off

<Directory />
    Options FollowSymLinks
    AllowOverride None
</Directory>

<IfModule @THREAD_MODULE@>
<IfModule mod_version.c>
<IfVersion < 2.3.4>
    LockFile             @t_logs@/accept.lock
</IfVersion>
</IfModule>
    StartServers         @StartServersThreadedMPM@
    MinSpareThreads      @ThreadsPerChild@
    MaxSpareThreads      @MaxSpareThreadedMPM@
    ThreadsPerChild      @ThreadsPerChild@
    MaxClients           @MaxClientsThreadedMPM@
    MaxRequestsPerChild  0
</IfModule>

<IfModule perchild.c>
<IfModule mod_version.c>
<IfVersion < 2.3.4>
    LockFile             @t_logs@/accept.lock
</IfVersion>
</IfModule>
    NumServers           1
    StartThreads         @MinClients@
    MinSpareThreads      1
    MaxSpareThreads      @MaxSpare@
    MaxThreadsPerChild   @MaxClients@
    MaxRequestsPerChild  0
</IfModule>

<IfModule prefork.c>
<IfModule mod_version.c>
<IfVersion < 2.3.4>
    LockFile             @t_logs@/accept.lock
</IfVersion>
</IfModule>
    StartServers         @MinClients@
    MinSpareServers      1
    MaxSpareServers      @MaxSpare@
    MaxClients           @MaxClients@
    MaxRequestsPerChild  0
</IfModule>

<IfDefine APACHE1>
    LockFile             @t_logs@/accept.lock
    StartServers         @MinClients@
    MinSpareServers      1
    MaxSpareServers      @MaxSpare@
    MaxClients           @MaxClients@
    MaxRequestsPerChild  0
</IfDefine>

<IfModule mpm_winnt.c>
    ThreadsPerChild      50
    MaxRequestsPerChild  0
</IfModule>

<Location /server-info>
    SetHandler server-info
</Location>

<Location /server-status>
    SetHandler server-status
</Location>
"""


@dataclass
class VHost:
    """A configured virtual host and its allocated port."""

    module: str
    port: int
    servername: str
    namebased: int = 0

    @property
    def name(self) -> str:
        return f"{self.servername}:{self.port}"

    @property
    def hostport(self) -> str:
        return self.name


class TestConfig:
    """Generates the httpd test configuration tree under a server root."""

    def __init__(
        self,
        *,
        info: HttpdInfo,
        top_dir: Path,
        servername: str = "localhost",
        base_port: int = DEFAULT_PORT,
        defines: list[str] | None = None,
        apxs: Path | None = None,
        fpm_port: int | None = None,
    ) -> None:
        self.info = info
        self.apxs = apxs  # path to apxs, for build-time queries (apxs -q VAR)
        # If set, route htdocs/php/*.php to a PHP-FPM daemon on this port via
        # mod_proxy_fcgi (mod_php is not built); enables the t/php tests.
        self.fpm_port = fpm_port
        self.defines = defines or []
        self._port_counter = base_port
        self.vhosts: dict[str, VHost] = {}
        # preamble/postamble accumulators flushed around the template body,
        # analogous to TestConfig's add_config_last + preamble_run/postamble_run.
        self.preamble: list[str] = []
        self.postamble: list[str] = []

        self.vars = self._build_vars(top_dir, servername, base_port)
        self._resolve_module_name_tokens()
        self._apply_inherited()

    def _apply_inherited(self) -> None:
        """Apply TAKE1 directives inherited from the install conf (spec_apply).

        * ServerAdmin -> override the serveradmin var (apply_take1).
        * DocumentRoot -> set inherit_documentroot var (inherit_directive_var);
          the test documentroot itself is unchanged.
        * TypesConfig -> remember the inherited file so the generated TypesConfig
          fallback is suppressed in favor of it (inherit_server_file).
        * ServerRoot -> intentionally ignored (spec_apply maps it to a no-op).
        """
        inh = self.info.inherited
        if "ServerAdmin" in inh:
            self.vars["serveradmin"] = inh["ServerAdmin"]
        if "DocumentRoot" in inh:
            self.vars["inherit_documentroot"] = inh["DocumentRoot"]
        # TypesConfig: inherit_server_file resolves a relative path against the
        # INSTALL ServerRoot (TestConfigParse). A bare "conf/mime.types" would
        # otherwise resolve against the test ServerRoot (python/t) and not exist,
        # so make it absolute here. If it can't be resolved to an existing file,
        # fall back to generating our own (treat as not-inherited).
        tc = inh.get("TypesConfig")
        if tc and not Path(tc).is_absolute():
            install_root = inh.get("ServerRoot")
            if install_root:
                tc = str(Path(install_root) / tc)
        if tc and not Path(tc).is_file():
            tc = None  # can't use it; we'll generate our own mime.types instead
        self._inherited_typesconfig = tc

    # -- vars table -------------------------------------------------------

    def _build_vars(self, top_dir: Path, servername: str, base_port: int) -> dict[str, str]:
        t_dir = top_dir / "t"
        serverroot = t_dir
        v: dict[str, str] = {}
        v["top_dir"] = str(top_dir)
        v["t_dir"] = str(t_dir)
        v["serverroot"] = str(serverroot).replace("\\", "/")
        v["documentroot"] = v["serverroot"] + "/htdocs"
        v["t_conf"] = v["serverroot"] + "/conf"
        v["t_logs"] = v["serverroot"] + "/logs"
        v["t_state"] = v["serverroot"] + "/state"
        v["statedir"] = v["t_state"]
        v["t_conf_file"] = v["t_conf"] + "/httpd.conf"
        v["t_pid_file"] = v["t_logs"] + "/httpd.pid"
        v["sslca"] = v["t_conf"] + "/ssl/ca"
        v["sslcaorg"] = "asf"
        v["sslproto"] = "all"
        v["scheme"] = "http"
        v["servername"] = servername
        v["port"] = str(base_port)
        v["serveradmin"] = f"unknown@{servername}"
        v["inherit_documentroot"] = v["documentroot"]
        # getfiles-* download aliases (see generate_httpd_conf %aliases). httpd
        # is the probed binary; perl is whatever runs the helper scripts.
        v["httpd"] = str(self.info.httpd)
        from .scripts import default_perl

        v["perl"] = default_perl()
        # perlpod: a 'pods' dir under @INC, like Perl's find_in_inc('pods')
        # (TestConfig.pm:297). Drives the /getfiles-perl-pod alias that
        # t/filter/case.t (mod_alias case) downloads from. Left "" if not found,
        # in which case the alias is not emitted and that subtest skips.
        v["perlpod"] = _find_perl_pods(v["perl"])

        # MPM tuning math (TestConfig.pm:331-373) with proxy off (no bump).
        tpc = 10
        minclients = 1
        maxclients = minclients + 1
        maxspare = 2 if minclients < 2 else minclients
        if maxclients < maxspare + 1:
            maxclients = maxspare + 1

        def round_up(n: int) -> int:
            return (n + tpc - 1) // tpc * tpc

        minc_t = round_up(minclients)
        maxc_t = round_up(maxclients)
        maxspare_t = round_up(maxspare)
        if maxspare_t < 2 * tpc:
            maxspare_t = 2 * tpc
        if maxc_t < maxspare_t + tpc:
            maxc_t = maxspare_t + tpc
        startservers_t = minc_t // tpc

        v["threadsperchild"] = str(tpc)
        v["minclients"] = str(minclients)
        v["maxclients"] = str(maxclients)
        v["maxspare"] = str(maxspare)
        v["minclientsthreadedmpm"] = str(minc_t)
        v["maxclientsthreadedmpm"] = str(maxc_t)
        v["maxsparethreadedmpm"] = str(maxspare_t)
        v["startserversthreadedmpm"] = str(startservers_t)

        # No explicit maxclients was passed (CLI override); used to gate the
        # proxy client bump in _bump_clients_for_proxy (check_vars).
        v["maxclients_preset"] = ""

        v["limitrequestline"] = "128"
        v["limitrequestlinex2"] = str(2 * 128)

        v["proxy"] = "off"
        v["proxyssl_url"] = ""
        v["defines"] = " ".join(self.defines)
        return v

    def _resolve_module_name_tokens(self) -> None:
        """Set ``<name>_module_name`` / ``<name>_module`` vars (TestConfig.pm:447-462)."""
        for name, candidates in MODULE_NAME_CANDIDATES.items():
            chosen = next((c for c in candidates if self.info.has_module(c)), candidates[0])
            self.vars[f"{name}_module_name"] = chosen
            self.vars[f"{name}_module"] = f"{chosen}.c"

    # -- ports ------------------------------------------------------------

    @staticmethod
    def _port_available(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port))
            except OSError:
                return False
            return True

    def select_next_port(self) -> int:
        """Return the next free port above the counter (TestServer::select_next_port)."""
        while True:
            self._port_counter += 1
            if self._port_available(self._port_counter):
                return self._port_counter

    # -- token expansion --------------------------------------------------

    def expand(self, text: str, *, source: str = "") -> str:
        """Expand ``@token@`` placeholders; raise on unknown (TestConfig.pm:1204)."""

        def repl(m: re.Match[str]) -> str:
            key = m.group(1).lower()
            if key == "nextavailableport":
                return str(self.select_next_port())
            if key in self.vars:
                return self.vars[key]
            where = f" in {source}" if source else ""
            raise KeyError(f"invalid token: @{m.group(1)}@{where}")

        return _TOKEN_RE.sub(repl, text)

    # -- vhost allocation -------------------------------------------------

    def _maybe_rewrite_vhost(self, line: str) -> str | None:
        """If ``line`` opens a ``<VirtualHost module>``, allocate a port and rewrite it.

        Returns the replacement text (which may emit an outer ``Listen`` to the
        postamble as a side effect) or ``None`` if the line is not a vhost open
        tag (or the vhost's module is not loaded, in which case the block is kept
        but no port is allocated — matching the Perl behavior of returning undef,
        leaving the literal line, relying on the surrounding ``<IfModule>``).
        """
        m = _VHOST_RE.match(line)
        if not m:
            return None
        indent = m.group(1) or ""
        namebased = m.group(2) or ""
        module = m.group(3)

        # mod_foo_ssl vhosts map to mod_foo.c presence + ssl loaded.
        have = f"{module}.c"
        ssl_mod = self.vars.get("ssl_module", "mod_ssl.c")
        ms = re.match(r"^(mod_\w+)_ssl$", module)
        if ms and have != ssl_mod:
            have = f"{ms.group(1)}.c"
            if not self.info.has_module(ssl_mod):
                return None
        # don't allocate for an unloaded mod_ vhost (relies on enclosing IfModule)
        if module.startswith("mod_") and not self.info.has_module(have):
            return None

        port, namebased_count = self._new_vhost(module, bool(namebased))
        self.vars[f"{module}_port"] = str(port)

        # Apache 2.x servername_config form 2: inside the vhost, emit only
        # "ServerName name:port" (the standalone "Port" directive was removed in
        # 2.0). See TestConfig.pm:1234-1237.
        servername = namebased or self.vars["servername"]
        inner = f"{indent}    ServerName {servername}:{port}"
        open_tag = f"{indent}<VirtualHost {'*' if namebased else '_default_'}:{port}>"

        # Listen (and, pre-2.3.11, NameVirtualHost) is emitted outside the block
        # only while namebased < 2 — i.e. once per shared name-based port, or
        # always for default vhosts. Mirrors parse_vhost (TestConfig.pm:1287-1296).
        out: list[str] = []
        if namebased_count < 2:
            out.append(f"{indent}Listen 0.0.0.0:{port}")
            if namebased:
                out.append(
                    f"<IfVersion < 2.3.11>\n"
                    f"{indent}{indent}NameVirtualHost *:{port}\n"
                    f"{indent}</IfVersion>"
                )
        return "\n".join([*out, open_tag, inner])

    def _new_vhost(self, module: str, namebased: bool) -> tuple[int, int]:
        """Allocate or reuse a vhost port; return (port, post-increment namebased count).

        Name-based vhosts sharing a module name reuse one port and bump the
        namebased counter (TestConfigPerl::new_vhost). Default vhosts always get
        a fresh port and a namebased count of 0.
        """
        existing = self.vhosts.get(module)
        if namebased and existing is not None:
            existing.namebased += 1
            return existing.port, existing.namebased
        port = self.select_next_port()
        self.vhosts[module] = VHost(
            module=module,
            port=port,
            servername=self.vars["servername"],
            namebased=1 if namebased else 0,
        )
        return port, self.vhosts[module].namebased

    # -- conf.in processing ----------------------------------------------

    def process_conf_in(self, conf_in: Path) -> Path:
        """Expand one ``*.conf.in`` to ``*.conf``; allocate vhost ports in-pass."""
        out_lines: list[str] = []
        # Split ONLY on newline — some configs embed literal control chars such
        # as a vertical tab (0x0B) inside directive values (see the http_strict
        # regression-header test). Python's str.splitlines() would break on those
        # and corrupt the config; the Perl `while (<$in>)` reads newline-delimited
        # records only.
        text = conf_in.read_text()
        if text.endswith("\n"):
            text = text[:-1]  # avoid a spurious trailing blank line after split
        for raw in text.split("\n"):
            # Match Perl order: replace (token expand) THEN replace_vhost_modules.
            # Some vhost open-tags carry tokens in the module name itself, e.g.
            # `<VirtualHost default:@ssl_module_name@>`, so tokens must be expanded
            # before the vhost line is matched/rewritten.
            expanded = self.expand(raw, source=str(conf_in))
            rewritten = self._maybe_rewrite_vhost(expanded)
            out_lines.append(rewritten if rewritten is not None else expanded)
        out_path = conf_in.with_suffix("")  # strip ".in" -> ".conf"
        out_path.write_text("\n".join(out_lines) + "\n", newline="\n")
        return out_path

    def conf_in_files(self) -> list[Path]:
        """All ``*.conf.in`` under ``t/conf``, SSL first (TestConfig.pm:1486-1493)."""
        conf_dir = Path(self.vars["t_conf"])
        files = sorted(conf_dir.rglob("*.conf.in"))
        ssl = [f for f in files if f.name.startswith("ssl")]
        rest = [f for f in files if not f.name.startswith("ssl")]
        return ssl + rest

    # -- supporting files -------------------------------------------------

    MIME_TYPES = (
        "text/html  html htm\n"
        "image/gif  gif\n"
        "image/jpeg jpeg jpg jpe\n"
        "image/png  png\n"
        "text/plain asc txt\n"
    )

    def _ensure_dirs(self) -> None:
        for key in ("t_conf", "t_logs", "t_state", "documentroot"):
            Path(self.vars[key]).mkdir(parents=True, exist_ok=True)

    def _generate_supporting_files(self) -> None:
        """mime.types + index.html, matching generate_types_config/generate_index_html."""
        # generate_types_config (TestConfig.pm:1396-1408): if the install conf
        # inherited a TypesConfig, re-emit it (resolved to an absolute path in
        # _apply_inherited) so mod_mime finds a real file; otherwise generate our
        # own mime.types. Either way we emit an explicit TypesConfig so mod_mime's
        # default (conf/mime.types relative to the test ServerRoot) is overridden.
        inherited_tc = getattr(self, "_inherited_typesconfig", None)
        if inherited_tc:
            self.postamble.append(
                f'<IfModule mod_mime.c>\n    TypesConfig "{inherited_tc}"\n</IfModule>'
            )
        else:
            mime = Path(self.vars["t_conf"]) / "mime.types"
            if not mime.exists():
                mime.write_text(self.MIME_TYPES, newline="\n")
            self.postamble.append(
                f'<IfModule mod_mime.c>\n    TypesConfig "{mime}"\n</IfModule>'
            )
        # index_html_template: "welcome to <server name>" where the server name
        # is servername:port (TestConfig.pm:1364-1366 + new_test_server name).
        index = Path(self.vars["documentroot"]) / "index.html"
        if not index.exists():
            index.write_text(
                f"welcome to {self.vars['servername']}:{self.vars['port']}\n",
                newline="\n",
            )

    def _load_module_preamble(self, name: str, so: Path) -> None:
        """Append a guarded LoadModule (find_and_load_module, TestConfig.pm:1329)."""
        so_fwd = str(so).replace("\\", "/")
        self.preamble.append(
            f'<IfModule !mod_{name}.c>\n'
            f'    LoadModule {name}_module "{so_fwd}"\n'
            f'</IfModule>'
        )

    def _find_and_load_fallback(self, mod: str) -> None:
        """Defensively LoadModule a shared mod_X.so if available but not built-in.

        Mirrors find_and_load_module (TestConfig.pm:1329): emits a guarded
        LoadModule into the preamble. We reuse the inherited load directive's .so
        path when present; otherwise scan the install modules directory.
        """
        sym = mod[len("mod_"):] if mod.startswith("mod_") else mod
        cname = f"mod_{sym}.c"
        for d in self.info.load_directives:
            if d.cname == cname and Path(d.so).exists():
                self._load_module_preamble(sym, Path(d.so))
                self.info.modules.add(cname)
                return
        modules_dir = self.info.httpd.parent.parent / "modules"
        so = modules_dir / f"mod_{sym}.so"
        if so.exists():
            self._load_module_preamble(sym, so)
            self.info.modules.add(cname)

    # %aliases map (TestConfig.pm:1604): label -> var holding the path.
    _GETFILES_ALIASES = {
        "perl-pod": "perlpod",
        "binary-httpd": "httpd",
        "binary-perl": "perl",
    }

    def _getfiles_aliases(self) -> str:
        """Emit the <IfModule mod_alias.c> getfiles-* download aliases (sorted)."""
        lines = ["<IfModule mod_alias.c>"]
        for label in sorted(self._GETFILES_ALIASES):
            var = self._GETFILES_ALIASES[label]
            val = self.vars.get(var)
            if val:
                lines.append(f'    Alias /getfiles-{label} "{val}"')
        lines.append("</IfModule>")
        return "\n".join(lines)

    def _php_fpm_config(self) -> str:
        """Route htdocs/php/*.php to PHP-FPM via mod_proxy_fcgi.

        Emitted only when a PHP-FPM port is configured (mod_php is not built).
        This makes the t/php tests resolve: any .php under the php docroot is
        handled by the FPM backend, which reads SCRIPT_FILENAME (passed through
        by ProxyFCGIBackendType FPM) to locate the script on disk.
        """
        if self.fpm_port is None:
            return ""
        php_root = f"{self.vars['documentroot']}/php"
        return (
            "<IfModule mod_proxy_fcgi.c>\n"
            f"    <Directory \"{php_root}\">\n"
            "        <FilesMatch \\.php$>\n"
            f"            SetHandler proxy:fcgi://127.0.0.1:{self.fpm_port}\n"
            "        </FilesMatch>\n"
            "        ProxyFCGIBackendType FPM\n"
            "        DirectoryIndex index.php\n"
            "    </Directory>\n"
            "</IfModule>"
        )

    def _check_vars(self) -> None:
        """Set late-bound vars after a conf file is parsed (check_vars).

        proxyssl_url defaults to the SSL module's vhost hostport once that vhost
        has been allocated; setting it also bumps the client/thread tuning to
        allow for the extra backend connections proxy-over-SSL needs
        (TestConfig.pm:1433-1456).
        """
        if not self.vars.get("proxyssl_url"):
            ssl_name = self.vars.get("ssl_module_name", "mod_ssl")
            ssl_vhost = self.vhosts.get(ssl_name)
            if ssl_vhost is not None:
                self.vars["proxyssl_url"] = ssl_vhost.hostport
                self._bump_clients_for_proxy()

    def _bump_clients_for_proxy(self) -> None:
        """Bump client/thread counts for proxy-to-self (check_vars/configure_proxy).

        Applied once when proxyssl_url (or proxy) is enabled, unless maxclients
        was preset. Mirrors TestConfig.pm:1438-1453.
        """
        if self.vars.get("maxclients_preset"):
            return
        tpc = int(self.vars["threadsperchild"])

        def inc(key: str, by: int = 1) -> None:
            self.vars[key] = str(int(self.vars[key]) + by)

        inc("minclients")
        inc("maxclients")
        inc("maxspare")
        inc("startserversthreadedmpm")
        inc("minclientsthreadedmpm", tpc)
        inc("maxclientsthreadedmpm", tpc)
        inc("maxsparethreadedmpm", tpc)
        # plus headroom for backend processes in keep-alive
        inc("maxclients", 3)

    def _maybe_generate_sslca(self) -> None:
        """Build the SSL CA tree if mod_ssl is loaded and t/conf/ssl exists."""
        if not self.info.has_module("mod_ssl"):
            return
        ssl_dir = Path(self.vars["t_conf"]) / "ssl"
        if not ssl_dir.is_dir():
            return
        from .sslca import SSLCA

        SSLCA(Path(self.vars["sslca"]), self.vars["servername"]).generate()

    def _emit_inherited_loadmodules(self) -> None:
        """Re-emit inherited (active) LoadModule lines (inherit_load_module).

        Each is wrapped in ``<IfModule !name>`` so a module already built-in
        isn't double-loaded. Only active directives reach here (the probe drops
        commented ones), so MPM exclusivity is the install conf's concern — it
        must keep a single MPM active, as the suite's build does.
        """
        from pathlib import Path as _Path

        for d in self.info.load_directives:
            if not _Path(d.so).exists():
                continue
            so = d.so.replace("\\", "/")
            self.preamble.append(
                f"<IfModule !{d.cname}>\n"
                f'    LoadModule {d.symbol} "{so}"\n'
                f"</IfModule>"
            )

    # -- C-module embedded config ----------------------------------------

    def add_module_config(self, c_source: Path, args: list[str]) -> None:
        """Extract a C module's ``#if CONFIG_FOR_HTTPD_TEST`` block to the postamble.

        Faithful port of ``add_module_config`` (TestConfigPerl.pm:337-385). The
        block holds httpd configuration (typically ``<VirtualHost mod_X>`` with
        directives) that is appended to ``httpd.conf`` with the same ``@token@``
        expansion and ``<VirtualHost module>`` -> port-allocation rewriting that
        ``.conf.in`` files get.

        Lines are consumed as a stream so nested-container helpers can keep
        reading the same iterator (mirroring the Perl ``<$fh>`` filehandle).
        Bare directives (not opening a container, not in ``%outside_container``)
        are appended to ``args``, which the caller flushes once after all
        modules (TestConfigC.pm:295-313).
        """
        text = c_source.read_text(errors="replace")
        if text.endswith("\n"):
            text = text[:-1]
        lines = iter(text.split("\n"))

        # Skip until the start marker (TestConfigPerl.pm:342-344).
        for line in lines:
            if re.match(r"^(__(DATA|END)__|\#if CONFIG_FOR_HTTPD_TEST)", line):
                break
        else:
            return  # no config block in this module

        # Body: read until ^#endif (TestConfigPerl.pm:348-382).
        for line in lines:
            if re.match(r"^\#endif", line):
                break
            if not re.search(r"\S", line):  # skip blank lines (next unless /\S+/)
                continue
            line = self.expand(line.lstrip(), source=str(c_source))

            if line.startswith("#"):
                self.postamble.append(line)  # preserve comments
                continue

            parts = re.split(r"\s+", line, maxsplit=1)
            directive = parts[0]
            rest = parts[1] if len(parts) > 1 else ""

            if directive in _OUTSIDE_CONTAINER:
                # postamble($directive => $rest) -> "directive rest"
                self.postamble.append(" ".join(p for p in (directive, rest) if p))
            elif "IfModule" in directive:
                self.postamble.append(line)
            elif (m := _CONTAINER_OPEN_RE.match(line)) is not None:
                tag = m.group(1).lower()
                self._process_container(line, lines, tag, tag in _STRIP_TAGS, "")
            else:
                args.extend([directive, rest])

    def _process_container(
        self,
        first_line: str,
        lines: "Iterator[str]",
        directive: str,
        strip_container: bool,
        indent: str,
    ) -> None:
        """Emit a container (recursively) to the postamble.

        Port of ``process_container`` (TestConfigPerl.pm:390-416): nested content
        is re-indented by 4 spaces and the closing tag's first letter is
        upper-cased. ``%strip_tags`` containers drop their open/close tags but
        keep the body.
        """
        new_indent = indent
        if not strip_container:
            new_indent = indent + "    "
            line = self.expand(first_line.lstrip(), source="<module config>")
            if line.lower().startswith("<virtualhost"):
                self._process_vhost_open_tag(line, indent)
            else:
                self.postamble.append(indent + line)

        self._process_container_remainder(lines, directive, new_indent)

        if not strip_container:
            closing = directive[:1].upper() + directive[1:]
            self.postamble.append(f"{indent}</{closing}>")

    def _process_container_remainder(
        self, lines: "Iterator[str]", directive: str, indent: str
    ) -> None:
        """Emit a container body up to (and consuming) its end tag.

        Port of ``process_container_remainder`` (TestConfigPerl.pm:421-439).
        """
        end_tag = f"</{directive}"
        for line in lines:
            if re.match(rf"^\s*{re.escape(end_tag)}", line, re.IGNORECASE):
                break
            line = self.expand(line.lstrip(), source="<module config>")
            if (m := _CONTAINER_OPEN_RE.match(line)) is not None:
                self._process_container(line, lines, m.group(1), False, indent)
            else:
                self.postamble.append(indent + line)

    def _process_vhost_open_tag(self, line: str, indent: str) -> None:
        """Emit a ``<VirtualHost module>`` open tag with port allocation.

        Port of ``process_vhost_open_tag`` (TestConfigPerl.pm:442-455): reuses
        ``_maybe_rewrite_vhost`` (the same parse_vhost path used for ``.conf.in``
        files) so module vhosts get a Listen + ServerName + ``<VirtualHost
        _default_:port>`` and the ``<module>_port`` var / ``vhosts`` registry are
        updated. If the vhost's module is not loaded, the literal line is kept.
        """
        rewritten = self._maybe_rewrite_vhost(line)
        if rewritten is not None:
            self.postamble.append(rewritten)
        else:
            self.postamble.append(f"{indent}{line}")

    # -- main conf assembly ----------------------------------------------

    def generate(self, cmodule_loads: list[tuple[str, Path]] | None = None) -> Path:
        """Generate the full config tree and return the path to httpd.conf.

        :param cmodule_loads: ``(symbol, so_path)`` pairs for compiled C modules,
            emitted as LoadModule lines in the preamble.
        """
        self._ensure_dirs()
        self._generate_supporting_files()

        # Generate helper scripts from *.PL templates (CGI scripts, rewrite-map
        # programs, etc.) that the config references by their generated names.
        from .scripts import default_perl, generate_pl_scripts

        generate_pl_scripts(Path(self.vars["t_dir"]), perl=default_perl())

        # Generate the SSL CA + certs when mod_ssl is available and a ssl/ conf
        # dir exists (mirrors sslca_can/sslca_generate, TestConfig.pm:1524-1554).
        self._maybe_generate_sslca()

        # Re-emit inherited LoadModule directives so the test server actually
        # loads modules (the generated conf does not Include the install conf).
        # Mirrors inherit_load_module (TestConfigParse.pm:213): wrap each in
        # <IfModule !name> so built-in modules don't double-load. Among MPMs,
        # only emit the one the binary reports active (they are mutually
        # exclusive); other commented MPM lines are skipped.
        self._emit_inherited_loadmodules()

        # C module LoadModules into the preamble, and each module's embedded
        # `#if CONFIG_FOR_HTTPD_TEST` block extracted to the postamble with vhost
        # port allocation (TestConfigC::cmodules_httpd_conf, TestConfigC.pm:292-314).
        # This runs BEFORE the .conf.in pass so module vhosts get ports allocated
        # in the same relative order as Perl (cmodules_configure precedes
        # generate_httpd_conf in TestRun.pm:501-502). The bare leftover directives
        # accumulate across modules and are flushed once at the end.
        cmodule_args: list[str] = []
        for sym, so in cmodule_loads or []:
            so_fwd = str(so).replace("\\", "/")
            self.preamble.append(f'LoadModule {sym}_module "{so_fwd}"')
            # Register the module in the modules set so <VirtualHost mod_X>
            # rewriting recognizes it (TestConfigC.pm:308 $self->{modules}{$cname}=1).
            self.info.modules.add(f"mod_{sym}.c")
            # so is <src_dir>/.libs/mod_<sym>.so (apxs) or <prefix>/modules/ (CMake).
            c_source = so.parent.parent / f"mod_{sym}.c"
            if not c_source.is_file():
                c_source = Path(self.vars["top_dir"]) / "c-modules" / sym / f"mod_{sym}.c"
            if c_source.is_file():
                self.add_module_config(c_source, cmodule_args)
        if cmodule_args:
            # postamble(\@args): join the flat directive/rest list with newlines
            # (massage_config_args ARRAY branch, TestConfig.pm:612-614).
            self.postamble.append("\n".join(cmodule_args))

        # Process every .conf.in (SSL first). This allocates vhost ports and
        # populates *_port vars BEFORE we assemble httpd.conf, and yields the
        # list of generated files to Include. After each file we run check_vars
        # so late-bound vars (e.g. proxyssl_url, derived from the ssl vhost's
        # hostport once ssl.conf.in is parsed) are available to later files.
        generated: list[Path] = []
        for f in self.conf_in_files():
            generated.append(self.process_conf_in(f))
            self._check_vars()
        for g in sorted(generated):
            g_fwd = str(g).replace("\\", "/")
            self.postamble.append(f'Include "{g_fwd}"')

        # mod_mime/mod_alias may be shared and absent from the system conf; load
        # them defensively. Order matches Perl: generate_types_config loads
        # mod_mime first (TestConfig.pm:1394), then mod_alias (TestConfig.pm:1635).
        self._find_and_load_fallback("mod_mime")
        self._find_and_load_fallback("mod_alias")
        # httpd-built test/experimental modules not in the default httpd.conf
        for mod in ("mod_bucketeer", "mod_case_filter", "mod_case_filter_in",
                     "mod_echo", "mod_log_debug", "mod_reflector", "mod_data"):
            self._find_and_load_fallback(mod)

        # On Windows, tell mod_cgi to read the #! shebang line instead of
        # using the Registry file association to find the script interpreter.
        if sys.platform == "win32":
            self.postamble.append(
                "<IfModule mod_cgi.c>\n"
                "    ScriptInterpreterSource Script\n"
                "</IfModule>"
            )

        # Assemble httpd.conf in generate_httpd_conf order (TestConfig.pm:1609-1690).
        parts: list[str] = []
        parts.extend(self.preamble)
        # ServerName <name>:<port>  (2.x servername_config form 2)
        parts.append(f"ServerName {self.vars['servername']}:{self.vars['port']}")
        parts.append(self.expand(BASE_TEMPLATE, source="<base template>"))
        # getfiles-* aliases for downloadable files (generate_httpd_conf %aliases).
        parts.append(self._getfiles_aliases())
        if (php_fpm := self._php_fpm_config()):
            parts.append(php_fpm)
        parts.extend(self.postamble)

        conf = Path(self.vars["t_conf_file"])
        conf.write_text("\n".join(parts) + "\n", newline="\n")
        return conf
