import importlib
import inspect
import logging
import re
import os
import signal
import shutil
import stat
import subprocess
import sys
import time
import platform
from datetime import datetime, timedelta
from string import Template
from typing import List, Optional

from configparser import ConfigParser, ExtendedInterpolation
from urllib.parse import urlparse

from .cmodules import ensure_built
from .certs import Credentials, HttpdTestCA, CertificateSpec
from .instance import HttpdInstance, HttpdStartError
from .log import HttpdErrorLog
from .ports import PORT_KEYS, resolve_ports
from .nghttp import Nghttp
from .result import ExecResult


log = logging.getLogger(__name__)


class Dummy:
    pass


class HttpdTestSetup:

    # modules which exist only on Unix
    UNIX_ONLY_MODULES = ("unixd", "suexec")

    # the modules we want to load
    MODULES = [
        "log_config",
        "logio",
        "unixd",
        "version",
        "watchdog",
        "authn_core",
        "authz_host",
        "authz_groupfile",
        "authz_user",
        "authz_core",
        "access_compat",
        "auth_basic",
        "cache",
        "cache_disk",
        "cache_socache",
        "socache_shmcb",
        "dumpio",
        "reqtimeout",
        "filter",
        "mime",
        "env",
        "headers",
        "setenvif",
        "slotmem_shm",
        "status",
        "dir",
        "alias",
        "rewrite",
        "deflate",
        "proxy",
        "proxy_http",
    ]

    CURL_STDOUT_SEPARATOR = "===CURL_STDOUT_SEPARATOR==="

    def __init__(self, env: 'HttpdTestEnv'):
        self.env = env
        self._source_dirs = [os.path.dirname(inspect.getfile(HttpdTestSetup))]
        self._modules = HttpdTestSetup.MODULES.copy()
        self._optional_modules = []

    def add_source_dir(self, source_dir):
        self._source_dirs.append(source_dir)

    def add_modules(self, modules: List[str]):
        self._modules.extend(modules)

    def add_optional_modules(self, modules: List[str]):
        self._optional_modules.extend(modules)

    def _cgi_module(self):
        """The name of a CGI module this build has: mod_cgid for preference,
        mod_cgi otherwise.  There is no mod_cgid on Windows."""
        if sys.platform != "win32" \
                and os.path.isfile(os.path.join(self.env.libexec_dir,
                                                "mod_cgid.so")):
            return "cgid"
        return "cgi"

    def add_cgi_module(self):
        """Load a CGI module, for a suite which needs CGI but does not care
        which of mod_cgid and mod_cgi runs it."""
        self.add_modules([self._cgi_module()])

    def make(self):
        self._make_dirs()
        self._make_conf()
        if self.env.mpm_module is not None \
                and self.env.mpm_module in self.env.mpm_modules:
            self.add_modules([self.env.mpm_module])
        if self.env.ssl_module is not None:
            self.add_modules([self.env.ssl_module])
        self._make_modules_conf()
        self._make_htdocs()

        self._add_aptest()
        self._build_clients()
        self.env.clear_curl_headerfiles()

    def _make_dirs(self):
        if not os.path.exists(self.env.gen_dir):
            os.makedirs(self.env.gen_dir)
        # wipe logs from any previous module run to avoid stale files in the archive
        if os.path.isdir(self.env.server_logs_dir):
            shutil.rmtree(self.env.server_logs_dir,
                          ignore_errors=(sys.platform == "win32"))
        os.makedirs(self.env.server_logs_dir, exist_ok=True)

    def _make_conf(self):
        # remove anything from another run/test suite
        conf_dest_dir = os.path.join(self.env.server_dir, 'conf')
        if os.path.isdir(conf_dest_dir):
            shutil.rmtree(conf_dest_dir)
        for d in self._source_dirs:
            conf_src_dir = os.path.join(d, 'conf')
            if os.path.isdir(conf_src_dir):
                if not os.path.exists(conf_dest_dir):
                    os.makedirs(conf_dest_dir)
                for name in os.listdir(conf_src_dir):
                    src_path = os.path.join(conf_src_dir, name)
                    m = re.match(r'(.+).template', name)
                    if m:
                        self._make_template(src_path, os.path.join(conf_dest_dir, m.group(1)))
                    elif os.path.isfile(src_path):
                        shutil.copy(src_path, os.path.join(conf_dest_dir, name))

    def _make_template(self, src, dest):
        var_map = dict()
        for name, value in HttpdTestEnv.__dict__.items():
            if isinstance(value, property):
                var_map[name] = value.fget(self.env)
        t = Template(''.join(open(src).readlines()))
        with open(dest, 'w') as fd:
            fd.write(t.substitute(var_map))

    def _get_builtin_modules(self) -> set:
        return HttpdTestEnv.static_modules()

    def _make_modules_conf(self):
        loaded = set()
        builtin_modules = self._get_builtin_modules()
        modules_conf = os.path.join(self.env.server_dir, 'conf/modules.conf')
        with open(modules_conf, 'w') as fd:
            # issue load directives for all modules we want that are shared
            missing_mods = list()
            modules = self._modules
            modules = [self._cgi_module() if m == "cgid" else m
                       for m in modules]
            for m in modules:
                match = re.match(r'^mod_(.+)$', m)
                if match:
                    m = match.group(1)
                if m in loaded:
                    continue
                if self.env.isWindows and m in HttpdTestSetup.UNIX_ONLY_MODULES:
                    continue
                mod_path = os.path.join(self.env.libexec_dir, f"mod_{m}.so")
                if m in builtin_modules:
                    fd.write(f"#built-in: LoadModule {m}_module   \"{mod_path}\"\n")
                elif os.path.isfile(mod_path):
                    fd.write(f"LoadModule {m}_module   \"{mod_path}\"\n")
                else:
                    # neither compiled in nor built as a DSO
                    missing_mods.append(m)
                loaded.add(m)
            for m in self._optional_modules:
                match = re.match(r'^mod_(.+)$', m)
                if match:
                    m = match.group(1)
                if m in loaded:
                    continue
                mod_path = os.path.join(self.env.libexec_dir, f"mod_{m}.so")
                if m not in builtin_modules and os.path.isfile(mod_path):
                    fd.write(f"LoadModule {m}_module   \"{mod_path}\"\n")
                    loaded.add(m)
        if len(missing_mods) > 0:
            raise Exception(f"Unable to find modules: {missing_mods} "
                            f"DSOs: {self.env.dso_modules}")

    def _make_htdocs(self):
        if not os.path.exists(self.env.server_docs_dir):
            os.makedirs(self.env.server_docs_dir)
        dest_dir = os.path.join(self.env.server_dir, 'htdocs')
        # remove anything from another run/test suite
        if os.path.isdir(dest_dir):
            shutil.rmtree(dest_dir)
        for d in self._source_dirs:
            srcdocs = os.path.join(d, 'htdocs')
            if os.path.isdir(srcdocs):
                shutil.copytree(srcdocs, dest_dir, dirs_exist_ok=True)
        for dirpath, _dirnames, filenames in os.walk(dest_dir):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                if sys.platform == "win32":
                    # normalize line endings to LF so test assertions match
                    try:
                        data = open(fpath, 'rb').read()
                        if b'\r\n' in data and b'\x00' not in data:
                            open(fpath, 'wb').write(data.replace(b'\r\n', b'\n'))
                    except OSError:
                        pass
                if re.search(r'\.(py|cgi)$', fname):
                    if sys.platform == "win32":
                        self._fix_shebang(fpath)
                    st = os.stat(fpath)
                    os.chmod(fpath, st.st_mode | stat.S_IEXEC)

    @staticmethod
    def _fix_shebang(py_file):
        python_path = sys.executable
        python_path = python_path.replace("\\", "/")
        with open(py_file, 'r') as f:
            lines = f.readlines()
        if lines and re.match(r'#!\s*/usr/bin/env\s+python', lines[0]):
            lines[0] = f"#!{python_path}\n"
            with open(py_file, 'w', newline='\n') as f:
                f.writelines(lines)

    def _add_aptest(self):
        module_dir = self.env.test_modules_dir
        if not self.env.isWindows:
            local_dir = os.path.dirname(inspect.getfile(HttpdTestSetup))
            try:
                ensure_built(os.path.join(local_dir, 'mod_aptest'), 'aptest',
                             self.env.apxs)
            except RuntimeError as e:
                log.error(f"compiling mod_aptest failed: {e}")
                raise Exception(f"compiling mod_aptest failed: {e}")

            module_dir = os.path.join(local_dir, "mod_aptest", ".libs")

        modules_conf = os.path.join(self.env.server_dir, 'conf/modules.conf')
        with open(modules_conf, 'a') as fd:
            # load our test module
            fd.write(f"LoadModule aptest_module   \"{module_dir}/mod_aptest.so\"\n")

    def _build_clients(self):
        if self.env.test_modules_dir:
            return
        clients_dir = os.path.join(
            os.path.dirname(os.path.dirname(inspect.getfile(HttpdTestSetup))),
            'clients')
        p = subprocess.run(['make'], capture_output=True, cwd=clients_dir)
        rv = p.returncode
        if rv != 0:
            log.error(f"compiling test clients failed: {p.stderr}")
            raise Exception(f"compiling test clients failed: {p.stderr}")


class HttpdTestEnv:

    LIBEXEC_DIR = None
    # entries shared across all modules, archived once in _shared
    SHARED_SERVER_ENTRIES = {'ca', 'ca1', 'ca2', 'md', 'acme-ca.pem',
                             'eab.json'}

    @staticmethod
    def has_tool(name: str) -> bool:
        return bool(shutil.which(name))

    @classmethod
    def has_python_package(cls, name: str) -> bool:
        return name in sys.modules or importlib.util.find_spec(name) is not None

    @classmethod
    def get_ssl_module(cls):
        return os.environ['SSL'] if 'SSL' in os.environ else 'mod_ssl'

    _static_modules = {}

    @classmethod
    def static_modules(cls) -> set:
        """The modules compiled into the httpd under test, by the name
        LoadModule and add_modules() use: "so", "http2", "mpm_event"..."""
        env = HttpdTestEnv()
        httpd_bin = os.path.join(env.bin_dir, 'httpd')
        if httpd_bin not in cls._static_modules:
            names = set()
            try:
                p = subprocess.run([httpd_bin, '-l'], capture_output=True, text=True)
                out = p.stdout
            except OSError:
                out = ""
            for line in out.splitlines():
                m = re.match(r'^\s+(mod_|mpm_)?(.+)\.c$', line)
                if m and m.group(1) == 'mod_':
                    names.add(m.group(2))
                elif m and m.group(1) == 'mpm_':                 # mpm_winnt.c
                    names.add(f"mpm_{m.group(2)}")
                elif m and m.group(2) in ('event', 'worker', 'prefork', 'motorz'):
                    names.add(f"mpm_{m.group(2)}")
            cls._static_modules[httpd_bin] = names
        return cls._static_modules[httpd_bin]

    @classmethod
    def has_shared_module(cls, name):
        """Whether mod_<name> is there to be loaded: built as a DSO, or
        compiled into httpd, when there is nothing to load."""
        if cls.LIBEXEC_DIR is None:
            env = HttpdTestEnv()  # will initialized it
        path = os.path.join(cls.LIBEXEC_DIR, f"mod_{name}.so")
        return os.path.isfile(path) or name in cls.static_modules()

    @classmethod
    def has_mod_ssl(cls):
        """Whether mod_ssl is installed.

        Not the same question as get_ssl_module(), which only reports which
        TLS module $SSL selected for this run. A test that is "only for
        mod_ssl" is not applicable under SSL=mod_tls and should skip; a test
        that needs mod_ssl to be installed at all has a real dependency.
        """
        return cls.has_shared_module("ssl")

    _directives = None

    def has_directive(self, name: str) -> bool:
        if HttpdTestEnv._directives is None:
            httpd_bin = os.path.join(self._bin_dir, 'httpd')
            try:
                p = subprocess.run([httpd_bin, '-L'],
                                   capture_output=True, text=True)
                HttpdTestEnv._directives = p.stdout
            except Exception:
                HttpdTestEnv._directives = ""
        return name in HttpdTestEnv._directives

    _nghttp_gate = {}

    @classmethod
    def needs_nghttp(cls, assets: bool = False):
        """A marker gating a test, class or module on the nghttp client.

        nghttp is the only client that can drive PUSH, trailers and explicit
        frame padding, so the tests that use it have no fallback. It is named
        unconditionally in config.ini, which says nothing about whether it is
        installed, so the binary has to be run to find out.

        :param assets: also require the '-a' asset-fetching support, which
            nghttp only has when built against libxml2
        """
        from .depends import needs_dependency
        if assets not in cls._nghttp_gate:
            env = HttpdTestEnv()
            ok = env.has_nghttp_get_assets() if assets else env.has_nghttp()
            if assets:
                reason = "nghttp not available or misses -a (needs libxml2)"
            else:
                reason = "nghttp not available"
            cls._nghttp_gate[assets] = needs_dependency(
                "nghttp", ok, reason=reason,
                detected=f"tried to run {env._nghttp}")
        return cls._nghttp_gate[assets]

    _h2load_gate = {}

    @classmethod
    def needs_h2load(cls, minv: str = None, reason: str = None):
        """A marker gating a test, class or module on the h2load client.

        :param minv: also require at least this h2load version. 1.41.0 is
            the one that matters here, it brought --connect-to.
        :param reason: skip reason, when the default wording is too vague
            about what the version is needed for.
        """
        from .depends import needs_dependency
        key = (minv, reason)
        if key not in cls._h2load_gate:
            env = HttpdTestEnv()
            if minv is None:
                ok = env.has_h2load()
                dep = "h2load"
                default_reason = "h2load not available"
            else:
                ok = env.h2load_is_at_least(minv)
                dep = f"h2load >= {minv}"
                default_reason = f"h2load unavailable or older than {minv}"
            found = env.h2load_version_str()
            cls._h2load_gate[key] = needs_dependency(
                dep, ok, reason=reason or default_reason,
                detected=(f"h2load {found}" if found is not None
                          else f"tried to run {env._h2load}"))
        return cls._h2load_gate[key]

    _multipart_gate = None

    @classmethod
    def needs_multipart(cls):
        """A marker gating a test, class or module on the multipart package.

        The CGI helpers in htdocs/cgi/ parse file uploads with it. They
        import it only for a multipart/ body, so this belongs on the tests
        that upload a file, not on everything that touches a CGI.
        """
        from .depends import needs_dependency
        if cls._multipart_gate is None:
            cls._multipart_gate = needs_dependency(
                "multipart", cls.has_python_package('python_multipart')
                or cls.has_python_package('multipart'),
                reason="no multipart python package available",
                detected="python package 'multipart' not installed "
                         "(pip install python-multipart)")
        return cls._multipart_gate

    def __init__(self, pytestconfig=None):
        self._our_dir = os.path.dirname(inspect.getfile(Dummy))
        self._config_ini = os.getenv("PYHTTPD_CONFIG",
                                     os.path.join(self._our_dir, 'config.ini'))
        self.config = ConfigParser(interpolation=ExtendedInterpolation())
        self.config.read(self._config_ini)

        self._bin_dir = self.config.get('global', 'bindir')
        self._apxs = self.config.get('global', 'apxs')
        self._prefix = self.config.get('global', 'prefix')
        self._apachectl = self.config.get('global', 'apachectl')

        self._libexec_dir = self.config.get('global', 'libexecdir')
        HttpdTestEnv.LIBEXEC_DIR = self._libexec_dir

        if HttpdTestEnv.LIBEXEC_DIR is None:
            HttpdTestEnv.LIBEXEC_DIR = self._libexec_dir = self.get_apxs_var('LIBEXECDIR')

        self._httpd_ver = self.config.get('httpd', 'version')

        self._curl = self.config.get('global', 'curl_bin')
        if 'CURL' in os.environ:
            self._curl = os.environ['CURL']
        self._nghttp = self.config.get('global', 'nghttp')
        if self._nghttp is None:
            self._nghttp = 'nghttp'
        self._h2load = self.config.get('global', 'h2load')
        if self._h2load is None:
            self._h2load = 'h2load'
        self._test_modules_dir = self.config.get('global', 'pre_built_test_binaries_dir',
                                                 fallback=None)

        ports = resolve_ports(
            {key: int(self.config.get('test', key)) for key in PORT_KEYS},
            base_port=(pytestconfig.getoption('--base-port', default=None)
                       if pytestconfig is not None else None),
            fixed=(bool(pytestconfig.getoption('--fixed-ports', default=False))
                   if pytestconfig is not None else True))
        self._http_port = ports['http_port']
        self._http_port2 = ports['http_port2']
        self._https_port = ports['https_port']
        self._proxy_port = ports['proxy_port']
        self._ws_port = ports['ws_port']
        self._http_tld = self.config.get('test', 'http_tld')
        self._test_dir = self.config.get('test', 'test_dir')

        # In cmake determining the test directory is a headache and this is a simple workaround
        if not self._test_dir:
            self._test_dir = os.getcwd() + "/pyhttpd" if "pyhttpd" not in os.getcwd() else os.getcwd()

        self._clients_dir = os.path.join(os.path.dirname(self._test_dir), 'clients')
        self._gen_dir = self.config.get('test', 'gen_dir')

        self._server_dir = os.path.join(self._gen_dir, 'apache')
        self._server_conf_dir = os.path.join(self._server_dir, "conf")
        self._server_docs_dir = os.path.join(self._server_dir, "htdocs")
        self._server_logs_dir = os.path.join(self._server_dir, "logs")
        self._server_run_dir = os.path.join(self._server_dir, "run")
        self._server_access_log = os.path.join(self._server_logs_dir, "access_log")
        error_log_sep = "." if self.isWindows else "_"
        self._error_log = HttpdErrorLog(os.path.join(self._server_logs_dir, f"error{error_log_sep}log"))
        self._apachectl_stderr = None
        self._instance = None

        self._apply_target()

        self._dso_modules = self.config.get('httpd', 'dso_modules').split(' ')
        self._mpm_modules = self.config.get('httpd', 'mpm_modules').split(' ')
        self._mpm_module = f"mpm_{os.environ['MPM']}" if 'MPM' in os.environ else 'mpm_winnt' if self.isWindows else 'mpm_event'
        self._ssl_module = self.get_ssl_module()
        if len(self._ssl_module.strip()) == 0:
            self._ssl_module = None

        self._httpd_addr = "127.0.0.1"
        self._http_base = f"http://{self._httpd_addr}:{self.http_port}"
        self._https_base = f"https://{self._httpd_addr}:{self.https_port}"

        self._verbosity = pytestconfig.option.verbose if pytestconfig is not None else 0
        # imported here, not at module scope, to keep env.py free of a
        # top-level pytest dependency: it is also built outside pytest runs
        from .depends import strict_optional_enabled
        self._strict_optional = strict_optional_enabled(pytestconfig)
        self._test_conf = os.path.join(self._server_conf_dir, "test.conf")
        self._httpd_base_conf = []
        self._httpd_env = {}
        self._httpd_log_modules = ['aptest']
        self._log_interesting = None
        self._setup = None

        self._ca = None
        self._cert_specs = [CertificateSpec(domains=[
            f"test1.{self._http_tld}",
            f"test2.{self._http_tld}",
            f"test3.{self._http_tld}",
            f"cgi.{self._http_tld}",
        ], key_type='rsa4096')]

        self._verify_certs = False
        self._curl_headerfiles_n = 0
        self._curl_version = None
        self._h2load_version = None
        self._nghttp_version = None
        self._current_test = None

    def _apply_target(self):
        """Point this environment at the httpd of the session.

        config.ini, generated by the build system from config.ini.in, names
        the build of this tree. When another one is tested (--apxs, --httpd),
        pyhttpd.build.resolve_build() found it before collection, and the
        server, its version and its modules come from there, whether or not
        the environment was created with a pytest config. Ports, clients and
        directories stay as config.ini has them.
        """
        from .build import current
        target = current()
        if target is None or target.source == "config.ini":
            return
        httpd_path = os.path.abspath(str(target.httpd))
        self._bin_dir = os.path.dirname(httpd_path)
        self._prefix = (str(target.prefix) if target.prefix is not None
                        else os.path.dirname(self._bin_dir))
        self._libexec_dir = str(target.libexecdir)
        HttpdTestEnv.LIBEXEC_DIR = self._libexec_dir
        if self.isWindows:
            self._apachectl = httpd_path
        else:
            ctl = os.path.join(self._bin_dir, "apachectl")
            self._apachectl = ctl if os.path.isfile(ctl) else httpd_path
        self._apxs = (str(target.apxs) if target.apxs is not None
                      else os.path.join(self._bin_dir, "apxs"))
        self._httpd_ver = target.version_str
        dso = []
        mpm = []
        if target.apxs is None and target.inherited_conf is not None:
            # --httpd with --conf, as on Windows: the modules the conf loads
            for d in target.load_directives:
                name = d.symbol[:-len("_module")] if d.symbol.endswith("_module") \
                    else d.symbol
                (mpm if name.startswith("mpm_") else dso).append(name)
        elif os.path.isdir(self._libexec_dir):
            # the shared modules that were built
            for so in sorted(os.listdir(self._libexec_dir)):
                m = re.match(r'^mod_(.+)\.so$', so)
                if m:
                    (mpm if m.group(1).startswith("mpm_") else dso).append(m.group(1))
        self.config.set('httpd', 'dso_modules', ' '.join(dso))
        self.config.set('httpd', 'mpm_modules', ' '.join(mpm))

    def add_httpd_conf(self, lines: List[str]):
        self._httpd_base_conf.extend(lines)

    def add_httpd_log_modules(self, modules: List[str]):
        self._httpd_log_modules.extend(modules)

    def set_httpd_env(self, name: str, value: Optional[str]):
        """Add a variable to the environment httpd is started with, or
        remove it again when passed None.

        Used by tests for modules which take their input from the
        environment rather than from the configuration, such as
        mod_systemd reading $NOTIFY_SOCKET.
        """
        if value is None:
            self._httpd_env.pop(name, None)
        else:
            self._httpd_env[name] = value

    def issue_certs(self):
        if self._ca is None:
            self._ca = HttpdTestCA.create_root(name=self.http_tld,
                                               store_dir=os.path.join(self.server_dir, 'ca'),
                                               key_type="rsa4096")
        self._ca.issue_certs(self._cert_specs)

    def setup_httpd(self, setup: HttpdTestSetup = None):
        """Create the server environment with config, htdocs and certificates"""
        self._setup = setup if setup is not None else HttpdTestSetup(env=self)
        self._setup.make()
        self.issue_certs()
        if self._httpd_log_modules:
            if self._verbosity >= 2:
                log_level = "trace2"
            elif self._verbosity >= 1:
                log_level = "debug"
            else:
                log_level = "info"
            self._log_interesting = "LogLevel"
            for name in self._httpd_log_modules:
                self._log_interesting += f" {name}:{log_level}"

    def check_error_log(self):
        errors, warnings = self._error_log.get_missed()
        assert (len(errors), len(warnings)) == (0, 0),\
                f"apache logged {len(errors)} errors and {len(warnings)} warnings: \n"\
                "{0}\n{1}\n".format("\n".join(errors), "\n".join(warnings))

    # combines httpd version & revision to identify the archive folder
    def _archive_version(self):
        if not hasattr(self, '_cached_archive_version'):
            version = self.get_httpd_version()
            r = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'],
                               capture_output=True, text=True,
                               cwd=self._our_dir)
            if r.returncode == 0:
                version = f"{version}-{r.stdout.strip()}"
            else:
                r = subprocess.run(['svn', 'info', '--show-item', 'revision'],
                                   capture_output=True, text=True,
                                   cwd=self._our_dir)

                if r.returncode == 0:
                    version = f"{version}-r{r.stdout.strip()}"
            self._cached_archive_version = version
        return self._cached_archive_version

    def archive_logs(self, package_name, archive_dir):
        version = self._archive_version()
        dest = os.path.join(archive_dir, version, package_name)
        os.makedirs(dest, exist_ok=True)

        # merge into existing dest to preserve per-test confs
        shutil.copytree(self._server_dir, dest, ignore=self.ignore_files,
                        dirs_exist_ok=True)

        shared_dest = os.path.join(archive_dir, version, '_shared')

        if os.path.isdir(shared_dest):
            shutil.rmtree(shared_dest)
        os.makedirs(shared_dest)

        for entry in self.SHARED_SERVER_ENTRIES:
            src = os.path.join(self._server_dir, entry)
            entry_dest = os.path.join(shared_dest, entry)
            if os.path.isdir(src):
                shutil.copytree(src, entry_dest)
            elif os.path.isfile(src):
                shutil.copy2(src, entry_dest)

        shared_conf_dest = os.path.join(shared_dest, 'conf')
        os.makedirs(shared_conf_dest)

        # copy them once
        for f in ['httpd.conf', 'mime.types', 'stop.conf']:
            src = os.path.join(self._server_conf_dir, f)
            if os.path.isfile(src):
                shutil.copy2(src, shared_conf_dest)

    def archive_test_conf(self, test_name, package_name, archive_dir):
        version = self._archive_version()
        dest = os.path.join(archive_dir, version, package_name, 'conf')
        if not os.path.isdir(dest):
            os.makedirs(dest)
        test_conf = os.path.join(self._server_conf_dir, 'test.conf')
        if os.path.isfile(test_conf):
            safe_name = test_name.replace('/', '_').replace('\\', '_')
            dest_file = os.path.join(dest, f"{safe_name}.conf")
            shutil.copy(test_conf, dest_file)

    # return files to ignore
    def ignore_files(self, d, entries):
        ignored = [e for e in entries if
                   e.endswith('.sock') or e in self.SHARED_SERVER_ENTRIES]
        # shared confs goes to _shared
        # test.conf is captured per-test
        if os.path.basename(d) == 'conf':
            ignored += ['httpd.conf', 'mime.types', 'stop.conf', 'test.conf']
        # htdocs are static test fixtures not useful in the archive
        if os.path.basename(d) == os.path.basename(self._server_dir):
            ignored += ['htdocs']
        return ignored

    @property
    def curl(self) -> str:
        return self._curl

    @property
    def apxs(self) -> str:
        return self._apxs

    @property
    def verbosity(self) -> int:
        return self._verbosity

    @property
    def prefix(self) -> str:
        return self._prefix

    @property
    def mpm_module(self) -> str:
        return self._mpm_module

    @property
    def ssl_module(self) -> str:
        return self._ssl_module

    @property
    def http_addr(self) -> str:
        return self._httpd_addr

    @property
    def http_port(self) -> int:
        return self._http_port

    @property
    def http_port2(self) -> int:
        return self._http_port2

    @property
    def https_port(self) -> int:
        return self._https_port

    @property
    def proxy_port(self) -> int:
        return self._proxy_port

    @property
    def ws_port(self) -> int:
        return self._ws_port

    @property
    def http_tld(self) -> str:
        return self._http_tld

    @property
    def http_base_url(self) -> str:
        return self._http_base

    @property
    def https_base_url(self) -> str:
        return self._https_base

    @property
    def bin_dir(self) -> str:
        return self._bin_dir

    @property
    def gen_dir(self) -> str:
        return self._gen_dir

    @property
    def test_dir(self) -> str:
        return self._test_dir

    @property
    def clients_dir(self) -> str:
        return self._clients_dir

    @property
    def server_dir(self) -> str:
        return self._server_dir

    @property
    def server_logs_dir(self) -> str:
        return self._server_logs_dir

    @property
    def server_run_dir(self) -> str:
        return self._server_run_dir

    @property
    def libexec_dir(self) -> str:
        return HttpdTestEnv.LIBEXEC_DIR

    @property
    def dso_modules(self) -> List[str]:
        return self._dso_modules

    @property
    def mpm_modules(self) -> List[str]:
        return self._mpm_modules

    @property
    def server_conf_dir(self) -> str:
        return self._server_conf_dir

    @property
    def server_docs_dir(self) -> str:
        return self._server_docs_dir

    @property
    def httpd_error_log(self) -> HttpdErrorLog:
        return self._error_log

    def htdocs_src(self, path):
        return os.path.join(self._our_dir, 'htdocs', path)

    @property
    def h2load(self) -> str:
        return self._h2load

    @property
    def ca(self) -> Credentials:
        return self._ca

    @property
    def current_test_name(self) -> str:
        return self._current_test

    def set_current_test_name(self, val) -> None:
        self._current_test = val

    def require(self, condition: bool, reason: str,
                dep: str = None, detected=None) -> None:
        """Skip, or fail under strict-optional mode, on a missing dependency.

        The in-test counterpart of the @needs_dependency decorator, for
        checks that can only be made once a test is running. Use it instead
        of a bare pytest.skip() whenever the reason is "something we expected
        to be installed is not", and a plain pytest.skip() when the reason is
        "this test does not apply here".

        :param condition: truthy if the dependency is present
        :param reason: skip reason, also the "reason" line when strict
        :param dep: short dependency name for the strict message
        :param detected: what was found instead, for the strict message
        """
        import pytest
        if condition:
            return
        if self._strict_optional:
            from .depends import strict_failure_message
            pytest.fail(strict_failure_message(
                dep or reason, expected=reason, detected=detected,
                where=self.current_test_name), pytrace=False)
        pytest.skip(reason)

    @property
    def apachectl_stderr(self) -> str:
        return self._apachectl_stderr

    @property
    def test_modules_dir(self) -> str:
        return self._test_modules_dir

    @property
    def isWindows(self) -> bool:
        return platform.system().lower() == "windows"

    def add_cert_specs(self, specs: List[CertificateSpec]):
        self._cert_specs.extend(specs)

    def get_credentials_for_name(self, dns_name) -> List['Credentials']:
        for spec in [s for s in self._cert_specs if s.domains is not None]:
            if dns_name in spec.domains:
                return self.ca.get_credentials_for_name(spec.domains[0])
        return []

    def _versiontuple(self, v):
        v = re.sub(r'(\d+\.\d+(\.\d+)?)(-\S+)?', r'\1', v)
        return tuple(map(int, v.split('.')))

    def httpd_is_at_least(self, minv):
        hv = self._versiontuple(self.get_httpd_version())
        return hv >= self._versiontuple(minv)

    @staticmethod
    def _run_version(args):
        """Run a --version style command, returning its stdout or None.

        None means the binary is not there or would not run, which callers
        must distinguish from "ran fine but is too old". config.ini/default
        may just be the bare command name ("h2load"), not a verified path,
        so catching OSError here is what keeps an uninstalled tool from
        crashing collection with FileNotFoundError.
        """
        try:
            p = subprocess.run(args, capture_output=True, text=True)
        except OSError:
            return None
        return p.stdout if p.returncode == 0 else None

    def _probe_h2load(self):
        """The h2load version tuple, or None when h2load is unusable."""
        if self._h2load_version is None:
            self._h2load_version = False  # probed, not found
            out = self._run_version([self._h2load, '--version']) if self._h2load else None
            if out is not None:
                m = re.match(r'h2load nghttp2/(\S+)', out.strip())
                if m:
                    self._h2load_version = self._versiontuple(m.group(1))
        return self._h2load_version or None

    def has_h2load(self):
        return self._probe_h2load() is not None

    def h2load_version_str(self):
        """'1.41.0', or None when h2load is absent. For strict messages."""
        v = self._probe_h2load()
        return None if v is None else ".".join(str(n) for n in v)

    def h2load_is_at_least(self, minv):
        v = self._probe_h2load()
        return v is not None and v >= self._versiontuple(minv)

    def _probe_curl(self):
        """The curl version tuple, or None when curl is unusable."""
        if self._curl_version is None:
            self._curl_version = False  # probed, not found
            out = self._run_version([self._curl, '-V']) if self._curl else None
            if out is not None:
                for l in out.splitlines():
                    m = re.match(r'curl ([0-9.]+)[- ].*', l)
                    if m:
                        self._curl_version = self._versiontuple(m.group(1))
                        break
        return self._curl_version or None

    def has_curl(self):
        return self._probe_curl() is not None

    def curl_version_str(self):
        """'8.4.0', or None when curl is absent. For strict messages."""
        v = self._probe_curl()
        return None if v is None else ".".join(str(n) for n in v)

    def curl_is_at_least(self, minv):
        v = self._probe_curl()
        return v is not None and v >= self._versiontuple(minv)

    def curl_is_less_than(self, version):
        v = self._probe_curl()
        return v is not None and v < self._versiontuple(version)

    def curl_is_8_1_x(self):
        """Whether curl is one of the 8.1.x releases.

        Those mishandle TLS renegotiation; 8.0.x and 8.2.0+ are both fine.
        Returns False when curl is absent, so combine it with has_curl() when
        the test also needs curl to exist at all.
        """
        v = self._probe_curl()
        return (v is not None
                and self._versiontuple('8.1.0') <= v < self._versiontuple('8.2.0'))

    def _probe_nghttp(self):
        """The nghttp version tuple, or None when nghttp is unusable.

        config.ini always names a binary, so the name alone proves nothing
        about whether nghttp is installed: it has to be run. 'nghttp
        --version' prints 'nghttp2/1.64.0', the nghttp2 library version.
        """
        if self._nghttp_version is None:
            self._nghttp_version = False  # probed, not found
            out = self._run_version([self._nghttp, '--version']) if self._nghttp else None
            if out is not None:
                m = re.search(r'nghttp2/(\S+)', out.strip())
                if m:
                    self._nghttp_version = self._versiontuple(m.group(1))
        return self._nghttp_version or None

    def has_nghttp(self):
        return self._probe_nghttp() is not None

    def nghttp_version_str(self):
        """'1.64.0', or None when nghttp is absent. For strict messages."""
        v = self._probe_nghttp()
        return None if v is None else ".".join(str(n) for n in v)

    def nghttp_is_at_least(self, minv):
        v = self._probe_nghttp()
        return v is not None and v >= self._versiontuple(minv)

    def has_nghttp_get_assets(self):
        if not self.has_nghttp():
            return False
        p = subprocess.run([self._nghttp, "-a"], capture_output=True, text=True)
        return p.returncode == 0 and p.stderr == ""

    def get_apxs_var(self, name: str) -> str:
        p = subprocess.run([self._apxs, "-q", name], capture_output=True, text=True)
        if p.returncode != 0:
            return ""
        return p.stdout.strip()

    def get_httpd_version(self) -> str:
        return self._httpd_ver

    def mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def run(self, args, stdout_list=False, intext=None, inbytes=None, debug_log=True, env=None):
        if debug_log:
            log.debug(f"run: {args}")
        start = datetime.now()
        if intext is not None:
            inbytes = intext.encode()
        p = subprocess.run(args, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                           input=inbytes, env=env)
        stdout_as_list = None
        if stdout_list:
            try:
                out = p.stdout.decode()
                if HttpdTestSetup.CURL_STDOUT_SEPARATOR in out:
                    stdout_as_list = out.split(HttpdTestSetup.CURL_STDOUT_SEPARATOR)
                    if not stdout_as_list[len(stdout_as_list) - 1]:
                        stdout_as_list.pop()
                p.stdout.replace(HttpdTestSetup.CURL_STDOUT_SEPARATOR.encode(), b'')
            except:
                pass
        return ExecResult(args=args, exit_code=p.returncode,
                          stdout=p.stdout, stderr=p.stderr,
                          stdout_as_list=stdout_as_list,
                          duration=datetime.now() - start)

    def mkurl(self, scheme, hostname, path='/'):
        port = self.https_port if scheme == 'https' else self.http_port
        return f"{scheme}://{hostname}.{self.http_tld}:{port}{path}"

    def install_test_conf(self, lines: List[str]):
        self.apache_stop()
        with open(self._test_conf, 'w') as fd:
            fd.write('\n'.join(self._httpd_base_conf))
            fd.write('\n')
            fd.write(f"CoreDumpDirectory {self._server_dir}\n")
            fd.write('\n')
            if self._verbosity >= 3:
                fd.write(f"LogLevel trace7 ssl:trace6\n")
                fd.write(f"DumpIoOutput on\n")
                fd.write(f"DumpIoInput on\n")
            elif self._verbosity >= 2:
                fd.write(f"LogLevel debug core:trace5 {self.mpm_module}:trace5 ssl:trace5 http:trace5\n")
            elif self._verbosity >= 1:
                fd.write(f"LogLevel info\n")
            else:
                fd.write(f"LogLevel warn\n")
            if self._log_interesting:
                fd.write(self._log_interesting)
            fd.write('\n\n')
            fd.write('\n'.join(lines))
            fd.write('\n')

    def is_live(self, url: str = None, timeout: timedelta = None):
        if url is None:
            url = self._http_base
        if timeout is None:
            timeout = timedelta(seconds=5)
        try_until = datetime.now() + timeout
        last_err = ""
        while datetime.now() < try_until:
            # noinspection PyBroadException
            try:
                r = self.curl_get(url, insecure=True)
                if r.exit_code == 0:
                    return True
                time.sleep(.1)
            except ConnectionRefusedError:
                log.debug("connection refused")
                time.sleep(.1)
            except:
                if last_err != str(sys.exc_info()[0]):
                    last_err = str(sys.exc_info()[0])
                    log.debug("Unexpected error: %s", last_err)
                time.sleep(.1)
        log.debug(f"Unable to contact server after {timeout}")
        return False

    def is_dead(self, url: str = None, timeout: timedelta = None):
        if url is None:
            url = self._http_base
        if timeout is None:
            timeout = timedelta(seconds=5)
        try_until = datetime.now() + timeout
        last_err = None
        while datetime.now() < try_until:
            # noinspection PyBroadException
            try:
                r = self.curl_get(url)
                if r.exit_code != 0:
                    return True
                time.sleep(.1)
            except ConnectionRefusedError:
                log.debug("connection refused")
                return True
            except:
                if last_err != str(sys.exc_info()[0]):
                    last_err = str(sys.exc_info()[0])
                    log.debug("Unexpected error: %s", last_err)
                time.sleep(.1)
        log.debug(f"Server still responding after {timeout}")
        return False

    def _clean_path_env(self) -> dict:
        # Strip shim directories (uv, plugin-injected) from PATH so CGI
        # scripts spawned by httpd resolve python3 to a real interpreter.
        # Also prepend the test-suite venv's bin/ if present so CGI scripts
        # pick up packages installed there (e.g. multipart).
        parts = [
            p for p in os.environ.get('PATH', '').split(os.pathsep)
            if '/shims' not in p
        ]
        venv_bin = os.path.join(os.path.dirname(self._our_dir), '.venv', 'bin')
        if os.path.isdir(venv_bin) and venv_bin not in parts:
            parts.insert(0, venv_bin)
        env = os.environ.copy()
        env['PATH'] = os.pathsep.join(parts)
        env.update(self._httpd_env)
        return env

    @property
    def instance(self) -> HttpdInstance:
        """The httpd of this environment; see pyhttpd.instance."""
        if self._instance is None:
            self._instance = HttpdInstance(
                os.path.join(self._bin_dir, 'httpd'),
                ["-d", self._server_dir,
                 "-f", os.path.join(self._server_conf_dir, 'httpd.conf')],
                ports=[self._http_port],
                error_log=self._error_log,
                pid_files=[os.path.join(d, 'httpd.pid')
                           for d in (self._server_logs_dir, self._server_dir)],
                env=self._server_env(),
                stderr_file=os.path.join(self._server_dir, 'start.stderr'))
        return self._instance

    def _server_env(self) -> dict:
        env = self._clean_path_env()
        # what apachectl did: the messages of the server in a known language
        env.setdefault('LANG', 'C')
        return env

    def _run_apachectl(self, cmd) -> ExecResult:
        """Run "httpd -k <cmd>" and return the result. Only for tests that
        look at what httpd itself reports; use apache_restart() and friends
        to control the server."""
        conf_file = 'stop.conf' if cmd == 'stop' else 'httpd.conf'
        args = [os.path.join(self._bin_dir, 'httpd'),
                "-d", self.server_dir,
                "-f", os.path.join(self._server_dir, 'conf', conf_file),
                "-k", cmd]
        r = self.run(args, env=self._server_env())
        self._apachectl_stderr = r.stderr
        if r.exit_code != 0:
            log.warning(f"failed: {r}")
        return r

    def _start_instance(self) -> int:
        """Start the server, and wait for it to answer. 0 if it does."""
        self._apachectl_stderr = None
        # tests change the environment of the server between starts
        self.instance.env = self._server_env()
        try:
            self.instance.start()
        except HttpdStartError as e:
            self._apachectl_stderr = e.stderr
            log.debug(f"httpd did not start: {e}")
            return e.returncode if e.returncode else -1
        self._apachectl_stderr = self.instance.stderr_text()
        return 0 if self.is_live(self._http_base, timeout=timedelta(seconds=10)) else -1

    def apache_reload(self):
        return 0 if self.instance.restart(graceful=True) else -1

    def apache_restart(self):
        self.apache_stop()
        return self._start_instance()

    def apache_stop(self):
        return 0 if self.instance.stop() else -1

    def apache_graceful_stop(self):
        log.debug("stop apache")
        return 0 if self.instance.graceful_stop() else -1

    def apache_fail(self):
        """Start the server with a configuration it has to reject. 0 if it
        did: httpd exited with an error before serving. -1 if it started
        after all, or neither started nor exited in time (that is a stuck
        server, not a rejected configuration). The server is stopped either
        way, and apachectl_stderr has what it reported.
        """
        log.debug("expect apache fail")
        self.apache_stop()
        self._apachectl_stderr = None
        self.instance.env = self._server_env()
        try:
            self.instance.start()
        except HttpdStartError as e:
            self._apachectl_stderr = e.stderr
            if e.returncode > 0:
                return 0
            log.error(f"httpd neither started nor failed: {e}")
            return -1
        self._apachectl_stderr = self.instance.stderr_text()
        log.error("httpd started where it was expected to fail")
        self.instance.stop()
        return -1

    def apache_hard_restart(self) -> int:
        """Restart without the "graceful" flag, so the MPM starts over."""
        return 0 if self.instance.restart(graceful=False) else -1

    def read_pid_file(self, name: str = 'httpd.pid') -> Optional[int]:
        # Where PidFile lands depends on how the httpd under test resolves
        # a relative path against DefaultRuntimeDir, which has differed
        # between versions; look in both places rather than assume.
        for d in (self._server_logs_dir, self._server_dir):
            try:
                with open(os.path.join(d, name)) as fd:
                    return int(fd.read().strip())
            except (OSError, ValueError):
                continue
        return None

    def apache_access_log_clear(self):
        if os.path.isfile(self._server_access_log):
            os.remove(self._server_access_log)

    def get_ca_pem_file(self, hostname: str) -> Optional[str]:
        if len(self.get_credentials_for_name(hostname)) > 0:
            return self.ca.cert_file
        return None

    def clear_curl_headerfiles(self):
        for fname in os.listdir(path=self.gen_dir):
            if re.match(r'curl\.headers\.\d+', fname):
                os.remove(os.path.join(self.gen_dir, fname))
        self._curl_headerfiles_n = 0

    def curl_resolve_args(self, url, insecure=False, force_resolve=True, options=None):
        u = urlparse(url)

        args = [
        ]
        if u.scheme == 'http':
            pass
        elif insecure:
            args.append('--insecure')
        elif options and "--cacert" in options:
            pass
        elif u.hostname:
            ca_pem = self.get_ca_pem_file(u.hostname)
            if ca_pem:
                args.extend(["--cacert", ca_pem])

        if force_resolve and u.hostname and u.hostname != 'localhost' \
                and u.hostname != self._httpd_addr \
                and not re.match(r'^(\d+|\[|:).*', u.hostname):
            assert u.port, f"port not in url: {url}"
            args.extend(["--resolve", f"{u.hostname}:{u.port}:{self._httpd_addr}"])
        return args

    def curl_complete_args(self, urls, stdout_list=False,
                           timeout=None, options=None,
                           insecure=False, force_resolve=True):
        headerfile = f"{self.gen_dir}/curl.headers.{self._curl_headerfiles_n}"
        self._curl_headerfiles_n += 1

        args = [
            self._curl, "-s", "--path-as-is", "-D", headerfile,
        ]
        args.extend(self.curl_resolve_args(urls[0], insecure=insecure,
                                           force_resolve=force_resolve,
                                           options=options))
        if stdout_list:
            args.extend(['-w', '%{stdout}' + HttpdTestSetup.CURL_STDOUT_SEPARATOR])
        if self._current_test is not None:
            args.extend(["-H", f'AP-Test-Name: {self._current_test}'])
        if timeout is not None and int(timeout) > 0:
            args.extend(["--connect-timeout", str(int(timeout))])
        if options:
            args.extend(options)
        return args, headerfile

    def curl_parse_headerfile(self, headerfile: str, r: ExecResult = None) -> ExecResult:
        lines = open(headerfile).readlines()
        if r is None:
            r = ExecResult(args=[], exit_code=0, stdout=b'', stderr=b'')

        response = None
        def fin_response(response):
            if response:
                r.add_response(response)

        expected = ['status']
        for line in lines:
            if re.match(r'^$', line):
                if 'trailer' in expected:
                    # end of trailers
                    fin_response(response)
                    response = None
                    expected = ['status']
                elif 'header' in expected:
                    # end of header, another status or trailers might follow
                    expected = ['status', 'trailer']
                else:
                    assert False, f"unexpected line: {line}"
                continue
            if 'status' in expected:
                log.debug("reading 1st response line: %s", line)
                m = re.match(r'^(\S+) (\d+) (.*)$', line)
                if m:
                    fin_response(response)
                    response = {
                        "protocol": m.group(1),
                        "status": int(m.group(2)),
                        "description": m.group(3),
                        "header": {},
                        "trailer": {},
                        "body": r.outraw
                    }
                    expected = ['header']
                    continue
            if 'trailer' in expected:
                m = re.match(r'^([^:]+):\s*(.*)$', line)
                if m:
                    response['trailer'][m.group(1).lower()] = m.group(2)
                    continue
            if 'header' in expected:
                m = re.match(r'^([^:]+):\s*(.*)$', line)
                if m:
                    response['header'][m.group(1).lower()] = m.group(2)
                    continue
            assert False, f"unexpected line: {line}"

        fin_response(response)
        return r

    def curl_raw(self, urls, timeout=10, options=None, insecure=False,
                 force_resolve=True, no_stdout_list=False):
        if not isinstance(urls, list):
            urls = [urls]
        stdout_list = False
        if len(urls) > 1 and not no_stdout_list:
            stdout_list = True
        args, headerfile = self.curl_complete_args(
            urls=urls, stdout_list=stdout_list,
            timeout=timeout, options=options, insecure=insecure,
            force_resolve=force_resolve)
        args += urls
        r = self.run(args, stdout_list=stdout_list)
        if r.exit_code == 0:
            self.curl_parse_headerfile(headerfile, r=r)
            if r.json:
                r.response["json"] = r.json
        if os.path.isfile(headerfile):
            os.remove(headerfile)
        return r

    def curl_get(self, url, insecure=False, options=None):
        return self.curl_raw([url], insecure=insecure, options=options)

    def curl_upload(self, url, fpath, timeout=5, options=None):
        if not options:
            options = []
        options.extend([
            "--form", ("file=@%s" % fpath)
        ])
        return self.curl_raw(urls=[url], timeout=timeout, options=options)

    def curl_post_data(self, url, data="", timeout=5, options=None):
        if not options:
            options = []
        options.extend(["--data", "%s" % data])
        return self.curl_raw(url, timeout, options)

    def curl_post_value(self, url, key, value, timeout=5, options=None):
        if not options:
            options = []
        options.extend(["--form", "{0}={1}".format(key, value)])
        return self.curl_raw(url, timeout, options)

    def curl_protocol_version(self, url, timeout=5, options=None):
        if not options:
            options = []
        devnull = "NUL" if sys.platform == "win32" else "/dev/null"
        options.extend(["-w", "%{http_version}\n", "-o", devnull])
        r = self.curl_raw(url, timeout=timeout, options=options)
        if r.exit_code == 0 and r.response:
            return r.response["body"].decode('utf-8').rstrip()
        return -1
        
    def nghttp(self):
        return Nghttp(self._nghttp, connect_addr=self._httpd_addr,
                      tmp_dir=self.gen_dir, test_name=self._current_test)

    def h2load_status(self, run: ExecResult):
        stats = {}
        m = re.search(
            r'requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded'
            r', (\d+) failed, (\d+) errored, (\d+) timeout', run.stdout)
        if m:
            stats["requests"] = {
                "total": int(m.group(1)),
                "started": int(m.group(2)),
                "done": int(m.group(3)),
                "succeeded": int(m.group(4))
            }
            m = re.search(r'status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx',
                          run.stdout)
            if m:
                stats["status"] = {
                    "2xx": int(m.group(1)),
                    "3xx": int(m.group(2)),
                    "4xx": int(m.group(3)),
                    "5xx": int(m.group(4))
                }
            run.add_results({"h2load": stats})
        return run

    def make_data_file(self, indir: str, fname: str, fsize: int) -> str:
        fpath = os.path.join(indir, fname)
        s10 = "0123456789"
        s = (101 * s10) + s10[0:3]
        with open(fpath, 'w', newline='') as fd:
            for i in range(int(fsize / 1024)):
                fd.write(f"{i:09d}-{s}\n")
            remain = int(fsize % 1024)
            if remain != 0:
                i = int(fsize / 1024) + 1
                s = f"{i:09d}-{s}\n"
                fd.write(s[0:remain])
        return fpath

