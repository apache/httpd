import importlib
import inspect
import logging
import re
import os
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta
from string import Template
from typing import List, Optional

from configparser import ConfigParser, ExtendedInterpolation
from urllib.parse import urlparse

from .certs import Credentials, HttpdTestCA, CertificateSpec
from .log import HttpdErrorLog
from .nghttp import Nghttp
from .result import ExecResult


log = logging.getLogger(__name__)


class Dummy:
    pass


class HttpdTestSetup:

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
        if not os.path.exists(self.env.server_logs_dir):
            os.makedirs(self.env.server_logs_dir)

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

    def _make_modules_conf(self):
        loaded = set()
        modules_conf = os.path.join(self.env.server_dir, 'conf/modules.conf')
        with open(modules_conf, 'w') as fd:
            # issue load directives for all modules we want that are shared
            missing_mods = list()
            for m in self._modules:
                match = re.match(r'^mod_(.+)$', m)
                if match:
                    m = match.group(1)
                if m in loaded:
                    continue
                mod_path = os.path.join(self.env.libexec_dir, f"mod_{m}.so")
                if os.path.isfile(mod_path):
                    fd.write(f"LoadModule {m}_module   \"{mod_path}\"\n")
                elif m in self.env.dso_modules:
                    missing_mods.append(m)
                else:
                    fd.write(f"#built static: LoadModule {m}_module   \"{mod_path}\"\n")
                loaded.add(m)
            for m in self._optional_modules:
                match = re.match(r'^mod_(.+)$', m)
                if match:
                    m = match.group(1)
                if m in loaded:
                    continue
                mod_path = os.path.join(self.env.libexec_dir, f"mod_{m}.so")
                if os.path.isfile(mod_path):
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
        # make all contained .py scripts executable
        for dirpath, _dirnames, filenames in os.walk(dest_dir):
            for fname in filenames:
                if re.match(r'.+\.py', fname):
                    py_file = os.path.join(dirpath, fname)
                    st = os.stat(py_file)
                    os.chmod(py_file, st.st_mode | stat.S_IEXEC)

    def _add_aptest(self):
        local_dir = os.path.dirname(inspect.getfile(HttpdTestSetup))
        p = subprocess.run([self.env.apxs, '-c', 'mod_aptest.c'],
                           capture_output=True,
                           cwd=os.path.join(local_dir, 'mod_aptest'))
        rv = p.returncode
        if rv != 0:
            log.error(f"compiling mod_aptest failed: {p.stderr}")
            raise Exception(f"compiling mod_aptest failed: {p.stderr}")

        modules_conf = os.path.join(self.env.server_dir, 'conf/modules.conf')
        with open(modules_conf, 'a') as fd:
            # load our test module which is not installed
            fd.write(f"LoadModule aptest_module   \"{local_dir}/mod_aptest/.libs/mod_aptest.so\"\n")

    def _build_clients(self):
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

    @classmethod
    def has_python_package(cls, name: str) -> bool:
        if name in sys.modules:
            # already loaded
            return True
        elif (spec := importlib.util.find_spec(name)) is not None:
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return True
        else:
            return False

    @classmethod
    def get_ssl_module(cls):
        return os.environ['SSL'] if 'SSL' in os.environ else 'mod_ssl'

    @classmethod
    def has_shared_module(cls, name):
        if cls.LIBEXEC_DIR is None:
            env = HttpdTestEnv()  # will initialized it
        path = os.path.join(cls.LIBEXEC_DIR, f"mod_{name}.so")
        return os.path.isfile(path)

    def __init__(self, pytestconfig=None):
        self._our_dir = os.path.dirname(inspect.getfile(Dummy))
        self.config = ConfigParser(interpolation=ExtendedInterpolation())
        self.config.read(os.path.join(self._our_dir, 'config.ini'))

        self._bin_dir = self.config.get('global', 'bindir')
        self._apxs = self.config.get('global', 'apxs')
        self._prefix = self.config.get('global', 'prefix')
        self._apachectl = self.config.get('global', 'apachectl')
        if HttpdTestEnv.LIBEXEC_DIR is None:
            HttpdTestEnv.LIBEXEC_DIR = self._libexec_dir = self.get_apxs_var('LIBEXECDIR')
        self._curl = self.config.get('global', 'curl_bin')
        if 'CURL' in os.environ:
            self._curl = os.environ['CURL']
        self._nghttp = self.config.get('global', 'nghttp')
        if self._nghttp is None:
            self._nghttp = 'nghttp'
        self._h2load = self.config.get('global', 'h2load')
        if self._h2load is None:
            self._h2load = 'h2load'

        self._http_port = int(self.config.get('test', 'http_port'))
        self._http_port2 = int(self.config.get('test', 'http_port2'))
        self._https_port = int(self.config.get('test', 'https_port'))
        self._proxy_port = int(self.config.get('test', 'proxy_port'))
        self._ws_port = int(self.config.get('test', 'ws_port'))
        self._http_tld = self.config.get('test', 'http_tld')
        self._test_dir = self.config.get('test', 'test_dir')
        self._clients_dir = os.path.join(os.path.dirname(self._test_dir), 'clients')
        self._gen_dir = self.config.get('test', 'gen_dir')
        self._server_dir = os.path.join(self._gen_dir, 'apache')
        self._server_conf_dir = os.path.join(self._server_dir, "conf")
        self._server_docs_dir = os.path.join(self._server_dir, "htdocs")
        self._server_logs_dir = os.path.join(self.server_dir, "logs")
        self._server_access_log = os.path.join(self._server_logs_dir, "access_log")
        self._error_log = HttpdErrorLog(os.path.join(self._server_logs_dir, "error_log"))
        self._apachectl_stderr = None

        self._dso_modules = self.config.get('httpd', 'dso_modules').split(' ')
        self._mpm_modules = self.config.get('httpd', 'mpm_modules').split(' ')
        self._mpm_module = f"mpm_{os.environ['MPM']}" if 'MPM' in os.environ else 'mpm_event'
        self._ssl_module = self.get_ssl_module()
        if len(self._ssl_module.strip()) == 0:
            self._ssl_module = None

        self._httpd_addr = "127.0.0.1"
        self._http_base = f"http://{self._httpd_addr}:{self.http_port}"
        self._https_base = f"https://{self._httpd_addr}:{self.https_port}"

        self._verbosity = pytestconfig.option.verbose if pytestconfig is not None else 0
        self._test_conf = os.path.join(self._server_conf_dir, "test.conf")
        self._httpd_base_conf = []
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
        self._current_test = None

    def add_httpd_conf(self, lines: List[str]):
        self._httpd_base_conf.extend(lines)

    def add_httpd_log_modules(self, modules: List[str]):
        self._httpd_log_modules.extend(modules)

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

    @property
    def apachectl_stderr(self):
        return self._apachectl_stderr

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

    def has_h2load(self):
        return self._h2load != ""

    def h2load_is_at_least(self, minv):
        if not self.has_h2load():
            return False
        if self._h2load_version is None:
            p = subprocess.run([self._h2load, '--version'], capture_output=True, text=True)
            if p.returncode != 0:
                return False
            s = p.stdout.strip()
            m = re.match(r'h2load nghttp2/(\S+)', s)
            if m:
                self._h2load_version = self._versiontuple(m.group(1))
        if self._h2load_version is not None:
            return self._h2load_version >= self._versiontuple(minv)
        return False

    def curl_is_at_least(self, minv):
        if self._curl_version is None:
            p = subprocess.run([self._curl, '-V'], capture_output=True, text=True)
            if p.returncode != 0:
                return False
            for l in p.stdout.splitlines():
                m = re.match(r'curl ([0-9.]+)[- ].*', l)
                if m:
                    self._curl_version = self._versiontuple(m.group(1))
                    break
        if self._curl_version is not None:
            return self._curl_version >= self._versiontuple(minv)
        return False

    def curl_is_less_than(self, version):
        if self._curl_version is None:
            p = subprocess.run([self._curl, '-V'], capture_output=True, text=True)
            if p.returncode != 0:
                return False
            for l in p.stdout.splitlines():
                m = re.match(r'curl ([0-9.]+)[- ].*', l)
                if m:
                    self._curl_version = self._versiontuple(m.group(1))
                    break
        if self._curl_version is not None:
            return self._curl_version < self._versiontuple(version)
        return False

    def has_nghttp(self):
        return self._nghttp != ""

    def has_nghttp_get_assets(self):
        if not self.has_nghttp():
            return False
        args = [self._nghttp, "-a"]
        p = subprocess.run(args, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        rv = p.returncode
        if rv != 0:
            return False
        return p.stderr == ""

    def get_apxs_var(self, name: str) -> str:
        p = subprocess.run([self._apxs, "-q", name], capture_output=True, text=True)
        if p.returncode != 0:
            return ""
        return p.stdout.strip()

    def get_httpd_version(self) -> str:
        return self.get_apxs_var("HTTPD_VERSION")

    def mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def run(self, args, stdout_list=False, intext=None, inbytes=None, debug_log=True):
        if debug_log:
            log.debug(f"run: {args}")
        start = datetime.now()
        if intext is not None:
            inbytes = intext.encode()
        p = subprocess.run(args, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                           input=inbytes)
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

    def _run_apachectl(self, cmd) -> ExecResult:
        conf_file = 'stop.conf' if cmd == 'stop' else 'httpd.conf'
        args = [self._apachectl,
                "-d", self.server_dir,
                "-f", os.path.join(self._server_dir, f'conf/{conf_file}'),
                "-k", cmd]
        r = self.run(args)
        self._apachectl_stderr = r.stderr
        if r.exit_code != 0:
            log.warning(f"failed: {r}")
        return r

    def apache_reload(self):
        r = self._run_apachectl("graceful")
        if r.exit_code == 0:
            timeout = timedelta(seconds=10)
            return 0 if self.is_live(self._http_base, timeout=timeout) else -1
        return r.exit_code

    def apache_restart(self):
        self.apache_stop()
        r = self._run_apachectl("start")
        if r.exit_code == 0:
            timeout = timedelta(seconds=10)
            return 0 if self.is_live(self._http_base, timeout=timeout) else -1
        return r.exit_code
        
    def apache_stop(self):
        r = self._run_apachectl("stop")
        if r.exit_code == 0:
            timeout = timedelta(seconds=10)
            return 0 if self.is_dead(self._http_base, timeout=timeout) else -1
        return r

    def apache_graceful_stop(self):
        log.debug("stop apache")
        self._run_apachectl("graceful-stop")
        return 0 if self.is_dead() else -1

    def apache_fail(self):
        log.debug("expect apache fail")
        self._run_apachectl("stop")
        rv = self._run_apachectl("start")
        if rv == 0:
            rv = 0 if self.is_dead() else -1
        else:
            rv = 0
        return rv

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
        options.extend(["-w", "%{http_version}\n", "-o", "/dev/null"])
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
        with open(fpath, 'w') as fd:
            for i in range(int(fsize / 1024)):
                fd.write(f"{i:09d}-{s}\n")
            remain = int(fsize % 1024)
            if remain != 0:
                i = int(fsize / 1024) + 1
                s = f"{i:09d}-{s}\n"
                fd.write(s[0:remain])
        return fpath

