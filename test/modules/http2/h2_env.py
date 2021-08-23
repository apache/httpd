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
from typing import List

import requests

from configparser import ConfigParser, ExtendedInterpolation
from urllib.parse import urlparse

from h2_certs import Credentials
from h2_nghttp import Nghttp
from h2_result import ExecResult


log = logging.getLogger(__name__)


class Dummy:
    pass


class H2TestSetup:

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
        "ssl",
        "status",
        "autoindex",
        "cgid",
        "dir",
        "alias",
        "rewrite",
        "deflate",
        "proxy",
        "proxy_http",
        "proxy_balancer",
        "proxy_hcheck",
    ]

    def __init__(self, env: 'H2TestEnv'):
        self.env = env

    def make(self):
        self._make_dirs()
        self._make_conf()
        self._make_htdocs()
        self._make_h2test()
        self._make_modules_conf()

    def _make_dirs(self):
        if os.path.exists(self.env.gen_dir):
            shutil.rmtree(self.env.gen_dir)
        os.makedirs(self.env.gen_dir)
        if not os.path.exists(self.env.server_logs_dir):
            os.makedirs(self.env.server_logs_dir)

    def _make_conf(self):
        conf_src_dir = os.path.join(self.env.test_dir, 'conf')
        conf_dest_dir = os.path.join(self.env.server_dir, 'conf')
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
        for name, value in self.env.__class__.__dict__.items():
            if isinstance(value, property):
                var_map[name] = value.fget(self.env)
        t = Template(''.join(open(src).readlines()))
        with open(dest, 'w') as fd:
            fd.write(t.substitute(var_map))

    def _make_htdocs(self):
        if not os.path.exists(self.env.server_docs_dir):
            os.makedirs(self.env.server_docs_dir)
        shutil.copytree(os.path.join(self.env.test_dir, 'htdocs'),
                        os.path.join(self.env.server_dir, 'htdocs'),
                        dirs_exist_ok=True)
        cgi_dir = os.path.join(self.env.server_dir, 'htdocs/cgi')
        for name in os.listdir(cgi_dir):
            if re.match(r'.+\.py', name):
                cgi_file = os.path.join(cgi_dir, name)
                st = os.stat(cgi_file)
                os.chmod(cgi_file, st.st_mode | stat.S_IEXEC)

    def _make_h2test(self):
        subprocess.run([self.env.apxs, '-c', 'mod_h2test.c'],
                       capture_output=True, check=True,
                       cwd=os.path.join(self.env.test_dir, 'mod_h2test'))

    def _make_modules_conf(self):
        modules_conf = os.path.join(self.env.server_dir, 'conf/modules.conf')
        with open(modules_conf, 'w') as fd:
            # issue load directives for all modules we want that are shared
            for m in self.MODULES:
                mod_path = os.path.join(self.env.libexec_dir, f"mod_{m}.so")
                if os.path.isfile(mod_path):
                    fd.write(f"LoadModule {m}_module   \"{mod_path}\"\n")
            for m in ["http2", "proxy_http2"]:
                fd.write(f"LoadModule {m}_module   \"{self.env.libexec_dir}/mod_{m}.so\"\n")
            # load our test module which is not installed
            fd.write(f"LoadModule h2test_module   \"{self.env.test_dir}/mod_h2test/.libs/mod_h2test.so\"\n")


class H2TestEnv:

    def __init__(self, pytestconfig=None):
        our_dir = os.path.dirname(inspect.getfile(Dummy))
        self.config = ConfigParser(interpolation=ExtendedInterpolation())
        self.config.read(os.path.join(our_dir, 'config.ini'))

        self._apxs = self.config.get('global', 'apxs')
        self._prefix = self.config.get('global', 'prefix')
        self._apachectl = self.config.get('global', 'apachectl')
        self._libexec_dir = self.get_apxs_var('LIBEXECDIR')

        self._curl = self.config.get('global', 'curl_bin')
        self._nghttp = self.config.get('global', 'nghttp')
        self._h2load = self.config.get('global', 'h2load')
        self._ca = None

        self._http_port = int(self.config.get('test', 'http_port'))
        self._https_port = int(self.config.get('test', 'https_port'))
        self._http_tld = self.config.get('test', 'http_tld')
        self._test_dir = self.config.get('test', 'test_dir')
        self._test_src_dir = self.config.get('test', 'test_src_dir')
        self._gen_dir = self.config.get('test', 'gen_dir')
        self._server_dir = os.path.join(self._gen_dir, 'apache')
        self._server_conf_dir = os.path.join(self._server_dir, "conf")
        self._server_docs_dir = os.path.join(self._server_dir, "htdocs")
        self._server_logs_dir = os.path.join(self.server_dir, "logs")
        self._server_error_log = os.path.join(self._server_logs_dir, "error_log")

        self._dso_modules = self.config.get('global', 'dso_modules').split(' ')
        self._domains = [
            f"test1.{self._http_tld}",
            f"test2.{self._http_tld}",
            f"test3.{self._http_tld}",
            f"cgi.{self._http_tld}",
            f"push.{self._http_tld}",
            f"hints.{self._http_tld}",
            f"ssl.{self._http_tld}",
            f"pad0.{self._http_tld}",
            f"pad1.{self._http_tld}",
            f"pad2.{self._http_tld}",
            f"pad3.{self._http_tld}",
            f"pad8.{self._http_tld}",
        ]
        self._domains_noh2 = [
            f"noh2.{self._http_tld}",
        ]
        self._mpm_type = os.environ['MPM'] if 'MPM' in os.environ else 'event'

        self._httpd_addr = "127.0.0.1"
        self._http_base = f"http://{self._httpd_addr}:{self.http_port}"
        self._https_base = f"https://{self._httpd_addr}:{self.https_port}"

        self._test_conf = os.path.join(self._server_conf_dir, "test.conf")
        self._httpd_base_conf = f"""
        LoadModule mpm_{self.mpm_type}_module  \"{self.libexec_dir}/mod_mpm_{self.mpm_type}.so\"
        H2MinWorkers 1
        H2MaxWorkers 64
        SSLSessionCache "shmcb:ssl_gcache_data(32000)"
        """
        py_verbosity = pytestconfig.option.verbose if pytestconfig is not None else 0
        if py_verbosity >= 2:
            self._httpd_base_conf += f"""
                LogLevel http2:trace2 proxy_http2:info 
                LogLevel core:trace5 mpm_{self.mpm_type}:trace5
                """
        if py_verbosity >= 1:
            self._httpd_base_conf += "LogLevel http2:debug proxy_http2:debug"
        else:
            self._httpd_base_conf += "LogLevel http2:info proxy_http2:info"

        self._verify_certs = False
        self._setup = H2TestSetup(env=self)
        self._setup.make()

    @property
    def apxs(self) -> str:
        return self._apxs

    @property
    def prefix(self) -> str:
        return self._prefix

    @property
    def mpm_type(self) -> str:
        return self._mpm_type

    @property
    def http_port(self) -> int:
        return self._http_port

    @property
    def https_port(self) -> int:
        return self._https_port

    @property
    def http_tld(self) -> str:
        return self._http_tld

    @property
    def domain_test1(self) -> str:
        return self._domains[0]

    @property
    def domains(self) -> List[str]:
        return self._domains

    @property
    def domains_noh2(self) -> List[str]:
        return self._domains_noh2

    @property
    def http_base_url(self) -> str:
        return self._http_base

    @property
    def https_base_url(self) -> str:
        return self._https_base

    @property
    def gen_dir(self) -> str:
        return self._gen_dir

    @property
    def test_dir(self) -> str:
        return self._test_dir

    @property
    def test_src_dir(self) -> str:
        return self._test_src_dir

    @property
    def server_dir(self) -> str:
        return self._server_dir

    @property
    def server_logs_dir(self) -> str:
        return self._server_logs_dir

    @property
    def libexec_dir(self) -> str:
        return self._libexec_dir

    @property
    def dso_modules(self) -> List[str]:
        return self._dso_modules

    @property
    def server_conf_dir(self) -> str:
        return self._server_conf_dir

    @property
    def server_docs_dir(self) -> str:
        return self._server_docs_dir

    @property
    def httpd_base_conf(self) -> str:
        return self._httpd_base_conf

    @property
    def h2load(self) -> str:
        return self._h2load

    @property
    def ca(self) -> Credentials:
        return self._ca

    def set_ca(self, ca: Credentials):
        self._ca = ca

    def get_credentials_for_name(self, dns_name) -> List['Credentials']:
        for domains in [self._domains, self._domains_noh2]:
            if dns_name in domains:
                return self.ca.get_credentials_for_name(domains[0])
        return []

    def has_h2load(self):
        return self._h2load != ""

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

    def test_src(self, path):
        return os.path.join(self._test_src_dir, path)

    def run(self, args) -> ExecResult:
        log.debug("execute: %s", " ".join(args))
        start = datetime.now()
        p = subprocess.run(args, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        return ExecResult(exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr,
                          duration=datetime.now() - start)

    def mkurl(self, scheme, hostname, path='/'):
        port = self.https_port if scheme == 'https' else self.http_port
        return "%s://%s.%s:%s%s" % (scheme, hostname, self.http_tld, port, path)

    def install_test_conf(self, conf: List[str]):
        with open(self._test_conf, 'w') as fd:
            fd.write(f"{self.httpd_base_conf}\n")
            for line in conf:
                fd.write(f"{line}\n")

    def is_live(self, url, timeout: timedelta = None):
        s = requests.Session()
        if not timeout:
            timeout = timedelta(seconds=10)
        try_until = datetime.now() + timeout
        log.debug("checking reachability of %s", url)
        while datetime.now() < try_until:
            try:
                req = requests.Request('HEAD', url).prepare()
                s.send(req, verify=self._verify_certs, timeout=timeout.total_seconds())
                return True
            except IOError:
                log.debug("connect error: %s", sys.exc_info()[0])
                time.sleep(.2)
            except:
                log.warning("Unexpected error: %s", sys.exc_info()[0])
                time.sleep(.2)
        log.debug(f"Unable to contact '{url}' after {timeout} sec")
        return False

    def is_dead(self, url, timeout: timedelta = None):
        s = requests.Session()
        if not timeout:
            timeout = timedelta(seconds=10)
        try_until = datetime.now() + timeout
        log.debug("checking reachability of %s", url)
        while datetime.now() < try_until:
            try:
                req = requests.Request('HEAD', url).prepare()
                s.send(req, verify=self._verify_certs, timeout=timeout)
                time.sleep(.2)
            except IOError:
                return True
            except:
                return True
        log.debug("Server still responding after %d sec", timeout)
        return False

    def apachectl(self, cmd, check_live=True):
        args = [self._apachectl,
                "-d", self.server_dir,
                "-f", os.path.join(self._server_dir, 'conf/httpd.conf'),
                "-k", cmd]
        log.debug("execute: %s", " ".join(args))
        p = subprocess.run(args, capture_output=True, text=True)
        rv = p.returncode
        if rv == 0:
            timeout = timedelta(seconds=10)
            if check_live:
                rv = 0 if self.is_live(self._http_base, timeout=timeout) else -1
            else:
                rv = 0 if self.is_dead(self._http_base, timeout=timeout) else -1
                log.debug("waited for a apache.is_dead, rv=%d", rv)
        else:
            log.warning(f"exit {rv}, stdout: {p.stdout}, stderr: {p.stderr}")
        return rv

    def apache_restart(self):
        return self.apachectl("graceful")
        
    def apache_start(self):
        return self.apachectl("start")

    def apache_stop(self):
        return self.apachectl("stop", check_live=False)

    def apache_error_log_clear(self):
        if os.path.isfile(self._server_error_log):
            os.remove(self._server_error_log)

    RE_APLOGNO = re.compile(r'.*\[(?P<module>[^:]+):(error|warn)].* (?P<aplogno>AH\d+): .+')
    RE_SSL_LIB_ERR = re.compile(r'.*\[ssl:error].* SSL Library Error: error:(?P<errno>\S+):.+')
    RE_ERRLOG_ERROR = re.compile(r'.*\[(?P<module>[^:]+):error].*')
    RE_ERRLOG_WARN = re.compile(r'.*\[(?P<module>[^:]+):warn].*')

    def apache_errors_and_warnings(self):
        errors = []
        warnings = []

        if os.path.isfile(self._server_error_log):
            for line in open(self._server_error_log):
                m = self.RE_APLOGNO.match(line)
                if m and m.group('aplogno') in [
                    'AH02032',
                    'AH01276',
                    'AH01630',
                    'AH00135',
                    'AH02261',  # Re-negotiation handshake failed (our test_101
                ]:
                    # we know these happen normally in our tests
                    continue
                m = self.RE_SSL_LIB_ERR.match(line)
                if m and m.group('errno') in [
                    '1417A0C1',  # cipher suite mismatch, test_101
                    '1417C0C7',  # client cert not accepted, test_101
                ]:
                    # we know these happen normally in our tests
                    continue
                m = self.RE_ERRLOG_ERROR.match(line)
                if m and m.group('module') not in ['cgid']:
                    errors.append(line)
                    continue
                m = self.RE_ERRLOG_WARN.match(line)
                if m:
                    warnings.append(line)
                    continue
        return errors, warnings

    def curl_complete_args(self, urls, timeout, options):
        if not isinstance(urls, list):
            urls = [urls]
        u = urlparse(urls[0])
        assert u.hostname, f"hostname not in url: {urls[0]}"
        assert u.port, f"port not in url: {urls[0]}"
        headerfile = ("%s/curl.headers" % self.gen_dir)
        if os.path.isfile(headerfile):
            os.remove(headerfile)

        args = [ 
            self._curl,
            "--cacert", self.ca.cert_file,
            "-s", "-D", headerfile,
            "--resolve", ("%s:%s:%s" % (u.hostname, u.port, self._httpd_addr)),
            "--connect-timeout", ("%d" % timeout) 
        ]
        if options:
            args.extend(options)
        args += urls
        return args, headerfile

    def curl_raw(self, urls, timeout, options):
        args, headerfile = self.curl_complete_args(urls, timeout, options)
        r = self.run(args)
        if r.exit_code == 0:
            lines = open(headerfile).readlines()
            exp_stat = True
            header = {}
            for line in lines:
                if exp_stat:
                    log.debug("reading 1st response line: %s", line)
                    m = re.match(r'^(\S+) (\d+) (.*)$', line)
                    assert m
                    r.add_response({
                        "protocol": m.group(1),
                        "status": int(m.group(2)),
                        "description": m.group(3),
                        "body": r.outraw
                    })
                    exp_stat = False
                    header = {}
                elif re.match(r'^$', line):
                    exp_stat = True
                else:
                    log.debug("reading header line: %s", line)
                    m = re.match(r'^([^:]+):\s*(.*)$', line)
                    assert m
                    header[m.group(1).lower()] = m.group(2)
            r.response["header"] = header
            if r.json:
                r.response["json"] = r.json
        return r

    def curl_get(self, url, timeout=5, options=None):
        return self.curl_raw([url], timeout=timeout, options=options)

    def curl_upload(self, url, fpath, timeout=5, options=None):
        if not options:
            options = []
        options.extend([
            "--form", ("file=@%s" % fpath)
        ])
        return self.curl_raw([url], timeout, options)

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
        return Nghttp(self._nghttp, connect_addr=self._httpd_addr, tmp_dir=self.gen_dir)

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

    def setup_data_1k_1m(self):
        s100 = "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678\n"
        with open(os.path.join(self.gen_dir, "data-1k"), 'w') as f:
            for i in range(10):
                f.write(s100)
        with open(os.path.join(self.gen_dir, "data-10k"), 'w') as f:
            for i in range(100):
                f.write(s100)
        with open(os.path.join(self.gen_dir, "data-100k"), 'w') as f:
            for i in range(1000):
                f.write(s100)
        with open(os.path.join(self.gen_dir, "data-1m"), 'w') as f:
            for i in range(10000):
                f.write(s100)
