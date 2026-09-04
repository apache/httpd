import sys
import os
import re
import subprocess
import warnings

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from pyhttpd.env import HttpdTestEnv


def pytest_ignore_collect(collection_path, config):
    if "pytest_suite" in collection_path.parts:
        return True

def pytest_report_header(config, start_path):
    env = HttpdTestEnv()
    return f"[apache httpd: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"

def pytest_addoption(parser):
    parser.addoption("--repeat", action="store", type=int, default=1,
                     help='Number of times to repeat each test')
    parser.addoption("--all", action="store_true")
    parser.addoption("--archive", action="store", default=None,
                     help='Archive the server dir after each test package '
                          'to the specified folder')
    parser.addoption("--httpd", action="store", default=None,
                     help="path to httpd binary (used to derive prefix, version, etc.)")
    parser.addoption("--conf", action="store", default=None,
                     help="path to the installed httpd.conf (for LoadModule discovery "
                     "when apxs is not available, e.g. on Windows)")


def _generate_config_ini(config):
    """Generate a config.ini from --httpd/--conf when no config.ini exists."""
    httpd_opt = config.getoption("--httpd")
    conf_opt = config.getoption("--conf")
    if not httpd_opt:
        return

    httpd_path = os.path.abspath(httpd_opt)
    prefix = os.path.dirname(os.path.dirname(httpd_path))
    bindir = os.path.join(prefix, "bin")
    libexecdir = os.path.join(prefix, "modules")
    is_win = sys.platform == "win32"

    # version from httpd -v
    version = "2.5.0"
    try:
        p = subprocess.run([httpd_path, "-v"], capture_output=True, text=True)
        m = re.search(r"Apache/(\S+)", p.stdout)
        if m:
            version = m.group(1)
    except Exception:
        pass

    # modules and mpm from conf file
    dso_modules = []
    mpm_modules = []
    if conf_opt:
        conf_path = os.path.abspath(conf_opt)
        try:
            with open(conf_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    m = re.match(r"LoadModule\s+(\S+)_module", line)
                    if m:
                        name = m.group(1)
                        if name.startswith("mpm_"):
                            mpm_modules.append(name)
                        else:
                            dso_modules.append(name)
        except Exception:
            pass

    if not mpm_modules:
        mpm_modules = ["mpm_winnt"] if is_win else ["mpm_event"]
    if is_win and "cgid" in dso_modules and "cgi" not in dso_modules:
        dso_modules = ["cgi" if m == "cgid" else m for m in dso_modules]

    apachectl = httpd_path if is_win else os.path.join(bindir, "apachectl")
    if is_win:
        prefix_curl = os.path.join(prefix, "bin", "curl.exe")
        curl_bin = prefix_curl if os.path.isfile(prefix_curl) else "curl.exe"
    else:
        curl_bin = "curl"
    test_dir = os.path.dirname(os.path.abspath(__file__))
    gen_dir = os.path.join(test_dir, "gen")

    ini_content = f"""[global]
prefix = {prefix}
exec_prefix = ${{prefix}}
bindir = ${{prefix}}/bin
sbindir = ${{exec_prefix}}/sbin
libdir = ${{exec_prefix}}/lib
libexecdir = ${{exec_prefix}}/modules

apr_bindir = ${{prefix}}
apxs = ${{prefix}}/bin/apxs
apachectl = {apachectl}

curl_bin = {curl_bin}
nghttp = nghttp
h2load = h2load

pre_built_test_binaries_dir = ${{libexecdir}}

[httpd]
version = {version}
name = httpd
dso_modules = {' '.join(dso_modules)}
mpm_modules = {' '.join(mpm_modules)}

[test]
gen_dir = {gen_dir}
http_port = 5002
https_port = 5001
proxy_port = 5003
http_port2 = 5004
ws_port = 5100
http_tld = tests.httpd.apache.org
test_dir = {test_dir}
test_src_dir = {test_dir}
"""
    ini_path = os.path.join(test_dir, "pyhttpd", "config.ini")
    with open(ini_path, "w") as f:
        f.write(ini_content)


def pytest_configure(config):
    httpd_opt = config.getoption("--httpd", default=None)
    if httpd_opt and sys.platform == "win32":
        _generate_config_ini(config)


def pytest_generate_tests(metafunc):
    if "repeat" in metafunc.fixturenames:
        count = int(metafunc.config.getoption("repeat"))
        metafunc.fixturenames.append('tmp_ct')
        metafunc.parametrize('repeat', range(count))


@pytest.fixture(autouse=True, scope="function")
def _function_scope(env, request):
    env.set_current_test_name(request.node.name)
    yield
    env.check_error_log()
    archive_dir = request.config.getoption("--archive")
    if archive_dir:
        fspath = str(request.fspath)
        if 'modules/' in fspath:
            package_name = fspath.split('modules/')[1].split('/')[0]
            env.archive_test_conf(request.node.name, package_name, archive_dir)
    env.set_current_test_name(None)


@pytest.fixture(autouse=True, scope="module")
def _module_scope(env):
    yield
    env.check_error_log()


@pytest.fixture(autouse=True, scope="package")
def _package_scope(env, request):
    env.httpd_error_log.clear_ignored_matches()
    env.httpd_error_log.clear_ignored_lognos()
    if sys.platform == "win32":
        env.httpd_error_log.add_ignored_lognos([
            "AH00098",
            "AH10373",
            "AH00336",
            "AH00337",
            "AH00338",
            "AH00341",
        ])
    yield
    assert env.apache_stop() == 0
    env.check_error_log()
    archive_dir = request.config.getoption("--archive")
    if archive_dir == "":
        warnings.warn("--archive option was empty, skipping archiving")
    if archive_dir:
        fspath = str(request.fspath)
        parts = fspath.split('modules/')
        package_name = parts[1].split('/')[0]
        env.archive_logs(package_name, archive_dir)
