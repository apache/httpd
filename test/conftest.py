import sys
import os
import re
import subprocess

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from pyhttpd.env import HttpdTestEnv

# Imported here before pytest_plugins loads it, so register it for
# assertion rewriting first, to avoid PytestAssertRewriteWarning.
pytest.register_assert_rewrite("pyhttpd.depends")
from pyhttpd.depends import apply_gate, strict_optional_enabled

# pyhttpd.plugin registers the command-line options of both suites;
# pyhttpd.gating evaluates the need_* and backport markers of both;
# pyhttpd.depends provides --strict-optional and the needs_dependency marker.
# pytest_plugins is only honoured in the rootdir conftest, and there is no
# pytest.ini in this tree, so this is the only place it can be declared.
pytest_plugins = ["pyhttpd.plugin", "pyhttpd.gating", "pyhttpd.depends",
                  "pyhttpd.classic_errorlog",
                  # pytester: the self-tests of these plugins
                  "pytester"]

# Everything below test/modules/ drives a real httpd.
MODULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules')


def pytest_report_header(config, start_path):
    from pyhttpd.build import config_ini_path, resolve_build
    info = resolve_build(config)
    if info is None:
        # no httpd found (neither --apxs/--httpd nor a build generated
        # config.ini); nothing to report
        return None
    line = f"[apache httpd: {info.version_str}, mpm: {info.mpm}, {info.prefix}, via {info.source}]"
    if info.source != "config.ini" and config_ini_path().is_file():
        # the modules/ suite tests the same httpd, but still takes its
        # ports and client tools from here
        line += f"\n[modules/ suite: ports and clients from {config_ini_path()}]"
    return line


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
    if config.getoption("--clean-modules", default=False):
        # the c-modules/ of pytest_suite are cleaned by its own fixture
        from pyhttpd.cmodules import clean_test_modules
        clean_test_modules(os.path.dirname(os.path.abspath(__file__)))
    httpd_opt = config.getoption("--httpd", default=None)
    if not httpd_opt:
        return
    ini_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "pyhttpd", "config.ini")
    if not os.path.isfile(ini_path):
        # No build-generated config.ini (typical on Windows without
        # autoconf) — generate one from --httpd/--conf so the framework
        # has something to read.
        _generate_config_ini(config)


def pytest_collection_modifyitems(config, items):
    """Gate the integration suite on the clients the framework itself needs.

    curl is not an optional dependency of the individual test cases that
    call curl_get(): apache_restart() proves the server came up with
    is_live(), and is_live() is a curl request. Without curl every test
    that starts an httpd dies in fixture setup, which is neither a skip nor
    a useful failure. So it is gated once here for the whole of
    test/modules/ rather than test by test.

    Tests outside that directory - the strict-mode self-test - run no httpd
    and are left alone.
    """
    if not any(str(item.path).startswith(MODULES_DIR) for item in items):
        return
    env = HttpdTestEnv()
    if env.has_curl():
        return
    missing = [("curl", "no curl available", f"tried to run {env.curl}")]
    strict = strict_optional_enabled(config)
    for item in items:
        if str(item.path).startswith(MODULES_DIR):
            apply_gate(item, missing, strict)


def pytest_generate_tests(metafunc):
    if "repeat" in metafunc.fixturenames:
        count = int(metafunc.config.getoption("repeat"))
        metafunc.fixturenames.append('tmp_ct')
        metafunc.parametrize('repeat', range(count))
