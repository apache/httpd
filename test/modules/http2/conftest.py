import logging
import os

import pytest
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from .env import H2TestEnv


def pytest_report_header(config, start_path):
    env = H2TestEnv()
    return f"mod_h2 [apache: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"


@pytest.fixture(scope="package")
def env(pytestconfig) -> H2TestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = H2TestEnv(pytestconfig=pytestconfig)
    # setup_httpd() raises if a module it LoadModules is missing, e.g. in a
    # build configured with --disable-http2. Report that as the missing
    # dependency instead.
    env.require(env.has_shared_module("http2") and env.has_shared_module("proxy_http2"),
                "mod_http2 and mod_proxy_http2 were not built", dep="mod_http2",
                detected=f"no mod_http2.so and mod_proxy_http2.so in {env.libexec_dir}")
    # the h2 vhosts are TLS, so setup_httpd() hard-requires mod_ssl and
    # raises if it was not built. Report that as the missing dependency.
    env.require(env.has_mod_ssl(), "no mod_ssl available", dep="mod_ssl",
                detected=f"no mod_ssl.so in {env.libexec_dir}")
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    return env


@pytest.fixture(autouse=True, scope="package")
def _h2_package_scope(env):
    env.httpd_error_log.add_ignored_lognos([
        'AH10400',  # warning that 'enablereuse' has not effect in certain configs
        'AH00045',  # child did not exit in time, SIGTERM was sent
    ])
    yield
    assert env.apache_stop() == 0
