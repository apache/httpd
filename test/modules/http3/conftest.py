import logging
import os
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from .env import H3TestEnv


def pytest_report_header(config, start_path):
    env = H3TestEnv()
    return f"mod_http3 [apache: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"


@pytest.fixture(scope="package")
def env(pytestconfig) -> H3TestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = H3TestEnv(pytestconfig=pytestconfig)
    env.require(env.has_shared_module("http3"), "mod_http3 is not built",
                dep="mod_http3")
    env.require(env.has_shared_module("ssl"), "mod_ssl is not built",
                dep="mod_ssl")
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    return env
