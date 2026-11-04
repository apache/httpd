import logging
import os
import sys

import pytest

from .env import BrotliTestEnv

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))


def pytest_report_header(config, start_path):
    env = BrotliTestEnv()
    return f"brotli [apache: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"


@pytest.fixture(scope="package")
def env(pytestconfig) -> BrotliTestEnv:
    logging.getLogger('').setLevel(level=logging.INFO)
    env = BrotliTestEnv(pytestconfig=pytestconfig)
    if not env.has_shared_module("brotli"):
        pytest.skip("mod_brotli not available")
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    return env


@pytest.fixture(autouse=True, scope="package")
def _stop_package_scope(env):
    yield
    assert env.apache_stop() == 0
