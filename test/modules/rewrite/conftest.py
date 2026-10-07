import logging
import os
import sys

import pytest

from .env import RewriteTestEnv

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))


def pytest_report_header(config, start_path):
    env = RewriteTestEnv()
    return f"rewrite [apache: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"


@pytest.fixture(scope="package")
def env(pytestconfig) -> RewriteTestEnv:
    logging.getLogger('').setLevel(level=logging.INFO)
    env = RewriteTestEnv(pytestconfig=pytestconfig)
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    return env


@pytest.fixture(autouse=True, scope="package")
def _stop_package_scope(env):
    yield
    assert env.apache_stop() == 0
