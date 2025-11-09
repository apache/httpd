import logging
import os

import pytest
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from .env import H2TestEnv


def pytest_report_header(config, startdir):
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
