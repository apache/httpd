import logging
import os

import pytest
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from .env import H1TestEnv


def pytest_report_header(config, startdir):
    env = H1TestEnv()
    return f"mod_http [apache: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"


def pytest_generate_tests(metafunc):
    if "repeat" in metafunc.fixturenames:
        count = int(metafunc.config.getoption("repeat"))
        metafunc.fixturenames.append('tmp_ct')
        metafunc.parametrize('repeat', range(count))


@pytest.fixture(scope="package")
def env(pytestconfig) -> H1TestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = H1TestEnv(pytestconfig=pytestconfig)
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    return env
