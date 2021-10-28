import logging
import os

import pytest
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from .env import H2TestEnv


def pytest_report_header(config, startdir):
    env = H2TestEnv(setup_dirs=False)
    return f"mod_h2 [apache: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"


def pytest_addoption(parser):
    parser.addoption("--repeat", action="store", type=int, default=1,
                     help='Number of times to repeat each test')
    parser.addoption("--all", action="store_true")


def pytest_generate_tests(metafunc):
    if "repeat" in metafunc.fixturenames:
        count = int(metafunc.config.getoption("repeat"))
        metafunc.fixturenames.append('tmp_ct')
        metafunc.parametrize('repeat', range(count))


@pytest.fixture(scope="package")
def env(pytestconfig) -> H2TestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = H2TestEnv(pytestconfig=pytestconfig)
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    return env


@pytest.fixture(autouse=True, scope="package")
def _session_scope(env):
    yield
    assert env.apache_stop() == 0
    errors, warnings = env.httpd_error_log.get_missed()
    assert (len(errors), len(warnings)) == (0, 0),\
            f"apache logged {len(errors)} errors and {len(warnings)} warnings: \n"\
            "{0}\n{1}\n".format("\n".join(errors), "\n".join(warnings))

