import logging
import os

import pytest
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from .env import CoreTestEnv


def pytest_report_header(config, startdir):
    env = CoreTestEnv(setup_dirs=False)
    return f"core [apache: {env.get_httpd_version()}, mpm: {env.mpm_type}, {env.prefix}]"


@pytest.fixture(scope="module")
def env(pytestconfig) -> CoreTestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = CoreTestEnv(pytestconfig=pytestconfig)
    env.apache_access_log_clear()
    env.apache_error_log_clear()
    return env


@pytest.fixture(autouse=True, scope="module")
def _session_scope(env):
    yield
    assert env.apache_stop() == 0
    errors, warnings = env.apache_errors_and_warnings()
    assert (len(errors), len(warnings)) == (0, 0),\
            f"apache logged {len(errors)} errors and {len(warnings)} warnings: \n"\
            "{0}\n{1}\n".format("\n".join(errors), "\n".join(warnings))

