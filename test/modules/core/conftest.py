import logging
import os

import pytest
import sys

from pyhttpd.env import HttpdTestEnv

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))


def pytest_report_header(config, startdir):
    env = HttpdTestEnv()
    return f"core [apache: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"


@pytest.fixture(scope="package")
def env(pytestconfig) -> HttpdTestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = HttpdTestEnv(pytestconfig=pytestconfig)
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    return env


@pytest.fixture(autouse=True, scope="package")
def _session_scope(env):
    env.httpd_error_log.set_ignored_lognos([
        'AH10244',  # core: invalid URI path
        'AH01264',  # mod_cgid script not found
    ])
    yield
    assert env.apache_stop() == 0
    errors, warnings = env.httpd_error_log.get_missed()
    assert (len(errors), len(warnings)) == (0, 0),\
            f"apache logged {len(errors)} errors and {len(warnings)} warnings: \n"\
            "{0}\n{1}\n".format("\n".join(errors), "\n".join(warnings))

