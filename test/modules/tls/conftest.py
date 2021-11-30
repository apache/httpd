import logging
import os
import sys
import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from .env import TlsTestEnv


def pytest_report_header(config, startdir):
    _x = config
    _x = startdir
    env = TlsTestEnv()
    return "mod_tls [apache: {aversion}({prefix})]".format(
        prefix=env.prefix,
        aversion=env.get_httpd_version()
    )


@pytest.fixture(scope="package")
def env(pytestconfig) -> TlsTestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = TlsTestEnv(pytestconfig=pytestconfig)
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    return env


@pytest.fixture(autouse=True, scope="package")
def _session_scope(env):
    yield
    assert env.apache_stop() == 0
