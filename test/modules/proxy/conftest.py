import logging
import os
import sys
import pytest

from .env import ProxyTestEnv

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))


def pytest_report_header(config, startdir):
    env = ProxyTestEnv()
    return "mod_proxy: [apache: {aversion}({prefix})]".format(
        prefix=env.prefix,
        aversion=env.get_httpd_version(),
    )


@pytest.fixture(scope="package")
def env(pytestconfig) -> ProxyTestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = ProxyTestEnv(pytestconfig=pytestconfig)
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    return env
