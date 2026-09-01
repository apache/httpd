import logging
import os
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '../../..'))

from .env import SystemdTestEnv


def pytest_report_header(config, start_path):
    env = SystemdTestEnv()
    return f"mod_systemd [apache: {env.get_httpd_version()}, " \
           f"mpm: {env.mpm_module}, {env.prefix}]"


@pytest.fixture(scope="package")
def env(pytestconfig) -> SystemdTestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = SystemdTestEnv(pytestconfig=pytestconfig)
    if not env.has_systemd_module:
        pytest.skip("mod_systemd is not built, configure with --enable-systemd")
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    env.start_notify_listener()
    yield env
    env.stop_notify_listener()


@pytest.fixture(autouse=True, scope="package")
def _stop_package_scope(env):
    yield
    assert env.apache_stop() == 0
