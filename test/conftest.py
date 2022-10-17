import sys
import os

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from pyhttpd.env import HttpdTestEnv

def pytest_report_header(config, startdir):
    env = HttpdTestEnv()
    return f"[apache httpd: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"

def pytest_addoption(parser):
    parser.addoption("--repeat", action="store", type=int, default=1,
                     help='Number of times to repeat each test')
    parser.addoption("--all", action="store_true")


def pytest_generate_tests(metafunc):
    if "repeat" in metafunc.fixturenames:
        count = int(metafunc.config.getoption("repeat"))
        metafunc.fixturenames.append('tmp_ct')
        metafunc.parametrize('repeat', range(count))

@pytest.fixture(autouse=True, scope="function")
def _function_scope(env, request):
    env.set_current_test_name(request.node.name)
    yield
    env.set_current_test_name(None)

