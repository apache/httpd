import sys
import os
import warnings

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
    parser.addoption("--archive", action="store", default=None,
                     help='Archive the server directory after each test package to the specified folder')


def pytest_generate_tests(metafunc):
    if "repeat" in metafunc.fixturenames:
        count = int(metafunc.config.getoption("repeat"))
        metafunc.fixturenames.append('tmp_ct')
        metafunc.parametrize('repeat', range(count))


@pytest.fixture(autouse=True, scope="function")
def _function_scope(env, request):
    env.set_current_test_name(request.node.name)
    yield
    env.check_error_log()
    archive_dir = request.config.getoption("--archive")
    if archive_dir:
        fspath = str(request.fspath)
        if 'modules/' in fspath:
            package_name = fspath.split('modules/')[1].split('/')[0]
            env.archive_test_conf(request.node.name, package_name, archive_dir)
    env.set_current_test_name(None)


@pytest.fixture(autouse=True, scope="module")
def _module_scope(env):
    yield
    env.check_error_log()


@pytest.fixture(autouse=True, scope="package")
def _package_scope(env, request):
    env.httpd_error_log.clear_ignored_matches()
    env.httpd_error_log.clear_ignored_lognos()
    yield
    assert env.apache_stop() == 0
    env.check_error_log()

    archive_dir = request.config.getoption("--archive")
    if archive_dir == "":
        warnings.warn("--archive option was empty, skipping archiving")
    if archive_dir:
        fspath = str(request.fspath)
        parts = fspath.split('modules/')
        package_name = parts[1].split('/')[0]
        env.archive_logs(package_name, archive_dir)
