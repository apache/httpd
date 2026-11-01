"""Fixtures shared by every test package below modules/.

They act on the package-scoped ``env`` that each package's conftest defines,
so they live here rather than in the root conftest: tests outside modules/
(pytest_suite) have no ``env``.
"""
import socket
import sys
import warnings

import pytest


def _has_ipv6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(('::1', 0))
        s.close()
        return True
    except (socket.error, OSError):
        return False


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
    if sys.platform == "win32":
        env.httpd_error_log.add_ignored_lognos([
            "AH00098",
            "AH10373",
            "AH00336",
            "AH00337",
            "AH00338",
            "AH00341",
            "AH02322",
        ])
    if sys.platform == "win32" and _has_ipv6():
        env.httpd_error_log.add_ignored_lognos(["AH00332"])
    yield
    assert env.apache_stop() == 0
    env.check_error_log()
    archive_dir = request.config.getoption("--archive")
    if archive_dir == "":
        warnings.warn("--archive option was empty, skipping archiving")
    if archive_dir:
        fspath = str(request.fspath)
        if 'modules/' in fspath:
            package_name = fspath.split('modules/')[1].split('/')[0]
            env.archive_logs(package_name, archive_dir)
