import logging
import os
import sys

import pytest

from .env import SessionTestEnv
from pyhttpd.conf import HttpdConf

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))


def pytest_report_header(config, start_path):
    env = SessionTestEnv()
    return f"mod_session_dbd [apache: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"


@pytest.fixture(scope="package")
def env(pytestconfig) -> SessionTestEnv:
    logging.getLogger('').setLevel(level=logging.INFO)
    env = SessionTestEnv(pytestconfig=pytestconfig)
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()

    docs = env.server_docs_dir
    conf = HttpdConf(env)
    # An anonymous, DBD-backed session (mirrors the reporter's own config
    # in BZ 68473), served from the default docroot so that a plain GET
    # already exercises session_dbd_save() on every response.
    conf.add([
        'DBDriver sqlite3',
        f'DBDParams "{env.dbd_file}"',
        'DBDPrepareSQL "SELECT value FROM sessions WHERE key = %s '
        'AND (expiry = 0 OR expiry > %lld)" selectsession',
        'DBDPrepareSQL "DELETE FROM sessions WHERE key = %s" deletesession',
        'DBDPrepareSQL "INSERT INTO sessions (value, expiry, key) '
        'VALUES (%s, %lld, %s)" insertsession',
        'DBDPrepareSQL "UPDATE sessions SET value = %s, expiry = %lld, '
        'key = %s WHERE key = %s" updatesession',
        f'<Directory "{docs}">',
        '    Session On',
        '    SessionMaxAge 300',
        '    SessionDBDCookieName session path=/',
        '    SessionDBDSelectLabel selectsession',
        '    SessionDBDInsertLabel insertsession',
        '    SessionDBDUpdateLabel updatesession',
        '    SessionDBDDeleteLabel deletesession',
        '</Directory>',
    ])
    conf.install()
    assert env.apache_restart() == 0
    return env


@pytest.fixture(autouse=True, scope="package")
def _stop_package_scope(env):
    yield
    assert env.apache_stop() == 0
