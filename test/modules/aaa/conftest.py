import logging
import os
import sys

import pytest

from .env import AAATestEnv
from pyhttpd.conf import HttpdConf

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))


def pytest_report_header(config, start_path):
    env = AAATestEnv()
    return f"mod_auth_digest [apache: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"


def _digest_dir(docs, path, extra_lines):
    lines = [
        f'<Directory "{docs}/digest/{path}">',
        '    AuthType Digest',
        f'    AuthName "{AAATestEnv.REALM}"',
    ]
    lines.extend(f"    {l}" for l in extra_lines)
    lines.append('    Require valid-user')
    lines.append('</Directory>')
    return lines


@pytest.fixture(scope="package")
def env(pytestconfig) -> AAATestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = AAATestEnv(pytestconfig=pytestconfig)
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()

    docs = env.server_docs_dir
    pwfile = env.digest_pwfile
    conf = HttpdConf(env)
    conf.add(_digest_dir(docs, "default", [
        'AuthDigestProvider file',
        f'AuthUserFile "{pwfile}"',
    ]))
    conf.add(_digest_dir(docs, "nccheck", [
        'AuthDigestProvider file',
        f'AuthUserFile "{pwfile}"',
        'AuthDigestNcCheck On',
    ]))
    conf.add(_digest_dir(docs, "shortlife", [
        'AuthDigestProvider file',
        f'AuthUserFile "{pwfile}"',
        'AuthDigestNonceLifetime 2',
    ]))
    conf.add(_digest_dir(docs, "neverexpire", [
        'AuthDigestProvider file',
        f'AuthUserFile "{pwfile}"',
        'AuthDigestNonceLifetime -1',
    ]))
    conf.add(_digest_dir(docs, "onetime", [
        'AuthDigestProvider file',
        f'AuthUserFile "{pwfile}"',
        'AuthDigestNonceLifetime 0',
    ]))
    conf.add(_digest_dir(docs, "domain", [
        'AuthDigestProvider file',
        f'AuthUserFile "{pwfile}"',
        'AuthDigestDomain "/digest/domain/" "https://mirror.example.org/other/"',
    ]))
    conf.add(_digest_dir(docs, "noprovider", [
        # AuthDigestProvider intentionally omitted: falls back to "file".
        f'AuthUserFile "{pwfile}"',
    ]))
    conf.install()
    assert env.apache_restart() == 0
    return env


@pytest.fixture(autouse=True, scope="package")
def _stop_package_scope(env):
    yield
    assert env.apache_stop() == 0
