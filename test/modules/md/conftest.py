import logging
import os
import sys
import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from .md_conf import HttpdConf
from .md_env import MDTestEnv
from .md_acme import MDPebbleRunner, MDBoulderRunner


def pytest_report_header(config, startdir):
    env = MDTestEnv()
    return "mod_md: [apache: {aversion}({prefix}), mod_{ssl}, ACME server: {acme}]".format(
        prefix=env.prefix,
        aversion=env.get_httpd_version(),
        ssl=env.ssl_module,
        acme=env.acme_server,
    )


@pytest.fixture(scope="package")
def env(pytestconfig) -> MDTestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = MDTestEnv(pytestconfig=pytestconfig)
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    yield env
    env.apache_stop()


@pytest.fixture(autouse=True, scope="package")
def _md_package_scope(env):
    env.httpd_error_log.add_ignored_lognos([
        "AH10085",   # There are no SSL certificates configured and no other module contributed any
        "AH10045",   # No VirtualHost matches Managed Domain
        "AH10105",   # MDomain does not match any VirtualHost with 'SSLEngine on'
    ])


@pytest.fixture(scope="package")
def acme(env):
    acme_server = None
    if env.acme_server == 'pebble':
        acme_server = MDPebbleRunner(env, configs={
            'default': os.path.join(env.gen_dir, 'pebble/pebble.json'),
            'eab': os.path.join(env.gen_dir, 'pebble/pebble-eab.json'),
        })
    elif env.acme_server == 'boulder':
        acme_server = MDBoulderRunner(env)
    yield acme_server
    if acme_server is not None:
        acme_server.stop()

