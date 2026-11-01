import logging
import os
import shutil
import sys
import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from pyhttpd.depends import apply_gate, strict_optional_enabled

from .md_env import MDTestEnv
from .md_acme import MDPebbleRunner, MDBoulderRunner


def pytest_report_header(config):
    env = MDTestEnv()
    return "mod_md: [apache: {aversion}({prefix}), mod_{ssl}, ACME server: {acme}]".format(
        prefix=env.prefix,
        aversion=env.get_httpd_version(),
        ssl=env.ssl_module,
        acme=env.acme_server,
    )


def pytest_collection_modifyitems(config, items):
    """Gate the tests that need the pebble ACME server on it being installed.

    The acme fixture starts 'pebble' and 'pebble-challtestsrv'. Without them
    every such test used to error in setup; it is a missing dependency, so
    skip (or fail under --strict-optional) before an httpd is started.
    """
    if MDTestEnv.get_acme_server() != 'pebble':
        return
    tools = ('pebble', 'pebble-challtestsrv')
    found = {tool: shutil.which(tool) for tool in tools}
    if all(found.values()):
        return
    missing = [(f"{', '.join(t for t in tools if not found[t])} (ACME test server)",
                "pebble ACME test server not installed",
                ", ".join(f"{t}: {found[t] or 'not on PATH'}" for t in tools))]
    strict = strict_optional_enabled(config)
    md_dir = os.path.dirname(os.path.abspath(__file__))
    for item in items:
        if str(item.path).startswith(md_dir) and 'acme' in item.fixturenames:
            apply_gate(item, missing, strict)


@pytest.fixture(scope="package")
def env(pytestconfig) -> MDTestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = MDTestEnv(pytestconfig=pytestconfig)
    # mod_md needs jansson and libcurl to be built; setup_httpd() raises if
    # the module it LoadModules is missing. Report the missing dependency.
    env.require(env.has_shared_module("md"), "mod_md was not built", dep="mod_md",
                detected=f"no mod_md.so in {env.libexec_dir}")
    env.setup_httpd()
    env.apache_access_log_clear()
    env.httpd_error_log.clear_log()
    yield env
    env.apache_stop()


@pytest.fixture(autouse=True, scope="package")
def _md_package_scope(env):
    env.httpd_error_log.add_ignored_lognos([
        "AH10085"   # There are no SSL certificates configured and no other module contributed any
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

