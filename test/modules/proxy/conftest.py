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


@pytest.fixture(autouse=True, scope="package")
def _session_scope(env):
    # we'd like to check the httpd error logs after the test suite has
    # run to catch anything unusual. For this, we setup the ignore list
    # of errors and warnings that we do expect.
    env.httpd_error_log.set_ignored_lognos([
        'AH01144',  # No protocol handler was valid for the URL
    ])

    env.httpd_error_log.add_ignored_patterns([
        #re.compile(r'.*urn:ietf:params:acme:error:.*'),
    ])
    yield
    assert env.apache_stop() == 0
    errors, warnings = env.httpd_error_log.get_missed()
    assert (len(errors), len(warnings)) == (0, 0),\
            f"apache logged {len(errors)} errors and {len(warnings)} warnings: \n"\
            "{0}\n{1}\n".format("\n".join(errors), "\n".join(warnings))
