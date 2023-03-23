import logging
import os
import re
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
    return env


@pytest.fixture(autouse=True, scope="package")
def _session_scope(env):
    # we'd like to check the httpd error logs after the test suite has
    # run to catch anything unusual. For this, we setup the ignore list
    # of errors and warnings that we do expect.
    env.httpd_error_log.set_ignored_lognos([
        'AH10040',  # mod_md, setup complain
        'AH10045',  # mod_md complains that there is no vhost for an MDomain
        'AH10056',  # mod_md, invalid params
        'AH10105',  # mod_md does not find a vhost with SSL enabled for an MDomain
        'AH10085',  # mod_ssl complains about fallback certificates
        'AH01909',  # mod_ssl, cert alt name complains
        'AH10170',  # mod_md, wrong config, tested
        'AH10171',  # mod_md, wrong config, tested
        'AH10373',  # SSL errors on uncompleted handshakes
        'AH10398',  # test on global store lock
    ])

    env.httpd_error_log.add_ignored_patterns([
        re.compile(r'.*urn:ietf:params:acme:error:.*'),
        re.compile(r'.*None of the ACME challenge methods configured for this domain are suitable.*'),
        re.compile(r'.*problem\[(challenge-mismatch|challenge-setup-failure|apache:eab-hmac-invalid)].*'),
        re.compile(r'.*CA considers answer to challenge invalid.].*'),
        re.compile(r'.*problem\[urn:org:apache:httpd:log:AH\d+:].*'),
        re.compile(r'.*Unsuccessful in contacting ACME server at :*'),
        re.compile(r'.*test-md-720-002-\S+.org: dns-01 setup command failed .*'),
        re.compile(r'.*AH\d*: unable to obtain global registry lock, .*'),
    ])
    if env.lacks_ocsp():
        env.httpd_error_log.add_ignored_patterns([
            re.compile(r'.*certificate with serial \S+ has no OCSP responder URL.*'),
        ])
    yield
    assert env.apache_stop() == 0
    errors, warnings = env.httpd_error_log.get_missed()
    assert (len(errors), len(warnings)) == (0, 0),\
            f"apache logged {len(errors)} errors and {len(warnings)} warnings: \n"\
            "{0}\n{1}\n".format("\n".join(errors), "\n".join(warnings))


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

