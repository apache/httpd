import logging
import os

import pytest

from h2_certs import CertificateSpec, H2TestCA
from h2_env import H2TestEnv


class Dummy:
    pass


def pytest_report_header(config, startdir):
    env = H2TestEnv()
    return "mod_h2 [apache: {aversion}({prefix}), mpm: {mpm}]".format(
        prefix=env.prefix,
        aversion=env.get_httpd_version(),
        mpm=env.mpm_type
    )


@pytest.fixture(scope="session")
def env(pytestconfig) -> H2TestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = H2TestEnv(pytestconfig=pytestconfig)
    env.apache_error_log_clear()
    cert_specs = [
        CertificateSpec(domains=env.domains, key_type='rsa4096'),
        CertificateSpec(domains=env.domains_noh2, key_type='rsa2048'),
    ]
    ca = H2TestCA.create_root(name=env.http_tld,
                              store_dir=os.path.join(env.server_dir, 'ca'), key_type="rsa4096")
    ca.issue_certs(cert_specs)
    env.set_ca(ca)
    return env


@pytest.fixture(autouse=True, scope="session")
def _session_scope(env):
    yield
    assert env.apache_stop() == 0
    errors, warnings = env.apache_errors_and_warnings()
    assert (len(errors), len(warnings)) == (0, 0),\
            f"apache logged {len(errors)} errors and {len(warnings)} warnings: \n"\
            "{0}\n{1}\n".format("\n".join(errors), "\n".join(warnings))

