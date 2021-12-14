import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from pyhttpd.env import HttpdTestEnv

def pytest_report_header(config, startdir):
    env = HttpdTestEnv()
    return f"[apache httpd: {env.get_httpd_version()}, mpm: {env.mpm_module}, {env.prefix}]"


