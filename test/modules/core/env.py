import inspect
import logging
import os

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class CoreTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None, setup_dirs=True):
        super().__init__(pytestconfig=pytestconfig,
                         local_dir=os.path.dirname(inspect.getfile(CoreTestEnv)))
        if setup_dirs:
            self._setup = HttpdTestSetup(env=self)
            self._setup.make()
            self.issue_certs()
