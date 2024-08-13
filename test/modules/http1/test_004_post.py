import difflib
import email.parser
import inspect
import json
import os
import sys

import pytest

from .env import H1Conf


class TestPost:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TestPost._local_dir = os.path.dirname(inspect.getfile(TestPost))
        H1Conf(env).add_vhost_cgi().install()
        assert env.apache_restart() == 0

    def local_src(self, fname):
        return os.path.join(TestPost._local_dir, fname)

    # upload and GET again using curl, compare to original content
    def curl_upload_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/upload.py")
        fpath = os.path.join(env.gen_dir, fname)
        r = env.curl_upload(url, fpath, options=options)
        assert r.exit_code == 0, f"{r}"
        assert 200 <= r.response["status"] < 300

        r2 = env.curl_get(r.response["header"]["location"])
        assert r2.exit_code == 0
        assert r2.response["status"] == 200
        with open(self.local_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r2.response["body"]
        return r

    def test_h1_004_01(self, env):
        self.curl_upload_and_verify(env, "data-1k", ["-vvv"])

    def test_h1_004_02(self, env):
        self.curl_upload_and_verify(env, "data-10k", [])

    def test_h1_004_03(self, env):
        self.curl_upload_and_verify(env, "data-100k", [])

    def test_h1_004_04(self, env):
        self.curl_upload_and_verify(env, "data-1m", [])

    def test_h1_004_05(self, env):
        r = self.curl_upload_and_verify(env, "data-1k", ["-vvv", "-H", "Expect: 100-continue"])
