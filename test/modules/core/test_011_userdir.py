import os
import pytest

from pyhttpd.conf import HttpdConf


class TestUserDir:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # Create userdir content that will be served for any ~user request.
        # Using UserDir with an absolute path makes every /~user/path resolve
        # to {absolute_path}/path, avoiding the need for real system users.
        userdir_base = os.path.join(env.server_dir, "htdocs", "userdir")
        hello_dir = os.path.join(userdir_base, "anyuser", "hello")
        os.makedirs(hello_dir, exist_ok=True)
        with open(os.path.join(hello_dir, "world.txt"), "w") as f:
            f.write("Hello World!")

        conf = HttpdConf(env, extras={
            'base': f"""
        UserDir "{userdir_base}"

        <Directory "{userdir_base}">
            AllowOverride None
            Require all granted
        </Directory>
        """
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # UserDir with absolute path: /~anyuser/hello/world.txt serves from
    # the configured directory regardless of the username
    def test_core_011_01(self, env):
        url = env.mkurl("http", "test1", "/~anyuser/hello/world.txt")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "Hello World!" in body
