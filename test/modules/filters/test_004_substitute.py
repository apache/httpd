import os

import pytest

from pyhttpd.conf import HttpdConf

# Basic mod_substitute body-replacement tests.
class TestSubstitute:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        hello_dir = os.path.join(doc_dir, "hello")
        os.makedirs(hello_dir, exist_ok=True)
        with open(os.path.join(hello_dir, "world.txt"), "w") as f:
            f.write("Hello World!")

    # With a Substitute directive active, "World" is replaced by "Folks".
    def test_filters_004_01(self, env):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            <Location "/hello/">
                AddOutputFilter SUBSTITUTE txt
                Substitute "s/World/Folks/"
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("http", "test1", "/hello/world.txt")
        r = env.curl_get(url)
        assert r.response, "no response"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "Hello Folks!" in body, f"expected substitution, got: {body!r}"
        assert "Hello World!" not in body, \
            f"original text should not appear after substitution: {body!r}"

    # Without the Substitute directive the file is served unmodified.
    def test_filters_004_02(self, env):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": "",
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("http", "test1", "/hello/world.txt")
        r = env.curl_get(url)
        assert r.response, "no response"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert body == "Hello World!", f"expected original content, got: {body!r}"
