import os

import pytest

from .env import H1Conf

# A static resource of a known length, so that the complete length of the
# representation can be checked in the Content-Range of the responses.
DATA = "0123456789" * 10
LENGTH = len(DATA)


class TestRanges:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        docs = os.path.join(env.gen_dir, "apache", "htdocs", "test1")
        with open(os.path.join(docs, "range-100"), "wb") as fd:
            fd.write(DATA.encode())
        H1Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0

    def get(self, env, range_value):
        url = env.mkurl("http", "test1", "/range-100")
        return env.curl_get(url, options=["-H", f"Range: {range_value}"])

    # a satisfiable range is answered with 206 and its Content-Range
    def test_h1_008_01(self, env):
        r = self.get(env, "bytes=10-19")
        assert r.response["status"] == 206
        assert r.response["header"]["content-range"] == f"bytes 10-19/{LENGTH}"
        assert r.response["body"].decode() == DATA[10:20]

    # RFC 9110, 15.5.17: a 416 SHOULD carry the unsatisfied range with the
    # complete length of the representation
    @pytest.mark.parametrize("range_value", [
        "bytes=1000-",
        "bytes=1000-2000",
        f"bytes={LENGTH}-",
        "bytes=1000-2000,3000-",
    ])
    def test_h1_008_02(self, env, range_value):
        r = self.get(env, range_value)
        assert r.response["status"] == 416
        assert r.response["header"].get("content-range") == f"bytes */{LENGTH}"

    # a Range which is not valid is ignored, as it was before
    @pytest.mark.parametrize("range_value", [
        "bytes=abc",
        "bytes=20-10",
        "bytes=-",
    ])
    def test_h1_008_03(self, env, range_value):
        r = self.get(env, range_value)
        assert r.response["status"] == 200
        assert "content-range" not in r.response["header"]
        assert r.response["body"].decode() == DATA
