import os
import pytest

from .env import H2Conf


def mk_text_file(fpath: str, lines: int):
    t110 = ""
    for _ in range(11):
        t110 += "0123456789"
    with open(fpath, "w") as fd:
        for i in range(lines):
            fd.write("{0:015d}: ".format(i))  # total 128 bytes per line
            fd.write(t110)
            fd.write("\n")


class TestFiles:

    URI_PATHS = []

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        docs_a = os.path.join(env.server_docs_dir, "cgi/files")
        uris = []
        file_count = 32
        file_sizes = [1, 10, 100, 10000]
        for i in range(file_count):
            fsize = file_sizes[i % len(file_sizes)]
            if fsize is None:
                raise Exception("file sizes?: {0} {1}".format(i, fsize))
            fname = "{0}-{1}k.txt".format(i, fsize)
            mk_text_file(os.path.join(docs_a, fname), 8 * fsize)
            self.URI_PATHS.append(f"/files/{fname}")

        H2Conf(env).add_vhost_cgi(
            proxy_self=True, h2proxy_self=True
        ).add_vhost_test1(
            proxy_self=True, h2proxy_self=True
        ).install()
        assert env.apache_restart() == 0

    def test_h2_005_01(self, env):
        url = env.mkurl("https", "cgi", self.URI_PATHS[2])
        r = env.curl_get(url)
        assert r.response, r.stderr + r.stdout
        assert r.response["status"] == 200
