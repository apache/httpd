import os
import pytest

from .env import H2Conf, H2TestEnv


def mk_text_file(fpath: str, lines: int):
    t110 = ""
    for _ in range(11):
        t110 += "0123456789"
    with open(fpath, "w") as fd:
        for i in range(lines):
            fd.write("{0:015d}: ".format(i))  # total 128 bytes per line
            fd.write(t110)
            fd.write("\n")


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestFrameLengths:

    URI_PATHS = []

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        docs_a = os.path.join(env.server_docs_dir, "cgi/files")
        for fsize in [10, 100]:
            fname = f'0-{fsize}k.txt'
            mk_text_file(os.path.join(docs_a, fname), 8 * fsize)
            self.URI_PATHS.append(f"/files/{fname}")

    @pytest.mark.parametrize("data_frame_len", [
        99, 1024, 8192
    ])
    def test_h2_107_01(self, env, data_frame_len):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                f'H2MaxDataFrameLen {data_frame_len}',
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        for p in self.URI_PATHS:
            url = env.mkurl("https", "cgi", p)
            r = env.nghttp().get(url, options=[
                '--header=Accept-Encoding: none',
            ])
            assert r.response["status"] == 200
            assert len(r.results["data_lengths"]) > 0, f'{r}'
            too_large = [ x for x in r.results["data_lengths"] if x > data_frame_len]
            assert len(too_large) == 0, f'{p}: {r.results["data_lengths"]}'
