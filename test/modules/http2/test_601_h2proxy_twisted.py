import json
import logging
import os
import pytest

from .env import H2Conf, H2TestEnv


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestH2ProxyTwisted:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_cgi(proxy_self=True, h2proxy_self=True).install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m",
    ])
    def test_h2_601_01_echo_uploads(self, env, name):
        fpath = os.path.join(env.gen_dir, name)
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/echo")
        r = env.curl_upload(url, fpath, options=[])
        assert r.exit_code == 0
        assert 200 <= r.response["status"] < 300
        # we POST a form, so echoed input is larger than the file itself
        assert len(r.response["body"]) > os.path.getsize(fpath)

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m",
    ])
    def test_h2_601_02_echo_delayed(self, env, name):
        fpath = os.path.join(env.gen_dir, name)
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/echo?chunk_delay=10ms")
        r = env.curl_upload(url, fpath, options=[])
        assert r.exit_code == 0
        assert 200 <= r.response["status"] < 300
        # we POST a form, so echoed input is larger than the file itself
        assert len(r.response["body"]) > os.path.getsize(fpath)

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m",
    ])
    def test_h2_601_03_echo_fail_early(self, env, name):
        fpath = os.path.join(env.gen_dir, name)
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/echo?fail_after=512")
        r = env.curl_upload(url, fpath, options=[])
        # 92 is curl's CURLE_HTTP2_STREAM
        assert r.exit_code == 92 or r.response["status"] == 502

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m",
    ])
    def test_h2_601_04_echo_fail_late(self, env, name):
        fpath = os.path.join(env.gen_dir, name)
        url = env.mkurl("https", "cgi", f"/h2proxy/h2test/echo?fail_after={os.path.getsize(fpath)}")
        r = env.curl_upload(url, fpath, options=[])
        # 92 is curl's CURLE_HTTP2_STREAM
        assert r.exit_code == 92 or r.response["status"] == 502

    def test_h2_601_05_echo_fail_many(self, env):
        count = 200
        fpath = os.path.join(env.gen_dir, "data-100k")
        args = [env.curl, '--parallel', '--parallel-max', '20']
        for i in range(count):
            if i > 0:
                args.append('--next')
            url = env.mkurl("https", "cgi", f"/h2proxy/h2test/echo?id={i}&fail_after={os.path.getsize(fpath)}")
            args.extend(env.curl_resolve_args(url=url))
            args.extend([
                '-o', '/dev/null', '-w', '%{json}\\n', '--form', f'file=@{fpath}', url
            ])
        log.error(f'run: {args}')
        r = env.run(args)
        stats = []
        for line in r.stdout.splitlines():
            stats.append(json.loads(line))
        assert len(stats) == count
        for st in stats:
            assert st['exitcode'] == 92 or st['http_code'] == 502, f'unexpected: {st}'
