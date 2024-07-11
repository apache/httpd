import inspect
import logging
import os
import shutil
import subprocess
import time
from datetime import timedelta, datetime
from typing import Tuple, List
import packaging.version

import pytest
import websockets
from pyhttpd.result import ExecResult
from pyhttpd.ws_util import WsFrameReader, WsFrame

from .env import H2Conf, H2TestEnv


log = logging.getLogger(__name__)

ws_version = packaging.version.parse(websockets.version.version)
ws_version_min = packaging.version.Version('10.4')


def ws_run(env: H2TestEnv, path, authority=None, do_input=None, inbytes=None,
           send_close=True, timeout=5, scenario='ws-stdin',
           wait_close: float = 0.0) -> Tuple[ExecResult, List[str], List[WsFrame]]:
    """ Run the h2ws test client in various scenarios with given input and
        timings.
    :param env: the test environment
    :param path: the path on the Apache server to CONNECt to
    :param authority: the host:port to use as
    :param do_input: a Callable for sending input to h2ws
    :param inbytes: fixed bytes to send to h2ws, unless do_input is given
    :param send_close: send a CLOSE WebSockets frame at the end
    :param timeout: timeout for waiting on h2ws to finish
    :param scenario: name of scenario h2ws should run in
    :param wait_close: time to wait before closing input
    :return: ExecResult with exit_code/stdout/stderr of run
    """
    h2ws = os.path.join(env.clients_dir, 'h2ws')
    if not os.path.exists(h2ws):
        pytest.fail(f'test client not build: {h2ws}')
    if authority is None:
        authority = f'cgi.{env.http_tld}:{env.http_port}'
    args = [
        h2ws, '-vv', '-c', f'localhost:{env.http_port}',
        f'ws://{authority}{path}',
        scenario
    ]
    # we write all output to files, because we manipulate input timings
    # and would run in deadlock situations with h2ws blocking operations
    # because its output is not consumed
    start = datetime.now()
    with open(f'{env.gen_dir}/h2ws.stdout', 'w') as fdout:
        with open(f'{env.gen_dir}/h2ws.stderr', 'w') as fderr:
            proc = subprocess.Popen(args=args, stdin=subprocess.PIPE,
                                    stdout=fdout, stderr=fderr)
            if do_input is not None:
                do_input(proc)
            elif inbytes is not None:
                proc.stdin.write(inbytes)
                proc.stdin.flush()

            if wait_close > 0:
                time.sleep(wait_close)
            try:
                inbytes = WsFrame.client_close(code=1000).to_network() if send_close else None
                proc.communicate(input=inbytes, timeout=timeout)
            except subprocess.TimeoutExpired:
                log.error(f'ws_run: timeout expired')
                proc.kill()
                proc.communicate(timeout=timeout)
    end = datetime.now()
    lines = open(f'{env.gen_dir}/h2ws.stdout').read().splitlines()
    infos = [line for line in lines if line.startswith('[1] ')]
    hex_content = ' '.join([line for line in lines if not line.startswith('[1] ')])
    if len(infos) > 0 and infos[0] == '[1] :status: 200':
        frames = WsFrameReader.parse(bytearray.fromhex(hex_content))
    else:
        frames = bytearray.fromhex(hex_content)
    return ExecResult(args=args, exit_code=proc.returncode,
                      stdout=b'', stderr=b'', duration=end - start), infos, frames


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
@pytest.mark.skipif(condition=not H2TestEnv().httpd_is_at_least("2.4.60"),
                    reason=f'need at least httpd 2.4.60 for this')
@pytest.mark.skipif(condition=ws_version < ws_version_min,
                    reason=f'websockets is {ws_version}, need at least {ws_version_min}')
class TestWebSockets:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # Apache config that CONNECT proxies a WebSocket server for paths starting
        # with '/ws/'
        # The WebSocket server is started in pytest fixture 'ws_server' below.
        conf = H2Conf(env, extras={
            'base': [
                'Timeout 1',
            ],
            f'cgi.{env.http_tld}': [
              f'  H2WebSockets on',
              f'  ProxyPass /ws/ http://127.0.0.1:{env.ws_port}/ \\',
              f'           upgrade=websocket timeout=10',
              f'  ReadBufferSize 65535'
            ]
        })
        conf.add_vhost_cgi(proxy_self=True, h2proxy_self=True).install()
        conf.add_vhost_test1(proxy_self=True, h2proxy_self=True).install()
        assert env.apache_restart() == 0

    def ws_check_alive(self, env, timeout=5):
        url = f'http://localhost:{env.ws_port}/'
        end = datetime.now() + timedelta(seconds=timeout)
        while datetime.now() < end:
            r = env.curl_get(url, 5)
            if r.exit_code == 0:
                return True
            time.sleep(.1)
        return False

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def _rmrf(self, path):
        if os.path.exists(path):
            return shutil.rmtree(path)

    @pytest.fixture(autouse=True, scope='class')
    def ws_server(self, env):
        # Run our python websockets server that has some special behaviour
        # for the different path to CONNECT to.
        run_dir = os.path.join(env.gen_dir, 'ws-server')
        err_file = os.path.join(run_dir, 'stderr')
        self._rmrf(run_dir)
        self._mkpath(run_dir)
        with open(err_file, 'w') as cerr:
            cmd = os.path.join(os.path.dirname(inspect.getfile(TestWebSockets)),
                               'ws_server.py')
            args = ['python3', cmd, '--port', str(env.ws_port)]
            p = subprocess.Popen(args=args, cwd=run_dir, stderr=cerr,
                                 stdout=cerr)
            if not self.ws_check_alive(env):
                p.kill()
                p.wait()
                pytest.fail(f'ws_server did not start. stderr={open(err_file).readlines()}')
            yield
            p.terminate()

    # CONNECT with invalid :protocol header, must fail
    def test_h2_800_01_fail_proto(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', scenario='fail-proto')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 501', '[1] EOF'], f'{r}'

    # a correct CONNECT, send CLOSE, expect CLOSE, basic success
    def test_h2_800_02_ws_empty(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) == 1, f'{frames}'
        assert frames[0].opcode == WsFrame.CLOSE, f'{frames}'

    # CONNECT to a URL path that does not exist on the server
    def test_h2_800_03_not_found(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/does-not-exist')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 404', '[1] EOF'] or infos == ['[1] :status: 404', '[1] EOF', '[1] RST'], f'{r}'

    # CONNECT to a URL path that is a normal HTTP file resource
    # we do not want to receive the body of that
    def test_h2_800_04_non_ws_resource(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/alive.json')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 502', '[1] EOF'] or infos == ['[1] :status: 502', '[1] EOF', '[1] RST'], f'{r}'
        assert frames == b''

    # CONNECT to a URL path that sends a delayed HTTP response body
    # we do not want to receive the body of that
    def test_h2_800_05_non_ws_delay_resource(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/h2test/error?body_delay=100ms')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 502', '[1] EOF'] or infos == ['[1] :status: 502', '[1] EOF', '[1] RST'], f'{r}'
        assert frames == b''

    # CONNECT missing the sec-webSocket-version header
    def test_h2_800_06_miss_version(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', scenario='miss-version')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 400', '[1] EOF'], f'{r}'

    # CONNECT missing the :path header
    def test_h2_800_07_miss_path(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', scenario='miss-path')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] RST'], f'{r}'

    # CONNECT missing the :scheme header
    def test_h2_800_08_miss_scheme(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', scenario='miss-scheme')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] RST'], f'{r}'

    # CONNECT missing the :authority header
    def test_h2_800_09a_miss_authority(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', scenario='miss-authority')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] RST'], f'{r}'

    # CONNECT to authority with disabled websockets
    def test_h2_800_09b_unsupported(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/',
                                  authority=f'test1.{env.http_tld}:{env.http_port}')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 501', '[1] EOF'] or infos == ['[1] :status: 501', '[1] EOF', '[1] RST'], f'{r}'

    # CONNECT and exchange a PING
    def test_h2_800_10_ws_ping(self, env: H2TestEnv, ws_server):
        ping = WsFrame.client_ping(b'12345')
        r, infos, frames = ws_run(env, path='/ws/echo/', inbytes=ping.to_network())
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) == 2, f'{frames}'
        assert frames[0].opcode == WsFrame.PONG, f'{frames}'
        assert frames[0].data == ping.data, f'{frames}'
        assert frames[1].opcode == WsFrame.CLOSE, f'{frames}'

    # CONNECT and send several PINGs with a delay of 200ms
    def test_h2_800_11_ws_timed_pings(self, env: H2TestEnv, ws_server):
        frame_count = 5
        ping = WsFrame.client_ping(b'12345')

        def do_send(proc):
            for _ in range(frame_count):
                try:
                    proc.stdin.write(ping.to_network())
                    proc.stdin.flush()
                    proc.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    pass

        r, infos, frames = ws_run(env, path='/ws/echo/', do_input=do_send)
        assert r.exit_code == 0
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) == frame_count + 1, f'{frames}'
        assert frames[-1].opcode == WsFrame.CLOSE, f'{frames}'
        for i in range(frame_count):
            assert frames[i].opcode == WsFrame.PONG, f'{frames}'
            assert frames[i].data == ping.data, f'{frames}'

    # CONNECT to path that closes immediately
    def test_h2_800_12_ws_unknown(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/unknown')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) == 1, f'{frames}'
        # expect a CLOSE with code=4999, reason='path unknown'
        assert frames[0].opcode == WsFrame.CLOSE, f'{frames}'
        assert frames[0].data[2:].decode() == 'path unknown', f'{frames}'

    # CONNECT to a path that sends us 1 TEXT frame
    def test_h2_800_13_ws_text(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/text/')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) == 2, f'{frames}'
        assert frames[0].opcode == WsFrame.TEXT, f'{frames}'
        assert frames[0].data.decode() == 'hello!', f'{frames}'
        assert frames[1].opcode == WsFrame.CLOSE, f'{frames}'

    # CONNECT to a path that sends us a named file in BINARY frames
    @pytest.mark.parametrize("fname,flen", [
        ("data-1k", 1000),
        ("data-10k", 10000),
        ("data-100k", 100*1000),
        ("data-1m", 1000*1000),
    ])
    def test_h2_800_14_ws_file(self, env: H2TestEnv, ws_server, fname, flen):
        r, infos, frames = ws_run(env, path=f'/ws/file/{fname}', wait_close=0.5)
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) > 0
        total_len = sum([f.data_len for f in frames if f.opcode == WsFrame.BINARY])
        assert total_len == flen, f'{frames}'

    # CONNECT to path with 1MB file and trigger varying BINARY frame lengths
    @pytest.mark.parametrize("frame_len", [
        1000 * 1024,
        100 * 1024,
        10 * 1024,
        1 * 1024,
        512,
    ])
    def test_h2_800_15_ws_frame_len(self, env: H2TestEnv, ws_server, frame_len):
        fname = "data-1m"
        flen = 1000*1000
        r, infos, frames = ws_run(env, path=f'/ws/file/{fname}/{frame_len}', wait_close=0.5)
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) > 0
        total_len = sum([f.data_len for f in frames if f.opcode == WsFrame.BINARY])
        assert total_len == flen, f'{frames}'

    # CONNECT to path with 1MB file and trigger delays between BINARY frame writes
    @pytest.mark.parametrize("frame_delay", [
        1,
        10,
        50,
        100,
    ])
    def test_h2_800_16_ws_frame_delay(self, env: H2TestEnv, ws_server, frame_delay):
        fname = "data-1m"
        flen = 1000*1000
        # adjust frame_len to allow for 1 second overall duration
        frame_len = int(flen / (1000 / frame_delay))
        r, infos, frames = ws_run(env, path=f'/ws/file/{fname}/{frame_len}/{frame_delay}',
                                  wait_close=1.5)
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) > 0
        total_len = sum([f.data_len for f in frames if f.opcode == WsFrame.BINARY])
        assert total_len == flen, f'{frames}\n{r}'

    # CONNECT to path with 1MB file and trigger delays between BINARY frame writes
    @pytest.mark.parametrize("frame_len", [
        64 * 1024,
        16 * 1024,
        1 * 1024,
    ])
    def test_h2_800_17_ws_throughput(self, env: H2TestEnv, ws_server, frame_len):
        fname = "data-1m"
        flen = 1000*1000
        ncount = 5
        r, infos, frames = ws_run(env, path=f'/ws/file/{fname}/{frame_len}/0/{ncount}',
                                  wait_close=0.1, send_close=False, timeout=30)
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) > 0
        total_len = sum([f.data_len for f in frames if f.opcode == WsFrame.BINARY])
        assert total_len == ncount * flen, f'{frames}\n{r}'
        # to see these logged, invoke: `pytest -o log_cli=true`
        log.info(f'throughput (frame-len={frame_len}): "'
                 f'"{(total_len / (1024*1024)) / r.duration.total_seconds():0.2f} MB/s')

    # Check that the tunnel timeout is observed, e.g. the longer holds and
    # the 1sec cleint conn timeout does not trigger
    def test_h2_800_18_timeout(self, env: H2TestEnv, ws_server):
        fname = "data-10k"
        frame_delay = 1500
        flen = 10*1000
        frame_len = 8192
        # adjust frame_len to allow for 1 second overall duration
        r, infos, frames = ws_run(env, path=f'/ws/file/{fname}/{frame_len}/{frame_delay}',
                                  wait_close=2)
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) > 0
        total_len = sum([f.data_len for f in frames if f.opcode == WsFrame.BINARY])
        assert total_len == flen, f'{frames}\n{r}'

