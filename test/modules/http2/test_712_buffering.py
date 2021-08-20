import datetime
import re
import sys
import time
import subprocess

from datetime import timedelta
from threading import Thread

import pytest

from h2_conf import HttpdConf


class CurlPiper:

    def __init__(self, url: str):
        self.url = url
        self.proc = None
        self.args = None
        self.headerfile = None
        self._stderr = []
        self._stdout = []
        self.stdout_thread = None
        self.stderr_thread = None

    def start(self, env):
        self.args, self.headerfile = env.curl_complete_args(self.url, timeout=5, options=[
            "-T", "-", "-X", "POST", "--trace-ascii", "%", "--trace-time"])
        sys.stderr.write("starting: {0}\n".format(self.args))
        self.proc = subprocess.Popen(self.args, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     bufsize=0)

        def read_output(fh, buffer):
            while True:
                chunk = fh.read()
                if not chunk:
                    break
                buffer.append(chunk.decode())

        # collect all stdout and stderr until we are done
        # use separate threads to not block ourself
        self._stderr = []
        self._stdout = []
        if self.proc.stderr:
            self.stderr_thread = Thread(target=read_output, args=(self.proc.stderr, self._stderr))
            self.stderr_thread.start()
        if self.proc.stdout:
            self.stdout_thread = Thread(target=read_output, args=(self.proc.stdout, self._stdout))
            self.stdout_thread.start()
        return self.proc

    def send(self, data: str):
        self.proc.stdin.write(data.encode())
        self.proc.stdin.flush()

    def close(self) -> ([str], [str]):
        self.proc.stdin.close()
        self.stdout_thread.join()
        self.stderr_thread.join()
        self._end()
        return self._stdout, self._stderr

    def _end(self):
        if self.proc:
            # noinspection PyBroadException
            try:
                if self.proc.stdin:
                    # noinspection PyBroadException
                    try:
                        self.proc.stdin.close()
                    except Exception:
                        pass
                if self.proc.stdout:
                    self.proc.stdout.close()
                if self.proc.stderr:
                    self.proc.stderr.close()
            except Exception:
                self.proc.terminate()
            finally:
                self.stdout_thread = None
                self.stderr_thread = None
                self.proc = None

    def stutter_check(self, env, chunks: [str], stutter: datetime.timedelta):
        if not self.proc:
            self.start(env)
        for chunk in chunks:
            self.send(chunk)
            time.sleep(stutter.total_seconds())
        recv_out, recv_err = self.close()
        # assert we got everything back
        assert "".join(chunks) == "".join(recv_out)
        # now the tricky part: check *when* we got everything back
        recv_times = []
        for line in "".join(recv_err).split('\n'):
            m = re.match(r'^\s*(\d+:\d+:\d+(\.\d+)?) <= Recv data, (\d+) bytes.*', line)
            if m:
                recv_times.append(datetime.time.fromisoformat(m.group(1)))
        # received as many chunks as we sent
        assert len(chunks) == len(recv_times), "received response not in {0} chunks, but {1}".format(
            len(chunks), len(recv_times))

        def microsecs(tdelta):
            return ((tdelta.hour * 60 + tdelta.minute) * 60 + tdelta.second) * 1000000 + tdelta.microsecond

        recv_deltas = []
        last_mics = microsecs(recv_times[0])
        for ts in recv_times[1:]:
            mics = microsecs(ts)
            delta_mics = mics - last_mics
            if delta_mics < 0:
                delta_mics += datetime.time(23, 59, 59, 999999)
            recv_deltas.append(datetime.timedelta(microseconds=delta_mics))
            last_mics = mics
        stutter_td = datetime.timedelta(seconds=stutter.total_seconds() * 0.9)  # 10% leeway
        for idx, td in enumerate(recv_deltas[1:]):
            assert stutter_td < td, "chunk {0} arrived too early after {1}".format(idx, td)


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.setup_data_1k_1m()
        conf = HttpdConf(env).add("H2OutputBuffering off")
        conf.add_vhost_cgi(h2proxy_self=True).install()
        assert env.apache_restart() == 0

    def test_712_01(self, env):
        # test gRPC like requests that do not end, but give answers, see #207
        #
        # this test works like this:
        # - use curl to POST data to the server /h2test/echo
        # - feed curl the data in chunks, wait a bit between chunks
        # - since some buffering on curl's stdout to Python is involved,
        #   we will see the response data only at the end.
        # - therefore, we enable tracing with timestamps in curl on stderr
        #   and see when the response chunks arrive
        # - if the server sends the incoming data chunks back right away,
        #   as it should, we see receiving timestamps separated roughly by the
        #   wait time between sends.
        #
        url = env.mkurl("https", "cgi", "/h2test/echo")
        base_chunk = "0123456789"
        chunks = ["chunk-{0:03d}-{1}\n".format(i, base_chunk) for i in range(5)]
        stutter = timedelta(seconds=0.1)  # this is short, but works on my machine (tm)
        piper = CurlPiper(url=url)
        piper.stutter_check(env, chunks, stutter)

    def test_712_02(self, env):
        # same as 712_01 but via mod_proxy_http2
        #
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/echo")
        base_chunk = "0123456789"
        chunks = ["chunk-{0:03d}-{1}\n".format(i, base_chunk) for i in range(3)]
        stutter = timedelta(seconds=0.3)  # need a bit more delay since we have the extra connection
        piper = CurlPiper(url=url)
        piper.stutter_check(env, chunks, stutter)

    def test_712_03(self, env):
        # same as 712_02 but with smaller chunks
        #
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/echo")
        base_chunk = "0"
        chunks = ["ck{0}-{1}\n".format(i, base_chunk) for i in range(3)]
        stutter = timedelta(seconds=0.3)  # need a bit more delay since we have the extra connection
        piper = CurlPiper(url=url)
        piper.stutter_check(env, chunks, stutter)
