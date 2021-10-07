import datetime
import re
import subprocess
import sys
import time
from threading import Thread

from h2_env import H2TestEnv


class CurlPiper:

    def __init__(self, env: H2TestEnv, url: str):
        self.env = env
        self.url = url
        self.proc = None
        self.args = None
        self.headerfile = None
        self._stderr = []
        self._stdout = []
        self.stdout_thread = None
        self.stderr_thread = None
        self._exitcode = -1
        self._r = None

    @property
    def exitcode(self):
        return self._exitcode

    @property
    def response(self):
        return self._r.response if self._r else None

    def start(self):
        self.args, self.headerfile = self.env.curl_complete_args(self.url, timeout=5, options=[
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
                self.proc.wait()
                self.stdout_thread = None
                self.stderr_thread = None
                self._exitcode = self.proc.returncode
                self.proc = None
                self._r = self.env.curl_parse_headerfile(self.headerfile)

    def stutter_check(self, chunks: [str], stutter: datetime.timedelta):
        if not self.proc:
            self.start()
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
        # TODO: the first two chunks are often close together, it seems
        # there still is a little buffering delay going on
        for idx, td in enumerate(recv_deltas[1:]):
            assert stutter_td < td, \
                f"chunk {idx} arrived too early \n{recv_deltas}\nafter {td}\n{recv_err}"
