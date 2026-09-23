import socket
import time
from datetime import timedelta

import pytest

from .env import H2Conf
from pyhttpd.curl import CurlPiper


class TestTimeout:

    # Check that base servers 'Timeout' setting is observed on SSL handshake
    def test_h2_105_01(self, env):
        conf = H2Conf(env)
        conf.add("""
            AcceptFilter http none
            Timeout 1.5
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        host = 'localhost'
        # read with a longer timeout than the server 
        sock = socket.create_connection((host, int(env.https_port)))
        try:
            # on some OS, the server does not see our connection until there is
            # something incoming
            sock.send(b'0')
            sock.settimeout(4)
            buff = sock.recv(1024)
            assert buff == b''
        except Exception as ex:
            print(f"server did not close in time: {ex}")
            assert False
        sock.close()
        # read with a shorter timeout than the server 
        sock = socket.create_connection((host, int(env.https_port)))
        try:
            sock.settimeout(0.5)
            sock.recv(1024)
            assert False
        except Exception as ex:
            print(f"as expected: {ex}")
        sock.close()
        #
        time.sleep(1) # let the log flush
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH10373"   # SSL handshake was not completed
            ]
        )

    # Check that mod_reqtimeout handshake setting takes effect
    def test_h2_105_02(self, env):
        conf = H2Conf(env)
        conf.add("""
            AcceptFilter http none
            Timeout 10
            RequestReadTimeout handshake=1 header=5 body=10
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        host = 'localhost'
        # read with a longer timeout than the server 
        sock = socket.create_connection((host, int(env.https_port)))
        try:
            # on some OS, the server does not see our connection until there is
            # something incoming
            sock.send(b'0')
            sock.settimeout(4)
            buff = sock.recv(1024)
            assert buff == b''
        except Exception as ex:
            print(f"server did not close in time: {ex}")
            assert False
        sock.close()
        # read with a shorter timeout than the server 
        sock = socket.create_connection((host, int(env.https_port)))
        try:
            sock.settimeout(0.5)
            sock.recv(1024)
            assert False
        except Exception as ex:
            print(f"as expected: {ex}")
        sock.close()
        #
        time.sleep(1) # let the log flush
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH10373"   # SSL handshake was not completed
            ]
        )

    # Check that mod_reqtimeout handshake setting do no longer apply to handshaked 
    # connections. See <https://github.com/icing/mod_h2/issues/196>.
    def test_h2_105_03(self, env):
        conf = H2Conf(env)
        conf.add("""
            Timeout 10
            RequestReadTimeout handshake=1 header=5 body=10
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/necho.py")
        r = env.curl_get(url, 5, options=[
            "-vvv",
            "-F", ("count=%d" % 100),
            "-F", ("text=%s" % "abcdefghijklmnopqrstuvwxyz"),
            "-F", ("wait1=%f" % 1.5),
        ])
        assert r.response["status"] == 200

    def test_h2_105_10(self, env):
        # just a check without delays if all is fine
        conf = H2Conf(env)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2test/delay")
        piper = CurlPiper(env=env, url=url)
        piper.start()
        stdout, stderr = piper.close()
        assert piper.exitcode == 0
        assert len("".join(stdout)) == 3 * 8192

    def test_h2_105_11(self, env):
        # short connection timeout, longer stream delay
        # connection timeout must not abort ongoing streams
        conf = H2Conf(env)
        conf.add_vhost_cgi()
        conf.add("Timeout 1")
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2test/delay?1200ms")
        piper = CurlPiper(env=env, url=url)
        piper.start()
        stdout, stderr = piper.close()
        assert len("".join(stdout)) == 3 * 8192

    def test_h2_105_12(self, env):
        # long connection timeout, short stream timeout
        # sending a slow POST
        if not env.curl_is_at_least('8.0.0'):
            pytest.skip(f'need at least curl v8.0.0 for this')
        if not env.httpd_is_at_least("2.5.0"):
            pytest.skip(f'need at least httpd 2.5.0 for this')
        conf = H2Conf(env)
        conf.add_vhost_cgi()
        conf.add("Timeout 10")
        conf.add("H2StreamTimeout 1")
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2test/delay?5")
        piper = CurlPiper(env=env, url=url)
        piper.start()
        for _ in range(3):
            time.sleep(2)
            try:
                piper.send("0123456789\n")
            except (BrokenPipeError, OSError):
                break
        piper.close()
        assert piper.response, f'{piper}'
        assert piper.response['status'] == 408, f"{piper.response}"

    # A CGI that starts a response (status + headers + some body) and then goes
    # silent past `Timeout` must lead to the HTTP/2 stream being RST_STREAM'd,
    # not leave the client hanging. Regression test for the mod_http2 hang where
    # a c2 that finished an *incomplete* response (no EOS, e.g. CGI timed out
    # mid-body) was treated as complete and no reset was ever sent.
    def test_h2_105_20(self, env):
        conf = H2Conf(env)
        conf.add("Timeout 1")
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2cgi_slow.py")
        # Open many concurrent streams on one h2 connection. The missed reset
        # is racy per stream: the single wakeup at close drives one receive,
        # which resets only if it finds the beam already drained but usually
        # still carries the response's trailing flush and re-suspends. So one
        # stream is unreliable while many in flight hang at least one every
        # run. Key on elapsed time, not curl's exit code (--parallel makes
        # that ambiguous): a hang is a multi-second stall, a correct reset a
        # sub-second teardown. --max-time bounds the client so a hang cannot
        # wedge the test. The per-stream hang is a timing race, so its odds
        # shift with hardware and load; 10 is cheap margin and, being
        # concurrent, costs no wall-clock.
        count = 10
        max_time = 10
        r = env.curl_raw([url] * count, options=[
            "--parallel", "--parallel-immediate", "--max-time", str(max_time)])
        assert r.duration < timedelta(seconds=max_time - 2), \
            f'streams hung waiting for RST_STREAM (batch took {r.duration}): {r}'
        # Resetting each silent CGI is logged as a CGI timeout (cgid) and the
        # failed body read that follows it (core); both are expected here.
        time.sleep(1)  # let the log flush
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH01220",  # cgid: Timeout waiting for output from CGI script
                "AH00574",  # core: ap_content_length_filter, apr_bucket_read() failed
            ]
        )

    # Complement to test_h2_105_20: a header-only response (204/304, or a
    # HEAD request) legitimately carries no body and so no EOS, and must
    # NOT be reset over HTTP/2. mod_cache revalidation of a cached,
    # immediately-stale resource emits exactly such a 304 (EOR + Flush, no
    # EOS). This guards the incomplete-response reset against re-opening
    # PR 69580: the reset is for a truncation (a non-header-only response
    # missing its EOS), never for a header-only one.
    def test_h2_105_21(self, env):
        cacheroot = f"{env.server_dir}/cacheroot"
        env.mkpath(cacheroot)
        conf = H2Conf(env)
        conf.add(f"""
            CacheRoot "{cacheroot}"
            CacheEnable disk /
            Header set Cache-Control "public, max-age=0"
            """)
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "test1", "/006/006.css")
        # prime the cache (stored, immediately stale via max-age=0)
        r = env.curl_get(url)
        assert r.exit_code == 0, f'{r}'
        assert r.response["status"] == 200
        lm = r.response["header"]["last-modified"]
        # revalidate: mod_cache freshens the stale entry and the origin returns a
        # body-less 304. The h2 stream must close cleanly; a regression shows up
        # as a curl exit (92, "stream not closed cleanly"), not as a 304.
        r = env.curl_get(url, options=["-H", "Cache-Control: max-age=0",
                                       "-H", f"if-modified-since: {lm}"])
        assert r.exit_code == 0, f'304 stream was reset (curl {r.exit_code}): {r}'
        assert r.response["status"] == 304, f'{r.response}'
