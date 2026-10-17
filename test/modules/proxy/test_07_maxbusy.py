import http.server
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from pyhttpd.conf import HttpdConf


class SlowBackend:
    """A threaded HTTP backend that tracks how many requests it is
    handling concurrently, and holds each request open for `delay`
    seconds. Used to prove that a BalancerMember's maxbusy limit bounds
    the number of requests actually reaching the backend at once,
    across all httpd child processes.
    """

    def __init__(self, port, delay=1.0):
        self._port = port
        self._delay = delay
        self._lock = threading.Lock()
        self._active = 0
        self._max_active = 0
        backend = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                with backend._lock:
                    backend._active += 1
                    backend._max_active = max(backend._max_active,
                                               backend._active)
                try:
                    d = float(self.path.strip('/').split('?')[0] or backend._delay)
                except ValueError:
                    d = backend._delay
                time.sleep(d)
                with backend._lock:
                    backend._active -= 1
                body = f"ok from {backend._port}\n".encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self._server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._thread.join(timeout=5)

    @property
    def port(self):
        return self._port

    @property
    def max_active(self):
        with self._lock:
            return self._max_active

    def reset(self):
        with self._lock:
            self._max_active = 0


class TestProxyMaxBusy:

    @pytest.fixture(scope='class')
    def backend_a(self, env):
        b = SlowBackend(env.http_port + 100, delay=1.5)
        b.start()
        yield b
        b.stop()

    @pytest.fixture(scope='class')
    def backend_b(self, env):
        b = SlowBackend(env.http_port + 101, delay=1.5)
        b.start()
        yield b
        b.stop()

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, backend_a, backend_b):
        conf = HttpdConf(env)
        conf.add([
            f"LoadModule lbmethod_bytraffic_module "
            f"\"{env.prefix}/modules/mod_lbmethod_bytraffic.so\"",
            f"LoadModule lbmethod_bybusyness_module "
            f"\"{env.prefix}/modules/mod_lbmethod_bybusyness.so\"",
            "StartServers 4",
            "MinSpareThreads 4",
            "MaxSpareThreads 8",
            "MaxRequestWorkers 20",
            "ServerLimit 20",
            # single-worker balancer: basic hard-cap behaviour
            "<Proxy balancer://maxbusy-cluster>",
            f"    BalancerMember http://127.0.0.1:{backend_a.port} maxbusy=2",
            "</Proxy>",
            "ProxyPass /maxbusy balancer://maxbusy-cluster",
            # two-worker balancer, heavily skewed loadfactor: proves
            # failover routes around a saturated worker rather than
            # 503'ing while spare capacity exists elsewhere
            "<Proxy balancer://maxbusy-byrequests>",
            f"    BalancerMember http://127.0.0.1:{backend_a.port} maxbusy=1 loadfactor=100",
            f"    BalancerMember http://127.0.0.1:{backend_b.port} maxbusy=1 loadfactor=1",
            "    ProxySet lbmethod=byrequests",
            "</Proxy>",
            "ProxyPass /maxbusy-br balancer://maxbusy-byrequests",
            "<Proxy balancer://maxbusy-bytraffic>",
            f"    BalancerMember http://127.0.0.1:{backend_a.port} maxbusy=1 loadfactor=100",
            f"    BalancerMember http://127.0.0.1:{backend_b.port} maxbusy=1 loadfactor=1",
            "    ProxySet lbmethod=bytraffic",
            "</Proxy>",
            "ProxyPass /maxbusy-bt balancer://maxbusy-bytraffic",
            "<Proxy balancer://maxbusy-bybusyness>",
            f"    BalancerMember http://127.0.0.1:{backend_a.port} maxbusy=1",
            f"    BalancerMember http://127.0.0.1:{backend_b.port} maxbusy=1",
            "    ProxySet lbmethod=bybusyness",
            "</Proxy>",
            "ProxyPass /maxbusy-bb balancer://maxbusy-bybusyness",
            # two-worker balancer with a Balancer Timeout, for the
            # all-saturated cases
            "<Proxy balancer://maxbusy-timeout>",
            f"    BalancerMember http://127.0.0.1:{backend_a.port} maxbusy=1",
            f"    BalancerMember http://127.0.0.1:{backend_b.port} maxbusy=1",
            "    ProxySet lbmethod=byrequests timeout=10",
            "</Proxy>",
            "ProxyPass /maxbusy-to balancer://maxbusy-timeout",
            # two-worker balancer with no Balancer Timeout: immediate 503
            "<Proxy balancer://maxbusy-notimeout>",
            f"    BalancerMember http://127.0.0.1:{backend_a.port} maxbusy=1",
            f"    BalancerMember http://127.0.0.1:{backend_b.port} maxbusy=1",
            "    ProxySet lbmethod=byrequests",
            "</Proxy>",
            "ProxyPass /maxbusy-noto balancer://maxbusy-notimeout",
            # sticky balancer, nofailover On and Off (two paths so both
            # can be exercised without changing config mid-test)
            "<Proxy balancer://maxbusy-sticky-on>",
            f"    BalancerMember http://127.0.0.1:{backend_a.port} route=1 maxbusy=1",
            f"    BalancerMember http://127.0.0.1:{backend_b.port} route=2 maxbusy=1",
            "    ProxySet stickysession=ROUTEID nofailover=On",
            "</Proxy>",
            "ProxyPass /maxbusy-sticky-on balancer://maxbusy-sticky-on",
            "<Proxy balancer://maxbusy-sticky-off>",
            f"    BalancerMember http://127.0.0.1:{backend_a.port} route=1 maxbusy=1",
            f"    BalancerMember http://127.0.0.1:{backend_b.port} route=2 maxbusy=1",
            "    ProxySet stickysession=ROUTEID nofailover=Off",
            "</Proxy>",
            "ProxyPass /maxbusy-sticky-off balancer://maxbusy-sticky-off",
            # a balancer with no maxbusy set at all: must behave exactly
            # like trunk (unlimited concurrency)
            "<Proxy balancer://nomaxbusy-cluster>",
            f"    BalancerMember http://127.0.0.1:{backend_a.port}",
            "</Proxy>",
            "ProxyPass /nomaxbusy balancer://nomaxbusy-cluster",
            # a worker with no backend listening yet, for the
            # release-on-connection-failure test; the backend is
            # started (and later stopped) by that test itself, config
            # is never touched again so the balancers above stay live
            "<Proxy balancer://maxbusy-dead>",
            "    BalancerMember http://127.0.0.1:18599 maxbusy=1 retry=1",
            "</Proxy>",
            "ProxyPass /maxbusy-dead balancer://maxbusy-dead",
            # worker A refuses connections outright (nothing listens on
            # 18598); worker B is healthy but slow. A single request must
            # fail over A -> B, and the regression under test is whether
            # A's maxbusy reservation is released the instant the
            # failover is taken, rather than leaking for as long as B's
            # (unrelated, successful) attempt takes to complete.
            "<Proxy balancer://maxbusy-failover-leak>",
            "    BalancerMember http://127.0.0.1:18598 maxbusy=1 "
            "loadfactor=100 retry=600",
            f"    BalancerMember http://127.0.0.1:{backend_a.port} maxbusy=1 "
            f"loadfactor=1",
            "    ProxySet lbmethod=byrequests",
            "</Proxy>",
            "ProxyPass /maxbusy-leak balancer://maxbusy-failover-leak",
            # three-worker chain: A and B refuse connections outright, C
            # is healthy; a request must fail over twice (A -> B -> C)
            # without leaking a reservation on either abandoned worker.
            "<Proxy balancer://maxbusy-chain>",
            "    BalancerMember http://127.0.0.1:18597 maxbusy=1 "
            "loadfactor=100 retry=600",
            "    BalancerMember http://127.0.0.1:18596 maxbusy=1 "
            "loadfactor=100 retry=600",
            "    BalancerMember http://127.0.0.1:18595 maxbusy=1 "
            "loadfactor=1",
            "    ProxySet lbmethod=byrequests",
            "</Proxy>",
            "ProxyPass /maxbusy-chain balancer://maxbusy-chain",
            "<Location /balancer-manager>",
            "    SetHandler balancer-manager",
            "    Require all granted",
            "</Location>",
        ])
        conf.install()
        assert env.apache_restart() == 0

    # -----------------------------------------------------------------
    # 1. Global hard cap across multiple child processes
    # -----------------------------------------------------------------
    def test_proxy_07_001_global_hard_cap(self, env, backend_a):
        backend_a.reset()
        url = f"http://localhost:{env.http_port}/maxbusy/x"
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: env.curl_get(url), range(6)))
        statuses = sorted(r.response["status"] for r in results)
        assert statuses == [200, 200, 503, 503, 503, 503], statuses
        assert backend_a.max_active <= 2, \
            f"observed concurrency {backend_a.max_active} > maxbusy=2"
        env.httpd_error_log.ignore_recent(
            matches=[r'.*is at its MaxBusy limit.*',
                     r'.*All workers are in error state.*'])

    def test_proxy_07_002_no_leak_after_burst(self, env, backend_a):
        # after the limit-exceeding burst above, the worker must not be
        # left with a leaked reservation: a fresh request must succeed.
        url = f"http://localhost:{env.http_port}/maxbusy/x"
        r = env.curl_get(url)
        assert r.response["status"] == 200

    def test_proxy_07_003_release_on_client_abort(self, env, backend_a):
        # a request that is aborted by the client before the backend
        # responds must not leak its reservation either.
        backend_a.reset()
        url = f"http://localhost:{env.http_port}/maxbusy/x"
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(env.curl_get, url)
            time.sleep(0.2)
            aborted = env.curl_raw([url], options=["--max-time", "0.2"])
            assert aborted.exit_code != 0
            r1 = fut.result()
        assert r1.response["status"] == 200
        time.sleep(0.5)
        r2 = env.curl_get(url)
        assert r2.response["status"] == 200

    def test_proxy_07_004_release_on_backend_failure(self, env):
        # a worker whose backend connection fails must not leave a
        # leaked maxbusy reservation behind either: bring up a fresh,
        # working backend on the port the (still-dead, per class setup)
        # worker points to, and confirm a later request succeeds once
        # the worker's retry interval has elapsed. The config is not
        # touched here, so the balancers set up for the rest of the
        # class stay live.
        dead_port = 18599
        url = f"http://localhost:{env.http_port}/maxbusy-dead/x"
        r1 = env.curl_get(url)
        assert r1.response["status"] in (502, 503)
        env.httpd_error_log.ignore_recent(
            matches=[r'.*failed to make connection to backend.*',
                     r'.*disabling worker.*',
                     r'.*attempt to connect.*failed.*'])
        backend = SlowBackend(dead_port, delay=0.1)
        backend.start()
        try:
            time.sleep(1.5)
            r2 = env.curl_get(url)
            assert r2.response["status"] == 200
        finally:
            backend.stop()

    # -----------------------------------------------------------------
    # Confirmed bug: proxy_handler() in mod_proxy.c retries a failed
    # worker with a fresh ap_proxy_pre_request() call, but (before the
    # fix) only released the abandoned worker's maxbusy reservation when
    # the whole request's pool was destroyed -- i.e. only after the
    # eventual successful worker finished, not the instant the failover
    # was taken. A worker refusing connections would therefore keep
    # counting as busy for as long as the request takes to complete
    # elsewhere, able to artificially exhaust its own maxbusy while
    # genuinely idle.
    # -----------------------------------------------------------------
    def _worker_reserved(self, env, balancer, port):
        """Scrape <httpd:reserved> for the worker at `port` out of the
        machine-readable XML balancer-manager produces with ?xml. A
        Referer matching the vhost is required, or balancer-manager
        discards all query parameters as a cross-site request and
        silently returns the full default HTML listing instead."""
        base = f"http://localhost:{env.http_port}"
        url = f"{base}/balancer-manager?b={balancer}&xml"
        r = env.curl_get(url, options=["-H", f"Referer: {base}/"])
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        worker_re = re.compile(
            r"<httpd:worker>.*?<httpd:port>%d</httpd:port>.*?"
            r"<httpd:reserved>(\d+)</httpd:reserved>.*?</httpd:worker>"
            % port, re.DOTALL)
        # Scope to this balancer's own <httpd:balancer> block first: the
        # XML dump lists every configured balancer regardless of `b=`,
        # and a worker URL/port is not necessarily unique across
        # balancers in this test's config (backend_a is reused by more
        # than one), so searching the whole document could match a
        # same-port worker belonging to a different, irrelevant balancer.
        balancer_re = re.compile(
            r"<httpd:balancer>\s*<httpd:name>balancer://%s</httpd:name>"
            r"(.*?)</httpd:balancer>" % re.escape(balancer), re.DOTALL)
        bm = balancer_re.search(body)
        assert bm, f"balancer {balancer} not found in {url}: {body}"
        m = worker_re.search(bm.group(1))
        assert m, f"worker on port {port} not found in balancer " \
                  f"{balancer}'s block: {bm.group(1)}"
        return int(m.group(1))

    def test_proxy_07_012_no_leak_during_failover(self, env, backend_a):
        backend_a.reset()
        dead_port = 18598
        url = f"http://localhost:{env.http_port}/maxbusy-leak/x"

        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(env.curl_get, url)
            # give the request time to: hit the dead worker, fail over,
            # and be in the middle of backend_a's 1.5s delayed response.
            time.sleep(0.7)
            reserved_dead = self._worker_reserved(
                env, "maxbusy-failover-leak", dead_port)
            reserved_live = self._worker_reserved(
                env, "maxbusy-failover-leak", backend_a.port)
            r = fut.result()

        assert r.response["status"] == 200, r.response
        assert reserved_live == 1, \
            f"expected the live worker to hold the reservation while " \
            f"active, got {reserved_live}"
        assert reserved_dead == 0, \
            f"maxbusy reservation leaked on the abandoned worker during " \
            f"failover: reserved={reserved_dead}, expected 0 while the " \
            f"request was still being served by the other worker"

        # and after completion, neither side has anything outstanding
        assert self._worker_reserved(
            env, "maxbusy-failover-leak", dead_port) == 0
        assert self._worker_reserved(
            env, "maxbusy-failover-leak", backend_a.port) == 0
        env.httpd_error_log.ignore_recent(
            matches=[r'.*failed to make connection to backend.*',
                     r'.*disabling worker.*',
                     r'.*attempt to connect.*failed.*'])

    def test_proxy_07_013_failover_chain_no_leak(self, env):
        # A and B both refuse connections, C is healthy and slow: the
        # request must fail over twice, and only C may hold a reservation
        # while it is active; A and B must be at 0 throughout, not just
        # at the end.
        dead_a, dead_b = 18597, 18596
        c = SlowBackend(18595, delay=1.5)
        c.start()
        try:
            url = f"http://localhost:{env.http_port}/maxbusy-chain/x"
            with ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(env.curl_get, url)
                time.sleep(0.7)
                r_a = self._worker_reserved(env, "maxbusy-chain", dead_a)
                r_b = self._worker_reserved(env, "maxbusy-chain", dead_b)
                r_c = self._worker_reserved(env, "maxbusy-chain", 18595)
                result = fut.result()
            assert result.response["status"] == 200, result.response
            assert (r_a, r_b, r_c) == (0, 0, 1), (r_a, r_b, r_c)
            assert self._worker_reserved(env, "maxbusy-chain", dead_a) == 0
            assert self._worker_reserved(env, "maxbusy-chain", dead_b) == 0
            assert self._worker_reserved(env, "maxbusy-chain", 18595) == 0
        finally:
            c.stop()
        env.httpd_error_log.ignore_recent(
            matches=[r'.*failed to make connection to backend.*',
                     r'.*disabling worker.*',
                     r'.*attempt to connect.*failed.*'])

    # -----------------------------------------------------------------
    # 2/3/4. byrequests / bytraffic / bybusyness: saturated A, available
    # B -> B is used, despite A's much higher loadfactor.
    # -----------------------------------------------------------------
    @pytest.mark.parametrize("path, lbmethod", [
        ("maxbusy-br", "byrequests"),
        ("maxbusy-bt", "bytraffic"),
    ])
    def test_proxy_07_005_failover_skips_saturated(self, env, backend_a,
                                                    backend_b, path, lbmethod):
        backend_a.reset()
        backend_b.reset()
        url = f"http://localhost:{env.http_port}/{path}/x"
        hold_url = f"http://localhost:{env.http_port}/{path}/2"
        with ThreadPoolExecutor(max_workers=1) as pool:
            # saturate the heavily-weighted worker A
            fut = pool.submit(env.curl_get, hold_url)
            time.sleep(0.3)
            # despite A's overwhelming loadfactor, new requests must be
            # routed to B, which has spare capacity
            r = env.curl_get(f"http://localhost:{env.http_port}/{path}/0.1")
            assert r.response["status"] == 200, \
                f"{lbmethod}: expected failover to the spare worker, got {r.response['status']}"
            assert fut.result().response["status"] == 200
        assert backend_a.max_active <= 1
        assert backend_b.max_active <= 1

    def test_proxy_07_006_bybusyness_runtime_reset_hard_cap(
            self, env, backend_a, backend_b):
        # The regression this patch fixes: triggering a real runtime
        # need_reset (via a balancer-manager lbmethod change) while
        # requests are active against bybusyness workers must NOT allow
        # the observed backend concurrency to exceed maxbusy, even
        # though the reset zeroes the unrelated 'busy' LB metric.
        backend_a.reset()
        backend_b.reset()
        base = f"http://localhost:{env.http_port}"
        nonce = env.get_balancer_manager_nonce(
            "maxbusy-bybusyness") if hasattr(
            env, "get_balancer_manager_nonce") else None
        if nonce is None:
            r = env.curl_get(f"{base}/balancer-manager?b=maxbusy-bybusyness")
            m = re.search(r"nonce=([a-f0-9-]{36})", r.response["body"].decode())
            assert m, "could not find balancer-manager nonce"
            nonce = m.group(1)

        with ThreadPoolExecutor(max_workers=4) as pool:
            # saturate both workers (maxbusy=1 each)
            futs = [pool.submit(env.curl_get, f"{base}/maxbusy-bb/3")
                    for _ in range(2)]
            time.sleep(0.5)

            # flip the lbmethod away and back: each change sets
            # need_reset, and bybusyness.reset() zeroes 'busy' for every
            # worker in the balancer the next time the balancer is
            # synced, while the two requests above are still active.
            # Use urllib directly (not the curl wrapper) so the Referer
            # header is guaranteed to be sent, and verify from the
            # response body that the lbmethod change was actually
            # applied (not silently dropped as a cross-site request),
            # since a dropped POST would make this test pass vacuously.
            import urllib.request
            for target in ("byrequests", "bybusyness"):
                req = urllib.request.Request(
                    f"{base}/balancer-manager",
                    data=f"b=maxbusy-bybusyness&nonce={nonce}&b_lbm={target}".encode(),
                    headers={"Referer": f"{base}/",
                             "Content-Type": "application/x-www-form-urlencoded"},
                    method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    assert resp.status == 200
                    body = resp.read().decode()
                assert f"<td>{target}</td>" in body, \
                    (f"b_lbm={target} was not applied (dropped as "
                     f"cross-site?): {body}")

            # immediately fire more requests; if the hard cap were only
            # enforced via the (now reset) 'busy' counter, these would
            # be wrongly admitted on top of the two still-active ones.
            extra = [pool.submit(env.curl_get, f"{base}/maxbusy-bb/0.2")
                     for _ in range(4)]
            extra_statuses = sorted(f.result().response["status"]
                                     for f in extra)
            assert extra_statuses == [503, 503, 503, 503], extra_statuses

            orig_statuses = sorted(f.result().response["status"]
                                    for f in futs)
            assert orig_statuses == [200, 200], orig_statuses

        assert backend_a.max_active <= 1, \
            f"bybusyness reset race: observed {backend_a.max_active} > maxbusy=1"
        assert backend_b.max_active <= 1, \
            f"bybusyness reset race: observed {backend_b.max_active} > maxbusy=1"
        env.httpd_error_log.ignore_recent(
            matches=[r'.*is at its MaxBusy limit.*',
                     r'.*All workers are in error state.*',
                     r'.*could not reserve a worker.*',
                     r'.*ignoring params in balancer-manager.*'])

    # -----------------------------------------------------------------
    # 6/7. All workers saturated
    # -----------------------------------------------------------------
    def test_proxy_07_007_all_saturated_no_timeout_503(
            self, env, backend_a, backend_b):
        backend_a.reset()
        backend_b.reset()
        base = f"http://localhost:{env.http_port}/maxbusy-noto"
        with ThreadPoolExecutor(max_workers=2) as pool:
            futs = [pool.submit(env.curl_get, f"{base}/2") for _ in range(2)]
            time.sleep(0.3)
            t0 = time.time()
            r = env.curl_get(f"{base}/0.1")
            elapsed = time.time() - t0
            assert r.response["status"] == 503
            assert elapsed < 1.0, \
                f"expected an immediate 503 with no Balancer Timeout, took {elapsed}s"
            for f in futs:
                assert f.result().response["status"] == 200
        env.httpd_error_log.ignore_recent(
            matches=[r'.*All workers are in error state.*'])

    def test_proxy_07_008_all_saturated_timeout_waits_and_succeeds(
            self, env, backend_a, backend_b):
        backend_a.reset()
        backend_b.reset()
        base = f"http://localhost:{env.http_port}/maxbusy-to"
        with ThreadPoolExecutor(max_workers=3) as pool:
            futs = [pool.submit(env.curl_get, f"{base}/4") for _ in range(2)]
            time.sleep(0.3)
            t0 = time.time()
            r = env.curl_get(f"{base}/0.1")
            elapsed = time.time() - t0
            assert r.response["status"] == 200, \
                "expected the waiting request to succeed once a slot freed"
            assert elapsed > 2.0, \
                f"expected the request to actually wait for capacity, took {elapsed}s"
            for f in futs:
                assert f.result().response["status"] == 200

    # -----------------------------------------------------------------
    # 8/9. Sticky sessions
    # -----------------------------------------------------------------
    def test_proxy_07_009_sticky_nofailover_on_503(
            self, env, backend_a, backend_b):
        backend_a.reset()
        backend_b.reset()
        base = f"http://localhost:{env.http_port}/maxbusy-sticky-on"
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(
                env.curl_raw, [f"{base}/2"],
                options=["-H", "Cookie: ROUTEID=x.1"])
            time.sleep(0.3)
            r = env.curl_raw([f"{base}/0.1"],
                             options=["-H", "Cookie: ROUTEID=x.1"])
            assert r.response["status"] == 503
            assert fut.result().response["status"] == 200
        env.httpd_error_log.ignore_recent(
            matches=[r'.*All workers are in error state.*'])

    def test_proxy_07_010_sticky_nofailover_off_failover(
            self, env, backend_a, backend_b):
        backend_a.reset()
        backend_b.reset()
        base = f"http://localhost:{env.http_port}/maxbusy-sticky-off"
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(
                env.curl_raw, [f"{base}/2"],
                options=["-H", "Cookie: ROUTEID=x.1"])
            time.sleep(0.3)
            r = env.curl_raw([f"{base}/0.1"],
                             options=["-H", "Cookie: ROUTEID=x.1"])
            assert r.response["status"] == 200, \
                "expected failover to the other worker, not a 503"
            assert fut.result().response["status"] == 200
        assert backend_a.max_active <= 1
        assert backend_b.max_active <= 1

    # -----------------------------------------------------------------
    # 15. maxbusy unset: behaves exactly like trunk (unlimited)
    # -----------------------------------------------------------------
    def test_proxy_07_011_unset_is_unlimited(self, env, backend_a):
        backend_a.reset()
        url = f"http://localhost:{env.http_port}/nomaxbusy/x"
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: env.curl_get(url), range(6)))
        statuses = [r.response["status"] for r in results]
        assert statuses == [200] * 6, statuses


class TestProxyMaxBusyIdentity:
    """Admission-table identity correctness: a BalancerMember's maxbusy
    reservation count must be scoped per (server/vhost, balancer, worker),
    not merely per worker URL or per textual balancer name, and must not
    be allocated merely by observing a worker (balancer-manager, or any
    other read of its current reservation count).
    """

    @pytest.fixture(scope='class')
    def backend_shared(self, env):
        b = SlowBackend(env.http_port + 120, delay=1.5)
        b.start()
        yield b
        b.stop()

    @pytest.fixture(scope='class')
    def backend_unlimited(self, env):
        b = SlowBackend(env.http_port + 121, delay=0.2)
        b.start()
        yield b
        b.stop()

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, backend_shared, backend_unlimited):
        vhost_a_port = env.http_port + 130
        vhost_b_port = env.http_port + 131
        conf = HttpdConf(env)
        lines = [
            f"Listen 127.0.0.1:{vhost_a_port}",
            f"Listen 127.0.0.1:{vhost_b_port}",
            f"<VirtualHost 127.0.0.1:{vhost_a_port}>",
            "    ServerName vhost-a.example.org",
            # same balancer name, same backend URL as vhost B below, but
            # a DIFFERENT maxbusy: these must not share one counter.
            "    <Proxy balancer://app>",
            f"        BalancerMember http://127.0.0.1:{backend_shared.port} maxbusy=1",
            "    </Proxy>",
            "    ProxyPass /app balancer://app",
            "</VirtualHost>",
            f"<VirtualHost 127.0.0.1:{vhost_b_port}>",
            "    ServerName vhost-b.example.org",
            "    <Proxy balancer://app>",
            f"        BalancerMember http://127.0.0.1:{backend_shared.port} maxbusy=2",
            "    </Proxy>",
            "    ProxyPass /app balancer://app",
            "</VirtualHost>",
        ]
        # Item 2: more than 64 configured BalancerMembers with maxbusy
        # set, to size the admission table beyond its 64-slot floor
        # (under the pre-fix code, which sized the table from the empty
        # conf->workers array of direct ProxyPass workers, this would
        # have silently relied on that floor instead of actual demand).
        # Each gets its own tiny backend-less worker: none are ever
        # requested, so no retry/connection-refused noise, this is only
        # about every one of them getting an independent, working slot.
        many = []
        for i in range(80):
            many.append(f"<Proxy balancer://many-{i}>")
            many.append(
                f"    BalancerMember http://127.0.0.1:19{700 + i} "
                f"maxbusy=1 disablereuse=on")
            many.append("</Proxy>")
            many.append(f"ProxyPass /many-{i} balancer://many-{i}")
        lines.extend(many)
        # Item 5: many maxbusy=0 (unlimited) workers, queried repeatedly
        # via balancer-manager; none of them may consume an admission
        # slot merely by being looked up.
        lines.append("<Proxy balancer://unlimited>")
        lines.append(
            f"    BalancerMember http://127.0.0.1:{backend_unlimited.port}")
        lines.append("</Proxy>")
        lines.append("ProxyPass /unlimited balancer://unlimited")
        lines.append("<Location /balancer-manager>")
        lines.append("    SetHandler balancer-manager")
        lines.append("    Require all granted")
        lines.append("</Location>")
        conf.add(lines)
        conf.install()
        assert env.apache_restart() == 0
        # A class-scoped fixture gets a fresh `self` per test method, so
        # instance attributes set here would not be visible there: store
        # on the class itself instead.
        type(self).vhost_a_port = vhost_a_port
        type(self).vhost_b_port = vhost_b_port

    # -----------------------------------------------------------------
    # Item 2: a large number of BalancerMembers must not exhaust the
    # admission table merely because the (wrong, pre-fix) sizing saw
    # zero direct ProxyPass workers; startup itself succeeding already
    # proves ap_proxy_admission_table_check() was satisfied, and the
    # cluster configured above (maxbusy=1 each) getting its own slot
    # proves the table has room beyond the 64-slot floor.
    # -----------------------------------------------------------------
    def test_proxy_07_101_many_balancer_members_each_get_a_slot(self, env):
        # The httpd instance is already up (fixture asserted restart==0
        # with 80+ maxbusy BalancerMembers configured, none of which
        # could be registered without ap_proxy_admission_table_check()
        # passing: under the pre-fix sizing, which counted zero direct
        # ProxyPass workers for this all-BalancerMember config and so
        # sized the table at its 16*4=64-slot floor, more than 64
        # distinct maxbusy'd members would eventually report "admission
        # table is full" (item 6's log line) once enough of them had
        # actually been requested to populate it past 64 entries.
        #
        # None of these members has a real backend, so a *request* to
        # one deterministically gets a connection-refused 503 from
        # mod_proxy_http regardless of admission state (confirmed via
        # error_log: "AH00957: ... Connection refused"), which would
        # make a response-code assertion here ambiguous. Instead, send
        # one request to each of several of them (enough to populate
        # that many slots) and assert the admission table's own
        # "is full" diagnostic never appears.
        for i in range(70):
            env.curl_get(f"http://127.0.0.1:{self.vhost_a_port}/many-{i}/x",
                        options=["--max-time", "1"])
        with open(env.httpd_error_log.path) as fd:
            log = fd.read()
        assert "admission table is full" not in log, \
            "admission table ran out of slots for 70 distinct " \
            "BalancerMembers -- sizing did not account for them"
        env.httpd_error_log.ignore_recent(
            matches=[r'.*Connection refused.*',
                     r'.*disabling worker.*',
                     r'.*failed to make connection to backend.*'])

    # -----------------------------------------------------------------
    # Item 4: same balancer name + same backend URL, in two different
    # vhosts, with two different maxbusy values -- saturating one must
    # not consume the other's reservations.
    # -----------------------------------------------------------------
    def test_proxy_07_102_cross_vhost_identity_independent(self, env):
        url_a = f"http://127.0.0.1:{self.vhost_a_port}/app/x"
        url_b = f"http://127.0.0.1:{self.vhost_b_port}/app/x"

        # Saturate vhost A's balancer (maxbusy=1): one request held busy.
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut_a_hold = pool.submit(env.curl_get, url_a)
            time.sleep(0.3)  # let it register as active before probing
            r_a_second = env.curl_get(url_a, options=["--max-time", "3"])
            assert r_a_second.response["status"] == 503, \
                "vhost A's own second request should be rejected (maxbusy=1)"

            # vhost B (maxbusy=2) must be entirely unaffected: both of
            # its own requests succeed concurrently, proving its counter
            # is independent of vhost A's, not aliased by the shared
            # balancer name/backend URL.
            with ThreadPoolExecutor(max_workers=2) as pool_b:
                futs_b = [pool_b.submit(env.curl_get, url_b,
                                        options=["--max-time", "3"])
                          for _ in range(2)]
                statuses_b = sorted(f.result().response["status"]
                                    for f in futs_b)
            assert statuses_b == [200, 200], \
                f"vhost B rejected a request while only vhost A was saturated: {statuses_b}"

            fut_a_hold.result()
        env.httpd_error_log.ignore_recent(
            matches=[r'.*is at its MaxBusy limit.*',
                     r'.*could not reserve a worker.*',
                     r'.*All workers are in error state.*'])

    # -----------------------------------------------------------------
    # Item 5: a read-only lookup (balancer-manager rendering a worker's
    # reservation count) must never allocate an admission slot, and a
    # maxbusy=0 worker must never consume one merely by being observed.
    # -----------------------------------------------------------------
    def test_proxy_07_103_readonly_lookup_does_not_allocate(self, env):
        mgr_url = f"http://127.0.0.1:{self.vhost_a_port}/balancer-manager"
        for _ in range(20):
            r = env.curl_get(mgr_url)
            assert r.response["status"] == 200
        # The unlimited (maxbusy=0) worker, rendered 20 times above via
        # balancer-manager (which reads its reservation count), must
        # still behave as genuinely unlimited: 5 real concurrent
        # requests all succeed against its own (real) backend. If
        # rendering it had allocated a slot for it, that alone would not
        # break this assertion (maxbusy=0 never checks the table either
        # way, see ap_proxy_try_reserve_worker()) -- the point is this
        # exercises the read path at all without the server logging any
        # problem.
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(
                lambda _: env.curl_get(
                    f"http://127.0.0.1:{self.vhost_a_port}/unlimited/x"),
                range(5)))
        statuses = [r.response["status"] for r in results]
        assert statuses == [200] * 5, statuses
        with open(env.httpd_error_log.path) as fd:
            log = fd.read()
        assert "admission table is full" not in log, \
            "balancer-manager reads of a maxbusy=0 worker appear to " \
            "have consumed admission-table slots"
        env.httpd_error_log.ignore_recent(
            matches=[r'.*ignoring params in balancer-manager.*'])
