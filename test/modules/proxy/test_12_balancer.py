"""The workers of balancers at run time: added through the balancer-managers.

Each class says what it covers.
"""

import http.client
import re
import threading
import urllib.parse

import pytest

from pyhttpd.conf import HttpdConf

NBALANCERS = 16
NWORKERS = 100


def _worker_url(b, w):
    return f"http://127.{b + 1}.0.{w + 1}:{20000 + w}"


class TestBalancerAddWorkers:
    """Workers added at run time to the balancers of several vhosts at once.

    A vhost with its own proxy configuration takes the main server's
    configuration pool, from which the run-time workers of all its balancers are
    allocated, while an add holds only its own balancer's locks: concurrent adds
    through the balancer-managers, one client per vhost, must neither crash the
    child nor lose or garble the workers.
    """

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        conf = HttpdConf(env)
        for b in range(NBALANCERS):
            conf.start_vhost(domains=[cls._domain(env, b)], port=env.http_port)
            conf.add([
                f"<Proxy balancer://add{b}>",
                f"    ProxySet growth={NWORKERS}",
                "</Proxy>",
                f"ProxyPass /add{b} balancer://add{b}",
                "<Location /balancer-manager>",
                "    SetHandler balancer-manager",
                "    Require all granted",
                "</Location>",
            ])
            conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    @staticmethod
    def _domain(env, b):
        return f"baladd{b}.{env.http_tld}"

    def _request(self, env, b, conn, method, path, body=None):
        domain = self._domain(env, b)
        headers = {"Host": domain, "Referer": f"http://{domain}/balancer-manager"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        return r.status, r.read().decode(errors="replace")

    def _add_workers(self, env, b, results):
        conn = http.client.HTTPConnection("127.0.0.1", env.http_port, timeout=10)
        try:
            _, page = self._request(env, b, conn, "GET", "/balancer-manager")
            m = re.search(rf"b=add{b}&[^\"]*?nonce=([0-9a-fA-F-]+)",
                          page.replace("&amp;", "&"))
            assert m, f"no nonce for balancer://add{b}"
            statuses = []
            for w in range(NWORKERS):
                body = (f"b=add{b}&b_wyes=1&nonce={m.group(1)}&b_nwrkr="
                        + urllib.parse.quote(_worker_url(b, w), safe=""))
                status, _ = self._request(env, b, conn, "POST", "/balancer-manager",
                                          body.encode())
                statuses.append(status)
            results[b] = statuses
        except Exception as e:
            results[b] = repr(e)
        finally:
            conn.close()

    def test_proxy_12_01_concurrent_adds(self, env):
        results = {}
        threads = [threading.Thread(target=self._add_workers, args=(env, b, results))
                   for b in range(NBALANCERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        for b in range(NBALANCERS):
            assert results.get(b) == [200] * NWORKERS, \
                f"adds to balancer://add{b} failed: {results.get(b)}"

        # Each balancer lists exactly the workers added to it (a child syncs
        # those the other children added from shm).
        for b in range(NBALANCERS):
            conn = http.client.HTTPConnection("127.0.0.1", env.http_port, timeout=10)
            try:
                status, page = self._request(env, b, conn, "GET", "/balancer-manager?xml=1")
            finally:
                conn.close()
            assert status == 200
            m = re.search(rf"<httpd:name>balancer://add{b}</httpd:name>(.*?)</httpd:balancer>",
                          page, re.S)
            assert m, f"balancer://add{b} not listed"
            names = re.findall(r"<httpd:worker>\s*<httpd:name>([^<]*)</httpd:name>",
                               m.group(1))
            assert sorted(names) == sorted(_worker_url(b, w) for w in range(NWORKERS)), \
                f"balancer://add{b} lists {len(names)} workers, not the {NWORKERS} added"
