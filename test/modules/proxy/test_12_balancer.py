"""The workers of balancers at run time: added through the balancer-managers,
listed by them, by mod_status and by ProxyPassReverse.

Each class says what it covers.
"""

import http.client
import re
import threading
import urllib.parse

import pytest

from pyhttpd.conf import HttpdConf

NBALANCERS = 16
NVHOSTS = 8
NWORKERS = 100
WALKS = ["page", "status", "reverse-map"]


def _worker_url(b, w):
    return f"http://127.{b + 1}.0.{w + 1}:{20000 + w}"


def _member_url(env, name="app"):
    return f"http://127.0.0.1:{env.http_port}/{name}"


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


class TestBalancerVhostCopies:
    """Workers added at run time to the vhost copies of one balancer.

    A balancer of the main server that vhosts with their own proxy
    configuration use is copied into each of them, and the copies share its
    workers array: an add through one vhost's balancer-manager grows the array
    that the other vhosts' balancer-managers walk at the same time, so all the
    copies must take the same lock for it.  mod_status' proxy section and
    ProxyPassReverse walk the array too, polled during the adds.
    """

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        conf = HttpdConf(env)
        conf.add([
            "<Proxy balancer://shared>",
            f"    BalancerMember {_member_url(env)}",
            f"    ProxySet growth={NWORKERS}",
            "</Proxy>",
            "ExtendedStatus On",
            "ProxyStatus On",
            "<Location /server-status>",
            "    SetHandler server-status",
            "    Require all granted",
            "</Location>",
        ])
        for v in range(NVHOSTS):
            conf.start_vhost(domains=[cls._domain(env, v)], port=env.http_port)
            conf.add([
                "ProxyPass /shared balancer://shared",
                # /rmap/* is proxied to this vhost's /redir/*, redirected to
                # the configured member (hit) or to no member (miss), the
                # Location mapped by the walk of balancer://shared's workers
                "ProxyPreserveHost On",
                f"ProxyPass /rmap/ http://127.0.0.1:{env.http_port}/redir/",
                "ProxyPassReverse /mapped balancer://shared/",
                f"Redirect /redir/hit {_member_url(env)}/x",
                "Redirect /redir/miss http://127.0.0.2:1/x",
                "<Location /balancer-manager>",
                "    SetHandler balancer-manager",
                "    Require all granted",
                "</Location>",
            ])
            conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    @staticmethod
    def _domain(env, v):
        return f"balcopy{v}.{env.http_tld}"

    def _request(self, env, v, conn, method, path, body=None):
        domain = self._domain(env, v)
        headers = {"Host": domain, "Referer": f"http://{domain}/balancer-manager"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        return r.status, r.read().decode(errors="replace")

    def _list_workers(self, env, v, conn):
        status, page = self._request(env, v, conn, "GET", "/balancer-manager?xml=1")
        assert status == 200
        m = re.search(r"<httpd:name>balancer://shared</httpd:name>(.*?)</httpd:balancer>",
                      page, re.S)
        assert m, f"balancer://shared not listed on vhost {v}"
        return re.findall(r"<httpd:worker>\s*<httpd:name>([^<]*)</httpd:name>", m.group(1))

    def _add_workers(self, env, v, results):
        conn = http.client.HTTPConnection("127.0.0.1", env.http_port, timeout=10)
        try:
            _, page = self._request(env, v, conn, "GET", "/balancer-manager")
            m = re.search(r"b=shared&[^\"]*?nonce=([0-9a-fA-F-]+)",
                          page.replace("&amp;", "&"))
            assert m, f"no nonce for balancer://shared on vhost {v}"
            statuses = []
            for w in range(NWORKERS):
                body = (f"b=shared&b_wyes=1&nonce={m.group(1)}&b_nwrkr="
                        + urllib.parse.quote(_worker_url(v, w), safe=""))
                status, _ = self._request(env, v, conn, "POST", "/balancer-manager",
                                          body.encode())
                statuses.append(status)
            results[v] = statuses
        except Exception as e:
            results[v] = repr(e)
        finally:
            conn.close()

    def _status_workers(self, env, v, conn):
        status, page = self._request(env, v, conn, "GET", "/server-status?auto")
        assert status == 200
        m = re.search(r"^ProxyBalancer\[(\d+)\]Name: balancer://shared$", page, re.M)
        assert m, f"balancer://shared not in the status of vhost {v}"
        return re.findall(rf"^ProxyBalancer\[{m.group(1)}\]Worker\[\d+\]Name: (.*)$",
                          page, re.M)

    def _reverse_map(self, env, v, conn, what):
        conn.request("GET", f"/rmap/{what}", headers={"Host": self._domain(env, v)})
        r = conn.getresponse()
        r.read()
        assert r.status == 302, f"/rmap/{what} on vhost {v}: {r.status}"
        return r.getheader("Location")

    def _walk(self, env, v, conn, kind):
        if kind == "page":
            self._list_workers(env, v, conn)
        elif kind == "status":
            assert _member_url(env) in self._status_workers(env, v, conn)
        else:
            loc = self._reverse_map(env, v, conn, "hit")
            assert loc.endswith("/mapped/x"), f"/rmap/hit on vhost {v}: {loc}"
            loc = self._reverse_map(env, v, conn, "miss")
            assert loc == "http://127.0.0.2:1/x", f"/rmap/miss on vhost {v}: {loc}"

    def _walk_workers(self, env, v, kind, done, results):
        conn = http.client.HTTPConnection("127.0.0.1", env.http_port, timeout=10)
        try:
            while not done.is_set():
                self._walk(env, v, conn, kind)
            results[(v, kind)] = "ok"
        except Exception as e:
            results[(v, kind)] = repr(e)
        finally:
            conn.close()

    def test_proxy_12_02_concurrent_adds_and_walks(self, env):
        added, walked = {}, {}
        done = threading.Event()
        adders = [threading.Thread(target=self._add_workers, args=(env, v, added))
                  for v in range(NVHOSTS)]
        walkers = [threading.Thread(target=self._walk_workers,
                                    args=(env, v, kind, done, walked))
                   for v in range(NVHOSTS) for kind in WALKS]
        for t in walkers + adders:
            t.start()
        for t in adders:
            t.join(timeout=120)
        done.set()
        for t in walkers:
            t.join(timeout=30)
        for v in range(NVHOSTS):
            assert added.get(v) == [200] * NWORKERS, \
                f"adds through vhost {v} failed: {added.get(v)}"
            for kind in WALKS:
                assert walked.get((v, kind)) == "ok", \
                    f"{kind} walk on vhost {v} failed: {walked.get((v, kind))}"

        # Each vhost lists the workers added through it, and no other than
        # those added through the vhosts (the copies share the array).
        everything = {_worker_url(v, w) for v in range(NVHOSTS) for w in range(NWORKERS)}
        everything.add(_member_url(env))
        for v in range(NVHOSTS):
            # the balancer-manager syncs the child's workers, the status
            # that follows on the same connection lists the same
            conn = http.client.HTTPConnection("127.0.0.1", env.http_port, timeout=10)
            try:
                names = self._list_workers(env, v, conn)
                in_status = self._status_workers(env, v, conn)
            finally:
                conn.close()
            assert sorted(in_status) == sorted(names), \
                f"vhost {v} lists other workers in its status than in its balancer-manager"
            assert len(names) == len(set(names)), f"vhost {v} lists a worker twice"
            assert set(names) <= everything, \
                f"vhost {v} lists unknown workers: {sorted(set(names) - everything)[:5]}"
            mine = {_worker_url(v, w) for w in range(NWORKERS)}
            assert mine <= set(names), \
                f"vhost {v} misses {len(mine - set(names))} of the workers added through it"
