"""The workers of balancers at run time: added through the balancer-managers,
listed by them, by mod_status and by ProxyPassReverse, with and without a
growth, and persisted.

Each class says what it covers.
"""

import glob
import http.client
import os
import re
import threading
import time
import urllib.parse

import pytest

from pyhttpd.conf import HttpdConf

NBALANCERS = 16
NVHOSTS = 8
NWORKERS = 100
WALKS = ["page", "status", "reverse-map"]
NFIXED_VHOSTS = 4
NFIXED_WORKERS = 50
WALK_SECS = 3


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


def _fixed_domain(env, v):
    return f"balfixed{v}.{env.http_tld}"


def _vhost_lines(env, balancer, last_member):
    # /rmap/* is proxied to the vhost's own /redir/*, redirected to the
    # member last_member (hit) or to no member (miss), the Location mapped
    # by the walk of the balancer's workers
    return [
        f"ProxyPass /{balancer} balancer://{balancer}",
        "ProxyPreserveHost On",
        f"ProxyPass /rmap/ http://127.0.0.1:{env.http_port}/redir/",
        f"ProxyPassReverse /mapped balancer://{balancer}/",
        f"Redirect /redir/hit {_member_url(env, last_member)}/x",
        "Redirect /redir/miss http://127.0.0.2:1/x",
        "<Location /balancer-manager>",
        "    SetHandler balancer-manager",
        "    Require all granted",
        "</Location>",
    ]


STATUS_LINES = [
    "ExtendedStatus On",
    "ProxyStatus On",
    "<Location /server-status>",
    "    SetHandler server-status",
    "    Require all granted",
    "</Location>",
]


class Client:

    def __init__(self, env, v, balancer):
        self.env = env
        self.domain = _fixed_domain(env, v)
        self.balancer = balancer
        self.conn = http.client.HTTPConnection("127.0.0.1", env.http_port, timeout=10)

    def close(self):
        self.conn.close()

    def request(self, method, path, body=None):
        headers = {"Host": self.domain,
                   "Referer": f"http://{self.domain}/balancer-manager"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.conn.request(method, path, body=body, headers=headers)
        r = self.conn.getresponse()
        return r.status, r.getheader("Location"), r.read().decode(errors="replace")

    def page_workers(self):
        status, _, page = self.request("GET", "/balancer-manager?xml=1")
        assert status == 200
        m = re.search(rf"<httpd:name>balancer://{self.balancer}</httpd:name>(.*?)"
                      r"</httpd:balancer>", page, re.S)
        assert m, f"balancer://{self.balancer} not listed on {self.domain}"
        return re.findall(r"<httpd:worker>\s*<httpd:name>([^<]*)</httpd:name>", m.group(1))

    def status_workers(self):
        status, _, page = self.request("GET", "/server-status?auto")
        assert status == 200
        m = re.search(rf"^ProxyBalancer\[(\d+)\]Name: balancer://{self.balancer}$",
                      page, re.M)
        assert m, f"balancer://{self.balancer} not in the status of {self.domain}"
        return re.findall(rf"^ProxyBalancer\[{m.group(1)}\]Worker\[\d+\]Name: (.*)$",
                          page, re.M)

    def reverse_map(self, what):
        status, loc, _ = self.request("GET", f"/rmap/{what}")
        assert status == 302, f"/rmap/{what} on {self.domain}: {status}"
        return loc

    def check_walks(self, members):
        """The page (first: it syncs the child's workers), the status and
        ProxyPassReverse see exactly members."""
        assert sorted(self.page_workers()) == sorted(members)
        assert sorted(self.status_workers()) == sorted(members)
        loc = self.reverse_map("hit")
        assert loc.endswith("/mapped/x"), f"/rmap/hit on {self.domain}: {loc}"
        loc = self.reverse_map("miss")
        assert loc == "http://127.0.0.2:1/x", f"/rmap/miss on {self.domain}: {loc}"

    def add_worker(self, url):
        _, _, page = self.request("GET", "/balancer-manager")
        m = re.search(rf"b={self.balancer}&[^\"]*?nonce=([0-9a-fA-F-]+)",
                      page.replace("&amp;", "&"))
        assert m, f"no nonce for balancer://{self.balancer} on {self.domain}"
        body = (f"b={self.balancer}&b_wyes=1&nonce={m.group(1)}&b_nwrkr="
                + urllib.parse.quote(url, safe=""))
        status, _, _ = self.request("POST", "/balancer-manager", body.encode())
        return status


def _walk_loop(env, v, balancer, members, done, results, key):
    c = Client(env, v, balancer)
    try:
        while not done.is_set():
            if members is None:
                c.page_workers()
                c.status_workers()
                c.reverse_map("miss")
            else:
                c.check_walks(members)
        results[key] = "ok"
    except Exception as e:
        results[key] = repr(e)
    finally:
        c.close()


class TestBalancerNoGrowth:
    """Balancers whose workers can't change at run time.

    No worker can be added to a balancer without a growth: all of its worker
    slots hold configured workers, so its workers array is walked without the
    lock (balancer-manager, mod_status' proxy section, ProxyPassReverse).
    balancer://fixed has no growth, its copies are in NFIXED_VHOSTS vhosts.
    """

    MEMBERS = ["app0", "app1", "app2"]

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        conf = HttpdConf(env)
        conf.add(["<Proxy balancer://fixed>"]
                 + [f"    BalancerMember {_member_url(env, m)}" for m in cls.MEMBERS]
                 + ["</Proxy>"] + STATUS_LINES)
        for v in range(NFIXED_VHOSTS):
            conf.start_vhost(domains=[_fixed_domain(env, v)], port=env.http_port)
            conf.add(_vhost_lines(env, "fixed", cls.MEMBERS[-1]))
            conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    def test_proxy_12_03_walks(self, env):
        members = [_member_url(env, m) for m in self.MEMBERS]
        results = {}
        done = threading.Event()
        threads = [threading.Thread(target=_walk_loop,
                                    args=(env, v, "fixed", members, done, results, (v, n)))
                   for v in range(NFIXED_VHOSTS) for n in range(4)]
        for t in threads:
            t.start()
        time.sleep(WALK_SECS)
        done.set()
        for t in threads:
            t.join(timeout=WALK_SECS + 30)
        for v in range(NFIXED_VHOSTS):
            for n in range(4):
                assert results.get((v, n)) == "ok", \
                    f"walks on vhost {v} failed: {results.get((v, n))}"

    def test_proxy_12_04_no_add(self, env):
        members = [_member_url(env, m) for m in self.MEMBERS]
        c = Client(env, 0, "fixed")
        try:
            c.add_worker(_member_url(env, "added"))
            c.check_walks(members)
        finally:
            c.close()
        env.httpd_error_log.ignore_recent(lognos=["AH10164"])


class TestBalancerMixedGrowth:
    """The vhost copies of a balancer share its workers array, and some
    copies may have a growth when others have none.  balancer://mixed has no
    growth in the main server's copy, inherited by vhost 0, and a growth in
    the copies of the other vhosts: this checks that the mixed configuration
    works, a copy without growth listing its members and serving while the
    other vhosts' copies add workers.  It can't observe the lock."""

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        conf = HttpdConf(env)
        conf.add(["<Proxy balancer://mixed>",
                  f"    BalancerMember {_member_url(env, 'app0')}",
                  "</Proxy>"] + STATUS_LINES)
        for v in range(NFIXED_VHOSTS):
            conf.start_vhost(domains=[_fixed_domain(env, v)], port=env.http_port)
            if v:
                conf.add(["<Proxy balancer://mixed>",
                          f"    ProxySet growth={NFIXED_WORKERS}",
                          "</Proxy>"])
            conf.add(_vhost_lines(env, "mixed", "app0"))
            conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    def _add_workers(self, env, v, results):
        c = Client(env, v, "mixed")
        try:
            results[v] = [c.add_worker(_worker_url(v, w))
                          for w in range(NFIXED_WORKERS)]
        except Exception as e:
            results[v] = repr(e)
        finally:
            c.close()

    def test_proxy_12_05_walk_while_others_grow(self, env):
        added, walked = {}, {}
        done = threading.Event()
        adders = [threading.Thread(target=self._add_workers, args=(env, v, added))
                  for v in range(1, NFIXED_VHOSTS)]
        walkers = [threading.Thread(target=_walk_loop,
                                    args=(env, 0, "mixed", None, done, walked, n))
                   for n in range(8)]
        for t in walkers + adders:
            t.start()
        for t in adders:
            t.join(timeout=120)
        done.set()
        for t in walkers:
            t.join(timeout=30)
        for v in range(1, NFIXED_VHOSTS):
            assert added.get(v) == [200] * NFIXED_WORKERS, f"adds on vhost {v}: {added.get(v)}"
        for n in range(8):
            assert walked.get(n) == "ok", f"walk {n} on vhost 0 failed: {walked.get(n)}"
        # A vhost lists the workers added through it (its balancer-manager
        # syncs them from its copy's slots); the copies share one array, so
        # it may list the others' too, in the children that added them.
        for v in range(NFIXED_VHOSTS):
            c = Client(env, v, "mixed")
            try:
                names = c.page_workers()
            finally:
                c.close()
            assert len(names) == len(set(names)), f"vhost {v} lists a worker twice"
            mine = {_member_url(env, "app0")}
            if v:
                mine |= {_worker_url(v, w)
                         for w in range(NFIXED_WORKERS)}
            assert mine <= set(names), f"vhost {v} misses {len(mine - set(names))} workers"


class TestBalancerPersist:
    """balancer://persist with BalancerPersist: a worker added with a growth,
    then restarts with and without the growth.  The balancer's configuration
    is in a file of its own, included, so that a graceful restart reads it
    changed."""

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        cls._install(env, ["app0"], 1)
        conf = HttpdConf(env)
        conf.add(STATUS_LINES + [f"Include {cls._conf_path(env)}"])
        conf.install()

    @staticmethod
    def _conf_path(env):
        return os.path.join(env.gen_dir, "balancer-persist.conf")

    @classmethod
    def _install(cls, env, members, growth):
        lines = (["BalancerPersist On", "<Proxy balancer://persist>"]
                 + [f"    BalancerMember {_member_url(env, m)}" for m in members]
                 + ([f"    ProxySet growth={growth}"] if growth else [])
                 + ["</Proxy>",
                    f"<VirtualHost *:{env.http_port}>",
                    f"    ServerName {_fixed_domain(env, 0)}",
                    "    BalancerPersist On"]
                 + [f"    {line}" for line in _vhost_lines(env, "persist", members[-1])]
                 + ["</VirtualHost>"])
        with open(cls._conf_path(env), "w") as fd:
            fd.write("\n".join(lines) + "\n")

    def _fresh_start_with_added(self, env):
        """Start with app0 and a growth of 1, add the worker "added"."""
        assert env.apache_stop() == 0
        for f in glob.glob(os.path.join(env.server_dir, "logs", "slotmem-shm-*.persist")):
            os.remove(f)
        self._install(env, ["app0"], 1)
        assert env.apache_restart() == 0
        c = Client(env, 0, "persist")
        try:
            assert c.add_worker(_member_url(env, "added")) == 200
            assert sorted(c.page_workers()) == sorted([_member_url(env, "app0"),
                                                       _member_url(env, "added")])
        finally:
            c.close()

    def _check(self, env, members):
        c = Client(env, 0, "persist")
        try:
            c.check_walks([_member_url(env, m) for m in members])
        finally:
            c.close()

    def test_proxy_12_06_persist_no_growth_graceful(self, env):
        # Two members and no growth: as many slots as the file restored, so
        # the added worker's slot goes to app1.
        self._fresh_start_with_added(env)
        self._install(env, ["app0", "app1"], 0)
        assert env.apache_reload() == 0
        self._check(env, ["app0", "app1"])

    def test_proxy_12_07_persist_no_growth_full_restart(self, env):
        self._fresh_start_with_added(env)
        self._install(env, ["app0", "app1"], 0)
        assert env.apache_restart() == 0
        self._check(env, ["app0", "app1"])
        # One member and no growth: one slot, the file (two) is not restored.
        self._install(env, ["app0"], 0)
        assert env.apache_restart() == 0
        self._check(env, ["app0"])
        env.httpd_error_log.ignore_recent(lognos=["AH02551"])

    def test_proxy_12_08_persist_growth_kept(self, env):
        # The same growth: the added worker comes back from the file.
        self._fresh_start_with_added(env)
        assert env.apache_restart() == 0
        added = sorted([_member_url(env, "app0"), _member_url(env, "added")])
        c = Client(env, 0, "persist")
        try:
            assert sorted(c.page_workers()) == added
            assert sorted(c.status_workers()) == added
        finally:
            c.close()
