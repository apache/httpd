import re

import pytest

from pyhttpd.conf import HttpdConf

# balancer-manager parameter handling.  The manager only acts on a POST
# whose Referer is this server and whose nonce matches the balancer's, so the
# nonce is pinned in the config and every request carries a Referer; a
# request which fails either check is silently ignored, which is why the
# first test is a positive control.
#
# Two members are needed: with a single member recalc_factors() pins its load
# factor to 100 whatever was set, so a w_lf change would be unobservable.  The
# second must differ in hostname, not just path, or mod_proxy shares the
# first worker for it (AH01145) and there is still only one.
BALANCER = "pr628"
NONCE = "pr628nonce"
ALT_HOST = "localhost"


class TestBalancerManager:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        domain = f"test1.{env.http_tld}"
        conf = HttpdConf(env)
        conf.start_vhost(domains=[domain], port=env.http_port,
                         doc_root="htdocs/test1")
        conf.add([
            f"<Proxy balancer://{BALANCER}>",
            f"  BalancerMember {self.member(env)}",
            f"  BalancerMember http://{ALT_HOST}:{env.http_port}",
            f"  ProxySet nonce={NONCE}",
            "</Proxy>",
            f"ProxyPass /{BALANCER} balancer://{BALANCER}",
            "<Location /balancer-manager>",
            "  SetHandler balancer-manager",
            "</Location>",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def member(env):
        """The member every setting is applied to."""
        return f"http://127.0.0.1:{env.http_port}"

    def url(self, env):
        return env.mkurl("http", "test1", "/balancer-manager")

    def post(self, env, **params):
        """Submit worker/balancer settings as the manager's own form does."""
        url = self.url(env)
        body = "&".join([f"b={BALANCER}", f"w={self.member(env)}",
                         f"nonce={NONCE}"]
                        + [f"{k}={v}" for k, v in params.items()])
        r = env.curl_post_data(url, data=body,
                               options=["-H", f"Referer: {url}"])
        assert r.exit_code == 0, f"{r.stdout}{r.stderr}"
        assert r.response["status"] == 200
        return r

    def workers(self, env):
        """{name: (status tokens, load factor)} for every member, from the
        XML view."""
        url = self.url(env)
        r = env.curl_get(f"{url}?xml=1&b={BALANCER}",
                         options=["-H", f"Referer: {url}"])
        assert r.response["status"] == 200
        body = r.response["body"]
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        found = {}
        for block in re.findall(r"<httpd:worker>(.*?)</httpd:worker>",
                                body, re.S):
            name = re.search(r"<httpd:name>([^<]*)</httpd:name>", block)
            status = re.search(r"<httpd:status>([^<]*)</httpd:status>", block)
            lf = re.search(r"<httpd:loadfactor>([^<]*)</httpd:loadfactor>",
                           block)
            assert name and status and lf, f"incomplete worker:\n{block}"
            found[name.group(1)] = (status.group(1).split(), lf.group(1))
        assert len(found) == 2, f"expected two members:\n{body}"
        return found

    def worker(self, env):
        """(status tokens, load factor) of the member settings are applied
        to - the one that is not on ALT_HOST."""
        return next(v for k, v in self.workers(env).items()
                    if ALT_HOST not in k)

    # -- tests -----------------------------------------------------------

    # Control: a well-formed value is applied and cleared.  Proves the
    # nonce/Referer/POST plumbing, so the cases below fail for the right reason.
    def test_proxy_07_001(self, env):
        self.post(env, w_status_D="1")
        assert "Dis" in self.worker(env)[0]
        self.post(env, w_status_D="0")
        assert "Dis" not in self.worker(env)[0]

    # An out-of-range flag value must be rejected, not treated as "set".
    def test_proxy_07_002(self, env):
        self.post(env, w_status_D="0")
        self.post(env, w_status_D="2")
        status, _ = self.worker(env)
        assert "Dis" not in status, \
            f"w_status_D=2 was accepted as 'set': {status}"

    # A non-numeric value must be rejected, not coerced to 0 and used to
    # clear a flag that was set.
    def test_proxy_07_003(self, env):
        self.post(env, w_status_D="1")
        assert "Dis" in self.worker(env)[0]
        self.post(env, w_status_D="junk")
        status, _ = self.worker(env)
        try:
            assert "Dis" in status, \
                f"w_status_D=junk cleared the flag: {status}"
        finally:
            self.post(env, w_status_D="0")

    # A load factor with trailing garbage must be rejected, not parsed up to
    # the garbage and applied.
    def test_proxy_07_004(self, env):
        assert self.worker(env)[1] == "1.00"
        self.post(env, w_lf="1.5junk")
        workers = self.workers(env)
        _, lf = self.worker(env)
        try:
            assert lf == "1.00", \
                f"w_lf=1.5junk was applied: {workers}"
        finally:
            self.post(env, w_lf="1")
