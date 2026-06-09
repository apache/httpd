r"""Translated from t/modules/proxy_balancer.t -- mod_proxy_balancer.

Hits balancer-fronted backends (one per lbmethod that's present), POSTs bodies
through the balancer for failover (PR63891), then drives the balancer-manager:
extracts the CSRF nonce, attempts a worker add without the Referer (must fail),
and with the Referer (must succeed). Version- and module-gated throughout.

Perl original: plan tests => ..., need 'proxy_balancer', 'proxy_http'.
"""

import re

import pytest

from apache_pytest import need_module, t_cmp

ECHOS = ["A" * 8, "A" * 64, "A" * 2048, "A" * 4096]


def _get_nonce(http, body, balancer):
    """Extract the balancer-manager CSRF nonce for the given balancer name."""
    for query in re.split(r"\?b=", body):
        if re.search(balancer, query):
            for var in re.split(r"&amp;", query):
                if re.search("nonce=", var):
                    for nonce in re.split("nonce=", var):
                        idx = nonce.find('"')
                        nonce = nonce[:idx] if idx != -1 else nonce
                        if re.match(r"^[0-9a-fA-F-]+$", nonce):
                            return nonce
                    break
            break
    return None


@need_module("proxy_balancer", "proxy_http")
def test_proxy_balancer(http):
    http.module("proxy_http_balancer")
    try:
        if http.have_module("lbmethod_byrequests"):
            r = http.GET("/baltest1/index.html")
            assert t_cmp(r.status_code, 200), "Balancer did not die"
        if http.have_module("lbmethod_bytraffic"):
            r = http.GET("/baltest2/index.html")
            assert t_cmp(r.status_code, 200), "Balancer did not die"
        if http.have_module("lbmethod_bybusyness"):
            r = http.GET("/baltest3/index.html")
            assert t_cmp(r.status_code, 200), "Balancer did not die"

        # PR63891 body failover (only meaningful on >= 2.4.42)
        if http.have_min_apache_version("2.4.42"):
            for t in ECHOS:
                r = http.POST("/baltest_echo_post", content=t.encode())
                assert t_cmp(r.status_code, 200), "failed over"
                assert t_cmp(r.text, t), "response body echoed"

        r = http.GET("/balancer-manager")
        assert t_cmp(r.status_code, 200), "Can't find balancer-manager"

        nonce = _get_nonce(http, r.text, "dynproxy")

        vars_ = http.vars()
        servername = vars_["servername"]
        port = vars_["port"]
        referer = {"Referer": f"http://{servername}:{port}/balancer-manager"}

        if http.have_min_apache_version("2.4.41"):
            # add a worker without the Referer -- should fail (no AJP worker)
            query = ("b_lbm=byrequests&b_tmo=0&b_max=0&b_sforce=0&b_ss=&b_nwrkr="
                     "ajp%3A%2F%2F%5B0%3A0%3A0%3A0%3A0%3A0%3A0%3A1%5D%3A8080&"
                     "b_wyes=1&b=dynproxy&nonce=" + str(nonce))
            r = http.POST("/balancer-manager", content=query.encode())
            assert t_cmp(r.status_code, 200), "request failed"
            assert not t_cmp(r.text, re.compile("ajp")), "AJP worker created"

        if (http.have_min_apache_version("2.4.49")
                and http.have_module("lbmethod_byrequests")):
            r = http.GET("/dynproxy")
            assert t_cmp(r.status_code, 503), "request should fail for /dynproxy"
            query = ("b_lbm=byrequests&b_tmo=0&b_max=0&b_sforce=0&b_ss=&b_nwrkr="
                     f"http%3A%2F%2F{servername}%3A{port}&b_wyes=1&b=dynproxy&"
                     f"nonce={nonce}")
            http.POST("/balancer-manager", content=query.encode(), headers=referer)
            query = (f"w=http%3A%2F%2F{servername}%3A{port}&b=dynproxy&"
                     f"w_status_D=0&nonce={nonce}")
            http.POST("/balancer-manager", content=query.encode(), headers=referer)
            r = http.GET("/dynproxy")
            assert t_cmp(r.status_code, 200), "request failed to /dynproxy"
    finally:
        http.module(None)
