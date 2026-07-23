r"""Translated from t/ssl/proxy.t.

Drives five proxy front-end virtual hosts, each a different http/https <->
http/https combination, and for each checks:

  * GET /                            -> 200
  * GET a CGI with folded headers    -> 200 (nph-foldhdr.pl)
  * (https backend only) the backend presents the configured proxy client cert
    (client_ok), so:
      - GET /verify                  -> 200 (valid proxy ccert)
      - GET /require/snakeoil        -> 403 (cert is client_ok, not snakeoil)
      - GET /require-ssl-cgi/env.pl  -> 200, with X-Forwarded-Host == frontend
        host:port and SSL_CLIENT_S_DN_CN == "client_ok"
  * ProxyPassReverse rewrites a backend redirect's Location to the frontend URL.

The five vhosts are selected via the http fixture's module()/scheme() (the Perl
Apache::TestRequest::module/scheme). The optional eat_post body-size sub-tests
(Apache::TestCommon::run_post_test) are skipped: that harness is not ported.
"""

import pytest

from apache_pytest import need_module, need_ssl
from apache_pytest.testapi import t_cmp

FRONTEND = {
    "proxy_http_https": "http",
    "proxy_https_https": "https",
    "proxy_https_http": "https",
    "proxy_http_https_proxy_section": "http",
    "proxy_https_https_proxy_section": "https",
}
BACKEND = {
    "proxy_http_https": "https",
    "proxy_https_https": "https",
    "proxy_https_http": "http",
    "proxy_http_https_proxy_section": "https",
    "proxy_https_https_proxy_section": "https",
}


def _parse_env(body: str) -> dict:
    out = {}
    for line in body.replace("\r", "\n").split("\n"):
        if " = " not in line:
            continue
        key, val = line.split(" = ", 1)
        out[key.strip()] = val.strip()
    return out


@need_ssl()
@need_module("proxy", "proxy_http")
@pytest.mark.parametrize("module", sorted(FRONTEND))
def test_proxy(http, module):
    scheme = FRONTEND[module]
    http.module(module)
    http.scheme(scheme)
    hostport = http.hostport()

    assert t_cmp(http.GET("/").status_code, 200), f"/ with {module} ({scheme})"
    assert t_cmp(
        http.GET("/modules/cgi/nph-foldhdr.pl").status_code, 200
    ), "CGI script with folded headers"

    if BACKEND[module] == "https":
        # /verify redirects to /verify/; follow it as the Perl GET would.
        assert t_cmp(
            http.GET("/verify", redirect_ok=True).status_code, 200
        ), "using valid proxyssl client cert"
        assert t_cmp(
            http.GET("/require/snakeoil").status_code, 403
        ), "using invalid proxyssl client cert"

        res = http.GET("/require-ssl-cgi/env.pl")
        assert t_cmp(res.status_code, 200), "protected cgi script"
        env = _parse_env(res.text)
        assert t_cmp(env.get("HTTP_X_FORWARDED_HOST"), hostport), (
            "X-Forwarded-Host header"
        )
        assert t_cmp(env.get("SSL_CLIENT_S_DN_CN"), "client_ok"), (
            "client subject common name"
        )

    # ProxyPassReverse must rewrite the backend redirect's Location to the
    # frontend server (RedirectOK off so we can inspect the Location header).
    res = http.GET("/modules")
    location = res.headers.get("Location", "NONE")
    assert t_cmp(
        location, f"{scheme}://{hostport}/modules/"
    ), "ProxyPassReverse Location rewrite"
