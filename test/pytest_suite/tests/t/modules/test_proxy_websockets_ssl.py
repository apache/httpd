r"""Translated from t/modules/proxy_websockets_ssl.t -- wss:// to a lua backend.

Like proxy_websockets.t but over TLS (wss://) directly to the lua websocket
handler on the mod_ssl vhost. Needs mod_ssl, mod_proxy_http and mod_lua plus an
async websocket client. mod_lua is not built locally, so this SKIPs via
@need_module; even with lua present there is no httpx/stdlib async websocket
client to drive the wss:// ping/echo exchange faithfully.

Perl original:
    plan tests => 2, need 'AnyEvent::WebSocket::Client', need 'URI::wss',
        need_module('ssl', 'proxy_http', 'lua'), need_min_apache_version('2.4.47');
"""

import pytest

from apache_pytest import need_min_apache_version, need_module


@need_module("ssl", "proxy_http", "lua")
@need_min_apache_version("2.4.47")
def test_proxy_websockets_ssl(http):
    pytest.skip(
        "needs an async websocket client (AnyEvent::WebSocket::Client) speaking "
        "wss://; no httpx/stdlib equivalent in the framework to faithfully drive "
        "the TLS ping/echo exchange"
    )
