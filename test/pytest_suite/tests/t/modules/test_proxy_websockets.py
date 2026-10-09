r"""Translated from t/modules/proxy_websockets.t -- mod_proxy_wstunnel + lua.

The Perl test drives an AnyEvent::WebSocket::Client against ws://.../proxy/wsoc
(a lua websocket backend reverse-proxied via mod_proxy_http), sends a series of
ping frames plus a "sendquit", and asserts every frame is echoed back unchanged.

This needs mod_lua (the websocket backend) and a websocket client. mod_lua is
not built locally, so the test SKIPs via @need_module("lua", "proxy_http").
Even where lua is present, the framework has no async websocket client
(AnyEvent::WebSocket::Client has no httpx analog), so the frame-exchange body of
the test is skipped with a precise reason rather than faked.

Perl original:
    plan tests => 2, need 'AnyEvent::WebSocket::Client', need 'URI::ws',
        need_module('proxy_http', 'lua'), need_min_apache_version('2.4.47');
"""

import pytest

from apache_pytest import need_min_apache_version, need_module


@need_module("lua", "proxy_http")
@need_min_apache_version("2.4.47")
def test_proxy_websockets(http):
    pytest.skip(
        "needs an async websocket client (AnyEvent::WebSocket::Client); "
        "no httpx/stdlib equivalent in the framework to faithfully drive the "
        "ws:// ping/echo exchange"
    )
