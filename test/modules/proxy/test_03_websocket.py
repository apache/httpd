import asyncio
import logging
import time
from threading import Thread

import pytest
try:
    import websockets
except ImportError:
    pass

from modules.proxy.env import ProxyTestEnv
from pyhttpd.conf import HttpdConf

log = logging.getLogger(__name__)

wsport = 9080


class WsEchoServer:

    def __init__(self, port):
        self.port = port
        self._thread = None

    async def ws_handler(self, ws, _path):
        while ws.open:
            data = await ws.recv()
            log.info(f"received: ")
            if data == "quit":
                await ws.close()
                break
            await ws.send(data)

    def start(self):
        def process(self):
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            start_ws = websockets.serve(self.ws_handler, "localhost", self.port)
            self.loop.run_until_complete(start_ws)
            self.loop.run_forever()
        self._thread = Thread(target=process, daemon=True, args=[self])
        self._thread.start()

    def stop(self):
        pass


@pytest.mark.skipif(condition=not ProxyTestEnv.has_python_package('websockets'),
                    reason="No python websockets installed")
class TestProxyWebsocket:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(cls, env: ProxyTestEnv):
        server = WsEchoServer(port=wsport)
        server.start()
        conf = HttpdConf(env)
        conf.add([
            f"ProxyPass /ws ws://localhost:{wsport}",
            "LogLevel http:trace4 http1:trace4",
            "<IfModule mod_lua.c>",
            "  AddHandler lua-script .lua ",
            f"  ProxyPass /ws-lua ws://localhost:{env.http_port}/lua/websockets.lua",
            "</Ifmodule>",
        ])
        conf.install()
        assert env.apache_restart() == 0
        yield
        server.stop()

    async def send_echo_msgs(self, uri, msgs):
        ws = await websockets.connect(uri=uri)
        for msg in msgs:
            await ws.send(msg)
            if "quit" == msg:
                break
            resp = await ws.recv()
            if resp != msg:
                await ws.close()
                assert self.resp == msg
                return
        await ws.close()

    def test_proxy_03_001(self, env):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            asyncio.ensure_future(self.send_echo_msgs(
                uri=f"ws://localhost:{env.http_port}/ws",
                msgs=['hello!']
            ))
        )

    @pytest.mark.skipif(condition=not ProxyTestEnv.has_shared_module("lua"),
                        reason="mod_lua not available")
    def test_proxy_03_010(self, env):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            asyncio.ensure_future(self.send_echo_msgs(
                uri=f"ws://localhost:{env.http_port}/ws-lua",
                msgs=['hello!', 'quit']
            ))
        )



