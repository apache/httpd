#!/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
import time

import websockets.sync.server as ws
from websockets.exceptions import ConnectionClosedError

log = logging.getLogger(__name__)

logging.basicConfig(
    format="[%(asctime)s] %(message)s",
    level=logging.DEBUG,
)


async def echo(websocket):
    try:
        async for message in websocket:
            try:
                log.info(f'got request {message}')
            except Exception as e:
                log.error(f'error {e} getting path from {message}')
            await websocket.send(message)
    except ConnectionClosedError:
        pass


def on_conn(conn):
    rpath = str(conn.request.path)
    pcomps = rpath[1:].split('/')
    if len(pcomps) == 0:
        pcomps = ['echo']  # default handler
    log.info(f'connection for {pcomps}')
    if pcomps[0] == 'echo':
        log.info(f'/echo endpoint')
        for message in conn:
            conn.send(message)
    elif pcomps[0] == 'text':
        conn.send('hello!')
    elif pcomps[0] == 'file':
        if len(pcomps) < 2:
            conn.close(code=4999, reason='unknown file')
            return
        fpath = os.path.join('../', pcomps[1])
        if not os.path.exists(fpath):
            conn.close(code=4999, reason='file not found')
            return
        bufsize = 0
        if len(pcomps) > 2:
            bufsize = int(pcomps[2])
        if bufsize <= 0:
            bufsize = 16*1024
        delay_ms = 0
        if len(pcomps) > 3:
            delay_ms = int(pcomps[3])
        with open(fpath, 'r+b') as fd:
            while True:
                buf = fd.read(bufsize)
                if buf is None or len(buf) == 0:
                    break
                conn.send(buf)
                if delay_ms > 0:
                    time.sleep(delay_ms/1000)
    else:
        log.info(f'unknown endpoint: {rpath}')
        conn.close(code=4999, reason='path unknown')
    conn.close(code=1000, reason='')


def run_server(port):
    log.info(f'starting server on port {port}')
    server = ws.serve(handler=on_conn, host="localhost", port=port)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(prog='scorecard', description="""
        Run a websocket echo server.
        """)
    parser.add_argument("--port", type=int,
                        default=0, help="port to listen on")
    args = parser.parse_args()

    if args.port == 0:
        sys.stderr.write('need --port\n')
        sys.exit(1)

    logging.basicConfig(
        format="%(asctime)s %(message)s",
        level=logging.DEBUG,
    )
    run_server(args.port)


if __name__ == "__main__":
    main()
