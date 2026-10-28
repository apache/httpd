"""The ports the modules/ suite's httpd listens on.

By default the five test ports are free ports, picked per test environment
(full runs of both suites on event and worker showed no difference from the
fixed ports). Two options change that:

  --base-port N      use N, N+1, ... instead, e.g. to know the ports in advance
  --fixed-ports      use the build's config.ini ports (5001 ...), which is what
                     the suite used before; also what an environment created
                     without a pytest config gets

Tests read their ports from the environment (env.http_port etc.) and the
generated configuration, pebble's included, is built from the same values, so
any of the three works. Dynamic ports, and one directory per instance, are
what running several servers side by side (pytest-xdist) needs.
"""

import random
import socket
from typing import Dict, List

# config.ini key, in the order --base-port hands out consecutive numbers
PORT_KEYS = ("https_port", "http_port", "proxy_port", "http_port2", "ws_port")

# Below the ephemeral ranges of Linux (32768-) and macOS/BSD (49152-), so that
# a port is not taken by an outgoing connection between picking and binding.
DYNAMIC_RANGE = (20000, 30000)


def free_ports(count: int, host: str = "127.0.0.1") -> List[int]:
    """*count* distinct ports that nobody listens on right now."""
    socks, ports = [], []
    try:
        while len(ports) < count:
            port = random.randrange(*DYNAMIC_RANGE)
            if port in ports:
                continue
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind((host, port))
            except OSError:
                s.close()
                continue
            socks.append(s)
            ports.append(port)
    finally:
        # held until all are chosen, so they are distinct
        for s in socks:
            s.close()
    return ports


def resolve_ports(defaults: Dict[str, int], base_port: int = None,
                  fixed: bool = False) -> Dict[str, int]:
    """The ports to use, by PORT_KEYS name; *defaults* are the config.ini ones."""
    if base_port:
        return {key: base_port + i for i, key in enumerate(PORT_KEYS)}
    if fixed:
        return {key: defaults[key] for key in PORT_KEYS}
    return dict(zip(PORT_KEYS, free_ports(len(PORT_KEYS))))
