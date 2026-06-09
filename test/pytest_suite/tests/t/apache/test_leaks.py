r"""Translated from t/apache/leaks.t -- check c->pool memory does not grow
across requests on a single keep-alive connection (mod_memory_track).

The Perl original gated on mod_memory_track being active (probed at runtime by
GET /memory_track returning 200). httpx does not guarantee a single persistent
connection across requests, so the connection-id check is preserved: if the
connection id changes the per-request check is skipped.

Skipped entirely if mod_memory_track is not activated.
"""

import pytest

URL = "/memory_track"
INIT_ITERS = 2000
ITERS = 500


def test_leaks(http):
    if http.GET_RC(URL) != 200:
        pytest.skip("mod_memory_track not activated")

    # initial iterations to bring workers to steady-state memory use
    for _ in range(INIT_ITERS):
        assert http.GET_RC(URL) == 200, "200 response"

    cid = -1
    mem = None
    for _ in range(ITERS):
        r = http.GET(URL)
        assert r.status_code == 200, "got response"
        key, conn_id, byte_str = r.text.strip().split(",")
        byts = int(byte_str)
        if cid == -1:
            cid = conn_id
            mem = byts
        elif cid != conn_id:
            # using a different connection -- can't compare; skip this iter
            continue
        else:
            assert byts <= mem, f"pool memory increased from {mem} to {byts}"
