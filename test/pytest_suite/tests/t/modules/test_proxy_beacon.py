r"""Test for mod_proxy_beacon -- UDP backend announce -> balancer membership.

The reverse proxy (main server) binds a UDP socket on a loopback port to receive
announcements; a backend vhost sends BEACON datagrams to it carrying a routable
URL (see t/conf/proxy_beacon.conf.in). Both halves run in the same instance,
driven by the mod_watchdog singleton thread.

  Phase 1: the receiver logs each "BEACON" it receives (channel proof).
  Phase 2: on an announcement carrying url=, the proxy adds that backend as a
           member of balancer://beacon (reusing mod_proxy_balancer's
           balancer_manage) and enables it, so /announce routes to the backend.
  Phase 3: when a backend stops announcing for longer than ProxyBeaconTimeout, the
           proxy disables it (out of rotation); a later announcement re-enables
           it.
  Phase 4: announcements are authenticated with a pre-shared secret
           (ProxyBeaconSecret); the proxy drops any that aren't validly signed and
           fresh. A second backend sends to the same port with the WRONG secret
           and a decoy URL -- it must be rejected and never added.

The config sets ProxyBeaconTimeout=1s on the proxy and ProxyBeaconInterval=4s on the
legit backend, so each cycle is: announce (add/enable) -> stale after ~1s
(evict) -> next announce (re-enable). We assert that whole lifecycle from the
error_log (the reliable signal; cf. t/modules/heartbeat.t's log-scan approach),
prove the member serves traffic while enabled, and assert the wrong-secret
backend is rejected.

mod_watchdog runs its singleton in a child process, so (like heartbeat.t) this
is skipped under the prefork MPM.
"""

import time
from pathlib import Path

import pytest

from apache_pytest import need_module, t_cmp

# Backend announces every 4s; cover at least one full add/evict/re-enable cycle.
NB_SECONDS = 11


@need_module("proxy_beacon", "watchdog", "proxy_balancer", "proxy_http")
def test_proxy_beacon(http):
    if http.have_module("mpm_prefork"):
        pytest.skip("proxy_beacon not run under the prefork MPM")

    error_log = Path(http.vars("t_logs")) / "error_log"
    start = error_log.stat().st_size if error_log.exists() else 0

    # Prove the member serves while enabled: poll /announce right after startup
    # (the first announce enables it within ~1 announce interval).
    vars_ = http.vars()
    expected_body = f"welcome to {vars_['servername']}:{vars_['port']}"
    served = False
    deadline = time.time() + 6
    while time.time() < deadline:
        r = http.GET("/beacon/index.html")
        if r.status_code == 200 and expected_body in r.text:
            served = True
            break
        time.sleep(0.5)
    assert served, "request through balancer://beacon never reached the backend"

    # Let the add -> evict -> re-enable lifecycle play out.
    time.sleep(NB_SECONDS)

    with error_log.open("r", errors="replace") as fh:
        fh.seek(start)
        loglines = fh.read().splitlines()

    # Announcements are received and carry a routable url=.
    received = [ln for ln in loglines if "received: BEACON" in ln]
    assert received, "no announcements received by the SUB"
    assert any("url=" in ln for ln in received), (
        "announcements should carry a url= token")

    # Phase 2: the backend was added exactly once (dedup), no add-failure spam.
    # Qualify by balancer://beacon so the capacity-test balancer (below) doesn't
    # perturb these counts.
    added = [ln for ln in loglines
             if "added backend" in ln and "balancer://beacon" in ln]
    assert len(added) == 1, (
        f"backend should be added exactly once; saw {len(added)}: {added}")
    assert not [ln for ln in loglines if "failed to add worker" in ln
                and "balancer://beacon:" in ln], (
        "unexpected add-failure log lines for balancer://beacon")

    # Phase 3: the member was evicted (stopped announcing within the timeout)
    # and later re-enabled (started announcing again).
    evicted = [ln for ln in loglines if "evicted backend" in ln]
    reenabled = [ln for ln in loglines if "re-enabled backend" in ln]
    assert evicted, "backend should have been evicted after the announce gap"
    assert reenabled, "backend should have been re-enabled on the next announce"

    # Phase 4: the rogue backend (wrong secret, decoy URL) must be rejected --
    # its announcements dropped and its url NEVER added as a balancer member.
    assert not [ln for ln in loglines if "http://127.0.0.1:1" in ln
                and "added backend" in ln], (
        "decoy backend with wrong secret must never be added")
    assert [ln for ln in loglines
            if "dropped" in ln and "mac mismatch" in ln], (
        "proxy should log dropping the wrong-secret announcements")

    # Slot exhaustion: balancer://cap has room for one member but two backends
    # announce to it. Exactly one must be added; the other can never fit.
    cap_added = [ln for ln in loglines
                 if "added backend" in ln and "balancer://cap" in ln]
    assert len(cap_added) == 1, (
        f"exactly one backend should fit balancer://cap; saw: {cap_added}")

    # The key regression guard: the un-addable backend must NOT trigger an
    # add attempt (and its log) on every announcement. Both backends announce
    # once per second over ~16s, so a per-interval retry storm would be >10
    # failure logs; the backoff must keep it tiny.
    cap_fail = [ln for ln in loglines if "balancer add failed" in ln]
    assert len(cap_fail) <= 3, (
        f"failed add must back off, not retry every announcement; "
        f"saw {len(cap_fail)} failure logs: {cap_fail}")

    # Anti-replay: the per-url monotonic ts check must NOT false-reject the
    # legitimate backends, which announce ~once/second. Because ts is in
    # microseconds it strictly increases between announcements, so no genuine
    # announcement should be logged as a replay. (A real replay can't be
    # injected from this harness; this guards against over-rejection.)
    assert not [ln for ln in loglines if "replayed/reordered ts" in ln], (
        "legitimate sub-second announcements must not be seen as replays")
