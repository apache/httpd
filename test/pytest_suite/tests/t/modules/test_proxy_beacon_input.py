r"""Hostile-input and member-identity tests for mod_proxy_beacon's receiver.

test_proxy_beacon.py covers the happy-path lifecycle.  These tests inject
hand-built, correctly *signed* announcements (a "valid MAC" sender that is not the
bundled sender, e.g. a buggy or compromised backend holding the shared secret) and
assert the receiver survives them.  They use the same t/conf/proxy_beacon.conf.in
as test_proxy_beacon.py: the main server listens for beacons on its own UDP port
for balancer://beacon, authenticated with the secret below.

Like test_proxy_beacon.py these are skipped under the prefork MPM (mod_watchdog's
singleton runs in a child process).
"""

import os
import re
import signal
import socket
import struct
import time
from pathlib import Path

import pytest

from apache_pytest import need_module

SECRET = b"beacon-test-shared-secret"
M64 = (1 << 64) - 1


def _siphash24(key: bytes, data: bytes) -> int:
    """Reference SipHash-2-4 (what apr_siphash24_auth computes)."""
    def rotl(x, b):
        return ((x << b) | (x >> (64 - b))) & M64

    k0, k1 = struct.unpack("<QQ", key)
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    def rnd():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & M64
        v1 = rotl(v1, 13) ^ v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & M64
        v3 = rotl(v3, 16) ^ v2
        v0 = (v0 + v3) & M64
        v3 = rotl(v3, 21) ^ v0
        v2 = (v2 + v1) & M64
        v1 = rotl(v1, 17) ^ v2
        v2 = rotl(v2, 32)

    n = len(data)
    for i in range(0, n - n % 8, 8):
        m = struct.unpack_from("<Q", data, i)[0]
        v3 ^= m
        rnd(); rnd()
        v0 ^= m
    tail = data[n - n % 8:]
    m = (n & 0xFF) << 56
    for i, b in enumerate(tail):
        m |= b << (8 * i)
    v3 ^= m
    rnd(); rnd()
    v0 ^= m
    v2 ^= 0xFF
    for _ in range(4):
        rnd()
    return v0 ^ v1 ^ v2 ^ v3


def _md5(data: bytes) -> bytes:
    import hashlib
    return hashlib.md5(data).digest()


def signed_beacon(url: str, seq: int = 1, ts_us: int = None) -> bytes:
    """A correctly signed announcement, as the bundled sender would build it."""
    if ts_us is None:
        ts_us = int(time.time() * 1_000_000)
    base = f"BEACON url={url} host=probe pid=1 seq={seq} ts={ts_us}"
    mac = _siphash24(_md5(SECRET), base.encode()).to_bytes(8, "little").hex()
    return f"{base} mac={mac}".encode()


def signed_raw(base: str, trailer: bytes = b"") -> bytes:
    """Sign an arbitrary frame prefix (it need not be well-formed)."""
    mac = _siphash24(_md5(SECRET), base.encode()).to_bytes(8, "little").hex()
    return f"{base} mac={mac}".encode() + trailer


def send_udp(port: int, payload: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(payload, ("127.0.0.1", port))


def log_since(error_log: Path, start: int) -> list:
    with error_log.open("r", errors="replace") as fh:
        fh.seek(start)
        return fh.read().splitlines()


def test_siphash_reference_vector():
    """Guard the test helper itself: SipHash-2-4 paper vector (key 00..0f, empty)."""
    key = bytes(range(16))
    assert _siphash24(key, b"") == 0x726FDB47DD0E0E31
    assert _siphash24(key, bytes(range(15))) == 0xA129CA6149BE45E5


def inject(http, urls, probe_url, port=None, balancer="beacon"):
    """Send one signed announcement per url, then a valid one for probe_url.

    The receiver handles datagrams in order, so once probe_url is reported as
    added every earlier datagram has definitely been processed -- no timing
    guesses and no reliance on a log line the hostile url itself may or may not
    produce.  Asserts that no child crashed; returns the log lines written since
    the first datagram was sent.
    """
    if http.have_module("mpm_prefork"):
        pytest.skip("proxy_beacon not run under the prefork MPM")

    port = int(port or http.vars("port"))
    error_log = Path(http.vars("t_logs")) / "error_log"

    # The listener socket is opened by the watchdog some time after startup, and
    # a datagram sent before that is simply lost.  The legit backend announces
    # on its own; wait until the receiver has logged one of its beacons.
    session_start = int(http.vars("session_log_start") or 0)
    deadline = time.time() + 15
    while not any("received: BEACON" in ln
                  for ln in log_since(error_log, session_start)):
        assert time.time() < deadline, "beacon receiver never came up"
        time.sleep(0.25)

    start = error_log.stat().st_size

    now_us = int(time.time() * 1_000_000)
    for seq, item in enumerate(list(urls) + [probe_url]):
        if isinstance(item, bytes):          # a hand-built datagram, sent as is
            send_udp(port, item)
        else:
            send_udp(port, signed_beacon(item, seq=seq, ts_us=now_us + seq))

    added = f"added backend {probe_url} to balancer://{balancer}"
    deadline = time.time() + 10
    lines = []
    while time.time() < deadline:
        time.sleep(0.5)
        lines = log_since(error_log, start)
        if any(added in ln for ln in lines):
            break
    time.sleep(1)  # let the parent report a child crash, if there was one
    lines = log_since(error_log, start)

    crashed = [ln for ln in lines if "exit signal" in ln]
    assert not crashed, f"a child crashed on a signed announcement: {crashed}"
    assert any(added in ln for ln in lines), (
        "the valid announcement after the hostile one(s) was never processed; "
        f"log tail: {lines[-10:]}")

    # Still serving.
    assert http.GET("/index.html").status_code == 200
    return lines


def added_members(lines, balancer="beacon"):
    """Members reported added to balancer://<balancer>, as a list of urls."""
    out = []
    for ln in lines:
        if "added backend " in ln and f" to balancer://{balancer}" in ln:
            out.append(ln.split("added backend ", 1)[1].split(" ", 1)[0])
    return out


need = need_module("proxy_beacon", "watchdog", "proxy_balancer", "proxy_http")


@need
def test_overlong_hostname_does_not_corrupt_worker_array(http):
    """A hostname the proxy cannot store makes worker definition fail *after* it
    appended a half-built entry to the balancer's worker array; the next lookup
    then dereferenced the NULL shared-worker pointer and killed the child."""
    inject(http, ["http://" + "a" * 300 + ".invalid:81"],
           "http://127.0.0.3:18091")


@need
def test_overlong_uds_path_does_not_crash(http):
    """unix:/<overlong>|http://localhost -- the original reproducer."""
    inject(http, ["unix:/" + "b" * 300 + "|http://localhost"],
           "http://127.0.0.3:18092")


# ---- member identity: an announced url names an origin, canonically ----------

@need
def test_default_port_is_dropped_from_identity(http):
    """http://host:80 is the same origin as http://host.  The proxy stores the
    worker as http://host; the member must be tracked, added and enabled under
    that name, not under the announced spelling (which then matches no worker,
    leaves it 'Init Dis' and still logs a successful add)."""
    lines = inject(http, ["http://127.0.0.4:80"], "http://127.0.0.3:18093")
    assert "http://127.0.0.4" in added_members(lines)
    assert not [ln for ln in lines if "127.0.0.4" in ln
                and "failed to enable" in ln]


@need
def test_scheme_and_host_case_are_canonicalized(http):
    lines = inject(http, ["HTTP://Canon.Invalid:8081"], "http://127.0.0.3:18094")
    assert "http://canon.invalid:8081" in added_members(lines)


@need
def test_equivalent_spellings_are_one_member(http):
    """Same origin spelled three ways: one member, one lease, one add."""
    lines = inject(http, ["http://127.0.0.7:8082", "http://127.0.0.7:8082/",
                          "HTTP://127.0.0.7:8082"], "http://127.0.0.3:18095")
    assert added_members(lines).count("http://127.0.0.7:8082") == 1


@need
@pytest.mark.parametrize("n,url", enumerate([
    "http://127.0.0.8:8083/one",            # path: would alias /one and /one/two
    "http://127.0.0.8:8083/one/two",
    "http://127.0.0.8:8083?x=1",            # query
    "http://127.0.0.8:8083/#frag",          # fragment
    "http://user:pw@127.0.0.8:8083",        # userinfo
    "http://127.0.0.8:0",                   # port 0
    "http://127.0.0.8:-80",                 # strtol sign wraps to port 65456
    "http://127.0.0.8:+80",
]))
def test_non_origin_urls_are_rejected(http, n, url):
    lines = inject(http, [url], f"http://127.0.0.3:{18100 + n}")
    assert not [m for m in added_members(lines) if "127.0.0.8" in m], (
        f"{url!r} must not become a member")


# ---- ownership and watchdog hand-off -----------------------------------------

STATIC_MEMBER = "http://127.0.0.11:19000"   # BalancerMember in balancer://handoff


def conf_port(http, name):
    conf = Path(http.vars("t_logs")).parent / "conf" / "proxy_beacon.conf"
    m = re.search(rf"Define BEACON_{name}_PORT (\d+)", conf.read_text())
    assert m, f"BEACON_{name}_PORT not found in {conf}"
    return int(m.group(1))


def handoff_port(http):
    return conf_port(http, "HANDOFF")


def wait_for(error_log, start, needle, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for ln in log_since(error_log, start):
            if needle in ln:
                return ln
        time.sleep(0.2)
    return None


@need
def test_beacon_does_not_manage_members_it_did_not_create(http):
    """A BalancerMember from the configuration is not beacon's to enable or
    evict, even if some backend announces exactly its url."""
    port = handoff_port(http)
    error_log = Path(http.vars("t_logs")) / "error_log"
    start = error_log.stat().st_size
    inject(http, [STATIC_MEMBER], "http://127.0.0.3:18200",
           port=port, balancer="handoff")
    # Outlast ProxyBeaconTimeout (3s) plus the 1s sweep: had beacon adopted the
    # static member it would be evicted by now.
    time.sleep(6)
    lines = log_since(error_log, start)
    assert STATIC_MEMBER not in added_members(lines, "handoff")
    assert not [ln for ln in lines if f"evicted backend {STATIC_MEMBER}" in ln]


@need
def test_new_watchdog_owner_evicts_silent_member(http):
    """Leases live in the watchdog owner's private memory.  When the owner dies
    the replacement used to start with none, so a member that had gone silent
    stayed enabled forever.  It must adopt the beacon-created members and expire
    the silent one after ProxyBeaconTimeout."""
    if http.have_module("mpm_prefork"):
        pytest.skip("proxy_beacon not run under the prefork MPM")

    port = handoff_port(http)
    error_log = Path(http.vars("t_logs")) / "error_log"
    member = "http://127.0.0.3:18201"

    # Wait for the receiver, announce once, and never again.
    session_start = int(http.vars("session_log_start") or 0)
    assert wait_for(error_log, session_start, "received: BEACON", 15)
    start = error_log.stat().st_size
    send_udp(port, signed_beacon(member))

    line = wait_for(error_log, start, f"added backend {member} to balancer://handoff", 10)
    assert line, "member was never added"
    owner = int(re.search(r"\[pid (\d+):", line).group(1))

    # Kill the owner straight away -- well inside the 3s timeout, so the old
    # owner never gets to evict anything.
    os.kill(owner, signal.SIGKILL)

    evicted = wait_for(error_log, start, f"evicted backend {member} from balancer://handoff", 40)
    assert evicted, "silent member was never evicted by the new watchdog owner"
    new_owner = int(re.search(r"\[pid (\d+):", evicted).group(1))
    assert new_owner != owner

    lines = log_since(error_log, start)
    assert any("took over" in ln and "balancer://handoff" in ln for ln in lines)
    # The static member was not adopted along with it.
    assert not [ln for ln in lines if f"evicted backend {STATIC_MEMBER}" in ln]


@need
def test_new_owner_reenables_adopted_evicted_member(http):
    """A member that was already evicted when the owner died is adopted as
    evicted; its next announcement must be handled by the new owner (which has
    not run any other balancer operation yet) and re-enable it."""
    if http.have_module("mpm_prefork"):
        pytest.skip("proxy_beacon not run under the prefork MPM")

    port = handoff_port(http)
    error_log = Path(http.vars("t_logs")) / "error_log"
    member = "http://127.0.0.3:18202"

    session_start = int(http.vars("session_log_start") or 0)
    assert wait_for(error_log, session_start, "received: BEACON", 15)
    start = error_log.stat().st_size
    seq = 0

    def announce():
        nonlocal seq
        seq += 1
        send_udp(port, signed_beacon(member, seq=seq))

    announce()
    line = wait_for(error_log, start, f"added backend {member} to balancer://handoff", 10)
    assert line, "member was never added"
    owner = int(re.search(r"\[pid (\d+):", line).group(1))

    # Let the old owner evict it (ProxyBeaconTimeout is 3s), then kill the owner.
    assert wait_for(error_log, start,
                    f"evicted backend {member} from balancer://handoff", 10)
    os.kill(owner, signal.SIGKILL)

    # Announce continuously: datagrams sent while no one is listening are lost,
    # but one lands in the window between the new owner binding its socket and
    # its first processing tick, which is when it knows nothing but the adopted
    # (evicted) lease.
    deadline = time.time() + 40
    reenabled = None
    while time.time() < deadline and not reenabled:
        announce()
        time.sleep(0.02)
        for ln in log_since(error_log, start):
            if f"re-enabled backend {member} in balancer://handoff" in ln:
                reenabled = ln
                break

    lines = log_since(error_log, start)
    crashed = [ln for ln in lines
               if "exit signal" in ln and "Killed" not in ln]
    assert not crashed, f"the new owner crashed: {crashed}"
    assert reenabled, "adopted evicted member was never re-enabled"
    assert int(re.search(r"\[pid (\d+):", reenabled).group(1)) != owner


# ---- wire grammar and timestamp strictness -----------------------------------
#
# Each frame below is correctly signed but malformed.  A parser that finds fields
# by searching the string accepts them; the receiver must not.  The member url in
# each is unique, and the valid probe sent after it proves it was processed.

def frame_cases():
    now = int(time.time() * 1_000_000)
    stale = now - 10_000_000

    def b(url, ts_part, marker="BEACON", sep=" "):
        return f"{marker}{sep}url={url}{sep}host=probe{sep}pid=1{sep}seq=1{sep}{ts_part}"

    return [
        ("ts-trailing-garbage", lambda u: signed_raw(b(u, f"ts={now}x"))),
        ("ts-signed", lambda u: signed_raw(b(u, f"ts=+{now}"))),
        ("ts-too-long", lambda u: signed_raw(b(u, f"ts={now}0000000"))),
        ("duplicate-ts", lambda u: signed_raw(b(u, f"ts={stale} ts={now}"))),
        ("duplicate-url", lambda u: signed_raw(b(u, f"ts={now} url=http://127.0.0.99:1"))),
        ("no-marker", lambda u: signed_raw(b(u, f"ts={now}", marker="XEACON"))),
        ("double-space", lambda u: signed_raw(b(u, f"ts={now}", sep="  "))),
        ("embedded-nul", lambda u: signed_raw(b(u, f"ts={now}"), b"\x00junk")),
        ("oversize", lambda u: signed_raw(b(u, f"ts={now}") + " host=" + "h" * 3000)),
    ]


@need
@pytest.mark.parametrize("n,case", enumerate(frame_cases()),
                         ids=[c[0] for c in frame_cases()])
def test_malformed_frames_are_dropped(http, n, case):
    name, build = case
    member = f"http://127.0.0.12:{8100 + n}"
    lines = inject(http, [build(member)], f"http://127.0.0.3:{18300 + n}")
    assert member not in added_members(lines), (
        f"malformed frame {name!r} must not register a member")


@need
def test_wellformed_frame_still_accepted(http):
    """Guard for the cases above: the same hand-built shape, but valid."""
    now = int(time.time() * 1_000_000)
    member = "http://127.0.0.12:8199"
    frame = signed_raw(f"BEACON url={member} host=probe pid=1 seq=1 ts={now}")
    lines = inject(http, [frame], "http://127.0.0.3:18399")
    assert member in added_members(lines)


@need
def test_subsecond_max_skew_is_honoured(http):
    """ProxyBeaconMaxSkew 500ms: a timestamp 700ms old is stale.  (It used to be
    rounded down to 0 seconds, which then selected the 30 second default.)"""
    port = conf_port(http, "SKEW")
    now = int(time.time() * 1_000_000)
    old, fresh = "http://127.0.0.13:8201", "http://127.0.0.13:8202"
    lines = inject(
        http,
        [signed_beacon(old, seq=1, ts_us=now - 700_000),
         signed_beacon(fresh, seq=2, ts_us=int(time.time() * 1_000_000))],
        "http://127.0.0.13:8203", port=port, balancer="skew")
    members = added_members(lines, "skew")
    assert old not in members, "a 700ms-old timestamp passed a 500ms window"
    assert fresh in members


# ---- tracking-table capacity -------------------------------------------------

TABLE_CAP = 256   # BEACON_MAX_MEMBERS


@need
def test_silent_members_are_reclaimed_so_new_ones_can_join(http):
    """The receiver tracks at most 256 urls.  Records of members that have been
    evicted, and of adds that failed, used to stay forever, so once 256 distinct
    urls had ever announced the table was full for good and every later
    announcement -- from any new backend -- was dropped.  They are reclaimed once
    a replay of their last message could no longer be fresh."""
    if http.have_module("mpm_prefork"):
        pytest.skip("proxy_beacon not run under the prefork MPM")

    port = conf_port(http, "RECLAIM")
    error_log = Path(http.vars("t_logs")) / "error_log"
    session_start = int(http.vars("session_log_start") or 0)
    assert wait_for(error_log, session_start, "received: BEACON", 15)

    start = error_log.stat().st_size
    members = [f"http://10.1.{i // 200}.{i % 200 + 1}:9000" for i in range(TABLE_CAP)]
    now_us = int(time.time() * 1_000_000)
    for i, url in enumerate(members):
        send_udp(port, signed_beacon(url, seq=i, ts_us=now_us + i))

    # A balancer takes at most 100 runtime members: 100 get added, the other 156
    # fail -- and all 256 occupy a tracking record.
    deadline = time.time() + 30
    while time.time() < deadline:
        added = set(added_members(log_since(error_log, start), "reclaim"))
        if len(added) >= 100:
            break
        time.sleep(0.5)
    assert len(added) == 100, f"{len(added)} members added, expected 100"

    # Everyone falls silent: members are evicted after 1s, and every record is
    # reclaimable after 2 * MaxSkew + 1s.
    time.sleep(10)

    # The table has room again: a newcomer is looked at (and fails, because the
    # balancer really is full) instead of being dropped for want of a record.
    mark = error_log.stat().st_size
    send_udp(port, signed_beacon("http://10.2.0.1:9000", seq=1000))
    time.sleep(3)
    lines = log_since(error_log, mark)
    assert any("balancer add failed" in ln for ln in lines), lines[-5:]
    assert not any("member table full" in ln for ln in lines)

    # An evicted member that comes back is re-adopted from the balancer.
    again = sorted(added)[0]
    mark = error_log.stat().st_size
    send_udp(port, signed_beacon(again, seq=1001))
    assert wait_for(error_log, mark,
                    f"backend {again} already in balancer://reclaim", 10)


# ---- operator intent ---------------------------------------------------------

def manager_post(http, query):
    """POST to the handoff vhost's balancer-manager (nonce taken from its page)."""
    r = http.GET("/balancer-manager")
    assert r.status_code == 200, "balancer-manager not reachable"
    m = re.search(r"b=handoff[^\"]*?nonce=([0-9a-fA-F-]+)", r.text.replace("&amp;", "&"))
    assert m, "no nonce for balancer://handoff"
    vars_ = http.vars()
    referer = {"Referer": f"http://{vars_['servername']}:{http.vhost_port('proxy_beacon_handoff')}/balancer-manager"}
    return http.POST("/balancer-manager", content=(query + "&nonce=" + m.group(1)).encode(),
                     headers=referer)


def member_status(http, member):
    """The balancer-manager's status text for one member of balancer://handoff."""
    r = http.GET("/balancer-manager")
    host = member.split("://", 1)[1]
    for row in re.split(r"</tr>", r.text):
        if host in row and "balancer://" not in row.split(host)[0][-40:]:
            cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
            for c in cells:
                if re.search(r"\b(Init|Ok|Dis|Stop|Drn)\b", c):
                    return re.sub(r"<[^>]+>", "", c).strip()
    return None


@need
def test_beacon_leaves_operator_flags_alone(http):
    """Beacon owns a member's Disabled flag.  An administrator who needs a member
    held out of rotation regardless of announcements uses Stopped (or Drain),
    which beacon never touches, so it survives an evict / re-enable cycle."""
    if http.have_module("mpm_prefork"):
        pytest.skip("proxy_beacon not run under the prefork MPM")
    http.module("proxy_beacon_handoff")
    try:
        port = handoff_port(http)
        error_log = Path(http.vars("t_logs")) / "error_log"
        member = "http://127.0.0.15:8300"

        session_start = int(http.vars("session_log_start") or 0)
        assert wait_for(error_log, session_start, "received: BEACON", 15)
        start = error_log.stat().st_size
        seq = 0

        def announce():
            nonlocal seq
            seq += 1
            send_udp(port, signed_beacon(member, seq=seq))

        announce()
        assert wait_for(error_log, start, f"added backend {member} to balancer://handoff", 10)

        r = manager_post(http, f"w={member}&b=handoff&w_status_S=1")
        assert r.status_code == 200
        assert "Stop" in (member_status(http, member) or ""), member_status(http, member)

        # Silent past ProxyBeaconTimeout (3s): beacon evicts it...
        assert wait_for(error_log, start, f"evicted backend {member} from balancer://handoff", 10)
        # ...then it announces again and beacon re-enables it.
        announce()
        assert wait_for(error_log, start, f"re-enabled backend {member} in balancer://handoff", 10)

        status = member_status(http, member) or ""
        assert "Stop" in status, f"beacon cleared the administrator's Stop: {status!r}"
        assert "Dis" not in status, f"member should be re-enabled: {status!r}"
    finally:
        http.module(None)
