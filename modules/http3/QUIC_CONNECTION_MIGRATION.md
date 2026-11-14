# QUIC Connection Migration in mod_http3

## Problem

QUIC connection migration (RFC 9000, Section 9) allows a client's source
address to change mid-connection — for example when a mobile device switches
networks or a NAT rebinds the client port. The server must continue serving
the connection at the new address.

mod_http3 supports connection migration. Two parts are necessary.

## 1. The QUIC stack updates the peer address

When the server receives a valid QUIC packet from a new source address,
RFC 9000 Section 9.3 requires:

- The server **MUST** start path validation (PATH_CHALLENGE) to the new
  address.
- The server **MUST** update the address it sends responses to, based on the
  highest-numbered non-probing packet from the new address.
- Before validation completes, the server **MUST NOT** send more than a
  minimum congestion window's worth of data to the unvalidated address
  (anti-amplification, Section 9.3).

RFC 9000 Section 9.3.1 specifically covers NAT rebinding (same IP, different
port). Even when the `disable_active_migration` transport parameter is set
(Section 18.2), the server must still handle NAT rebinding.

mod_http3 uses ngtcp2. ngtcp2 fully implements server-side migration in
`conn_recv_non_probing_pkt_on_new_path()`: it updates the peer address
immediately, distinguishes NAT rebinding from full IP changes, resets
congestion state on IP changes (Section 9.4), and runs path validation
with fallback to the old path.

## 2. Multi-child UDP socket routing (SO_REUSEPORT)

On Linux with `ListenCoresBucketsRatio`, the parent binds one `SO_REUSEPORT`
socket per listener bucket, and each child serves one of them. The
kernel hashes each UDP datagram independently by 4-tuple (source IP, source
port, destination IP, destination port). Unlike TCP — where `SO_REUSEPORT`
only matters at `accept()` time and all subsequent packets follow the
established connection — UDP has no kernel-level connection state.

If the client's source address changes, the hash changes, and the packet is
delivered to a different child's socket. That child has no QUIC state for
this connection, so the packet is dropped.

The solution is `SO_ATTACH_REUSEPORT_EBPF`: a BPF program attached to the
socket group that reads the QUIC Destination Connection ID from each incoming
packet and steers it to the correct socket regardless of source address.
`h3_socket_bpf.c` implements it. Each child puts its bucket index in the
connection IDs that it issues.

If the BPF program does not attach, the server logs a warning and sends the
`disable_active_migration` transport parameter. With one QUIC socket, one
child serves all connections and this routing is not necessary.

## Test

`test/modules/http3/test_109_migration.py` exercises NAT rebinding:

1. Establishes a QUIC connection from local port A.
2. Sends a GET request (succeeds).
3. Rebinds the client's UDP socket to a new local port B.
4. Sends a second GET request on the same QUIC connection.
5. Asserts the second request succeeds.

`test/modules/http3/test_016_cid_routing.py` does the same test with more
than one bucket.

## References

- RFC 9000 Section 9: Connection Migration
- RFC 9000 Section 9.3: Responding to Connection Migration
- RFC 9000 Section 9.3.1: Peer Address Spoofing / NAT Rebinding
- RFC 9000 Section 9.4: Loss Detection and Congestion Control (reset on migration)
- RFC 9000 Section 18.2: `disable_active_migration` transport parameter
- ngtcp2 `lib/ngtcp2_conn.c`: `conn_recv_non_probing_pkt_on_new_path()`
