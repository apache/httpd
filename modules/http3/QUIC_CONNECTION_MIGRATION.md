# QUIC Connection Migration in mod_http3

## Problem

QUIC connection migration (RFC 9000, Section 9) allows a client's source
address to change mid-connection — for example when a mobile device switches
networks or a NAT rebinds the client port. The server must continue serving
the connection at the new address.

mod_http3 currently does not support connection migration. Two independent
issues block it.

## 1. OpenSSL does not update the peer address

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

OpenSSL's QUIC server implementation (as of 3.5.x):

- Hardcodes `disable_active_migration = 1` in `quic_port.c`.
- Accepts packets from a changed source address on the server side (no
  address check in `ch_rx_handle_packet` for `is_server`).
- **Never updates `cur_peer_addr`** after the initial handshake. The TX
  packetiser sends responses to the stale address, so the client never
  receives them.
- Marks this as future work with `TODO(QUIC FUTURE)` comments.

For comparison, ngtcp2 fully implements server-side migration in
`conn_recv_non_probing_pkt_on_new_path()`: it updates the peer address
immediately, distinguishes NAT rebinding from full IP changes, resets
congestion state on IP changes (Section 9.4), and runs path validation
with fallback to the old path.

## 2. Multi-child UDP socket routing (SO_REUSEPORT)

When multiple httpd children share the QUIC port via `SO_REUSEPORT`, the
kernel hashes each UDP datagram independently by 4-tuple (source IP, source
port, destination IP, destination port). Unlike TCP — where `SO_REUSEPORT`
only matters at `accept()` time and all subsequent packets follow the
established connection — UDP has no kernel-level connection state.

If the client's source address changes, the hash changes, and the packet is
delivered to a different child's socket. That child has no QUIC state for
this connection, so the packet is dropped.

The solution is `SO_ATTACH_REUSEPORT_EBPF`: a BPF program attached to the
socket group that reads the QUIC Destination Connection ID from each incoming
packet and steers it to the correct socket regardless of source address. This
is implemented in the `h3bench_improvements` branch (`h3q_reuseport.c`,
`h3q_reuseport_kern.c`).

Note: the current trunk code does not use `SO_REUSEPORT` at all — only one
child binds the UDP port; the others retry in the background. This means
issue #1 (OpenSSL) is the only blocker in trunk today; issue #2 becomes
relevant once multi-child QUIC socket sharing is enabled.

## Test

`test/modules/http3/test_109_migration.py` exercises NAT rebinding:

1. Establishes a QUIC connection from local port A.
2. Sends a GET request (succeeds).
3. Rebinds the client's UDP socket to a new local port B.
4. Sends a second GET request on the same QUIC connection.
5. Asserts the second request succeeds.

The test currently xfails because OpenSSL responds to the old address.

## References

- RFC 9000 Section 9: Connection Migration
- RFC 9000 Section 9.3: Responding to Connection Migration
- RFC 9000 Section 9.3.1: Peer Address Spoofing / NAT Rebinding
- RFC 9000 Section 9.4: Loss Detection and Congestion Control (reset on migration)
- RFC 9000 Section 18.2: `disable_active_migration` transport parameter
- OpenSSL `ssl/quic/quic_port.c`: `disable_active_migration = 1` (hardcoded)
- OpenSSL `ssl/quic/quic_channel.c`: `cur_peer_addr` never updated after handshake
- ngtcp2 `lib/ngtcp2_conn.c`: `conn_recv_non_probing_pkt_on_new_path()` — full implementation
