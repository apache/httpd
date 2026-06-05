# A Practical Guide to `mod_proxy_beacon`

*Self-registering, self-healing reverse-proxy balancer membership over UDP.*

---

## 1. What it does

Normally, adding a backend to an httpd reverse-proxy load balancer means editing
the proxy config (or clicking around in `balancer-manager`) every time the fleet
changes. `mod_proxy_beacon` flips that around: **each backend announces itself**
to the proxy, and the proxy automatically:

- **adds and enables** the backend as a live `BalancerMember` when it first
  announces, and
- **disables it** (takes it out of rotation) when it stops announcing — then
  **re-enables it** when it comes back.

The result is a balancer whose membership tracks the running fleet with no
operator action. A backend added this way is a normal balancer member: it shows
up in `balancer-manager` and behaves exactly like a statically configured
`BalancerMember`.

```
   backend-1 ──┐  (periodic UDP "BEACON" datagrams,
   backend-2 ──┤   each advertising its own URL)
   backend-3 ──┘            │
                            ▼
                    ┌──────────────┐
                    │ reverse proxy│  ProxyBeaconListen :5555
                    │  balancer://  │  → add / enable / evict members
                    │   cluster     │
                    └──────────────┘
                            │
                       clients
```

---

## 2. How it works (the short version)

- **Transport:** plain **unicast UDP** datagrams (not multicast — multicast is
  filtered on most networks and never crosses the public Internet). Backends
  `sendto` the proxy; the proxy binds one socket and receives. No external
  library — APR sockets for transport, APR-util SipHash for auth.
- **Fire-and-forget:** a lost datagram is simply recovered by the next periodic
  announcement; reordered/replayed datagrams are rejected by a per-backend
  timestamp check. No connection, reconnect, or framing layer.
- **Where it runs:** all the work happens in a single `mod_watchdog` **singleton**
  child process, which owns the socket and applies membership changes. The change
  propagates fleet-wide through the balancer's shared-memory “updated” timestamp,
  the same way `balancer-manager` edits do.

---

## 3. Requirements

| Need | Why |
|------|-----|
| `mod_proxy` + `mod_proxy_balancer` | the balancer the members are added to |
| `mod_watchdog` | runs the background send/receive/evict loop |
| A **non-prefork** MPM (`event`, `worker`, …) | the watchdog singleton can't run under `prefork`; the module is silently inactive there |
| `mod_proxy_http` (or your backend protocol module) | to actually proxy the traffic |

Build it with `--enable-proxy-beacon` (or `--enable-mods-shared=all`). Confirm
it's present:

```sh
httpd -M 2>&1 | grep proxy_beacon      # shared build
# or
httpd -l   | grep mod_proxy_beacon     # static build
```

---

## 4. Quick start

### On the reverse proxy

```apache
# Receive backend announcements on the cluster-facing interface (UDP/5555).
ProxyBeaconListen   0.0.0.0:5555
ProxyBeaconSecret   "a-long-random-shared-cluster-secret"
ProxyBeaconBalancer cluster

# Drop a backend from rotation if it goes silent for 30s; re-add on next beacon.
ProxyBeaconTimeout  30

# An initially EMPTY balancer with spare slots for the dynamic members.
<Proxy balancer://cluster>
    ProxySet growth=16
</Proxy>

ProxyPass        "/" "balancer://cluster/"
ProxyPassReverse "/" "balancer://cluster/"
```

### On each backend

```apache
# Announce this backend's routable origin to the proxy every 10s (UDP).
ProxyBeaconAddress   proxy.example.com:5555
ProxyBeaconAdvertise http://10.0.0.5:8080
ProxyBeaconSecret    "a-long-random-shared-cluster-secret"
ProxyBeaconInterval  10
```

That's it. Start the backends; within one announcement interval each one appears
as an enabled member of `balancer://cluster` on the proxy. Stop one, and after
`ProxyBeaconTimeout` it drops out of rotation; start it again and it returns.

> **`ProxyBeaconAdvertise` must be the URL the *proxy* can reach** — the
> backend's routable origin, not `127.0.0.1`. It's validated at config-parse
> time and must be a full `scheme://host[:port]`.

---

## 5. Directive reference

### Proxy side (the receiver)

| Directive | Default | Meaning |
|-----------|---------|---------|
| `ProxyBeaconListen [addr][:port]` | — | **Marks this server as the receiver.** Binds a UDP socket. `addr`/`port` are optional and inherited from the server's own `Listen`/`ServerName` when omitted (see note below). |
| `ProxyBeaconBalancer name` | — | Balancer that announced backends are added to. Bare name (`cluster`); a leading `balancer://` is stripped. Must already exist with spare `growth`. |
| `ProxyBeaconTimeout interval` | `0` (no eviction) | Seconds of silence before a member is disabled. `0` = add-only, never auto-remove. Set to a small multiple of the backends' interval to get self-healing. |
| `ProxyBeaconSecret secret` | — (unauthenticated) | Shared cluster secret; **same value on proxy and all backends.** |
| `ProxyBeaconMaxSkew interval` | `30` | Anti-replay freshness window: reject announcements whose signed timestamp is more than this far from now (either direction). |

**Inheriting the listen address:** because UDP and TCP are separate port spaces,
`ProxyBeaconListen` can share the server's own service port without colliding
with the TCP listener. With no argument it binds the server's own address:port;
given just an address it inherits the port; etc. (The socket binds in an
unprivileged watchdog child, so you **can't** share a privileged port like 80/443
this way — use an explicit high port there.)

### Backend side (the sender)

| Directive | Default | Meaning |
|-----------|---------|---------|
| `ProxyBeaconAddress addr:port` | — | **Marks this server as a sender.** UDP target = the proxy's `ProxyBeaconListen` address. |
| `ProxyBeaconAdvertise url` | — | The routable `scheme://host[:port]` the proxy adds as a member. Omit it and the backend beacons but advertises nothing (logged, never added). |
| `ProxyBeaconInterval interval` | `5` | How often this backend announces. Must be **meaningfully smaller** than the proxy's `ProxyBeaconTimeout`. |
| `ProxyBeaconSecret secret` | — | Same shared secret as the proxy. |

> `ProxyBeaconListen` and `ProxyBeaconAddress` are **mutually exclusive** on the
> same server — a server is either a receiver or a sender, not both.

All directives accept `server config` and `virtual host` context. Interval-style
directives use the standard httpd
[time-interval syntax](../../docs/manual/mod/directive-dict.html#Syntax) and
default to seconds (e.g. `ProxyBeaconInterval 10` or `... 500ms`).

---

## 6. Security — read this before production

The control channel decides where the proxy sends client traffic, so an
unauthenticated channel is a route-hijack / SSRF risk: anyone who can reach the
receive port could announce an arbitrary backend URL, and **UDP source addresses
are trivially spoofable.**

**Always set `ProxyBeaconSecret`** in production (identical on proxy and every
backend). With it:

- Each announcement is signed with a **SipHash-2-4 MAC** plus a timestamp; the
  proxy recomputes the MAC (constant-time compare) and drops anything forged or
  tampered **before parsing the URL**.
- **Replay protection is two-layered:** (1) the `ProxyBeaconMaxSkew` freshness
  window rejects stale timestamps, and (2) a per-backend high-water mark rejects
  any timestamp that doesn't strictly advance — so capturing and re-sending a
  dead backend's last datagram (to keep it from being evicted) is rejected even
  inside the freshness window.

Operational notes:

- **Clocks must be roughly in sync** (NTP). The timestamp check compares the
  announcement's time against the proxy's clock; widen `ProxyBeaconMaxSkew` if
  your hosts drift.
- With **no secret**, the channel is unauthenticated and the proxy logs a
  one-time `UNAUTHENTICATED` warning at startup.
- The secret lives in your config file — **restrict its permissions like a
  private key.**
- Announcements are **authenticated, not encrypted.** The payload is operational
  metadata (URLs), not secrets. There's no transport confidentiality (DTLS would
  be a separate future layer).

---

## 7. Tuning

- **Interval vs. timeout.** Keep `ProxyBeaconInterval` well under
  `ProxyBeaconTimeout` so an occasional dropped datagram doesn't evict a healthy
  backend. A common ratio is timeout ≈ 3–6× interval (e.g. interval 10s, timeout
  30–60s).
- **Size `growth` for your peak fleet.** A runtime-added member occupies one
  growth slot **for the life of the proxy process** — it's *disabled* on
  eviction, not removed (httpd can't remove workers at runtime, mirroring
  `balancer-manager`). So `growth` must cover the maximum number of distinct
  backend URLs you ever expect, not just the count live at one moment.
- **One proxy, many backends.** A single receiver serves the whole fleet. For
  multiple proxies, run `ProxyBeaconListen` on each and point backends at all of
  them (one `ProxyBeaconAddress` server per proxy, or accept that only the
  configured proxy learns about the backend).

---

## 8. Verifying & troubleshooting

**See members appear:** enable `balancer-manager` on the proxy and watch the
worker list:

```apache
<Location "/balancer-manager">
    SetHandler balancer-manager
    Require host localhost
</Location>
```

**Watch the log.** Bump verbosity for the module and tail the error log:

```apache
LogLevel proxy_beacon:info
```

Useful log signals (grep the error log):

| Log fragment | Means |
|--------------|-------|
| `received: BEACON ... url=...` | proxy is receiving announcements |
| `added backend ... balancer://cluster` | member created + enabled |
| `evicted backend ...` | a backend went silent past the timeout |
| `re-enabled backend ...` | a previously-evicted backend came back |
| `dropped ... mac mismatch` | wrong/missing secret on a sender (or a forged datagram) |
| `replayed/reordered ts` | a stale/duplicate datagram was rejected |
| `UNAUTHENTICATED` (startup) | no `ProxyBeaconSecret` — channel is open |

**Common gotchas:**

- *Backend never joins.* Usually a **secret mismatch** (look for `mac mismatch`)
  or a firewall blocking **UDP** on the beacon port (it's UDP, not TCP — separate
  rule). Confirm the proxy is logging `received: BEACON` at all.
- *Nothing happens, no errors.* You're probably on the **prefork MPM** — the
  watchdog singleton doesn't run there, so the module is inactive. Switch to
  `event`/`worker`.
- *Traffic 503s to a backend that's “up”.* Check that `ProxyBeaconAdvertise` is
  the URL the **proxy** can reach (not the backend's loopback) and that the
  balancer has free `growth` slots.
- *Healthy backend keeps getting evicted.* Interval too close to timeout, or
  clock skew larger than `ProxyBeaconMaxSkew`. Widen the timeout/skew or sync
  clocks.

---

## 9. The wire format (for the curious)

One ASCII, space-separated, key=value datagram per announcement:

```
BEACON url=http://host:port host=<h> pid=<n> seq=<n> ts=<usec> mac=<hex>
```

- `url=` — the routable origin added as a `BalancerMember`.
- `ts=` (microseconds since epoch) and `mac=` — present only when a secret is set;
  `ts` drives replay protection, `mac` is the SipHash signature.
- `host=` / `pid=` / `seq=` — informational. (`seq` resets on backend restart, so
  it's *not* used for replay detection — the wall-clock `ts` is.)

---

## 10. See also

- `mod_proxy`, `mod_proxy_balancer` — the balancer these members live in
- `mod_proxy_hcheck` — active health checking, complementary to beacon liveness
- `mod_watchdog` — the background runner this module rides on
- `modules/proxy/README.beacon` — the architecture/internals companion to this guide
- `docs/manual/mod/mod_proxy_beacon.xml` — the formal directive reference
