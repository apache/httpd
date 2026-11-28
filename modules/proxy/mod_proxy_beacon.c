/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * mod_proxy_beacon -- a UDP datagram announcement channel between backend
 * servers and a front-end reverse proxy, by which backends self-register as
 * balancer members.
 *
 * This module uses plain APR UDP sockets, adapting the socket-handling pattern
 * of mod_heartmonitor.  UDP datagrams are a natural fit for small, periodic,
 * fire-and-forget announcements, and avoid a third-party dependency.
 *
 * UNICAST, not multicast: unlike mod_heartbeat (which multicasts to a group),
 * each backend sends a point-to-point datagram to the proxy's configured address
 * (apr_socket_sendto to a single resolved unicast sockaddr).  Multicast is
 * filtered on most networks and does not traverse the public Internet, so a
 * cross-host control plane must be unicast.  The proxy is a fixed unicast
 * rendezvous; each backend is configured with its address.
 *
 * Direction: backends announce themselves to the proxy.  The proxy binds a
 * stable UDP port (the rendezvous) and receives; each backend sends to it:
 *
 *   - Reverse proxy:  ProxyBeaconListen 0.0.0.0:5555     (receiver, binds)
 *   - Backend server: ProxyBeaconAddress   proxy-host:5555  (sender, sendto)
 *
 * A leading scheme (e.g. tcp://) in the address is accepted and ignored, so
 * addresses written with a transport scheme keep working.  Each backend sends
 * a "BEACON" datagram every interval.  Datagrams are fire-and-forget: a lost
 * packet just delays an update by one interval, and reordering is rejected by
 * the per-url monotonic timestamp (Phase 4), so the design tolerates UDP's lack
 * of delivery/ordering guarantees without a reconnect or framing layer.
 *
 * Phase 1 (the channel): the proxy simply logged each announcement, proving the
 * channel works between separate, remote servers.
 *
 * Phase 2: when the proxy receives an announcement that carries a backend
 * URL, it ADDS that backend as a member (worker) of a configured balancer and
 * ENABLES it -- the dynamic equivalent of "Add Worker" in the balancer-manager
 * web UI, but driven by the backend announcing itself.  We reuse
 * mod_proxy_balancer's exported balancer_manage() optional function (the same
 * core balancer_handler calls), so the add path is identical to the proven
 * manager flow.  The backend advertises its routable URL via ProxyBeaconAdvertise;
 * the proxy names the target balancer via ProxyBeaconBalancer.
 *
 * Phase 3: the inverse -- when a backend STOPS announcing for longer than
 * ProxyBeaconTimeout, the proxy takes it out of rotation by setting the worker's
 * DISABLED flag (again via balancer_manage), and re-enables it if the backend
 * starts announcing again.  This gives the cluster automatic liveness without
 * operator action.  The timeout is a config directive (0 = disabled = pure
 * Phase-2 behavior).  All of this runs in the watchdog singleton that already
 * owns the socket, so the per-URL last-seen table lives in this process's
 * ctx -- no shared memory.
 *
 * Phase 4: authenticate the channel.  Without this, anyone who can reach the
 * proxy's bound port can announce an arbitrary url and the proxy will route real
 * client traffic to it (SSRF / hijack) -- and a UDP source address is trivially
 * spoofable, so authentication matters as much here as on any control plane.  With
 * a pre-shared cluster secret (ProxyBeaconSecret) on both ends, the sender appends
 * a keyed MAC (SipHash-2-4 via APR-util -- the same primitive mod_session_crypto
 * uses) plus a timestamp; the receiver recomputes the MAC and checks timestamp
 * freshness (anti-replay), dropping any forged, tampered, or stale message
 * before it is parsed/acted on.  Authentication is REQUIRED: ProxyBeaconSecret
 * must be set on every server that participates in the channel (sender or
 * listener), or startup fails -- there is no unauthenticated mode.  We
 * authenticate, not encrypt -- the payload (backend URLs) is not secret; for
 * transport confidentiality DTLS would be a separate, orthogonal future layer.
 *
 * The background work runs on a mod_watchdog SINGLETON instance (exactly one
 * child process owns the socket), mirroring mod_proxy_hcheck.c.  That child has
 * no request_rec, so the receiver synthesizes a minimal one for balancer_manage()
 * (see beacon_make_fake_request -- adapted from mod_proxy_hcheck's
 * create_request_rec, plus a fake conn_rec that ap_log_rerror requires).
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_provider.h"
#include "ap_listen.h"
#include "mod_watchdog.h"
#include "mod_proxy.h"

#include "apr_strings.h"
#include "apr_time.h"
#include "apr_hash.h"
#include "apr_uri.h"
#include "apr_network_io.h"
#include "apr_siphash.h"
#include "apr_md5.h"

#if APR_HAVE_PROCESS_H
#include <process.h>            /* for getpid() on Windows */
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>             /* for getpid() */
#endif

module AP_MODULE_DECLARE_DATA proxy_beacon_module;

#define BEACON_WATCHDOG_NAME       "_proxy_beacon_"
#define BEACON_DEFAULT_INTERVAL    apr_time_from_sec(5)

typedef enum {
    BEACON_ROLE_NONE = 0,
    BEACON_ROLE_SEND,   /* backend: dials the proxy and announces itself */
    BEACON_ROLE_LISTEN    /* reverse proxy: listens and receives announcements */
} beacon_role_e;

/* Longest announced url we handle (including the NUL). */
#define BEACON_URL_MAX  512

/* listener-side per-backend state, keyed by url in ctx->seen. */
typedef struct beacon_member_t {
    apr_time_t last_seen;    /* updated on every beacon for this url */
    apr_time_t last_attempt; /* last add attempt (throttles retry when full) */
    apr_int64_t last_ts;     /* highest signed ts= accepted (replay guard) */
    int        added;        /* worker exists in the balancer (add dedup) */
    int        evicted;      /* WE set DISABLED on timeout (guards flip churn) */
    char       url[BEACON_URL_MAX]; /* the key in ctx->seen (the hash keeps no copy) */
    struct beacon_member_t *next_free; /* free list link while unused */
} beacon_member_t;

typedef struct {
    apr_pool_t          *p;            /* subpool for this context */
    server_rec          *s;            /* canonical server identity */
    char                *pub_url;      /* ProxyBeaconAddress   (backend dial url) */
    char                *sub_url;      /* ProxyBeaconListen (proxy listen url) */
    char                *advertise_url;/* ProxyBeaconAdvertise (sender: routable url) */
    char                *balancer_name;/* ProxyBeaconBalancer  (listener: bare bal name) */
    apr_interval_time_t  interval;     /* ProxyBeaconInterval (announce period) */
    apr_interval_time_t  evict_timeout;/* ProxyBeaconTimeout (0 = no eviction) */
    beacon_role_e           role;
    apr_socket_t        *sock;         /* live UDP socket; valid only when opened */
    apr_sockaddr_t      *addr;         /* listener: bind addr; sender: destination addr */
    int                  opened;       /* guard double-open / stop-without-start */
    apr_time_t           last_publish; /* sender throttle */
    apr_time_t           last_sweep;   /* listener eviction-scan throttle */
    apr_uint64_t         seq;          /* announcement counter */
    apr_hash_t          *seen;         /* listener: url -> beacon_member_t* */
    beacon_member_t     *free_members; /* listener: reclaimed records, for reuse */
    APR_OPTIONAL_FN_TYPE(balancer_manage) *manage_fn; /* listener: cached, lazy */
    /* Phase 4: channel authentication. */
    int                  has_secret;   /* ProxyBeaconSecret was set */
    unsigned char        mac_key[APR_MD5_DIGESTSIZE]; /* siphash key (16 bytes) */
    apr_interval_time_t  max_skew;     /* ProxyBeaconMaxSkew (replay window); 0 = default */
    apr_uint64_t         reject_count; /* listener: dropped-since-last-log counter */
    apr_time_t           last_reject_log; /* listener: reject-log rate limiter */
    int                  open_failed;     /* socket open failed; retried with back-off */
    int                  reconciled;      /* listener: adopted pre-existing members as owner */
    apr_pool_t          *open_pool;       /* socket + address of the current open attempt */
    apr_time_t           next_open_try;   /* when to retry a failed open (0 = not scheduled) */
    apr_interval_time_t  open_delay;      /* current retry back-off (0 = no failure yet) */
    int                  io_errors;       /* failed sends/receives in a row */
    apr_time_t           last_io_error_log;
    apr_time_t           next_refresh;    /* sender: when to resolve the destination again */
    apr_pool_t          *addr_pool;       /* sender: a refreshed destination, if any */
    apr_time_t           recv_log_window; /* start of the second counted below */
    unsigned int         recv_log_count;  /* "received:" lines logged in it */
    apr_uint64_t         recv_log_suppressed; /* ...and those it left out */
} beacon_ctx_t;

/* SipHash-2-4 output is 8 bytes -> 16 hex chars (+ NUL). */
#define BEACON_MAC_HEXLEN  (APR_SIPHASH_DSIZE * 2)
/* Shortest ProxyBeaconSecret accepted. */
#define BEACON_MIN_SECRET_LEN   16
/* A secret of this form is used directly as the MAC key (no passphrase). */
#define BEACON_HEXKEY_PREFIX    "hex:"
#define BEACON_MAXSKEW_DEFAULT  apr_time_from_sec(30)

/* Max announcement datagram we accept.  Our messages are a few hundred bytes;
 * anything larger is not one of ours and is dropped. */
#define BEACON_MAX_MSG_LEN  2048

/* When an add fails (e.g. the balancer is full), don't retry on every
 * announcement -- back off this long between attempts for a given url. */
#define BEACON_RETRY_BACKOFF    apr_time_from_sec(60)

/* Cap on tracked backend urls, to bound memory against a buggy or compromised
 * (authenticated) backend announcing unboundedly many distinct urls.  Once
 * reached, unknown urls are dropped (rate-limited log) rather than tracked/added. */
#define BEACON_MAX_MEMBERS      256

/* A failed socket open (unresolvable address, port in use, ...) is retried: the
 * cause may be transient (a name server that is not up yet).  The delay starts
 * at BEACON_OPEN_RETRY and doubles up to BEACON_OPEN_RETRY_MAX.  Retrying every
 * watchdog tick would flood the error log, and an address lookup blocks the
 * (single, shared) watchdog thread for as long as the resolver takes to give
 * up, so a failing name must not be retried often. */
#define BEACON_OPEN_RETRY       apr_time_from_sec(30)
#define BEACON_OPEN_RETRY_MAX   apr_time_from_sec(600)

/* Cap on datagrams handled per watchdog tick, so a flood can't hold the
 * watchdog thread in the receive loop; the rest wait for the next tick. */
#define BEACON_MAX_DRAIN        1024
/* ...and no more than this much time per tick, so that a flood of datagrams
 * cannot keep the watchdog thread from the eviction sweep and the other
 * contexts that share it. */
#define BEACON_DRAIN_BUDGET     apr_time_from_msec(50)
/* After this many failed sends or receives in a row the socket is closed and
 * reopened (re-resolving the address) under the open back-off. */
#define BEACON_IO_ERRORS_MAX    5
/* A sender looks its destination up again this often, so that a proxy which
 * moved to another address is found. */
#define BEACON_REFRESH          apr_time_from_sec(300)
/* The "received:" lines, at most this many per second and context. */
#define BEACON_RECV_LOG_PER_SEC 20

/* Process-wide watchdog handle, like mod_proxy_hcheck's static watchdog. */
static ap_watchdog_t *beacon_watchdog;

/*
 * Per-server config.  No socket calls here -- the role may not even be known yet,
 * and this runs in the parent at config-parse time (possibly more than once).
 */
static void *beacon_create_server_config(apr_pool_t *p, server_rec *s)
{
    beacon_ctx_t *ctx = apr_pcalloc(p, sizeof(beacon_ctx_t));

    ctx->s = s;
    apr_pool_create(&ctx->p, p);
    apr_pool_tag(ctx->p, "proxy_beacon");
    ctx->interval = BEACON_DEFAULT_INTERVAL;
    ctx->role = BEACON_ROLE_NONE;
    ctx->seen = apr_hash_make(ctx->p);

    return ctx;
}

static const char *beacon_set_sub_url(cmd_parms *cmd, void *dummy,
                                      int argc, char *const argv[])
{
    beacon_ctx_t *ctx = ap_get_module_config(cmd->server->module_config,
                                          &proxy_beacon_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    if (argc > 1) {
        return "ProxyBeaconListen takes at most one argument: [host][:port]";
    }
    if (ctx->pub_url) {
        return "ProxyBeaconListen and ProxyBeaconAddress are mutually exclusive "
               "on the same server";
    }
    /* No argument -> inherit both host and port from this server; one argument
     * -> "[host][:port]", an omitted host or port being inherited from the
     * server too.  Store "" for the no-argument case (resolved against the
     * server's own address at startup). */
    ctx->sub_url = (argc == 1) ? apr_pstrdup(cmd->pool, argv[0]) : "";
    ctx->role = BEACON_ROLE_LISTEN;
    return NULL;
}

static const char *beacon_set_pub_url(cmd_parms *cmd, void *dummy, const char *arg)
{
    beacon_ctx_t *ctx = ap_get_module_config(cmd->server->module_config,
                                          &proxy_beacon_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    if (ctx->sub_url) {
        return "ProxyBeaconListen and ProxyBeaconAddress are mutually exclusive "
               "on the same server";
    }
    ctx->pub_url = apr_pstrdup(cmd->pool, arg);
    ctx->role = BEACON_ROLE_SEND;
    return NULL;
}

/*
 * Canonical member identity.  An announced url names a backend *origin*:
 * scheme://host[:port], nothing more.  Returns that origin in the exact form the
 * proxy's worker-definition code stores it as the worker name -- lower-case
 * scheme and host, the scheme's default port dropped, no trailing slash -- or
 * NULL if url is not an origin (no scheme or host, a non-empty path, a query,
 * a fragment, userinfo, or a port that is not a valid number).
 *
 * The announced string is used both as the key beacon tracks a member under and
 * as the name handed to balancer_manage(), whose worker lookup is a
 * longest-prefix match.  Using one canonical origin for all of them keeps those
 * identities equal; accepting paths would let /one and /one/two name the same
 * worker while holding separate leases.
 */
static const char *beacon_canonical_url(apr_pool_t *pool, const char *url)
{
    apr_uri_t uri;
    const char *host, *port = "", *c, *canon;

    /* Printable ASCII only: the url is logged and becomes a worker name. */
    for (c = url; *c; c++) {
        if (!apr_isgraph(*c) || !apr_isascii(*c)) {
            return NULL;
        }
    }
    if (apr_uri_parse(pool, url, &uri) != APR_SUCCESS
        || !uri.scheme || !*uri.scheme
        || !uri.hostname || !*uri.hostname) {
        return NULL;
    }
    if (uri.user || uri.password || uri.query || uri.fragment
        || (uri.path && *uri.path && strcmp(uri.path, "/"))) {
        return NULL;
    }
    /* apr_uri_parse() runs strtol() and truncates to 16 bits, so "-80" would
     * otherwise come out as port 65456 and "99999" as 34463. */
    if (uri.port_str && *uri.port_str) {
        const char *d;
        unsigned long port_val = 0;
        for (d = uri.port_str; *d; d++) {
            if (!apr_isdigit(*d)) {
                return NULL;
            }
            port_val = port_val * 10 + (*d - '0');
            if (port_val > 65535) {
                return NULL;
            }
        }
        if (!port_val) {
            return NULL;
        }
    }

    /* The proxy truncates a scheme or worker name that does not fit its shared
     * storage, which would give the member another identity than the one
     * announced. */
    if (strlen(uri.scheme) >= PROXY_WORKER_MAX_SCHEME_SIZE
        || strlen(uri.hostname) >= PROXY_RFC1035_HOSTNAME_SIZE) {
        return NULL;
    }

    ap_str_tolower(uri.scheme);
    ap_str_tolower(uri.hostname);
    host = ap_strchr_c(uri.hostname, ':')
           ? apr_pstrcat(pool, "[", uri.hostname, "]", NULL)
           : uri.hostname;
    if (uri.port && uri.port != ap_proxy_port_of_scheme(uri.scheme)) {
        port = apr_psprintf(pool, ":%u", (unsigned)uri.port);
    }
    canon = apr_pstrcat(pool, uri.scheme, "://", host, port, NULL);
    return strlen(canon) < PROXY_WORKER_MAX_NAME_SIZE ? canon : NULL;
}

static const char *beacon_set_advertise(cmd_parms *cmd, void *dummy,
                                     const char *arg)
{
    beacon_ctx_t *ctx = ap_get_module_config(cmd->server->module_config,
                                          &proxy_beacon_module);
    const char *canon;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    /* Must be a routable backend origin (scheme://host[:port], no path); it
     * becomes a BalancerMember on the proxy.  Announce its canonical form, so
     * sender and receiver agree on the member's identity. */
    canon = beacon_canonical_url(cmd->pool, arg);
    if (!canon) {
        return apr_psprintf(cmd->pool,
                            "ProxyBeaconAdvertise: '%s' is not a valid "
                            "scheme://host[:port] URL (no path, query, "
                            "fragment or userinfo; short enough to be a "
                            "worker name)", arg);
    }
    ctx->advertise_url = (char *)canon;
    return NULL;
}

static const char *beacon_set_balancer(cmd_parms *cmd, void *dummy,
                                    const char *arg)
{
    beacon_ctx_t *ctx = ap_get_module_config(cmd->server->module_config,
                                          &proxy_beacon_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    /* Store the bare name; balancer_manage() prepends BALANCER_PREFIX itself.
     * Be forgiving if the admin wrote the full "balancer://name". */
    if (!strncasecmp(arg, BALANCER_PREFIX, sizeof(BALANCER_PREFIX) - 1)) {
        arg += sizeof(BALANCER_PREFIX) - 1;
    }
    if (!*arg) {
        return "ProxyBeaconBalancer: empty balancer name";
    }
    ctx->balancer_name = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *beacon_set_interval(cmd_parms *cmd, void *dummy,
                                    const char *arg)
{
    beacon_ctx_t *ctx = ap_get_module_config(cmd->server->module_config,
                                          &proxy_beacon_module);
    apr_interval_time_t iv;
    apr_status_t rv;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    rv = ap_timeout_parameter_parse(arg, &iv, "s");
    if (rv != APR_SUCCESS) {
        return "Unparse-able ProxyBeaconInterval setting";
    }
    if (iv < AP_WD_TM_SLICE) {
        return apr_psprintf(cmd->pool,
                            "ProxyBeaconInterval must be greater than %"
                            APR_TIME_T_FMT "ms",
                            apr_time_as_msec(AP_WD_TM_SLICE));
    }
    ctx->interval = iv;
    return NULL;
}

static const char *beacon_set_timeout(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    beacon_ctx_t *ctx = ap_get_module_config(cmd->server->module_config,
                                          &proxy_beacon_module);
    apr_interval_time_t iv;
    apr_status_t rv;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    rv = ap_timeout_parameter_parse(arg, &iv, "s");
    if (rv != APR_SUCCESS || iv < 0) {
        return "ProxyBeaconTimeout must be a non-negative time (0 disables "
               "eviction)";
    }
    /* 0 = eviction disabled (pure announce-and-add behavior). */
    ctx->evict_timeout = iv;
    return NULL;
}

static int beacon_hexval(char c)
{
    return apr_isdigit(c) ? c - '0' : apr_tolower(c) - 'a' + 10;
}

static const char *beacon_set_secret(cmd_parms *cmd, void *dummy, const char *arg)
{
    beacon_ctx_t *ctx = ap_get_module_config(cmd->server->module_config,
                                          &proxy_beacon_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    if (!*arg) {
        return "ProxyBeaconSecret: empty secret";
    }
    /* hex:<32 hex digits> is the key itself: a random 128-bit key has no
     * passphrase to guess, so it needs no key derivation. */
    if (!strncmp(arg, BEACON_HEXKEY_PREFIX, sizeof(BEACON_HEXKEY_PREFIX) - 1)) {
        const char *h = arg + sizeof(BEACON_HEXKEY_PREFIX) - 1;
        int i;

        if (strlen(h) != 2 * sizeof(ctx->mac_key)) {
            return apr_psprintf(cmd->pool,
                                "ProxyBeaconSecret: hex: needs exactly %d hex "
                                "digits (e.g. from 'openssl rand -hex %d')",
                                (int)(2 * sizeof(ctx->mac_key)),
                                (int)sizeof(ctx->mac_key));
        }
        for (i = 0; i < (int)sizeof(ctx->mac_key); i++) {
            if (!apr_isxdigit(h[2 * i]) || !apr_isxdigit(h[2 * i + 1])) {
                return "ProxyBeaconSecret: hex: value has a non-hex digit";
            }
            ctx->mac_key[i] = (unsigned char)
                ((beacon_hexval(h[2 * i]) << 4) | beacon_hexval(h[2 * i + 1]));
        }
        ctx->has_secret = 1;
        return NULL;
    }
    /* The MAC key is derived from the passphrase with a fast hash, so anyone who
     * captures one announcement can test guesses offline at full speed; only a
     * long random secret resists that. */
    if (strlen(arg) < BEACON_MIN_SECRET_LEN) {
        return apr_psprintf(cmd->pool,
                            "ProxyBeaconSecret: the secret must be at least %d "
                            "characters (use a long random value)",
                            BEACON_MIN_SECRET_LEN);
    }
    /* Derive a 16-byte SipHash key from the passphrase.  This is key
     * derivation (spreading the shared secret to the key size both ends use),
     * not message hashing, so MD5 is fine here -- same approach as
     * mod_session_crypto.c's compute_auth(). */
    apr_md5(ctx->mac_key, arg, strlen(arg));
    ctx->has_secret = 1;
    return NULL;
}

static const char *beacon_set_maxskew(cmd_parms *cmd, void *dummy, const char *arg)
{
    beacon_ctx_t *ctx = ap_get_module_config(cmd->server->module_config,
                                          &proxy_beacon_module);
    apr_interval_time_t iv;
    apr_status_t rv;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    rv = ap_timeout_parameter_parse(arg, &iv, "s");
    if (rv != APR_SUCCESS || iv <= 0) {
        return "ProxyBeaconMaxSkew must be a positive time (replay window)";
    }
    ctx->max_skew = iv;
    return NULL;
}

static const command_rec beacon_cmds[] = {
    AP_INIT_TAKE_ARGV("ProxyBeaconListen", beacon_set_sub_url, NULL, RSRC_CONF,
                  "reverse proxy: UDP address [host][:port] to receive beacons "
                  "on. An omitted host or port (or no argument at all) is "
                  "inherited from this server's own address and port, so the "
                  "beacon channel can share the service endpoint. "
                  "e.g. 0.0.0.0:5555"),
    AP_INIT_TAKE1("ProxyBeaconAddress", beacon_set_pub_url, NULL, RSRC_CONF,
                  "backend: UDP address host:port of the proxy to send beacons "
                  "to, e.g. proxy-host:5555"),
    AP_INIT_TAKE1("ProxyBeaconInterval", beacon_set_interval, NULL, RSRC_CONF,
                  "backend announcement interval in seconds (default 5)"),
    AP_INIT_TAKE1("ProxyBeaconAdvertise", beacon_set_advertise, NULL, RSRC_CONF,
                  "backend: routable URL to advertise to the proxy, "
                  "e.g. http://10.0.0.5:8080 (added as a BalancerMember)"),
    AP_INIT_TAKE1("ProxyBeaconBalancer", beacon_set_balancer, NULL, RSRC_CONF,
                  "proxy: name of the balancer that announced backends are "
                  "added to, e.g. mycluster (for balancer://mycluster)"),
    AP_INIT_TAKE1("ProxyBeaconTimeout", beacon_set_timeout, NULL, RSRC_CONF,
                  "proxy: seconds without an announcement after which a backend "
                  "is disabled (taken out of rotation); 0 disables eviction"),
    AP_INIT_TAKE1("ProxyBeaconSecret", beacon_set_secret, NULL, RSRC_CONF,
                  "pre-shared cluster secret (REQUIRED); set to the same value on "
                  "the proxy and all backends to authenticate announcements "
                  "(SipHash MAC). Keep the conf file readable only by the server "
                  "user."),
    AP_INIT_TAKE1("ProxyBeaconMaxSkew", beacon_set_maxskew, NULL, RSRC_CONF,
                  "proxy: max allowed seconds between an announcement's timestamp "
                  "and now (anti-replay window; requires NTP-synced clocks). "
                  "Default 30 seconds."),
    { NULL }
};

/*
 * Resolve a "[scheme://][host][:port]" address string to a UDP sockaddr.  Any
 * leading scheme (e.g. tcp://) is accepted and ignored, so addresses written
 * with a transport scheme keep working.  A NULL/empty url, or an omitted host
 * or port, is filled from the caller-supplied defaults:
 *   - default_host NULL  -> bind/resolve the wildcard address (all interfaces);
 *   - default_port 0     -> the port is then required (APR_EINVAL if missing).
 * Letting the host/port be inherited lets the beacon channel share the server's
 * own address:port; UDP and TCP are independent port spaces, so binding UDP:N
 * does not collide with the server's TCP listener.  *addr_out is from p.
 */
/*
 * Split "[host][:port]". apr_parse_addr_port() refuses a string that starts
 * with ':', which the directive syntax allows to mean "this server's host".
 */
static apr_status_t beacon_parse_hostport(apr_pool_t *p, const char *hostport,
                                          char **host, apr_port_t *port)
{
    char *scope;

    if (*hostport == ':') {
        apr_off_t val;
        char *end;

        if (apr_isdigit(hostport[1]) == 0
            || apr_strtoff(&val, hostport + 1, &end, 10) != APR_SUCCESS
            || *end || val < 1 || val > 65535) {
            return APR_EINVAL;
        }
        *host = NULL;
        *port = (apr_port_t)val;
        return APR_SUCCESS;
    }
    return apr_parse_addr_port(host, &scope, port, hostport, p);
}

static apr_status_t beacon_resolve(apr_pool_t *p, const char *url,
                                   const char *default_host,
                                   apr_port_t default_port,
                                   apr_sockaddr_t **addr_out)
{
    char *host = NULL;
    apr_port_t port = 0;
    apr_status_t rv;

    if (url && *url) {
        const char *hostport = url, *sep;
        if ((sep = ap_strstr_c(url, "://")) != NULL) {
            hostport = sep + 3;
        }
        rv = beacon_parse_hostport(p, hostport, &host, &port);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }
    if (!host || !*host) {
        host = (char *)default_host;   /* NULL -> wildcard (any address) */
    }
    if (!port) {
        port = default_port;
    }
    if (!port) {
        return APR_EINVAL;             /* no port given and none to inherit */
    }
    return apr_sockaddr_info_get(addr_out, host, APR_UNSPEC, port, 0, p);
}

/*
 * The listener may inherit its bind host/port from this server (so the beacon
 * channel can share the server's own endpoint).  Derive a concrete address/port
 * from the server's actual bound listeners (ap_listeners) -- this reflects the
 * real Listen socket (e.g. 0.0.0.0), which is what the beacon should match, and
 * avoids leaving the host NULL (which resolves to the IPv6 wildcard and could
 * miss IPv4 senders on a v6-only-strict host).  The port is the server's own
 * (ServerName/Listen) port; the host is taken from the listener on that port,
 * else the first listener.  Either output may remain unset (host NULL / port 0)
 * if no listeners are configured.
 */
static void beacon_server_default_addr(server_rec *s, const char **host_out,
                                       apr_port_t *port_out)
{
    const char *host = NULL;
    apr_port_t port = s->port;
    ap_listen_rec *lr, *match = NULL;

    for (lr = ap_listeners; lr; lr = lr->next) {
        if (!lr->bind_addr) {
            continue;
        }
        if (!match) {
            match = lr;                 /* first, as a fallback */
        }
        if (port && lr->bind_addr->port == port) {
            match = lr;                 /* prefer the server's own port */
            break;
        }
    }
    if (match && match->bind_addr) {
        char *ip = NULL;
        if (!port) {
            port = match->bind_addr->port;
        }
        if (apr_sockaddr_ip_get(&ip, match->bind_addr) == APR_SUCCESS) {
            host = ip;
        }
    }

    *host_out = host;
    *port_out = port;
}

/* STARTING: open the UDP socket; listener binds to receive, sender resolves
 * its destination. */
static void beacon_cb_starting(beacon_ctx_t *ctx)
{
    server_rec *s = ctx->s;
    apr_status_t rv;

    /* After an open/bind failure, wait for the retry in beacon_cb_running()
     * (BEACON_OPEN_RETRY): retrying on every ~100ms watchdog tick would fill
     * the error log. */
    if (ctx->opened || ctx->open_failed) {
        return;
    }

    /* The address and socket of an attempt live in their own pool, cleared
     * before each retry so a persistent failure does not grow ctx->p. */
    if (ctx->addr_pool) {
        apr_pool_destroy(ctx->addr_pool);
        ctx->addr_pool = NULL;
    }
    if (ctx->open_pool) {
        apr_pool_clear(ctx->open_pool);
    }
    else {
        apr_pool_create(&ctx->open_pool, ctx->p);
    }

    if (ctx->role == BEACON_ROLE_LISTEN) {
        /* An omitted host and/or port in ProxyBeaconListen is inherited from
         * this server's own address/port (ServerName/Listen), so the beacon
         * channel can share the server's service endpoint.  UDP and TCP are
         * independent, so binding UDP:<port> does not collide with the server's
         * TCP listener.  (A privileged port still cannot be bound here -- this
         * callback runs in an unprivileged watchdog child -- so endpoint sharing
         * is for non-privileged service ports.) */
        const char *defhost;
        apr_port_t defport;
        beacon_server_default_addr(s, &defhost, &defport);
        if ((rv = beacon_resolve(ctx->open_pool, ctx->sub_url, defhost, defport,
                                 &ctx->addr)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10567) "mod_proxy_beacon: cannot resolve "
                         "ProxyBeaconListen address '%s' (an omitted port "
                         "requires a known server port)",
                         *ctx->sub_url ? ctx->sub_url : "(inherit)");
            ctx->open_failed = 1;
            return;
        }
        if ((rv = apr_socket_create(&ctx->sock, ctx->addr->family, SOCK_DGRAM,
                                    APR_PROTO_UDP, ctx->open_pool)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10568) "mod_proxy_beacon: apr_socket_create failed");
            ctx->open_failed = 1;
            return;
        }
        apr_socket_opt_set(ctx->sock, APR_SO_REUSEADDR, 1);
        /* Receiving must never block: it happens on the watchdog thread. */
        if ((rv = apr_socket_opt_set(ctx->sock, APR_SO_NONBLOCK, 1))
                != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10637) "mod_proxy_beacon: cannot make the "
                         "listening socket non-blocking");
            apr_socket_close(ctx->sock);
            ctx->open_failed = 1;
            return;
        }
        if ((rv = apr_socket_bind(ctx->sock, ctx->addr)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10569) "mod_proxy_beacon: bind to %pI failed",
                         ctx->addr);
            apr_socket_close(ctx->sock);
            ctx->open_failed = 1;
            return;
        }
        ctx->opened = 1;
        ctx->io_errors = 0;
        {
            /* Nothing could have been received while the socket was closed:
             * do not evict members for that silence. */
            apr_hash_index_t *hi;
            apr_time_t t = apr_time_now();

            for (hi = apr_hash_first(ctx->open_pool, ctx->seen); hi;
                 hi = apr_hash_next(hi)) {
                void *val;

                apr_hash_this(hi, NULL, NULL, &val);
                ((beacon_member_t *)val)->last_seen = t;
            }
        }
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                     APLOGNO(10570) "mod_proxy_beacon: listening for beacons on %pI",
                     ctx->addr);
        /* Warn if no balancer is configured: beacons will be logged but no
         * backend workers will be added (Phase-1 log-only behavior). */
        if (!ctx->balancer_name) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         APLOGNO(10571) "mod_proxy_beacon: listener on %pI has no "
                         "ProxyBeaconBalancer; beacons will be logged only. "
                         "Set ProxyBeaconBalancer to add announced backends.",
                         ctx->addr);
        }
    }
    else if (ctx->role == BEACON_ROLE_SEND) {
        /* Sender: the destination host:port targets the proxy and cannot be
         * inferred from this backend's own address, so both must be given
         * explicitly (no defaults). */
        if ((rv = beacon_resolve(ctx->open_pool, ctx->pub_url, NULL, 0, &ctx->addr))
                != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10573) "mod_proxy_beacon: cannot resolve "
                         "ProxyBeaconAddress '%s' (must be host:port)",
                         ctx->pub_url);
            ctx->open_failed = 1;
            return;
        }
        if ((rv = apr_socket_create(&ctx->sock, ctx->addr->family, SOCK_DGRAM,
                                    APR_PROTO_UDP, ctx->open_pool)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10574) "mod_proxy_beacon: apr_socket_create failed");
            ctx->open_failed = 1;
            return;
        }
        /* UDP is connectionless: no dial, no reconnect.  Datagrams are sent to
         * ctx->addr each interval; if the proxy isn't up yet they are simply
         * dropped and the next interval tries again. */
        if ((rv = apr_socket_opt_set(ctx->sock, APR_SO_NONBLOCK, 1))
                != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10638) "mod_proxy_beacon: cannot make the "
                         "sending socket non-blocking");
            apr_socket_close(ctx->sock);
            ctx->open_failed = 1;
            return;
        }
        ctx->opened = 1;
        ctx->io_errors = 0;
        ctx->next_refresh = apr_time_now() + BEACON_REFRESH;
        ctx->last_publish = 0; /* beacon on the first running tick */
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                     APLOGNO(10575) "mod_proxy_beacon: beaconing to %pI", ctx->addr);
    }
}

/*
 * Synthesize a minimal request_rec for balancer_manage(), which runs here in
 * the watchdog thread with no real client request.  Adapted from
 * mod_proxy_hcheck.c's create_request_rec (same watchdog context), but that one
 * attaches a real backend conn_rec before logging; we have none, so we fabricate
 * a minimal conn_rec too.
 *
 * balancer_manage()/balancer_process_balancer_worker() touch only r->pool,
 * r->server, and ap_log_rerror().  ap_log_rerror is the trap: log_error_core()
 * asserts r->connection != NULL and do_errorlog_default() unconditionally reads
 * r->connection->outgoing, while add_log_id()->core_generate_log_id() reads
 * c->current_thread.  So we (a) give r a non-NULL conn_rec with ->outgoing set,
 * and (b) pre-set r->log_id / c->log_id so the log-id generation path is skipped
 * entirely.
 */
static request_rec *beacon_make_fake_request(apr_pool_t *p, server_rec *s)
{
    conn_rec *c = apr_pcalloc(p, sizeof(*c));
    request_rec *r = apr_pcalloc(p, sizeof(*r));

    c->pool         = p;
    c->base_server  = s;
    c->log          = &s->log;
    c->log_id       = "beacon";    /* non-NULL -> skip add_log_id/log-id gen */
    c->outgoing     = 1;        /* read by do_errorlog_default() */
    c->client_ip    = "-";
    c->notes        = apr_table_make(p, 1);

    r->pool           = p;
    r->server         = s;
    r->connection     = c;
    r->log            = &s->log;
    r->log_id         = "beacon";
    r->per_dir_config = s->lookup_defaults;
    r->request_config = ap_create_request_config(p);
    r->notes          = apr_table_make(p, 4);
    r->subprocess_env = apr_table_make(p, 4);
    r->headers_in     = apr_table_make(p, 1);
    r->headers_out    = apr_table_make(p, 1);
    r->err_headers_out = apr_table_make(p, 1);
    r->useragent_ip   = "-";
    r->useragent_addr = NULL;
    r->proxyreq       = PROXYREQ_PROXY;
    r->status         = HTTP_OK;

    return r;
}

/*
 * Resolve mod_proxy_balancer's balancer_manage() optional fn (lazily, cached).
 * Registered at hook-registration time, so available by the time we run.
 */
static int beacon_have_manage_fn(beacon_ctx_t *ctx)
{
    if (!ctx->manage_fn) {
        ctx->manage_fn = APR_RETRIEVE_OPTIONAL_FN(balancer_manage);
        if (!ctx->manage_fn) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ctx->s,
                         APLOGNO(10576) "mod_proxy_beacon: balancer_manage unavailable "
                         "(is mod_proxy_balancer loaded?)");
            return 0;
        }
    }
    return 1;
}

/* Status flags a beacon worker is created with (see b_nwrkr_flags). */
static const char beacon_new_flags[] = { PROXY_WORKER_BEACON_FLAG, '\0' };

/*
 * Look up url among the members of the configured balancer.  Beacon only ever
 * deals in canonical origins (see beacon_canonical_url()), for which the
 * balancer's longest-prefix lookup can only match the worker of that exact name.
 * balancer_manage()/balancer_process_balancer_worker() silently succeed on an
 * operation on a worker they cannot find, so callers use this to learn what
 * really happened.  Returns NULL if there is no such member.
 */
static proxy_worker *beacon_find_worker(beacon_ctx_t *ctx, apr_pool_t *pool,
                                        const char *url)
{
    proxy_server_conf *conf =
        ap_get_module_config(ctx->s->module_config, &proxy_module);
    proxy_balancer *bsel = ap_proxy_get_balancer(pool, conf,
            apr_pstrcat(pool, BALANCER_PREFIX, ctx->balancer_name, NULL), 0);
    proxy_worker *w;

    if (!bsel) {
        return NULL;
    }
    /* A worker added through another child's balancer-manager is not in this
     * process's view until synced; without it the ownership check is blind. */
    PROXY_THREAD_LOCK(bsel);
    ap_proxy_sync_balancer(bsel, ctx->s, conf);
    w = ap_proxy_get_worker(pool, bsel, conf, url);
    PROXY_THREAD_UNLOCK(bsel);
    return w;
}

static int beacon_worker_exists(beacon_ctx_t *ctx, apr_pool_t *pool,
                                const char *url)
{
    return beacon_find_worker(ctx, pool, url) != NULL;
}

/*
 * Set (or clear) a worker's DISABLED flag via balancer_manage -- the exact path
 * the balancer-manager UI uses (params { b, w, w_status_D }).  This is how both
 * "enable" (disabled=0) and "evict" (disabled=1) are performed.  Returns
 * APR_SUCCESS on success.
 */
static apr_status_t beacon_set_worker_disabled(beacon_ctx_t *ctx, apr_pool_t *pool,
                                            const char *url, int disabled)
{
    apr_pool_t *subp;
    request_rec *r;
    apr_table_t *params;
    apr_status_t rv;

    /* ctx->manage_fn is resolved lazily; a status change can be the first
     * balancer operation this process performs (e.g. re-enabling a member
     * adopted from the previous watchdog owner). */
    if (!beacon_have_manage_fn(ctx)) {
        return APR_EGENERAL;
    }

    /* balancer_manage() reports success when it finds no such worker, which
     * would let us record a status change that never happened. */
    if (!beacon_worker_exists(ctx, pool, url)) {
        return APR_ENOENT;
    }

    apr_pool_create(&subp, pool);
    r = beacon_make_fake_request(subp, ctx->s);

    params = apr_table_make(subp, 4);
    apr_table_setn(params, "b", ctx->balancer_name);
    apr_table_setn(params, "w", url);
    apr_table_setn(params, "w_status_D", disabled ? "1" : "0");
    rv = ctx->manage_fn(r, params);

    apr_pool_destroy(subp);
    return rv;
}

/*
 * Emit a rate-limited (~1/s) message about dropped/failed announcements, so a
 * full balancer or a flood of bad urls can't flood the error log.  Shares the
 * counter/timer with the Phase-4 rejection logging.
 */
static void beacon_log_throttled(beacon_ctx_t *ctx, apr_time_t now, const char *what)
{
    ctx->reject_count++;
    if (ctx->last_reject_log == 0
        || now - ctx->last_reject_log >= apr_time_from_sec(1)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ctx->s,
                     APLOGNO(10577) "mod_proxy_beacon: dropped %" APR_UINT64_T_FMT
                     " announcement(s) (last: %s)", ctx->reject_count, what);
        ctx->reject_count = 0;
        ctx->last_reject_log = now;
    }
}

/*
 * Attempt to add (and enable) url as a member of the configured balancer,
 * reusing balancer_manage().  Two calls: add (the worker is created DISABLED by
 * default), then clear the DISABLED flag so it serves traffic.  Updates the
 * caller-owned member entry m: m->added is set on success.  Returns APR_SUCCESS
 * on success.  A failure here (e.g. the balancer is full) is expected and
 * handled by the caller via backoff, not retried every announcement.
 *
 * Beacon only manages workers it created: a worker it adds is marked with
 * PROXY_WORKER_BEACON, which lives in the worker's shared state and so outlives
 * both this process and the watchdog owner that set it.  A same-named worker
 * that is not so marked (a BalancerMember from the configuration, or one an
 * administrator added) is left alone.
 */
static apr_status_t beacon_try_add(beacon_ctx_t *ctx, apr_pool_t *pool,
                                const char *url, beacon_member_t *m,
                                apr_time_t now)
{
    server_rec *s = ctx->s;
    apr_pool_t *subp;
    request_rec *r;
    apr_table_t *params;
    apr_status_t rv;
    proxy_worker *w;

    m->last_attempt = now;

    if (!beacon_have_manage_fn(ctx)) {
        return APR_EGENERAL;
    }

    w = beacon_find_worker(ctx, pool, url);
    if (w) {
        /* The normal case after a graceful restart, when the balancer's
         * members (persisted in shared memory) outlive this process's empty
         * ctx->seen: balancer_manage() refuses to re-add an existing worker,
         * so recover it -- otherwise a previously-evicted member would stay
         * DISABLED forever -- but only if it is ours. */
        if (!(w->s->status & PROXY_WORKER_BEACON)) {
            beacon_log_throttled(ctx, now, "member not managed by beacon");
            return APR_EEXIST;
        }
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                     APLOGNO(10589) "mod_proxy_beacon: backend %s already in "
                     "balancer://%s (re-adopted)",
                     url, ctx->balancer_name);
    }
    else {
        /* Step 1: add the worker (created DISABLED).  A genuinely full
         * balancer fails here; that is throttled and retried only after the
         * backoff window, not on every announcement. */
        apr_pool_create(&subp, pool);
        r = beacon_make_fake_request(subp, s);
        params = apr_table_make(subp, 4);
        apr_table_setn(params, "b", ctx->balancer_name);
        apr_table_setn(params, "b_nwrkr", url);
        apr_table_setn(params, "b_wyes", "1");
        apr_table_setn(params, "b_nwrkr_flags", beacon_new_flags);
        rv = ctx->manage_fn(r, params);
        apr_pool_destroy(subp);
        if (rv != APR_SUCCESS) {
            beacon_log_throttled(ctx, now, "balancer add failed (full?)");
            return rv;
        }
        w = beacon_find_worker(ctx, pool, url);
        if (!w) {
            /* balancer_manage() said yes but there is no such member: don't
             * claim a registration that did not happen. */
            beacon_log_throttled(ctx, now, "balancer add not confirmed");
            return APR_ENOENT;
        }
        if (!(w->s->status & PROXY_WORKER_BEACON)) {
            /* Whatever this is, balancer_manage() did not create it with our
             * mark, so it is not ours to manage (and to evict). */
            beacon_log_throttled(ctx, now, "member not created by beacon");
            return APR_EEXIST;
        }
    }

    /* Step 2: enable it (clear the DISABLED flag) so it serves traffic.
     * beacon_set_worker_disabled is self-contained -- it creates its own subpool
     * from `pool`. */
    rv = beacon_set_worker_disabled(ctx, pool, url, 0);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     APLOGNO(10578) "mod_proxy_beacon: added but failed to enable worker %s "
                     "in balancer://%s; will retry on its next announcement",
                     url, ctx->balancer_name);
        /* Still a member, but disabled: recorded as evicted, so that the next
         * announcement enables it (beacon_handle_announce). */
        m->added = 1;
        m->evicted = 1;
        return rv;
    }

    m->added = 1;
    m->evicted = 0;
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 APLOGNO(10579) "mod_proxy_beacon: added backend %s to balancer://%s",
                 url, ctx->balancer_name);
    return APR_SUCCESS;
}

/*
 * Member records come from a free list, so the memory used for tracking is
 * bounded by BEACON_MAX_MEMBERS records however many are reclaimed and
 * recreated.  Returns NULL if url does not fit.
 */
static beacon_member_t *beacon_member_new(beacon_ctx_t *ctx, const char *url,
                                          apr_time_t now)
{
    beacon_member_t *m;

    if (strlen(url) >= BEACON_URL_MAX) {
        return NULL;
    }
    if (ctx->free_members) {
        m = ctx->free_members;
        ctx->free_members = m->next_free;
    }
    else {
        m = apr_palloc(ctx->p, sizeof(*m));
    }
    memset(m, 0, sizeof(*m));
    strcpy(m->url, url);
    m->last_seen = now;
    apr_hash_set(ctx->seen, m->url, APR_HASH_KEY_STRING, m);
    return m;
}

static void beacon_member_free(beacon_ctx_t *ctx, beacon_member_t *m)
{
    apr_hash_set(ctx->seen, m->url, APR_HASH_KEY_STRING, NULL);
    m->next_free = ctx->free_members;
    ctx->free_members = m;
}

/*
 * Handle one announced url.  Tracks every url in ctx->seen (capped) so that:
 *   - a successful member is deduplicated and its last_seen refreshed;
 *   - a previously-evicted member is re-enabled when it announces again;
 *   - an add that failed (e.g. balancer full) is retried only after a backoff,
 *     not on every announcement.
 * msg_ts is the signed timestamp (microseconds) from the verified message; this
 * path is only reached on the authenticated balancer path, so it is always set.
 */
static void beacon_handle_announce(beacon_ctx_t *ctx, apr_pool_t *pool,
                                const char *url, apr_time_t now,
                                apr_int64_t msg_ts)
{
    beacon_member_t *m = apr_hash_get(ctx->seen, url, APR_HASH_KEY_STRING);

    if (!m) {
        /* Bound memory: don't track unboundedly many distinct urls (defense in
         * depth against a buggy or compromised authenticated backend). */
        if (apr_hash_count(ctx->seen) >= BEACON_MAX_MEMBERS) {
            beacon_log_throttled(ctx, now, "member table full");
            return;
        }
        m = beacon_member_new(ctx, url, now);
        if (!m) {
            return;
        }
        m->last_ts = msg_ts;
        beacon_try_add(ctx, pool, m->url, m, now);
        return;
    }

    /* Anti-replay (2): each url's signed ts must strictly increase.  A replayed
     * (byte-identical) announcement carries a ts we've already accepted, so
     * reject it -- this closes the in-window replay the freshness check alone
     * allows (e.g. replaying a dead backend's last announcement to keep it from
     * being evicted). */
    if (msg_ts <= m->last_ts) {
        beacon_log_throttled(ctx, now, "replayed/reordered ts");
        return;
    }
    m->last_ts = msg_ts;
    m->last_seen = now;

    if (!m->added) {
        /* A prior add failed; retry, but only after the backoff window. */
        if (now - m->last_attempt >= BEACON_RETRY_BACKOFF) {
            beacon_try_add(ctx, pool, url, m, now);
        }
        return;
    }

    if (m->evicted) {
        if (beacon_set_worker_disabled(ctx, pool, url, 0) == APR_SUCCESS) {
            m->evicted = 0;
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ctx->s,
                         APLOGNO(10580) "mod_proxy_beacon: re-enabled backend %s in "
                         "balancer://%s (announcing again)",
                         url, ctx->balancer_name);
        }
    }
}

/*
 * Take over the beacon members already in the balancer.
 *
 * The leases (ctx->seen) are private to the watchdog-owning process, but the
 * members they describe are not: they live in the balancer's shared memory and
 * outlive that process.  When the watchdog singleton moves to another child --
 * after a crash, a recycle, or a restart -- the new owner starts with an empty
 * table and would never evict a member that has since fallen silent, leaving it
 * enabled for good.
 *
 * So, once, at the start of ownership, adopt every member carrying
 * PROXY_WORKER_BEACON and start its lease now: it is evicted after the usual
 * ProxyBeaconTimeout unless it announces again.  A member that is already
 * disabled is recorded as evicted, so that its next announcement re-enables it.
 * Members without the mark (configured or added by an administrator) are not
 * ours and are left alone.
 *
 * The per-member replay high-water mark is not recovered (last_ts starts at 0);
 * see the replay notes in the documentation.
 */
static int beacon_reconcile(beacon_ctx_t *ctx, apr_pool_t *pool, apr_time_t now)
{
    proxy_server_conf *conf =
        ap_get_module_config(ctx->s->module_config, &proxy_module);
    proxy_balancer *bsel = ap_proxy_get_balancer(pool, conf,
            apr_pstrcat(pool, BALANCER_PREFIX, ctx->balancer_name, NULL), 0);
    proxy_worker **workers;
    int i, adopted = 0, untracked = 0;

    if (!bsel) {
        return 0;
    }

    PROXY_THREAD_LOCK(bsel);
    /* Pick up the members the previous owner added: this process's own view of
     * the balancer only knows the ones that existed at configuration time.
     * Without that the picture is incomplete: try again on the next tick. */
    if (ap_proxy_sync_balancer(bsel, ctx->s, conf) != APR_SUCCESS) {
        PROXY_THREAD_UNLOCK(bsel);
        beacon_log_throttled(ctx, now, "takeover: balancer sync failed");
        return 0;
    }

    workers = (proxy_worker **)bsel->workers->elts;
    for (i = 0; i < bsel->workers->nelts; i++) {
        proxy_worker *w = workers[i];
        beacon_member_t *m;

        if (!w->s || !(w->s->status & PROXY_WORKER_BEACON)
            || apr_hash_get(ctx->seen, w->s->name, APR_HASH_KEY_STRING)) {
            continue;
        }
        if (apr_hash_count(ctx->seen) >= BEACON_MAX_MEMBERS) {
            /* No lease can be kept for it, so it would never be evicted: take
             * it out of rotation until it announces again and is adopted. */
            if (!(w->s->status & PROXY_WORKER_DISABLED)) {
                ap_proxy_set_wstatus(PROXY_WORKER_DISABLED_FLAG, 1, w);
                untracked++;
            }
            continue;
        }
        m = beacon_member_new(ctx, w->s->name, now);
        if (!m) {
            continue;
        }
        m->added = 1;
        m->evicted = (w->s->status & PROXY_WORKER_DISABLED) != 0;
        adopted++;
    }
    PROXY_THREAD_UNLOCK(bsel);

    if (adopted) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ctx->s,
                     APLOGNO(10636) "mod_proxy_beacon: took over %d existing "
                     "member(s) of balancer://%s; their leases restart now",
                     adopted, ctx->balancer_name);
    }
    if (untracked) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ctx->s,
                     APLOGNO(10660) "mod_proxy_beacon: balancer://%s has more "
                     "members than the %d beacon can track; disabled %d of "
                     "them until they announce again",
                     ctx->balancer_name, BEACON_MAX_MEMBERS, untracked);
    }
    return 1;
}

/*
 * Periodic sweep (watchdog singleton, throttled by the caller):
 *
 *  - eviction: disable any member that has not announced within evict_timeout
 *    (no-op when eviction is disabled, timeout 0);
 *  - reclamation: forget members that are evicted, or whose add failed, once
 *    they have been silent long enough.  Without this, failed registrations and
 *    departed backends would fill the BEACON_MAX_MEMBERS table for good and lock
 *    out new members.
 *
 * A record also carries the replay high-water mark, so it must outlive any
 * replay of the member's last accepted message.  That message was accepted at
 * last_seen with a timestamp within max_skew of it, so it is stale (rejected by
 * the freshness check) after last_seen + 2 * max_skew; reclaiming only after that
 * loses no replay protection.  A reclaimed member that announces again is simply
 * recreated: its worker is still in the balancer and is re-adopted.
 */
static void beacon_sweep(beacon_ctx_t *ctx, apr_pool_t *pool, apr_time_t now)
{
    apr_hash_index_t *hi;
    apr_time_t skew = ctx->max_skew > 0 ? ctx->max_skew : BEACON_MAXSKEW_DEFAULT;
    /* Saturate: MaxSkew is any positive time the administrator wrote. */
    apr_time_t reclaim_after =
        skew > (APR_INT64_MAX - apr_time_from_sec(1)) / 2
        ? APR_INT64_MAX : 2 * skew + apr_time_from_sec(1);

    for (hi = apr_hash_first(pool, ctx->seen); hi; hi = apr_hash_next(hi)) {
        void *val;
        beacon_member_t *m;

        apr_hash_this(hi, NULL, NULL, &val);
        m = val;
        if (ctx->evict_timeout > 0 && m->added && !m->evicted
            && now - m->last_seen > ctx->evict_timeout
            && beacon_have_manage_fn(ctx)) {
            if (beacon_set_worker_disabled(ctx, pool, m->url, 1) == APR_SUCCESS) {
                m->evicted = 1;
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ctx->s,
                             APLOGNO(10581) "mod_proxy_beacon: evicted backend %s from "
                             "balancer://%s (no announcement for %"
                             APR_TIME_T_FMT "s)",
                             m->url, ctx->balancer_name,
                             apr_time_sec(now - m->last_seen));
            }
        }
        else if ((!m->added || m->evicted)
                 && now - m->last_seen > reclaim_after) {
            /* Safe while iterating: only the current entry is removed. */
            beacon_member_free(ctx, m);
        }
    }
}

/*
 * Extract the value of the "url=" token from a beacon message into buf.
 * Returns 1 on success.  The payload is untrusted network input, so parse
 * defensively: the token is "url=" followed by non-space characters.
 */
static int beacon_parse_url(const char *msg, char *buf, apr_size_t buflen)
{
    const char *p = msg;

    while (p && *p) {
        if (!strncmp(p, "url=", 4)) {
            apr_size_t i = 0;
            p += 4;
            while (*p && *p != ' ' && i + 1 < buflen) {
                buf[i++] = *p++;
            }
            buf[i] = '\0';
            /* A token that does not fit is rejected, not silently cut short:
             * the truncated prefix could be a different, valid-looking url. */
            if (*p && *p != ' ') {
                return 0;
            }
            return (i > 0);
        }
        /* advance to the next space-separated token */
        p = ap_strchr_c(p, ' ');
        if (p) {
            p++;
        }
    }
    return 0;
}

/* ----- Phase 4: channel authentication (SipHash MAC + timestamp) ----- */

/* Constant-time buffer compare (time depends only on size, not contents) --
 * avoids a timing oracle on the MAC.  apr_crypto_equals() would do this but is
 * gated behind APU_HAVE_CRYPTO, which isn't always built; this is the same
 * branchless idiom. */
static int beacon_const_time_eq(const void *a, const void *b, apr_size_t n)
{
    const unsigned char *p1 = a, *p2 = b;
    volatile unsigned char diff = 0;
    apr_size_t i;
    for (i = 0; i < n; i++) {
        diff |= p1[i] ^ p2[i];
    }
    return diff == 0;
}

/* Hex-encode the SipHash-2-4 MAC of [base, base+len) into out (BEACON_MAC_HEXLEN+1
 * bytes). */
static void beacon_mac_hex(const beacon_ctx_t *ctx, const char *base,
                        apr_size_t len, char *out)
{
    unsigned char mac[APR_SIPHASH_DSIZE];
    apr_siphash24_auth(mac, base, len, ctx->mac_key);
    ap_bin2hex(mac, sizeof(mac), out);   /* writes BEACON_MAC_HEXLEN + NUL */
}

/* sender: return "<base> mac=<hex>", appending the keyed MAC.  A secret is
 * required on every participating server (enforced at config time), so this
 * always signs. */
static const char *beacon_sign(beacon_ctx_t *ctx, apr_pool_t *pool, const char *base)
{
    char hex[BEACON_MAC_HEXLEN + 1];

    beacon_mac_hex(ctx, base, strlen(base), hex);
    return apr_psprintf(pool, "%s mac=%s", base, hex);
}

/*
 * Parse a timestamp token value strictly: 1 to 18 decimal digits, ending at a
 * space or the end of the string.  apr_atoi64() would also accept a sign,
 * leading space, trailing garbage and out-of-range values, and arithmetic on an
 * extreme timestamp could overflow.
 */
static int beacon_parse_ts(const char *p, apr_int64_t *out)
{
    apr_int64_t v = 0;
    int n = 0;

    for (; apr_isdigit(*p); p++, n++) {
        if (n >= 18) {
            return 0;
        }
        v = v * 10 + (*p - '0');
    }
    if (!n || (*p && *p != ' ')) {
        return 0;
    }
    *out = v;
    return 1;
}

/*
 * Check the wire grammar of a message whose MAC has already been verified:
 *
 *     BEACON <key>=<value> <key>=<value> ... mac=<hex>
 *
 * one leading BEACON marker, single-space-separated key=value tokens with a
 * lower-case key and a non-empty value, and no repeated field among the ones we
 * know.  Without this the receiver reads fields by searching the string (the
 * last "ts=" wins, a leading marker is never checked, a repeated field is
 * silently resolved one way), so two parties can read the same signed bytes
 * differently.  Returns the ts= value via *tsp (NULL if absent).
 */
static const char *beacon_frame_check(const char *msg, const char **tsp,
                                      const char **reason)
{
    static const char * const known[] = {
        "url", "host", "pid", "seq", "ts", "mac"
    };
    unsigned seen = 0;
    const char *p = msg;

    *tsp = NULL;
    if (strncmp(p, "BEACON ", 7)) {
        return *reason = "bad frame", NULL;
    }
    p += 7;

    while (*p) {
        const char *key = p, *eq;
        apr_size_t klen;
        unsigned i;

        while (*p && *p != ' ') {
            p++;
        }
        eq = memchr(key, '=', p - key);
        if (p == key || !eq || eq == key || eq + 1 == p) {
            return *reason = "bad frame", NULL;
        }
        for (klen = 0; key + klen < eq; klen++) {
            if (!apr_islower(key[klen])) {
                return *reason = "bad frame", NULL;
            }
        }
        for (i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
            if (strlen(known[i]) == klen && !strncmp(key, known[i], klen)) {
                if (seen & (1u << i)) {
                    return *reason = "duplicate field", NULL;
                }
                seen |= 1u << i;
                if (!strcmp(known[i], "ts")) {
                    *tsp = eq + 1;
                }
                break;
            }
        }
        if (*p == ' ') {
            p++;
            if (!*p) {
                return *reason = "bad frame", NULL;  /* trailing space */
            }
        }
    }
    return msg;
}

/*
 * listener: verify a received, NUL-terminated message.  Returns 1 if the MAC matches
 * the pre-shared key, the message is well-formed, AND the ts= timestamp is within
 * ctx->max_skew of now.
 * Only called when ctx->has_secret.  Constant-time MAC compare.  On success the
 * parsed ts= (microseconds since the epoch) is written to *ts_out for the
 * caller's per-url monotonic replay check.  reason (out) is set on failure.
 */
static int beacon_verify(beacon_ctx_t *ctx, const char *msg, apr_time_t now,
                      apr_int64_t *ts_out, const char **reason)
{
    const char *macp = NULL, *p, *tsp;
    char expected[BEACON_MAC_HEXLEN + 1];
    apr_size_t prefix_len;
    apr_int64_t ts, skew, delta;

    /* Locate the last " mac=" -- the MAC covers everything before it. */
    for (p = msg; (p = ap_strstr_c(p, " mac=")) != NULL; p += 5) {
        macp = p;
    }
    if (!macp) {
        *reason = "no mac";
        return 0;
    }
    /* mac= must be the final field: exactly BEACON_MAC_HEXLEN chars followed by
     * end-of-string.  strlen is NUL-safe here -- the caller hands us a
     * NUL-terminated copy with no embedded NUL -- so a short or garbled payload
     * cannot make the constant-time compare below over-read past the buffer.
     * The compare itself validates the hex content; we deliberately do not
     * pre-scan for hex digits, which would leak MAC bytes through an early
     * exit (timing oracle). */
    if (strlen(macp + 5) != BEACON_MAC_HEXLEN) {
        *reason = "bad mac length";
        return 0;
    }

    prefix_len = (apr_size_t)(macp - msg);
    beacon_mac_hex(ctx, msg, prefix_len, expected);
    if (!beacon_const_time_eq(expected, macp + 5, BEACON_MAC_HEXLEN)) {
        *reason = "mac mismatch";
        return 0;
    }

    /* Authentic.  Now insist it is also well-formed, so that every reader of
     * these bytes sees the same fields. */
    if (!beacon_frame_check(msg, &tsp, reason)) {
        return 0;
    }

    /* Anti-replay (1): ts= must be present and within the freshness window.
     * ts is in microseconds (raw apr_time_now()) so that announcements made
     * less than a second apart still have strictly-increasing timestamps for
     * the caller's per-url check. */
    if (!tsp) {
        *reason = "no ts";
        return 0;
    }
    if (!beacon_parse_ts(tsp, &ts)) {
        *reason = "bad ts";
        return 0;
    }
    skew = ctx->max_skew > 0 ? ctx->max_skew : BEACON_MAXSKEW_DEFAULT;
    delta = (apr_int64_t)now - ts;      /* both well below 2^62: no overflow */
    if (delta < 0) {
        delta = -delta;
    }
    if (delta > skew) {
        *reason = "stale timestamp";
        return 0;
    }

    *ts_out = ts;
    return 1;
}

/* RUNNING: sender sends a throttled beacon; listener drains its receive socket. */
/*
 * Count a failed send or receive. Returns true if it should be logged, which is
 * at most once in 10 seconds. After BEACON_IO_ERRORS_MAX in a row the socket
 * is closed: the open back-off in beacon_cb_running() opens it again, looking
 * the address up again.
 */
static int beacon_io_failed(beacon_ctx_t *ctx, apr_time_t now)
{
    int log_it = now - ctx->last_io_error_log >= apr_time_from_sec(10);

    if (log_it) {
        ctx->last_io_error_log = now;
    }
    if (++ctx->io_errors >= BEACON_IO_ERRORS_MAX) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ctx->s, APLOGNO(10672)
                     "mod_proxy_beacon: closing the socket after repeated "
                     "errors; it will be opened again");
        apr_socket_close(ctx->sock);
        ctx->opened = 0;
        ctx->open_failed = 1;
        ctx->io_errors = 0;
    }
    return log_it;
}

/*
 * Sender: look the destination up again. The address in use is kept if that
 * fails. This runs on the watchdog thread, so a slow resolver delays the other
 * contexts for as long as the lookup takes: ProxyBeaconAddress should be an IP
 * address, or a name that resolves quickly.
 */
static void beacon_refresh_destination(beacon_ctx_t *ctx, apr_time_t now)
{
    apr_pool_t *np;
    apr_pool_t *old;
    apr_sockaddr_t *na = NULL;
    apr_status_t rv;

    ctx->next_refresh = now + BEACON_REFRESH;
    apr_pool_create(&np, ctx->p);
    rv = beacon_resolve(np, ctx->pub_url, NULL, 0, &na);
    if (rv != APR_SUCCESS) {
        apr_pool_destroy(np);
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ctx->s, APLOGNO(10673)
                     "mod_proxy_beacon: cannot resolve ProxyBeaconAddress '%s' "
                     "again; keeping the address in use", ctx->pub_url);
        return;
    }
    if (na->family != ctx->addr->family) {
        /* The socket belongs to the old family: open a new one. */
        apr_pool_destroy(np);
        apr_socket_close(ctx->sock);
        ctx->opened = 0;
        beacon_cb_starting(ctx);
        return;
    }
    if (!apr_sockaddr_equal(na, ctx->addr)) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ctx->s, APLOGNO(10674)
                     "mod_proxy_beacon: beaconing to %pI now", na);
    }
    old = ctx->addr_pool;
    ctx->addr_pool = np;
    ctx->addr = na;
    if (old) {
        apr_pool_destroy(old);
    }
}

static void beacon_cb_running(beacon_ctx_t *ctx, apr_pool_t *pool)
{
    server_rec *s = ctx->s;
    apr_status_t rv;

    if (ctx->open_failed) {
        /* Retry a failed open, at a pace that cannot flood the log. */
        apr_time_t t = apr_time_now();
        if (!ctx->next_open_try) {
            ctx->open_delay = ctx->open_delay
                              ? ctx->open_delay * 2 : BEACON_OPEN_RETRY;
            if (ctx->open_delay > BEACON_OPEN_RETRY_MAX) {
                ctx->open_delay = BEACON_OPEN_RETRY_MAX;
            }
            ctx->next_open_try = t + ctx->open_delay;
        }
        else if (t >= ctx->next_open_try) {
            ctx->open_failed = 0;
            ctx->next_open_try = 0;
            beacon_cb_starting(ctx);
        }
    }
    if (!ctx->opened) {
        return;
    }
    ctx->open_delay = 0;

    if (ctx->role == BEACON_ROLE_LISTEN && ctx->balancer_name
        && !ctx->reconciled) {
        ctx->reconciled = beacon_reconcile(ctx, pool, apr_time_now());
    }

    if (ctx->role == BEACON_ROLE_SEND) {
        apr_time_t now = apr_time_now();

        if (now >= ctx->next_refresh) {
            beacon_refresh_destination(ctx, now);
            if (!ctx->opened) {
                return;
            }
        }
        if (now >= ctx->last_publish + ctx->interval) {
            const char *host = ctx->s->server_hostname
                                   ? ctx->s->server_hostname : "(unknown)";
            const char *msg;
            char *base;
            apr_size_t len;
            /* Carry the routable URL so the proxy can add us as a member.
             * Without ProxyBeaconAdvertise, fall back to the Phase-1 payload
             * (channel proof only; the listener just logs it).  ts= is the signing
             * timestamp in microseconds (Phase 4 anti-replay): the proxy checks
             * both a freshness window and that it strictly increases per url, so
             * a byte-identical replay (same ts) is rejected.  Harmless when
             * unsigned. */
            if (ctx->advertise_url) {
                base = apr_psprintf(pool,
                            "BEACON url=%s host=%s pid=%" APR_PID_T_FMT
                            " seq=%" APR_UINT64_T_FMT " ts=%" APR_INT64_T_FMT,
                            ctx->advertise_url, host, getpid(), ctx->seq++,
                            (apr_int64_t)now);
            }
            else {
                base = apr_psprintf(pool,
                            "BEACON host=%s pid=%" APR_PID_T_FMT
                            " seq=%" APR_UINT64_T_FMT " ts=%" APR_INT64_T_FMT,
                            host, getpid(), ctx->seq++,
                            (apr_int64_t)now);
            }
            /* Phase 4: append a keyed MAC when a shared secret is configured. */
            msg = beacon_sign(ctx, pool, base);
            /* Send strlen(msg) bytes (no trailing NUL on the wire) as a single
             * UDP datagram to the proxy.  Fire-and-forget; a failure here just
             * means this announcement is lost and the next interval retries. */
            len = strlen(msg);
            if ((rv = apr_socket_sendto(ctx->sock, ctx->addr, 0, msg, &len))
                    != APR_SUCCESS) {
                if (beacon_io_failed(ctx, now)) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                                 APLOGNO(10582) "mod_proxy_beacon: sendto %s "
                                 "failed", ctx->pub_url);
                }
            }
            else {
                ctx->io_errors = 0;
            }
            ctx->last_publish = now;
        }
    }
    else if (ctx->role == BEACON_ROLE_LISTEN) {
        apr_time_t now;
        apr_pool_t *ptemp;
        apr_time_t started = apr_time_now();
        int n;

        apr_pool_create(&ptemp, pool);
        apr_pool_tag(ptemp, "beacon_recv");

        /* Drain the socket every tick (re-enable latency matters), up to
         * BEACON_MAX_DRAIN datagrams and BEACON_DRAIN_BUDGET of time. */
        for (n = 0; n < BEACON_MAX_DRAIN; n++) {
            char buf[BEACON_MAX_MSG_LEN + 2];
            apr_sockaddr_t from;
            /* Ask for one byte more than we accept: recvfrom() silently
             * truncates a longer datagram to the buffer size, so receiving
             * the extra byte is how an oversize datagram is told from one
             * that exactly fits. */
            apr_size_t sz = BEACON_MAX_MSG_LEN + 1;
            apr_time_t msg_now;
            const char *msg_str;
            char url[BEACON_URL_MAX];
            apr_int64_t msg_ts = 0;

            if (n && apr_time_now() - started > BEACON_DRAIN_BUDGET) {
                break;
            }
            apr_pool_clear(ptemp);
            from.pool = ptemp;
            rv = apr_socket_recvfrom(&from, ctx->sock, 0, buf, &sz);
            if (APR_STATUS_IS_EAGAIN(rv)) {
                ctx->io_errors = 0;
                break; /* socket drained */
            }
            if (rv != APR_SUCCESS) {
                if (beacon_io_failed(ctx, apr_time_now())) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                                 APLOGNO(10583) "mod_proxy_beacon: recvfrom "
                                 "failed");
                }
                break;
            }
            ctx->io_errors = 0;
            if (sz == 0) {
                continue; /* empty datagram */
            }

            /* Capture a single wall-clock snapshot for this message so that
             * MAC verification, throttle logging, and last-seen recording all
             * share the same time base (no TOCTOU drift across calls). */
            msg_now = apr_time_now();

            if (sz > BEACON_MAX_MSG_LEN) {
                beacon_log_throttled(ctx, msg_now, "oversize datagram");
                continue;
            }
            /* Our messages are text.  A NUL would end the string every parser
             * below works on while the datagram goes on, so what is verified
             * and what was sent would differ. */
            if (memchr(buf, '\0', sz)) {
                beacon_log_throttled(ctx, msg_now, "embedded NUL");
                continue;
            }
            buf[sz] = '\0';
            msg_str = buf;

            /* Phase 4: verify the MAC and freshness BEFORE logging or acting on
             * the payload, so forged/tampered content is dropped (throttled) and
             * never reaches the INFO log.  A secret is required (enforced at
             * config time) on every participating server, with or without a
             * ProxyBeaconBalancer.  msg_ts (microseconds) is the signed
             * timestamp, used below for the per-url monotonic replay check. */
            {
                const char *reason = "?";
                if (!beacon_verify(ctx, msg_str, msg_now, &msg_ts, &reason)) {
                    beacon_log_throttled(ctx, msg_now, reason);
                    continue;
                }
            }

            /* Escape the payload before it reaches the log, so even an
             * authenticated sender cannot embed newline/control/ANSI sequences
             * to forge or corrupt error-log lines.  Done only after
             * verification so a rejected datagram allocates nothing. */
            if (APLOGinfo(s)) {
                /* An authentic message can be replayed within the freshness
                 * window as often as the sender likes: bound the log. */
                if (msg_now - ctx->recv_log_window >= apr_time_from_sec(1)) {
                    if (ctx->recv_log_suppressed) {
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                                     APLOGNO(10675) "mod_proxy_beacon: %"
                                     APR_UINT64_T_FMT " received: lines left "
                                     "out in the last second",
                                     ctx->recv_log_suppressed);
                    }
                    ctx->recv_log_window = msg_now;
                    ctx->recv_log_count = 0;
                    ctx->recv_log_suppressed = 0;
                }
                if (ctx->recv_log_count < BEACON_RECV_LOG_PER_SEC) {
                    ctx->recv_log_count++;
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                                 APLOGNO(10584) "mod_proxy_beacon: received: %s",
                                 ap_escape_logitem(ptemp, msg_str));
                }
                else {
                    ctx->recv_log_suppressed++;
                }
            }

            if (!ctx->balancer_name) {
                continue;
            }

            /* Phase 2/3: carries a routable url= -> add the backend (or
             * refresh last-seen / re-enable if previously evicted). */
            if (beacon_parse_url(msg_str, url, sizeof(url))) {
                /* A valid MAC only shows the sender holds the secret, not
                 * that it used the bundled sender: apply the sender's rule
                 * here too, and track the member by its canonical origin. */
                const char *canon = beacon_canonical_url(ptemp, url);
                if (!canon) {
                    beacon_log_throttled(ctx, msg_now, "unacceptable url");
                    continue;
                }
                beacon_handle_announce(ctx, ptemp, canon, msg_now, msg_ts);
            }
        }
        apr_pool_destroy(ptemp);

        /* Phase 3: evict backends that stopped announcing.  Throttle the scan
         * to ~1s (the recv drain above already runs every tick). */
        now = apr_time_now();
        if (ctx->balancer_name
            && now - ctx->last_sweep >= apr_time_from_sec(1)) {
            beacon_sweep(ctx, pool, now);
            ctx->last_sweep = now;
        }
    }
}

/* STOPPING: close the socket if we opened it. */
static void beacon_cb_stopping(beacon_ctx_t *ctx)
{
    if (ctx->opened) {
        apr_socket_close(ctx->sock);
        ctx->opened = 0;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s,
                     APLOGNO(10585) "mod_proxy_beacon: socket closed");
    }
}

/*
 * Watchdog callback.  Always returns APR_SUCCESS: a non-success return would
 * unregister the callback and permanently stop the channel, which we never
 * want for a transient socket error.
 */
static apr_status_t beacon_watchdog_callback(int state, void *data,
                                          apr_pool_t *pool)
{
    beacon_ctx_t *ctx = (beacon_ctx_t *)data;

    switch (state) {
    case AP_WATCHDOG_STATE_STARTING:
        beacon_cb_starting(ctx);
        break;
    case AP_WATCHDOG_STATE_RUNNING:
        beacon_cb_running(ctx, pool);
        break;
    case AP_WATCHDOG_STATE_STOPPING:
        beacon_cb_stopping(ctx);
        break;
    }

    return APR_SUCCESS;
}

static int beacon_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                           apr_pool_t *ptemp, server_rec *main_s)
{
    apr_status_t rv;
    server_rec *s;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *beacon_get_instance;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *beacon_register_callback;

    /* post_config runs twice; skip the initial config-test pass. */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    beacon_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    beacon_register_callback =
        APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    if (!beacon_get_instance || !beacon_register_callback) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, main_s,
                     APLOGNO(10586) "mod_proxy_beacon: mod_watchdog is required");
        return !OK;
    }

    rv = beacon_get_instance(&beacon_watchdog, BEACON_WATCHDOG_NAME, 0, 1, pconf);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, main_s,
                     APLOGNO(10587) "mod_proxy_beacon: failed to create watchdog instance (%s)",
                     BEACON_WATCHDOG_NAME);
        return !OK;
    }

    for (s = main_s; s; s = s->next) {
        beacon_ctx_t *ctx = ap_get_module_config(s->module_config,
                                              &proxy_beacon_module);
        /* Skip non-canonical server contexts (shared across vhosts). */
        if (s != ctx->s) {
            continue;
        }
        /* Only servers with a directive participate. */
        if (ctx->role == BEACON_ROLE_NONE) {
            continue;
        }
        /* ProxyBeaconSecret is required on every participating server (sender or
         * listener): the channel is authenticated, with no unauthenticated mode.
         * A UDP source address is trivially spoofable, so an unsigned channel
         * would let anyone who can reach the listen port announce an arbitrary
         * backend url and hijack client traffic.  Fail startup rather than run
         * insecurely. */
        if (!ctx->has_secret) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                         APLOGNO(10572) "mod_proxy_beacon: ProxyBeaconSecret is "
                         "required but not set; the beacon channel must be "
                         "authenticated. Set ProxyBeaconSecret to the same value "
                         "on the proxy and all backends.");
            return !OK;
        }
        rv = beacon_register_callback(beacon_watchdog, AP_WD_TM_SLICE, ctx,
                                   beacon_watchdog_callback);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         APLOGNO(10588) "mod_proxy_beacon: failed to register watchdog callback");
            return !OK;
        }
    }

    return OK;
}

/*
 * "[scheme://][host][:port]" syntax only, with no lookup: a name that does not
 * resolve yet may be fine once the network is up, but a malformed address never
 * is.  A sender needs both host and port; a listener inherits what is omitted.
 */
static int beacon_addr_syntax_ok(apr_pool_t *p, const char *url,
                                 int need_host_port)
{
    char *host = NULL;
    apr_port_t port = 0;
    const char *hostport = url, *sep;

    if (url && (sep = ap_strstr_c(url, "://")) != NULL) {
        hostport = sep + 3;
    }
    if (!hostport || !*hostport) {
        return !need_host_port;
    }
    if (beacon_parse_hostport(p, hostport, &host, &port) != APR_SUCCESS) {
        return 0;
    }
    return !need_host_port || (host && *host && port);
}

/*
 * Everything that is wrong with the configuration for good, however the
 * network is when the server starts, so that "httpd -t" says so and a start
 * does not go ahead only to fail in a child.  What can change (the address
 * resolving, the port binding) is left to the retries in the watchdog callback.
 */
static int beacon_check_config(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *main_s)
{
    server_rec *s, *t;
    int errs = 0, participating = 0;

    for (s = main_s; s; s = s->next) {
        beacon_ctx_t *ctx = ap_get_module_config(s->module_config,
                                                 &proxy_beacon_module);
        if (s != ctx->s || ctx->role == BEACON_ROLE_NONE) {
            continue;
        }
        participating++;

        if (!ctx->has_secret) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, 0, s,
                         APLOGNO(10661) "mod_proxy_beacon: ProxyBeaconSecret "
                         "is required but not set; the beacon channel must be "
                         "authenticated");
            errs++;
        }

        if (ctx->role == BEACON_ROLE_SEND) {
            if (!beacon_addr_syntax_ok(ptemp, ctx->pub_url, 1)) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, 0, s,
                             APLOGNO(10662) "mod_proxy_beacon: "
                             "ProxyBeaconAddress '%s' must be host:port",
                             ctx->pub_url);
                errs++;
            }
            continue;
        }

        if (!beacon_addr_syntax_ok(ptemp, ctx->sub_url, 0)) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, 0, s,
                         APLOGNO(10663) "mod_proxy_beacon: ProxyBeaconListen "
                         "'%s' must be [host][:port]", ctx->sub_url);
            errs++;
        }
        if (ctx->balancer_name) {
            proxy_server_conf *conf = ap_get_module_config(s->module_config,
                                                           &proxy_module);
            if (!conf || !ap_proxy_get_balancer(ptemp, conf,
                    apr_pstrcat(ptemp, BALANCER_PREFIX, ctx->balancer_name,
                                NULL), 0)) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, 0, s,
                             APLOGNO(10664) "mod_proxy_beacon: "
                             "ProxyBeaconBalancer: balancer://%s is not "
                             "defined for this server", ctx->balancer_name);
                errs++;
            }
            if (!APR_RETRIEVE_OPTIONAL_FN(balancer_manage)) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, 0, s,
                             APLOGNO(10665) "mod_proxy_beacon: "
                             "ProxyBeaconBalancer needs mod_proxy_balancer");
                errs++;
            }
        }
        /* Two listeners on one address: only one of them would receive. */
        for (t = main_s; t != s; t = t->next) {
            beacon_ctx_t *other = ap_get_module_config(t->module_config,
                                                       &proxy_beacon_module);
            if (t == other->s && other->role == BEACON_ROLE_LISTEN
                && !strcmp(other->sub_url, ctx->sub_url)) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_WARNING, 0, s,
                             APLOGNO(10667) "mod_proxy_beacon: ProxyBeaconListen "
                             "'%s' is also written for another server; if "
                             "both resolve to the same address, only one of "
                             "them will receive the beacons", ctx->sub_url);
            }
        }
    }

    if (participating
        && !APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance)) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, 0, main_s,
                     APLOGNO(10666) "mod_proxy_beacon: mod_watchdog is "
                     "required");
        errs++;
    }

    return errs ? !OK : OK;
}

static void beacon_register_hooks(apr_pool_t *p)
{
    static const char *const aszSucc[] = { "mod_watchdog.c",
                                           "mod_proxy_balancer.c", NULL };
    ap_hook_check_config(beacon_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(beacon_post_config, NULL, aszSucc, APR_HOOK_LAST);
}

AP_DECLARE_MODULE(proxy_beacon) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    beacon_create_server_config,   /* create per-server config */
    NULL,                       /* merge per-server config */
    beacon_cmds,                   /* command table */
    beacon_register_hooks          /* register hooks */
};
