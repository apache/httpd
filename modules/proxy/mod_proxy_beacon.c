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

/* listener-side per-backend state, keyed by url in ctx->seen. */
typedef struct {
    apr_time_t last_seen;    /* updated on every beacon for this url */
    apr_time_t last_attempt; /* last add attempt (throttles retry when full) */
    apr_int64_t last_ts;     /* highest signed ts= accepted (replay guard) */
    int        added;        /* worker exists in the balancer (add dedup) */
    int        evicted;      /* WE set DISABLED on timeout (guards flip churn) */
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
    APR_OPTIONAL_FN_TYPE(balancer_manage) *manage_fn; /* listener: cached, lazy */
    /* Phase 4: channel authentication. */
    int                  has_secret;   /* ProxyBeaconSecret was set */
    unsigned char        mac_key[APR_MD5_DIGESTSIZE]; /* siphash key (16 bytes) */
    apr_int64_t          max_skew;     /* ProxyBeaconMaxSkew, seconds (replay window) */
    apr_uint64_t         reject_count; /* listener: dropped-since-last-log counter */
    apr_time_t           last_reject_log; /* listener: reject-log rate limiter */
    int                  open_failed;     /* STARTING: socket open/listen/dial failed permanently */
} beacon_ctx_t;

/* SipHash-2-4 output is 8 bytes -> 16 hex chars (+ NUL). */
#define BEACON_MAC_HEXLEN  (APR_SIPHASH_DSIZE * 2)
#define BEACON_MAXSKEW_DEFAULT  30   /* seconds */

/* Max announcement datagram we accept.  Our messages are a few hundred bytes;
 * anything larger is not one of ours and is truncated on receive. */
#define BEACON_MAX_MSG_LEN  2048

/* When an add fails (e.g. the balancer is full), don't retry on every
 * announcement -- back off this long between attempts for a given url. */
#define BEACON_RETRY_BACKOFF    apr_time_from_sec(60)

/* Cap on tracked backend urls, to bound memory against a buggy or compromised
 * (authenticated) backend announcing unboundedly many distinct urls.  Once
 * reached, unknown urls are dropped (rate-limited log) rather than tracked/added. */
#define BEACON_MAX_MEMBERS      256

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

static const char *beacon_set_advertise(cmd_parms *cmd, void *dummy,
                                     const char *arg)
{
    beacon_ctx_t *ctx = ap_get_module_config(cmd->server->module_config,
                                          &proxy_beacon_module);
    apr_uri_t uri;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    /* Must be a routable backend URL (scheme://host[:port]); it becomes a
     * BalancerMember on the proxy. */
    if (apr_uri_parse(cmd->pool, arg, &uri) != APR_SUCCESS
        || !uri.scheme || !uri.hostname) {
        return apr_psprintf(cmd->pool,
                            "ProxyBeaconAdvertise: '%s' is not a valid "
                            "scheme://host[:port] URL", arg);
    }
    ctx->advertise_url = apr_pstrdup(cmd->pool, arg);
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
    ctx->max_skew = apr_time_sec(iv);
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
static apr_status_t beacon_resolve(apr_pool_t *p, const char *url,
                                   const char *default_host,
                                   apr_port_t default_port,
                                   apr_sockaddr_t **addr_out)
{
    char *host = NULL, *scope;
    apr_port_t port = 0;
    apr_status_t rv;

    if (url && *url) {
        const char *hostport = url, *sep;
        if ((sep = ap_strstr_c(url, "://")) != NULL) {
            hostport = sep + 3;
        }
        rv = apr_parse_addr_port(&host, &scope, &port, hostport, p);
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

    /* A prior open/bind failure is treated as permanent: the admin must fix the
     * configuration (bad address, port conflict) and restart.  Without this
     * guard the watchdog would retry every ~100ms and fill the error log. */
    if (ctx->opened || ctx->open_failed) {
        return;
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
        if ((rv = beacon_resolve(ctx->p, ctx->sub_url, defhost, defport,
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
                                    APR_PROTO_UDP, ctx->p)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10568) "mod_proxy_beacon: apr_socket_create failed");
            ctx->open_failed = 1;
            return;
        }
        apr_socket_opt_set(ctx->sock, APR_SO_REUSEADDR, 1);
        apr_socket_opt_set(ctx->sock, APR_SO_NONBLOCK, 1);
        if ((rv = apr_socket_bind(ctx->sock, ctx->addr)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10569) "mod_proxy_beacon: bind to %pI failed",
                         ctx->addr);
            apr_socket_close(ctx->sock);
            ctx->open_failed = 1;
            return;
        }
        ctx->opened = 1;
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
        if ((rv = beacon_resolve(ctx->p, ctx->pub_url, NULL, 0, &ctx->addr))
                != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10573) "mod_proxy_beacon: cannot resolve "
                         "ProxyBeaconAddress '%s' (must be host:port)",
                         ctx->pub_url);
            ctx->open_failed = 1;
            return;
        }
        if ((rv = apr_socket_create(&ctx->sock, ctx->addr->family, SOCK_DGRAM,
                                    APR_PROTO_UDP, ctx->p)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(10574) "mod_proxy_beacon: apr_socket_create failed");
            ctx->open_failed = 1;
            return;
        }
        /* UDP is connectionless: no dial, no reconnect.  Datagrams are sent to
         * ctx->addr each interval; if the proxy isn't up yet they are simply
         * dropped and the next interval tries again. */
        apr_socket_opt_set(ctx->sock, APR_SO_NONBLOCK, 1);
        ctx->opened = 1;
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

    m->last_attempt = now;

    if (!beacon_have_manage_fn(ctx)) {
        return APR_EGENERAL;
    }

    apr_pool_create(&subp, pool);
    r = beacon_make_fake_request(subp, s);

    /* Step 1: add the worker (created DISABLED). */
    params = apr_table_make(subp, 4);
    apr_table_setn(params, "b", ctx->balancer_name);
    apr_table_setn(params, "b_nwrkr", url);
    apr_table_setn(params, "b_wyes", "1");
    rv = ctx->manage_fn(r, params);
    apr_pool_destroy(subp);
    if (rv != APR_SUCCESS) {
        /* Most likely the balancer has no free slots (grow it via ProxySet
         * growth / BalancerGrowth).  Throttled log; retried only after the
         * backoff window, not on every announcement. */
        beacon_log_throttled(ctx, now, "balancer add failed (full?)");
        return rv;
    }

    /* Step 2: enable it (clear the DISABLED flag) so it serves traffic.
     * beacon_set_worker_disabled is self-contained -- it creates its own subpool
     * from `pool` -- so it does not rely on `subp`, which we destroyed above. */
    rv = beacon_set_worker_disabled(ctx, pool, url, 0);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     APLOGNO(10578) "mod_proxy_beacon: added but failed to enable worker %s "
                     "in balancer://%s", url, ctx->balancer_name);
        /* fall through: still a member, just disabled */
    }

    m->added = 1;
    m->evicted = 0;
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 APLOGNO(10579) "mod_proxy_beacon: added backend %s to balancer://%s",
                 url, ctx->balancer_name);
    return APR_SUCCESS;
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
        m = apr_pcalloc(ctx->p, sizeof(*m));
        m->last_seen = now;
        m->last_ts = msg_ts;
        apr_hash_set(ctx->seen, apr_pstrdup(ctx->p, url), APR_HASH_KEY_STRING,
                     m);
        beacon_try_add(ctx, pool, url, m, now);
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
 * Eviction sweep: disable any member that has not announced within
 * evict_timeout.  No-op when eviction is disabled (timeout 0).  Runs in the
 * watchdog singleton, throttled by the caller.
 */
static void beacon_sweep(beacon_ctx_t *ctx, apr_pool_t *pool, apr_time_t now)
{
    apr_hash_index_t *hi;

    if (ctx->evict_timeout <= 0 || !beacon_have_manage_fn(ctx)) {
        return;
    }

    for (hi = apr_hash_first(pool, ctx->seen); hi; hi = apr_hash_next(hi)) {
        const void *key;
        void *val;
        beacon_member_t *m;

        apr_hash_this(hi, &key, NULL, &val);
        m = val;
        if (!m->added || m->evicted) {
            continue;
        }
        if (now - m->last_seen > ctx->evict_timeout) {
            const char *url = key;
            if (beacon_set_worker_disabled(ctx, pool, url, 1) == APR_SUCCESS) {
                m->evicted = 1;
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ctx->s,
                             APLOGNO(10581) "mod_proxy_beacon: evicted backend %s from "
                             "balancer://%s (no announcement for %"
                             APR_TIME_T_FMT "s)",
                             url, ctx->balancer_name,
                             apr_time_sec(now - m->last_seen));
            }
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
 * listener: verify a received, NUL-terminated message.  Returns 1 if the MAC matches
 * the pre-shared key AND the ts= timestamp is within ctx->max_skew of now.
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
     * NUL-terminated apr_pstrmemdup() copy -- so a short or garbled payload
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

    /* Anti-replay (1): ts= must be present and within the freshness window.
     * ts is in microseconds (raw apr_time_now()) so that announcements made
     * less than a second apart still have strictly-increasing timestamps for
     * the caller's per-url check. */
    tsp = NULL;
    for (p = msg; (p = ap_strstr_c(p, "ts=")) != NULL && p < macp; p += 3) {
        /* token-start: beginning of message or preceded by a space */
        if (p == msg || *(p - 1) == ' ') {
            tsp = p;
        }
    }
    if (!tsp) {
        *reason = "no ts";
        return 0;
    }
    ts = apr_atoi64(tsp + 3);
    skew = ctx->max_skew > 0 ? ctx->max_skew : BEACON_MAXSKEW_DEFAULT;
    delta = (apr_int64_t)now - ts;
    if (delta < 0) {
        delta = -delta;
    }
    if (delta > apr_time_from_sec(skew)) {
        *reason = "stale timestamp";
        return 0;
    }

    *ts_out = ts;
    return 1;
}

/* RUNNING: sender sends a throttled beacon; listener drains its receive socket. */
static void beacon_cb_running(beacon_ctx_t *ctx, apr_pool_t *pool)
{
    server_rec *s = ctx->s;
    apr_status_t rv;

    if (!ctx->opened) {
        return;
    }

    if (ctx->role == BEACON_ROLE_SEND) {
        apr_time_t now = apr_time_now();
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
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                             APLOGNO(10582) "mod_proxy_beacon: sendto %s failed",
                             ctx->pub_url);
            }
            ctx->last_publish = now;
        }
    }
    else if (ctx->role == BEACON_ROLE_LISTEN) {
        apr_time_t now;

        /* Drain the socket every tick (re-enable latency matters). */
        for (;;) {
            char buf[BEACON_MAX_MSG_LEN + 1];
            apr_sockaddr_t from;
            apr_size_t sz = BEACON_MAX_MSG_LEN;
            apr_time_t msg_now;
            const char *msg_str, *safe;
            char url[512];
            apr_int64_t msg_ts = 0;

            from.pool = pool;
            rv = apr_socket_recvfrom(&from, ctx->sock, 0, buf, &sz);
            if (APR_STATUS_IS_EAGAIN(rv)) {
                break; /* socket drained */
            }
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                             APLOGNO(10583) "mod_proxy_beacon: recvfrom failed");
                break;
            }
            if (sz == 0) {
                continue; /* empty datagram */
            }

            /* Capture a single wall-clock snapshot for this message so that
             * MAC verification, throttle logging, and last-seen recording all
             * share the same time base (no TOCTOU drift across calls). */
            msg_now = apr_time_now();

            /* recvfrom wrote into our own stack buffer; NUL-terminate it (a UDP
             * datagram is delivered whole, so sz is the full message length). */
            buf[sz] = '\0';
            msg_str = buf;

            /* Escape the untrusted payload before it can reach the log: on the
             * log-only path (no ProxyBeaconBalancer) messages are logged without
             * MAC verification, so anyone who can reach the listen port could
             * embed newline/control/ANSI sequences to forge or corrupt error-log
             * lines.  (On the balancer path, forged messages are dropped at
             * verification below and `safe` is only logged after it passes.) */
            safe = ap_escape_logitem(pool, msg_str);

            /* Phase 4: verify the MAC and freshness BEFORE logging or acting on
             * the payload, so forged/tampered content is dropped (throttled) and
             * never reaches the INFO log.  A secret is required (enforced at
             * config time), so this always runs in the active (balancer) path.
             * msg_ts (microseconds) is the signed timestamp, used below for the
             * per-url monotonic replay check.  With no balancer we take no action
             * and the escaped payload is safe to log for diagnostics. */
            if (ctx->balancer_name) {
                const char *reason = "?";
                if (!beacon_verify(ctx, msg_str, msg_now, &msg_ts, &reason)) {
                    beacon_log_throttled(ctx, msg_now, reason);
                    continue;
                }
            }

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         APLOGNO(10584) "mod_proxy_beacon: received: %s", safe);

            if (!ctx->balancer_name) {
                continue;
            }

            /* Phase 2/3: carries a routable url= -> add the backend (or
             * refresh last-seen / re-enable if previously evicted). */
            if (beacon_parse_url(msg_str, url, sizeof(url))) {
                beacon_handle_announce(ctx, pool, url, msg_now, msg_ts);
            }
        }

        /* Phase 3: evict backends that stopped announcing.  Throttle the scan
         * to ~1s (the recv drain above already runs every tick). */
        now = apr_time_now();
        if (ctx->balancer_name && ctx->evict_timeout > 0
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

static void beacon_register_hooks(apr_pool_t *p)
{
    static const char *const aszSucc[] = { "mod_watchdog.c",
                                           "mod_proxy_balancer.c", NULL };
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
