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
 *
 * Portions of the input filter code for PROXY protocol support is
 * Copyright 2014 Cloudzilla Inc.
 */

#include "ap_config.h"
#include "ap_mmn.h"
#include "ap_listen.h"
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "apr_strings.h"
#include "apr_lib.h"
#define APR_WANT_BYTEFUNC
#include "apr_want.h"
#include "apr_network_io.h"
#include "apr_version.h"

module AP_MODULE_DECLARE_DATA remoteip_module;

typedef struct {
    /** A proxy IP mask to match */
    apr_ipsubnet_t *ip;
    /** Flagged if internal, otherwise an external trusted proxy */
    void  *internal;
} remoteip_proxymatch_t;

typedef struct remoteip_addr_info {
    struct remoteip_addr_info *next;
    apr_sockaddr_t *addr;
    server_rec *source;
} remoteip_addr_info;

typedef struct {
    /** The header to retrieve a proxy-via IP list */
    const char *header_name;
    /** A header to record the proxied IP's
     * (removed as the physical connection and
     * from the proxy-via IP header value list)
     */
    const char *proxies_header_name;
    /** A list of trusted proxies, ideally configured
     *  with the most commonly encountered listed first
     */
    apr_array_header_t *proxymatch_ip;

    remoteip_addr_info *proxy_protocol_enabled;
    remoteip_addr_info *proxy_protocol_disabled;

    apr_array_header_t *disabled_subnets;
    apr_pool_t *pool;
} remoteip_config_t;

typedef struct {
    apr_sockaddr_t *useragent_addr;
    char *useragent_ip;
    /** The list of proxy IP's ignored as remote IP's */
    const char *proxy_ips;
    /** The remaining list of untrusted proxied remote IP's */
    const char *proxied_remote;
} remoteip_req_t;

/* For PROXY protocol processing */
static ap_filter_rec_t *remoteip_filter;

typedef struct {
    char line[108];
} proxy_v1;

typedef union {
    struct {        /* for TCP/UDP over IPv4, len = 12 */
        apr_uint32_t src_addr;
        apr_uint32_t dst_addr;
        apr_uint16_t src_port;
        apr_uint16_t dst_port;
    } ip4;
    struct {        /* for TCP/UDP over IPv6, len = 36 */
         apr_byte_t  src_addr[16];
         apr_byte_t  dst_addr[16];
         apr_uint16_t src_port;
         apr_uint16_t dst_port;
    } ip6;
    struct {        /* for AF_UNIX sockets, len = 216 */
         apr_byte_t src_addr[108];
         apr_byte_t dst_addr[108];
    } unx;
} proxy_v2_addr;

typedef struct {
    apr_byte_t  sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
    apr_byte_t  ver_cmd;  /* protocol version and command */
    apr_byte_t  fam;      /* protocol family and address */
    apr_uint16_t len;     /* number of following bytes part of the header */
    proxy_v2_addr addr;
} proxy_v2;

typedef union {
        proxy_v1 v1;
        proxy_v2 v2;
} proxy_header;

static const char v2sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
#define MIN_V1_HDR_LEN 15
#define MIN_V2_HDR_LEN 16
#define MIN_HDR_LEN MIN_V1_HDR_LEN

/* XXX: Unsure if this is needed if v6 support is not available on
   this platform */
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

typedef struct {
    char header[sizeof(proxy_header)];
    apr_size_t rcvd;
    apr_size_t need;
    int version;
    ap_input_mode_t mode;
    apr_bucket_brigade *bb;
    int done;
} remoteip_filter_context;

/** Holds the resolved proxy info for this connection and any additional
  configurable parameters
*/
typedef struct {
    /** The parsed client address in native format */
    apr_sockaddr_t *client_addr;
    /** Character representation of the client */
    char *client_ip;
} remoteip_conn_config_t;

typedef enum { HDR_DONE, HDR_ERROR, HDR_NEED_MORE } remoteip_parse_status_t;

static void *create_remoteip_server_config(apr_pool_t *p, server_rec *s)
{
    remoteip_config_t *config = apr_pcalloc(p, sizeof(*config));
    config->disabled_subnets = apr_array_make(p, 1, sizeof(apr_ipsubnet_t *));
    /* config->header_name = NULL;
     * config->proxies_header_name = NULL;
     * config->proxy_protocol_enabled = NULL;
     * config->proxy_protocol_disabled = NULL;
     */
    config->pool = p;
    return config;
}

static void *merge_remoteip_server_config(apr_pool_t *p, void *globalv,
                                          void *serverv)
{
    remoteip_config_t *global = (remoteip_config_t *) globalv;
    remoteip_config_t *server = (remoteip_config_t *) serverv;
    remoteip_config_t *config;

    config = (remoteip_config_t *) apr_palloc(p, sizeof(*config));
    config->header_name = server->header_name
                        ? server->header_name
                        : global->header_name;
    config->proxies_header_name = server->proxies_header_name
                                ? server->proxies_header_name
                                : global->proxies_header_name;
    config->proxymatch_ip = server->proxymatch_ip
                          ? server->proxymatch_ip
                          : global->proxymatch_ip;
    return config;
}

static const char *header_name_set(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    remoteip_config_t *config = ap_get_module_config(cmd->server->module_config,
                                                     &remoteip_module);
    config->header_name = arg;
    return NULL;
}

static const char *proxies_header_name_set(cmd_parms *cmd, void *dummy,
                                           const char *arg)
{
    remoteip_config_t *config = ap_get_module_config(cmd->server->module_config,
                                                     &remoteip_module);
    config->proxies_header_name = arg;
    return NULL;
}

/* Would be quite nice if APR exported this */
/* apr:network_io/unix/sockaddr.c */
static int looks_like_ip(const char *ipstr)
{
    if (ap_strchr_c(ipstr, ':')) {
        /* definitely not a hostname; assume it is intended to be an IPv6 address */
        return 1;
    }

    /* simple IPv4 address string check */
    while ((*ipstr == '.') || apr_isdigit(*ipstr))
        ipstr++;
    return (*ipstr == '\0');
}

static const char *proxies_set(cmd_parms *cmd, void *cfg,
                               const char *arg)
{
    remoteip_config_t *config = ap_get_module_config(cmd->server->module_config,
                                                     &remoteip_module);
    remoteip_proxymatch_t *match;
    apr_status_t rv;
    char *ip = apr_pstrdup(cmd->temp_pool, arg);
    char *s = ap_strchr(ip, '/');
    if (s) {
        *s++ = '\0';
    }

    if (!config->proxymatch_ip) {
        config->proxymatch_ip = apr_array_make(cmd->pool, 1, sizeof(*match));
    }
    match = (remoteip_proxymatch_t *) apr_array_push(config->proxymatch_ip);
    match->internal = cmd->info;

    if (looks_like_ip(ip)) {
        /* Note s may be null, that's fine (explicit host) */
        rv = apr_ipsubnet_create(&match->ip, ip, s, cmd->pool);
    }
    else
    {
        apr_sockaddr_t *temp_sa;

        if (s) {
            return apr_pstrcat(cmd->pool, "RemoteIP: Error parsing IP ", arg,
                               " the subnet /", s, " is invalid for ",
                               cmd->cmd->name, NULL);
        }

        rv = apr_sockaddr_info_get(&temp_sa,  ip, APR_UNSPEC, 0,
                                   APR_IPV4_ADDR_OK, cmd->temp_pool);
        while (rv == APR_SUCCESS)
        {
            apr_sockaddr_ip_get(&ip, temp_sa);
            rv = apr_ipsubnet_create(&match->ip, ip, NULL, cmd->pool);
            if (!(temp_sa = temp_sa->next)) {
                break;
            }
            match = (remoteip_proxymatch_t *)
                    apr_array_push(config->proxymatch_ip);
            match->internal = cmd->info;
        }
    }

    if (rv != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "RemoteIP: Error parsing IP %s (%pm error) for %s",
                            arg, &rv, cmd->cmd->name);
    }

    return NULL;
}

static const char *proxylist_read(cmd_parms *cmd, void *cfg,
                                  const char *filename)
{
    char lbuf[MAX_STRING_LEN];
    char *arg;
    const char *args;
    const char *errmsg;
    ap_configfile_t *cfp;
    apr_status_t rv;

    filename = ap_server_root_relative(cmd->temp_pool, filename);
    rv = ap_pcfg_openfile(&cfp, cmd->temp_pool, filename);
    if (rv != APR_SUCCESS) {
        return apr_psprintf(cmd->pool, "%s: Could not open file %s: %pm",
                            cmd->cmd->name, filename, &rv);
    }

    while (!(ap_cfg_getline(lbuf, MAX_STRING_LEN, cfp))) {
        args = lbuf;
        while (*(arg = ap_getword_conf(cmd->temp_pool, &args)) != '\0') {
            if (*arg == '#') {
                break;
            }
            errmsg = proxies_set(cmd, cfg, arg);
            if (errmsg) {
                ap_cfg_closefile(cfp);
                errmsg = apr_psprintf(cmd->pool, "%s at line %d of %s",
                                      errmsg, cfp->line_number, filename);
                return errmsg;
            }
        }
    }

    ap_cfg_closefile(cfp);
    return NULL;
}

/** Similar to apr_sockaddr_equal, except that it compares ports too. */
static int remoteip_sockaddr_equal(apr_sockaddr_t *addr1, apr_sockaddr_t *addr2)
{
    return (addr1->port == addr2->port && apr_sockaddr_equal(addr1, addr2));
}

#if !APR_VERSION_AT_LEAST(1,5,0)
#define apr_sockaddr_is_wildcard sockaddr_is_wildcard
/* XXX: temp build fix from apr 1.5.x */
static int sockaddr_is_wildcard(const apr_sockaddr_t *addr)
{
    static const char inaddr_any[
#if APR_HAVE_IPV6
        sizeof(struct in6_addr)
#else
        sizeof(struct in_addr)
#endif
    ] = {0};

    if (addr->ipaddr_ptr /* IP address initialized */
        && addr->ipaddr_len <= sizeof inaddr_any) { /* else bug elsewhere? */
        if (!memcmp(inaddr_any, addr->ipaddr_ptr, addr->ipaddr_len)) {
            return 1;
        }
#if APR_HAVE_IPV6
    if (addr->family == AF_INET6
        && IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addr->ipaddr_ptr)) {
        struct in_addr *v4 = (struct in_addr *)&((apr_uint32_t *)addr->ipaddr_ptr)[3];

        if (!memcmp(inaddr_any, v4, sizeof *v4)) {
            return 1;
        }
    }
#endif
    }
    return 0;
}
#endif


/** Similar to remoteip_sockaddr_equal, except that it handles wildcard addresses
 *  and ports too.
 */
static int remoteip_sockaddr_compat(apr_sockaddr_t *addr1, apr_sockaddr_t *addr2)
{
    /* test exact address equality */
    if (apr_sockaddr_equal(addr1, addr2) &&
        (addr1->port == addr2->port || addr1->port == 0 || addr2->port == 0)) {
        return 1;
    }

    /* test address wildcards */
    if (apr_sockaddr_is_wildcard(addr1) &&
        (addr1->port == 0 || addr1->port == addr2->port)) {
        return 1;
    }

    if (apr_sockaddr_is_wildcard(addr2) &&
        (addr2->port == 0 || addr2->port == addr1->port)) {
        return 1;
    }

    return 0;
}

static int remoteip_addr_in_list(remoteip_addr_info *list, apr_sockaddr_t *addr)
{
    for (; list; list = list->next) {
        if (remoteip_sockaddr_compat(list->addr, addr)) {
            return 1;
        }
    }

    return 0;
}

static void remoteip_warn_enable_conflict(remoteip_addr_info *prev, server_rec *new, int flag)
{
    char buf[INET6_ADDRSTRLEN];

    apr_sockaddr_ip_getbuf(buf, sizeof(buf), prev->addr);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, new, APLOGNO(03491)
                 "RemoteIPProxyProtocol: previous setting for %s:%hu from virtual "
                 "host {%s:%hu in %s} is being overridden by virtual host "
                 "{%s:%hu in %s}; new setting is '%s'",
                 buf, prev->addr->port, prev->source->server_hostname,
                 prev->source->addrs->host_port, prev->source->defn_name,
                 new->server_hostname, new->addrs->host_port, new->defn_name,
                 flag ? "On" : "Off");
}

static const char *remoteip_enable_proxy_protocol(cmd_parms *cmd, void *config,
                                                  int flag)
{
    remoteip_config_t *conf;
    server_addr_rec *addr;
    remoteip_addr_info **add;
    remoteip_addr_info **rem;
    remoteip_addr_info *list;

    conf = ap_get_module_config(ap_server_conf->module_config,
                                &remoteip_module);

    if (flag) {
        add = &conf->proxy_protocol_enabled;
        rem = &conf->proxy_protocol_disabled;
    }
    else {
        add = &conf->proxy_protocol_disabled;
        rem = &conf->proxy_protocol_enabled;
    }

    for (addr = cmd->server->addrs; addr; addr = addr->next) {
        /* remove address from opposite list */
        if (*rem) {
            if (remoteip_sockaddr_equal((*rem)->addr, addr->host_addr)) {
                remoteip_warn_enable_conflict(*rem, cmd->server, flag);
                *rem = (*rem)->next;
            }
            else {
                for (list = *rem; list->next; list = list->next) {
                    if (remoteip_sockaddr_equal(list->next->addr, addr->host_addr)) {
                        remoteip_warn_enable_conflict(list->next, cmd->server, flag);
                        list->next = list->next->next;
                        break;
                    }
                }
            }
        }

        /* add address to desired list */
        if (!remoteip_addr_in_list(*add, addr->host_addr)) {
            remoteip_addr_info *info = apr_palloc(conf->pool, sizeof(*info));
            info->addr = addr->host_addr;
            info->source = cmd->server;
            info->next = *add;
            *add = info;
        }
    }

    return NULL;
}

static const char *remoteip_disable_networks(cmd_parms *cmd, void *d,
                                             int argc, char *const argv[])
{
    int i;
    apr_pool_t *ptemp = cmd->temp_pool;
    apr_pool_t *p = cmd->pool;
    remoteip_config_t *conf = ap_get_module_config(ap_server_conf->module_config,
                                &remoteip_module);

    if (argc == 0)
        return apr_pstrcat(p, cmd->cmd->name, " requires an argument", NULL);


    for (i=0; i<argc; i++) {
        char *addr = apr_pstrdup(ptemp, argv[i]);
        char *mask;
        apr_status_t rv;
        apr_ipsubnet_t **ip = apr_pcalloc(p, sizeof(apr_ipsubnet_t *));

        if ((mask = ap_strchr(addr, '/')))
            *mask++ = '\0';

        rv = apr_ipsubnet_create(ip, addr, mask, p);

        if (APR_STATUS_IS_EINVAL(rv)) {
            /* looked nothing like an IP address */
            return apr_psprintf(p, "ip address '%s' appears to be invalid", addr);
        }
        else if (rv != APR_SUCCESS) {
            return apr_psprintf(p, "ip address '%s' appears to be invalid: %pm",
                                addr, &rv);
        }

        *(apr_ipsubnet_t**)apr_array_push(conf->disabled_subnets) = *ip;
    }

    return NULL;
}

static int remoteip_hook_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *s)
{
    remoteip_config_t *conf;
    remoteip_addr_info *info;
    char buf[INET6_ADDRSTRLEN];

    conf = ap_get_module_config(ap_server_conf->module_config,
                                &remoteip_module);

    for (info = conf->proxy_protocol_enabled; info; info = info->next) {
        apr_sockaddr_ip_getbuf(buf, sizeof(buf), info->addr);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, APLOGNO(03492)
                     "RemoteIPProxyProtocol: enabled on %s:%hu", buf, info->addr->port);
    }
    for (info = conf->proxy_protocol_disabled; info; info = info->next) {
        apr_sockaddr_ip_getbuf(buf, sizeof(buf), info->addr);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, APLOGNO(03494)
                     "RemoteIPProxyProtocol: disabled on %s:%hu", buf, info->addr->port);
    }

    return OK;
}

static int remoteip_modify_request(request_rec *r)
{
    conn_rec *c = r->connection;
    remoteip_config_t *config = (remoteip_config_t *)
        ap_get_module_config(r->server->module_config, &remoteip_module);
    remoteip_conn_config_t *conn_config = (remoteip_conn_config_t *)
        ap_get_module_config(r->connection->conn_config, &remoteip_module);

    remoteip_req_t *req = NULL;
    apr_sockaddr_t *temp_sa;

    apr_status_t rv;
    char *remote;
    char *proxy_ips = NULL;
    char *parse_remote;
    char *eos;
    unsigned char *addrbyte;

    /* If no RemoteIPInternalProxy, RemoteIPInternalProxyList, RemoteIPTrustedProxy
       or RemoteIPTrustedProxyList directive is configured,
       all proxies will be considered as external trusted proxies.
     */
    void *internal = NULL;

    /* No header defined or results from our input filter */
    if (!config->header_name && !conn_config) {
        return DECLINED;
    }
 
    /* Easy parsing case - just position the data we already have from PROXY
       protocol handling allowing it to take precedence and return
    */
    if (conn_config) {
        if (!conn_config->client_addr) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(03496)
                          "RemoteIPProxyProtocol data is missing, but required! Aborting request.");
            return HTTP_BAD_REQUEST;
        }

        r->useragent_addr = conn_config->client_addr;
        r->useragent_ip = conn_config->client_ip;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "Using %s as client's IP from PROXY protocol", r->useragent_ip);
        return OK;
    }

    if (config->proxymatch_ip) {
        /* This indicates that a RemoteIPInternalProxy, RemoteIPInternalProxyList, RemoteIPTrustedProxy
           or RemoteIPTrustedProxyList directive is configured.
           In this case, default to internal proxy.
         */
        internal = (void *) 1;
    }

    remote = (char *) apr_table_get(r->headers_in, config->header_name);
    if (!remote) {
        return OK;
    }
    remote = apr_pstrdup(r->pool, remote);

    temp_sa = r->useragent_addr ? r->useragent_addr : c->client_addr;

    while (remote) {

        /* verify user agent IP against the trusted proxy list
         */
        if (config->proxymatch_ip) {
            int i;
            remoteip_proxymatch_t *match;
            match = (remoteip_proxymatch_t *)config->proxymatch_ip->elts;
            for (i = 0; i < config->proxymatch_ip->nelts; ++i) {
                if (apr_ipsubnet_test(match[i].ip, temp_sa)) {
                    if (internal) {
                        /* Allow an internal proxy to present an external proxy,
                           but do not allow an external proxy to present an internal proxy.
                           In this case, the presented internal proxy will be considered external.
                         */
                        internal = match[i].internal;
                    }
                    break;
                }
            }
            if (i && i >= config->proxymatch_ip->nelts) {
                break;
            }
        }

        if ((parse_remote = strrchr(remote, ',')) == NULL) {
            parse_remote = remote;
            remote = NULL;
        }
        else {
            *(parse_remote++) = '\0';
        }

        while (*parse_remote == ' ') {
            ++parse_remote;
        }

        eos = parse_remote + strlen(parse_remote) - 1;
        while (eos >= parse_remote && *eos == ' ') {
            *(eos--) = '\0';
        }

        if (eos < parse_remote) {
            if (remote) {
                *(remote + strlen(remote)) = ',';
            }
            else {
                remote = parse_remote;
            }
            break;
        }

        /* We map as IPv4 rather than IPv6 for equivalent host names
         * or IPV4OVERIPV6
         */
        rv = apr_sockaddr_info_get(&temp_sa,  parse_remote,
                                   APR_UNSPEC, temp_sa->port,
                                   APR_IPV4_ADDR_OK, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  rv, r, APLOGNO(01568)
                          "RemoteIP: Header %s value of %s cannot be parsed "
                          "as a client IP",
                          config->header_name, parse_remote);

            if (remote) {
                *(remote + strlen(remote)) = ',';
            }
            else {
                remote = parse_remote;
            }
            break;
        }

        addrbyte = (unsigned char *) &temp_sa->sa.sin.sin_addr;

        /* For intranet (Internal proxies) ignore all restrictions below */
        if (!internal
              && ((temp_sa->family == APR_INET
                   /* For internet (non-Internal proxies) deny all
                    * RFC3330 designated local/private subnets:
                    * 10.0.0.0/8   169.254.0.0/16  192.168.0.0/16
                    * 127.0.0.0/8  172.16.0.0/12
                    */
                      && (addrbyte[0] == 10
                       || addrbyte[0] == 127
                       || (addrbyte[0] == 169 && addrbyte[1] == 254)
                       || (addrbyte[0] == 172 && (addrbyte[1] & 0xf0) == 16)
                       || (addrbyte[0] == 192 && addrbyte[1] == 168)))
#if APR_HAVE_IPV6
               || (temp_sa->family == APR_INET6
                   /* For internet (non-Internal proxies) we translated
                    * IPv4-over-IPv6-mapped addresses as IPv4, above.
                    * Accept only Global Unicast 2000::/3 defined by RFC4291
                    */
                      && ((temp_sa->sa.sin6.sin6_addr.s6_addr[0] & 0xe0) != 0x20))
#endif
        )) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  rv, r, APLOGNO(01569)
                          "RemoteIP: Header %s value of %s appears to be "
                          "a private IP or nonsensical.  Ignored",
                          config->header_name, parse_remote);
            if (remote) {
                *(remote + strlen(remote)) = ',';
            }
            else {
                remote = parse_remote;
            }

            break;
        }

        /* save away our results */
        if (!req) {
            req = (remoteip_req_t *) apr_palloc(r->pool, sizeof(remoteip_req_t));
            req->useragent_ip = r->useragent_ip;
        }

        /* Set useragent_ip string */
        if (!internal) {
            if (proxy_ips) {
                proxy_ips = apr_pstrcat(r->pool, proxy_ips, ", ",
                                        req->useragent_ip, NULL);
            }
            else {
                proxy_ips = req->useragent_ip;
            }
        }

        req->useragent_addr = temp_sa;
        apr_sockaddr_ip_get(&req->useragent_ip, req->useragent_addr);
    }

    /* Nothing happened? */
    if (!req) {
        return OK;
    }

    /* Port is not known so set it to zero; otherwise it can be misleading */
    req->useragent_addr->port = 0;

    req->proxied_remote = remote;
    req->proxy_ips = proxy_ips;

    if (req->proxied_remote) {
        apr_table_setn(r->headers_in, config->header_name,
                       req->proxied_remote);
    }
    else {
        apr_table_unset(r->headers_in, config->header_name);
    }
    if (req->proxy_ips) {
        apr_table_setn(r->notes, "remoteip-proxy-ip-list", req->proxy_ips);
        if (config->proxies_header_name) {
            apr_table_setn(r->headers_in, config->proxies_header_name,
                           req->proxy_ips);
        }
    }

    r->useragent_addr = req->useragent_addr;
    r->useragent_ip = req->useragent_ip;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                  req->proxy_ips
                      ? "Using %s as client's IP by proxies %s"
                      : "Using %s as client's IP by internal proxies%s",
                  req->useragent_ip,
                  (req->proxy_ips ? req->proxy_ips : ""));
    return OK;
}

static int remoteip_is_server_port(apr_port_t port)
{
    ap_listen_rec *lr;

    for (lr = ap_listeners; lr; lr = lr->next) {
        if (lr->bind_addr && lr->bind_addr->port == port) {
            return 1;
        }
    }

    return 0;
}

/*
 * Human readable format:
 * PROXY {TCP4|TCP6|UNKNOWN} <client-ip-addr> <dest-ip-addr> <client-port> <dest-port><CR><LF>
 */
static remoteip_parse_status_t remoteip_process_v1_header(conn_rec *c,
                                                          remoteip_conn_config_t *conn_conf,
                                                          proxy_header *hdr, apr_size_t len,
                                                          apr_size_t *hdr_len)
{
    char *end, *word, *host, *valid_addr_chars, *saveptr;
    char buf[sizeof(hdr->v1.line)];
    apr_port_t port;
    apr_status_t ret;
    apr_int32_t family;

#define GET_NEXT_WORD(field) \
    word = apr_strtok(NULL, " ", &saveptr); \
    if (!word) { \
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(03497) \
                      "RemoteIPProxyProtocol: no " field " found in header '%s'", \
                      hdr->v1.line); \
        return HDR_ERROR; \
    }

    end = memchr(hdr->v1.line, '\r', len - 1);
    if (!end || end[1] != '\n') {
        return HDR_NEED_MORE; /* partial or invalid header */
    }

    *end = '\0';
    *hdr_len = end + 2 - hdr->v1.line; /* skip header + CRLF */

    /* parse in separate buffer so have the original for error messages */
    strcpy(buf, hdr->v1.line);

    apr_strtok(buf, " ", &saveptr);

    /* parse family */
    GET_NEXT_WORD("family")
    if (strcmp(word, "UNKNOWN") == 0) {
        conn_conf->client_addr = c->client_addr;
        conn_conf->client_ip = c->client_ip;
        return HDR_DONE;
    }
    else if (strcmp(word, "TCP4") == 0) {
        family = APR_INET;
        valid_addr_chars = "0123456789.";
    }
    else if (strcmp(word, "TCP6") == 0) {
#if APR_HAVE_IPV6
        family = APR_INET6;
        valid_addr_chars = "0123456789abcdefABCDEF:";
#else
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(03498)
                      "RemoteIPProxyProtocol: Unable to parse v6 address - APR is not compiled with IPv6 support");
        return HDR_ERROR;
#endif
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(03499)
                      "RemoteIPProxyProtocol: unknown family '%s' in header '%s'",
                      word, hdr->v1.line);
        return HDR_ERROR;
    }

    /* parse client-addr */
    GET_NEXT_WORD("client-address")

    if (strspn(word, valid_addr_chars) != strlen(word)) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(03500)
                      "RemoteIPProxyProtocol: invalid client-address '%s' found in "
                      "header '%s'", word, hdr->v1.line);
        return HDR_ERROR;
    }

    host = word;

    /* parse dest-addr */
    GET_NEXT_WORD("destination-address")

    /* parse client-port */
    GET_NEXT_WORD("client-port")
    if (sscanf(word, "%hu", &port) != 1) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(03501)
                      "RemoteIPProxyProtocol: error parsing port '%s' in header '%s'",
                      word, hdr->v1.line);
        return HDR_ERROR;
    }

    /* parse dest-port */
    /* GET_NEXT_WORD("destination-port") - no-op since we don't care about it */

    /* create a socketaddr from the info */
    ret = apr_sockaddr_info_get(&conn_conf->client_addr, host, family, port, 0,
                                c->pool);
    if (ret != APR_SUCCESS) {
        conn_conf->client_addr = NULL;
        ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, c, APLOGNO(03502)
                      "RemoteIPProxyProtocol: error converting family '%d', host '%s',"
                      " and port '%hu' to sockaddr; header was '%s'",
                      family, host, port, hdr->v1.line);
        return HDR_ERROR;
    }

    conn_conf->client_ip = apr_pstrdup(c->pool, host);

    return HDR_DONE;
}

/** Add our filter to the connection if it is requested
 */
static int remoteip_hook_pre_connection(conn_rec *c, void *csd)
{
    remoteip_config_t *conf;
    remoteip_conn_config_t *conn_conf;
    int i;

    /* Establish master config in slave connections, so that request processing
     * finds it. */
    if (c->master != NULL) {
        conn_conf = ap_get_module_config(c->master->conn_config, &remoteip_module);
        if (conn_conf) {
            ap_set_module_config(c->conn_config, &remoteip_module, conn_conf);
        }
        return DECLINED;
    }

    conf = ap_get_module_config(ap_server_conf->module_config,
                                &remoteip_module);

    /* check if we're enabled for this connection */
    if (!remoteip_addr_in_list(conf->proxy_protocol_enabled, c->local_addr)
        || remoteip_addr_in_list(conf->proxy_protocol_disabled, c->local_addr)) {

        return DECLINED;
    }

    /* We are enabled for this IP/port, but check that we aren't
       explicitly disabled */
    for (i = 0; i < conf->disabled_subnets->nelts; i++) {
        apr_ipsubnet_t *ip = ((apr_ipsubnet_t**)conf->disabled_subnets->elts)[i];

        if (ip && apr_ipsubnet_test(ip, c->client_addr))
            return DECLINED;
    }

    /* mod_proxy creates outgoing connections - we don't want those */
    if (!remoteip_is_server_port(c->local_addr->port)) {
        return DECLINED;
    }

    /* add our filter */
    if (!ap_add_input_filter_handle(remoteip_filter, NULL, NULL, c)) {
        /* XXX: Shouldn't this WARN in log? */
        return DECLINED;
    }

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03503)
                  "RemoteIPProxyProtocol: enabled on connection to %s:%hu",
                  c->local_ip, c->local_addr->port);

    /* this holds the resolved proxy info for this connection */
    conn_conf = apr_pcalloc(c->pool, sizeof(*conn_conf));

    ap_set_module_config(c->conn_config, &remoteip_module, conn_conf);

    return OK;
}

/* Binary format:
 * <sig><cmd><proto><addr-len><addr>
 * sig = \x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A
 * cmd = <4-bits-version><4-bits-command>
 * 4-bits-version = \x02
 * 4-bits-command = {\x00|\x01}  (\x00 = LOCAL: discard con info; \x01 = PROXY)
 * proto = <4-bits-family><4-bits-protocol>
 * 4-bits-family = {\x00|\x01|\x02|\x03}  (AF_UNSPEC, AF_INET, AF_INET6, AF_UNIX)
 * 4-bits-protocol = {\x00|\x01|\x02}  (UNSPEC, STREAM, DGRAM)
 */
static remoteip_parse_status_t remoteip_process_v2_header(conn_rec *c,
                                              remoteip_conn_config_t *conn_conf,
                                              proxy_header *hdr)
{
    apr_status_t ret;

    switch (hdr->v2.ver_cmd & 0xF) {
        case 0x01: /* PROXY command */
            switch (hdr->v2.fam) {
                case 0x11:  /* TCPv4 */
                    ret = apr_sockaddr_info_get(&conn_conf->client_addr, NULL,
                                                APR_INET,
                                                ntohs(hdr->v2.addr.ip4.src_port),
                                                0, c->pool);
                    if (ret != APR_SUCCESS) {
                        conn_conf->client_addr = NULL;
                        ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, c, APLOGNO(03504)
                                      "RemoteIPPProxyProtocol: error creating sockaddr");
                        return HDR_ERROR;
                    }

                    conn_conf->client_addr->sa.sin.sin_addr.s_addr =
                            hdr->v2.addr.ip4.src_addr;
                    break;

                case 0x21:  /* TCPv6 */
#if APR_HAVE_IPV6
                    ret = apr_sockaddr_info_get(&conn_conf->client_addr, NULL,
                                                APR_INET6,
                                                ntohs(hdr->v2.addr.ip6.src_port),
                                                0, c->pool);
                    if (ret != APR_SUCCESS) {
                        conn_conf->client_addr = NULL;
                        ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, c, APLOGNO(03505)
                                      "RemoteIPProxyProtocol: error creating sockaddr");
                        return HDR_ERROR;
                    }
                    memcpy(&conn_conf->client_addr->sa.sin6.sin6_addr.s6_addr,
                           hdr->v2.addr.ip6.src_addr, 16);
                    break;
#else
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(03506)
                                  "RemoteIPProxyProtocol: APR is not compiled with IPv6 support");
                    return HDR_ERROR;
#endif
                default:
                    /* unsupported protocol */
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(10183)
                                  "RemoteIPProxyProtocol: unsupported protocol %.2hx",
                                  (unsigned short)hdr->v2.fam);
                    return HDR_ERROR;
            }
            break;  /* we got a sockaddr now */
        default:
            /* not a supported command */
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(03507)
                          "RemoteIPProxyProtocol: unsupported command %.2hx",
                          (unsigned short)hdr->v2.ver_cmd);
            return HDR_ERROR;
    }

    /* got address - compute the client_ip from it */
    ret = apr_sockaddr_ip_get(&conn_conf->client_ip, conn_conf->client_addr);
    if (ret != APR_SUCCESS) {
        conn_conf->client_addr = NULL;
        ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, c, APLOGNO(03508)
                      "RemoteIPProxyProtocol: error converting address to string");
        return HDR_ERROR;
    }

    return HDR_DONE;
}

/** Return length for a v2 protocol header. */
static apr_size_t remoteip_get_v2_len(proxy_header *hdr)
{
    return ntohs(hdr->v2.len);
}

/** Determine if this is a v1 or v2 PROXY header.
 */
static int remoteip_determine_version(conn_rec *c, const char *ptr)
{
    proxy_header *hdr = (proxy_header *) ptr;

    /* assert len >= 14 */

    if (memcmp(&hdr->v2, v2sig, sizeof(v2sig)) == 0 &&
        (hdr->v2.ver_cmd & 0xF0) == 0x20) {
        return 2;
    }
    else if (memcmp(hdr->v1.line, "PROXY ", 6) == 0) {
        return 1;
    }
    else {
        return -1;
    }
}

/* Capture the first bytes on the protocol and parse the PROXY protocol header.
 * Removes itself when the header is complete.
 */
static apr_status_t remoteip_input_filter(ap_filter_t *f,
                                    apr_bucket_brigade *bb_out,
                                    ap_input_mode_t mode,
                                    apr_read_type_e block,
                                    apr_off_t readbytes)
{
    apr_status_t ret;
    remoteip_filter_context *ctx = f->ctx;
    remoteip_conn_config_t *conn_conf;
    apr_bucket *b;
    remoteip_parse_status_t psts = HDR_NEED_MORE;
    const char *ptr;
    apr_size_t len;

    if (f->c->aborted) {
        return APR_ECONNABORTED;
    }

    /* allocate/retrieve the context that holds our header */
    if (!ctx) {
        ctx = f->ctx = apr_palloc(f->c->pool, sizeof(*ctx));
        ctx->rcvd = 0;
        ctx->need = MIN_HDR_LEN;
        ctx->version = 0;
        ctx->mode = AP_MODE_READBYTES;
        ctx->bb = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
        ctx->done = 0;
    }

    if (ctx->done) {
        /* Note: because we're a connection filter we can't remove ourselves
         * when we're done, so we have to stay in the chain and just go into
         * passthrough mode.
         */
        return ap_get_brigade(f->next, bb_out, mode, block, readbytes);
    }

    conn_conf = ap_get_module_config(f->c->conn_config, &remoteip_module);

    /* try to read a header's worth of data */
    while (!ctx->done) {
        if (APR_BRIGADE_EMPTY(ctx->bb)) {
            apr_off_t got, want = ctx->need - ctx->rcvd;

            ret = ap_get_brigade(f->next, ctx->bb, ctx->mode, block, want);
            if (ret != APR_SUCCESS) {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, f->c, APLOGNO(10184)
                              "failed reading input");
                return ret;
            }

            ret = apr_brigade_length(ctx->bb, 1, &got);
            if (ret || got > want) {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, f->c, APLOGNO(10185)
                              "RemoteIPProxyProtocol header too long, "
                              "got %" APR_OFF_T_FMT " expected %" APR_OFF_T_FMT,
                              got, want);
                f->c->aborted = 1;
                return APR_ECONNABORTED;
            }
        }
        if (APR_BRIGADE_EMPTY(ctx->bb)) {
            return block == APR_NONBLOCK_READ ? APR_SUCCESS : APR_EOF;
        }

        while (!ctx->done && !APR_BRIGADE_EMPTY(ctx->bb)) {
            b = APR_BRIGADE_FIRST(ctx->bb);

            ret = apr_bucket_read(b, &ptr, &len, block);
            if (APR_STATUS_IS_EAGAIN(ret) && block == APR_NONBLOCK_READ) {
                return APR_SUCCESS;
            }
            if (ret != APR_SUCCESS) {
                return ret;
            }

            memcpy(ctx->header + ctx->rcvd, ptr, len);
            ctx->rcvd += len;

            apr_bucket_delete(b);
            psts = HDR_NEED_MORE;

            if (ctx->version == 0) {
                /* reading initial chunk */
                if (ctx->rcvd >= MIN_HDR_LEN) {
                    ctx->version = remoteip_determine_version(f->c, ctx->header);
                    if (ctx->version < 0) {
                        psts = HDR_ERROR;
                    }
                    else if (ctx->version == 1) {
                        ctx->mode = AP_MODE_GETLINE;
                        ctx->need = sizeof(proxy_v1);
                    }
                    else if (ctx->version == 2) {
                        ctx->need = MIN_V2_HDR_LEN;
                    }
                }
            }
            else if (ctx->version == 1) {
                psts = remoteip_process_v1_header(f->c, conn_conf,
                                            (proxy_header *) ctx->header,
                                            ctx->rcvd, &ctx->need);
            }
            else if (ctx->version == 2) {
                if (ctx->rcvd >= MIN_V2_HDR_LEN) {
                    ctx->need = MIN_V2_HDR_LEN +
                        remoteip_get_v2_len((proxy_header *) ctx->header);
                    if (ctx->need > sizeof(proxy_v2)) {
                        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, APLOGNO(10186)
                                      "RemoteIPProxyProtocol protocol header length too long");
                        f->c->aborted = 1;
                        apr_brigade_destroy(ctx->bb);
                        return APR_ECONNABORTED;
                    }
                }
                if (ctx->rcvd >= ctx->need) {
                    psts = remoteip_process_v2_header(f->c, conn_conf,
                                                (proxy_header *) ctx->header);
                }
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, APLOGNO(03509)
                              "RemoteIPProxyProtocol: internal error: unknown version "
                              "%d", ctx->version);
                f->c->aborted = 1;
                apr_brigade_destroy(ctx->bb);
                return APR_ECONNABORTED;
            }

            switch (psts) {
                case HDR_ERROR:
                    f->c->aborted = 1;
                    apr_brigade_destroy(ctx->bb);
                    return APR_ECONNABORTED;

                case HDR_DONE:
                    ctx->done = 1;
                    break;

                case HDR_NEED_MORE:
                    break;
            }
        }
    }

    /* we only get here when done == 1 */
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, APLOGNO(03511)
                  "RemoteIPProxyProtocol: received valid PROXY header: %s:%hu",
                  conn_conf->client_ip, conn_conf->client_addr->port);

    if (ctx->rcvd > ctx->need || !APR_BRIGADE_EMPTY(ctx->bb)) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, APLOGNO(03513)
                      "RemoteIPProxyProtocol: internal error: have data left over; "
                      " need=%" APR_SIZE_T_FMT ", rcvd=%" APR_SIZE_T_FMT
                      ", brigade-empty=%d", ctx->need, ctx->rcvd,
                      APR_BRIGADE_EMPTY(ctx->bb));
        f->c->aborted = 1;
        apr_brigade_destroy(ctx->bb);
        return APR_ECONNABORTED;
    }

    /* clean up */
    apr_brigade_destroy(ctx->bb);
    ctx->bb = NULL;

    /* now do the real read for the upper layer */
    return ap_get_brigade(f->next, bb_out, mode, block, readbytes);
}

static const command_rec remoteip_cmds[] =
{
    AP_INIT_TAKE1("RemoteIPHeader", header_name_set, NULL, RSRC_CONF,
                  "Specifies a request header to trust as the client IP, "
                  "e.g. X-Forwarded-For"),
    AP_INIT_TAKE1("RemoteIPProxiesHeader", proxies_header_name_set,
                  NULL, RSRC_CONF,
                  "Specifies a request header to record proxy IP's, "
                  "e.g. X-Forwarded-By; if not given then do not record"),
    AP_INIT_ITERATE("RemoteIPTrustedProxy", proxies_set, 0, RSRC_CONF,
                    "Specifies one or more proxies which are trusted "
                    "to present IP headers"),
    AP_INIT_ITERATE("RemoteIPInternalProxy", proxies_set, (void*)1, RSRC_CONF,
                    "Specifies one or more internal (transparent) proxies "
                    "which are trusted to present IP headers"),
    AP_INIT_TAKE1("RemoteIPTrustedProxyList", proxylist_read, 0,
                  RSRC_CONF | EXEC_ON_READ,
                  "The filename to read the list of trusted proxies, "
                  "see the RemoteIPTrustedProxy directive"),
    AP_INIT_TAKE1("RemoteIPInternalProxyList", proxylist_read, (void*)1,
                  RSRC_CONF | EXEC_ON_READ,
                  "The filename to read the list of internal proxies, "
                  "see the RemoteIPInternalProxy directive"),
    AP_INIT_FLAG("RemoteIPProxyProtocol", remoteip_enable_proxy_protocol, NULL,
                  RSRC_CONF, "Enable PROXY protocol handling ('on', 'off')"),
    AP_INIT_TAKE_ARGV("RemoteIPProxyProtocolExceptions",
                  remoteip_disable_networks, NULL, RSRC_CONF, "Disable PROXY "
                  "protocol handling for this list of networks in CIDR format"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    /* mod_ssl is CONNECTION + 5, so we want something higher (earlier);
     * mod_reqtimeout is CONNECTION + 8, so we want something lower (later) */
    remoteip_filter = 
        ap_register_input_filter("REMOTEIP_INPUT", remoteip_input_filter, NULL,
                                 AP_FTYPE_CONNECTION + 7);

    ap_hook_post_config(remoteip_hook_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(remoteip_hook_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(remoteip_modify_request, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(remoteip) = {
    STANDARD20_MODULE_STUFF,
    NULL,                          /* create per-directory config structure */
    NULL,                          /* merge per-directory config structures */
    create_remoteip_server_config, /* create per-server config structure */
    merge_remoteip_server_config,  /* merge per-server config structures */
    remoteip_cmds,                 /* command apr_table_t */
    register_hooks                 /* register hooks */
};
