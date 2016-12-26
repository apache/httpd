/*
 * Copyright 2014 Cloudzilla Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * mod_proxy_protocol.c -- Apache proxy_protocol module
 *
 * This implements the server side of the proxy protocol decribed in
 * http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt . It works
 * by installing itself (where enabled) as a connection filter (ahead of
 * mod_ssl) to parse and remove the proxy protocol header, and by then
 * modifying the useragent_* fields in the requests accordingly.
 *
 * TODO:
 * * add the following configs:
 *     ProxyProtocolTrustedProxies "all"|ip-addr|host [ip-addr|host] ...  (default all)
 *     ProxyProtocolRejectUntrusted Yes|No  (default Yes)
 *         What to do if a connection is received from an untrusted proxy:
 *         yes = abort the connection
 *         no = allow connection and remove header, but ignore header
 * * add support for sending the header on outgoing connections (mod_proxy),
 *   and config for choosing which hosts to enable it for
 *   (ProxyProtocolDownstreamHosts?)
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_connection.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_config.h"
#include "ap_listen.h"
#include "apr_strings.h"

module AP_MODULE_DECLARE_DATA proxy_protocol_module;

/*
 * Module configuration
 */

typedef struct pp_addr_info {
    struct pp_addr_info *next;
    apr_sockaddr_t *addr;
    server_rec *source;
} pp_addr_info;

typedef struct {
    pp_addr_info *enabled;
    pp_addr_info *disabled;
    apr_pool_t *pool;
} pp_config;

static int pp_hook_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp)
{
    pp_config *conf;

    conf = (pp_config *) apr_palloc(pconf, sizeof(pp_config));
    conf->enabled = NULL;
    conf->disabled = NULL;
    conf->pool = pconf;

    ap_set_module_config(ap_server_conf->module_config, &proxy_protocol_module,
                         conf);

    return OK;
}

/* Similar apr_sockaddr_equal, except that it compares ports too. */
static int pp_sockaddr_equal(apr_sockaddr_t *addr1, apr_sockaddr_t *addr2)
{
    return (addr1->port == addr2->port && apr_sockaddr_equal(addr1, addr2));
}

/* Similar pp_sockaddr_equal, except that it handles wildcard addresses
 * and ports too.
 */
static int pp_sockaddr_compat(apr_sockaddr_t *addr1, apr_sockaddr_t *addr2)
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

static int pp_addr_in_list(pp_addr_info *list, apr_sockaddr_t *addr)
{
    for (; list; list = list->next) {
        if (pp_sockaddr_compat(list->addr, addr)) {
            return 1;
        }
    }

    return 0;
}

static void pp_warn_enable_conflict(pp_addr_info *prev, server_rec *new, int on)
{
    char buf[INET6_ADDRSTRLEN];

    apr_sockaddr_ip_getbuf(buf, sizeof(buf), prev->addr);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, new,
                 "ProxyProtocol: previous setting for %s:%hu from virtual "
                 "host {%s:%hu in %s} is being overriden by virtual host "
                 "{%s:%hu in %s}; new setting is '%s'",
                 buf, prev->addr->port, prev->source->server_hostname,
                 prev->source->addrs->host_port, prev->source->defn_name,
                 new->server_hostname, new->addrs->host_port, new->defn_name,
                 on ? "On" : "Off");
}

static const char *pp_enable_proxy_protocol(cmd_parms *cmd, void *config,
                                            int flag)
{
    pp_config *conf;
    server_addr_rec *addr;
    pp_addr_info **add;
    pp_addr_info **rem;
    pp_addr_info *list;

    conf = ap_get_module_config(ap_server_conf->module_config,
                                &proxy_protocol_module);

    if (flag) {
        add = &conf->enabled;
        rem = &conf->disabled;
    }
    else {
        add = &conf->disabled;
        rem = &conf->enabled;
    }

    for (addr = cmd->server->addrs; addr; addr = addr->next) {
        /* remove address from opposite list */
        if (*rem) {
            if (pp_sockaddr_equal((*rem)->addr, addr->host_addr)) {
                pp_warn_enable_conflict(*rem, cmd->server, flag);
                *rem = (*rem)->next;
            }
            else {
                for (list = *rem; list->next; list = list->next) {
                    if (pp_sockaddr_equal(list->next->addr, addr->host_addr)) {
                        pp_warn_enable_conflict(list->next, cmd->server, flag);
                        list->next = list->next->next;
                        break;
                    }
                }
            }
        }

        /* add address to desired list */
        if (!pp_addr_in_list(*add, addr->host_addr)) {
            pp_addr_info *info = apr_palloc(conf->pool, sizeof(*info));
            info->addr = addr->host_addr;
            info->source = cmd->server;
            info->next = *add;
            *add = info;
        }
    }

    return NULL;
}

static int pp_hook_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *s)
{
    pp_config *conf;
    pp_addr_info *info;
    char buf[INET6_ADDRSTRLEN];

    conf = ap_get_module_config(ap_server_conf->module_config,
                                &proxy_protocol_module);

    for (info = conf->enabled; info; info = info->next) {
        apr_sockaddr_ip_getbuf(buf, sizeof(buf), info->addr);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                     "ProxyProtocol: enabled on %s:%hu", buf, info->addr->port);
    }
    for (info = conf->disabled; info; info = info->next) {
        apr_sockaddr_ip_getbuf(buf, sizeof(buf), info->addr);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                     "ProxyProtocol: disabled on %s:%hu", buf, info->addr->port);
    }

    return OK;
}

static const command_rec proxy_protocol_cmds[] = {
    AP_INIT_FLAG("ProxyProtocol", pp_enable_proxy_protocol, NULL, RSRC_CONF,
                 "Enable proxy-protocol handling (`on', `off')"),
    { NULL }
};

/*
 * Proxy-protocol implementation
 */

static const char *pp_inp_filter = "ProxyProtocol Filter";

typedef struct {
    char line[108];
} proxy_v1;

typedef union {
    struct {        /* for TCP/UDP over IPv4, len = 12 */
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
    } ip4;
    struct {        /* for TCP/UDP over IPv6, len = 36 */
         uint8_t  src_addr[16];
         uint8_t  dst_addr[16];
         uint16_t src_port;
         uint16_t dst_port;
    } ip6;
    struct {        /* for AF_UNIX sockets, len = 216 */
         uint8_t src_addr[108];
         uint8_t dst_addr[108];
    } unx;
} proxy_v2_addr;

typedef struct {
    uint8_t  sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
    uint8_t  ver_cmd;  /* protocol version and command */
    uint8_t  fam;      /* protocol family and address */
    uint16_t len;     /* number of following bytes part of the header */
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

typedef struct {
    char header[sizeof(proxy_header)];
    apr_size_t rcvd;
    apr_size_t need;
    int version;
    ap_input_mode_t mode;
    apr_bucket_brigade *bb;
    int done;
} pp_filter_context;

typedef struct {
    apr_sockaddr_t *client_addr;
    char *client_ip;
} pp_conn_config;

static int pp_is_server_port(apr_port_t port)
{
    ap_listen_rec *lr;

    for (lr = ap_listeners; lr; lr = lr->next) {
        if (lr->bind_addr && lr->bind_addr->port == port) {
            return 1;
        }
    }

    return 0;
}

/* Add our filter to the connection.
 */
static int pp_hook_pre_connection(conn_rec *c, void *csd)
{
    pp_config *conf;
    pp_conn_config *conn_conf;

    /* check if we're enabled for this connection */
    conf = ap_get_module_config(ap_server_conf->module_config,
                                &proxy_protocol_module);

    if (!pp_addr_in_list(conf->enabled, c->local_addr) ||
        pp_addr_in_list(conf->disabled, c->local_addr)) {
        return DECLINED;
    }

    /* mod_proxy creates outgoing connections - we don't want those */
    if (!pp_is_server_port(c->local_addr->port)) {
        return DECLINED;
    }

    /* add our filter */
    if (!ap_add_input_filter(pp_inp_filter, NULL, NULL, c)) {
        return DECLINED;
    }

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "ProxyProtocol: enabled on connection to %s:%hu",
                  c->local_ip, c->local_addr->port);

    /* this holds the resolved proxy info for this connection */
    conn_conf = apr_pcalloc(c->pool, sizeof(*conn_conf));
    ap_set_module_config(c->conn_config, &proxy_protocol_module, conn_conf);

    return OK;
}

/* Set the request's useragent fields to our client info.
 */
static int pp_hook_post_read_request(request_rec *r)
{
    pp_conn_config *conn_conf;

    conn_conf = ap_get_module_config(r->connection->conn_config,
                                     &proxy_protocol_module);
    if (!conn_conf || !conn_conf->client_addr) {
        return DECLINED;
    }

    r->useragent_addr = conn_conf->client_addr;
    r->useragent_ip = conn_conf->client_ip;

    return OK;
}

typedef enum { HDR_DONE, HDR_ERROR, HDR_NEED_MORE } pp_parse_status_t;

/*
 * Human readable format:
 * PROXY {TCP4|TCP6|UNKNOWN} <client-ip-addr> <dest-ip-addr> <client-port> <dest-port><CR><LF>
 */
static pp_parse_status_t pp_process_v1_header(conn_rec *c,
                                              pp_conn_config *conn_conf,
                                              proxy_header *hdr, apr_size_t len,
                                              apr_size_t *hdr_len)
{
    char *end, *next, *word, *host, *valid_addr_chars, *saveptr;
    char buf[sizeof(hdr->v1.line)];
    apr_port_t port;
    apr_status_t ret;
    apr_int32_t family;

#define GET_NEXT_WORD(field) \
    word = apr_strtok(NULL, " ", &saveptr); \
    if (!word) { \
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,  \
                      "ProxyProtocol: no " field " found in header '%s'", \
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
        family = APR_INET6;
        valid_addr_chars = "0123456789abcdefABCDEF:";
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, 
                      "ProxyProtocol: unknown family '%s' in header '%s'",
                      word, hdr->v1.line);
        return HDR_ERROR;
    }

    /* parse client-addr */
    GET_NEXT_WORD("client-address")

    if (strspn(word, valid_addr_chars) != strlen(word)) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, 
                      "ProxyProtocol: invalid client-address '%s' found in "
                      "header '%s'", word, hdr->v1.line);
        return HDR_ERROR;
    }

    host = word;

    /* parse dest-addr */
    GET_NEXT_WORD("destination-address")

    /* parse client-port */
    GET_NEXT_WORD("client-port")
    if (sscanf(word, "%hu", &port) != 1) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, 
                      "ProxyProtocol: error parsing port '%s' in header '%s'",
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
        ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, c, 
                      "ProxyProtocol: error converting family '%d', host '%s',"
                      " and port '%hu' to sockaddr; header was '%s'",
                      family, host, port, hdr->v1.line);
        return HDR_ERROR;
    }

    conn_conf->client_ip = apr_pstrdup(c->pool, host);

    return HDR_DONE;
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
static pp_parse_status_t pp_process_v2_header(conn_rec *c,
                                              pp_conn_config *conn_conf,
                                              proxy_header *hdr)
{
    apr_status_t ret;
    struct in_addr *in_addr;
    struct in6_addr *in6_addr;

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
                        ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, c, 
                                      "ProxyProtocol: error creating sockaddr");
                        return HDR_ERROR;
                    }

                    conn_conf->client_addr->sa.sin.sin_addr.s_addr =
                            hdr->v2.addr.ip4.src_addr;
                    break;

                case 0x21:  /* TCPv6 */
                    ret = apr_sockaddr_info_get(&conn_conf->client_addr, NULL,
                                                APR_INET6,
                                                ntohs(hdr->v2.addr.ip6.src_port),
                                                0, c->pool);
                    if (ret != APR_SUCCESS) {
                        conn_conf->client_addr = NULL;
                        ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, c, 
                                      "ProxyProtocol: error creating sockaddr");
                        return HDR_ERROR;
                    }

                    memcpy(&conn_conf->client_addr->sa.sin6.sin6_addr.s6_addr,
                           hdr->v2.addr.ip6.src_addr, 16);
                    break;

                default:
                    /* unsupported protocol, keep local connection address */
                    return HDR_DONE;
            }
            break;  /* we got a sockaddr now */

        case 0x00: /* LOCAL command */
            /* keep local connection address for LOCAL */
            return HDR_DONE;

        default:
            /* not a supported command */
            ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, c, 
                          "ProxyProtocol: unsupported command %.2hx",
                          hdr->v2.ver_cmd);
            return HDR_ERROR;
    }

    /* got address - compute the client_ip from it */
    ret = apr_sockaddr_ip_get(&conn_conf->client_ip, conn_conf->client_addr);
    if (ret != APR_SUCCESS) {
        conn_conf->client_addr = NULL;
        ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, c, 
                      "ProxyProtocol: error converting address to string");
        return HDR_ERROR;
    }

    return HDR_DONE;
}

/* Determine if this is a v1 or v2 header.
 */
static int pp_determine_version(conn_rec *c, const char *ptr)
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
       ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, 
                     "ProxyProtocol: no valid header found");
       return -1;
    }
}

/* Capture the first bytes on the protocol and parse the proxy protocol header.
 * Removes itself when the header is complete.
 */
static apr_status_t pp_input_filter(ap_filter_t *f,
                                    apr_bucket_brigade *bb_out,
                                    ap_input_mode_t mode,
                                    apr_read_type_e block,
                                    apr_off_t readbytes)
{
    apr_status_t ret;
    pp_filter_context *ctx = f->ctx;
    pp_conn_config *conn_conf;
    apr_bucket *b;
    pp_parse_status_t psts;
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

    conn_conf = ap_get_module_config(f->c->conn_config, &proxy_protocol_module);

    /* try to read a header's worth of data */
    while (!ctx->done) {
        if (APR_BRIGADE_EMPTY(ctx->bb)) {
            ret = ap_get_brigade(f->next, ctx->bb, ctx->mode, block,
                                 ctx->need - ctx->rcvd);
            if (ret != APR_SUCCESS) {
                return ret;
            }
        }
        if (APR_BRIGADE_EMPTY(ctx->bb)) {
            return APR_EOF;
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
                    ctx->version = pp_determine_version(f->c, ctx->header);
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
                psts = pp_process_v1_header(f->c, conn_conf,
                                            (proxy_header *) ctx->header,
                                            ctx->rcvd, &ctx->need);
            }
            else if (ctx->version == 2) {
                if (ctx->rcvd >= MIN_V2_HDR_LEN) {
                    ctx->need = MIN_V2_HDR_LEN +
                                ntohs(((proxy_header *) ctx->header)->v2.len);
                }
                if (ctx->rcvd >= ctx->need) {
                    psts = pp_process_v2_header(f->c, conn_conf,
                                                (proxy_header *) ctx->header);
                }
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, 
                              "ProxyProtocol: internal error: unknown version "
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
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c,
                  "ProxyProtocol: received valid header: %s:%hu",
                  conn_conf->client_ip, conn_conf->client_addr->port);

    if (ctx->rcvd > ctx->need || !APR_BRIGADE_EMPTY(ctx->bb)) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, 
                      "ProxyProtocol: internal error: have data left over; "
                      " need=%lu, rcvd=%lu, brigade-empty=%d", ctx->need,
                      ctx->rcvd, APR_BRIGADE_EMPTY(ctx->bb));
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

static void proxy_protocol_register_hooks(apr_pool_t *p)
{
    /* mod_ssl is CONNECTION + 5, so we want something higher (earlier);
     * mod_reqtimeout is CONNECTION + 8, so we want something lower (later) */
    ap_register_input_filter(pp_inp_filter, pp_input_filter, NULL,
                             AP_FTYPE_CONNECTION + 7);

    ap_hook_pre_config(pp_hook_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(pp_hook_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(pp_hook_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(pp_hook_post_read_request, NULL, NULL,
                              APR_HOOK_REALLY_FIRST);
}

/* Dispatch list for API hooks */
AP_DECLARE_MODULE(proxy_protocol) = {
    STANDARD20_MODULE_STUFF, 
    NULL,                          /* create per-dir    config structures */
    NULL,                          /* merge  per-dir    config structures */
    NULL,                          /* create per-server config structures */
    NULL,                           /* merge  per-server config structures */
    proxy_protocol_cmds,           /* table of config file commands       */
    proxy_protocol_register_hooks  /* register hooks                      */
};
