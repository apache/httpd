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

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_connection.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_core.h"
#include "util_filter.h"
#define APR_WANT_STRFUNC
#include "apr_strings.h"
#include "apr_version.h"

module AP_MODULE_DECLARE_DATA reqtimeout_module;

#define UNSET                            -1
#define MRT_DEFAULT_handshake_TIMEOUT     0 /* disabled */
#define MRT_DEFAULT_handshake_MAX_TIMEOUT 0
#define MRT_DEFAULT_handshake_MIN_RATE    0
#define MRT_DEFAULT_header_TIMEOUT       20
#define MRT_DEFAULT_header_MAX_TIMEOUT   40
#define MRT_DEFAULT_header_MIN_RATE      500
#define MRT_DEFAULT_body_TIMEOUT         20
#define MRT_DEFAULT_body_MAX_TIMEOUT     0
#define MRT_DEFAULT_body_MIN_RATE        500

typedef struct
{
    int timeout;            /* timeout in secs */
    int max_timeout;        /* max timeout in secs */
    int min_rate;           /* min rate in bytes/s */
    apr_time_t rate_factor; /* scale factor (#usecs per min_rate) */
} reqtimeout_stage_t;

typedef struct
{
    reqtimeout_stage_t handshake;   /* Handshaking (TLS) */
    reqtimeout_stage_t header;      /* Reading the HTTP header */
    reqtimeout_stage_t body;        /* Reading the HTTP body */
} reqtimeout_srv_cfg;

/* this struct is used both as conn_config and as filter context */
typedef struct
{
    apr_time_t timeout_at;
    apr_time_t max_timeout_at;
    reqtimeout_stage_t cur_stage;
    int in_keep_alive;
    char *type;
    apr_socket_t *socket;
    apr_bucket_brigade *tmpbb;
} reqtimeout_con_cfg;

static const char *const reqtimeout_filter_name = "reqtimeout";
static int default_handshake_rate_factor;
static int default_header_rate_factor;
static int default_body_rate_factor;

static void extend_timeout(reqtimeout_con_cfg *ccfg, apr_bucket_brigade *bb)
{
    apr_off_t len;
    apr_time_t new_timeout_at;

    if (apr_brigade_length(bb, 0, &len) != APR_SUCCESS || len <= 0)
        return;

    new_timeout_at = ccfg->timeout_at + len * ccfg->cur_stage.rate_factor;
    if (ccfg->max_timeout_at > 0 && new_timeout_at > ccfg->max_timeout_at) {
        ccfg->timeout_at = ccfg->max_timeout_at;
    }
    else {
        ccfg->timeout_at = new_timeout_at;
    }
}

static apr_status_t check_time_left(reqtimeout_con_cfg *ccfg,
                                    apr_time_t *time_left_p,
                                    apr_time_t now)
{
    if (!now)
        now = apr_time_now();
    *time_left_p = ccfg->timeout_at - now;
    if (*time_left_p <= 0)
        return APR_TIMEUP;

    if (*time_left_p < apr_time_from_sec(1)) {
        *time_left_p = apr_time_from_sec(1);
    }
    return APR_SUCCESS;
}

static apr_status_t have_lf_or_eos(apr_bucket_brigade *bb)
{
    apr_bucket *b = APR_BRIGADE_LAST(bb);

    for ( ; b != APR_BRIGADE_SENTINEL(bb) ; b = APR_BUCKET_PREV(b) ) {
        const char *str;
        apr_size_t len;
        apr_status_t rv;

        if (APR_BUCKET_IS_EOS(b))
            return APR_SUCCESS;

        if (APR_BUCKET_IS_METADATA(b))
            continue;

        rv = apr_bucket_read(b, &str, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS)
            return rv;

        if (len == 0)
            continue;

        if (str[len-1] == APR_ASCII_LF)
            return APR_SUCCESS;
    }
    return APR_INCOMPLETE;
}

/*
 * Append bbIn to bbOut and merge small buckets, to avoid DoS by high memory
 * usage
 */
static apr_status_t brigade_append(apr_bucket_brigade *bbOut, apr_bucket_brigade *bbIn)
{
    while (!APR_BRIGADE_EMPTY(bbIn)) {
        apr_bucket *e = APR_BRIGADE_FIRST(bbIn);
        const char *str;
        apr_size_t len;
        apr_status_t rv;

        rv = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        APR_BUCKET_REMOVE(e);
        if (APR_BUCKET_IS_METADATA(e) || len > APR_BUCKET_BUFF_SIZE/4) {
            APR_BRIGADE_INSERT_TAIL(bbOut, e);
        }
        else {
            if (len > 0) {
                rv = apr_brigade_write(bbOut, NULL, NULL, str, len);
                if (rv != APR_SUCCESS) {
                    apr_bucket_destroy(e);
                    return rv;
                }
            }
            apr_bucket_destroy(e);
        }
    }
    return APR_SUCCESS;
}


#define MIN(x,y) ((x) < (y) ? (x) : (y))
static apr_status_t reqtimeout_filter(ap_filter_t *f,
                                      apr_bucket_brigade *bb,
                                      ap_input_mode_t mode,
                                      apr_read_type_e block,
                                      apr_off_t readbytes)
{
    apr_time_t time_left;
    apr_time_t now = 0;
    apr_status_t rv;
    apr_interval_time_t saved_sock_timeout = UNSET;
    reqtimeout_con_cfg *ccfg = f->ctx;

    if (ccfg->in_keep_alive) {
        /* For this read[_request line()], wait for the first byte using the
         * normal keep-alive timeout (hence don't take this expected idle time
         * into account to setup the connection expiry below).
         */
        ccfg->in_keep_alive = 0;
        rv = ap_get_brigade(f->next, bb, AP_MODE_SPECULATIVE, block, 1);
        if (rv != APR_SUCCESS || APR_BRIGADE_EMPTY(bb)) {
            return rv;
        }
        apr_brigade_cleanup(bb);
    }

    if (ccfg->cur_stage.timeout > 0) {
        /* set new timeout */
        now = apr_time_now();
        ccfg->timeout_at = now + apr_time_from_sec(ccfg->cur_stage.timeout);
        ccfg->cur_stage.timeout = 0;
        if (ccfg->cur_stage.max_timeout > 0) {
            ccfg->max_timeout_at = now + apr_time_from_sec(ccfg->cur_stage.max_timeout);
            ccfg->cur_stage.max_timeout = 0;
        }
    }
    else if (ccfg->timeout_at == 0) {
        /* no timeout set, or in between requests */
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    if (!ccfg->socket) {
        ccfg->socket = ap_get_conn_socket(f->c);
    }

    rv = check_time_left(ccfg, &time_left, now);
    if (rv != APR_SUCCESS)
        goto out;

    if (block == APR_NONBLOCK_READ || mode == AP_MODE_INIT
        || mode == AP_MODE_EATCRLF) {
        rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
        if (ccfg->cur_stage.rate_factor && rv == APR_SUCCESS) {
            extend_timeout(ccfg, bb);
        }
        return rv;
    }

    rv = apr_socket_timeout_get(ccfg->socket, &saved_sock_timeout);
    AP_DEBUG_ASSERT(rv == APR_SUCCESS);

    rv = apr_socket_timeout_set(ccfg->socket, MIN(time_left, saved_sock_timeout));
    AP_DEBUG_ASSERT(rv == APR_SUCCESS);

    if (mode == AP_MODE_GETLINE) {
        /*
         * For a blocking AP_MODE_GETLINE read, apr_brigade_split_line()
         * would loop until a whole line has been read. As this would make it
         * impossible to enforce a total timeout, we only do non-blocking
         * reads.
         */
        apr_off_t remaining = HUGE_STRING_LEN;
        do {
            apr_off_t bblen;
#if APR_MAJOR_VERSION < 2
            apr_int32_t nsds;
            apr_interval_time_t poll_timeout;
            apr_pollfd_t pollset;
#endif

            rv = ap_get_brigade(f->next, bb, AP_MODE_GETLINE, APR_NONBLOCK_READ, remaining);
            if (rv != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(rv)) {
                break;
            }

            if (!APR_BRIGADE_EMPTY(bb)) {
                if (ccfg->cur_stage.rate_factor) {
                    extend_timeout(ccfg, bb);
                }

                rv = have_lf_or_eos(bb);
                if (rv != APR_INCOMPLETE) {
                    break;
                }

                rv = apr_brigade_length(bb, 1, &bblen);
                if (rv != APR_SUCCESS) {
                    break;
                }
                remaining -= bblen;
                if (remaining <= 0) {
                    break;
                }

                /* Haven't got a whole line yet, save what we have ... */
                if (!ccfg->tmpbb) {
                    ccfg->tmpbb = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
                }
                rv = brigade_append(ccfg->tmpbb, bb);
                if (rv != APR_SUCCESS)
                    break;
            }

            /* ... and wait for more */
#if APR_MAJOR_VERSION < 2
            pollset.p = f->c->pool;
            pollset.desc_type = APR_POLL_SOCKET;
            pollset.reqevents = APR_POLLIN|APR_POLLHUP;
            pollset.desc.s = ccfg->socket;
            apr_socket_timeout_get(ccfg->socket, &poll_timeout);
            rv = apr_poll(&pollset, 1, &nsds, poll_timeout);
#else
            rv = apr_socket_wait(ccfg->socket, APR_WAIT_READ);
#endif
            if (rv != APR_SUCCESS)
                break;

            rv = check_time_left(ccfg, &time_left, 0);
            if (rv != APR_SUCCESS)
                break;

            rv = apr_socket_timeout_set(ccfg->socket,
                                   MIN(time_left, saved_sock_timeout));
            AP_DEBUG_ASSERT(rv == APR_SUCCESS);

        } while (1);

        if (ccfg->tmpbb)
            APR_BRIGADE_PREPEND(bb, ccfg->tmpbb);

    }
    else { /* mode != AP_MODE_GETLINE */
        rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
        /* Don't extend the timeout in speculative mode, wait for
         * the real (relevant) bytes to be asked later, within the
         * currently allotted time.
         */
        if (ccfg->cur_stage.rate_factor && rv == APR_SUCCESS
                && mode != AP_MODE_SPECULATIVE) {
            extend_timeout(ccfg, bb);
        }
    }

    apr_socket_timeout_set(ccfg->socket, saved_sock_timeout);

out:
    if (APR_STATUS_IS_TIMEUP(rv)) {
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, f->c, APLOGNO(01382)
                      "Request %s read timeout", ccfg->type);
        /*
         * If we allow a normal lingering close, the client may keep this
         * process/thread busy for another 30s (MAX_SECS_TO_LINGER).
         * Therefore we tell ap_lingering_close() to shorten this period to
         * 2s (SECONDS_TO_LINGER).
         */
        apr_table_setn(f->c->notes, "short-lingering-close", "1");

        /*
         * Also, we must not allow keep-alive requests, as
         * ap_finalize_protocol() may ignore our error status (if the timeout
         * happened on a request body that is discarded).
         */
        f->c->keepalive = AP_CONN_CLOSE;
    }
    return rv;
}

static apr_status_t reqtimeout_eor(ap_filter_t *f, apr_bucket_brigade *bb)
{
    if (!APR_BRIGADE_EMPTY(bb) && AP_BUCKET_IS_EOR(APR_BRIGADE_LAST(bb))) {
        reqtimeout_con_cfg *ccfg = f->ctx;
        ccfg->timeout_at = 0;
    }
    return ap_pass_brigade(f->next, bb);
}

#define INIT_STAGE(cfg, ccfg, stage) do { \
    if (cfg->stage.timeout != UNSET) { \
        ccfg->cur_stage.timeout     = cfg->stage.timeout; \
        ccfg->cur_stage.max_timeout = cfg->stage.max_timeout; \
        ccfg->cur_stage.rate_factor = cfg->stage.rate_factor; \
    } \
    else { \
        ccfg->cur_stage.timeout     = MRT_DEFAULT_##stage##_TIMEOUT; \
        ccfg->cur_stage.max_timeout = MRT_DEFAULT_##stage##_MAX_TIMEOUT; \
        ccfg->cur_stage.rate_factor = default_##stage##_rate_factor; \
    } \
} while (0)

static int reqtimeout_init(conn_rec *c)
{
    reqtimeout_con_cfg *ccfg;
    reqtimeout_srv_cfg *cfg;

    cfg = ap_get_module_config(c->base_server->module_config,
                               &reqtimeout_module);
    AP_DEBUG_ASSERT(cfg != NULL);

    /* For compatibility, handshake timeout is disabled when UNSET (< 0) */
    if (cfg->handshake.timeout <= 0
            && cfg->header.timeout == 0
            && cfg->body.timeout == 0) {
        /* disabled for this vhost */
        return DECLINED;
    }

    ccfg = ap_get_module_config(c->conn_config, &reqtimeout_module);
    if (ccfg == NULL) {
        ccfg = apr_pcalloc(c->pool, sizeof(reqtimeout_con_cfg));
        ap_set_module_config(c->conn_config, &reqtimeout_module, ccfg);
        ap_add_output_filter(reqtimeout_filter_name, ccfg, NULL, c);
        ap_add_input_filter(reqtimeout_filter_name, ccfg, NULL, c);

        ccfg->type = "handshake";
        if (cfg->handshake.timeout > 0) {
            INIT_STAGE(cfg, ccfg, handshake);
        }
    }

    /* we are not handling the connection, we just do initialization */
    return DECLINED;
}

static void reqtimeout_before_header(request_rec *r, conn_rec *c)
{
    reqtimeout_srv_cfg *cfg;
    reqtimeout_con_cfg *ccfg =
        ap_get_module_config(c->conn_config, &reqtimeout_module);

    if (ccfg == NULL) {
        /* not configured for this connection */
        return;
    }

    cfg = ap_get_module_config(c->base_server->module_config,
                               &reqtimeout_module);
    AP_DEBUG_ASSERT(cfg != NULL);

    /* (Re)set the state for this new request, but ccfg->socket and
     * ccfg->tmpbb which have the lifetime of the connection.
     */
    ccfg->type = "header";
    ccfg->timeout_at = 0;
    ccfg->max_timeout_at = 0;
    ccfg->in_keep_alive = (c->keepalives > 0);
    INIT_STAGE(cfg, ccfg, header);
}

static int reqtimeout_before_body(request_rec *r)
{
    reqtimeout_srv_cfg *cfg;
    reqtimeout_con_cfg *ccfg =
        ap_get_module_config(r->connection->conn_config, &reqtimeout_module);

    if (ccfg == NULL) {
        /* not configured for this connection */
        return OK;
    }
    cfg = ap_get_module_config(r->server->module_config,
                              &reqtimeout_module);
    AP_DEBUG_ASSERT(cfg != NULL);

    ccfg->type = "body";
    ccfg->timeout_at = 0;
    ccfg->max_timeout_at = 0;
    if (r->method_number == M_CONNECT) {
        /* disabled for a CONNECT request */
        ccfg->cur_stage.timeout = 0;
    }
    else {
        INIT_STAGE(cfg, ccfg, body);
    }
    return OK;
}

#define UNSET_STAGE(cfg, stage) do { \
    cfg->stage.timeout = UNSET; \
    cfg->stage.max_timeout = UNSET; \
    cfg->stage.min_rate = UNSET; \
} while (0)

static void *reqtimeout_create_srv_config(apr_pool_t *p, server_rec *s)
{
    reqtimeout_srv_cfg *cfg = apr_pcalloc(p, sizeof(reqtimeout_srv_cfg));

    UNSET_STAGE(cfg, handshake);
    UNSET_STAGE(cfg, header);
    UNSET_STAGE(cfg, body);

    return cfg;
}

#define MERGE_INT(cfg, base, add, val) \
    cfg->val = (add->val == UNSET) ? base->val : add->val
#define MERGE_STAGE(cfg, base, add, stage) do { \
    MERGE_INT(cfg, base, add, stage.timeout); \
    MERGE_INT(cfg, base, add, stage.max_timeout); \
    MERGE_INT(cfg, base, add, stage.min_rate); \
    cfg->stage.rate_factor = (cfg->stage.min_rate == UNSET) \
                             ? base->stage.rate_factor \
                             : add->stage.rate_factor; \
} while (0)

static void *reqtimeout_merge_srv_config(apr_pool_t *p, void *base_, void *add_)
{
    reqtimeout_srv_cfg *base = base_;
    reqtimeout_srv_cfg *add  = add_;
    reqtimeout_srv_cfg *cfg  = apr_pcalloc(p, sizeof(reqtimeout_srv_cfg));

    MERGE_STAGE(cfg, base, add, handshake);
    MERGE_STAGE(cfg, base, add, header);
    MERGE_STAGE(cfg, base, add, body);

    return cfg;
}

static const char *parse_int(apr_pool_t *p, const char *arg, int *val)
{
    char *endptr;
    *val = strtol(arg, &endptr, 10);

    if (arg == endptr) {
        return apr_psprintf(p, "Value '%s' not numerical", endptr);
    }
    if (*endptr != '\0') {
        return apr_psprintf(p, "Cannot parse '%s'", endptr);
    }
    if (*val < 0) {
        return "Value must be non-negative";
    }
    return NULL;
}

static const char *set_reqtimeout_param(reqtimeout_srv_cfg *conf,
                                      apr_pool_t *p,
                                      const char *key,
                                      const char *val)
{
    const char *ret = NULL;
    char *rate_str = NULL, *initial_str, *max_str = NULL;
    reqtimeout_stage_t *stage;

    if (!strcasecmp(key, "handshake")) {
        stage = &conf->handshake;
    }
    else if (!strcasecmp(key, "header")) {
        stage = &conf->header;
    }
    else if (!strcasecmp(key, "body")) {
        stage = &conf->body;
    }
    else {
        return "Unknown RequestReadTimeout parameter";
    }

    memset(stage, 0, sizeof(*stage));

    if ((rate_str = ap_strcasestr(val, ",minrate="))) {
        initial_str = apr_pstrndup(p, val, rate_str - val);
        rate_str += strlen(",minrate=");
        ret = parse_int(p, rate_str, &stage->min_rate);
        if (ret)
            return ret;

        if (stage->min_rate == 0)
            return "Minimum data rate must be larger than 0";

        if ((max_str = strchr(initial_str, '-'))) {
            *max_str++ = '\0';
            ret = parse_int(p, max_str, &stage->max_timeout);
            if (ret)
                return ret;
        }

        ret = parse_int(p, initial_str, &stage->timeout);
    }
    else {
        if (ap_strchr_c(val, '-'))
            return "Must set MinRate option if using timeout range";
        ret = parse_int(p, val, &stage->timeout);
    }
    if (ret)
        return ret;

    if (stage->max_timeout && stage->timeout >= stage->max_timeout) {
        return "Maximum timeout must be larger than initial timeout";
    }

    if (stage->min_rate) {
        stage->rate_factor = apr_time_from_sec(1) / stage->min_rate;
    }

    return NULL;
}

static const char *set_reqtimeouts(cmd_parms *cmd, void *mconfig,
                                   const char *arg)
{
    reqtimeout_srv_cfg *conf =
    ap_get_module_config(cmd->server->module_config,
                         &reqtimeout_module);

    while (*arg) {
        char *word, *val;
        const char *err;

        word = ap_getword_conf(cmd->temp_pool, &arg);
        val = strchr(word, '=');
        if (!val) {
            return "Invalid RequestReadTimeout parameter. Parameter must be "
            "in the form 'key=value'";
        }
        else
            *val++ = '\0';

        err = set_reqtimeout_param(conf, cmd->pool, word, val);

        if (err)
            return apr_psprintf(cmd->temp_pool, "RequestReadTimeout: %s=%s: %s",
                               word, val, err);
    }

    return NULL;

}

static void reqtimeout_hooks(apr_pool_t *pool)
{
    /*
     * mod_ssl is AP_FTYPE_CONNECTION + 5 and mod_reqtimeout needs to
     * be called before mod_ssl for the handshake stage to catch SSL traffic.
     */
    ap_register_input_filter(reqtimeout_filter_name, reqtimeout_filter, NULL,
                             AP_FTYPE_CONNECTION + 8);

    /*
     * We need to pause timeout detection in between requests, for
     * speculative and non-blocking reads, so between each outgoing EOR
     * and the next pre_read_request call.
     */
    ap_register_output_filter(reqtimeout_filter_name, reqtimeout_eor, NULL,
                              AP_FTYPE_CONNECTION);

    /*
     * mod_reqtimeout needs to be called before ap_process_http_request (which
     * is run at APR_HOOK_REALLY_LAST) but after all other protocol modules.
     * This ensures that it only influences normal http connections and not
     * e.g. mod_ftp. We still process it first though, for the handshake stage
     * to work with/before mod_ssl, but since it's disabled by default it won't
     * influence non-HTTP modules unless configured explicitly. Also, if
     * mod_reqtimeout used the pre_connection hook, it would be inserted on
     * mod_proxy's backend connections, and we don't want this.
     */
    ap_hook_process_connection(reqtimeout_init, NULL, NULL, APR_HOOK_FIRST);

    ap_hook_pre_read_request(reqtimeout_before_header, NULL, NULL,
                             APR_HOOK_MIDDLE);
    ap_hook_post_read_request(reqtimeout_before_body, NULL, NULL,
                              APR_HOOK_MIDDLE);

#if MRT_DEFAULT_handshake_MIN_RATE
    default_handshake_rate_factor = apr_time_from_sec(1) /
                                    MRT_DEFAULT_handshake_MIN_RATE;
#endif
#if MRT_DEFAULT_header_MIN_RATE
    default_header_rate_factor = apr_time_from_sec(1) /
                                 MRT_DEFAULT_header_MIN_RATE;
#endif
#if MRT_DEFAULT_body_MIN_RATE
    default_body_rate_factor = apr_time_from_sec(1) /
                               MRT_DEFAULT_body_MIN_RATE;
#endif
}

static const command_rec reqtimeout_cmds[] = {
    AP_INIT_RAW_ARGS("RequestReadTimeout", set_reqtimeouts, NULL, RSRC_CONF,
                     "Set various timeout parameters for TLS handshake and/or "
                     "reading request headers and body"),
    {NULL}
};

AP_DECLARE_MODULE(reqtimeout) = {
    STANDARD20_MODULE_STUFF,
    NULL,                           /* create per-dir config structures */
    NULL,                           /* merge  per-dir config structures */
    reqtimeout_create_srv_config,   /* create per-server config structures */
    reqtimeout_merge_srv_config,    /* merge per-server config structures */
    reqtimeout_cmds,                /* table of config file commands */
    reqtimeout_hooks
};
