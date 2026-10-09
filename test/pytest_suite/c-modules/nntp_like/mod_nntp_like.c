#define HTTPD_TEST_REQUIRE_APACHE 2

/*
 * purpose of this module is to test protocol modules that need to 
 * send data to the client before reading any request data.
 * in this case, mod_ssl needs to handshake before sending data to the client.
 * t/protocol/nntp-like.t tests both with and without ssl
 * to make sure the protocol code works in both cases.
 */

#if CONFIG_FOR_HTTPD_TEST

<VirtualHost mod_nntp_like>
    NNTPLike On
</VirtualHost>

<IfModule @ssl_module@>
    <VirtualHost mod_nntp_like_ssl>
        NNTPLike On
        SSLEngine On
    </VirtualHost>
</IfModule>

#endif

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "apr_strings.h"

module AP_MODULE_DECLARE_DATA nntp_like_module;

typedef struct {
    int enabled;
} nntp_like_srv_cfg_t;

static void *nntp_like_srv_cfg_create(apr_pool_t *p, server_rec *s)
{
    nntp_like_srv_cfg_t *cfg = apr_palloc(p, sizeof(*cfg));

    cfg->enabled = 0;

    return cfg;
}

static const char *nntp_like_cmd_enable(cmd_parms *cmd, void *dummy, int arg)
{
    nntp_like_srv_cfg_t *cfg =
        ap_get_module_config(cmd->server->module_config,
                             &nntp_like_module);
    cfg->enabled = arg;

    return NULL;
}

/* this function just triggers the SSL handshake.
 * normally that would happen in a protocol such as HTTP when
 * the client request is read.  however, with certain protocols
 * such as NNTP, the server sends a response before the client
 * sends a request
 *
 * if SSL is not enabled, this function is a noop
 */
static apr_status_t nntp_like_init_connection(conn_rec *c)
{
    apr_bucket_brigade *bb;
    apr_status_t rv;

    bb = apr_brigade_create(c->pool, c->bucket_alloc);

    rv = ap_get_brigade(c->input_filters, bb, AP_MODE_INIT, 
                        APR_BLOCK_READ, 0);

    apr_brigade_destroy(bb);

    return rv;
}

static apr_status_t nntp_like_send_welcome(conn_rec *c)
{
    apr_bucket *bucket;
    apr_bucket_brigade *bb = apr_brigade_create(c->pool, c->bucket_alloc);

#define NNTP_LIKE_WELCOME \
    "200 localhost - ready\r\n"

    bucket = apr_bucket_immortal_create(NNTP_LIKE_WELCOME,
                                        sizeof(NNTP_LIKE_WELCOME)-1,
                                        c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, bucket);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_flush_create(c->bucket_alloc));

    return ap_pass_brigade(c->output_filters, bb);
}

static int nntp_like_pre_connection(conn_rec *c, void *csd)
{
    nntp_like_srv_cfg_t *cfg =
        ap_get_module_config(c->base_server->module_config,
                             &nntp_like_module);

    if (cfg->enabled) {
        apr_socket_timeout_set(csd, c->base_server->keep_alive_timeout);
    }

    return DECLINED;
}

static int nntp_like_process_connection(conn_rec *c)
{
    apr_bucket_brigade *bb;
    apr_status_t rv;
    nntp_like_srv_cfg_t *cfg =
        ap_get_module_config(c->base_server->module_config,
                             &nntp_like_module);

    if (!cfg->enabled) {
        return DECLINED;
    }

    /* handshake if talking over SSL */
    if ((rv = nntp_like_init_connection(c)) != APR_SUCCESS) {
        return rv;
    }

    /* send the welcome message */
    if ((rv = nntp_like_send_welcome(c)) != APR_SUCCESS) {
        return rv;
    }

    do {
        bb = apr_brigade_create(c->pool, c->bucket_alloc);

        if ((rv = ap_get_brigade(c->input_filters, bb,
                                 AP_MODE_GETLINE,
                                 APR_BLOCK_READ, 0)) != APR_SUCCESS || 
             APR_BRIGADE_EMPTY(bb))
        {
            apr_brigade_destroy(bb);
            break;
        }

        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_flush_create(c->bucket_alloc));

        rv = ap_pass_brigade(c->output_filters, bb);
    } while (rv == APR_SUCCESS);

    return OK;
}

static void nntp_like_register_hooks(apr_pool_t *p)
{
    ap_hook_pre_connection(nntp_like_pre_connection, NULL, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_process_connection(nntp_like_process_connection,
                               NULL, NULL,
                               APR_HOOK_MIDDLE);
}

static const command_rec nntp_like_cmds[] = 
{
    AP_INIT_FLAG("NNTPLike", nntp_like_cmd_enable, NULL, RSRC_CONF,
                 "enable nntp like protocol on this host"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA nntp_like_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    nntp_like_srv_cfg_create, /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    nntp_like_cmds,        /* table of config file commands       */
    nntp_like_register_hooks  /* register hooks                      */
};
