#define HTTPD_TEST_REQUIRE_APACHE 2

#if CONFIG_FOR_HTTPD_TEST

<Location /input_body_filter>
  SetHandler input-body-filter
  InputBodyFilter On
</Location>

#endif

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "apr_strings.h"

module AP_MODULE_DECLARE_DATA input_body_filter_module;

#define INPUT_BODY_FILTER_NAME "INPUT_BODY_FILTER"

typedef struct {
    int enabled;
} input_body_filter_dcfg_t;

static void *input_body_filter_dcfg_create(apr_pool_t *p, char *dummy)
{
    input_body_filter_dcfg_t *dcfg =
        (input_body_filter_dcfg_t *)apr_pcalloc(p, sizeof(*dcfg));

    return dcfg;
}

static int input_body_filter_fixup_handler(request_rec *r)
{
    if ((r->method_number == M_POST) && r->handler &&
        !strcmp(r->handler, "input-body-filter"))
    {
        r->handler = "echo_post";
    }

    return OK;
}

static int input_body_filter_response_handler(request_rec *r)
{
    if (strcmp(r->handler, "echo_post")) {
        return DECLINED;
    }

    if (r->method_number != M_POST) {
        ap_rputs("1..1\nok 1\n", r);
        return OK;
    }
    else {
        return DECLINED;
    }
}

static void reverse_string(char *string, int len)
{
    register char *up, *down;
    register unsigned char tmp;

    up = string;
    down = string + len - 1;

    while (down > up) {
        tmp = *up;
        *up++ = *down;
        *down-- = tmp;
    }
}

typedef struct input_body_ctx_t {
    apr_bucket_brigade *b;
} input_body_ctx_t;

static int input_body_filter_handler(ap_filter_t *f, apr_bucket_brigade *bb, 
                                     ap_input_mode_t mode, 
                                     apr_read_type_e block,
                                     apr_off_t readbytes)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_status_t rv;
    input_body_ctx_t *ctx = f->ctx;

    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ctx->b = apr_brigade_create(r->pool, c->bucket_alloc);
    }

    if (APR_BRIGADE_EMPTY(ctx->b))
    {
        if ((rv = ap_get_brigade(f->next, ctx->b, mode, block,
                                 readbytes)) != APR_SUCCESS) {
            return rv;
        }
    }

    while (!APR_BRIGADE_EMPTY(ctx->b)) {
        const char *data;
        apr_size_t len;
        apr_bucket *bucket;

        bucket = APR_BRIGADE_FIRST(ctx->b);

        if (APR_BUCKET_IS_EOS(bucket)) {
            APR_BUCKET_REMOVE(bucket);
            APR_BRIGADE_INSERT_TAIL(bb, bucket);
            break;
        }

        rv = apr_bucket_read(bucket, &data, &len, block);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        APR_BUCKET_REMOVE(bucket);

        if (len) {
            char *reversed = apr_pstrndup(r->pool, data, len);
            reverse_string(reversed, len);
            bucket = apr_bucket_pool_create(reversed, len, r->pool,
                                            c->bucket_alloc);
        }

        APR_BRIGADE_INSERT_TAIL(bb, bucket);
    }

    return OK;
}

static void input_body_filter_insert_filter(request_rec *r)
{
    input_body_filter_dcfg_t *dcfg =
        ap_get_module_config(r->per_dir_config, 
                             &input_body_filter_module);

    if (dcfg->enabled) {
        ap_add_input_filter(INPUT_BODY_FILTER_NAME, NULL, r, r->connection);
    }
}

static void input_body_filter_register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(input_body_filter_fixup_handler,
                  NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_handler(input_body_filter_response_handler,
                    NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_insert_filter(input_body_filter_insert_filter,
                          NULL, NULL, APR_HOOK_MIDDLE);

    ap_register_input_filter(INPUT_BODY_FILTER_NAME,
                             input_body_filter_handler, 
                             NULL,
                             AP_FTYPE_RESOURCE);  
}

static const command_rec input_body_filter_cmds[] = {
    AP_INIT_FLAG("InputBodyFilter", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(input_body_filter_dcfg_t, enabled),
                 OR_ALL, "Enable input body filter"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA input_body_filter_module = {
    STANDARD20_MODULE_STUFF, 
    input_body_filter_dcfg_create, /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    input_body_filter_cmds,   /* table of config file commands       */
    input_body_filter_register_hooks  /* register hooks                      */
};

