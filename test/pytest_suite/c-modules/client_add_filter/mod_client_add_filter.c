#define HTTPD_TEST_REQUIRE_APACHE 2

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"

/* 
 * in real life we'd never allow the client to configure filters.
 * the purpose of this module is to let .t tests configure filters
 * this allows to test non-filtered and filtered requests without
 * duplicating lots of test configuration
 */

static int client_add_filter_header(void *data,
                                    const char *key,
                                    const char *val)
{
    request_rec *r = (request_rec *)data;

    if (strcasecmp(key, "X-AddInputFilter") == 0) {
        ap_add_input_filter(val, NULL, r, r->connection);
    }
    else if (strcasecmp(key, "X-AddOutputFilter") == 0) {
        ap_add_output_filter(val, NULL, r, r->connection);
    }

    return 1;
}

static void client_add_filter_insert(request_rec *r)
{
    apr_table_do(client_add_filter_header, (void*)r,
                 r->headers_in, NULL);
}

static void client_add_filter_register_hooks(apr_pool_t *p)
{
    ap_hook_insert_filter(client_add_filter_insert,
                          NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA client_add_filter_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    client_add_filter_register_hooks  /* register hooks          */
};

