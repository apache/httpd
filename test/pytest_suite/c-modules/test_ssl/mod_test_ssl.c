#define HTTPD_TEST_REQUIRE_APACHE 2

#if CONFIG_FOR_HTTPD_TEST

<IfModule @ssl_module@>
    <Location /test_ssl_var_lookup>
        SetHandler test-ssl-var-lookup
        SSLVerifyClient require
        SSLVerifyDepth  10
    </Location>

    <Location /test_ssl_ext_lookup>
        SetHandler test-ssl-ext-lookup
        SSLVerifyClient require
        SSLVerifyDepth  10
    </Location>
</IfModule>

#endif

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_optional.h"

#if AP_MODULE_MAGIC_AT_LEAST(20040425, 0) /* simply include mod_ssl.h if using >= 2.1.0 */

#include "mod_ssl.h"

#if MODULE_MAGIC_COOKIE > 0x41503234UL || \
    (MODULE_MAGIC_COOKIE == 0x41503234UL \
    && AP_MODULE_MAGIC_AT_LEAST(20050919, 0)) /* ssl_ext_list() only in 2.4.x */
#define HAVE_SSL_EXT_LIST
static APR_OPTIONAL_FN_TYPE(ssl_ext_list) *ext_list;
#elif AP_MODULE_MAGIC_AT_LEAST(20050127, 0) /* approx. when ssl_ext_lookup was added */
#define HAVE_SSL_EXT_LOOKUP
static APR_OPTIONAL_FN_TYPE(ssl_ext_lookup) *ext_lookup;
#endif

#else
/* For use of < 2.0.x, inline the declaration: */

APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *,
                         char *));

#endif

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *var_lookup;

static void import_ssl_var_lookup(void)
{
    var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
#ifdef HAVE_SSL_EXT_LOOKUP
    ext_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_ext_lookup);
#endif
#ifdef HAVE_SSL_EXT_LIST
    ext_list = APR_RETRIEVE_OPTIONAL_FN(ssl_ext_list);
#endif
}

#if defined(HAVE_SSL_EXT_LOOKUP) || defined(HAVE_SSL_EXT_LIST)
static int test_ssl_ext_lookup(request_rec *r)
{
    const char *value;

    if (strcmp(r->handler, "test-ssl-ext-lookup")
        || r->method_number != M_GET) {
        return DECLINED;
    }

    if (!r->args) {
        ap_rputs("no query", r);
        return OK;
    }

#ifdef HAVE_SSL_EXT_LOOKUP
    if (!ext_lookup) {
        ap_rputs("ssl_ext_lookup not available", r);
        return OK;
    }

    value = ext_lookup(r->pool, r->connection, 1, r->args);
#else
    if (!ext_list) {
        ap_rputs("ssl_ext_list not available", r);
        return OK;
    }
    
    {
        apr_array_header_t *vals = ext_list(r->pool, r->connection, 1,
                                            r->args);
        
        if (vals) {
            value = *(const char **)apr_array_pop(vals);
        }
        else {
            value = NULL;
        }
    }
#endif

    if (!value) value = "NULL";
    
    ap_rputs(value, r);
    
    return OK;
}

#endif

static int test_ssl_var_lookup(request_rec *r)
{
    const char *value;

    if (strcmp(r->handler, "test-ssl-var-lookup")) {
        return DECLINED;
    }

    if (r->method_number != M_GET) {
        return DECLINED;
    }

    if (!r->args) {
        ap_rputs("no query", r);
        return OK;
    }

    apr_table_setn(r->subprocess_env, "THE_ARGS", r->args);

    if (!var_lookup) {
        ap_rputs("ssl_var_lookup is not available", r);
        return OK;
    }

    value = var_lookup(r->pool, r->server,
                       r->connection, r, r->args);

    if (value && *value) {
        ap_rputs(value, r);
    }
    else {
        ap_rputs("NULL", r);
    }

    return OK;
}

static void test_ssl_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(test_ssl_var_lookup, NULL, NULL, APR_HOOK_MIDDLE);
#if defined(HAVE_SSL_EXT_LOOKUP) || defined(HAVE_SSL_EXT_LIST)
    ap_hook_handler(test_ssl_ext_lookup, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    ap_hook_optional_fn_retrieve(import_ssl_var_lookup,
                                 NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA test_ssl_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    test_ssl_register_hooks  /* register hooks                      */
};

