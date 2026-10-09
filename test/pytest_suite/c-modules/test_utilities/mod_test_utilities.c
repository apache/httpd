#define HTTPD_TEST_REQUIRE_APACHE 2.4

/**
 * This module provides utility functions for other tests; it doesn't provide
 * test cases of its own.
 */

#define APACHE_HTTPD_TEST_EXTRA_HOOKS util_register_hooks
#include "apache_httpd_test.h"

#include "apr_strings.h"
#include "ap_expr.h"

/**
 * The util_strlen() ap_expr function simply returns the length of its string
 * argument as a decimal string.
 */
static const char *util_strlen_func(ap_expr_eval_ctx_t *ctx, const void *data,
                                    const char *arg)
{
    if (!arg) {
        return NULL;
    }

    return apr_psprintf(ctx->p, "%" APR_SIZE_T_FMT, strlen(arg));
}

static int util_expr_lookup(ap_expr_lookup_parms *parms)
{
    switch (parms->type) {
    case AP_EXPR_FUNC_STRING:
        if (!strcasecmp(parms->name, "util_strlen")) {
            *parms->func = util_strlen_func;
            *parms->data = "dummy";
            return OK;
        }
        break;
    }

    return DECLINED;
}

static void util_register_hooks(apr_pool_t *p)
{
    ap_hook_expr_lookup(util_expr_lookup, NULL, NULL, APR_HOOK_MIDDLE);
}

APACHE_HTTPD_TEST_MODULE(test_utilities);
