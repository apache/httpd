/*
 * mod_random - Apache module for generating cryptographically secure random tokens
 *
 * Purpose:
 *   Generates cryptographically secure random strings and injects them into
 *   environment variables and/or HTTP headers for each HTTP request.
 *
 * Use cases:
 *   - CSRF tokens
 *   - Request IDs for logging/tracing (non-unique, probabilistic)
 *   - Nonces for security headers (CSP, etc.)
 *   - One-time tokens
 *
 * Security notes:
 *   - Uses CSPRNG (apr_generate_random_bytes)
 *   - NOT guaranteed unique - collision probability exists but is negligible
 *   - Default 16 bytes = 128 bits of entropy
 *   - For guaranteed unique IDs, use mod_unique_id instead
 */

#include "mod_random.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

/* Forward declaration */
extern module AP_MODULE_DECLARE_DATA random_module;

/* Request hook - generate and inject random tokens */
static int random_fixups(request_rec *r)
{
    random_config *cfg;
    char *final_token;
    int final_length;
    random_format_t final_format;
    int final_include_timestamp;
    int final_ttl;
    random_token_spec *spec;

    if (r->main) {
        return DECLINED;
    }

    cfg = ap_get_module_config(r->per_dir_config, &random_module);
    if (!cfg) {
        return DECLINED;
    }

    /* No tokens configured - nothing to do */
    if (!cfg->token_specs) {
        return DECLINED;
    }

    /* Apply defaults for token generation */
    final_length = (cfg->length != RANDOM_LENGTH_UNSET) ? cfg->length : RANDOM_LENGTH_DEFAULT;
    final_format = (cfg->format != RANDOM_FORMAT_UNSET) ? cfg->format : RANDOM_FORMAT_BASE64;
    final_include_timestamp = (cfg->include_timestamp != RANDOM_ENABLED_UNSET) ? cfg->include_timestamp : 0;
    final_ttl = (cfg->ttl_seconds != RANDOM_TTL_UNSET) ? cfg->ttl_seconds : 0;

    /* Check URL pattern if configured */
    if (cfg->url_pattern) {
        if (ap_regexec(cfg->url_pattern, r->uri, 0, NULL, 0) != 0) {
            return DECLINED;  /* Pattern doesn't match */
        }
    }

    /* Generate all configured tokens */
    for (spec = cfg->token_specs; spec; spec = spec->next) {
        final_token = random_generate_token_from_spec(r, cfg, spec,
                                                      final_length, final_format,
                                                      final_include_timestamp,
                                                      cfg->prefix, cfg->suffix,
                                                      final_ttl,
                                                      &spec->cached_token, &spec->cache_time,
                                                      spec->cache_mutex, spec->pool);

        /* Check if token generation failed (CSPRNG error) */
        if (!final_token) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                         "mod_random: Failed to generate token for %s - skipping",
                         spec->var_name);
            continue; /* Skip this token but try to generate others */
        }

        /* Set environment variable */
        apr_table_set(r->subprocess_env, spec->var_name, final_token);

        /* Set HTTP header if configured */
        if (spec->header_name) {
            apr_table_set(r->headers_out, spec->header_name, final_token);
        }
    }

    return DECLINED;
}

/* Register hooks */
static void random_register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(random_fixups, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Module declaration */
module AP_MODULE_DECLARE_DATA random_module = {
    STANDARD20_MODULE_STUFF,
    random_create_config,
    random_merge_config,
    NULL,
    NULL,
    random_directives,
    random_register_hooks
};
