/*
 * mod_random_token.c - Token generation with caching and metadata
 */

#include "mod_random.h"
#include "apr_time.h"
#include "apr_thread_mutex.h"
#include "apr_strings.h"
#include "http_log.h"

/**
 * Generate a token based on spec and defaults, with optional caching
 *
 * @param r             Request record (required, must not be NULL)
 * @param cfg           Configuration (required, must not be NULL)
 * @param spec          Token specification (optional, can be NULL)
 * @param default_*     Default values to use if spec is NULL or unset
 * @param cached_token  Pointer to cached token string (for TTL caching)
 * @param cache_time    Pointer to cache timestamp
 * @param cache_mutex   Mutex for thread-safe cache access
 * @param cache_pool    Pool for cache allocation (must persist across requests)
 *
 * @return Generated token string, or NULL on critical error (CSPRNG failure)
 *
 * Thread-safety: This function is thread-safe when called with valid mutex.
 * The cache is protected by mutex locks during read/write operations.
 */
char *random_generate_token_from_spec(request_rec *r, const random_config *cfg,
                                      const random_token_spec *spec,
                                      int default_length, random_format_t default_format,
                                      int default_timestamp,
                                      const char *default_prefix, const char *default_suffix,
                                      int default_ttl,
                                      char **cached_token, apr_time_t *cache_time,
                                      apr_thread_mutex_t *cache_mutex, apr_pool_t *cache_pool)
{
    char *random_string, *final_token;
    int use_cached = 0;
    apr_time_t now = 0;  /* Initialize to 0, will be set when needed */
    int final_length, final_timestamp, final_ttl;
    random_format_t final_format;
    const char *final_prefix, *final_suffix;

    /* CRITICAL: Validate required parameters */
    if (!r) {
        /* Cannot log without request - this is a programming error */
        return NULL;
    }
    if (!cfg) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                     "mod_random: CRITICAL - NULL config passed to token generator");
        return NULL;
    }

    /* Apply spec values or use defaults */
    final_length = (spec && spec->length != RANDOM_LENGTH_UNSET) ? spec->length : default_length;
    final_format = (spec && spec->format != RANDOM_FORMAT_UNSET) ? spec->format : default_format;
    final_timestamp = (spec && spec->include_timestamp != RANDOM_ENABLED_UNSET) ? spec->include_timestamp : default_timestamp;
    final_prefix = (spec && spec->prefix) ? spec->prefix : default_prefix;
    final_suffix = (spec && spec->suffix) ? spec->suffix : default_suffix;
    final_ttl = (spec && spec->ttl_seconds != RANDOM_TTL_UNSET) ? spec->ttl_seconds : default_ttl;

    /* Defensive validation: ensure token length is within bounds */
    if (final_length < RANDOM_LENGTH_MIN || final_length > RANDOM_LENGTH_MAX) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                     "mod_random: Invalid token length %d, using default %d",
                     final_length, RANDOM_LENGTH_DEFAULT);
        final_length = RANDOM_LENGTH_DEFAULT;
    }

    /* Defensive validation: ensure format is valid */
    if (final_format < RANDOM_FORMAT_BASE64 || final_format > RANDOM_FORMAT_CUSTOM) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                     "mod_random: Invalid format %d, using BASE64",
                     (int)final_format);
        final_format = RANDOM_FORMAT_BASE64;
    }

    /* Defensive validation: ensure TTL is within bounds */
    if (final_ttl < 0 && final_ttl != RANDOM_TTL_UNSET) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                     "mod_random: Invalid TTL %d (negative), disabling cache",
                     final_ttl);
        final_ttl = 0;  /* Disable caching */
    } else if (final_ttl > RANDOM_TTL_MAX_SECONDS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                     "mod_random: TTL %d exceeds maximum %d, clamping to max",
                     final_ttl, RANDOM_TTL_MAX_SECONDS);
        final_ttl = RANDOM_TTL_MAX_SECONDS;
    }

    /* Get current time once for cache check, timestamp, and cache update */
    if (final_ttl > 0 || final_timestamp) {
        now = apr_time_now();
    }

    /* Check TTL cache with thread-safe mutex protection */
    if (final_ttl > 0 && cache_mutex && cached_token && cache_time && cache_pool) {
        apr_status_t rv = apr_thread_mutex_lock(cache_mutex);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                         "mod_random: Failed to lock cache mutex - skipping cache read");
            /* Continue without cache - safer than risking race condition */
        } else {
            if (*cached_token) {
                /* Use time_t for clearer semantics - elapsed is in seconds */
                time_t elapsed = (time_t)apr_time_sec(now - *cache_time);

                /* Handle clock going backwards (NTP correction, manual change) */
                if (elapsed < 0) {
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                                 "mod_random: System clock went backwards, invalidating cache");
                    *cached_token = NULL;
                    *cache_time = 0;
                } else if (elapsed < final_ttl) {
                    /* Valid cache hit - duplicate to request pool BEFORE unlock
                     * to prevent race condition where another thread could invalidate cache */
                    final_token = apr_pstrdup(r->pool, *cached_token);
                    use_cached = 1;
                }
            }
            apr_thread_mutex_unlock(cache_mutex);

            /* If cache was valid, we're done - return immediately */
            if (use_cached) {
                return final_token;
            }
        }
    }

    /* Generate new token (cache miss or not enabled) */
    {
        int final_alphabet_grouping;
        int final_expiry_seconds;
        int final_encode_metadata;

        /* Apply defaults for alphabet grouping and metadata encoding */
        final_alphabet_grouping = (cfg->alphabet_grouping != RANDOM_GROUPING_UNSET) ? cfg->alphabet_grouping : 0;
        final_expiry_seconds = (cfg->expiry_seconds != RANDOM_EXPIRY_UNSET) ? cfg->expiry_seconds : 0;
        final_encode_metadata = (cfg->encode_metadata != RANDOM_ENABLED_UNSET) ? cfg->encode_metadata : 0;

        /* Validate alphabet_grouping */
        if (final_alphabet_grouping < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                         "mod_random: Invalid alphabet grouping %d (negative), disabling grouping",
                         final_alphabet_grouping);
            final_alphabet_grouping = 0;
        } else if (final_alphabet_grouping > RANDOM_GROUPING_MAX) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                         "mod_random: Alphabet grouping %d exceeds maximum %d, clamping to max",
                         final_alphabet_grouping, RANDOM_GROUPING_MAX);
            final_alphabet_grouping = RANDOM_GROUPING_MAX;
        }

        /* Validate expiry_seconds if metadata encoding is enabled */
        if (final_expiry_seconds < 0 && final_expiry_seconds != RANDOM_EXPIRY_UNSET) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                         "mod_random: Invalid expiry %d (negative), disabling metadata encoding",
                         final_expiry_seconds);
            final_expiry_seconds = 0;
        } else if (final_expiry_seconds > RANDOM_EXPIRY_MAX_SECONDS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                         "mod_random: Expiry %d exceeds maximum %d, clamping to max",
                         final_expiry_seconds, RANDOM_EXPIRY_MAX_SECONDS);
            final_expiry_seconds = RANDOM_EXPIRY_MAX_SECONDS;
        }

        /* Validate custom alphabet if CUSTOM format is selected */
        if (final_format == RANDOM_FORMAT_CUSTOM && !cfg->custom_alphabet) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                         "mod_random: CUSTOM format requires alphabet, falling back to BASE64");
            final_format = RANDOM_FORMAT_BASE64;
        }

        /* Generate random string with specified format */
        random_string = random_generate_string_ex(r->pool, final_length, final_format,
                                                  cfg->custom_alphabet, final_alphabet_grouping);

        /* CRITICAL: Check if CSPRNG failed */
        if (!random_string) {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                         "mod_random: CRITICAL - Failed to generate random bytes. "
                         "This is a system error - cryptographic token generation failed.");
            return NULL;
        }

        /* Add timestamp if requested (reuse 'now' already calculated above) */
        if (final_timestamp) {
            time_t timestamp = apr_time_sec(now);
            random_string = apr_psprintf(r->pool, "%ld-%s", (long)timestamp, random_string);
        }

        /* Encode metadata with expiry and signature if requested */
        if (final_encode_metadata && final_expiry_seconds > 0 && cfg->signing_key) {
            char *encoded = random_encode_with_metadata(r->pool, random_string,
                                                       final_expiry_seconds, cfg->signing_key);
            if (!encoded) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                             "mod_random: Failed to encode metadata, using plain token");
                /* Continue with unencoded token - safer than failing completely */
            } else {
                random_string = encoded;
            }
        } else if (final_encode_metadata && final_expiry_seconds > 0 && !cfg->signing_key) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                         "mod_random: Metadata encoding requested but no signing key configured - skipping");
        }

        /* Add prefix/suffix if configured - single allocation for efficiency */
        if (final_prefix || final_suffix) {
            final_token = apr_psprintf(r->pool, "%s%s%s",
                                      final_prefix ? final_prefix : "",
                                      random_string,
                                      final_suffix ? final_suffix : "");
        } else {
            final_token = random_string;
        }

        /* Update cache if TTL is enabled - use provided pool and mutex */
        if (final_ttl > 0 && cache_mutex && cached_token && cache_time && cache_pool) {
            apr_status_t rv = apr_thread_mutex_lock(cache_mutex);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                             "mod_random: Failed to lock cache mutex - skipping cache write");
                /* Continue without caching - token still valid for this request */
            } else {
                *cached_token = apr_pstrdup(cache_pool, final_token);
                /* Reuse 'now' from line 86 instead of calling apr_time_now() again
                 * This ensures cache_time reflects when token generation started */
                *cache_time = now;
                apr_thread_mutex_unlock(cache_mutex);
            }
        }
    }

    return final_token;
}
