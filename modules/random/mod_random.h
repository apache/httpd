/*
 * mod_random.h - Public API declarations
 */

#ifndef MOD_RANDOM_H
#define MOD_RANDOM_H

#include "httpd.h"
#include "http_config.h"
#include "apr_pools.h"
#include "mod_random_types.h"

/* Module declaration */
extern module AP_MODULE_DECLARE_DATA random_module;

/* Configuration functions (mod_random_config.c) */
void *random_create_config(apr_pool_t *pool, char *dir);
void *random_merge_config(apr_pool_t *pool, void *base, void *override);
extern const command_rec random_directives[];

/* Encoding functions (mod_random_encode.c) */
char *random_encode_hex(apr_pool_t *pool, const unsigned char *data, int length);
char *random_encode_base64url(apr_pool_t *pool, const char *data, int length);
char *random_encode_custom_alphabet(apr_pool_t *pool, const unsigned char *data,
                                    int length, const char *alphabet, int grouping);
char *random_generate_string_ex(apr_pool_t *pool, int length, random_format_t format,
                                const char *alphabet, int grouping);
char *random_generate_string(apr_pool_t *pool, int length, random_format_t format);

/* Crypto functions (mod_random_crypto.c) */
void random_hmac_sha256(apr_pool_t *pool, const char *key, apr_size_t key_len,
                       const char *data, apr_size_t data_len, unsigned char *digest);
char *random_encode_with_metadata(apr_pool_t *pool, const char *token,
                                  int expiry_seconds, const char *signing_key);

/* Token generation (mod_random_token.c) */
char *random_generate_token_from_spec(request_rec *r, const random_config *cfg,
                                      const random_token_spec *spec,
                                      int default_length, random_format_t default_format,
                                      int default_timestamp,
                                      const char *default_prefix, const char *default_suffix,
                                      int default_ttl,
                                      char **cached_token, apr_time_t *cache_time,
                                      apr_thread_mutex_t *cache_mutex, apr_pool_t *cache_pool);

#endif /* MOD_RANDOM_H */
