/*
 * mod_random_crypto.c - HMAC-SHA256 and metadata encoding functions
 */

#include "mod_random.h"
#include "apr_strings.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>

#define HMAC_SHA256_DIGESTSIZE 32

/* HMAC-SHA256 implementation using OpenSSL */
void random_hmac_sha256(apr_pool_t *pool, const char *key, apr_size_t key_len,
                       const char *data, apr_size_t data_len, unsigned char *digest)
{
    unsigned int digest_len = 0;

    /* Use OpenSSL HMAC with SHA256 */
    HMAC(EVP_sha256(),
         key, (int)key_len,
         (const unsigned char *)data, (int)data_len,
         digest, &digest_len);
}

/* Encode token with metadata (expiry timestamp) and optional HMAC-SHA256 signature */
char *random_encode_with_metadata(apr_pool_t *pool, const char *token,
                                  int expiry_seconds, const char *signing_key)
{
    apr_time_t now;
    time_t now_sec, expiry_time;
    char *payload, *final_token;
    unsigned char hmac_digest[HMAC_SHA256_DIGESTSIZE];
    char *hmac_hex;

    now = apr_time_now();
    now_sec = apr_time_sec(now);
    expiry_time = now_sec + expiry_seconds;

    if (signing_key && *signing_key) {
        /* Format: expiry:token:signature */
        /* Create payload for signing */
        payload = apr_psprintf(pool, "%ld:%s", (long)expiry_time, token);

        /* Generate HMAC-SHA256 signature */
        random_hmac_sha256(pool, signing_key, strlen(signing_key),
                          payload, strlen(payload), hmac_digest);

        /* Convert HMAC to hex */
        hmac_hex = random_encode_hex(pool, hmac_digest, HMAC_SHA256_DIGESTSIZE);

        /* Final token with signature */
        final_token = apr_psprintf(pool, "%ld:%s:%s", (long)expiry_time, token, hmac_hex);
    } else {
        /* Format: expiry:token (no signature) */
        final_token = apr_psprintf(pool, "%ld:%s", (long)expiry_time, token);
    }

    return final_token;
}
