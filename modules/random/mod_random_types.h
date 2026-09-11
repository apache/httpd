/*
 * mod_random_types.h - Type definitions and constants
 */

#ifndef MOD_RANDOM_TYPES_H
#define MOD_RANDOM_TYPES_H

#include "apr_time.h"
#include "apr_thread_mutex.h"
#include "ap_regex.h"

/* Configuration constants */
#define RANDOM_LENGTH_DEFAULT  16    /* 128 bits of entropy */
#define RANDOM_LENGTH_MIN      1     /* Minimum allowed length */
#define RANDOM_LENGTH_MAX      1024  /* Maximum to prevent DoS */

/* Sentinel values (unset/not configured) */
#define RANDOM_LENGTH_UNSET    -1    /* Sentinel: length not configured */
#define RANDOM_ENABLED_UNSET   -1    /* Sentinel: boolean not configured */
#define RANDOM_FORMAT_UNSET    -1    /* Sentinel: format not configured */
#define RANDOM_GROUPING_UNSET  -1    /* Sentinel: grouping not configured */
#define RANDOM_EXPIRY_UNSET    -1    /* Sentinel: expiry not configured */
#define RANDOM_TTL_UNSET       -1    /* Sentinel: TTL not configured */

/* Limits to prevent DoS */
#define RANDOM_MAX_TOKENS          50      /* Maximum tokens per context */
#define RANDOM_TTL_MAX_SECONDS     86400   /* 24 hours */
#define RANDOM_EXPIRY_MAX_SECONDS  31536000 /* 1 year */
#define RANDOM_ALPHABET_MAX_SIZE   256     /* Maximum alphabet size */
#define RANDOM_ALPHABET_MIN_SIZE   2       /* Minimum alphabet size */
#define RANDOM_GROUPING_MAX        128     /* Maximum grouping size */

/* Output format types */
typedef enum {
    RANDOM_FORMAT_BASE64 = 0,
    RANDOM_FORMAT_HEX = 1,
    RANDOM_FORMAT_BASE64URL = 2,
    RANDOM_FORMAT_CUSTOM = 3
} random_format_t;

/* Individual token specification */
typedef struct random_token_spec {
    char *var_name;                    /* Environment variable name (required) */
    int length;                        /* Bytes of random data */
    random_format_t format;            /* Output format */
    char *header_name;                 /* Optional HTTP header */
    int include_timestamp;             /* Include timestamp prefix */
    char *prefix;                      /* Optional prefix */
    char *suffix;                      /* Optional suffix */
    int ttl_seconds;                   /* Cache TTL */
    char *cached_token;                /* Cached token value */
    apr_time_t cache_time;             /* Cache timestamp */
    apr_thread_mutex_t *cache_mutex;   /* Mutex to protect this token's cache */
    apr_pool_t *pool;                  /* Pool for cache allocation */
    struct random_token_spec *next;    /* Linked list next */
} random_token_spec;

/* Main configuration structure */
typedef struct {
    /* Default values for RandomAddToken */
    int length;                        /* Default token length in bytes */
    random_format_t format;            /* Default output format */
    int include_timestamp;             /* Default timestamp inclusion */
    char *prefix;                      /* Default prefix for all tokens */
    char *suffix;                      /* Default suffix for all tokens */
    int ttl_seconds;                   /* Default cache TTL */

    /* Global settings */
    ap_regex_t *url_pattern;           /* URL pattern filter (RandomOnlyFor) */
    apr_pool_t *pool;                  /* Pool for this config */
    random_token_spec *token_specs;    /* Linked list of token specifications */

    /* Custom alphabet settings (for RANDOM_FORMAT_CUSTOM) */
    char *custom_alphabet;             /* Custom character set */
    int alphabet_grouping;             /* Group size (0=no grouping) */

    /* Metadata encoding settings */
    int expiry_seconds;                /* Token expiration time (0=no expiry) */
    int encode_metadata;               /* Enable metadata encoding */
    char *signing_key;                 /* HMAC signing key for validation */
} random_config;

#endif /* MOD_RANDOM_TYPES_H */
