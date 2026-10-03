/*
 * mod_random_config.c - Configuration directives and handlers
 */

#include "mod_random.h"
#include "apr_strings.h"
#include "apr_thread_mutex.h"
#include "ap_regex.h"
#include <strings.h>
#include <string.h>

/* Helper function to copy a token spec to a new pool */
static random_token_spec *copy_token_spec(apr_pool_t *pool, random_token_spec *src)
{
    random_token_spec *new_spec = apr_pcalloc(pool, sizeof(random_token_spec));

    new_spec->var_name = src->var_name;
    new_spec->length = src->length;
    new_spec->format = src->format;
    new_spec->header_name = src->header_name;
    new_spec->include_timestamp = src->include_timestamp;
    new_spec->prefix = src->prefix;
    new_spec->suffix = src->suffix;
    new_spec->ttl_seconds = src->ttl_seconds;
    new_spec->cached_token = NULL;  /* Don't inherit cache */
    new_spec->cache_time = 0;
    new_spec->pool = pool;
    new_spec->next = NULL;

    /* Thread-safe cache requires mutex - verify creation succeeded */
    if (apr_thread_mutex_create(&new_spec->cache_mutex,
                                APR_THREAD_MUTEX_DEFAULT, pool) != APR_SUCCESS) {
        /* Mutex creation failed - disable caching for this token */
        new_spec->cache_mutex = NULL;
    }

    return new_spec;
}

/* Create per-directory configuration */
void *random_create_config(apr_pool_t *pool, char *dir)
{
    random_config *cfg = apr_pcalloc(pool, sizeof(random_config));

    /* Default values for RandomAddToken */
    cfg->length = RANDOM_LENGTH_UNSET;
    cfg->format = RANDOM_FORMAT_UNSET;
    cfg->include_timestamp = RANDOM_ENABLED_UNSET;
    cfg->prefix = NULL;
    cfg->suffix = NULL;
    cfg->ttl_seconds = RANDOM_TTL_UNSET;

    /* Global settings */
    cfg->url_pattern = NULL;
    cfg->pool = pool;
    cfg->token_specs = NULL;

    /* Custom alphabet settings */
    cfg->custom_alphabet = NULL;
    cfg->alphabet_grouping = RANDOM_GROUPING_UNSET;

    /* Metadata encoding settings */
    cfg->expiry_seconds = RANDOM_EXPIRY_UNSET;
    cfg->encode_metadata = RANDOM_ENABLED_UNSET;
    cfg->signing_key = NULL;

    return cfg;
}

/* Merge configurations (parent < child) */
void *random_merge_config(apr_pool_t *pool, void *base, void *override)
{
    random_config *parent = (random_config *)base;
    random_config *child = (random_config *)override;
    random_config *merged = apr_pcalloc(pool, sizeof(random_config));
    random_token_spec *spec, *new_spec, *last_spec = NULL;

    /* Child settings take precedence if explicitly set, otherwise inherit from parent */
    merged->length = (child->length != RANDOM_LENGTH_UNSET) ? child->length : parent->length;
    merged->format = (child->format != RANDOM_FORMAT_UNSET) ? child->format : parent->format;
    merged->include_timestamp = (child->include_timestamp != RANDOM_ENABLED_UNSET) ? child->include_timestamp : parent->include_timestamp;
    merged->prefix = child->prefix ? child->prefix : parent->prefix;
    merged->suffix = child->suffix ? child->suffix : parent->suffix;
    merged->ttl_seconds = (child->ttl_seconds != RANDOM_TTL_UNSET) ? child->ttl_seconds : parent->ttl_seconds;

    /* Global settings */
    merged->url_pattern = child->url_pattern ? child->url_pattern : parent->url_pattern;
    merged->pool = pool;

    /* Custom alphabet settings */
    merged->custom_alphabet = child->custom_alphabet ? child->custom_alphabet : parent->custom_alphabet;
    merged->alphabet_grouping = (child->alphabet_grouping != RANDOM_GROUPING_UNSET) ? child->alphabet_grouping : parent->alphabet_grouping;

    /* Metadata encoding settings */
    merged->expiry_seconds = (child->expiry_seconds != RANDOM_EXPIRY_UNSET) ? child->expiry_seconds : parent->expiry_seconds;
    merged->encode_metadata = (child->encode_metadata != RANDOM_ENABLED_UNSET) ? child->encode_metadata : parent->encode_metadata;
    merged->signing_key = child->signing_key ? child->signing_key : parent->signing_key;

    /* Merge token specs: inherit parent's tokens, then add child's tokens */
    merged->token_specs = NULL;
    int token_count = 0;

    /* Copy parent's token specs */
    for (spec = parent->token_specs; spec; spec = spec->next) {
        /* Enforce RANDOM_MAX_TOKENS limit to prevent DoS via config merge */
        if (token_count >= RANDOM_MAX_TOKENS) {
            break;  /* Silently skip excess tokens - logged at server startup */
        }

        new_spec = copy_token_spec(pool, spec);

        if (!merged->token_specs) {
            merged->token_specs = new_spec;
        } else {
            last_spec->next = new_spec;
        }
        last_spec = new_spec;
        token_count++;
    }

    /* Append child's token specs */
    for (spec = child->token_specs; spec; spec = spec->next) {
        /* Enforce RANDOM_MAX_TOKENS limit to prevent DoS via config merge */
        if (token_count >= RANDOM_MAX_TOKENS) {
            break;  /* Silently skip excess tokens - logged at server startup */
        }

        new_spec = copy_token_spec(pool, spec);

        if (!merged->token_specs) {
            merged->token_specs = new_spec;
        } else {
            last_spec->next = new_spec;
        }
        last_spec = new_spec;
        token_count++;
    }

    return merged;
}

/* Directive handlers */
static const char *set_random_length(cmd_parms *cmd, void *cfg, const char *arg)
{
    random_config *config = (random_config *)cfg;
    char *endptr;
    long length = strtol(arg, &endptr, 10);

    if (*endptr != '\0' || length < RANDOM_LENGTH_MIN || length > RANDOM_LENGTH_MAX) {
        return apr_psprintf(cmd->pool, "RandomLength must be between %d and %d",
                           RANDOM_LENGTH_MIN, RANDOM_LENGTH_MAX);
    }

    config->length = (int)length;
    return NULL;
}

static const char *set_random_format(cmd_parms *cmd, void *cfg, const char *arg)
{
    random_config *config = (random_config *)cfg;

    if (strcasecmp(arg, "base64") == 0) {
        config->format = RANDOM_FORMAT_BASE64;
    } else if (strcasecmp(arg, "hex") == 0) {
        config->format = RANDOM_FORMAT_HEX;
    } else if (strcasecmp(arg, "base64url") == 0) {
        config->format = RANDOM_FORMAT_BASE64URL;
    } else if (strcasecmp(arg, "custom") == 0) {
        config->format = RANDOM_FORMAT_CUSTOM;
    } else {
        return "RandomFormat must be one of: base64, hex, base64url, custom";
    }

    return NULL;
}

static const char *set_random_timestamp(cmd_parms *cmd, void *cfg, int flag)
{
    random_config *config = (random_config *)cfg;
    config->include_timestamp = flag;
    return NULL;
}

static const char *set_random_prefix(cmd_parms *cmd, void *cfg, const char *arg)
{
    random_config *config = (random_config *)cfg;
    config->prefix = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *set_random_suffix(cmd_parms *cmd, void *cfg, const char *arg)
{
    random_config *config = (random_config *)cfg;
    config->suffix = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *set_random_pattern(cmd_parms *cmd, void *cfg, const char *arg)
{
    random_config *config = (random_config *)cfg;
    config->url_pattern = ap_pregcomp(cmd->pool, arg, AP_REG_EXTENDED);

    if (!config->url_pattern) {
        return apr_psprintf(cmd->pool, "RandomOnlyFor: Invalid regex pattern '%s'", arg);
    }

    return NULL;
}

static const char *set_random_ttl(cmd_parms *cmd, void *cfg, const char *arg)
{
    random_config *config = (random_config *)cfg;
    char *endptr;
    long ttl = strtol(arg, &endptr, 10);

    if (*endptr != '\0' || ttl < 0 || ttl > RANDOM_TTL_MAX_SECONDS) {
        return apr_psprintf(cmd->pool, "RandomTTL must be between 0 and %d seconds (24 hours)", RANDOM_TTL_MAX_SECONDS);
    }

    config->ttl_seconds = (int)ttl;
    return NULL;
}

static const char *set_random_alphabet(cmd_parms *cmd, void *cfg, const char *arg)
{
    random_config *config = (random_config *)cfg;
    int len, i;
    unsigned char seen[256] = {0};

    if (!arg || !*arg) {
        return "RandomAlphabet: alphabet cannot be empty";
    }

    len = strlen(arg);
    if (len < RANDOM_ALPHABET_MIN_SIZE) {
        return apr_psprintf(cmd->pool, "RandomAlphabet: alphabet must contain at least %d characters", RANDOM_ALPHABET_MIN_SIZE);
    }

    if (len > RANDOM_ALPHABET_MAX_SIZE) {
        return apr_psprintf(cmd->pool, "RandomAlphabet: alphabet too long (max %d characters)", RANDOM_ALPHABET_MAX_SIZE);
    }

    /* Check for duplicate characters */
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)arg[i];
        if (seen[c]) {
            return apr_psprintf(cmd->pool,
                "RandomAlphabet: duplicate character '%c' at position %d", arg[i], i);
        }
        seen[c] = 1;
    }

    config->custom_alphabet = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *set_alphabet_grouping(cmd_parms *cmd, void *cfg, const char *arg)
{
    random_config *config = (random_config *)cfg;
    char *endptr;
    long grouping = strtol(arg, &endptr, 10);

    if (*endptr != '\0' || grouping < 0 || grouping > RANDOM_GROUPING_MAX) {
        return apr_psprintf(cmd->pool, "RandomAlphabetGrouping must be between 0 and %d (0 = no grouping)", RANDOM_GROUPING_MAX);
    }

    config->alphabet_grouping = (int)grouping;
    return NULL;
}

static const char *set_random_expiry(cmd_parms *cmd, void *cfg, const char *arg)
{
    random_config *config = (random_config *)cfg;
    char *endptr;
    long expiry = strtol(arg, &endptr, 10);

    if (*endptr != '\0' || expiry < 0 || expiry > RANDOM_EXPIRY_MAX_SECONDS) {
        return apr_psprintf(cmd->pool, "RandomExpiry must be between 0 and %d seconds (1 year)", RANDOM_EXPIRY_MAX_SECONDS);
    }

    config->expiry_seconds = (int)expiry;
    return NULL;
}

static const char *set_encode_metadata(cmd_parms *cmd, void *cfg, int flag)
{
    random_config *config = (random_config *)cfg;
    config->encode_metadata = flag;
    return NULL;
}

static const char *set_signing_key(cmd_parms *cmd, void *cfg, const char *arg)
{
    random_config *config = (random_config *)cfg;

    if (!arg || !*arg) {
        return "RandomSigningKey: key cannot be empty";
    }

    config->signing_key = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *add_random_token(cmd_parms *cmd, void *cfg, const char *args)
{
    random_config *config = (random_config *)cfg;
    random_token_spec *spec, *last_spec;
    char *token, *key, *value, *args_copy, *var_name;
    char *endptr;
    long num_val;
    int token_count = 0;

    if (!args || !*args) {
        return "RandomAddToken: variable name is required";
    }

    /* Count existing tokens to enforce limit */
    for (spec = config->token_specs; spec; spec = spec->next) {
        token_count++;
    }

    if (token_count >= RANDOM_MAX_TOKENS) {
        return apr_psprintf(cmd->pool,
            "RandomAddToken: maximum number of tokens (%d) exceeded", RANDOM_MAX_TOKENS);
    }

    /* Parse arguments: first token is variable name, rest are key=value pairs */
    args_copy = apr_pstrdup(cmd->pool, args);
    var_name = apr_strtok(args_copy, " \t", &args_copy);

    if (!var_name || !*var_name) {
        return "RandomAddToken: variable name is required";
    }

    /* Create new token spec with defaults */
    spec = apr_pcalloc(cmd->pool, sizeof(random_token_spec));
    spec->var_name = apr_pstrdup(cmd->pool, var_name);
    spec->length = RANDOM_LENGTH_UNSET;
    spec->format = RANDOM_FORMAT_UNSET;
    spec->header_name = NULL;
    spec->include_timestamp = RANDOM_ENABLED_UNSET;
    spec->prefix = NULL;
    spec->suffix = NULL;
    spec->ttl_seconds = RANDOM_TTL_UNSET;
    spec->cached_token = NULL;
    spec->cache_time = 0;
    spec->pool = cmd->pool;
    spec->next = NULL;

    /* Create mutex for this token's cache protection (thread-safe) */
    if (apr_thread_mutex_create(&spec->cache_mutex, APR_THREAD_MUTEX_DEFAULT, cmd->pool) != APR_SUCCESS) {
            /* Mutex creation failed - disable caching for this token */
            spec->cache_mutex = NULL;
        }

    /* Parse optional key=value arguments */
    token = apr_strtok(NULL, " \t", &args_copy);
    while (token) {
        key = token;
        value = strchr(token, '=');
        if (!value) {
            return apr_psprintf(cmd->pool, "RandomAddToken: invalid argument '%s' (expected key=value)", token);
        }
        *value++ = '\0';

        if (strcasecmp(key, "length") == 0) {
            num_val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || num_val < RANDOM_LENGTH_MIN || num_val > RANDOM_LENGTH_MAX) {
                return apr_psprintf(cmd->pool, "RandomAddToken: invalid length %ld (must be %d-%d)",
                                    num_val, RANDOM_LENGTH_MIN, RANDOM_LENGTH_MAX);
            }
            spec->length = (int)num_val;
        } else if (strcasecmp(key, "format") == 0) {
            if (strcasecmp(value, "base64") == 0) {
                spec->format = RANDOM_FORMAT_BASE64;
            } else if (strcasecmp(value, "hex") == 0) {
                spec->format = RANDOM_FORMAT_HEX;
            } else if (strcasecmp(value, "base64url") == 0) {
                spec->format = RANDOM_FORMAT_BASE64URL;
            } else if (strcasecmp(value, "custom") == 0) {
                spec->format = RANDOM_FORMAT_CUSTOM;
            } else {
                return apr_psprintf(cmd->pool, "RandomAddToken: invalid format '%s' (must be base64, hex, base64url, or custom)", value);
            }
        } else if (strcasecmp(key, "header") == 0) {
            spec->header_name = apr_pstrdup(cmd->pool, value);
        } else if (strcasecmp(key, "timestamp") == 0) {
            if (strcasecmp(value, "on") == 0 || strcasecmp(value, "1") == 0) {
                spec->include_timestamp = 1;
            } else if (strcasecmp(value, "off") == 0 || strcasecmp(value, "0") == 0) {
                spec->include_timestamp = 0;
            } else {
                return apr_psprintf(cmd->pool, "RandomAddToken: invalid timestamp value '%s' (must be on/off)", value);
            }
        } else if (strcasecmp(key, "prefix") == 0) {
            spec->prefix = apr_pstrdup(cmd->pool, value);
        } else if (strcasecmp(key, "suffix") == 0) {
            spec->suffix = apr_pstrdup(cmd->pool, value);
        } else if (strcasecmp(key, "ttl") == 0) {
            num_val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || num_val < 0 || num_val > RANDOM_TTL_MAX_SECONDS) {
                return apr_psprintf(cmd->pool, "RandomAddToken: invalid ttl %ld (must be 0-%d)",
                                   num_val, RANDOM_TTL_MAX_SECONDS);
            }
            spec->ttl_seconds = (int)num_val;
        } else {
            return apr_psprintf(cmd->pool, "RandomAddToken: unknown parameter '%s'", key);
        }

        token = apr_strtok(NULL, " \t", &args_copy);
    }

    /* Add to end of linked list */
    if (!config->token_specs) {
        config->token_specs = spec;
    } else {
        last_spec = config->token_specs;
        while (last_spec->next) {
            last_spec = last_spec->next;
        }
        last_spec->next = spec;
    }

    return NULL;
}

/* Configuration directives table */
const command_rec random_directives[] = {
    AP_INIT_TAKE1("RandomLength", set_random_length, NULL, OR_ALL,
                  "Default token length in bytes for RandomAddToken (default: 16)"),
    AP_INIT_TAKE1("RandomFormat", set_random_format, NULL, OR_ALL,
                  "Default output format for RandomAddToken: base64, hex, base64url, custom (default: base64)"),
    AP_INIT_FLAG("RandomIncludeTimestamp", set_random_timestamp, NULL, OR_ALL,
                 "Default timestamp inclusion for RandomAddToken (default: Off)"),
    AP_INIT_TAKE1("RandomPrefix", set_random_prefix, NULL, OR_ALL,
                  "Default prefix for all tokens (optional)"),
    AP_INIT_TAKE1("RandomSuffix", set_random_suffix, NULL, OR_ALL,
                  "Default suffix for all tokens (optional)"),
    AP_INIT_TAKE1("RandomOnlyFor", set_random_pattern, NULL, OR_ALL,
                  "Regex pattern to match URLs for conditional token generation (optional)"),
    AP_INIT_TAKE1("RandomTTL", set_random_ttl, NULL, OR_ALL,
                  "Default cache TTL for RandomAddToken in seconds (0-86400, default: 0 = no cache)"),
    AP_INIT_TAKE1("RandomAlphabet", set_random_alphabet, NULL, OR_ALL,
                  "Set custom character set for 'custom' format (e.g., '0123456789ABCDEFGHJKMNPQRSTVWXYZ')"),
    AP_INIT_TAKE1("RandomAlphabetGrouping", set_alphabet_grouping, NULL, OR_ALL,
                  "Group custom alphabet output every N characters with '-' (0 = no grouping)"),
    AP_INIT_TAKE1("RandomExpiry", set_random_expiry, NULL, OR_ALL,
                  "Set token expiration time in seconds (0-31536000, requires RandomEncodeMetadata On)"),
    AP_INIT_FLAG("RandomEncodeMetadata", set_encode_metadata, NULL, OR_ALL,
                 "Encode expiry metadata into token (requires RandomExpiry > 0)"),
    AP_INIT_TAKE1("RandomSigningKey", set_signing_key, NULL, OR_ALL,
                  "Set HMAC-SHA256 signing key for token validation (optional, for metadata mode)"),
    AP_INIT_RAW_ARGS("RandomAddToken", add_random_token, NULL, OR_ALL,
                     "Add a token with custom configuration: RandomAddToken VAR_NAME [key=value ...]"),
    {NULL}
};
