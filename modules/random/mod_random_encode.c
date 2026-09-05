/*
 * mod_random_encode.c - Encoding functions (hex, base64, base64url, custom alphabet)
 */

#include "mod_random.h"
#include "apr_base64.h"
#include "apr_strings.h"
#include <string.h>

/* Encode binary data to hexadecimal string */
char *random_encode_hex(apr_pool_t *pool, const unsigned char *data, int length)
{
    static const char hex_chars[] = "0123456789abcdef";
    char *hex_string;
    int i;

    hex_string = apr_palloc(pool, length * 2 + 1);
    for (i = 0; i < length; i++) {
        hex_string[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        hex_string[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    hex_string[length * 2] = '\0';

    return hex_string;
}

/* Encode to base64url (URL-safe base64 without padding) */
char *random_encode_base64url(apr_pool_t *pool, const char *data, int length)
{
    char *base64_string;
    char *p;
    int encoded_len;

    encoded_len = apr_base64_encode_len(length);
    base64_string = apr_palloc(pool, encoded_len);
    apr_base64_encode(base64_string, data, length);

    /* Convert to base64url: replace + with -, / with _, remove = padding */
    for (p = base64_string; *p; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') {
            *p = '\0';
            break;
        }
    }

    return base64_string;
}

/* Encode using custom alphabet with optional grouping */
char *random_encode_custom_alphabet(apr_pool_t *pool, const unsigned char *data, int length,
                                    const char *alphabet, int grouping)
{
    int alphabet_len, max_output_len, i, pos;
    char *result, *p, *end;
    unsigned long long value;  /* Use 64-bit to prevent overflow */
    int bits_available, bits_needed;

    if (!alphabet || !*alphabet) {
        /* Fallback to hex if no alphabet */
        return random_encode_hex(pool, data, length);
    }

    alphabet_len = strlen(alphabet);
    if (alphabet_len < 2) {
        return random_encode_hex(pool, data, length);
    }

    /* Calculate bits per character based on alphabet size */
    bits_needed = 0;
    while ((1 << bits_needed) < alphabet_len) {
        bits_needed++;
    }

    /* Allocate maximum possible output length to prevent overflow */
    /* Worst case: (bytes * 8 / bits_per_char) + grouping separators + flush + null */
    max_output_len = ((length * 8) / bits_needed) + (length * 2) + 10;
    if (grouping > 0) {
        max_output_len += (max_output_len / grouping) + 10;
    }
    result = apr_palloc(pool, max_output_len);
    p = result;
    end = result + max_output_len - 1;  /* Reserve space for null terminator */

    /* Encode bytes using custom alphabet */
    value = 0;
    bits_available = 0;
    pos = 0;

    for (i = 0; i < length; i++) {
        value = (value << 8) | data[i];
        bits_available += 8;

        while (bits_available >= bits_needed) {
            unsigned int index;

            /* Ensure we don't overflow buffer */
            if (p >= end - 2) {  /* Reserve space for separator and null */
                *p = '\0';
                return result;
            }

            bits_available -= bits_needed;
            index = (value >> bits_available) & ((1 << bits_needed) - 1);

            if (index < (unsigned int)alphabet_len) {
                *p++ = alphabet[index];
                pos++;

                /* Add grouping separator if needed */
                if (grouping > 0 && pos % grouping == 0 && i < length - 1 && p < end - 1) {
                    *p++ = '-';
                }
            }
        }
    }

    /* Flush remaining bits if any */
    if (bits_available > 0 && p < end) {
        unsigned int index = (value << (bits_needed - bits_available)) & ((1 << bits_needed) - 1);
        if (index < (unsigned int)alphabet_len) {
            *p++ = alphabet[index];
        }
    }

    *p = '\0';
    return result;
}

/* Generate random string with specified format (extended version) */
char *random_generate_string_ex(apr_pool_t *pool, int length, random_format_t format,
                                const char *alphabet, int grouping)
{
    unsigned char *random_bytes;
    char *result;
    int encoded_len;
    apr_status_t rv;

    random_bytes = apr_palloc(pool, length);

    /* CRITICAL: Verify CSPRNG succeeded - security depends on this */
    rv = apr_generate_random_bytes(random_bytes, length);
    if (rv != APR_SUCCESS) {
        /* CSPRNG failed - this is a critical system error
         * Return NULL to signal failure - caller must handle this */
        return NULL;
    }

    switch (format) {
        case RANDOM_FORMAT_HEX:
            result = random_encode_hex(pool, random_bytes, length);
            break;

        case RANDOM_FORMAT_BASE64URL:
            result = random_encode_base64url(pool, (char *)random_bytes, length);
            break;

        case RANDOM_FORMAT_CUSTOM:
            result = random_encode_custom_alphabet(pool, random_bytes, length, alphabet, grouping);
            break;

        case RANDOM_FORMAT_BASE64:
        default:
            encoded_len = apr_base64_encode_len(length);
            result = apr_palloc(pool, encoded_len);
            apr_base64_encode(result, (char *)random_bytes, length);
            break;
    }

    return result;
}

/* Generate random string with specified format (simple version) */
char *random_generate_string(apr_pool_t *pool, int length, random_format_t format)
{
    return random_generate_string_ex(pool, length, format, NULL, 0);
}
