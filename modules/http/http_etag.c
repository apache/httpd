/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_strings.h"
#include "apr_thread_proc.h"    /* for RLIMIT stuff */

#define APR_WANT_STRFUNC
#include "apr_want.h"

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_protocol.h"   /* For index_of_response().  Grump. */
#include "http_request.h"

/* Generate the human-readable hex representation of an apr_uint64_t
 * (basically a faster version of 'sprintf("%llx")')
 */
#define HEX_DIGITS "0123456789abcdef"
static char *etag_uint64_to_hex(char *next, apr_uint64_t u)
{
    int printing = 0;
    int shift = sizeof(apr_uint64_t) * 8 - 4;
    do {
        unsigned short next_digit = (unsigned short)
                                    ((u >> shift) & (apr_uint64_t)0xf);
        if (next_digit) {
            *next++ = HEX_DIGITS[next_digit];
            printing = 1;
        }
        else if (printing) {
            *next++ = HEX_DIGITS[next_digit];
        }
        shift -= 4;
    } while (shift);
    *next++ = HEX_DIGITS[u & (apr_uint64_t)0xf];
    return next;
}

#define ETAG_WEAK "W/"
#define CHARS_PER_UINT64 (sizeof(apr_uint64_t) * 2)
/*
 * Construct an entity tag (ETag) from resource information.  If it's a real
 * file, build in some of the file characteristics.  If the modification time
 * is newer than (request-time minus 1 second), mark the ETag as weak - it
 * could be modified again in as short an interval.  We rationalize the
 * modification time we're given to keep it from being in the future.
 */
AP_DECLARE(char *) ap_make_etag(request_rec *r, int force_weak)
{
    char *weak;
    apr_size_t weak_len;
    char *etag;
    char *next;
    core_dir_config *cfg;
    etag_components_t etag_bits;
    etag_components_t bits_added;

    cfg = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                  &core_module);
    etag_bits = (cfg->etag_bits & (~ cfg->etag_remove)) | cfg->etag_add;

    /*
     * If it's a file (or we wouldn't be here) and no ETags
     * should be set for files, return an empty string and
     * note it for the header-sender to ignore.
     */
    if (etag_bits & ETAG_NONE) {
        apr_table_setn(r->notes, "no-etag", "omit");
        return "";
    }

    if (etag_bits == ETAG_UNSET) {
        etag_bits = ETAG_BACKWARD;
    }
    /*
     * Make an ETag header out of various pieces of information. We use
     * the last-modified date and, if we have a real file, the
     * length and inode number - note that this doesn't have to match
     * the content-length (i.e. includes), it just has to be unique
     * for the file.
     *
     * If the request was made within a second of the last-modified date,
     * we send a weak tag instead of a strong one, since it could
     * be modified again later in the second, and the validation
     * would be incorrect.
     */
    if ((r->request_time - r->mtime > (1 * APR_USEC_PER_SEC)) &&
        !force_weak) {
        weak = NULL;
        weak_len = 0;
    }
    else {
        weak = ETAG_WEAK;
        weak_len = sizeof(ETAG_WEAK);
    }

    if (r->finfo.filetype != 0) {
        /*
         * ETag gets set to [W/]"inode-size-mtime", modulo any
         * FileETag keywords.
         */
        etag = apr_palloc(r->pool, weak_len + sizeof("\"--\"") +
                          3 * CHARS_PER_UINT64 + 1);
        next = etag;
        if (weak) {
            while (*weak) {
                *next++ = *weak++;
            }
        }
        *next++ = '"';
        bits_added = 0;
        if (etag_bits & ETAG_INODE) {
            next = etag_uint64_to_hex(next, r->finfo.inode);
            bits_added |= ETAG_INODE;
        }
        if (etag_bits & ETAG_SIZE) {
            if (bits_added != 0) {
                *next++ = '-';
            }
            next = etag_uint64_to_hex(next, r->finfo.size);
            bits_added |= ETAG_SIZE;
        }
        if (etag_bits & ETAG_MTIME) {
            if (bits_added != 0) {
                *next++ = '-';
            }
            next = etag_uint64_to_hex(next, r->mtime);
        }
        *next++ = '"';
        *next = '\0';
    }
    else {
        /*
         * Not a file document, so just use the mtime: [W/]"mtime"
         */
        etag = apr_palloc(r->pool, weak_len + sizeof("\"\"") +
                          CHARS_PER_UINT64 + 1);
        next = etag;
        if (weak) {
            while (*weak) {
                *next++ = *weak++;
            }
        }
        *next++ = '"';
        next = etag_uint64_to_hex(next, r->mtime);
        *next++ = '"';
        *next = '\0';
    }

    return etag;
}

AP_DECLARE(void) ap_set_etag(request_rec *r)
{
    char *etag;
    char *variant_etag, *vlv;
    int vlv_weak;

    if (!r->vlist_validator) {
        etag = ap_make_etag(r, 0);

        /* If we get a blank etag back, don't set the header. */
        if (!etag[0]) {
            return;
        }
    }
    else {
        /* If we have a variant list validator (vlv) due to the
         * response being negotiated, then we create a structured
         * entity tag which merges the variant etag with the variant
         * list validator (vlv).  This merging makes revalidation
         * somewhat safer, ensures that caches which can deal with
         * Vary will (eventually) be updated if the set of variants is
         * changed, and is also a protocol requirement for transparent
         * content negotiation.
         */

        /* if the variant list validator is weak, we make the whole
         * structured etag weak.  If we would not, then clients could
         * have problems merging range responses if we have different
         * variants with the same non-globally-unique strong etag.
         */

        vlv = r->vlist_validator;
        vlv_weak = (vlv[0] == 'W');

        variant_etag = ap_make_etag(r, vlv_weak);

        /* If we get a blank etag back, don't append vlv and stop now. */
        if (!variant_etag[0]) {
            return;
        }

        /* merge variant_etag and vlv into a structured etag */
        variant_etag[strlen(variant_etag) - 1] = '\0';
        if (vlv_weak) {
            vlv += 3;
        }
        else {
            vlv++;
        }
        etag = apr_pstrcat(r->pool, variant_etag, ";", vlv, NULL);
    }

    apr_table_setn(r->headers_out, "ETag", etag);
}
