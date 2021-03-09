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
#include "apr_sha1.h"
#include "apr_base64.h"
#include "apr_buckets.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"   /* For index_of_response().  Grump. */
#include "http_request.h"

#if APR_HAS_MMAP
#include "apr_mmap.h"
#endif /* APR_HAS_MMAP */

#define SHA1_DIGEST_BASE64_LEN 4*(APR_SHA1_DIGESTSIZE/3)

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

static void etag_start(char *etag, const char *weak, char **next)
{
    if (weak) {
        while (*weak) {
            *etag++ = *weak++;
        }
    }
    *etag++ = '"';

    *next = etag;
}

static void etag_end(char *next, const char *vlv, apr_size_t vlv_len)
{
    if (vlv) {
        *next++ = ';';
        apr_cpystrn(next, vlv, vlv_len);
    }
    else {
        *next++ = '"';
        *next = '\0';
    }
}

/*
 * Construct a strong ETag by creating a SHA1 hash across the file content.
 */
static char *make_digest_etag(request_rec *r, etag_rec *er, char *vlv,
        apr_size_t vlv_len, char *weak, apr_size_t weak_len)
{
    apr_sha1_ctx_t context;
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    apr_file_t *fd = NULL;
    core_dir_config *cfg;
    char *etag, *next;
    apr_bucket_brigade *bb;
    apr_bucket *e;

    apr_size_t nbytes;
    apr_off_t offset = 0, zero = 0, len = 0;
    apr_status_t status;

    cfg = (core_dir_config *)ap_get_core_module_config(r->per_dir_config);

    if (er->fd) {
        fd = er->fd;
    }
    else if (er->pathname) {
        if ((status = apr_file_open(&fd, er->pathname, APR_READ | APR_BINARY,
                0, r->pool)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(10251)
                          "Make etag: could not open %s", er->pathname);
            return "";
        }
    }
    if (!fd) {
        return "";
    }

    if ((status = apr_file_seek(fd, APR_CUR, &offset)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(10252)
                      "Make etag: could not seek");
        if (er->pathname) {
            apr_file_close(fd);
        }
        return "";
    }

    if ((status = apr_file_seek(fd, APR_END, &len)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(10258)
                      "Make etag: could not seek");
        if (er->pathname) {
            apr_file_close(fd);
        }
        return "";
    }

    if ((status = apr_file_seek(fd, APR_SET, &zero)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(10253)
                      "Make etag: could not seek");
        if (er->pathname) {
            apr_file_close(fd);
        }
        return "";
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    e = apr_brigade_insert_file(bb, fd, 0, len, r->pool);

#if APR_HAS_MMAP
    if (cfg->enable_mmap == ENABLE_MMAP_OFF) {
        (void)apr_bucket_file_enable_mmap(e, 0);
    }
#endif

    apr_sha1_init(&context);
    while (!APR_BRIGADE_EMPTY(bb))
    {
        const char *str;

        e = APR_BRIGADE_FIRST(bb);

        if ((status = apr_bucket_read(e, &str, &nbytes, APR_BLOCK_READ)) != APR_SUCCESS) {
        	apr_brigade_destroy(bb);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(10254)
                          "Make etag: could not read");
            if (er->pathname) {
                apr_file_close(fd);
            }
            return "";
        }

        apr_sha1_update(&context, str, nbytes);
        apr_bucket_delete(e);
    }

    if ((status = apr_file_seek(fd, APR_SET, &offset)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(10255)
                      "Make etag: could not seek");
        if (er->pathname) {
            apr_file_close(fd);
        }
        return "";
    }
    apr_sha1_final(digest, &context);

    etag = apr_palloc(r->pool, weak_len + sizeof("\"\"") +
            SHA1_DIGEST_BASE64_LEN + vlv_len + 4);

    etag_start(etag, weak, &next);
    next += apr_base64_encode_binary(next, digest, APR_SHA1_DIGESTSIZE) - 1;
    etag_end(next, vlv, vlv_len);

    if (er->pathname) {
        apr_file_close(fd);
    }

    return etag;
}

/*
 * Construct an entity tag (ETag) from resource information.  If it's a real
 * file, build in some of the file characteristics.  If the modification time
 * is newer than (request-time minus 1 second), mark the ETag as weak - it
 * could be modified again in as short an interval.
 */
AP_DECLARE(char *) ap_make_etag_ex(request_rec *r, etag_rec *er)
{
    char *weak = NULL;
    apr_size_t weak_len = 0, vlv_len = 0;
    char *etag, *next, *vlv;
    core_dir_config *cfg;
    etag_components_t etag_bits;
    etag_components_t bits_added;

    cfg = (core_dir_config *)ap_get_core_module_config(r->per_dir_config);
    etag_bits = (cfg->etag_bits & (~ cfg->etag_remove)) | cfg->etag_add;

    if (er->force_weak) {
        weak = ETAG_WEAK;
        weak_len = sizeof(ETAG_WEAK);
    }

    if (r->vlist_validator) {

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
        if (vlv[0] == 'W') {
            vlv += 3;
            weak = ETAG_WEAK;
            weak_len = sizeof(ETAG_WEAK);
        }
        else {
            vlv++;
        }
        vlv_len = strlen(vlv);

    }
    else {
        vlv = NULL;
        vlv_len = 0;
    }

    /*
     * Did a module flag the need for a strong etag, or did the
     * configuration tell us to generate a digest?
     */
    if (er->finfo->filetype == APR_REG &&
            (AP_REQUEST_IS_STRONG_ETAG(r) || (etag_bits & ETAG_DIGEST))) {

        return make_digest_etag(r, er, vlv, vlv_len, weak, weak_len);
    }

    /*
     * If it's a file (or we wouldn't be here) and no ETags
     * should be set for files, return an empty string and
     * note it for the header-sender to ignore.
     */
    if (etag_bits & ETAG_NONE) {
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
    if ((er->request_time - er->finfo->mtime < (1 * APR_USEC_PER_SEC))) {
        weak = ETAG_WEAK;
        weak_len = sizeof(ETAG_WEAK);
    }

    if (er->finfo->filetype != APR_NOFILE) {
        /*
         * ETag gets set to [W/]"inode-size-mtime", modulo any
         * FileETag keywords.
         */
        etag = apr_palloc(r->pool, weak_len + sizeof("\"--\"") +
                          3 * CHARS_PER_UINT64 + vlv_len + 2);

        etag_start(etag, weak, &next);

        bits_added = 0;
        if (etag_bits & ETAG_INODE) {
            next = etag_uint64_to_hex(next, er->finfo->inode);
            bits_added |= ETAG_INODE;
        }
        if (etag_bits & ETAG_SIZE) {
            if (bits_added != 0) {
                *next++ = '-';
            }
            next = etag_uint64_to_hex(next, er->finfo->size);
            bits_added |= ETAG_SIZE;
        }
        if (etag_bits & ETAG_MTIME) {
            if (bits_added != 0) {
                *next++ = '-';
            }
            next = etag_uint64_to_hex(next, er->finfo->mtime);
        }

        etag_end(next, vlv, vlv_len);

    }
    else {
        /*
         * Not a file document, so just use the mtime: [W/]"mtime"
         */
        etag = apr_palloc(r->pool, weak_len + sizeof("\"\"") +
                          CHARS_PER_UINT64 + vlv_len + 2);

        etag_start(etag, weak, &next);
        next = etag_uint64_to_hex(next, er->finfo->mtime);
        etag_end(next, vlv, vlv_len);

    }

    return etag;
}

AP_DECLARE(char *) ap_make_etag(request_rec *r, int force_weak)
{
    etag_rec er;

    er.vlist_validator = NULL;
    er.request_time = r->request_time;
    er.finfo = &r->finfo;
    er.pathname = r->filename;
    er.fd = NULL;
    er.force_weak = force_weak;

    return ap_make_etag_ex(r, &er);
}

AP_DECLARE(void) ap_set_etag(request_rec *r)
{
    char *etag;

    etag_rec er;

    er.vlist_validator = r->vlist_validator;
    er.request_time = r->request_time;
    er.finfo = &r->finfo;
    er.pathname = r->filename;
    er.fd = NULL;
    er.force_weak = 0;

    etag = ap_make_etag_ex(r, &er);

    if (etag && etag[0]) {
        apr_table_setn(r->headers_out, "ETag", etag);
    }
    else {
        apr_table_setn(r->notes, "no-etag", "omit");
    }

}

AP_DECLARE(void) ap_set_etag_fd(request_rec *r, apr_file_t *fd)
{
    char *etag;

    etag_rec er;

    er.vlist_validator = r->vlist_validator;
    er.request_time = r->request_time;
    er.finfo = &r->finfo;
    er.pathname = NULL;
    er.fd = fd;
    er.force_weak = 0;

    etag = ap_make_etag_ex(r, &er);

    if (etag && etag[0]) {
        apr_table_setn(r->headers_out, "ETag", etag);
    }
    else {
        apr_table_setn(r->notes, "no-etag", "omit");
    }

}
