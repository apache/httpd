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
#include <assert.h>
#include <apr_lib.h>
#include <apr_file_info.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include <rustls.h>

#include "tls_proto.h"
#include "tls_util.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);


tls_data_t tls_data_from_str(const char *s)
{
    tls_data_t d;
    d.data = (const unsigned char*)s;
    d.len = s? strlen(s) : 0;
    return d;
}

tls_data_t tls_data_assign_copy(apr_pool_t *p, const tls_data_t *d)
{
    tls_data_t copy;
    copy.data = apr_pmemdup(p, d->data, d->len);
    copy.len = d->len;
    return copy;
}

tls_data_t *tls_data_copy(apr_pool_t *p, const tls_data_t *d)
{
    tls_data_t *copy;
    copy = apr_pcalloc(p, sizeof(*copy));
    *copy = tls_data_assign_copy(p, d);
    return copy;
}

const char *tls_data_to_str(apr_pool_t *p, const tls_data_t *d)
{
    char *s = apr_pcalloc(p, d->len+1);
    memcpy(s, d->data, d->len);
    return s;
}

apr_status_t tls_util_rustls_error(
    apr_pool_t *p, rustls_result rr, const char **perr_descr)
{
    if (perr_descr) {
        char buffer[HUGE_STRING_LEN];
        apr_size_t len = 0;

        rustls_error(rr, buffer, sizeof(buffer), &len);
        *perr_descr = apr_pstrndup(p, buffer, len);
    }
    return APR_EGENERAL;
}

int tls_util_is_file(
    apr_pool_t *p, const char *fpath)
{
    apr_finfo_t finfo;

    return (fpath != NULL
        && apr_stat(&finfo, fpath, APR_FINFO_TYPE|APR_FINFO_SIZE, p) == 0
        && finfo.filetype == APR_REG);
}

apr_status_t tls_util_file_load(
    apr_pool_t *p, const char *fpath, apr_size_t min_len, apr_size_t max_len, tls_data_t *data)
{
    apr_finfo_t finfo;
    apr_status_t rv;
    apr_file_t *f = NULL;
    unsigned char *buffer;
    apr_size_t len;
    const char *err = NULL;
    tls_data_t *d;

    rv = apr_stat(&finfo, fpath, APR_FINFO_TYPE|APR_FINFO_SIZE, p);
    if (APR_SUCCESS != rv) {
        err = "cannot stat"; goto cleanup;
    }
    if (finfo.filetype != APR_REG) {
        err = "not a plain file";
        rv = APR_EINVAL; goto cleanup;
    }
    if (finfo.size > LONG_MAX) {
        err = "file is too large";
        rv = APR_EINVAL; goto cleanup;
    }
    len = (apr_size_t)finfo.size;
    if (len < min_len || len > max_len) {
        err = "file size not in allowed range";
        rv = APR_EINVAL; goto cleanup;
    }
    d = apr_pcalloc(p, sizeof(*d));
    buffer = apr_pcalloc(p, len+1); /* keep it NUL terminated in any case */
    rv = apr_file_open(&f, fpath, APR_FOPEN_READ, 0, p);
    if (APR_SUCCESS != rv) {
        err = "error opening"; goto cleanup;
    }
    rv = apr_file_read(f, buffer, &len);
    if (APR_SUCCESS != rv) {
        err = "error reading"; goto cleanup;
    }
cleanup:
    if (f) apr_file_close(f);
    if (APR_SUCCESS == rv) {
        data->data = buffer;
        data->len = len;
    }
    else {
        memset(data, 0, sizeof(*data));
        ap_log_perror(APLOG_MARK, APLOG_ERR, rv, p, APLOGNO(10361)
                      "Failed to load file %s: %s", fpath, err? err: "-");
    }
    return rv;
}

int tls_util_array_uint16_contains(const apr_array_header_t* a, apr_uint16_t n)
{
    int i;
    for (i = 0; i < a->nelts; ++i) {
        if (APR_ARRAY_IDX(a, i, apr_uint16_t) == n) return 1;
    }
    return 0;
}

const apr_array_header_t *tls_util_array_uint16_remove(
    apr_pool_t *pool, const apr_array_header_t* from, const apr_array_header_t* others)
{
    apr_array_header_t *na = NULL;
    apr_uint16_t id;
    int i, j;

    for (i = 0; i < from->nelts; ++i) {
        id = APR_ARRAY_IDX(from, i, apr_uint16_t);
        if (tls_util_array_uint16_contains(others, id)) {
            if (na == NULL) {
                /* first removal, make a new result array, copy elements before */
                na = apr_array_make(pool, from->nelts, sizeof(apr_uint16_t));
                for (j = 0; j < i; ++j) {
                    APR_ARRAY_PUSH(na, apr_uint16_t) = APR_ARRAY_IDX(from, j, apr_uint16_t);
                }
            }
        }
        else if (na) {
            APR_ARRAY_PUSH(na, apr_uint16_t) = id;
        }
    }
    return na? na : from;
}

apr_status_t tls_util_brigade_transfer(
    apr_bucket_brigade *dest, apr_bucket_brigade *src, apr_off_t length,
    apr_off_t *pnout)
{
    apr_bucket *b;
    apr_off_t remain = length;
    apr_status_t rv = APR_SUCCESS;
    const char *ign;
    apr_size_t ilen;

    *pnout = 0;
    while (!APR_BRIGADE_EMPTY(src)) {
        b = APR_BRIGADE_FIRST(src);

        if (APR_BUCKET_IS_METADATA(b)) {
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(dest, b);
        }
        else {
            if (remain == (apr_off_t)b->length) {
                /* fall through */
            }
            else if (remain <= 0) {
                goto cleanup;
            }
            else {
                if (b->length == ((apr_size_t)-1)) {
                    rv= apr_bucket_read(b, &ign, &ilen, APR_BLOCK_READ);
                    if (APR_SUCCESS != rv) goto cleanup;
                }
                if (remain < (apr_off_t)b->length) {
                    apr_bucket_split(b, (apr_size_t)remain);
                }
            }
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(dest, b);
            remain -= (apr_off_t)b->length;
            *pnout += (apr_off_t)b->length;
        }
    }
cleanup:
    return rv;
}

apr_status_t tls_util_brigade_copy(
    apr_bucket_brigade *dest, apr_bucket_brigade *src, apr_off_t length,
    apr_off_t *pnout)
{
    apr_bucket *b, *next;
    apr_off_t remain = length;
    apr_status_t rv = APR_SUCCESS;
    const char *ign;
    apr_size_t ilen;

    *pnout = 0;
    for (b = APR_BRIGADE_FIRST(src);
         b != APR_BRIGADE_SENTINEL(src);
         b = next) {
        next = APR_BUCKET_NEXT(b);

        if (APR_BUCKET_IS_METADATA(b)) {
            /* fall through */
        }
        else {
            if (remain == (apr_off_t)b->length) {
                /* fall through */
            }
            else if (remain <= 0) {
                goto cleanup;
            }
            else {
                if (b->length == ((apr_size_t)-1)) {
                    rv = apr_bucket_read(b, &ign, &ilen, APR_BLOCK_READ);
                    if (APR_SUCCESS != rv) goto cleanup;
                }
                if (remain < (apr_off_t)b->length) {
                    apr_bucket_split(b, (apr_size_t)remain);
                }
            }
        }
        rv = apr_bucket_copy(b, &b);
        if (APR_SUCCESS != rv) goto cleanup;
        APR_BRIGADE_INSERT_TAIL(dest, b);
        remain -= (apr_off_t)b->length;
        *pnout += (apr_off_t)b->length;
    }
cleanup:
    return rv;
}

apr_status_t tls_util_brigade_split_line(
    apr_bucket_brigade *dest, apr_bucket_brigade *src,
    apr_read_type_e block, apr_off_t length,
    apr_off_t *pnout)
{
    apr_off_t nstart, nend;
    apr_status_t rv;

    apr_brigade_length(dest, 0, &nstart);
    rv = apr_brigade_split_line(dest, src, block, length);
    if (APR_SUCCESS != rv) goto cleanup;
    apr_brigade_length(dest, 0, &nend);
    /* apr_brigade_split_line() has the nasty habit of leaving a 0-length bucket
     * at the start of the brigade when it transferred the whole content. Get rid of it.
     */
    if (!APR_BRIGADE_EMPTY(src)) {
         apr_bucket *b = APR_BRIGADE_FIRST(src);
        if (!APR_BUCKET_IS_METADATA(b) && 0 == b->length) {
            APR_BUCKET_REMOVE(b);
            apr_bucket_delete(b);
        }
    }
cleanup:
    *pnout = (APR_SUCCESS == rv)? (nend - nstart) : 0;
    return rv;
}

int tls_util_name_matches_server(const char *name, server_rec *s)
{
    apr_array_header_t *names;
    char **alias;
    int i;

    if (!s || !s->server_hostname) return 0;
    if (!strcasecmp(name, s->server_hostname)) return 1;
    /* first the fast equality match, then the pattern wild_name matches */
    names = s->names;
    if (!names) return 0;
    alias = (char **)names->elts;
    for (i = 0; i < names->nelts; ++i) {
        if (alias[i] && !strcasecmp(name, alias[i])) return 1;
    }
    names = s->wild_names;
    if (!names) return 0;
    alias = (char **)names->elts;
    for (i = 0; i < names->nelts; ++i) {
        if (alias[i] && !ap_strcasecmp_match(name, alias[i])) return 1;
    }
    return 0;
}

apr_size_t tls_util_bucket_print(char *buffer, apr_size_t bmax,
                                 apr_bucket *b, const char *sep)
{
    apr_size_t off = 0;
    if (sep && *sep) {
        off += (size_t)apr_snprintf(buffer+off, bmax-off, "%s", sep);
    }

    if (bmax <= off) {
        return off;
    }
    else if (APR_BUCKET_IS_METADATA(b)) {
        off += (size_t)apr_snprintf(buffer+off, bmax-off, "%s", b->type->name);
    }
    else if (bmax > off) {
        off += (size_t)apr_snprintf(buffer+off, bmax-off, "%s[%ld]",
                                    b->type->name, (long)(b->length == ((apr_size_t)-1)?
                                   -1 : (int)b->length));
    }
    return off;
}

apr_size_t tls_util_bb_print(char *buffer, apr_size_t bmax,
                             const char *tag, const char *sep,
                             apr_bucket_brigade *bb)
{
    apr_size_t off = 0;
    const char *sp = "";
    apr_bucket *b;

    if (bmax > 1) {
        if (bb) {
            memset(buffer, 0, bmax--);
            off += (size_t)apr_snprintf(buffer+off, bmax-off, "%s(", tag);
            for (b = APR_BRIGADE_FIRST(bb);
                 (bmax > off) && (b != APR_BRIGADE_SENTINEL(bb));
                 b = APR_BUCKET_NEXT(b)) {

                off += tls_util_bucket_print(buffer+off, bmax-off, b, sp);
                sp = " ";
            }
            if (bmax > off) {
                off += (size_t)apr_snprintf(buffer+off, bmax-off, ")%s", sep);
            }
        }
        else {
            off += (size_t)apr_snprintf(buffer+off, bmax-off, "%s(null)%s", tag, sep);
        }
    }
    return off;
}

