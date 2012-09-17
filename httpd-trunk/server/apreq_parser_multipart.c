/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

#include "apreq_parser.h"
#include "apreq_error.h"
#include "apreq_util.h"
#include "apr_strings.h"
#include "apr_strmatch.h"

#ifndef CRLF
#define CRLF    "\015\012"
#endif

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define PARSER_STATUS_CHECK(PREFIX)   do {         \
    if (ctx->status == PREFIX##_ERROR)             \
        return APREQ_ERROR_GENERAL;                \
    else if (ctx->status == PREFIX##_COMPLETE)     \
        return APR_SUCCESS;                        \
    else if (bb == NULL)                           \
        return APR_INCOMPLETE;                     \
} while (0);

/* maximum recursion level in the mfd parser */
#define MAX_LEVEL 8

struct mfd_ctx {
    apr_table_t                 *info;
    apr_bucket_brigade          *in;
    apr_bucket_brigade          *bb;
    apreq_parser_t              *hdr_parser;
    apreq_parser_t              *next_parser;
    const apr_strmatch_pattern  *pattern;
    char                        *bdry;
    enum {
        MFD_INIT,
        MFD_NEXTLINE,
        MFD_HEADER,
        MFD_POST_HEADER,
        MFD_PARAM,
        MFD_UPLOAD,
        MFD_MIXED,
        MFD_COMPLETE,
        MFD_ERROR
    }                            status;
    apr_bucket                  *eos;
    const char                  *param_name;
    apreq_param_t               *upload;
    unsigned                    level;
};


/********************* multipart/form-data *********************/

APR_INLINE
static apr_status_t brigade_start_string(apr_bucket_brigade *bb,
                                         const char *start_string)
{
    apr_bucket *e;
    apr_size_t slen = strlen(start_string);

    for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        const char *buf;
        apr_status_t s, bytes_to_check;
        apr_size_t blen;

        if (slen == 0)
            return APR_SUCCESS;

        if (APR_BUCKET_IS_EOS(e))
            return APR_EOF;

        s = apr_bucket_read(e, &buf, &blen, APR_BLOCK_READ);

        if (s != APR_SUCCESS)
            return s;

        if (blen == 0)
            continue;

        bytes_to_check = MIN(slen,blen);

        if (strncmp(buf,start_string,bytes_to_check) != 0)
            return APREQ_ERROR_GENERAL;

        slen -= bytes_to_check;
        start_string += bytes_to_check;
    }

    /* slen > 0, so brigade isn't large enough yet */
    return APR_INCOMPLETE;
}


static apr_status_t split_on_bdry(apr_bucket_brigade *out,
                                  apr_bucket_brigade *in,
                                  const apr_strmatch_pattern *pattern,
                                  const char *bdry)
{
    apr_bucket *e = APR_BRIGADE_FIRST(in);
    apr_size_t blen = strlen(bdry), off = 0;

    while ( e != APR_BRIGADE_SENTINEL(in) ) {
        apr_ssize_t idx;
        apr_size_t len;
        const char *buf;
        apr_status_t s;

        if (APR_BUCKET_IS_EOS(e))
            return APR_EOF;

        s = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
        if (s != APR_SUCCESS)
            return s;

        if (len == 0) {
            apr_bucket *f = e;
            e = APR_BUCKET_NEXT(e);
            apr_bucket_delete(f);
            continue;
        }

    look_for_boundary_up_front:
        if (strncmp(bdry + off, buf, MIN(len, blen - off)) == 0) {
            if ( len >= blen - off ) {
                /* complete match */
                if (len > blen - off)
                    apr_bucket_split(e, blen - off);
                e = APR_BUCKET_NEXT(e);

                do {
                    apr_bucket *f = APR_BRIGADE_FIRST(in);
                    apr_bucket_delete(f);
                } while (APR_BRIGADE_FIRST(in) != e);

                return APR_SUCCESS;
            }
            /* partial match */
            off += len;
            e = APR_BUCKET_NEXT(e);
            continue;
        }
        else if (off > 0) {
            /* prior (partial) strncmp failed,
             * so we can move previous buckets across
             * and retest buf against the full bdry.
             */

            /* give hints to GCC by making the brigade volatile, otherwise the
             * loop below will end up being endless. See:
             * https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=193740
             */
            apr_bucket_brigade * volatile in_v = in;

            do {
                apr_bucket *f = APR_BRIGADE_FIRST(in_v);
                APR_BUCKET_REMOVE(f);
                APR_BRIGADE_INSERT_TAIL(out, f);
            } while (e != APR_BRIGADE_FIRST(in_v));
            off = 0;
            goto look_for_boundary_up_front;
        }

        if (pattern != NULL && len >= blen) {
            const char *match = apr_strmatch(pattern, buf, len);
            if (match != NULL)
                idx = match - buf;
            else {
                idx = apreq_index(buf + len-blen, blen, bdry, blen,
                                  APREQ_MATCH_PARTIAL);
                if (idx >= 0)
                    idx += len-blen;
            }
        }
        else
            idx = apreq_index(buf, len, bdry, blen, APREQ_MATCH_PARTIAL);

        /* Theoretically idx should never be 0 here, because we
         * already tested the front of the brigade for a potential match.
         * However, it doesn't hurt to allow for the possibility,
         * since this will just start the whole loop over again.
         */
        if (idx >= 0)
            apr_bucket_split(e, idx);

        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(out, e);
        e = APR_BRIGADE_FIRST(in);
    }

    return APR_INCOMPLETE;
}


static
struct mfd_ctx * create_multipart_context(const char *content_type,
                                          apr_pool_t *pool,
                                          apr_bucket_alloc_t *ba,
                                          apr_size_t brigade_limit,
                                          const char *temp_dir,
                                          unsigned level)

{
    apr_status_t s;
    apr_size_t blen;
    struct mfd_ctx *ctx = apr_palloc(pool, sizeof *ctx);
    char *ct = apr_pstrdup(pool, content_type);

    ct = strchr(ct, ';');
    if (ct == NULL)
        return NULL; /* missing semicolon */

    *ct++ = 0;
    s = apreq_header_attribute(ct, "boundary", 8,
                               (const char **)&ctx->bdry, &blen);

    if (s != APR_SUCCESS)
        return NULL; /* missing boundary */

    ctx->bdry[blen] = 0;

    *--ctx->bdry = '-';
    *--ctx->bdry = '-';
    *--ctx->bdry = '\n';
    *--ctx->bdry = '\r';

    ctx->status = MFD_INIT;
    ctx->pattern = apr_strmatch_precompile(pool, ctx->bdry, 1);
    ctx->hdr_parser = apreq_parser_make(pool, ba, "",
                                        apreq_parse_headers,
                                        brigade_limit,
                                        temp_dir, NULL, NULL);
    ctx->info = NULL;
    ctx->bb = apr_brigade_create(pool, ba);
    ctx->in = apr_brigade_create(pool, ba);
    ctx->eos = apr_bucket_eos_create(ba);
    ctx->next_parser = NULL;
    ctx->param_name = NULL;
    ctx->upload = NULL;
    ctx->level = level;

    return ctx;
}

APREQ_DECLARE_PARSER(apreq_parse_multipart)
{
    apr_pool_t *pool = parser->pool;
    apr_bucket_alloc_t *ba = parser->bucket_alloc;
    struct mfd_ctx *ctx = parser->ctx;
    apr_status_t s;

    if (ctx == NULL) {
        ctx = create_multipart_context(parser->content_type,
                                       pool, ba,
                                       parser->brigade_limit,
                                       parser->temp_dir, 1);
        if (ctx == NULL)
            return APREQ_ERROR_GENERAL;


        parser->ctx = ctx;
    }

    PARSER_STATUS_CHECK(MFD);
    APR_BRIGADE_CONCAT(ctx->in, bb);

 mfd_parse_brigade:

    switch (ctx->status) {

    case MFD_INIT:
        {
            s = split_on_bdry(ctx->bb, ctx->in, NULL, ctx->bdry + 2);
            if (s != APR_SUCCESS) {
                apreq_brigade_setaside(ctx->in, pool);
                apreq_brigade_setaside(ctx->bb, pool);
                return s;
            }
            ctx->status = MFD_NEXTLINE;
            /* Be polite and return any preamble text to the caller. */
            APR_BRIGADE_CONCAT(bb, ctx->bb);
        }

        /* fall through */

    case MFD_NEXTLINE:
        {
            s = split_on_bdry(ctx->bb, ctx->in, NULL, CRLF);
            if (s == APR_EOF) {
                ctx->status = MFD_COMPLETE;
                return APR_SUCCESS;
            }
            if (s != APR_SUCCESS) {
                apreq_brigade_setaside(ctx->in, pool);
                apreq_brigade_setaside(ctx->bb, pool);
                return s;
            }
            if (!APR_BRIGADE_EMPTY(ctx->bb)) {
                char *line;
                apr_size_t len;
                apr_brigade_pflatten(ctx->bb, &line, &len, pool);

                if (len >= 2 && strncmp(line, "--", 2) == 0) {
                    APR_BRIGADE_CONCAT(bb, ctx->in);
                    ctx->status = MFD_COMPLETE;
                    return APR_SUCCESS;
                }
                apr_brigade_cleanup(ctx->bb);
            }

            ctx->status = MFD_HEADER;
            ctx->info = NULL;
        }
        /* fall through */

    case MFD_HEADER:
        {
            if (ctx->info == NULL) {
                ctx->info = apr_table_make(pool, APREQ_DEFAULT_NELTS);
                /* flush out header parser internal structs for reuse */
                ctx->hdr_parser->ctx = NULL;
            }
            s = apreq_parser_run(ctx->hdr_parser, ctx->info, ctx->in);
            switch (s) {
            case APR_SUCCESS:
                ctx->status = MFD_POST_HEADER;
                break;
            case APR_INCOMPLETE:
                apreq_brigade_setaside(ctx->in, pool);
                return APR_INCOMPLETE;
            default:
                ctx->status = MFD_ERROR;
                return s;
            }
        }
        /* fall through */

    case MFD_POST_HEADER:
        {
            /*  Must handle special case of missing CRLF (mainly
             *  coming from empty file uploads). See RFC2065 S5.1.1:
             *
             *    body-part = MIME-part-header [CRLF *OCTET]
             *
             *  So the CRLF we already matched in MFD_HEADER may have been
             *  part of the boundary string! Both Konqueror (v??) and
             *  Mozilla-0.97 are known to emit such blocks.
             *
             *  Here we first check for this condition with
             *  brigade_start_string, and prefix the brigade with
             *  an additional CRLF bucket if necessary.
             */

            const char *cd, *ct, *name, *filename;
            apr_size_t nlen, flen;
            apr_bucket *e;

            switch (brigade_start_string(ctx->in, ctx->bdry + 2)) {

            case APR_INCOMPLETE:
                apreq_brigade_setaside(ctx->in, pool);
                return APR_INCOMPLETE;

            case APR_SUCCESS:
                /* part has no body- return CRLF to front */
                e = apr_bucket_immortal_create(CRLF, 2,
                                                ctx->bb->bucket_alloc);
                APR_BRIGADE_INSERT_HEAD(ctx->in, e);
                break;

            default:
                ; /* has body, ok */
            }

            cd = apr_table_get(ctx->info, "Content-Disposition");

            /*  First check to see if must descend into a new multipart
             *  block.  If we do, create a new parser and pass control
             *  to it.
             */

            ct = apr_table_get(ctx->info, "Content-Type");

            if (ct != NULL && strncmp(ct, "multipart/", 10) == 0) {
                struct mfd_ctx *next_ctx;

                if (ctx->level >= MAX_LEVEL) {
                    ctx->status = MFD_ERROR;
                    goto mfd_parse_brigade;
                }

                next_ctx = create_multipart_context(ct, pool, ba,
                                                    parser->brigade_limit,
                                                    parser->temp_dir,
                                                    ctx->level + 1);

                next_ctx->param_name = "";

                if (cd != NULL) {
                    s = apreq_header_attribute(cd, "name", 4,
                                               &name, &nlen);
                    if (s == APR_SUCCESS) {
                        next_ctx->param_name
                            = apr_pstrmemdup(pool, name, nlen);
                    }
                    else {
                        const char *cid = apr_table_get(ctx->info,
                                                        "Content-ID");
                        if (cid != NULL)
                            next_ctx->param_name = apr_pstrdup(pool, cid);
                    }

                }

                ctx->next_parser = apreq_parser_make(pool, ba, ct,
                                                     apreq_parse_multipart,
                                                     parser->brigade_limit,
                                                     parser->temp_dir,
                                                     parser->hook,
                                                     next_ctx);
                ctx->status = MFD_MIXED;
                goto mfd_parse_brigade;

            }

            /* Look for a normal form-data part. */

            if (cd != NULL && strncmp(cd, "form-data", 9) == 0) {
                s = apreq_header_attribute(cd, "name", 4, &name, &nlen);
                if (s != APR_SUCCESS) {
                    ctx->status = MFD_ERROR;
                    goto mfd_parse_brigade;
                }

                s = apreq_header_attribute(cd, "filename",
                                           8, &filename, &flen);
                if (s == APR_SUCCESS) {
                    apreq_param_t *param;

                    param = apreq_param_make(pool, name, nlen,
                                             filename, flen);
                    apreq_param_tainted_on(param);
                    param->info = ctx->info;
                    param->upload
                        = apr_brigade_create(pool, ctx->bb->bucket_alloc);
                    ctx->upload = param;
                    ctx->status = MFD_UPLOAD;
                    goto mfd_parse_brigade;
                }
                else {
                    ctx->param_name = apr_pstrmemdup(pool, name, nlen);
                    ctx->status = MFD_PARAM;
                    /* fall thru */
                }
            }

            /* else check for a file part in a multipart section */
            else if (cd != NULL && strncmp(cd, "file", 4) == 0) {
                apreq_param_t *param;

                s = apreq_header_attribute(cd, "filename",
                                           8, &filename, &flen);
                if (s != APR_SUCCESS || ctx->param_name == NULL) {
                    ctx->status = MFD_ERROR;
                    goto mfd_parse_brigade;
                }
                name = ctx->param_name;
                nlen = strlen(name);
                param = apreq_param_make(pool, name, nlen,
                                         filename, flen);
                apreq_param_tainted_on(param);
                param->info = ctx->info;
                param->upload = apr_brigade_create(pool,
                                                   ctx->bb->bucket_alloc);
                ctx->upload = param;
                ctx->status = MFD_UPLOAD;
                goto mfd_parse_brigade;
            }

            /* otherwise look for Content-ID in multipart/mixed case */
            else {
                const char *cid = apr_table_get(ctx->info, "Content-ID");
                apreq_param_t *param;

                if (cid != NULL) {
                    name = cid;
                    nlen = strlen(name);
                }
                else {
                    name = "";
                    nlen = 0;
                }

                filename = "";
                flen = 0;
                param = apreq_param_make(pool, name, nlen,
                                         filename, flen);
                apreq_param_tainted_on(param);
                param->info = ctx->info;
                param->upload = apr_brigade_create(pool,
                                               ctx->bb->bucket_alloc);
                ctx->upload = param;
                ctx->status = MFD_UPLOAD;
                goto mfd_parse_brigade;
            }
        }
        /* fall through */

    case MFD_PARAM:
        {
            apreq_param_t *param;
            apreq_value_t *v;
            apr_size_t len;
            apr_off_t off;

            s = split_on_bdry(ctx->bb, ctx->in, ctx->pattern, ctx->bdry);

            switch (s) {

            case APR_INCOMPLETE:
                apreq_brigade_setaside(ctx->in, pool);
                apreq_brigade_setaside(ctx->bb, pool);
                return s;

            case APR_SUCCESS:
                s = apr_brigade_length(ctx->bb, 1, &off);
                if (s != APR_SUCCESS) {
                    ctx->status = MFD_ERROR;
                    return s;
                }
                len = off;
                param = apreq_param_make(pool, ctx->param_name,
                                         strlen(ctx->param_name),
                                         NULL, len);
                apreq_param_tainted_on(param);
                param->info = ctx->info;

                *(const apreq_value_t **)&v = &param->v;
                apr_brigade_flatten(ctx->bb, v->data, &len);
                v->data[len] = 0;

                if (parser->hook != NULL) {
                    s = apreq_hook_run(parser->hook, param, NULL);
                    if (s != APR_SUCCESS) {
                        ctx->status = MFD_ERROR;
                        return s;
                    }
                }

                apreq_param_charset_set(param,
                                        apreq_charset_divine(v->data, len));
                apreq_value_table_add(v, t);
                ctx->status = MFD_NEXTLINE;
                ctx->param_name = NULL;
                apr_brigade_cleanup(ctx->bb);
                goto mfd_parse_brigade;

            default:
                ctx->status = MFD_ERROR;
                return s;
            }


        }
        break;  /* not reached */

    case MFD_UPLOAD:
        {
            apreq_param_t *param = ctx->upload;

            s = split_on_bdry(ctx->bb, ctx->in, ctx->pattern, ctx->bdry);
            switch (s) {

            case APR_INCOMPLETE:
                if (parser->hook != NULL) {
                    s = apreq_hook_run(parser->hook, param, ctx->bb);
                    if (s != APR_SUCCESS) {
                        ctx->status = MFD_ERROR;
                        return s;
                    }
                }
                apreq_brigade_setaside(ctx->bb, pool);
                apreq_brigade_setaside(ctx->in, pool);
                s = apreq_brigade_concat(pool, parser->temp_dir,
                                         parser->brigade_limit,
                                         param->upload, ctx->bb);
                return (s == APR_SUCCESS) ? APR_INCOMPLETE : s;

            case APR_SUCCESS:
                if (parser->hook != NULL) {
                    APR_BRIGADE_INSERT_TAIL(ctx->bb, ctx->eos);
                    s = apreq_hook_run(parser->hook, param, ctx->bb);
                    APR_BUCKET_REMOVE(ctx->eos);
                    if (s != APR_SUCCESS) {
                        ctx->status = MFD_ERROR;
                        return s;
                    }
                }
                apreq_value_table_add(&param->v, t);
                apreq_brigade_setaside(ctx->bb, pool);
                s = apreq_brigade_concat(pool, parser->temp_dir,
                                         parser->brigade_limit,
                                         param->upload, ctx->bb);

                if (s != APR_SUCCESS)
                    return s;

                ctx->status = MFD_NEXTLINE;
                goto mfd_parse_brigade;

            default:
                ctx->status = MFD_ERROR;
                return s;
            }

        }
        break;  /* not reached */


    case MFD_MIXED:
        {
            s = apreq_parser_run(ctx->next_parser, t, ctx->in);
            switch (s) {
            case APR_SUCCESS:
                ctx->status = MFD_INIT;
                ctx->param_name = NULL;
                goto mfd_parse_brigade;
            case APR_INCOMPLETE:
                APR_BRIGADE_CONCAT(bb, ctx->in);
                return APR_INCOMPLETE;
            default:
                ctx->status = MFD_ERROR;
                return s;
            }

        }
        break; /* not reached */

    default:
        return APREQ_ERROR_GENERAL;
    }

    return APR_INCOMPLETE;
}
