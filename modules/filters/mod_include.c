/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/*
 * http_include.c: Handles the server-parsed HTML documents
 * 
 * Original by Rob McCool; substantial fixups by David Robinson;
 * incorporated into the Apache module framework by rst.
 * 
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"
#include "apr_hash.h"
#include "apr_user.h"
#include "apr_lib.h"
#include "apr_optional.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#define CORE_PRIVATE

#include "ap_config.h"
#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"
#include "http_core.h"

#define MOD_INCLUDE_REDESIGN
#include "mod_include.h"
#include "util_ebcdic.h"

module AP_MODULE_DECLARE_DATA include_module;
static apr_hash_t *include_hash;
static APR_OPTIONAL_FN_TYPE(ap_register_include_handler) *ssi_pfn_register;

/*****************************************************************
 *
 * XBITHACK.  Sigh...  NB it's configurable per-directory; the compile-time
 * option only changes the default.
 */

enum xbithack {
    xbithack_off, xbithack_on, xbithack_full
};

struct bndm_t {
    unsigned int T[256];
    unsigned int x;
} ;

typedef struct {
    char *default_error_msg;
    char *default_time_fmt;
    enum xbithack *xbithack;
} include_dir_config;

typedef struct {
    char *default_start_tag;
    char *default_end_tag;
    int  start_tag_len;
    bndm_t start_seq_pat;
    char *undefinedEcho;
    int  undefinedEchoLen;
} include_server_config;

#ifdef MOD_INCLUDE_REDESIGN
/* main parser states */
typedef enum {
    PARSE_PRE_HEAD,
    PARSE_HEAD,
    PARSE_DIRECTIVE,
    PARSE_DIRECTIVE_POSTNAME,
    PARSE_DIRECTIVE_TAIL,
    PARSE_DIRECTIVE_POSTTAIL,
    PARSE_PRE_ARG,
    PARSE_ARG,
    PARSE_ARG_NAME,
    PARSE_ARG_POSTNAME,
    PARSE_ARG_EQ,
    PARSE_ARG_PREVAL,
    PARSE_ARG_VAL,
    PARSE_ARG_VAL_ESC,
    PARSE_ARG_POSTVAL,
    PARSE_TAIL,
    PARSE_TAIL_SEQ,
    PARSE_EXECUTE
} parse_state_t;

typedef struct ssi_arg_item {
    struct ssi_arg_item *next;
    char                *name;
    apr_size_t           name_len;
    char                *value;
    apr_size_t           value_len;
} ssi_arg_item_t;

typedef struct {
    parse_state_t state;
    int           seen_eos;
    int           error;
    char          quote;         /* quote character value (or \0) */

    apr_bucket_brigade *tmp_bb;

    apr_size_t    end_seq_len;
    char         *directive;     /* name of the current directive */

    unsigned        argc;        /* argument counter (of the current
                                  * directive)
                                  */
    ssi_arg_item_t *argv;        /* all arguments */
    ssi_arg_item_t *current_arg; /* currently parsed argument */
    request_rec    *r;
    include_ctx_t  *ctx;         /* public part of the context structure */

    apr_pool_t     *dpool;
} ssi_ctx_t;

#define SSI_CREATE_ERROR_BUCKET(ctx, f, bb) APR_BRIGADE_INSERT_TAIL((bb),   \
    apr_bucket_pool_create(apr_pstrdup((ctx)->pool, (ctx)->error_str),  \
                           strlen((ctx)->error_str), (ctx)->pool,       \
                           (f)->c->bucket_alloc))

#endif /* MOD_INCLUDE_REDESIGN */

#ifdef XBITHACK
#define DEFAULT_XBITHACK xbithack_full
#else
#define DEFAULT_XBITHACK xbithack_off
#endif

#define BYTE_COUNT_THRESHOLD AP_MIN_BYTES_TO_WRITE

/* ------------------------ Environment function -------------------------- */

/* Sentinel value to store in subprocess_env for items that
 * shouldn't be evaluated until/unless they're actually used
 */
static const char lazy_eval_sentinel;
#define LAZY_VALUE (&lazy_eval_sentinel)

static void add_include_vars(request_rec *r, char *timefmt)
{
    apr_table_t *e = r->subprocess_env;
    char *t;

    apr_table_setn(e, "DATE_LOCAL", LAZY_VALUE);
    apr_table_setn(e, "DATE_GMT", LAZY_VALUE);
    apr_table_setn(e, "LAST_MODIFIED", LAZY_VALUE);
    apr_table_setn(e, "DOCUMENT_URI", r->uri);
    if (r->path_info && *r->path_info) {
        apr_table_setn(e, "DOCUMENT_PATH_INFO", r->path_info);
    }
    apr_table_setn(e, "USER_NAME", LAZY_VALUE);
    if ((t = strrchr(r->filename, '/'))) {
        apr_table_setn(e, "DOCUMENT_NAME", ++t);
    }
    else {
        apr_table_setn(e, "DOCUMENT_NAME", r->uri);
    }
    if (r->args) {
        char *arg_copy = apr_pstrdup(r->pool, r->args);

        ap_unescape_url(arg_copy);
        apr_table_setn(e, "QUERY_STRING_UNESCAPED",
                  ap_escape_shell_cmd(r->pool, arg_copy));
    }
}

static const char *add_include_vars_lazy(request_rec *r, const char *var)
{
    char *val;
    if (!strcasecmp(var, "DATE_LOCAL")) {
        include_dir_config *conf =
            (include_dir_config *)ap_get_module_config(r->per_dir_config,
                                                       &include_module);
        val = ap_ht_time(r->pool, r->request_time, conf->default_time_fmt, 0);
    }
    else if (!strcasecmp(var, "DATE_GMT")) {
        include_dir_config *conf =
            (include_dir_config *)ap_get_module_config(r->per_dir_config,
                                                       &include_module);
        val = ap_ht_time(r->pool, r->request_time, conf->default_time_fmt, 1);
    }
    else if (!strcasecmp(var, "LAST_MODIFIED")) {
        include_dir_config *conf =
            (include_dir_config *)ap_get_module_config(r->per_dir_config,
                                                       &include_module);
        val = ap_ht_time(r->pool, r->finfo.mtime, conf->default_time_fmt, 0);
    }
    else if (!strcasecmp(var, "USER_NAME")) {
        if (apr_get_username(&val, r->finfo.user, r->pool) != APR_SUCCESS) {
            val = "<unknown>";
        }
    }
    else {
        val = NULL;
    }

    if (val) {
        apr_table_setn(r->subprocess_env, var, val);
    }
    return val;
}

static const char *get_include_var(request_rec *r, include_ctx_t *ctx, 
                                   const char *var)
{
    const char *val;
    if (apr_isdigit(*var) && !var[1]) {
        /* Handle $0 .. $9 from the last regex evaluated.
         * The choice of returning NULL strings on not-found,
         * v.s. empty strings on an empty match is deliberate.
         */
        if (!ctx->re_result || !ctx->re_string) {
            return NULL;
        }
        else {
            int idx = atoi(var);
            apr_size_t len = (*ctx->re_result)[idx].rm_eo
                           - (*ctx->re_result)[idx].rm_so;
            if (    (*ctx->re_result)[idx].rm_so < 0
                 || (*ctx->re_result)[idx].rm_eo < 0) {
                return NULL;
            }
            val = apr_pstrmemdup(r->pool, ctx->re_string 
                                        + (*ctx->re_result)[idx].rm_so, len);
        }
    }
    else {
        val = apr_table_get(r->subprocess_env, var);

        if (val == LAZY_VALUE)
            val = add_include_vars_lazy(r, var);
    }
    return val;
}

/* --------------------------- Parser functions --------------------------- */

/* This is an implementation of the BNDM search algorithm.
 *
 * Fast and Flexible String Matching by Combining Bit-parallelism and 
 * Suffix Automata (2001) 
 * Gonzalo Navarro, Mathieu Raffinot
 *
 * http://www-igm.univ-mlv.fr/~raffinot/ftp/jea2001.ps.gz
 *
 * Initial code submitted by Sascha Schumann.
 */
   
/* Precompile the bndm_t data structure. */
static void bndm_compile(bndm_t *t, const char *n, apr_size_t nl)
{
    unsigned int x;
    const char *ne = n + nl;

    memset(t->T, 0, sizeof(unsigned int) * 256);
    
    for (x = 1; n < ne; x <<= 1)
        t->T[(unsigned char) *n++] |= x;

    t->x = x - 1;
}

/* Implements the BNDM search algorithm (as described above).
 *
 * n  - the pattern to search for
 * nl - length of the pattern to search for
 * h  - the string to look in
 * hl - length of the string to look for
 * t  - precompiled bndm structure against the pattern 
 *
 * Returns the count of character that is the first match or hl if no
 * match is found.
 */
static apr_size_t bndm(const char *n, apr_size_t nl, const char *h, 
                       apr_size_t hl, bndm_t *t)
{
    const char *skip;
    const char *he, *p, *pi;
    unsigned int *T, x, d;

    he = h + hl;

    T = t->T;
    x = t->x;

    pi = h - 1; /* pi: p initial */
    p = pi + nl; /* compare window right to left. point to the first char */

    while (p < he) {
        skip = p;
        d = x;
        do {
            d &= T[(unsigned char) *p--];
            if (!d) {
                break;
            }
            if ((d & 1)) {
                if (p != pi)
                    skip = p;
                else
                    return p - h + 1;
            }
            d >>= 1;
        } while (d);

        pi = skip;
        p = pi + nl;
    }

    return hl;
}

#ifndef MOD_INCLUDE_REDESIGN
/* We've now found a start sequence tag... */
static apr_bucket* found_start_sequence(apr_bucket *dptr,
                                        include_ctx_t *ctx, 
                                        apr_size_t tagStart,
                                        apr_size_t len)
{
    /* We want to split the bucket at the '<'. */
    ctx->state = PARSE_DIRECTIVE;
    ctx->tag_length = 0;
    ctx->parse_pos = 0;

    /* If tagStart indexes the end of the bucket, then tag_start_bucket
     * should be the next bucket
     */
    if (tagStart < len) {
        ctx->tag_start_bucket = dptr;
        ctx->tag_start_index = tagStart;
    }
    else {
        ctx->tag_start_bucket = APR_BUCKET_NEXT(dptr);
        ctx->tag_start_index = 0;
    }

    if (ctx->head_start_index > 0) {
        apr_bucket *tmp_bkt;

        /* Split the bucket with the start of the tag in it */
        apr_bucket_split(ctx->head_start_bucket, ctx->head_start_index);
        tmp_bkt = APR_BUCKET_NEXT(ctx->head_start_bucket);
        /* If it was a one bucket match */
        if ((tagStart < len) && (dptr == ctx->head_start_bucket)) {
            ctx->tag_start_bucket = tmp_bkt;
            ctx->tag_start_index = tagStart - ctx->head_start_index;
        }
        ctx->head_start_bucket = tmp_bkt;
        ctx->head_start_index = 0;
    }
    return ctx->head_start_bucket;
}

/* This function returns either a pointer to the split bucket containing the
 * first byte of the BEGINNING_SEQUENCE (after finding a complete match) or it
 * returns NULL if no match found.
 */
static apr_bucket *find_start_sequence(apr_bucket *dptr, include_ctx_t *ctx,
                                       apr_bucket_brigade *bb, int *do_cleanup)
{
    apr_size_t len;
    const char *c;
    const char *buf;
    const char *str = ctx->start_seq ;
    apr_size_t slen = ctx->start_seq_len;
    apr_size_t pos;

    *do_cleanup = 0;

    do {
        apr_status_t rv = 0;
        int read_done = 0;

        if (APR_BUCKET_IS_EOS(dptr)) {
            break;
        }

#if 0
        /* XXX the bucket flush support is commented out for now
         * because it was causing a segfault */
        if (APR_BUCKET_IS_FLUSH(dptr)) {
            apr_bucket *old = dptr; 
            dptr = APR_BUCKET_NEXT(old);
            APR_BUCKET_REMOVE(old);
            ctx->output_now = 1;
            ctx->output_flush = 1;
        }
        else
#endif /* 0 */
        if (ctx->bytes_parsed >= BYTE_COUNT_THRESHOLD) {
            ctx->output_now = 1;
        }
        else if (ctx->bytes_parsed > 0) {
            rv = apr_bucket_read(dptr, &buf, &len, APR_NONBLOCK_READ);
            read_done = 1;
            if (APR_STATUS_IS_EAGAIN(rv)) {
                ctx->output_now = 1;
            }
        }

        if (ctx->output_now) {
            apr_bucket *start_bucket;
            if (ctx->head_start_index > 0) {
                start_bucket = ctx->head_start_bucket;
                apr_bucket_split(start_bucket, ctx->head_start_index);
                start_bucket = APR_BUCKET_NEXT(start_bucket);
                ctx->head_start_index = 0;
                ctx->head_start_bucket = start_bucket;
                ctx->parse_pos = 0;
                ctx->state = PRE_HEAD;
            }
            else {
                start_bucket = dptr;
            }
            return start_bucket;
        }

        if (!read_done) {
            rv = apr_bucket_read(dptr, &buf, &len, APR_BLOCK_READ);
        }
        if (!APR_STATUS_IS_SUCCESS(rv)) {
            ctx->status = rv;
            return NULL;
        }

        if (len == 0) { /* end of pipe? */
            dptr = APR_BUCKET_NEXT(dptr);
            continue;
        }

        /* Set our buffer to use. */
        c = buf;

        /* The last bucket had a left over partial match that we need to
         * complete. 
         */
        if (ctx->state == PARSE_HEAD)
        {
            apr_size_t tmpLen;
            tmpLen = (len < (slen - 1)) ? len : (slen - 1);

            while (c < buf + tmpLen && *c == str[ctx->parse_pos])
            {
                c++; 
                ctx->parse_pos++;
            }

            if (str[ctx->parse_pos] == '\0')
            {
                ctx->bytes_parsed += c - buf;
                return found_start_sequence(dptr, ctx, c - buf, len);
            }
            else if (c == buf + tmpLen) {
                dptr = APR_BUCKET_NEXT(dptr);
                continue;
            }

            /* False alarm... 
             */
            APR_BRIGADE_PREPEND(bb, ctx->ssi_tag_brigade);

            /* We know we are at the beginning of this bucket so
             *   we can just prepend the saved bytes from the
             *   ssi_tag_brigade (which empties the ssi_tag_brigade)
             *   and continue processing.
             * We do not need to set do_cleanup beacuse the
             *   prepend takes care of that.
             */
            ctx->state = PRE_HEAD;
            ctx->head_start_bucket = NULL;
            ctx->head_start_index = 0;
        }

        if (len)
        {
            pos = bndm(str, slen, buf, len, ctx->start_seq_pat);
            if (pos != len)
            {
                ctx->head_start_bucket = dptr;
                ctx->head_start_index = pos;
                ctx->bytes_parsed += pos + slen;
                return found_start_sequence(dptr, ctx, pos + slen, len);
            }
        }
        
        /* Consider the case where we have <!-- at the end of the bucket. */
        if (len > slen) {
            ctx->bytes_parsed += (len - slen);
            c = buf + len - slen;
        }
        else {
            c = buf;
        }
        ctx->parse_pos = 0;

        while (c < buf + len)
        {
            if (*c == str[ctx->parse_pos]) {
                if (ctx->state == PRE_HEAD) {
                    ctx->state = PARSE_HEAD;
                    ctx->head_start_bucket = dptr;
                    ctx->head_start_index = c - buf;
                }
                ctx->parse_pos++;
                c++;
                ctx->bytes_parsed++;
            }
            else if (ctx->parse_pos != 0) 
            {
                /* DO NOT INCREMENT c IN THIS BLOCK!
                 * Don't increment bytes_parsed either.
                 * This block is just to reset the indexes and
                 *   pointers related to parsing the tag start_sequence.
                 * The value c needs to be checked again to handle
                 *   the case where we find "<<!--#". We are now
                 *   looking at the second "<" and need to restart
                 *   the start_sequence checking from parse_pos = 0.
                 * do_cleanup causes the stored bytes in ssi_tag_brigade
                 *   to be forwarded on and cleaned up. We may not be
                 *   able to just prepend the ssi_tag_brigade because
                 *   we may have advanced too far before we noticed this
                 *   case, so just flag it and clean it up later.
                 */
                *do_cleanup = 1;
                ctx->parse_pos = 0;
                ctx->state = PRE_HEAD;
                ctx->head_start_bucket = NULL;
                ctx->head_start_index = 0;
            }
            else {
               c++;
               ctx->bytes_parsed++;
            }
        }
        dptr = APR_BUCKET_NEXT(dptr);
    } while (dptr != APR_BRIGADE_SENTINEL(bb));
          
  
    return NULL;
}

static apr_bucket *find_end_sequence(apr_bucket *dptr, include_ctx_t *ctx, 
                                     apr_bucket_brigade *bb)
{
    apr_size_t len;
    const char *c;
    const char *buf;
    const char *str = ctx->end_seq;
    const char *start;

    do {
        apr_status_t rv = 0;
        int read_done = 0;

        if (APR_BUCKET_IS_EOS(dptr)) {
            break;
        }
#if 0
        /* XXX the bucket flush support is commented out for now
         * because it was causing a segfault */
        if (APR_BUCKET_IS_FLUSH(dptr)) {
            apr_bucket *old = dptr; 
            dptr = APR_BUCKET_NEXT(old);
            APR_BUCKET_REMOVE(old);
            ctx->output_now = 1;
            ctx->output_flush = 1;
        }
        else
#endif /* 0 */
        if (ctx->bytes_parsed >= BYTE_COUNT_THRESHOLD) {
            ctx->output_now = 1;
        }
        else if (ctx->bytes_parsed > 0) {
            rv = apr_bucket_read(dptr, &buf, &len, APR_NONBLOCK_READ);
            read_done = 1;
            if (APR_STATUS_IS_EAGAIN(rv)) {
                ctx->output_now = 1;
            }
        }

        if (ctx->output_now) {
            if (ctx->state == PARSE_DIRECTIVE) {
                /* gonna start over parsing the directive next time through */
                ctx->directive_length = 0;
                ctx->tag_length       = 0;
            }
            return dptr;
        }

        if (!read_done) {
            rv = apr_bucket_read(dptr, &buf, &len, APR_BLOCK_READ);
        }
        if (!APR_STATUS_IS_SUCCESS(rv)) {
            ctx->status = rv;
            return NULL;
        }

        if (len == 0) { /* end of pipe? */
            dptr = APR_BUCKET_NEXT(dptr);
            continue;
        }
        if (dptr == ctx->tag_start_bucket) {
            c = buf + ctx->tag_start_index;
        }
        else {
            c = buf;
        }
        start = c;
        while (c < buf + len) {
            if (*c == str[ctx->parse_pos]) {
                if (ctx->state != PARSE_TAIL) {
                    ctx->state             = PARSE_TAIL;
                    ctx->tail_start_bucket = dptr;
                    ctx->tail_start_index  = c - buf;
                }
                ctx->parse_pos++;
                if (str[ctx->parse_pos] == '\0') {
                        apr_bucket *tmp_buck = dptr;

                        /* We want to split the bucket at the '>'. The
                         * end of the END_SEQUENCE is in the current bucket.
                         * The beginning might be in a previous bucket.
                         */
                        c++;
                        ctx->bytes_parsed += (c - start);
                        ctx->state = PARSED;
                        apr_bucket_split(dptr, c - buf);
                        tmp_buck = APR_BUCKET_NEXT(dptr);
                        return (tmp_buck);
                    }           
            }
            else {
                if (ctx->state == PARSE_DIRECTIVE) {
                    if (ctx->tag_length == 0) {
                        if (!apr_isspace(*c)) {
                            const char *tmp = c;
                            ctx->tag_start_bucket = dptr;
                            ctx->tag_start_index  = c - buf;
                            do {
                                c++;
                            } while ((c < buf + len) && !apr_isspace(*c) &&
                                     *c != *str);
                            ctx->tag_length = ctx->directive_length = c - tmp;
                            continue;
                        }
                    }
                    else {
                        if (!apr_isspace(*c)) {
                            ctx->directive_length++;
                        }
                        else {
                            ctx->state = PARSE_TAG;
                        }
                        ctx->tag_length++;
                    }
                }
                else if (ctx->state == PARSE_TAG) {
                    const char *tmp = c;
                    do {
                        c++;
                    } while ((c < buf + len) && (*c != *str));
                    ctx->tag_length += (c - tmp);
                    continue;
                }
                else {
                    if (ctx->parse_pos != 0) {
                        /* The reason for this, is that we need to make sure 
                         * that we catch cases like --->.  This makes the 
                         * second check after the original check fails.
                         * If parse_pos was already 0 then we already checked 
                         * this.
                         */
                         ctx->tag_length += ctx->parse_pos;

                         if (*c == str[0]) {
                             ctx->state = PARSE_TAIL;
                             ctx->tail_start_bucket = dptr;
                             ctx->tail_start_index = c - buf;
                             ctx->parse_pos = 1;
                         }
                         else {
                             ctx->tag_length++;
                             if (ctx->tag_length > ctx->directive_length) {
                                 ctx->state = PARSE_TAG;
                             }
                             else {
                                 ctx->state = PARSE_DIRECTIVE;
                                 ctx->directive_length += ctx->parse_pos;
                             }
                             ctx->tail_start_bucket = NULL;
                             ctx->tail_start_index = 0;
                             ctx->parse_pos = 0;
                         }
                    }
                }
            }
            c++;
        }
        ctx->bytes_parsed += (c - start);
        dptr = APR_BUCKET_NEXT(dptr);
    } while (dptr != APR_BRIGADE_SENTINEL(bb));
    return NULL;
}

/* This function culls through the buckets that have been set aside in the 
 * ssi_tag_brigade and copies just the directive part of the SSI tag (none
 * of the start and end delimiter bytes are copied).
 */
static apr_status_t get_combined_directive (include_ctx_t *ctx,
                                            request_rec *r,
                                            apr_bucket_brigade *bb,
                                            char *tmp_buf, 
                                            apr_size_t tmp_buf_size)
{
    int        done = 0;
    apr_bucket *dptr;
    const char *tmp_from;
    apr_size_t tmp_from_len;

    /* If the tag length is longer than the tmp buffer, allocate space. */
    if (ctx->tag_length > tmp_buf_size-1) {
        if ((ctx->combined_tag = apr_pcalloc(r->pool, 
             ctx->tag_length + 1)) == NULL) {
            return (APR_ENOMEM);
        }
    }     /* Else, just use the temp buffer. */
    else {
        ctx->combined_tag = tmp_buf;
    }

    /* Prime the pump. Start at the beginning of the tag... */
    dptr = ctx->tag_start_bucket;
    /* Read the bucket... */
    apr_bucket_read (dptr, &tmp_from, &tmp_from_len, 0);

    /* Adjust the pointer to start at the tag within the bucket... */
    if (dptr == ctx->tail_start_bucket) {
        tmp_from_len -= (tmp_from_len - ctx->tail_start_index);
    }
    tmp_from          = &tmp_from[ctx->tag_start_index];
    tmp_from_len     -= ctx->tag_start_index;
    ctx->curr_tag_pos = ctx->combined_tag;

    /* Loop through the buckets from the tag_start_bucket until before
     * the tail_start_bucket copying the contents into the buffer.
     */
    do {
        memcpy (ctx->curr_tag_pos, tmp_from, tmp_from_len);
        ctx->curr_tag_pos += tmp_from_len;

        if (dptr == ctx->tail_start_bucket) {
            done = 1;
        }
        else {
            dptr = APR_BUCKET_NEXT (dptr);
            apr_bucket_read (dptr, &tmp_from, &tmp_from_len, 0);
            /* Adjust the count to stop at the beginning of the tail. */
            if (dptr == ctx->tail_start_bucket) {
                tmp_from_len -= (tmp_from_len - ctx->tail_start_index);
            }
        }
    } while ((!done) &&
             (ctx->curr_tag_pos < ctx->combined_tag + ctx->tag_length));

    ctx->combined_tag[ctx->tag_length] = '\0';
    ctx->curr_tag_pos = ctx->combined_tag;

    return (APR_SUCCESS);
}
#endif /* !MOD_INCLUDE_REDESIGN */

/*
 * decodes a string containing html entities or numeric character references.
 * 's' is overwritten with the decoded string.
 * If 's' is syntatically incorrect, then the followed fixups will be made:
 *   unknown entities will be left undecoded;
 *   references to unused numeric characters will be deleted.
 *   In particular, &#00; will not be decoded, but will be deleted.
 *
 * drtr
 */

/* maximum length of any ISO-LATIN-1 HTML entity name. */
#define MAXENTLEN (6)

/* The following is a shrinking transformation, therefore safe. */

static void decodehtml(char *s)
{
    int val, i, j;
    char *p;
    const char *ents;
    static const char * const entlist[MAXENTLEN + 1] =
    {
        NULL,                   /* 0 */
        NULL,                   /* 1 */
        "lt\074gt\076",         /* 2 */
        "amp\046ETH\320eth\360",        /* 3 */
        "quot\042Auml\304Euml\313Iuml\317Ouml\326Uuml\334auml\344euml\353\
iuml\357ouml\366uuml\374yuml\377",      /* 4 */
        "Acirc\302Aring\305AElig\306Ecirc\312Icirc\316Ocirc\324Ucirc\333\
THORN\336szlig\337acirc\342aring\345aelig\346ecirc\352icirc\356ocirc\364\
ucirc\373thorn\376",            /* 5 */
        "Agrave\300Aacute\301Atilde\303Ccedil\307Egrave\310Eacute\311\
Igrave\314Iacute\315Ntilde\321Ograve\322Oacute\323Otilde\325Oslash\330\
Ugrave\331Uacute\332Yacute\335agrave\340aacute\341atilde\343ccedil\347\
egrave\350eacute\351igrave\354iacute\355ntilde\361ograve\362oacute\363\
otilde\365oslash\370ugrave\371uacute\372yacute\375"     /* 6 */
    };

    /* Do a fast scan through the string until we find anything
     * that needs more complicated handling
     */
    for (; *s != '&'; s++) {
        if (*s == '\0') {
            return;
        }
    }

    for (p = s; *s != '\0'; s++, p++) {
        if (*s != '&') {
            *p = *s;
            continue;
        }
        /* find end of entity */
        for (i = 1; s[i] != ';' && s[i] != '\0'; i++) {
            continue;
        }

        if (s[i] == '\0') {     /* treat as normal data */
            *p = *s;
            continue;
        }

        /* is it numeric ? */
        if (s[1] == '#') {
            for (j = 2, val = 0; j < i && apr_isdigit(s[j]); j++) {
                val = val * 10 + s[j] - '0';
            }
            s += i;
            if (j < i || val <= 8 || (val >= 11 && val <= 31) ||
                (val >= 127 && val <= 160) || val >= 256) {
                p--;            /* no data to output */
            }
            else {
                *p = RAW_ASCII_CHAR(val);
            }
        }
        else {
            j = i - 1;
            if (j > MAXENTLEN || entlist[j] == NULL) {
                /* wrong length */
                *p = '&';
                continue;       /* skip it */
            }
            for (ents = entlist[j]; *ents != '\0'; ents += i) {
                if (strncmp(s + 1, ents, j) == 0) {
                    break;
                }
            }

            if (*ents == '\0') {
                *p = '&';       /* unknown */
            }
            else {
                *p = RAW_ASCII_CHAR(((const unsigned char *) ents)[j]);
                s += i;
            }
        }
    }

    *p = '\0';
}

/*
 * Extract the next tag name and value.
 * If there are no more tags, set the tag name to NULL.
 * The tag value is html decoded if dodecode is non-zero.
 * The tag value may be NULL if there is no tag value..
 *    format:
 *        [WS]<Tag>[WS]=[WS]['|"|`]<Value>[['|"|`|]|WS]
 */

#define SKIP_TAG_WHITESPACE(ptr) while ((*ptr != '\0') && (apr_isspace (*ptr))) ptr++

#ifdef MOD_INCLUDE_REDESIGN
static void ap_ssi_get_tag_and_value(include_ctx_t *ctx, char **tag,
                                     char **tag_val, int dodecode)
{
    *tag_val = NULL;
    if (ctx->curr_tag_pos >= ctx->combined_tag + ctx->tag_length) {
        *tag = NULL;
        return;
    }

    *tag = ctx->curr_tag_pos;
    if (!**tag) {
        *tag = NULL;
        return;
    }

    *tag_val = ap_strchr(*tag, '=');
    if (!*tag_val) {
        return;
    }

    if (*tag_val == *tag) {
        *tag = NULL;
    }

    **tag_val = '\0';
    ++(*tag_val);
    ctx->curr_tag_pos = *tag_val + strlen(*tag_val) + 1;

    if (dodecode) {
        decodehtml(*tag_val);
    }

    return;
}
#endif /* MOD_INCLUDE_REDESIGN */

#ifndef MOD_INCLUDE_REDESIGN
static void ap_ssi_get_tag_and_value(include_ctx_t *ctx, char **tag,
                                     char **tag_val, int dodecode)
{
    char *c = ctx->curr_tag_pos;
    int   shift_val = 0; 
    char  term = '\0';

    *tag_val = NULL;
    if (ctx->curr_tag_pos > ctx->combined_tag + ctx->tag_length) {
        *tag = NULL;
        return;
    }
    SKIP_TAG_WHITESPACE(c);
    *tag = c;             /* First non-whitespace character (could be NULL). */

    while (apr_islower(*c)) {
        c++;  /* Optimization for the common case where the tag */
    }         /* is already lowercase */

    while ((*c != '=') && (!apr_isspace(*c)) && (*c != '\0')) {
        *c = apr_tolower(*c);    /* find end of tag, lowercasing as we go... */
        c++;
    }

    if ((*c == '\0') || (**tag == '=')) {
        if ((**tag == '\0') || (**tag == '=')) {
            *tag = NULL;
        }
        ctx->curr_tag_pos = c;
        return;                      /* We have found the end of the buffer. */
    }                       /* We might have a tag, but definitely no value. */

    if (*c == '=') {
        *c++ = '\0'; /* Overwrite the '=' with a terminating byte after tag. */
    }
    else {                               /* Try skipping WS to find the '='. */
        *c++ = '\0';                                 /* Terminate the tag... */
        SKIP_TAG_WHITESPACE(c);
        
        /* There needs to be an equal sign if there's a value. */
        if (*c != '=') {
            ctx->curr_tag_pos = c;
            return; /* There apparently was no value. */
        }
        else {
            c++; /* Skip the equals sign. */
        }
    }

    SKIP_TAG_WHITESPACE(c);
    if (*c == '"' || *c == '\'' || *c == '`') { 
        /* Allow quoted values for space inclusion. 
         * NOTE: This does not pass the quotes on return.
         */
        term = *c++;
    }
    
    *tag_val = c;
    if (!term) {
        while (!apr_isspace(*c) && (*c != '\0')) {
            c++;
        }
    }
    else {
        while ((*c != term) && (*c != '\0') && (*c != '\\')) {
            /* Quickly scan past the string until we reach
             * either the end of the tag or a backslash.  If
             * we find a backslash, we have to switch to the
             * more complicated parser loop that follows.
             */
            c++;
        }
        if (*c == '\\') {
            do {
                /* Accept \" (or ' or `) as valid quotation of string. 
                 */
                if (*c == '\\') {  
                    /* Overwrite the "\" during the embedded 
                     * escape sequence of '"'. "\'" or '`'. 
                     * Shift bytes from here to next delimiter.     
                     */
                    c++;
                    if (*c == term) {
                        shift_val++;
                    }
                    if (shift_val > 0) {
                        *(c-shift_val) = *c;
                    }
                    if (*c == '\0') {
                        break;
                    }
                }

                c++;
                if (shift_val > 0) {
                    *(c-shift_val) = *c;
                }
            } while ((*c != term) && (*c != '\0'));
        }
    }
    
    *(c-shift_val) = '\0'; /* Overwrites delimiter (term or WS) with NULL. */
    ctx->curr_tag_pos = ++c;
    if (dodecode) {
        decodehtml(*tag_val);
    }

    return;
}
#endif /* !MOD_INCLUDE_REDESIGN */

/* initial buffer size for power-of-two allocator in ap_ssi_parse_string */
#define PARSE_STRING_INITIAL_SIZE 64

/*
 * Do variable substitution on strings
 * (Note: If out==NULL, this function allocs a buffer for the resulting
 * string from r->pool.  The return value is the parsed string)
 */
static char *ap_ssi_parse_string(request_rec *r, include_ctx_t *ctx, 
                                 const char *in, char *out,
                                 apr_size_t length, int leave_name)
{
    char ch;
    char *next;
    char *end_out;
    apr_size_t out_size;

    /* allocate an output buffer if needed */
    if (!out) {
        out_size = PARSE_STRING_INITIAL_SIZE;
        if (out_size > length) {
            out_size = length;
        }
        out = apr_palloc(r->pool, out_size);
    }
    else {
        out_size = length;
    }

    /* leave room for nul terminator */
    end_out = out + out_size - 1;

    next = out;
    while ((ch = *in++) != '\0') {
        switch (ch) {
        case '\\':
            if (next == end_out) {
                if (out_size < length) {
                    /* double the buffer size */
                    apr_size_t new_out_size = out_size * 2;
                    apr_size_t current_length = next - out;
                    char *new_out;
                    if (new_out_size > length) {
                        new_out_size = length;
                    }
                    new_out = apr_palloc(r->pool, new_out_size);
                    memcpy(new_out, out, current_length);
                    out = new_out;
                    out_size = new_out_size;
                    end_out = out + out_size - 1;
                    next = out + current_length;
                }
                else {
                    /* truncated */
                    *next = '\0';
                    return out;
                }
            }
            if (*in == '$') {
                *next++ = *in++;
            }
            else {
                *next++ = ch;
            }
            break;
        case '$':
            {
                const char *start_of_var_name;
                char *end_of_var_name;        /* end of var name + 1 */
                const char *expansion, *temp_end, *val;
                char        tmp_store;
                apr_size_t l;

                /* guess that the expansion won't happen */
                expansion = in - 1;
                if (*in == '{') {
                    ++in;
                    start_of_var_name = in;
                    in = ap_strchr_c(in, '}');
                    if (in == NULL) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR,
                                      0, r, "Missing '}' on variable \"%s\"",
                                      expansion);
                        *next = '\0';
                        return out;
                    }
                    temp_end = in;
                    end_of_var_name = (char *)temp_end;
                    ++in;
                }
                else {
                    start_of_var_name = in;
                    while (apr_isalnum(*in) || *in == '_') {
                        ++in;
                    }
                    temp_end = in;
                    end_of_var_name = (char *)temp_end;
                }
                /* what a pain, too bad there's no table_getn where you can
                 * pass a non-nul terminated string */
                l = end_of_var_name - start_of_var_name;
                if (l != 0) {
                    tmp_store        = *end_of_var_name;
                    *end_of_var_name = '\0';
                    val = get_include_var(r, ctx, start_of_var_name);
                    *end_of_var_name = tmp_store;

                    if (val) {
                        expansion = val;
                        l = strlen(expansion);
                    }
                    else if (leave_name) {
                        l = in - expansion;
                    }
                    else {
                        /* no expansion to be done */
                        break;
                    }
                }
                else {
                    /* zero-length variable name causes just the $ to be 
                     * copied */
                    l = 1;
                }
                if ((next + l > end_out) && (out_size < length)) {
                    /* increase the buffer size to accommodate l more chars */
                    apr_size_t new_out_size = out_size;
                    apr_size_t current_length = next - out;
                    char *new_out;
                    do {
                        new_out_size *= 2;
                    } while (new_out_size < current_length + l);
                    if (new_out_size > length) {
                        new_out_size = length;
                    }
                    new_out = apr_palloc(r->pool, new_out_size);
                    memcpy(new_out, out, current_length);
                    out = new_out;
                    out_size = new_out_size;
                    end_out = out + out_size - 1;
                    next = out + current_length;
                }
                l = ((int)l > end_out - next) ? (end_out - next) : l;
                memcpy(next, expansion, l);
                next += l;
                break;
            }
        default:
            if (next == end_out) {
                if (out_size < length) {
                    /* double the buffer size */
                    apr_size_t new_out_size = out_size * 2;
                    apr_size_t current_length = next - out;
                    char *new_out;
                    if (new_out_size > length) {
                        new_out_size = length;
                    }
                    new_out = apr_palloc(r->pool, new_out_size);
                    memcpy(new_out, out, current_length);
                    out = new_out;
                    out_size = new_out_size;
                    end_out = out + out_size - 1;
                    next = out + current_length;
                }
                else {
                    /* truncated */
                    *next = '\0';
                    return out;
                }
            }
            *next++ = ch;
            break;
        }
    }
    *next = '\0';
    return out;
}

/* --------------------------- Action handlers ---------------------------- */

/* ensure that path is relative, and does not contain ".." elements
 * ensentially ensure that it does not match the regex:
 * (^/|(^|/)\.\.(/|$))
 * XXX: Simply replace with apr_filepath_merge                    
 */
static int is_only_below(const char *path)
{
#ifdef HAVE_DRIVE_LETTERS
    if (path[1] == ':') 
        return 0;
#endif
#ifdef NETWARE
    if (ap_strchr_c(path, ':'))
        return 0;
#endif
    if (path[0] == '/') {
        return 0;
    }
    while (*path) {
        int dots = 0;
        while (path[dots] == '.')
            ++dots;
#if defined(WIN32) 
        /* If the name is canonical this is redundant
         * but in security, redundancy is worthwhile.
         * Does OS2 belong here (accepts ... for ..)?
         */
        if (dots > 1 && (!path[dots] || path[dots] == '/'))
            return 0;
#else
        if (dots == 2 && (!path[dots] || path[dots] == '/'))
            return 0;
#endif
        path += dots;
        /* Advance to either the null byte at the end of the
         * string or the character right after the next slash,
         * whichever comes first
         */
        while (*path && (*path++ != '/')) {
            continue;
        }
    }
    return 1;
}

static int handle_include(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                         request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                         apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    apr_bucket  *tmp_buck;
    char *parsed_string;
    int loglevel = APLOG_ERR;

    *inserted_head = NULL;
    if (ctx->flags & FLAG_PRINTING) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 1);
            if (tag_val == NULL) {
                if (tag == NULL) {
                    return (0);
                }
                else {
                    return (1);
                }
            }
            if (!strcmp(tag, "virtual") || !strcmp(tag, "file")) {
                request_rec *rr = NULL;
                char *error_fmt = NULL;
                apr_status_t rc = APR_SUCCESS;

                SPLIT_AND_PASS_PRETAG_BUCKETS(*bb, ctx, f->next, rc);
                if (rc != APR_SUCCESS) {
                    return rc;
                }
 
                parsed_string = ap_ssi_parse_string(r, ctx, tag_val, NULL, 
                                                    MAX_STRING_LEN, 0);
                if (tag[0] == 'f') {
                    /* XXX: Port to apr_filepath_merge
                     * be safe; only files in this directory or below allowed 
                     */
                    if (!is_only_below(parsed_string)) {
                        error_fmt = "unable to include file \"%s\" "
                                    "in parsed file %s";
                    }
                    else {
                        rr = ap_sub_req_lookup_uri(parsed_string, r, f->next);
                    }
                }
                else {
                    rr = ap_sub_req_lookup_uri(parsed_string, r, f->next);
                }

                if (!error_fmt && rr->status != HTTP_OK) {
                    error_fmt = "unable to include \"%s\" in parsed file %s";
                }

                if (!error_fmt && (ctx->flags & FLAG_NO_EXEC) && 
                    rr->content_type && 
                    (strncmp(rr->content_type, "text/", 5))) {
                    error_fmt = "unable to include potential exec \"%s\" "
                        "in parsed file %s";
                }
                if (error_fmt == NULL) {
                    /* try to avoid recursive includes.  We do this by walking
                     * up the r->main list of subrequests, and at each level
                     * walking back through any internal redirects.  At each
                     * step, we compare the filenames and the URIs.  
                     *
                     * The filename comparison catches a recursive include
                     * with an ever-changing URL, eg.
                     * <!--#include virtual=
                     *      "$REQUEST_URI/$QUERY_STRING?$QUERY_STRING/x" -->
                     * which, although they would eventually be caught because
                     * we have a limit on the length of files, etc., can 
                     * recurse for a while.
                     *
                     * The URI comparison catches the case where the filename
                     * is changed while processing the request, so the 
                     * current name is never the same as any previous one.
                     * This can happen with "DocumentRoot /foo" when you
                     * request "/" on the server and it includes "/".
                     * This only applies to modules such as mod_dir that 
                     * (somewhat improperly) mess with r->filename outside 
                     * of a filename translation phase.
                     */
                    int founddupe = 0;
                    request_rec *p;
                    for (p = r; p != NULL && !founddupe; p = p->main) {
                        request_rec *q;
                        for (q = p; q != NULL; q = q->prev) {
                            if ((q->filename && rr->filename && 
                                (strcmp(q->filename, rr->filename) == 0)) ||
                                ((*q->uri == '/') && 
                                 (strcmp(q->uri, rr->uri) == 0)))
                            {
                                founddupe = 1;
                                break;
                            }
                        }
                    }

                    if (p != NULL) {
                        error_fmt = "Recursive include of \"%s\" "
                            "in parsed file %s";
                    }
                }

                /* See the Kludge in send_parsed_file for why */
                /* Basically, it puts a bread crumb in here, then looks */
                /*   for the crumb later to see if its been here.       */
                if (rr) 
                    ap_set_module_config(rr->request_config, 
                                         &include_module, r);

                if (!error_fmt && ap_run_sub_req(rr)) {
                    error_fmt = "unable to include \"%s\" in parsed file %s";
                }
                if (error_fmt) {
                    ap_log_rerror(APLOG_MARK, loglevel,
                                  0, r, error_fmt, tag_val, r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                }

                /* destroy the sub request */
                if (rr != NULL) {
                    ap_destroy_sub_req(rr);
                }
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "unknown parameter \"%s\" to tag include in %s",
                            tag, r->filename);
                CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
            }
        }
    }
    return 0;
}


static int handle_echo(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                       request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                       apr_bucket **inserted_head)
{
    char       *tag       = NULL;
    char       *tag_val   = NULL;
    const char *echo_text = NULL;
    apr_bucket  *tmp_buck;
    apr_size_t e_len;
    enum {E_NONE, E_URL, E_ENTITY} encode;

    encode = E_ENTITY;

    *inserted_head = NULL;
    if (ctx->flags & FLAG_PRINTING) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 1);
            if (tag_val == NULL) {
                if (tag != NULL) {
                    return 1;
                }
                else {
                    return 0;
                }
            }
            if (!strcmp(tag, "var")) {
                conn_rec *c = r->connection;
                const char *val =
                    get_include_var(r, ctx,
                                    ap_ssi_parse_string(r, ctx, tag_val, NULL,
                                                        MAX_STRING_LEN, 0));
                if (val) {
                    switch(encode) {
                    case E_NONE:   
                        echo_text = val;
                        break;
                    case E_URL:
                        echo_text = ap_escape_uri(r->pool, val);  
                        break;
                    case E_ENTITY: 
                        echo_text = ap_escape_html(r->pool, val); 
                        break;
                    }

                    e_len = strlen(echo_text);
                    tmp_buck = apr_bucket_pool_create(echo_text, e_len,
                                                      r->pool, c->bucket_alloc);
                }
                else {
                    include_server_config *sconf= 
                        ap_get_module_config(r->server->module_config,
                                             &include_module);
                    tmp_buck = apr_bucket_pool_create(sconf->undefinedEcho, 
                                                      sconf->undefinedEchoLen,
                                                      r->pool, c->bucket_alloc);
                }
                APR_BUCKET_INSERT_BEFORE(head_ptr, tmp_buck);
                if (*inserted_head == NULL) {
                    *inserted_head = tmp_buck;
                }
            }
            else if (!strcmp(tag, "encoding")) {
                if (!strcasecmp(tag_val, "none")) encode = E_NONE;
                else if (!strcasecmp(tag_val, "url")) encode = E_URL;
                else if (!strcasecmp(tag_val, "entity")) encode = E_ENTITY;
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                           "unknown value \"%s\" to parameter \"encoding\" of "
                           "tag echo in %s", tag_val, r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                }
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "unknown parameter \"%s\" in tag echo of %s",
                            tag, r->filename);
                CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
            }

        }
    }
    return 0;
}

/* error and tf must point to a string with room for at 
 * least MAX_STRING_LEN characters 
 */
static int handle_config(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                         request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                         apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    char *parsed_string;
    apr_table_t *env = r->subprocess_env;

    *inserted_head = NULL;
    if (ctx->flags & FLAG_PRINTING) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 0);
            if (tag_val == NULL) {
                if (tag == NULL) {
                    return 0;  /* Reached the end of the string. */
                }
                else {
                    return 1;  /* tags must have values. */
                }
            }
            if (!strcmp(tag, "errmsg")) {
                if (ctx->error_str_override == NULL) {
                    ctx->error_str_override = (char *)apr_palloc(ctx->pool,
                                                              MAX_STRING_LEN);
                    ctx->error_str = ctx->error_str_override;
                }
                ap_ssi_parse_string(r, ctx, tag_val, ctx->error_str_override,
                                    MAX_STRING_LEN, 0);
            }
            else if (!strcmp(tag, "timefmt")) {
                apr_time_t date = r->request_time;
                if (ctx->time_str_override == NULL) {
                    ctx->time_str_override = (char *)apr_palloc(ctx->pool,
                                                              MAX_STRING_LEN);
                    ctx->time_str = ctx->time_str_override;
                }
                ap_ssi_parse_string(r, ctx, tag_val, ctx->time_str_override,
                                    MAX_STRING_LEN, 0);
                apr_table_setn(env, "DATE_LOCAL", ap_ht_time(r->pool, date, 
                               ctx->time_str, 0));
                apr_table_setn(env, "DATE_GMT", ap_ht_time(r->pool, date, 
                               ctx->time_str, 1));
                apr_table_setn(env, "LAST_MODIFIED",
                               ap_ht_time(r->pool, r->finfo.mtime, 
                               ctx->time_str, 0));
            }
            else if (!strcmp(tag, "sizefmt")) {
                parsed_string = ap_ssi_parse_string(r, ctx, tag_val, NULL, 
                                                    MAX_STRING_LEN, 0);
                decodehtml(parsed_string);
                if (!strcmp(parsed_string, "bytes")) {
                    ctx->flags |= FLAG_SIZE_IN_BYTES;
                }
                else if (!strcmp(parsed_string, "abbrev")) {
                    ctx->flags &= FLAG_SIZE_ABBREV;
                }
            }
            else {
                apr_bucket *tmp_buck;

                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "unknown parameter \"%s\" to tag config in %s",
                              tag, r->filename);
                CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
            }
        }
    }
    return 0;
}


static int find_file(request_rec *r, const char *directive, const char *tag,
                     char *tag_val, apr_finfo_t *finfo)
{
    char *to_send = tag_val;
    request_rec *rr = NULL;
    int ret=0;
    char *error_fmt = NULL;
    apr_status_t rv = APR_SUCCESS;

    if (!strcmp(tag, "file")) {
        /* XXX: Port to apr_filepath_merge
         * be safe; only files in this directory or below allowed 
         */
        if (!is_only_below(tag_val)) {
            error_fmt = "unable to access file \"%s\" "
                        "in parsed file %s";
        }
        else {
            ap_getparents(tag_val);    /* get rid of any nasties */

            /* note: it is okay to pass NULL for the "next filter" since
               we never attempt to "run" this sub request. */
            rr = ap_sub_req_lookup_file(tag_val, r, NULL);

            if (rr->status == HTTP_OK && rr->finfo.filetype != 0) {
                to_send = rr->filename;
                if ((rv = apr_stat(finfo, to_send, 
                    APR_FINFO_GPROT | APR_FINFO_MIN, rr->pool)) != APR_SUCCESS
                    && rv != APR_INCOMPLETE) {
                    error_fmt = "unable to get information about \"%s\" "
                        "in parsed file %s";
                }
            }
            else {
                error_fmt = "unable to lookup information about \"%s\" "
                            "in parsed file %s";
            }
        }

        if (error_fmt) {
            ret = -1;
            ap_log_rerror(APLOG_MARK, APLOG_ERR,
                          rv, r, error_fmt, to_send, r->filename);
        }

        if (rr) ap_destroy_sub_req(rr);
        
        return ret;
    }
    else if (!strcmp(tag, "virtual")) {
        /* note: it is okay to pass NULL for the "next filter" since
           we never attempt to "run" this sub request. */
        rr = ap_sub_req_lookup_uri(tag_val, r, NULL);

        if (rr->status == HTTP_OK && rr->finfo.filetype != 0) {
            memcpy((char *) finfo, (const char *) &rr->finfo,
                   sizeof(rr->finfo));
            ap_destroy_sub_req(rr);
            return 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "unable to get information about \"%s\" "
                        "in parsed file %s",
                        tag_val, r->filename);
            ap_destroy_sub_req(rr);
            return -1;
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "unknown parameter \"%s\" to tag %s in %s",
                    tag, directive, r->filename);
        return -1;
    }
}

static int handle_fsize(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                        request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                        apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    apr_finfo_t  finfo;
    apr_size_t  s_len;
    apr_bucket   *tmp_buck;
    char *parsed_string;

    *inserted_head = NULL;
    if (ctx->flags & FLAG_PRINTING) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 1);
            if (tag_val == NULL) {
                if (tag == NULL) {
                    return 0;
                }
                else {
                    return 1;
                }
            }
            else {
                parsed_string = ap_ssi_parse_string(r, ctx, tag_val, NULL, 
                                                    MAX_STRING_LEN, 0);
                if (!find_file(r, "fsize", tag, parsed_string, &finfo)) {
                    /* XXX: if we *know* we're going to have to copy the
                     * thing off of the stack anyway, why not palloc buff
                     * instead of sticking it on the stack; then we can just
                     * use a pool bucket and skip the copy
                     */
                    char buff[50];

                    if (!(ctx->flags & FLAG_SIZE_IN_BYTES)) {
                        apr_strfsize(finfo.size, buff);
                        s_len = strlen (buff);
                    }
                    else {
                        int l, x, pos = 0;
                        char tmp_buff[50];

                        apr_snprintf(tmp_buff, sizeof(tmp_buff), 
                                     "%" APR_OFF_T_FMT, finfo.size);
                        l = strlen(tmp_buff);    /* grrr */
                        for (x = 0; x < l; x++) {
                            if (x && (!((l - x) % 3))) {
                                buff[pos++] = ',';
                            }
                            buff[pos++] = tmp_buff[x];
                        }
                        buff[pos] = '\0';
                        s_len = pos;
                    }

                    tmp_buck = apr_bucket_heap_create(buff, s_len, NULL,
                                                  r->connection->bucket_alloc);
                    APR_BUCKET_INSERT_BEFORE(head_ptr, tmp_buck);
                    if (*inserted_head == NULL) {
                        *inserted_head = tmp_buck;
                    }
                }
                else {
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                }
            }
        }
    }
    return 0;
}

static int handle_flastmod(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                           request_rec *r, ap_filter_t *f, 
                           apr_bucket *head_ptr, apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    apr_finfo_t  finfo;
    apr_size_t  t_len;
    apr_bucket   *tmp_buck;
    char *parsed_string;

    *inserted_head = NULL;
    if (ctx->flags & FLAG_PRINTING) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 1);
            if (tag_val == NULL) {
                if (tag == NULL) {
                    return 0;
                }
                else {
                    return 1;
                }
            }
            else {
                parsed_string = ap_ssi_parse_string(r, ctx, tag_val, NULL, 
                                                    MAX_STRING_LEN, 0);
                if (!find_file(r, "flastmod", tag, parsed_string, &finfo)) {
                    char *t_val;

                    t_val = ap_ht_time(r->pool, finfo.mtime, ctx->time_str, 0);
                    t_len = strlen(t_val);

                    tmp_buck = apr_bucket_pool_create(t_val, t_len, r->pool,
                                                  r->connection->bucket_alloc);
                    APR_BUCKET_INSERT_BEFORE(head_ptr, tmp_buck);
                    if (*inserted_head == NULL) {
                        *inserted_head = tmp_buck;
                    }
                }
                else {
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                }
            }
        }
    }
    return 0;
}

static int re_check(request_rec *r, include_ctx_t *ctx, 
                    char *string, char *rexp)
{
    regex_t *compiled;
    const apr_size_t nres = sizeof(*ctx->re_result) / sizeof(regmatch_t);
    int regex_error;

    compiled = ap_pregcomp(r->pool, rexp, REG_EXTENDED | REG_NOSUB);
    if (compiled == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "unable to compile pattern \"%s\"", rexp);
        return -1;
    }
    if (!ctx->re_result) {
        ctx->re_result = apr_pcalloc(r->pool, sizeof(*ctx->re_result));
    }
    ctx->re_string = string;
    regex_error = ap_regexec(compiled, string, nres, *ctx->re_result, 0);
    ap_pregfree(r->pool, compiled);
    return (!regex_error);
}

enum token_type {
    token_string, token_re,
    token_and, token_or, token_not, token_eq, token_ne,
    token_rbrace, token_lbrace, token_group,
    token_ge, token_le, token_gt, token_lt
};
struct token {
    enum token_type type;
    char* value;
};

static const char *get_ptoken(request_rec *r, const char *string, 
                              struct token *token, int *unmatched)
{
    char ch;
    int next = 0;
    char qs = 0;
    int tkn_fnd = 0;

    token->value = NULL;

    /* Skip leading white space */
    if (string == (char *) NULL) {
        return (char *) NULL;
    }
    while ((ch = *string++)) {
        if (!apr_isspace(ch)) {
            break;
        }
    }
    if (ch == '\0') {
        return (char *) NULL;
    }

    token->type = token_string; /* the default type */
    switch (ch) {
    case '(':
        token->type = token_lbrace;
        return (string);
    case ')':
        token->type = token_rbrace;
        return (string);
    case '=':
        token->type = token_eq;
        return (string);
    case '!':
        if (*string == '=') {
            token->type = token_ne;
            return (string + 1);
        }
        else {
            token->type = token_not;
            return (string);
        }
    case '\'':
        /* already token->type == token_string */
        qs = '\'';
        break;
    case '/':
        token->type = token_re;
        qs = '/';
        break;
    case '|':
        if (*string == '|') {
            token->type = token_or;
            return (string + 1);
        }
        break;
    case '&':
        if (*string == '&') {
            token->type = token_and;
            return (string + 1);
        }
        break;
    case '>':
        if (*string == '=') {
            token->type = token_ge;
            return (string + 1);
        }
        else {
            token->type = token_gt;
            return (string);
        }
    case '<':
        if (*string == '=') {
            token->type = token_le;
            return (string + 1);
        }
        else {
            token->type = token_lt;
            return (string);
        }
    default:
        /* already token->type == token_string */
        break;
    }
    /* We should only be here if we are in a string */
    token->value = apr_palloc(r->pool, strlen(string) + 2); /* 2 for ch plus
                                                               trailing null */
    if (!qs) {
        token->value[next++] = ch;
    }

    /* 
     * I used the ++string throughout this section so that string
     * ends up pointing to the next token and I can just return it
     */
    for (ch = *string; ((ch != '\0') && (!tkn_fnd)); ch = *++string) {
        if (ch == '\\') {
            if ((ch = *++string) == '\0') {
                tkn_fnd = 1;
            }
            else {
                token->value[next++] = ch;
            }
        }
        else {
            if (!qs) {
                if (apr_isspace(ch)) {
                    tkn_fnd = 1;
                }
                else {
                    switch (ch) {
                    case '(':
                    case ')':
                    case '=':
                    case '!':
                    case '<':
                    case '>':
                        tkn_fnd = 1;
                        break;
                    case '|':
                        if (*(string + 1) == '|') {
                            tkn_fnd = 1;
                        }
                        break;
                    case '&':
                        if (*(string + 1) == '&') {
                            tkn_fnd = 1;
                        }
                        break;
                    }
                    if (!tkn_fnd) {
                        token->value[next++] = ch;
                    }
                }
            }
            else {
                if (ch == qs) {
                    qs = 0;
                    tkn_fnd = 1;
                    string++;
                }
                else {
                    token->value[next++] = ch;
                }
            }
        }
        if (tkn_fnd) {
            break;
        }
    }

    /* If qs is still set, we have an unmatched quote */
    if (qs) {
        *unmatched = 1;
        next = 0;
    }
    token->value[next] = '\0';

    return (string);
}


/* there is an implicit assumption here that expr is at most MAX_STRING_LEN-1
 * characters long...
 */
static int parse_expr(request_rec *r, include_ctx_t *ctx, const char *expr,
                      int *was_error, int *was_unmatched, char *debug)
{
    struct parse_node {
        struct parse_node *left, *right, *parent;
        struct token token;
        int value, done;
    } *root, *current, *new;
    const char *parse;
    char* buffer;
    int retval = 0;
    apr_size_t debug_pos = 0;

    debug[debug_pos] = '\0';
    *was_error       = 0;
    *was_unmatched   = 0;
    if ((parse = expr) == (char *) NULL) {
        return (0);
    }
    root = current = (struct parse_node *) NULL;

    /* Create Parse Tree */
    while (1) {
        new = (struct parse_node *) apr_palloc(r->pool,
                                           sizeof(struct parse_node));
        new->parent = new->left = new->right = (struct parse_node *) NULL;
        new->done = 0;
        if ((parse = get_ptoken(r, parse, &new->token, was_unmatched)) == 
            (char *) NULL) {
            break;
        }
        switch (new->token.type) {

        case token_string:
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], 
                                  "     Token: string (%s)\n", 
                                  new->token.value);
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            switch (current->token.type) {
            case token_string:
                current->token.value = apr_pstrcat(r->pool,
                                                   current->token.value,
                                                   current->token.value[0] ? " " : "",
                                                   new->token.value,
                                                   NULL);
                                                   
                break;
            case token_eq:
            case token_ne:
            case token_and:
            case token_or:
            case token_lbrace:
            case token_not:
            case token_ge:
            case token_gt:
            case token_le:
            case token_lt:
                new->parent = current;
                current = current->right = new;
                break;
            default:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            break;

        case token_re:
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], 
                                  "     Token: regex (%s)\n", 
                                  new->token.value);
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            switch (current->token.type) {
            case token_eq:
            case token_ne:
            case token_and:
            case token_or:
            case token_lbrace:
            case token_not:
                new->parent = current;
                current = current->right = new;
                break;
            default:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            break;

        case token_and:
        case token_or:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Token: and/or\n",
                    sizeof ("     Token: and/or\n"));
            debug_pos += sizeof ("     Token: and/or\n");
#endif
            if (current == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            /* Percolate upwards */
            while (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_string:
                case token_re:
                case token_group:
                case token_not:
                case token_eq:
                case token_ne:
                case token_and:
                case token_or:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                    current = current->parent;
                    continue;
                case token_lbrace:
                    break;
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "Invalid expression \"%s\" in file %s",
                                expr, r->filename);
                    *was_error = 1;
                    return retval;
                }
                break;
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;

        case token_not:
#ifdef DEBUG_INCLUDE
            memcpy(&debug[debug_pos], "     Token: not\n",
                    sizeof("     Token: not\n"));
            debug_pos += sizeof("     Token: not\n");
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            /* Percolate upwards */
            if (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_not:
                case token_eq:
                case token_ne:
                case token_and:
                case token_or:
                case token_lbrace:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                    break;
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "Invalid expression \"%s\" in file %s",
                                  expr, r->filename);
                    *was_error = 1;
                    return retval;
                }
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;

        case token_eq:
        case token_ne:
        case token_ge:
        case token_gt:
        case token_le:
        case token_lt:
#ifdef DEBUG_INCLUDE
            memcpy(&debug[debug_pos], "     Token: eq/ne/ge/gt/le/lt\n",
                    sizeof("     Token: eq/ne/ge/gt/le/lt\n"));
            debug_pos += sizeof("     Token: eq/ne/ge/gt/le/lt\n");
#endif
            if (current == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Invalid expression \"%s\" in file %s",
                              expr, r->filename);
                *was_error = 1;
                return retval;
            }
            /* Percolate upwards */
            while (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_string:
                case token_re:
                case token_group:
                    current = current->parent;
                    continue;
                case token_lbrace:
                case token_and:
                case token_or:
                    break;
                case token_not:
                case token_eq:
                case token_ne:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "Invalid expression \"%s\" in file %s",
                                expr, r->filename);
                    *was_error = 1;
                    return retval;
                }
                break;
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;

        case token_rbrace:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Token: rbrace\n",
                    sizeof ("     Token: rbrace\n"));
            debug_pos += sizeof ("     Token: rbrace\n");
#endif
            while (current != (struct parse_node *) NULL) {
                if (current->token.type == token_lbrace) {
                    current->token.type = token_group;
                    break;
                }
                current = current->parent;
            }
            if (current == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Unmatched ')' in \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            break;

        case token_lbrace:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Token: lbrace\n",
                    sizeof ("     Token: lbrace\n"));
            debug_pos += sizeof ("     Token: lbrace\n");
#endif
            if (current == (struct parse_node *) NULL) {
                root = current = new;
                break;
            }
            /* Percolate upwards */
            if (current != (struct parse_node *) NULL) {
                switch (current->token.type) {
                case token_not:
                case token_eq:
                case token_ne:
                case token_and:
                case token_or:
                case token_lbrace:
                case token_ge:
                case token_gt:
                case token_le:
                case token_lt:
                    break;
                case token_string:
                case token_re:
                case token_group:
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "Invalid expression \"%s\" in file %s",
                                expr, r->filename);
                    *was_error = 1;
                    return retval;
                }
            }
            if (current == (struct parse_node *) NULL) {
                new->left = root;
                new->left->parent = new;
                new->parent = (struct parse_node *) NULL;
                root = new;
            }
            else {
                new->left = current->right;
                current->right = new;
                new->parent = current;
            }
            current = new;
            break;
        default:
            break;
        }
    }

    /* Evaluate Parse Tree */
    current = root;
    while (current != (struct parse_node *) NULL) {
        switch (current->token.type) {
        case token_string:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Evaluate string\n",
                    sizeof ("     Evaluate string\n"));
            debug_pos += sizeof ("     Evaluate string\n");
#endif
            buffer = ap_ssi_parse_string(r, ctx, current->token.value, NULL, 
                                         MAX_STRING_LEN, 0);
            current->token.value = buffer;
            current->value = (current->token.value[0] != '\0');
            current->done = 1;
            current = current->parent;
            break;

        case token_re:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "No operator before regex of expr \"%s\" in file %s",
                          expr, r->filename);
            *was_error = 1;
            return retval;

        case token_and:
        case token_or:
#ifdef DEBUG_INCLUDE
            memcpy(&debug[debug_pos], "     Evaluate and/or\n",
                    sizeof("     Evaluate and/or\n"));
            debug_pos += sizeof("     Evaluate and/or\n");
#endif
            if (current->left  == (struct parse_node *) NULL ||
                current->right == (struct parse_node *) NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Invalid expression \"%s\" in file %s",
                              expr, r->filename);
                *was_error = 1;
                return retval;
            }
            if (!current->left->done) {
                switch (current->left->token.type) {
                case token_string:
                    buffer = ap_ssi_parse_string(r, ctx, current->left->token.value,
                                                 NULL, MAX_STRING_LEN, 0);
                    current->left->token.value = buffer;
                    current->left->value = 
                                       (current->left->token.value[0] != '\0');
                    current->left->done = 1;
                    break;
                default:
                    current = current->left;
                    continue;
                }
            }
            if (!current->right->done) {
                switch (current->right->token.type) {
                case token_string:
                    buffer = ap_ssi_parse_string(r, ctx, current->right->token.value,
                                                 NULL, MAX_STRING_LEN, 0);
                    current->right->token.value = buffer;
                    current->right->value = 
                                      (current->right->token.value[0] != '\0');
                    current->right->done = 1;
                    break;
                default:
                    current = current->right;
                    continue;
                }
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Left: %c\n",
                                  current->left->value ? '1' : '0');
            debug_pos += sprintf (&debug[debug_pos], "     Right: %c\n",
                                  current->right->value ? '1' : '0');
#endif
            if (current->token.type == token_and) {
                current->value = current->left->value && current->right->value;
            }
            else {
                current->value = current->left->value || current->right->value;
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Returning %c\n",
                                  current->value ? '1' : '0');
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_eq:
        case token_ne:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Evaluate eq/ne\n",
                    sizeof ("     Evaluate eq/ne\n"));
            debug_pos += sizeof ("     Evaluate eq/ne\n");
#endif
            if ((current->left == (struct parse_node *) NULL) ||
                (current->right == (struct parse_node *) NULL) ||
                (current->left->token.type != token_string) ||
                ((current->right->token.type != token_string) &&
                 (current->right->token.type != token_re))) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            buffer = ap_ssi_parse_string(r, ctx, current->left->token.value,
                                         NULL, MAX_STRING_LEN, 0);
            current->left->token.value = buffer;
            buffer = ap_ssi_parse_string(r, ctx, current->right->token.value,
                                         NULL, MAX_STRING_LEN, 0);
            current->right->token.value = buffer;
            if (current->right->token.type == token_re) {
#ifdef DEBUG_INCLUDE
                debug_pos += sprintf (&debug[debug_pos],
                                      "     Re Compare (%s) with /%s/\n",
                                      current->left->token.value,
                                      current->right->token.value);
#endif
                current->value =
                    re_check(r, ctx, current->left->token.value,
                             current->right->token.value);
            }
            else {
#ifdef DEBUG_INCLUDE
                debug_pos += sprintf (&debug[debug_pos],
                                      "     Compare (%s) with (%s)\n",
                                      current->left->token.value,
                                      current->right->token.value);
#endif
                current->value =
                    (strcmp(current->left->token.value,
                            current->right->token.value) == 0);
            }
            if (current->token.type == token_ne) {
                current->value = !current->value;
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Returning %c\n",
                                  current->value ? '1' : '0');
#endif
            current->done = 1;
            current = current->parent;
            break;
        case token_ge:
        case token_gt:
        case token_le:
        case token_lt:
#ifdef DEBUG_INCLUDE
            memcpy (&debug[debug_pos], "     Evaluate ge/gt/le/lt\n",
                    sizeof ("     Evaluate ge/gt/le/lt\n"));
            debug_pos += sizeof ("     Evaluate ge/gt/le/lt\n");
#endif
            if ((current->left == (struct parse_node *) NULL) ||
                (current->right == (struct parse_node *) NULL) ||
                (current->left->token.type != token_string) ||
                (current->right->token.type != token_string)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                *was_error = 1;
                return retval;
            }
            buffer = ap_ssi_parse_string(r, ctx, current->left->token.value,
                                         NULL, MAX_STRING_LEN, 0);
            current->left->token.value = buffer;
            buffer = ap_ssi_parse_string(r, ctx, current->right->token.value,
                                         NULL, MAX_STRING_LEN, 0);
            current->right->token.value = buffer;
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos],
                                  "     Compare (%s) with (%s)\n",
                                  current->left->token.value,
                                  current->right->token.value);
#endif
            current->value =
                strcmp(current->left->token.value,
                       current->right->token.value);
            if (current->token.type == token_ge) {
                current->value = current->value >= 0;
            }
            else if (current->token.type == token_gt) {
                current->value = current->value > 0;
            }
            else if (current->token.type == token_le) {
                current->value = current->value <= 0;
            }
            else if (current->token.type == token_lt) {
                current->value = current->value < 0;
            }
            else {
                current->value = 0;     /* Don't return -1 if unknown token */
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Returning %c\n",
                                  current->value ? '1' : '0');
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_not:
            if (current->right != (struct parse_node *) NULL) {
                if (!current->right->done) {
                    current = current->right;
                    continue;
                }
                current->value = !current->right->value;
            }
            else {
                current->value = 0;
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Evaluate !: %c\n",
                                  current->value ? '1' : '0');
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_group:
            if (current->right != (struct parse_node *) NULL) {
                if (!current->right->done) {
                    current = current->right;
                    continue;
                }
                current->value = current->right->value;
            }
            else {
                current->value = 1;
            }
#ifdef DEBUG_INCLUDE
            debug_pos += sprintf (&debug[debug_pos], "     Evaluate (): %c\n",
                                  current->value ? '1' : '0');
#endif
            current->done = 1;
            current = current->parent;
            break;

        case token_lbrace:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "Unmatched '(' in \"%s\" in file %s",
                        expr, r->filename);
            *was_error = 1;
            return retval;

        case token_rbrace:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "Unmatched ')' in \"%s\" in file %s",
                        expr, r->filename);
            *was_error = 1;
            return retval;

        default:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "bad token type");
            *was_error = 1;
            return retval;
        }
    }

    retval = (root == (struct parse_node *) NULL) ? 0 : root->value;
    return (retval);
}

/*-------------------------------------------------------------------------*/
#ifdef DEBUG_INCLUDE

#define MAX_DEBUG_SIZE MAX_STRING_LEN
#define LOG_COND_STATUS(cntx, t_buck, h_ptr, ins_head, tag_text)           \
{                                                                          \
    char cond_txt[] = "**** X     conditional_status=\"0\"\n";             \
                                                                           \
    if (cntx->flags & FLAG_COND_TRUE) {                                    \
        cond_txt[31] = '1';                                                \
    }                                                                      \
    memcpy(&cond_txt[5], tag_text, sizeof(tag_text)-1);                    \
    t_buck = apr_bucket_heap_create(cond_txt, sizeof(cond_txt)-1,          \
                                    NULL, h_ptr->list);                    \
    APR_BUCKET_INSERT_BEFORE(h_ptr, t_buck);                               \
                                                                           \
    if (ins_head == NULL) {                                                \
        ins_head = t_buck;                                                 \
    }                                                                      \
}
#define DUMP_PARSE_EXPR_DEBUG(t_buck, h_ptr, d_buf, ins_head)            \
{                                                                        \
    if (d_buf[0] != '\0') {                                              \
        t_buck = apr_bucket_heap_create(d_buf, strlen(d_buf),            \
                                        NULL, h_ptr->list);              \
        APR_BUCKET_INSERT_BEFORE(h_ptr, t_buck);                         \
                                                                         \
        if (ins_head == NULL) {                                          \
            ins_head = t_buck;                                           \
        }                                                                \
    }                                                                    \
}
#else

#define MAX_DEBUG_SIZE 10
#define LOG_COND_STATUS(cntx, t_buck, h_ptr, ins_head, tag_text)
#define DUMP_PARSE_EXPR_DEBUG(t_buck, h_ptr, d_buf, ins_head)

#endif
/*-------------------------------------------------------------------------*/

/* pjr - These seem to allow expr="fred" expr="joe" where joe overwrites fred. */
static int handle_if(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                     request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                     apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    char *expr    = NULL;
    int   expr_ret, was_error, was_unmatched;
    apr_bucket *tmp_buck;
    char debug_buf[MAX_DEBUG_SIZE];

    *inserted_head = NULL;
    if (!(ctx->flags & FLAG_PRINTING)) {
        ctx->if_nesting_level++;
    }
    else {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 0);
            if (tag == NULL) {
                if (expr == NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "missing expr in if statement: %s", 
                                  r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return 1;
                }
                expr_ret = parse_expr(r, ctx, expr, &was_error, 
                                      &was_unmatched, debug_buf);
                if (was_error) {
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return 1;
                }
                if (was_unmatched) {
                    DUMP_PARSE_EXPR_DEBUG(tmp_buck, head_ptr, 
                                          "\nUnmatched '\n", *inserted_head);
                }
                DUMP_PARSE_EXPR_DEBUG(tmp_buck, head_ptr, debug_buf, 
                                      *inserted_head);
                
                if (expr_ret) {
                    ctx->flags |= (FLAG_PRINTING | FLAG_COND_TRUE);
                }
                else {
                    ctx->flags &= FLAG_CLEAR_PRINT_COND;
                }
                LOG_COND_STATUS(ctx, tmp_buck, head_ptr, *inserted_head, 
                                "   if");
                ctx->if_nesting_level = 0;
                return 0;
            }
            else if (!strcmp(tag, "expr")) {
                expr = tag_val;
#ifdef DEBUG_INCLUDE
                if (1) {
                    apr_size_t d_len = 0;
                    d_len = sprintf(debug_buf, "**** if expr=\"%s\"\n", expr);
                    tmp_buck = apr_bucket_heap_create(debug_buf, d_len, NULL,
                                                  r->connection->bucket_alloc);
                    APR_BUCKET_INSERT_BEFORE(head_ptr, tmp_buck);

                    if (*inserted_head == NULL) {
                        *inserted_head = tmp_buck;
                    }
                }
#endif
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "unknown parameter \"%s\" to tag if in %s", tag, 
                            r->filename);
                CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
            }

        }
    }
    return 0;
}

static int handle_elif(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                       request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                       apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    char *expr    = NULL;
    int   expr_ret, was_error, was_unmatched;
    apr_bucket *tmp_buck;
    char debug_buf[MAX_DEBUG_SIZE];

    *inserted_head = NULL;
    if (!ctx->if_nesting_level) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 0);
            if (tag == '\0') {
                LOG_COND_STATUS(ctx, tmp_buck, head_ptr, *inserted_head, 
                                " elif");
                
                if (ctx->flags & FLAG_COND_TRUE) {
                    ctx->flags &= FLAG_CLEAR_PRINTING;
                    return (0);
                }
                if (expr == NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "missing expr in elif statement: %s", 
                                  r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return (1);
                }
                expr_ret = parse_expr(r, ctx, expr, &was_error, 
                                      &was_unmatched, debug_buf);
                if (was_error) {
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return 1;
                }
                if (was_unmatched) {
                    DUMP_PARSE_EXPR_DEBUG(tmp_buck, head_ptr, 
                                          "\nUnmatched '\n", *inserted_head);
                }
                DUMP_PARSE_EXPR_DEBUG(tmp_buck, head_ptr, debug_buf, 
                                      *inserted_head);
                
                if (expr_ret) {
                    ctx->flags |= (FLAG_PRINTING | FLAG_COND_TRUE);
                }
                else {
                    ctx->flags &= FLAG_CLEAR_PRINT_COND;
                }
                LOG_COND_STATUS(ctx, tmp_buck, head_ptr, *inserted_head, 
                                " elif");
                return (0);
            }
            else if (!strcmp(tag, "expr")) {
                expr = tag_val;
#ifdef DEBUG_INCLUDE
                if (1) {
                    apr_size_t d_len = 0;
                    d_len = sprintf(debug_buf, "**** elif expr=\"%s\"\n", expr);
                    tmp_buck = apr_bucket_heap_create(debug_buf, d_len, NULL,
                                                  r->connection->bucket_alloc);
                    APR_BUCKET_INSERT_BEFORE(head_ptr, tmp_buck);

                    if (*inserted_head == NULL) {
                        *inserted_head = tmp_buck;
                    }
                }
#endif
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                               "unknown parameter \"%s\" to tag if in %s", tag, 
                               r->filename);
                CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
            }
        }
    }
    return 0;
}

static int handle_else(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                       request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                       apr_bucket **inserted_head)
{
    char *tag = NULL;
    char *tag_val = NULL;
    apr_bucket *tmp_buck;

    *inserted_head = NULL;
    if (!ctx->if_nesting_level) {
        ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 1);
        if ((tag != NULL) || (tag_val != NULL)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "else directive does not take tags in %s", r->filename);
            if (ctx->flags & FLAG_PRINTING) {
                CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
            }
            return -1;
        }
        else {
            LOG_COND_STATUS(ctx, tmp_buck, head_ptr, *inserted_head, " else");
            
            if (ctx->flags & FLAG_COND_TRUE) {
                ctx->flags &= FLAG_CLEAR_PRINTING;
            }
            else {
                ctx->flags |= (FLAG_PRINTING | FLAG_COND_TRUE);
            }
            return 0;
        }
    }
    return 0;
}

static int handle_endif(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                        request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                        apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    apr_bucket *tmp_buck;

    *inserted_head = NULL;
    if (!ctx->if_nesting_level) {
        ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 1);
        if ((tag != NULL) || (tag_val != NULL)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                       "endif directive does not take tags in %s", r->filename);
            CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
            return -1;
        }
        else {
            LOG_COND_STATUS(ctx, tmp_buck, head_ptr, *inserted_head, "endif");
            ctx->flags |= (FLAG_PRINTING | FLAG_COND_TRUE);
            return 0;
        }
    }
    else {
        ctx->if_nesting_level--;
        return 0;
    }
}

static int handle_set(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                      request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                      apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    char *var     = NULL;
    apr_bucket *tmp_buck;
    char *parsed_string;
    request_rec *sub = r->main;
    apr_pool_t *p = r->pool;

    /* we need to use the 'main' request pool to set notes as that is 
     * a notes lifetime
     */
    while (sub) {
        p = sub->pool;
        sub = sub->main;
    }

    *inserted_head = NULL;
    if (ctx->flags & FLAG_PRINTING) {
        while (1) {
            ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 1);
            if ((tag == NULL) && (tag_val == NULL)) {
                return 0;
            }
            else if (tag_val == NULL) {
                return 1;
            }
            else if (!strcmp(tag, "var")) {
                var = ap_ssi_parse_string(r, ctx, tag_val, NULL,
                                          MAX_STRING_LEN, 0);
            }
            else if (!strcmp(tag, "value")) {
                if (var == (char *) NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                           "variable must precede value in set directive in %s",
                           r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return (-1);
                }
                parsed_string = ap_ssi_parse_string(r, ctx, tag_val, NULL, 
                                                    MAX_STRING_LEN, 0);
                apr_table_setn(r->subprocess_env, apr_pstrdup(p, var),
                               apr_pstrdup(p, parsed_string));
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid tag for set directive in %s", r->filename);
                CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
                return -1;
            }
        }
    }
    return 0;
}

static int handle_printenv(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                           request_rec *r, ap_filter_t *f, 
                           apr_bucket *head_ptr, apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    apr_bucket *tmp_buck;

    if (ctx->flags & FLAG_PRINTING) {
        ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, 1);
        if ((tag == NULL) && (tag_val == NULL)) {
            const apr_array_header_t *arr = apr_table_elts(r->subprocess_env);
            const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
            int i;
            const char *key_text, *val_text;
            char *key_val, *next;
            apr_size_t   k_len, v_len, kv_length;

            *inserted_head = NULL;
            for (i = 0; i < arr->nelts; ++i) {
                key_text = ap_escape_html(r->pool, elts[i].key);
                val_text = elts[i].val;
                if (val_text == LAZY_VALUE) {
                    val_text = add_include_vars_lazy(r, elts[i].key);
                }
                val_text = ap_escape_html(r->pool, elts[i].val);
                k_len = strlen(key_text);
                v_len = strlen(val_text);
                kv_length = k_len + v_len + sizeof("=\n");
                key_val = apr_palloc(r->pool, kv_length);
                next = key_val;
                memcpy(next, key_text, k_len);
                next += k_len;
                *next++ = '=';
                memcpy(next, val_text, v_len);
                next += v_len;
                *next++ = '\n';
                *next = 0;
                tmp_buck = apr_bucket_pool_create(key_val, kv_length - 1,
                                                  r->pool,
                                                  r->connection->bucket_alloc);
                APR_BUCKET_INSERT_BEFORE(head_ptr, tmp_buck);
                if (*inserted_head == NULL) {
                    *inserted_head = tmp_buck;
                }
            }
            return 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "printenv directive does not take tags in %s", 
                        r->filename);
            CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
            return -1;
        }
    }
    return 0;
}

/* -------------------------- The main function --------------------------- */

#ifdef MOD_INCLUDE_REDESIGN
/*
 * returns the index position of the first byte of start_seq (or the len of
 * the buffer as non-match)
 */
static apr_size_t find_start_sequence(ssi_ctx_t *ctx, const char *data,
                                      apr_size_t len)
{
    apr_size_t slen = ctx->ctx->start_seq_len;
    apr_size_t index;
    const char *p, *ep;

    if (len < slen) {
        p = data; /* try partial match at the end of the buffer (below) */
    }
    else {
        /* try fast bndm search over the buffer
         * (hopefully the whole start sequence can be found in this buffer)
         */
        index = bndm(ctx->ctx->start_seq, ctx->ctx->start_seq_len, data, len,
                     ctx->ctx->start_seq_pat);

        /* wow, found it. ready. */
        if (index < len) {
            ctx->state = PARSE_DIRECTIVE;
            return index;
        }
        else {
            /* ok, the pattern can't be found as whole in the buffer,
             * check the end for a partial match
             */
            p = data + len - slen + 1;
        }
    }

    ep = data + len;
    do {
        while (p < ep && *p != *ctx->ctx->start_seq) {
            ++p;
        }

        index = p - data;

        /* found a possible start_seq start */
        if (p < ep) {
            apr_size_t pos = 1;

            ++p;
            while (p < ep && *p == ctx->ctx->start_seq[pos]) {
                ++p;
                ++pos;
            }

            /* partial match found. Store the info for the next round */
            if (p == ep) {
                ctx->state = PARSE_HEAD;
                ctx->ctx->parse_pos = pos;
                return index;
            }
        }

        /* we must try all combinations; consider (e.g.) SSIStartTag "--->"
         * and a string data of "--.-" and the end of the buffer
         */
        p = data + index + 1;
    } while (p < ep);

    /* no match */
    return len;
}

/*
 * returns the first byte *after* the partial (or final) match.
 *
 * If we had to trick with the start_seq start, 'release' returns the
 * number of chars of the start_seq which appeared not to be part of a
 * full tag and may have to be passed down the filter chain.
 */
static apr_size_t find_partial_start_sequence(ssi_ctx_t *ctx,
                                              const char *data,
                                              apr_size_t len,
                                              apr_size_t *release)
{
    apr_size_t pos, spos = 0;
    apr_size_t slen = ctx->ctx->start_seq_len;
    const char *p, *ep;

    pos = ctx->ctx->parse_pos;
    ep = data + len;
    *release = 0;

    do {
        p = data;

        while (p < ep && pos < slen && *p == ctx->ctx->start_seq[pos]) {
            ++p;
            ++pos;
        }

        /* full match */
        if (pos == slen) {
            ctx->state = PARSE_DIRECTIVE;
            return (p - data);
        }

        /* the whole buffer is a partial match */
        if (p == ep) {
            ctx->ctx->parse_pos = pos;
            return (p - data);
        }

        /* No match so far, but again:
         * We must try all combinations, since the start_seq is a random
         * user supplied string
         *
         * So: look if the first char of start_seq appears somewhere within
         * the current partial match. If it does, try to start a match that
         * begins with this offset. (This can happen, if a strange
         * start_seq like "---->" spans buffers)
         */
        if (spos < ctx->ctx->parse_pos) {
            do {
                ++spos;
                ++*release;
                p = ctx->ctx->start_seq + spos;
                pos = ctx->ctx->parse_pos - spos;

                while (pos && *p != *ctx->ctx->start_seq) {
                    ++p;
                    ++spos;
                    ++*release;
                    --pos;
                }

                /* if a matching beginning char was found, try to match the
                 * remainder of the old buffer.
                 */
                if (pos > 1) {
                    apr_size_t t = 1;

                    ++p;
                    while (t < pos && *p == ctx->ctx->start_seq[t]) {
                        ++p;
                        ++t;
                    }

                    if (t == pos) {
                        /* yeah, another partial match found in the *old*
                         * buffer, now test the *current* buffer for
                         * continuing match
                         */
                        break;
                    }
                }
            } while (pos > 1);

            if (pos) {
                continue;
            }
        }

        break;
    } while (1); /* work hard to find a match ;-) */

    /* no match at all, release all (wrongly) matched chars so far */
    *release = ctx->ctx->parse_pos;
    ctx->state = PARSE_PRE_HEAD;
    return 0;
}

/*
 * returns the position after the directive
 */
static apr_size_t find_directive(ssi_ctx_t *ctx, const char *data,
                                 apr_size_t len, char ***store,
                                 apr_size_t **store_len)
{
    const char *p = data;
    const char *ep = data + len;
    apr_size_t pos;

    switch (ctx->state) {
    case PARSE_DIRECTIVE:
        while (p < ep && !apr_isspace(*p)) {
            /* we have to consider the case of missing space between directive
             * and end_seq (be somewhat lenient), e.g. <!--#printenv-->
             */
            if (*p == *ctx->ctx->end_seq) {
                ctx->state = PARSE_DIRECTIVE_TAIL;
                ctx->ctx->parse_pos = 1;
                ++p;
                return (p - data);
            }
            ++p;
        }

        if (p < ep) { /* found delimiter whitespace */
            ctx->state = PARSE_DIRECTIVE_POSTNAME;
            *store = &ctx->directive;
            *store_len = &ctx->ctx->directive_length;
        }

        break;

    case PARSE_DIRECTIVE_TAIL:
        pos = ctx->ctx->parse_pos;

        while (p < ep && pos < ctx->end_seq_len &&
               *p == ctx->ctx->end_seq[pos]) {
            ++p;
            ++pos;
        }

        /* full match, we're done */
        if (pos == ctx->end_seq_len) {
            ctx->state = PARSE_DIRECTIVE_POSTTAIL;
            *store = &ctx->directive;
            *store_len = &ctx->ctx->directive_length;
            break;
        }

        /* partial match, the buffer is too small to match fully */
        if (p == ep) {
            ctx->ctx->parse_pos = pos;
            break;
        }

        /* no match. continue normal parsing */
        ctx->state = PARSE_DIRECTIVE;
        return 0;

    case PARSE_DIRECTIVE_POSTTAIL:
        ctx->state = PARSE_EXECUTE;
        ctx->ctx->directive_length -= ctx->end_seq_len;
        /* continue immediately with the next state */

    case PARSE_DIRECTIVE_POSTNAME:
        if (PARSE_DIRECTIVE_POSTNAME == ctx->state) {
            ctx->state = PARSE_PRE_ARG;
        }
        ctx->argc = 0;
        ctx->argv = NULL;

        if (!ctx->ctx->directive_length) {
            ctx->error = 1;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->r, "missing directive "
                          "name in parsed document %s", ctx->r->filename);
        }
        else {
            char *sp = ctx->directive;
            char *sep = ctx->directive + ctx->ctx->directive_length;

            /* normalize directive name */
            for (; sp < sep; ++sp) {
                *sp = apr_tolower(*sp);
            }
        }

        return 0;

    default:
        /* get a rid of a gcc warning about unhandled enumerations */
        break;
    }

    return (p - data);
}

/*
 * find out whether the next token is (a possible) end_seq or an argument
 */
static apr_size_t find_arg_or_tail(ssi_ctx_t *ctx, const char *data,
                                   apr_size_t len)
{
    const char *p = data;
    const char *ep = data + len;

    /* skip leading WS */
    while (p < ep && apr_isspace(*p)) {
        ++p;
    }

    /* buffer doesn't consist of whitespaces only */
    if (p < ep) {
        ctx->state = (*p == *ctx->ctx->end_seq) ? PARSE_TAIL : PARSE_ARG;
    }

    return (p - data);
}

/*
 * test the stream for end_seq. If it doesn't match at all, it must be an
 * argument
 */
static apr_size_t find_tail(ssi_ctx_t *ctx, const char *data,
                            apr_size_t len)
{
    const char *p = data;
    const char *ep = data + len;
    apr_size_t pos = ctx->ctx->parse_pos;

    if (PARSE_TAIL == ctx->state) {
        ctx->state = PARSE_TAIL_SEQ;
        pos = ctx->ctx->parse_pos = 0;
    }

    while (p < ep && pos < ctx->end_seq_len && *p == ctx->ctx->end_seq[pos]) {
        ++p;
        ++pos;
    }

    /* bingo, full match */
    if (pos == ctx->end_seq_len) {
        ctx->state = PARSE_EXECUTE;
        return (p - data);
    }

    /* partial match, the buffer is too small to match fully */
    if (p == ep) {
        ctx->ctx->parse_pos = pos;
        return (p - data);
    }

    /* no match. It must be an argument string then
     * The caller should cleanup and rewind to the reparse point
     */
    ctx->state = PARSE_ARG;
    return 0;
}

/*
 * extract name=value from the buffer
 * A pcre-pattern could look (similar to):
 * name\s*(?:=\s*(["'`]?)value\1(?>\s*))?
 */
static apr_size_t find_argument(ssi_ctx_t *ctx, const char *data,
                                apr_size_t len, char ***store,
                                apr_size_t **store_len)
{
    const char *p = data;
    const char *ep = data + len;

    switch (ctx->state) {
    case PARSE_ARG:
        /*
         * create argument structure and append it to the current list
         */
        ctx->current_arg = apr_palloc(ctx->dpool,
                                      sizeof(*ctx->current_arg));
        ctx->current_arg->next = NULL;

        ++(ctx->argc);
        if (!ctx->argv) {
            ctx->argv = ctx->current_arg;
        }
        else {
            ssi_arg_item_t *newarg = ctx->argv;

            while (newarg->next) {
                newarg = newarg->next;
            }
            newarg->next = ctx->current_arg;
        }

        /* check whether it's a valid one. If it begins with a quote, we
         * can safely assume, someone forgot the name of the argument
         */
        switch (*p) {
        case '"': case '\'': case '`':
            *store = NULL;

            ctx->state = PARSE_ARG_VAL;
            ctx->quote = *p++;
            ctx->current_arg->name = NULL;
            ctx->current_arg->name_len = 0;
            ctx->error = 1;

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->r, "missing argument "
                          "name for value to tag %s in %s",
                          apr_pstrmemdup(ctx->r->pool, ctx->directive,
                                         ctx->ctx->directive_length),
                                         ctx->r->filename);

            return (p - data);

        default:
            ctx->state = PARSE_ARG_NAME;
        }
        /* continue immediately with next state */

    case PARSE_ARG_NAME:
        while (p < ep && !apr_isspace(*p) && *p != '=') {
            ++p;
        }

        if (p < ep) {
            ctx->state = PARSE_ARG_POSTNAME;
            *store = &ctx->current_arg->name;
            *store_len = &ctx->current_arg->name_len;
            return (p - data);
        }
        break;

    case PARSE_ARG_POSTNAME:
        ctx->current_arg->name = apr_pstrmemdup(ctx->dpool,
                                                ctx->current_arg->name,
                                                ctx->current_arg->name_len);
        if (!ctx->current_arg->name_len) {
            ctx->error = 1;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->r, "missing argument "
                          "name for value to tag %s in %s",
                          apr_pstrmemdup(ctx->r->pool, ctx->directive,
                                         ctx->ctx->directive_length),
                                         ctx->r->filename);
        }
        else {
            char *sp = ctx->current_arg->name;

            /* normalize the name */
            while (*sp) {
                *sp = apr_tolower(*sp);
                ++sp;
            }
        }

        ctx->state = PARSE_ARG_EQ;
        /* continue with next state immediately */

    case PARSE_ARG_EQ:
        *store = NULL;

        while (p < ep && apr_isspace(*p)) {
            ++p;
        }

        if (p < ep) {
            if (*p == '=') {
                ctx->state = PARSE_ARG_PREVAL;
                ++p;
            }
            else { /* no value */
                ctx->current_arg->value = NULL;
                ctx->state = PARSE_PRE_ARG;
            }

            return (p - data);
        }
        break;

    case PARSE_ARG_PREVAL:
        *store = NULL;

        while (p < ep && apr_isspace(*p)) {
            ++p;
        }

        /* buffer doesn't consist of whitespaces only */
        if (p < ep) {
            ctx->state = PARSE_ARG_VAL;
            switch (*p) {
            case '"': case '\'': case '`':
                ctx->quote = *p++;
                break;
            default:
                ctx->quote = '\0';
                break;
            }

            return (p - data);
        }
        break;

    case PARSE_ARG_VAL_ESC:
        if (*p == ctx->quote) {
            ++p;
        }
        ctx->state = PARSE_ARG_VAL;
        /* continue with next state immediately */

    case PARSE_ARG_VAL:
        for (; p < ep; ++p) {
            if (ctx->quote && *p == '\\') {
                ++p;
                if (p == ep) {
                    ctx->state = PARSE_ARG_VAL_ESC;
                    break;
                }

                if (*p != ctx->quote) {
                    --p;
                }
            }
            else if (ctx->quote && *p == ctx->quote) {
                ++p;
                *store = &ctx->current_arg->value;
                *store_len = &ctx->current_arg->value_len;
                ctx->state = PARSE_ARG_POSTVAL;
                break;
            }
            else if (!ctx->quote && apr_isspace(*p)) {
                ++p;
                *store = &ctx->current_arg->value;
                *store_len = &ctx->current_arg->value_len;
                ctx->state = PARSE_ARG_POSTVAL;
                break;
            }
        }

        return (p - data);

    case PARSE_ARG_POSTVAL:
        /*
         * The value is still the raw input string. Finally clean it up.
         */
        --(ctx->current_arg->value_len);
        ctx->current_arg->value[ctx->current_arg->value_len] = '\0';

        /* strip quote escaping \ from the string */
        if (ctx->quote) {
            apr_size_t shift = 0;
            char *sp;

            sp = ctx->current_arg->value;
            ep = ctx->current_arg->value + ctx->current_arg->value_len;
            while (sp < ep && *sp != '\\') {
                ++sp;
            }
            for (; sp < ep; ++sp) {
                if (*sp == '\\' && sp[1] == ctx->quote) {
                    ++sp;
                    ++shift;
                }
                if (shift) {
                    *(sp-shift) = *sp;
                }
            }

            ctx->current_arg->value_len -= shift;
        }

        ctx->current_arg->value[ctx->current_arg->value_len] = '\0';
        ctx->state = PARSE_PRE_ARG;

        return 0;

    default:
        /* get a rid of a gcc warning about unhandled enumerations */
        break;
    }

    return len; /* partial match of something */
}

/*
 * This is the main loop over the current bucket brigade.
 */
static apr_status_t send_parsed_content(ap_filter_t *f, apr_bucket_brigade *bb)
{
    ssi_ctx_t *ctx = f->ctx;
    request_rec *r = f->r;
    apr_bucket *b = APR_BRIGADE_FIRST(bb);
    apr_bucket_brigade *pass_bb;
    apr_status_t rv = APR_SUCCESS;
    char *magic; /* magic pointer for sentinel use */

    /* fast exit */
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    /* we may crash, since already cleaned up; hand over the responsibility
     * to the next filter;-)
     */
    if (ctx->seen_eos) {
        return ap_pass_brigade(f->next, bb);
    }

    /* All stuff passed along has to be put into that brigade */
    pass_bb = apr_brigade_create(ctx->ctx->pool, f->c->bucket_alloc);
    ctx->ctx->bytes_parsed = 0;
    ctx->ctx->output_now = 0;
    ctx->error = 0;

    /* loop over the current bucket brigade */
    while (b != APR_BRIGADE_SENTINEL(bb)) {
        const char *data = NULL;
        apr_size_t len, index, release;
        apr_bucket *newb = NULL;
        char **store = &magic;
        apr_size_t *store_len;

        /* handle meta buckets before reading any data */
        if (APR_BUCKET_IS_METADATA(b)) {
            newb = APR_BUCKET_NEXT(b);

            APR_BUCKET_REMOVE(b);

            if (APR_BUCKET_IS_EOS(b)) {
                ctx->seen_eos = 1;

                /* Hit end of stream, time for cleanup ... But wait!
                 * Perhaps we're not ready yet. We may have to loop one or
                 * two times again to finish our work. In that case, we
                 * just re-insert the EOS bucket to allow for an extra loop.
                 *
                 * PARSE_EXECUTE means, we've hit a directive just before the
                 *    EOS, which is now waiting for execution.
                 *
                 * PARSE_DIRECTIVE_POSTTAIL means, we've hit a directive with
                 *    no argument and no space between directive and end_seq
                 *    just before the EOS. (consider <!--#printenv--> as last
                 *    or only string within the stream). This state, however,
                 *    just cleans up and turns itself to PARSE_EXECUTE, which
                 *    will be passed through within the next (and actually
                 *    last) round.
                 */
                if (PARSE_EXECUTE            == ctx->state ||
                    PARSE_DIRECTIVE_POSTTAIL == ctx->state) {
                    APR_BUCKET_INSERT_BEFORE(newb, b);
                }
                else {
                    break; /* END OF STREAM */
                }
            }
            else {
                APR_BRIGADE_INSERT_TAIL(pass_bb, b);

                if (APR_BUCKET_IS_FLUSH(b)) {
                    ctx->ctx->output_now = 1;
                }

                b = newb;
                continue;
            }
        }

        /* enough is enough ... */
        if (ctx->ctx->output_now ||
            ctx->ctx->bytes_parsed > AP_MIN_BYTES_TO_WRITE) {

            if (!APR_BRIGADE_EMPTY(pass_bb)) {
                rv = ap_pass_brigade(f->next, pass_bb);
                if (!APR_STATUS_IS_SUCCESS(rv)) {
                    apr_brigade_destroy(pass_bb);
                    return rv;
                }
            }

            ctx->ctx->output_now = 0;
            ctx->ctx->bytes_parsed = 0;
        }

        /* read the current bucket data */
        len = 0;
        if (!ctx->seen_eos) {
            if (ctx->ctx->bytes_parsed > 0) {
                rv = apr_bucket_read(b, &data, &len, APR_NONBLOCK_READ);
                if (APR_STATUS_IS_EAGAIN(rv)) {
                    ctx->ctx->output_now = 1;
                    continue;
                }
            }

            if (!len || !APR_STATUS_IS_SUCCESS(rv)) {
                rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
            }

            if (!APR_STATUS_IS_SUCCESS(rv)) {
                apr_brigade_destroy(pass_bb);
                return rv;
            }

            ctx->ctx->bytes_parsed += len;
        }

        /* zero length bucket, fetch next one */
        if (!len && !ctx->seen_eos) {
            b = APR_BUCKET_NEXT(b);
            continue;
        }

        /*
         * it's actually a data containing bucket, start/continue parsing
         */

        switch (ctx->state) {
        /* no current tag; search for start sequence */
        case PARSE_PRE_HEAD:
            index = find_start_sequence(ctx, data, len);

            if (index < len) {
                apr_bucket_split(b, index);
            }

            newb = APR_BUCKET_NEXT(b);
            if (ctx->ctx->flags & FLAG_PRINTING) {
                APR_BUCKET_REMOVE(b);
                APR_BRIGADE_INSERT_TAIL(pass_bb, b);
            }
            else {
                apr_bucket_delete(b);
            }

            if (index < len) {
                /* now delete the start_seq stuff from the remaining bucket */
                if (PARSE_DIRECTIVE == ctx->state) { /* full match */
                    apr_bucket_split(newb, ctx->ctx->start_seq_len);
                    ctx->ctx->output_now = 1; /* pass pre-tag stuff */
                }

                b = APR_BUCKET_NEXT(newb);
                apr_bucket_delete(newb);
            }
            else {
                b = newb;
            }

            break;

        /* we're currently looking for the end of the start sequence */
        case PARSE_HEAD:
            index = find_partial_start_sequence(ctx, data, len, &release);

            /* check if we mismatched earlier and have to release some chars */
            if (release && (ctx->ctx->flags & FLAG_PRINTING)) {
                char *to_release = apr_palloc(ctx->ctx->pool, release);

                memcpy(to_release, ctx->ctx->start_seq, release);
                newb = apr_bucket_pool_create(to_release, release,
                                              ctx->ctx->pool,
                                              f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(pass_bb, newb);
            }

            if (index) { /* any match */
                /* now delete the start_seq stuff from the remaining bucket */
                if (PARSE_DIRECTIVE == ctx->state) { /* final match */
                    apr_bucket_split(b, index);
                    ctx->ctx->output_now = 1; /* pass pre-tag stuff */
                }
                newb = APR_BUCKET_NEXT(b);
                apr_bucket_delete(b);
                b = newb;
            }

            break;

        /* we're currently grabbing the directive name */
        case PARSE_DIRECTIVE:
        case PARSE_DIRECTIVE_POSTNAME:
        case PARSE_DIRECTIVE_TAIL:
        case PARSE_DIRECTIVE_POSTTAIL:
            index = find_directive(ctx, data, len, &store, &store_len);

            if (index) {
                apr_bucket_split(b, index);
                newb = APR_BUCKET_NEXT(b);
            }

            if (store) {
                if (index) {
                    APR_BUCKET_REMOVE(b);
                    APR_BRIGADE_INSERT_TAIL(ctx->tmp_bb, b);
                    b = newb;
                }

                /* time for cleanup? */
                if (store != &magic) {
                    apr_brigade_pflatten(ctx->tmp_bb, store, store_len,
                                         ctx->dpool);
                    apr_brigade_cleanup(ctx->tmp_bb);
                }
            }
            else if (index) {
                apr_bucket_delete(b);
                b = newb;
            }

            break;

        /* skip WS and find out what comes next (arg or end_seq) */
        case PARSE_PRE_ARG:
            index = find_arg_or_tail(ctx, data, len);

            if (index) { /* skipped whitespaces */
                if (index < len) {
                    apr_bucket_split(b, index);
                }
                newb = APR_BUCKET_NEXT(b);
                apr_bucket_delete(b);
                b = newb;
            }

            break;

        /* currently parsing name[=val] */
        case PARSE_ARG:
        case PARSE_ARG_NAME:
        case PARSE_ARG_POSTNAME:
        case PARSE_ARG_EQ:
        case PARSE_ARG_PREVAL:
        case PARSE_ARG_VAL:
        case PARSE_ARG_VAL_ESC:
        case PARSE_ARG_POSTVAL:
            index = find_argument(ctx, data, len, &store, &store_len);

            if (index) {
                apr_bucket_split(b, index);
                newb = APR_BUCKET_NEXT(b);
            }

            if (store) {
                if (index) {
                    APR_BUCKET_REMOVE(b);
                    APR_BRIGADE_INSERT_TAIL(ctx->tmp_bb, b);
                    b = newb;
                }

                /* time for cleanup? */
                if (store != &magic) {
                    apr_brigade_pflatten(ctx->tmp_bb, store, store_len,
                                         ctx->dpool);
                    apr_brigade_cleanup(ctx->tmp_bb);
                }
            }
            else if (index) {
                apr_bucket_delete(b);
                b = newb;
            }

            break;

        /* try to match end_seq at current pos. */
        case PARSE_TAIL:
        case PARSE_TAIL_SEQ:
            index = find_tail(ctx, data, len);

            switch (ctx->state) {
            case PARSE_EXECUTE:  /* full match */
                apr_bucket_split(b, index);
                newb = APR_BUCKET_NEXT(b);
                apr_bucket_delete(b);
                b = newb;
                break;

            case PARSE_ARG:      /* no match */
                /* PARSE_ARG must reparse at the beginning */
                APR_BRIGADE_PREPEND(bb, ctx->tmp_bb);
                b = APR_BRIGADE_FIRST(bb);
                break;

            default:             /* partial match */
                newb = APR_BUCKET_NEXT(b);
                APR_BUCKET_REMOVE(b);
                APR_BRIGADE_INSERT_TAIL(ctx->tmp_bb, b);
                b = newb;
                break;
            }

            break;

        /* now execute the parsed directive, cleanup the space and
         * start again with PARSE_PRE_HEAD
         */
        case PARSE_EXECUTE:
            /* if there was an error, it was already logged; just stop here */
            if (ctx->error) {
                if (ctx->ctx->flags & FLAG_PRINTING) {
                    SSI_CREATE_ERROR_BUCKET(ctx->ctx, f, pass_bb);
                    ctx->error = 0;
                }
            }
            else {
                include_handler_fn_t *handle_func;

                handle_func = apr_hash_get(include_hash, ctx->directive, 
                                           ctx->ctx->directive_length);
                if (handle_func) {
                    apr_bucket *dummy;
                    char *tag;
                    apr_size_t tag_len = 0;
                    ssi_arg_item_t *carg = ctx->argv;

                    /* legacy wrapper code */
                    while (carg) {
                        tag_len += (carg->name  ? carg->name_len      : 0) +
                                   (carg->value ? carg->value_len + 1 : 0);
                        carg = carg->next;
                    }

                    tag = ctx->ctx->combined_tag = ctx->ctx->curr_tag_pos =
                        apr_palloc(ctx->dpool, tag_len + 1);

                    carg = ctx->argv;
                    while (carg) {
                        if (carg->name) {
                            memcpy(tag, carg->name, carg->name_len);
                            tag += carg->name_len;
                        }
                        if (carg->value) {
                            memcpy(tag++, "=", 1);
                            memcpy(tag, carg->value, carg->value_len + 1);
                            tag += carg->value_len + 1;
                        }
                        carg = carg->next;
                    }
                    ctx->ctx->tag_length = tag_len;

                    rv = handle_func(ctx->ctx, &bb, r, f, b, &dummy);
                    if (rv != 0 && rv != 1 && rv != -1) {
                        apr_brigade_destroy(pass_bb);
                        return rv;
                    }

                    if (dummy) {
                        apr_bucket_brigade *remain;

                        remain = apr_brigade_split(bb, b);
                        APR_BRIGADE_CONCAT(pass_bb, bb);
                        bb = remain;
                    }
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "unknown directive \"%s\" in parsed doc %s",
                                  apr_pstrmemdup(r->pool, ctx->directive,
                                                 ctx->ctx->directive_length),
                                                 r->filename);
                    if (ctx->ctx->flags & FLAG_PRINTING) {
                        SSI_CREATE_ERROR_BUCKET(ctx->ctx, f, pass_bb);
                    }
                }
            }

            /* cleanup */
            apr_pool_clear(ctx->dpool);
            apr_brigade_cleanup(ctx->tmp_bb);

            /* Oooof. Done here, start next round */
            ctx->state = PARSE_PRE_HEAD;
            break;

        } /* switch(ctx->state) */

    } /* while(brigade) */

    /* End of stream. Final cleanup */
    if (ctx->seen_eos) {
        if (PARSE_HEAD == ctx->state) {
            if (ctx->ctx->flags & FLAG_PRINTING) {
                char *to_release = apr_palloc(ctx->ctx->pool,
                                              ctx->ctx->parse_pos);

                memcpy(to_release, ctx->ctx->start_seq, ctx->ctx->parse_pos);
                APR_BRIGADE_INSERT_TAIL(pass_bb,
                                        apr_bucket_pool_create(to_release,
                                        ctx->ctx->parse_pos, ctx->ctx->pool,
                                        f->c->bucket_alloc));
            }
        }
        else if (PARSE_PRE_HEAD != ctx->state) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "SSI directive was not properly finished at the end "
                          "of parsed document %s", r->filename);
            if (ctx->ctx->flags & FLAG_PRINTING) {
                SSI_CREATE_ERROR_BUCKET(ctx->ctx, f, pass_bb);
            }
        }

        if (!(ctx->ctx->flags & FLAG_PRINTING)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "missing closing endif directive in parsed document"
                          " %s", r->filename);
        }

        /* cleanup our temporary memory */
        apr_brigade_destroy(ctx->tmp_bb);
        apr_pool_destroy(ctx->dpool);

        /* don't forget to finally insert the EOS bucket */
        APR_BRIGADE_INSERT_TAIL(pass_bb, b);
    }

    /* if something's left over, pass it along */
    if (!APR_BRIGADE_EMPTY(pass_bb)) {
        rv = ap_pass_brigade(f->next, pass_bb);
    }
    else {
        rv = APR_SUCCESS;
    }

    apr_brigade_destroy(pass_bb);
    return rv;
}
#endif /* MOD_INCLUDE_REDESIGN */

#ifndef MOD_INCLUDE_REDESIGN
static apr_status_t send_parsed_content(apr_bucket_brigade **bb, 
                                        request_rec *r, ap_filter_t *f)
{
    include_ctx_t *ctx = f->ctx;
    apr_bucket *dptr = APR_BRIGADE_FIRST(*bb);
    apr_bucket *tmp_dptr;
    apr_bucket_brigade *tag_and_after;
    apr_status_t rv = APR_SUCCESS;

    if (r->args) {               /* add QUERY stuff to env cause it ain't yet */
        char *arg_copy = apr_pstrdup(r->pool, r->args);

        apr_table_setn(r->subprocess_env, "QUERY_STRING", r->args);
        ap_unescape_url(arg_copy);
        apr_table_setn(r->subprocess_env, "QUERY_STRING_UNESCAPED",
                  ap_escape_shell_cmd(r->pool, arg_copy));
    }

    while (dptr != APR_BRIGADE_SENTINEL(*bb) && !APR_BUCKET_IS_EOS(dptr)) {
        /* State to check for the STARTING_SEQUENCE. */
        if ((ctx->state == PRE_HEAD) || (ctx->state == PARSE_HEAD)) {
            int do_cleanup = 0;
            apr_size_t cleanup_bytes = ctx->parse_pos;

            tmp_dptr = find_start_sequence(dptr, ctx, *bb, &do_cleanup);
            if (!APR_STATUS_IS_SUCCESS(ctx->status)) {
                return ctx->status;
            }

            /* The few bytes stored in the ssi_tag_brigade turned out not to
             * be a tag after all. This can only happen if the starting
             * tag actually spans brigades. This should be very rare.
             */
            if ((do_cleanup) && (!APR_BRIGADE_EMPTY(ctx->ssi_tag_brigade))) {
                apr_bucket *tmp_bkt;

                tmp_bkt = apr_bucket_immortal_create(ctx->start_seq,
                                                  cleanup_bytes,
                                                  r->connection->bucket_alloc);
                APR_BRIGADE_INSERT_HEAD(*bb, tmp_bkt);
                apr_brigade_cleanup(ctx->ssi_tag_brigade);
            }

            /* If I am inside a conditional (if, elif, else) that is false
             *   then I need to throw away anything contained in it.
             */
            if ((!(ctx->flags & FLAG_PRINTING)) &&
                (dptr != APR_BRIGADE_SENTINEL(*bb))) {
                apr_bucket *stop = (!tmp_dptr && ctx->state == PARSE_HEAD)
                                   ? ctx->head_start_bucket
                                   : tmp_dptr;

                while ((dptr != APR_BRIGADE_SENTINEL(*bb)) && (dptr != stop)) {
                    apr_bucket *free_bucket = dptr;

                    dptr = APR_BUCKET_NEXT(dptr);
                    if (!APR_BUCKET_IS_METADATA(free_bucket)) {
                        apr_bucket_delete(free_bucket);
                    }
                }
            }

            /* Adjust the current bucket position based on what was found... */
            if ((tmp_dptr != NULL) && (ctx->state == PARSE_DIRECTIVE)) {
                if (ctx->tag_start_bucket != NULL) {
                    dptr = ctx->tag_start_bucket;
                }
                else {
                    dptr = APR_BRIGADE_SENTINEL(*bb);
                }
            }
            else if ((tmp_dptr != NULL) &&
                     (ctx->output_now ||
                      (ctx->bytes_parsed >= BYTE_COUNT_THRESHOLD))) {
                /* Send the large chunk of pre-tag bytes...  */
                tag_and_after = apr_brigade_split(*bb, tmp_dptr);
                if (ctx->output_flush) {
                    APR_BRIGADE_INSERT_TAIL(*bb, apr_bucket_flush_create((*bb)->bucket_alloc));
                }

                rv = ap_pass_brigade(f->next, *bb);
                if (rv != APR_SUCCESS) {
                    return rv;
                }
                *bb  = tag_and_after;
                dptr = tmp_dptr;
                ctx->output_flush = 0;
                ctx->bytes_parsed = 0;
                ctx->output_now = 0;
            }
            else if (tmp_dptr == NULL) { 
                /* There was no possible SSI tag in the
                 * remainder of this brigade... */
                dptr = APR_BRIGADE_SENTINEL(*bb);  
            }
        }

        /* State to check for the ENDING_SEQUENCE. */
        if (((ctx->state == PARSE_DIRECTIVE) ||
             (ctx->state == PARSE_TAG)       ||
             (ctx->state == PARSE_TAIL))       &&
            (dptr != APR_BRIGADE_SENTINEL(*bb))) {
            tmp_dptr = find_end_sequence(dptr, ctx, *bb);
            if (!APR_STATUS_IS_SUCCESS(ctx->status)) {
                return ctx->status;
            }

            if (tmp_dptr != NULL) {
                dptr = tmp_dptr;  /* Adjust bucket pos... */
                
                /* If some of the tag has already been set aside then set
                 * aside remainder of tag. Now the full tag is in 
                 * ssi_tag_brigade.
                 * If none has yet been set aside, then leave it all where it 
                 * is.
                 * In any event after this the entire set of tag buckets will 
                 * be in one place or another.
                 */
                if (!APR_BRIGADE_EMPTY(ctx->ssi_tag_brigade)) {
                    tag_and_after = apr_brigade_split(*bb, dptr);
                    APR_BRIGADE_CONCAT(ctx->ssi_tag_brigade, *bb);
                    *bb = tag_and_after;
                }
                else if (ctx->output_now ||
                         (ctx->bytes_parsed >= BYTE_COUNT_THRESHOLD)) {
                    SPLIT_AND_PASS_PRETAG_BUCKETS(*bb, ctx, f->next, rv);
                    if (rv != APR_SUCCESS) {
                        return rv;
                    }
                    ctx->output_flush = 0;
                    ctx->output_now = 0;
                }
            }
            else {
                /* remainder of this brigade...    */
                dptr = APR_BRIGADE_SENTINEL(*bb);  
            }
        }

        /* State to processed the directive... */
        if (ctx->state == PARSED) {
            apr_bucket    *content_head = NULL, *tmp_bkt;
            apr_size_t    tmp_i;
            char          tmp_buf[TMP_BUF_SIZE];
            int (*handle_func)(include_ctx_t *, apr_bucket_brigade **,
                               request_rec *, ap_filter_t *, apr_bucket *,
                               apr_bucket **);

            /* By now the full tag (all buckets) should either be set aside into
             *  ssi_tag_brigade or contained within the current bb. All tag
             *  processing from here on can assume that.
             */

            /* At this point, everything between ctx->head_start_bucket and
             * ctx->tail_start_bucket is an SSI
             * directive, we just have to deal with it now.
             */
            if (get_combined_directive(ctx, r, *bb, tmp_buf,
                                        TMP_BUF_SIZE) != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "mod_include: error copying directive in %s",
                            r->filename);
                CREATE_ERROR_BUCKET(ctx, tmp_bkt, dptr, content_head);

                /* DO CLEANUP HERE!!!!! */
                tmp_dptr = ctx->head_start_bucket;
                if (!APR_BRIGADE_EMPTY(ctx->ssi_tag_brigade)) {
                    apr_brigade_cleanup(ctx->ssi_tag_brigade);
                }
                else {
                    do {
                        tmp_bkt  = tmp_dptr;
                        tmp_dptr = APR_BUCKET_NEXT (tmp_dptr);
                        apr_bucket_delete(tmp_bkt);
                    } while ((tmp_dptr != dptr) &&
                             (tmp_dptr != APR_BRIGADE_SENTINEL(*bb)));
                }

                return APR_SUCCESS;
            }

            /* Can't destroy the tag buckets until I'm done processing
             * because the combined_tag might just be pointing to
             * the contents of a single bucket!
             */

            /* Retrieve the handler function to be called for this directive 
             * from the functions registered in the hash table.
             * Need to lower case the directive for proper matching. Also need 
             * to have it NULL terminated for proper hash matching.
             */
            for (tmp_i = 0; tmp_i < ctx->directive_length; tmp_i++) {
                ctx->combined_tag[tmp_i] = 
                                          apr_tolower(ctx->combined_tag[tmp_i]);
            }
            ctx->combined_tag[ctx->directive_length] = '\0';
            ctx->curr_tag_pos = &ctx->combined_tag[ctx->directive_length+1];

            handle_func = 
                (include_handler_fn_t *)apr_hash_get(include_hash, 
                                                     ctx->combined_tag, 
                                                     ctx->directive_length);
            if (handle_func != NULL) {
                rv = (*handle_func)(ctx, bb, r, f, dptr, &content_head);
                if ((rv != 0) && (rv != 1)) {
                    return (rv);
                }
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "unknown directive \"%s\" in parsed doc %s",
                              ctx->combined_tag, r->filename);
                CREATE_ERROR_BUCKET(ctx, tmp_bkt, dptr, content_head);
            }

            /* This chunk of code starts at the first bucket in the chain
             * of tag buckets (assuming that by this point the bucket for
             * the STARTING_SEQUENCE has been split) and loops through to
             * the end of the tag buckets freeing them all.
             *
             * Remember that some part of this may have been set aside
             * into the ssi_tag_brigade and the remainder (possibly as
             * little as one byte) will be in the current brigade.
             *
             * The value of dptr should have been set during the
             * PARSE_TAIL state to the first bucket after the
             * ENDING_SEQUENCE.
             *
             * The value of content_head may have been set during processing
             * of the directive. If so, the content was inserted in front
             * of the dptr bucket. The inserted buckets should not be thrown
             * away here, but they should also not be parsed later.
             */
            if (content_head == NULL) {
                content_head = dptr;
            }
            tmp_dptr = ctx->head_start_bucket;
            if (!APR_BRIGADE_EMPTY(ctx->ssi_tag_brigade)) {
                apr_brigade_cleanup(ctx->ssi_tag_brigade);
            }
            else {
                do {
                    tmp_bkt  = tmp_dptr;
                    tmp_dptr = APR_BUCKET_NEXT (tmp_dptr);
                    apr_bucket_delete(tmp_bkt);
                } while ((tmp_dptr != content_head) &&
                         (tmp_dptr != APR_BRIGADE_SENTINEL(*bb)));
            }
            if (ctx->combined_tag == tmp_buf) {
                ctx->combined_tag = NULL;
            }

            /* Don't reset the flags or the nesting level!!! */
            ctx->parse_pos         = 0;
            ctx->head_start_bucket = NULL;
            ctx->head_start_index  = 0;
            ctx->tag_start_bucket  = NULL;
            ctx->tag_start_index   = 0;
            ctx->tail_start_bucket = NULL;
            ctx->tail_start_index  = 0;
            ctx->curr_tag_pos      = NULL;
            ctx->tag_length        = 0;
            ctx->directive_length  = 0;

            if (!APR_BRIGADE_EMPTY(ctx->ssi_tag_brigade)) {
                apr_brigade_cleanup(ctx->ssi_tag_brigade);
            }

            ctx->state     = PRE_HEAD;
        }
    }

    /* We have nothing more to send, stop now. */
    if (dptr != APR_BRIGADE_SENTINEL(*bb) &&
        APR_BUCKET_IS_EOS(dptr)) {
        /* We might have something saved that we never completed, but send
         * down unparsed.  This allows for <!-- at the end of files to be
         * sent correctly. */
        if (!APR_BRIGADE_EMPTY(ctx->ssi_tag_brigade)) {
            APR_BRIGADE_CONCAT(ctx->ssi_tag_brigade, *bb);
            return ap_pass_brigade(f->next, ctx->ssi_tag_brigade);
        }
        return ap_pass_brigade(f->next, *bb);
    }

    /* If I am in the middle of parsing an SSI tag then I need to set aside
     *   the pertinent trailing buckets and pass on the initial part of the
     *   brigade. The pertinent parts of the next brigades will be added to
     *   these set aside buckets to form the whole tag and will be processed
     *   once the whole tag has been found.
     */
    if (ctx->state == PRE_HEAD) {
        if (!APR_BRIGADE_EMPTY(*bb)) {
            /* pass it along... */
            rv = ap_pass_brigade(f->next, *bb);  
            if (rv != APR_SUCCESS) {
                return rv;
            }
            ctx->bytes_parsed = 0;
        }
    }
    else if (ctx->state == PARSED) {         /* Invalid internal condition... */
        apr_bucket *content_head = NULL, *tmp_bkt;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid mod_include state during file %s", r->filename);
        CREATE_ERROR_BUCKET(ctx, tmp_bkt, APR_BRIGADE_FIRST(*bb), content_head);
    }
    else {                    /* Entire brigade is middle chunk of SSI tag... */
        if (!APR_BRIGADE_EMPTY(ctx->ssi_tag_brigade)) {
            APR_BRIGADE_CONCAT(ctx->ssi_tag_brigade, *bb);
        }
        else {                  /* End of brigade contains part of SSI tag... */
            apr_bucket *last;
            if (ctx->head_start_index > 0) {
                apr_bucket_split(ctx->head_start_bucket, ctx->head_start_index);
                ctx->head_start_bucket = 
                                        APR_BUCKET_NEXT(ctx->head_start_bucket);
                ctx->head_start_index = 0;
            }
                           /* Set aside tag, pass pre-tag... */
            tag_and_after = apr_brigade_split(*bb, ctx->head_start_bucket);
            rv = ap_pass_brigade(f->next, *bb);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            
            /* Set aside the partial tag
             * Exception: if there's an EOS at the end of this brigade,
             * the tag will never be completed, so send an error and EOS
             */
            last = APR_BRIGADE_LAST(tag_and_after);
            if (APR_BUCKET_IS_EOS(last)) {
                /* Remove everything before the EOS (i.e., the partial tag)
                 * and replace it with an error msg */
                apr_bucket *b;
                apr_bucket *err_bucket = NULL;
                for (b = APR_BRIGADE_FIRST(tag_and_after);
                     !APR_BUCKET_IS_EOS(b);
                     b = APR_BRIGADE_FIRST(tag_and_after)) {
                    APR_BUCKET_REMOVE(b);
                    apr_bucket_destroy(b);
                }
                CREATE_ERROR_BUCKET(ctx, err_bucket, b, err_bucket);
                rv = ap_pass_brigade(f->next, tag_and_after);
            }
            else {
                ap_save_brigade(f, &ctx->ssi_tag_brigade,
                                &tag_and_after, r->pool);
            }
            if (rv != APR_SUCCESS) {
                return rv;
            }
            ctx->bytes_parsed = 0;
        }
    }
    return APR_SUCCESS;
}
#endif /* !MOD_INCLUDE_REDESIGN */

static void *create_includes_dir_config(apr_pool_t *p, char *dummy)
{
    include_dir_config *result =
        (include_dir_config *)apr_palloc(p, sizeof(include_dir_config));
    enum xbithack *xbh = (enum xbithack *) apr_palloc(p, sizeof(enum xbithack));
    *xbh = DEFAULT_XBITHACK;
    result->default_error_msg = DEFAULT_ERROR_MSG;
    result->default_time_fmt = DEFAULT_TIME_FORMAT;
    result->xbithack = xbh;
    return result;
}

static void *create_includes_server_config(apr_pool_t*p, server_rec *server)
{
    include_server_config *result =
        (include_server_config *)apr_palloc(p, sizeof(include_server_config));
    result->default_end_tag = ENDING_SEQUENCE;
    result->default_start_tag =STARTING_SEQUENCE;
    result->start_tag_len = sizeof(STARTING_SEQUENCE)-1;
    /* compile the pattern used by find_start_sequence */
    bndm_compile(&result->start_seq_pat, result->default_start_tag, 
                 result->start_tag_len); 

    result->undefinedEcho = apr_pstrdup(p,"(none)");
    result->undefinedEchoLen = strlen( result->undefinedEcho);
    return result; 
}
static const char *set_xbithack(cmd_parms *cmd, void *xbp, const char *arg)
{
    include_dir_config *conf = (include_dir_config *)xbp;

    if (!strcasecmp(arg, "off")) {
        *conf->xbithack = xbithack_off;
    }
    else if (!strcasecmp(arg, "on")) {
        *conf->xbithack = xbithack_on;
    }
    else if (!strcasecmp(arg, "full")) {
        *conf->xbithack = xbithack_full;
    }
    else {
        return "XBitHack must be set to Off, On, or Full";
    }

    return NULL;
}

static int includes_setup(ap_filter_t *f)
{
    include_dir_config *conf = 
               (include_dir_config *)ap_get_module_config(f->r->per_dir_config,
                                                          &include_module);

    /* When our xbithack value isn't set to full or our platform isn't
     * providing group-level protection bits or our group-level bits do not
     * have group-execite on, we will set the no_local_copy value to 1 so
     * that we will not send 304s.
     */
    if ((*conf->xbithack != xbithack_full)
        || !(f->r->finfo.valid & APR_FINFO_GPROT)
        || !(f->r->finfo.protection & APR_GEXECUTE)) {
        f->r->no_local_copy = 1;
    }
    
    return OK;
}

static apr_status_t includes_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
    request_rec *r = f->r;
#ifdef MOD_INCLUDE_REDESIGN
    ssi_ctx_t *ctx = f->ctx;
#else
    include_ctx_t *ctx = f->ctx;
#endif
    request_rec *parent;
    include_dir_config *conf = 
                   (include_dir_config *)ap_get_module_config(r->per_dir_config,
                                                              &include_module);

    include_server_config *sconf= ap_get_module_config(r->server->module_config,
                                                              &include_module);

    if (!(ap_allow_options(r) & OPT_INCLUDES)) {
        return ap_pass_brigade(f->next, b);
    }

    if (!f->ctx) {
#ifdef MOD_INCLUDE_REDESIGN
        /* create context for this filter */
        f->ctx = ctx = apr_palloc(f->c->pool, sizeof(*ctx));
        ctx->ctx = apr_pcalloc(f->c->pool, sizeof(*ctx->ctx));
        ctx->ctx->pool = f->r->pool;
        apr_pool_create(&ctx->dpool, ctx->ctx->pool);

        /* configuration data */
        ctx->end_seq_len = strlen(sconf->default_end_tag);
        ctx->r = f->r;

        /* runtime data */
        ctx->tmp_bb = apr_brigade_create(ctx->ctx->pool, f->c->bucket_alloc);
        ctx->seen_eos = 0;
        ctx->state = PARSE_PRE_HEAD;
        ctx->ctx->flags = (FLAG_PRINTING | FLAG_COND_TRUE);
        if (ap_allow_options(f->r) & OPT_INCNOEXEC) {
            ctx->ctx->flags |= FLAG_NO_EXEC;
        }
        ctx->ctx->if_nesting_level = 0;
        ctx->ctx->re_string = NULL;
        ctx->ctx->error_str_override = NULL;
        ctx->ctx->time_str_override = NULL;

        ctx->ctx->state = PARSED; /* dummy */
        ctx->ctx->ssi_tag_brigade = apr_brigade_create(f->c->pool,
                                                       f->c->bucket_alloc);
        ctx->ctx->status = APR_SUCCESS;

        ctx->ctx->error_str = conf->default_error_msg;
        ctx->ctx->time_str = conf->default_time_fmt;
        ctx->ctx->start_seq_pat = &sconf->start_seq_pat;
        ctx->ctx->start_seq  = sconf->default_start_tag;
        ctx->ctx->start_seq_len = sconf->start_tag_len;
        ctx->ctx->end_seq = sconf->default_end_tag;
    }
    else {
        ctx->ctx->bytes_parsed = 0;
    }
#else /* MOD_INCLUDE_REDESIGN */
        f->ctx = ctx = apr_pcalloc(f->c->pool, sizeof(*ctx));
        ctx->state = PRE_HEAD;
        ctx->flags = (FLAG_PRINTING | FLAG_COND_TRUE);
        if (ap_allow_options(r) & OPT_INCNOEXEC) {
            ctx->flags |= FLAG_NO_EXEC;
        }
        ctx->ssi_tag_brigade = apr_brigade_create(f->c->pool,
                                                  f->c->bucket_alloc);
        ctx->status = APR_SUCCESS;

        ctx->error_str = conf->default_error_msg;
        ctx->time_str = conf->default_time_fmt;
        ctx->pool = f->c->pool;
        ctx->start_seq_pat = &sconf->start_seq_pat;
        ctx->start_seq  = sconf->default_start_tag;
        ctx->start_seq_len = sconf->start_tag_len;
        ctx->end_seq = sconf->default_end_tag;
    }
    else {
        ctx->bytes_parsed = 0;
    }
#endif /* !MOD_INCLUDE_REDESIGN */

    if ((parent = ap_get_module_config(r->request_config, &include_module))) {
        /* Kludge --- for nested includes, we want to keep the subprocess
         * environment of the base document (for compatibility); that means
         * torquing our own last_modified date as well so that the
         * LAST_MODIFIED variable gets reset to the proper value if the
         * nested document resets <!--#config timefmt -->.
         */
        r->subprocess_env = r->main->subprocess_env;
        apr_pool_join(r->main->pool, r->pool);
        r->finfo.mtime = r->main->finfo.mtime;
    }
    else {
        /* we're not a nested include, so we create an initial
         * environment */
        ap_add_common_vars(r);
        ap_add_cgi_vars(r);
        add_include_vars(r, conf->default_time_fmt);
    }
    /* Always unset the content-length.  There is no way to know if
     * the content will be modified at some point by send_parsed_content.
     * It is very possible for us to not find any content in the first
     * 9k of the file, but still have to modify the content of the file.
     * If we are going to pass the file through send_parsed_content, then
     * the content-length should just be unset.
     */
    apr_table_unset(f->r->headers_out, "Content-Length");

    /* Always unset the ETag/Last-Modified fields - see RFC2616 - 13.3.4.
     * We don't know if we are going to be including a file or executing
     * a program which may change the Last-Modified header or make the 
     * content completely dynamic.  Therefore, we can't support these
     * headers.
     * Exception: XBitHack full means we *should* set the Last-Modified field.
     */
    apr_table_unset(f->r->headers_out, "ETag");

    /* Assure the platform supports Group protections */
    if ((*conf->xbithack == xbithack_full)
        && (r->finfo.valid & APR_FINFO_GPROT)
        && (r->finfo.protection & APR_GEXECUTE)) {
        ap_update_mtime(r, r->finfo.mtime);
        ap_set_last_modified(r);
    }
    else {
        apr_table_unset(f->r->headers_out, "Last-Modified");
    }

#ifdef MOD_INCLUDE_REDESIGN
    /* add QUERY stuff to env cause it ain't yet */
    if (r->args) {
        char *arg_copy = apr_pstrdup(r->pool, r->args);

        apr_table_setn(r->subprocess_env, "QUERY_STRING", r->args);
        ap_unescape_url(arg_copy);
        apr_table_setn(r->subprocess_env, "QUERY_STRING_UNESCAPED",
                  ap_escape_shell_cmd(r->pool, arg_copy));
    }

    return send_parsed_content(f, b);
#else
    return send_parsed_content(&b, r, f);
#endif
}

static void ap_register_include_handler(char *tag, include_handler_fn_t *func)
{
    apr_hash_set(include_hash, tag, strlen(tag), (const void *)func);
}

static int include_post_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    include_hash = apr_hash_make(p);
    
    ssi_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_include_handler);

    if(ssi_pfn_register) {
        ssi_pfn_register("if", handle_if);
        ssi_pfn_register("set", handle_set);
        ssi_pfn_register("else", handle_else);
        ssi_pfn_register("elif", handle_elif);
        ssi_pfn_register("echo", handle_echo);
        ssi_pfn_register("endif", handle_endif);
        ssi_pfn_register("fsize", handle_fsize);
        ssi_pfn_register("config", handle_config);
        ssi_pfn_register("include", handle_include);
        ssi_pfn_register("flastmod", handle_flastmod);
        ssi_pfn_register("printenv", handle_printenv);
    }
    return OK;
}

static const char *set_default_error_msg(cmd_parms *cmd, void *mconfig, const char *msg)
{
    include_dir_config *conf = (include_dir_config *)mconfig;
    conf->default_error_msg = apr_pstrdup(cmd->pool, msg);
    return NULL;
}

static const char *set_default_start_tag(cmd_parms *cmd, void *mconfig, const char *msg)
{
    include_server_config *conf;
    const char *p = msg;

    /* be consistent. (See below in set_default_end_tag) */
    while (*p) {
        if (apr_isspace(*p)) {
            return "SSIStartTag may not contain any whitespaces";
        }
        ++p;
    }

    conf= ap_get_module_config(cmd->server->module_config , &include_module);
    conf->default_start_tag = apr_pstrdup(cmd->pool, msg);
    conf->start_tag_len = strlen(conf->default_start_tag );
    bndm_compile(&conf->start_seq_pat, conf->default_start_tag, 
                 conf->start_tag_len); 

    return NULL;
}
static const char *set_undefined_echo(cmd_parms *cmd, void *mconfig, const char *msg)
{
    include_server_config *conf;
    conf = ap_get_module_config(cmd->server->module_config, &include_module);
    conf->undefinedEcho = apr_pstrdup(cmd->pool, msg);
    conf->undefinedEchoLen = strlen(msg);

    return NULL;
}


static const char *set_default_end_tag(cmd_parms *cmd, void *mconfig, const char *msg)
{
    include_server_config *conf;
    const char *p = msg;

    /* sanity check. The parser may fail otherwise */
    while (*p) {
        if (apr_isspace(*p)) {
            return "SSIEndTag may not contain any whitespaces";
        }
        ++p;
    }

    conf= ap_get_module_config(cmd->server->module_config , &include_module);
    conf->default_end_tag = apr_pstrdup(cmd->pool, msg);

    return NULL;
}

static const char *set_default_time_fmt(cmd_parms *cmd, void *mconfig, const char *fmt)
{
    include_dir_config *conf = (include_dir_config *)mconfig;
    conf->default_time_fmt = apr_pstrdup(cmd->pool, fmt);
    return NULL;
}

/*
 * Module definition and configuration data structs...
 */
static const command_rec includes_cmds[] =
{
    AP_INIT_TAKE1("XBitHack", set_xbithack, NULL, OR_OPTIONS, 
                  "Off, On, or Full"),
    AP_INIT_TAKE1("SSIErrorMsg", set_default_error_msg, NULL, OR_ALL, 
                  "a string"),
    AP_INIT_TAKE1("SSITimeFormat", set_default_time_fmt, NULL, OR_ALL,
                  "a strftime(3) formatted string"),
    AP_INIT_TAKE1("SSIStartTag", set_default_start_tag, NULL, RSRC_CONF,
                  "SSI Start String Tag"),
    AP_INIT_TAKE1("SSIEndTag", set_default_end_tag, NULL, RSRC_CONF,
                  "SSI End String Tag"),
    AP_INIT_TAKE1("SSIUndefinedEcho", set_undefined_echo, NULL, RSRC_CONF,
                  "String to be displayed if an echoed variable is undefined"),
    {NULL}
};

static int include_fixup(request_rec *r)
{
    include_dir_config *conf;
 
    conf = (include_dir_config *) ap_get_module_config(r->per_dir_config,
                                                &include_module);
 
    if (r->handler && (strcmp(r->handler, "server-parsed") == 0)) 
    {
        if (!r->content_type || !*r->content_type) {
            ap_set_content_type(r, "text/html");
        }
        r->handler = "default-handler";
    }
    else 
#if defined(OS2) || defined(WIN32) || defined(NETWARE)
    /* These OS's don't support xbithack. This is being worked on. */
    {
        return DECLINED;
    }
#else
    {
        if (*conf->xbithack == xbithack_off) {
            return DECLINED;
        }

        if (!(r->finfo.protection & APR_UEXECUTE)) {
            return DECLINED;
        }

        if (!r->content_type || strcmp(r->content_type, "text/html")) {
            return DECLINED;
        }
    }
#endif

    /* We always return declined, because the default handler actually
     * serves the file.  All we have to do is add the filter.
     */
    ap_add_output_filter("INCLUDES", NULL, r, r->connection);
    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(ap_ssi_get_tag_and_value);
    APR_REGISTER_OPTIONAL_FN(ap_ssi_parse_string);
    APR_REGISTER_OPTIONAL_FN(ap_register_include_handler);
    ap_hook_post_config(include_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_fixups(include_fixup, NULL, NULL, APR_HOOK_LAST);
    ap_register_output_filter("INCLUDES", includes_filter, includes_setup,
                              AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA include_module =
{
    STANDARD20_MODULE_STUFF,
    create_includes_dir_config,   /* dir config creater */
    NULL,                         /* dir merger --- default is to override */
    create_includes_server_config,/* server config */
    NULL,                         /* merge server config */
    includes_cmds,                /* command apr_table_t */
    register_hooks                /* register hooks */
};
