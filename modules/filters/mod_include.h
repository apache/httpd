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

#ifndef _MOD_INCLUDE_H
#define _MOD_INCLUDE_H 1

#include "apr_pools.h"
#include "apr_optional.h"

/*
 * Constants used for ap_ssi_get_tag_and_value's decode parameter
 */
#define SSI_VALUE_DECODED 1
#define SSI_VALUE_RAW     0

/*
 * Constants used for ap_ssi_parse_string's leave_name parameter
 */
#define SSI_EXPAND_LEAVE_NAME 1
#define SSI_EXPAND_DROP_NAME  0

/*
 * This macro creates a bucket which contains an error message and appends it
 * to the current pass brigade
 */
#define SSI_CREATE_ERROR_BUCKET(ctx, f, bb) APR_BRIGADE_INSERT_TAIL((bb), \
    apr_bucket_pool_create(apr_pstrdup((ctx)->pool, (ctx)->error_str),    \
                           strlen((ctx)->error_str), (ctx)->pool,         \
                           (f)->c->bucket_alloc))

/*
 * These constants are used to set or clear flag bits.
 */
#define SSI_FLAG_PRINTING         (1<<0)  /* Printing conditional lines. */
#define SSI_FLAG_COND_TRUE        (1<<1)  /* Conditional eval'd to true. */
#define SSI_FLAG_SIZE_IN_BYTES    (1<<2)  /* Sizes displayed in bytes.   */
#define SSI_FLAG_NO_EXEC          (1<<3)  /* No Exec in current context. */

#define SSI_FLAG_SIZE_ABBREV      (~(SSI_FLAG_SIZE_IN_BYTES))
#define SSI_FLAG_CLEAR_PRINT_COND (~((SSI_FLAG_PRINTING) | \
                                     (SSI_FLAG_COND_TRUE)))
#define SSI_FLAG_CLEAR_PRINTING   (~(SSI_FLAG_PRINTING))

/*
 * The public SSI context structure
 */
typedef struct {
    /* permanent pool, use this for creating bucket data */
    apr_pool_t  *pool;

    /* temp pool; will be cleared after the execution of every directive */
    apr_pool_t  *dpool;

    /* See the SSI_FLAG_XXXXX definitions. */
    int          flags;

    /* nesting of *invisible* ifs */
    int          if_nesting_level;

    /* if true, the current buffer will be passed down the filter chain before
     * continuing with next input bucket and the variable will be reset to
     * false.
     */
    int          flush_now;

    /* argument counter (of the current directive) */
    unsigned     argc;

    /* currently configured error string */
    char        *error_str;

    /* currently configured time format */
    char        *time_str;

    /* pointer to internal (non-public) data, don't touch */
    struct ssi_internal_ctx *intern;
} include_ctx_t;

typedef apr_status_t (include_handler_fn_t)(include_ctx_t *, ap_filter_t *,
                                            apr_bucket_brigade *);

APR_DECLARE_OPTIONAL_FN(void, ap_ssi_get_tag_and_value,
                        (include_ctx_t *ctx, char **tag, char **tag_val,
                         int dodecode));

APR_DECLARE_OPTIONAL_FN(char*, ap_ssi_parse_string,
                        (request_rec *r, include_ctx_t *ctx, const char *in,
                         char *out, apr_size_t length, int leave_name));

APR_DECLARE_OPTIONAL_FN(void, ap_register_include_handler, 
                        (char *tag, include_handler_fn_t *func));

#endif /* MOD_INCLUDE */
