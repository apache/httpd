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
 */

/*
 * mod_bucketeer.c: split buckets whenever we find a control-char
 *
 * Written by Ian Holsman (IanH@apache.org)
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"
#include "http_protocol.h"

static const char bucketeerFilterName[] = "BUCKETEER";
module AP_MODULE_DECLARE_DATA bucketeer_module;

typedef struct bucketeer_filter_config_t
{
    char bucketdelimiter;
    char passdelimiter;
    char flushdelimiter;
} bucketeer_filter_config_t;


static void *create_bucketeer_server_config(apr_pool_t *p, server_rec *s)
{
    bucketeer_filter_config_t *c = apr_pcalloc(p, sizeof *c);

    c->bucketdelimiter = 0x02; /* ^B */
    c->passdelimiter = 0x10;   /* ^P */
    c->flushdelimiter = 0x06;  /* ^F */

    return c;
}

typedef struct bucketeer_ctx_t
{
    apr_bucket_brigade *bb;
} bucketeer_ctx_t;

static apr_status_t bucketeer_out_filter(ap_filter_t *f,
                                         apr_bucket_brigade *bb)
{
    apr_bucket *e;
    request_rec *r = f->r;
    bucketeer_ctx_t *ctx = f->ctx;
    bucketeer_filter_config_t *c;

    c = ap_get_module_config(r->server->module_config, &bucketeer_module);

    /* If have a context, it means we've done this before successfully. */
    if (!ctx) {  
        if (!r->content_type || strncmp(r->content_type, "text/", 5)) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* We're cool with filtering this. */
        ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc); 
        apr_table_unset(f->r->headers_out, "Content-Length");
    }

    APR_BRIGADE_FOREACH(e, bb) {
        const char *data;
        apr_size_t len, i, lastpos;

        if (APR_BUCKET_IS_EOS(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* Okay, we've seen the EOS.
             * Time to pass it along down the chain.
             */
            return ap_pass_brigade(f->next, ctx->bb);
        }

        if (APR_BUCKET_IS_FLUSH(e)) {     
            /*
             * Ignore flush buckets for the moment.. 
             * we decide what to stream
             */
            continue;
        }

        if (APR_BUCKET_IS_METADATA(e)) {
            /* metadata bucket */
            apr_bucket *cpy;
            apr_bucket_copy(e, &cpy);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, cpy);
            continue;
        }

        /* read */
        apr_bucket_read(e, &data, &len, APR_BLOCK_READ);

        if (len > 0) {
            lastpos = 0;
            for (i = 0; i < len; i++) {
                if (data[i] == c->flushdelimiter ||
                    data[i] == c->bucketdelimiter ||
                    data[i] == c->passdelimiter) {
                    apr_bucket *p;
                    if (i - lastpos > 0) {
                        p = apr_bucket_pool_create(apr_pmemdup(f->r->pool,
                                                               &data[lastpos],
                                                               i - lastpos),
                                                    i - lastpos,
                                                    f->r->pool,
                                                    f->c->bucket_alloc);
                        APR_BRIGADE_INSERT_TAIL(ctx->bb, p);
                    }
                    lastpos = i + 1;
                    if (data[i] == c->flushdelimiter) {
                        p = apr_bucket_flush_create(f->c->bucket_alloc);
                        APR_BRIGADE_INSERT_TAIL(ctx->bb, p);
                    }
                    if (data[i] == c->flushdelimiter ||
                        data[i] == c->passdelimiter) {
                        ap_pass_brigade(f->next, ctx->bb);
                       /* apr_brigade_cleanup(ctx->bb);*/
                    }
                }                       
            }
            /* XXX: really should append this to the next 'real' bucket */
            if (lastpos < i) {
                apr_bucket *p;
                p = apr_bucket_pool_create(apr_pmemdup(f->r->pool,
                                                       &data[lastpos],
                                                       i - lastpos),
                                           i - lastpos,
                                           f->r->pool,
                                           f->c->bucket_alloc);
                lastpos = i;
                APR_BRIGADE_INSERT_TAIL(ctx->bb, p);
            }
        }     
    }

    return APR_SUCCESS;
}

static void register_hooks(apr_pool_t * p)
{
    ap_register_output_filter(bucketeerFilterName, bucketeer_out_filter,
                              NULL, AP_FTYPE_RESOURCE-1);
}

static const command_rec bucketeer_filter_cmds[] = {
    {NULL}
};

module AP_MODULE_DECLARE_DATA bucketeer_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_bucketeer_server_config,
    NULL,
    bucketeer_filter_cmds,
    register_hooks
};
