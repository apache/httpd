/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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

#include "apr_strings.h"
#include "ap_config.h"
#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"
#include "http_core.h" 
#include "mod_cache.h"
#include "ap_hooks.h"

module MODULE_VAR_EXPORT cache_module;

AP_HOOK_STRUCT(
            AP_HOOK_LINK(serve_cache)
            AP_HOOK_LINK(store_cache)
)

AP_IMPLEMENT_HOOK_RUN_FIRST(int,serve_cache,(request_rec *r),(r),DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,store_cache,(request_rec *r, ap_bucket_brigade *bb, void **cf),
                            (r, bb, cf),DECLINED)

static int cache_handler(request_rec *r)
{
    /* I am sure there is common error checking that belongs in this function,
     * but I'm not sure what it is.
     */
    return ap_run_serve_cache(r);
}

typedef struct cache_struct {
    void *cf;
} cache_struct;

static int cache_filter(ap_filter_t *f, ap_bucket_brigade *bb)
{
    cache_struct *ctx = f->ctx;
    
    if (ctx == NULL) {
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
    }

    ap_run_store_cache(f->r, bb, &ctx->cf);
    ap_pass_brigade(f->next, bb);
    return APR_SUCCESS;	
}

static void cache_register_hook(void)
{
    ap_register_output_filter("CACHE", cache_filter, AP_FTYPE_HTTP_HEADER);
}

static const handler_rec cache_handlers[] =
{
    {"*/*", cache_handler},
    {NULL}
};

module MODULE_VAR_EXPORT cache_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,        		/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    NULL,			/* command apr_table_t */
    cache_handlers,      	/* handlers */
    cache_register_hook		/* register hooks */
};
