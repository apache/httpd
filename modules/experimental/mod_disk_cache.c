/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

#include "mod_cache.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "http_config.h"
#include "http_log.h"
#include "util_filter.h"

module MODULE_VAR_EXPORT disk_cache_module;

static int disk_serve(request_rec *r)
{
    apr_bucket *e;
    apr_bucket_brigade *bb = apr_brigade_create(r->pool); 
    const char *filename;
    apr_file_t *fd = NULL;
    apr_status_t rv;
    ap_filter_t *f;
    char str[256];
    apr_off_t offset = 0;

    /* XXX Very expensive!!! */
    filename = ap_server_root_relative(r->pool, 
                        apr_pstrcat(r->pool, "proxy", r->uri, NULL));
    if ((rv = apr_file_open(&fd, filename, APR_READ, 
                 APR_UREAD, r->connection->pool)) != APR_SUCCESS) {
        return DECLINED;
    }

    /* skip the cached headers. */
    do {
        apr_file_gets(str, 256, fd);
        offset += strlen(str);
    } while (strcmp(str, CRLF));

    /* If we are serving from the cache, we don't want to try to cache it
     * again.
     */
    for ((f = r->output_filters); (f = f->next);) {
        if (!strcmp(f->frec->name, "CACHE")) {
            ap_remove_output_filter(f);
        }
    }

    e = apr_bucket_file_create(fd, offset, r->finfo.size, r->pool);

    APR_BRIGADE_INSERT_HEAD(bb, e);
    e = apr_bucket_eos_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);

    ap_pass_brigade(r->output_filters, bb);
    return OK;
}

typedef struct cache_struct {
    const char *filename;
    apr_file_t *fd;
    int state;
} cache_struct;

static int disk_cache(request_rec *r, apr_bucket_brigade *bb, void **cf)
{
    cache_struct *ctx = *cf;
    apr_bucket *e;
    
    if (ctx == NULL) {
        *cf = ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    }
    if (ctx->filename == NULL) {
        apr_status_t rv;
        /* XXX Very expensive!!! */
        apr_dir_make(ap_server_root_relative(r->pool, "proxy"), APR_UREAD | APR_UWRITE | APR_UEXECUTE | APR_GREAD | APR_GWRITE, r->pool);

        /* currently, we are using the uri as the cache key.  This is
         * probably wrong, but it is much better than a hard-coded filename.
         */
        /* XXX Very expensive!!! */
        ctx->filename = ap_server_root_relative(r->pool, 
                            apr_pstrcat(r->pool, "proxy", r->uri, NULL));
        if ((rv = apr_file_open(&ctx->fd, ctx->filename, 
                     APR_WRITE | APR_CREATE | APR_TRUNCATE | APR_BUFFERED,
                     APR_UREAD | APR_UWRITE, r->pool)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                         "Could not create cache file");
            *cf = NULL;
            return DECLINED;
        }
    } 
    APR_BRIGADE_FOREACH(e, bb) {
        const char *str;
        apr_ssize_t length;

        apr_bucket_read(e, &str, &length, APR_BLOCK_READ);
        apr_file_write(ctx->fd, str, &length);
    }
    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
        apr_file_close(ctx->fd);
    }
    return OK;	
}

static void disk_cache_register_hook(apr_pool_t *p)
{
    ap_hook_store_cache(disk_cache, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_serve_cache(disk_serve, NULL, NULL, APR_HOOK_MIDDLE);
}

module MODULE_VAR_EXPORT disk_cache_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,        		/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    NULL,			/* command apr_table_t */
    disk_cache_register_hook	/* register hooks */
};
