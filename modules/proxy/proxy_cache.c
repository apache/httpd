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
 */

#include "apr_strings.h"
#include "proxy_cache.h"
#include "httpd.h"
#include "http_log.h"
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

/* struct ap_cache_handle_t, some function pointer in the meth */
#define VERIFY_IMPL(x, fun) if(!x || !x->meth.fun) return APR_ENOTIMPL

APR_HOOK_STRUCT(
    APR_HOOK_LINK(cache_init)
)

apr_status_t ap_cache_init(ap_cache_handle_t **h, const char *desc, server_rec *server)
{
    return ap_run_cache_init(h, desc, server);
}
apr_status_t ap_cache_close(ap_cache_handle_t *h)
{
    VERIFY_IMPL(h, cache_close);
    return h->meth.cache_close(h);
}
apr_status_t ap_cache_garbage_collect(ap_cache_handle_t *h)
{
    VERIFY_IMPL(h, cache_garbage_coll);
    return h->meth.cache_garbage_coll(h);
}
apr_status_t ap_cache_seek(ap_cache_handle_t *h, const char *name, ap_cache_el **el)
{
    VERIFY_IMPL(h, cache_element);
    *el = NULL;
    return h->meth.cache_element(h, name, el, AP_CACHE_SEEK);
}
apr_status_t ap_cache_create(ap_cache_handle_t *h, const char *name, ap_cache_el **el)
{
    VERIFY_IMPL(h, cache_element);
    *el = NULL;
    return h->meth.cache_element(h, name, el, AP_CACHE_CREATE);
}
apr_status_t ap_cache_remove(ap_cache_handle_t *h, const char *name)
{
    VERIFY_IMPL(h, cache_element);
    return h->meth.cache_element(h, name, NULL, AP_CACHE_REMOVE);
}
struct walk_struct { char **place; apr_pool_t *pool; };
static int get_first_val(void *datum, const char *name, const char *val)
{
    struct walk_struct *ws = (struct walk_struct *)datum;
    *(ws->place) = apr_pstrdup(ws->pool, val);
    return 0;
}
apr_status_t ap_cache_el_header(ap_cache_el *el, const char *hdr, char **val)
{
    struct walk_struct ws;
    if(!val || !el) return APR_BADARG;
    *val = NULL;
    ws.place = val;
    ws.pool = el->cache->pool;
    ap_cache_el_header_walk(el, get_first_val, &ws, hdr, NULL);
    return *val ? APR_SUCCESS : APR_ENOENT;
}
apr_status_t ap_cache_el_header_walk(ap_cache_el *el,
               int (*comp)(void *, const char *, const char *), void *rec, ...)
{
    va_list args;
    apr_status_t ret;
    
    if(!el) return APR_BADARG;
    VERIFY_IMPL(el->cache, cache_el_header_walk);
    va_start(args, rec);
    ret = el->cache->meth.cache_el_header_walk(el, comp, rec, args);
    va_end(args);
    return ret;
}
/*
static int merge_tables(void *datum, const char *name, const char *val)
{
    ap_cache_el *el = (ap_cache_el *)datum;
    ap_cache_el_header_remove(el, name);
    ap_cache_el_header_add(el, name, val);
    return APR_SUCCESS;
}
*/
apr_status_t ap_cache_el_header_merge(ap_cache_el *el, apr_table_t *tbl)
{
    apr_table_entry_t *elts = (apr_table_entry_t *) tbl->a.elts;
    int i;
/*
    const char *val;
*/
    
    for (i = 0; i < tbl->a.nelts; ++i)
        ap_cache_el_header_set(el, elts[i].key, elts[i].val);
    return APR_SUCCESS;
}
apr_status_t ap_cache_el_header_set(ap_cache_el *el, const char *hdrname,
                                   const char *hdrval)
{
    if(!el) return APR_BADARG;
    VERIFY_IMPL(el->cache, cache_el_hdr);
    return el->cache->meth.cache_el_hdr(el, hdrname, hdrval, AP_CACHE_CHANGE);
}
apr_status_t ap_cache_el_header_add(ap_cache_el *el, const char *hdrname,
                                   const char *hdrval)
{
    if(!el) return APR_BADARG;
    VERIFY_IMPL(el->cache, cache_el_hdr);
    return el->cache->meth.cache_el_hdr(el, hdrname, hdrval, AP_CACHE_CREATE);
}
apr_status_t ap_cache_el_header_remove(ap_cache_el *el, const char *hdrname)
{
    if(!el) return APR_BADARG;
    VERIFY_IMPL(el->cache, cache_el_hdr);
    return el->cache->meth.cache_el_hdr(el, hdrname, NULL, AP_CACHE_REMOVE);
}
apr_status_t ap_cache_el_header_clear(ap_cache_el *el)
{
    if(!el) return APR_BADARG;
    VERIFY_IMPL(el->cache, cache_el_reset);
    return el->cache->meth.cache_el_reset(el, AP_CACHE_HEADER);
}
apr_status_t ap_cache_el_data(ap_cache_el *el, apr_file_t **b)
{
    if(!b || !el) return APR_BADARG;
    *b = NULL;
    VERIFY_IMPL(el->cache, cache_el_data);
    return el->cache->meth.cache_el_data(el, b);
}
apr_status_t ap_cache_el_data_append(ap_cache_el *el, apr_file_t *data)
{
    apr_file_t *place;
    char buffer[HUGE_STRING_LEN];
    apr_status_t ret = APR_SUCCESS;
    apr_size_t nbytes, i, o;
    
    if((ret = ap_cache_el_data(el, &place)) != APR_SUCCESS) return ret;
    nbytes = HUGE_STRING_LEN;
    while(apr_read(data, buffer, &nbytes) == APR_SUCCESS && nbytes) {
        o = 0;
        while(nbytes)
        {
            i = nbytes;
            apr_write(place, buffer + o, &i);
            o += i;
            nbytes -= i;
        }
    }    
    return ret;
}
apr_status_t ap_cache_el_data_clear(ap_cache_el *el)
{
    if(!el) return APR_BADARG;
    VERIFY_IMPL(el->cache, cache_el_reset);
    return el->cache->meth.cache_el_reset(el, AP_CACHE_DATA);
}
apr_status_t ap_cache_el_finalize(ap_cache_el *el)
{
    if(!el) return APR_BADARG;
    VERIFY_IMPL(el->cache, cache_el_final);
    return el->cache->meth.cache_el_final(el);
}

/* hooks */
AP_IMPLEMENT_HOOK_RUN_FIRST(apr_status_t, cache_init, (ap_cache_handle_t **h, const char *desc, server_rec *s),
                         (h, desc, s), APR_ENOTIMPL)

