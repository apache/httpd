/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_log.h"
#include "util_filter.h"

/* NOTE: Apache's current design doesn't allow a pool to be passed thru,
   so we depend on a global to hold the correct pool
*/
#define FILTER_POOL     apr_hook_global_pool
#include "apr_hooks.h"   /* for apr_hook_global_pool */

/*
** This macro returns true/false if a given filter should be inserted BEFORE
** another filter. This will happen when one of: 1) there isn't another
** filter; 2) that filter has a higher filter type (class); 3) that filter
** corresponds to a different request.
*/
#define INSERT_BEFORE(f, before_this) ((before_this) == NULL \
                           || (before_this)->frec->ftype > (f)->frec->ftype \
                           || (before_this)->r != (f)->r)

/* Trie structure to hold the mapping from registered
 * filter names to filters
 */

typedef struct filter_trie_node filter_trie_node;

typedef struct {
    int c;
    filter_trie_node *child;
} filter_trie_child_ptr;

/* Each trie node has an array of pointers to its children.
 * The array is kept in sorted order so that add_any_filter()
 * can do a binary search
 */
struct filter_trie_node {
    ap_filter_rec_t *frec;
    filter_trie_child_ptr *children;
    int nchildren;
    int size;
};

#define TRIE_INITIAL_SIZE 4

/* Link a trie node to its parent
 */
static void trie_node_link(apr_pool_t *p, filter_trie_node *parent,
                           filter_trie_node *child, int c)
{
    int i, j;

    if (parent->nchildren == parent->size) {
        filter_trie_child_ptr *new;
        parent->size *= 2;
        new = (filter_trie_child_ptr *)apr_palloc(p, parent->size *
                                             sizeof(filter_trie_child_ptr));
        memcpy(new, parent->children, parent->nchildren *
               sizeof(filter_trie_child_ptr));
        parent->children = new;
    }

    for (i = 0; i < parent->nchildren; i++) {
        if (c == parent->children[i].c) {
            return;
        }
        else if (c < parent->children[i].c) {
            break;
        }
    }
    for (j = parent->nchildren; j > i; j--) {
        parent->children[j].c = parent->children[j - 1].c;
        parent->children[j].child = parent->children[j - 1].child;
    }
    parent->children[i].c = c;
    parent->children[i].child = child;

    parent->nchildren++;
}

/* Allocate a new node for a trie.
 * If parent is non-NULL, link the new node under the parent node with
 * key 'c' (or, if an existing child node matches, return that one)
 */
static filter_trie_node *trie_node_alloc(apr_pool_t *p,
                                         filter_trie_node *parent, char c)
{
    filter_trie_node *new_node;
    if (parent) {
        int i;
        for (i = 0; i < parent->nchildren; i++) {
            if (c == parent->children[i].c) {
                return parent->children[i].child;
            }
            else if (c < parent->children[i].c) {
                break;
            }
        }
        new_node =
            (filter_trie_node *)apr_palloc(p, sizeof(filter_trie_node));
        trie_node_link(p, parent, new_node, c);
    }
    else { /* No parent node */
        new_node = (filter_trie_node *)apr_palloc(p,
                                                  sizeof(filter_trie_node));
    }

    new_node->frec = NULL;
    new_node->nchildren = 0;
    new_node->size = TRIE_INITIAL_SIZE;
    new_node->children = (filter_trie_child_ptr *)apr_palloc(p,
                             new_node->size * sizeof(filter_trie_child_ptr));
    return new_node;
}

static filter_trie_node *registered_output_filters = NULL;
static filter_trie_node *registered_input_filters = NULL;


static apr_status_t filter_cleanup(void *ctx)
{
    registered_output_filters = NULL;
    registered_input_filters = NULL;
    return APR_SUCCESS;
}

static ap_filter_rec_t *get_filter_handle(const char *name,
                                          const filter_trie_node *filter_set)
{
    if (filter_set) {
        const char *n;
        const filter_trie_node *node;

        node = filter_set;
        for (n = name; *n; n++) {
            int start, end;
            start = 0;
            end = node->nchildren - 1;
            while (end >= start) {
                int middle = (end + start) / 2;
                char ch = node->children[middle].c;
                if (*n == ch) {
                    node = node->children[middle].child;
                    break;
                }
                else if (*n < ch) {
                    end = middle - 1;
                }
                else {
                    start = middle + 1;
                }
            }
            if (end < start) {
                node = NULL;
                break;
            }
        }

        if (node && node->frec) {
            return node->frec;
        }
    }
    return NULL;
}

AP_DECLARE(ap_filter_rec_t *)ap_get_output_filter_handle(const char *name)
{
    return get_filter_handle(name, registered_output_filters);
}

AP_DECLARE(ap_filter_rec_t *)ap_get_input_filter_handle(const char *name)
{
    return get_filter_handle(name, registered_input_filters);
}

static ap_filter_rec_t *register_filter(const char *name,
                            ap_filter_func filter_func,
                            ap_init_filter_func filter_init,
                            ap_filter_type ftype,
                            filter_trie_node **reg_filter_set)
{
    ap_filter_rec_t *frec;
    char *normalized_name;
    const char *n;
    filter_trie_node *node;

    if (!*reg_filter_set) {
        *reg_filter_set = trie_node_alloc(FILTER_POOL, NULL, 0);
    }

    normalized_name = apr_pstrdup(FILTER_POOL, name);
    ap_str_tolower(normalized_name);

    node = *reg_filter_set;
    for (n = normalized_name; *n; n++) {
        filter_trie_node *child = trie_node_alloc(FILTER_POOL, node, *n);
        if (apr_isalpha(*n)) {
            trie_node_link(FILTER_POOL, node, child, apr_toupper(*n));
        }
        node = child;
    }
    if (node->frec) {
        frec = node->frec;
    }
    else {
        frec = apr_palloc(FILTER_POOL, sizeof(*frec));
        node->frec = frec;
        frec->name = normalized_name;
    }
    frec->filter_func = filter_func;
    frec->filter_init_func = filter_init;
    frec->ftype = ftype;
    
    apr_pool_cleanup_register(FILTER_POOL, NULL, filter_cleanup, 
                              apr_pool_cleanup_null);
    return frec;
}

AP_DECLARE(ap_filter_rec_t *) ap_register_input_filter(const char *name,
                                          ap_in_filter_func filter_func,
                                          ap_init_filter_func filter_init,
                                          ap_filter_type ftype)
{
    ap_filter_func f;
    f.in_func = filter_func;
    return register_filter(name, f, filter_init, ftype,
                           &registered_input_filters);
}                                                                    

AP_DECLARE(ap_filter_rec_t *) ap_register_output_filter(const char *name,
                                           ap_out_filter_func filter_func,
                                           ap_init_filter_func filter_init,
                                           ap_filter_type ftype)
{
    ap_filter_func f;
    f.out_func = filter_func;
    return register_filter(name, f, filter_init, ftype,
                           &registered_output_filters);
}

static ap_filter_t *add_any_filter_handle(ap_filter_rec_t *frec, void *ctx, 
                                          request_rec *r, conn_rec *c, 
                                          ap_filter_t **r_filters,
                                          ap_filter_t **p_filters,
                                          ap_filter_t **c_filters)
{
    apr_pool_t* p = r ? r->pool : c->pool;
    ap_filter_t *f = apr_palloc(p, sizeof(*f));
    ap_filter_t **outf;

    if (frec->ftype < AP_FTYPE_PROTOCOL) {
        if (r) {
            outf = r_filters;
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                      "a content filter was added without a request: %s", frec->name);
            return NULL;
        }
    }
    else if (frec->ftype < AP_FTYPE_CONNECTION) {
        if (r) {
            outf = p_filters;
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "a protocol filter was added without a request: %s", frec->name);
            return NULL;
        }
    }
    else {
        outf = c_filters;
    }

    f->frec = frec;
    f->ctx = ctx;
    f->r = r;
    f->c = c;
    f->next = NULL;

    if (INSERT_BEFORE(f, *outf)) {
        f->next = *outf;

        if (*outf) {
            ap_filter_t *first = NULL;

            if (r) {
                /* If we are adding our first non-connection filter,
                 * Then don't try to find the right location, it is
                 * automatically first.
                 */
                if (*r_filters != *c_filters) {
                    first = *r_filters;
                    while (first && (first->next != (*outf))) {
                        first = first->next;
                    }
                }
            }
            if (first && first != (*outf)) {
                first->next = f;
            }
        }
        *outf = f;
    }
    else {
        ap_filter_t *fscan = *outf;
        while (!INSERT_BEFORE(f, fscan->next))
            fscan = fscan->next;

        f->next = fscan->next;
	fscan->next = f;
    }

    if (frec->ftype < AP_FTYPE_CONNECTION && (*r_filters == *c_filters)) {
        *r_filters = *p_filters;
    }
    return f;
}

static ap_filter_t *add_any_filter(const char *name, void *ctx, 
                                   request_rec *r, conn_rec *c, 
                                   const filter_trie_node *reg_filter_set,
                                   ap_filter_t **r_filters, 
                                   ap_filter_t **p_filters,
                                   ap_filter_t **c_filters)
{
    if (reg_filter_set) {
        const char *n;
        const filter_trie_node *node;

        node = reg_filter_set;
        for (n = name; *n; n++) {
            int start, end;
            start = 0;
            end = node->nchildren - 1;
            while (end >= start) {
                int middle = (end + start) / 2;
                char ch = node->children[middle].c;
                if (*n == ch) {
                    node = node->children[middle].child;
                    break;
                }
                else if (*n < ch) {
                    end = middle - 1;
                }
                else {
                    start = middle + 1;
                }
            }
            if (end < start) {
                node = NULL;
                break;
            }
        }

        if (node && node->frec) {
            return add_any_filter_handle(node->frec, ctx, r, c, r_filters, 
                                         p_filters, c_filters);
        }
    }

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                 "an unknown filter was not added: %s", name);
    return NULL;
}

AP_DECLARE(ap_filter_t *) ap_add_input_filter(const char *name, void *ctx,
                                              request_rec *r, conn_rec *c)
{
    return add_any_filter(name, ctx, r, c, registered_input_filters,
                          r ? &r->input_filters : NULL, 
                          r ? &r->proto_input_filters : NULL, &c->input_filters);
}

AP_DECLARE(ap_filter_t *) ap_add_input_filter_handle(ap_filter_rec_t *f,
                                                     void *ctx,
                                                     request_rec *r,
                                                     conn_rec *c)
{
    return add_any_filter_handle(f, ctx, r, c, r ? &r->input_filters : NULL,
                                 r ? &r->proto_input_filters : NULL, 
                                 &c->input_filters);
}

AP_DECLARE(ap_filter_t *) ap_add_output_filter(const char *name, void *ctx,
                                               request_rec *r, conn_rec *c)
{
    return add_any_filter(name, ctx, r, c, registered_output_filters,
                          r ? &r->output_filters : NULL, 
                          r ? &r->proto_output_filters : NULL, &c->output_filters);
}

AP_DECLARE(ap_filter_t *) ap_add_output_filter_handle(ap_filter_rec_t *f,
                                                      void *ctx,
                                                      request_rec *r,
                                                      conn_rec *c)
{
    return add_any_filter_handle(f, ctx, r, c, r ? &r->output_filters : NULL,
                                 r ? &r->proto_output_filters : NULL,
                                 &c->output_filters);
}

static void remove_any_filter(ap_filter_t *f, ap_filter_t **r_filt, ap_filter_t **p_filt,
                              ap_filter_t **c_filt)
{
    ap_filter_t **curr = r_filt ? r_filt : c_filt;
    ap_filter_t *fscan = *curr;

    if (p_filt && *p_filt == f)
        *p_filt = (*p_filt)->next;

    if (*curr == f) {
        *curr = (*curr)->next;
        return;
    }

    while (fscan->next != f) {
        if (!(fscan = fscan->next)) {
            return;
        }
    }

    fscan->next = f->next;
}

AP_DECLARE(void) ap_remove_input_filter(ap_filter_t *f)
{
    remove_any_filter(f, f->r ? &f->r->input_filters : NULL, 
                      f->r ? &f->r->proto_input_filters : NULL, 
                      &f->c->input_filters);
}

AP_DECLARE(void) ap_remove_output_filter(ap_filter_t *f)
{
    remove_any_filter(f, f->r ? &f->r->output_filters : NULL, 
                      f->r ? &f->r->proto_output_filters : NULL, 
                      &f->c->output_filters);
}

/* 
 * Read data from the next filter in the filter stack.  Data should be 
 * modified in the bucket brigade that is passed in.  The core allocates the
 * bucket brigade, modules that wish to replace large chunks of data or to
 * save data off to the side should probably create their own temporary
 * brigade especially for that use.
 */
AP_DECLARE(apr_status_t) ap_get_brigade(ap_filter_t *next,
                                        apr_bucket_brigade *bb, 
                                        ap_input_mode_t mode,
                                        apr_read_type_e block,
                                        apr_off_t readbytes)
{
    if (next) {
        return next->frec->filter_func.in_func(next, bb, mode, block, 
                                               readbytes);
    }
    return AP_NOBODY_READ;
}

/* Pass the buckets to the next filter in the filter stack.  If the
 * current filter is a handler, we should get NULL passed in instead of
 * the current filter.  At that point, we can just call the first filter in
 * the stack, or r->output_filters.
 */
AP_DECLARE(apr_status_t) ap_pass_brigade(ap_filter_t *next, 
                                         apr_bucket_brigade *bb)
{
    if (next) {
        apr_bucket *e;
        if ((e = APR_BRIGADE_LAST(bb)) && APR_BUCKET_IS_EOS(e) && next->r) {
            /* This is only safe because HTTP_HEADER filter is always in
             * the filter stack.   This ensures that there is ALWAYS a
             * request-based filter that we can attach this to.  If the
             * HTTP_FILTER is removed, and another filter is not put in its
             * place, then handlers like mod_cgi, which attach their own
             * EOS bucket to the brigade will be broken, because we will
             * get two EOS buckets on the same request.
             */
            next->r->eos_sent = 1;

            /* remember the eos for internal redirects, too */
            if (next->r->prev) {
                request_rec *prev = next->r->prev;

                while (prev) {
                    prev->eos_sent = 1;
                    prev = prev->prev;
                }
            }
        }
        return next->frec->filter_func.out_func(next, bb);
    }
    return AP_NOBODY_WROTE;
}

AP_DECLARE(apr_status_t) ap_save_brigade(ap_filter_t *f, 
                                         apr_bucket_brigade **saveto,
                                         apr_bucket_brigade **b, apr_pool_t *p)
{
    apr_bucket *e;
    apr_status_t rv;

    /* If have never stored any data in the filter, then we had better
     * create an empty bucket brigade so that we can concat.
     */
    if (!(*saveto)) {
        *saveto = apr_brigade_create(p, f->c->bucket_alloc);
    }
    
    APR_RING_FOREACH(e, &(*b)->list, apr_bucket, link) {
        rv = apr_bucket_setaside(e, p);
        if (rv != APR_SUCCESS
            /* ### this ENOTIMPL will go away once we implement setaside
               ### for all bucket types. */
            && rv != APR_ENOTIMPL) {
            return rv;
        }
    }
    APR_BRIGADE_CONCAT(*saveto, *b);
    return APR_SUCCESS;
}

AP_DECLARE_NONSTD(apr_status_t) ap_filter_flush(apr_bucket_brigade *bb, 
                                                void *ctx)
{
    ap_filter_t *f = ctx;

    return ap_pass_brigade(f, bb);
}

AP_DECLARE(apr_status_t) ap_fflush(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *b;

    b = apr_bucket_flush_create(f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    return ap_pass_brigade(f, bb);
}

AP_DECLARE_NONSTD(apr_status_t) ap_fputstrs(ap_filter_t *f,
                                            apr_bucket_brigade *bb, ...)
{
    va_list args;
    apr_status_t rv;

    va_start(args, bb);
    rv = apr_brigade_vputstrs(bb, ap_filter_flush, f, args);
    va_end(args);
    return rv;
}

AP_DECLARE_NONSTD(apr_status_t) ap_fprintf(ap_filter_t *f,
                                           apr_bucket_brigade *bb,
                                           const char *fmt,
                                           ...)
{
    va_list args;
    apr_status_t rv;

    va_start(args, fmt);
    rv = apr_brigade_vprintf(bb, ap_filter_flush, f, fmt, args);
    va_end(args);
    return rv;
}
