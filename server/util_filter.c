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

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "util_filter.h"

/* NOTE: Apache's current design doesn't allow a pool to be passed thru,
   so we depend on a global to hold the correct pool
*/
#define FILTER_POOL     apr_hook_global_pool
#include "ap_hooks.h"   /* for apr_hook_global_pool */

/* XXX: Should these be configurable parameters? */
#define THRESHOLD_MAX_BUFFER 65536
#define MAX_REQUESTS_IN_PIPELINE 5

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

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

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
                            ap_filter_direction_e direction,
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
        frec = apr_pcalloc(FILTER_POOL, sizeof(*frec));
        node->frec = frec;
        frec->name = normalized_name;
    }
    frec->filter_func = filter_func;
    frec->filter_init_func = filter_init;
    frec->ftype = ftype;
    frec->direction = direction;

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
    return register_filter(name, f, filter_init, ftype, AP_FILTER_INPUT,
                           &registered_input_filters);
}

AP_DECLARE(ap_filter_rec_t *) ap_register_output_filter(const char *name,
                                           ap_out_filter_func filter_func,
                                           ap_init_filter_func filter_init,
                                           ap_filter_type ftype)
{
    return ap_register_output_filter_protocol(name, filter_func,
                                              filter_init, ftype, 0);
}

AP_DECLARE(ap_filter_rec_t *) ap_register_output_filter_protocol(
                                           const char *name,
                                           ap_out_filter_func filter_func,
                                           ap_init_filter_func filter_init,
                                           ap_filter_type ftype,
                                           unsigned int proto_flags)
{
    ap_filter_rec_t* ret ;
    ap_filter_func f;
    f.out_func = filter_func;
    ret = register_filter(name, f, filter_init, ftype, AP_FILTER_OUTPUT,
                          &registered_output_filters);
    ret->proto_flags = proto_flags ;
    return ret ;
}

static ap_filter_t *add_any_filter_handle(ap_filter_rec_t *frec, void *ctx,
                                          request_rec *r, conn_rec *c,
                                          ap_filter_t **r_filters,
                                          ap_filter_t **p_filters,
                                          ap_filter_t **c_filters)
{
    apr_pool_t *p = frec->ftype < AP_FTYPE_CONNECTION && r ? r->pool : c->pool;
    ap_filter_t *f = apr_palloc(p, sizeof(*f));
    ap_filter_t **outf;

    if (frec->ftype < AP_FTYPE_PROTOCOL) {
        if (r) {
            outf = r_filters;
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(00080)
                          "a content filter was added without a request: %s", frec->name);
            return NULL;
        }
    }
    else if (frec->ftype < AP_FTYPE_CONNECTION) {
        if (r) {
            outf = p_filters;
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(00081)
                          "a protocol filter was added without a request: %s", frec->name);
            return NULL;
        }
    }
    else {
        outf = c_filters;
    }

    f->frec = frec;
    f->ctx = ctx;
    /* f->r must always be NULL for connection filters */
    f->r = frec->ftype < AP_FTYPE_CONNECTION ? r : NULL;
    f->c = c;
    f->next = NULL;
    f->bb = NULL;
    f->deferred_pool = NULL;

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

    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r ? r->connection : c, APLOGNO(00082)
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

    if ((f->bb) && !APR_BRIGADE_EMPTY(f->bb)) {
        apr_brigade_cleanup(f->bb);
    }

    if (f->deferred_pool) {
        apr_pool_destroy(f->deferred_pool);
        f->deferred_pool = NULL;
    }

    remove_any_filter(f, f->r ? &f->r->output_filters : NULL,
                      f->r ? &f->r->proto_output_filters : NULL,
                      &f->c->output_filters);
}

AP_DECLARE(apr_status_t) ap_remove_input_filter_byhandle(ap_filter_t *next,
                                                         const char *handle)
{
    ap_filter_t *found = NULL;
    ap_filter_rec_t *filter;

    if (!handle) {
        return APR_EINVAL;
    }
    filter = ap_get_input_filter_handle(handle);
    if (!filter) {
        return APR_NOTFOUND;
    }

    while (next) {
        if (next->frec == filter) {
            found = next;
            break;
        }
        next = next->next;
    }
    if (found) {
        ap_remove_input_filter(found);
        return APR_SUCCESS;
    }
    return APR_NOTFOUND;
}

AP_DECLARE(apr_status_t) ap_remove_output_filter_byhandle(ap_filter_t *next,
                                                          const char *handle)
{
    ap_filter_t *found = NULL;
    ap_filter_rec_t *filter;

    if (!handle) {
        return APR_EINVAL;
    }
    filter = ap_get_output_filter_handle(handle);
    if (!filter) {
        return APR_NOTFOUND;
    }

    while (next) {
        if (next->frec == filter) {
            found = next;
            break;
        }
        next = next->next;
    }
    if (found) {
        ap_remove_output_filter(found);
        return APR_SUCCESS;
    }
    return APR_NOTFOUND;
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
        apr_bucket *e = APR_BRIGADE_LAST(bb);

        if (e != APR_BRIGADE_SENTINEL(bb) && APR_BUCKET_IS_EOS(e) && next->r) {
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

/* Pass the buckets to the next filter in the filter stack
 * checking return status for filter errors.
 * returns: OK if ap_pass_brigade returns APR_SUCCESS
 *          AP_FILTER_ERROR if filter error exists
 *          HTTP_INTERNAL_SERVER_ERROR for all other cases
 *          logged with optional errmsg
 */
AP_DECLARE(apr_status_t) ap_pass_brigade_fchk(request_rec *r,
                                              apr_bucket_brigade *bb,
                                              const char *fmt,
                                              ...)
{
    apr_status_t rv;

    rv = ap_pass_brigade(r->output_filters, bb);
    if (rv != APR_SUCCESS) {
        if (rv != AP_FILTER_ERROR) {
            if (!fmt)
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(00083)
                              "ap_pass_brigade returned %d", rv);
            else {
                va_list ap;
                const char *res;
                va_start(ap, fmt);
                res = apr_pvsprintf(r->pool, fmt, ap);
                va_end(ap);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(03158)
                              "%s", res);
            }
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        return AP_FILTER_ERROR;
    }
    return OK;
}

AP_DECLARE(apr_status_t) ap_save_brigade(ap_filter_t *f,
                                         apr_bucket_brigade **saveto,
                                         apr_bucket_brigade **b, apr_pool_t *p)
{
    apr_bucket *e;
    apr_status_t rv, srv = APR_SUCCESS;

    /* If have never stored any data in the filter, then we had better
     * create an empty bucket brigade so that we can concat. Register
     * a cleanup to zero out the pointer if the pool is cleared.
     */
    if (!(*saveto)) {
        *saveto = apr_brigade_create(p, f->c->bucket_alloc);
    }

    for (e = APR_BRIGADE_FIRST(*b);
         e != APR_BRIGADE_SENTINEL(*b);
         e = APR_BUCKET_NEXT(e))
    {
        rv = apr_bucket_setaside(e, p);

        /* If the bucket type does not implement setaside, then
         * (hopefully) morph it into a bucket type which does, and set
         * *that* aside... */
        if (rv == APR_ENOTIMPL) {
            const char *s;
            apr_size_t n;

            rv = apr_bucket_read(e, &s, &n, APR_BLOCK_READ);
            if (rv == APR_SUCCESS) {
                rv = apr_bucket_setaside(e, p);
            }
        }

        if (rv != APR_SUCCESS) {
            srv = rv;
            /* Return an error but still save the brigade if
             * ->setaside() is really not implemented. */
            if (rv != APR_ENOTIMPL) {
                return rv;
            }
        }
    }
    APR_BRIGADE_CONCAT(*saveto, *b);
    return srv;
}

static apr_status_t filters_cleanup(void *data)
{
    ap_filter_t **key = data;

    apr_hash_set((*key)->c->filters, key, sizeof *key, NULL);

    return APR_SUCCESS;
}

AP_DECLARE(int) ap_filter_prepare_brigade(ap_filter_t *f, apr_pool_t **p)
{
    apr_pool_t *pool;
    ap_filter_t **key;

    if (!f->bb) {

        pool = f->r ? f->r->pool : f->c->pool;

        key = apr_pmemdup(pool, &f, sizeof f);
        apr_hash_set(f->c->filters, key, sizeof *key, f);

        f->bb = apr_brigade_create(pool, f->c->bucket_alloc);

        apr_pool_pre_cleanup_register(pool, key, filters_cleanup);

        if (p) {
            *p = pool;
        }

        return OK;
    }

    return DECLINED;
}

AP_DECLARE(apr_status_t) ap_filter_setaside_brigade(ap_filter_t *f,
        apr_bucket_brigade *bb)
{
    int loglevel = ap_get_conn_module_loglevel(f->c, APLOG_MODULE_INDEX);

    if (loglevel >= APLOG_TRACE6) {
        ap_log_cerror(
            APLOG_MARK, APLOG_TRACE6, 0, f->c,
            "setaside %s brigade to %s brigade in '%s' output filter",
            (APR_BRIGADE_EMPTY(bb) ? "empty" : "full"),
            (!f->bb || APR_BRIGADE_EMPTY(f->bb) ? "empty" : "full"), f->frec->name);
    }

    if (!APR_BRIGADE_EMPTY(bb)) {
        apr_pool_t *pool = NULL;
        /*
         * Set aside the brigade bb within f->bb.
         */
        ap_filter_prepare_brigade(f, &pool);

        /* decide what pool we setaside to, request pool or deferred pool? */
        if (f->r) {
            apr_bucket *e;
            for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb); e =
                    APR_BUCKET_NEXT(e)) {
                if (APR_BUCKET_IS_TRANSIENT(e)) {
                    int rv = apr_bucket_setaside(e, f->r->pool);
                    if (rv != APR_SUCCESS) {
                        return rv;
                    }
                }
            }
            pool = f->r->pool;
            APR_BRIGADE_CONCAT(f->bb, bb);
        }
        else {
            if (!f->deferred_pool) {
                apr_pool_create(&f->deferred_pool, f->c->pool);
                apr_pool_tag(f->deferred_pool, "deferred_pool");
            }
            pool = f->deferred_pool;
            return ap_save_brigade(f, &f->bb, &bb, pool);
        }

    }
    else if (f->deferred_pool) {
        /*
         * There are no more requests in the pipeline. We can just clear the
         * pool.
         */
        apr_brigade_cleanup(f->bb);
        apr_pool_clear(f->deferred_pool);
    }
    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_filter_reinstate_brigade(ap_filter_t *f,
                                                     apr_bucket_brigade *bb,
                                                     apr_bucket **flush_upto)
{
    apr_bucket *bucket, *next;
    apr_size_t bytes_in_brigade, non_file_bytes_in_brigade;
    int eor_buckets_in_brigade, morphing_bucket_in_brigade;
    int loglevel = ap_get_conn_module_loglevel(f->c, APLOG_MODULE_INDEX);

    if (loglevel >= APLOG_TRACE6) {
        ap_log_cerror(
            APLOG_MARK, APLOG_TRACE6, 0, f->c,
            "reinstate %s brigade to %s brigade in '%s' output filter",
            (!f->bb || APR_BRIGADE_EMPTY(f->bb) ? "empty" : "full"),
            (APR_BRIGADE_EMPTY(bb) ? "empty" : "full"), f->frec->name);
    }

    if (f->bb && !APR_BRIGADE_EMPTY(f->bb)) {
        APR_BRIGADE_PREPEND(bb, f->bb);
    }

    /*
     * Determine if and up to which bucket we need to do a blocking write:
     *
     *  a) The brigade contains a flush bucket: Do a blocking write
     *     of everything up that point.
     *
     *  b) The request is in CONN_STATE_HANDLER state, and the brigade
     *     contains at least THRESHOLD_MAX_BUFFER bytes in non-file
     *     buckets: Do blocking writes until the amount of data in the
     *     buffer is less than THRESHOLD_MAX_BUFFER.  (The point of this
     *     rule is to provide flow control, in case a handler is
     *     streaming out lots of data faster than the data can be
     *     sent to the client.)
     *
     *  c) The request is in CONN_STATE_HANDLER state, and the brigade
     *     contains at least MAX_REQUESTS_IN_PIPELINE EOR buckets:
     *     Do blocking writes until less than MAX_REQUESTS_IN_PIPELINE EOR
     *     buckets are left. (The point of this rule is to prevent too many
     *     FDs being kept open by pipelined requests, possibly allowing a
     *     DoS).
     *
     *  d) The request is being served by a connection filter and the
     *     brigade contains a morphing bucket: If there was no other
     *     reason to do a blocking write yet, try reading the bucket. If its
     *     contents fit into memory before THRESHOLD_MAX_BUFFER is reached,
     *     everything is fine. Otherwise we need to do a blocking write the
     *     up to and including the morphing bucket, because ap_save_brigade()
     *     would read the whole bucket into memory later on.
     */

    *flush_upto = NULL;

    bytes_in_brigade = 0;
    non_file_bytes_in_brigade = 0;
    eor_buckets_in_brigade = 0;
    morphing_bucket_in_brigade = 0;

    for (bucket = APR_BRIGADE_FIRST(bb); bucket != APR_BRIGADE_SENTINEL(bb);
         bucket = next) {
        next = APR_BUCKET_NEXT(bucket);

        if (!APR_BUCKET_IS_METADATA(bucket)) {
            if (bucket->length == (apr_size_t)-1) {
                /*
                 * A setaside of morphing buckets would read everything into
                 * memory. Instead, we will flush everything up to and
                 * including this bucket.
                 */
                morphing_bucket_in_brigade = 1;
            }
            else {
                bytes_in_brigade += bucket->length;
                if (!APR_BUCKET_IS_FILE(bucket))
                    non_file_bytes_in_brigade += bucket->length;
            }
        }
        else if (AP_BUCKET_IS_EOR(bucket)) {
            eor_buckets_in_brigade++;
        }

        if (APR_BUCKET_IS_FLUSH(bucket)
            || non_file_bytes_in_brigade >= THRESHOLD_MAX_BUFFER
            || (!f->r && morphing_bucket_in_brigade)
            || eor_buckets_in_brigade > MAX_REQUESTS_IN_PIPELINE) {
            /* this segment of the brigade MUST be sent before returning. */

            if (loglevel >= APLOG_TRACE6) {
                char *reason = APR_BUCKET_IS_FLUSH(bucket) ?
                               "FLUSH bucket" :
                               (non_file_bytes_in_brigade >= THRESHOLD_MAX_BUFFER) ?
                               "THRESHOLD_MAX_BUFFER" :
                               (!f->r && morphing_bucket_in_brigade) ? "morphing bucket" :
                               "MAX_REQUESTS_IN_PIPELINE";
                ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, f->c,
                              "will flush because of %s", reason);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c,
                              "seen in brigade%s: bytes: %" APR_SIZE_T_FMT
                              ", non-file bytes: %" APR_SIZE_T_FMT ", eor "
                              "buckets: %d, morphing buckets: %d",
                              *flush_upto == NULL ? " so far"
                                                  : " since last flush point",
                              bytes_in_brigade,
                              non_file_bytes_in_brigade,
                              eor_buckets_in_brigade,
                              morphing_bucket_in_brigade);
            }
            /*
             * Defer the actual blocking write to avoid doing many writes.
             */
            *flush_upto = next;

            bytes_in_brigade = 0;
            non_file_bytes_in_brigade = 0;
            eor_buckets_in_brigade = 0;
            morphing_bucket_in_brigade = 0;
        }
    }

    if (loglevel >= APLOG_TRACE8) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c,
                      "brigade contains: bytes: %" APR_SIZE_T_FMT
                      ", non-file bytes: %" APR_SIZE_T_FMT
                      ", eor buckets: %d, morphing buckets: %d",
                      bytes_in_brigade, non_file_bytes_in_brigade,
                      eor_buckets_in_brigade, morphing_bucket_in_brigade);
    }

    return APR_SUCCESS;
}

AP_DECLARE(int) ap_filter_should_yield(ap_filter_t *f)
{
    /*
     * Handle the AsyncFilter directive. We limit the filters that are
     * eligible for asynchronous handling here.
     */
    if (f->frec->ftype < f->c->async_filter) {
        return 0;
    }

    /*
     * This function decides whether a filter should yield due to buffered
     * data in a downstream filter. If a downstream filter buffers we
     * must back off so we don't overwhelm the server. If this function
     * returns true, the filter should call ap_filter_setaside_brigade()
     * to save unprocessed buckets, and then reinstate those buckets on
     * the next call with ap_filter_reinstate_brigade() and continue
     * where it left off.
     *
     * If this function is forced to return zero, we return back to
     * synchronous filter behaviour.
     *
     * Subrequests present us with a problem - we don't know how much data
     * they will produce and therefore how much buffering we'll need, and
     * if a subrequest had to trigger buffering, but next subrequest wouldn't
     * know when the previous one had finished sending data and buckets
     * could be sent out of order.
     *
     * In the case of subrequests, deny the ability to yield. When the data
     * reaches the filters from the main request, they will be setaside
     * there in the right order and the request will be given the
     * opportunity to yield.
     */
    if (f->r && f->r->main) {
        return 0;
    }

    /*
     * This is either a main request or internal redirect, or it is a
     * connection filter. Yield if there is any buffered data downstream
     * from us.
     */
    while (f) {
        if (f->bb && !APR_BRIGADE_EMPTY(f->bb)) {
            return 1;
        }
        f = f->next;
    }
    return 0;
}

AP_DECLARE(int) ap_filter_output_pending(conn_rec *c)
{
    apr_hash_index_t *rindex;
    int data_in_output_filters = DECLINED;

    rindex = apr_hash_first(NULL, c->filters);
    while (rindex) {
        ap_filter_t *f = apr_hash_this_val(rindex);

        if (f->frec->direction == AP_FILTER_OUTPUT && f->bb
                && !APR_BRIGADE_EMPTY(f->bb)) {

            apr_status_t rv;

            rv = ap_pass_brigade(f, c->empty);
            apr_brigade_cleanup(c->empty);
            if (APR_SUCCESS != rv) {
                ap_log_cerror(
                        APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO(00470)
                        "write failure in '%s' output filter", f->frec->name);
                return rv;
            }

            if (ap_filter_should_yield(f)) {
                data_in_output_filters = OK;
            }
        }

        rindex = apr_hash_next(rindex);
    }

    return data_in_output_filters;
}

AP_DECLARE(int) ap_filter_input_pending(conn_rec *c)
{
    apr_hash_index_t *rindex;

    rindex = apr_hash_first(NULL, c->filters);
    while (rindex) {
        ap_filter_t *f = apr_hash_this_val(rindex);

        if (f->frec->direction == AP_FILTER_INPUT && f->bb) {
            apr_bucket *e = APR_BRIGADE_FIRST(f->bb);

            /* if there is at least one non-morphing bucket
             * in place, then we have data pending
             */
            if (e != APR_BRIGADE_SENTINEL(f->bb)
                    && e->length != (apr_size_t)(-1)) {
                return OK;
            }

        }

        rindex = apr_hash_next(rindex);
    }

    return DECLINED;
}

AP_DECLARE_NONSTD(apr_status_t) ap_filter_flush(apr_bucket_brigade *bb,
                                                void *ctx)
{
    ap_filter_t *f = ctx;
    apr_status_t rv;

    rv = ap_pass_brigade(f, bb);

    /* Before invocation of the flush callback, apr_brigade_write et
     * al may place transient buckets in the brigade, which will fall
     * out of scope after returning.  Empty the brigade here, to avoid
     * issues with leaving such buckets in the brigade if some filter
     * fails and leaves a non-empty brigade. */
    apr_brigade_cleanup(bb);

    return rv;
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
AP_DECLARE(void) ap_filter_protocol(ap_filter_t *f, unsigned int flags)
{
    f->frec->proto_flags = flags ;
}
