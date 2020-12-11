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

struct ap_filter_private {
    /* Link to a pending_ring (keep first preferably) */
    APR_RING_ENTRY(ap_filter_private) pending;

    /* Backref to owning filter */
    ap_filter_t *f;

    /* Pending buckets */
    apr_bucket_brigade *bb;
    /* Dedicated pool to use for deferred writes. */
    apr_pool_t *deferred_pool;
};
APR_RING_HEAD(pending_ring, ap_filter_private);

struct spare_data {
    APR_RING_ENTRY(spare_data) link;
    void *data;
};
APR_RING_HEAD(spare_ring, spare_data);

struct ap_filter_conn_ctx {
    struct pending_ring *pending_input_filters;
    struct pending_ring *pending_output_filters;

    struct spare_ring *spare_containers,
                      *spare_brigades,
                      *spare_filters,
                      *dead_filters;
};

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

static struct ap_filter_conn_ctx *get_conn_ctx(conn_rec *c)
{
    struct ap_filter_conn_ctx *x = c->filter_conn_ctx;
    if (!x) {
        c->filter_conn_ctx = x = apr_pcalloc(c->pool, sizeof(*x));
    }
    return x;
}

static APR_INLINE
void make_spare_ring(struct spare_ring **ring, apr_pool_t *p)
{
    if (!*ring) {
        *ring = apr_palloc(p, sizeof(**ring));
        APR_RING_INIT(*ring, spare_data, link);
    }
}

static void *get_spare(conn_rec *c, struct spare_ring *ring)
{
    void *data = NULL;

    if (ring && !APR_RING_EMPTY(ring, spare_data, link)) {
        struct spare_data *sdata = APR_RING_FIRST(ring);
        struct ap_filter_conn_ctx *x = c->filter_conn_ctx;

        data = sdata->data;
        sdata->data = NULL;
        APR_RING_REMOVE(sdata, link);
        make_spare_ring(&x->spare_containers, c->pool);
        APR_RING_INSERT_TAIL(x->spare_containers, sdata, spare_data, link);
    }

    return data;
}

static void put_spare(conn_rec *c, void *data, struct spare_ring **ring)
{
    struct ap_filter_conn_ctx *x = c->filter_conn_ctx;
    struct spare_data *sdata;

    if (!x->spare_containers || APR_RING_EMPTY(x->spare_containers,
                                               spare_data, link)) {
        sdata = apr_palloc(c->pool, sizeof(*sdata));
    }
    else {
        sdata = APR_RING_FIRST(x->spare_containers);
        APR_RING_REMOVE(sdata, link);
    }
    sdata->data = data;

    make_spare_ring(ring, c->pool);
    APR_RING_INSERT_TAIL(*ring, sdata, spare_data, link);
}

AP_DECLARE(apr_bucket_brigade *) ap_acquire_brigade(conn_rec *c)
{
    struct ap_filter_conn_ctx *x = get_conn_ctx(c);
    apr_bucket_brigade *bb = get_spare(c, x->spare_brigades);

    return bb ? bb : apr_brigade_create(c->pool, c->bucket_alloc);
}

AP_DECLARE(void) ap_release_brigade(conn_rec *c, apr_bucket_brigade *bb)
{
    struct ap_filter_conn_ctx *x = get_conn_ctx(c);

    AP_DEBUG_ASSERT(bb->p == c->pool && bb->bucket_alloc == c->bucket_alloc);

    apr_brigade_cleanup(bb);
    put_spare(c, bb, &x->spare_brigades);
}

static apr_status_t request_filter_cleanup(void *arg)
{
    ap_filter_t *f = arg;
    conn_rec *c = f->c;
    struct ap_filter_conn_ctx *x = c->filter_conn_ctx;

    /* A request filter is cleaned up with an EOR bucket, so possibly
     * while it is handling/passing the EOR, and we want each filter or
     * ap_filter_output_pending() to be able to dereference f until they
     * return. So request filters are recycled in dead_filters and will only
     * be moved to spare_filters when recycle_dead_filters() is called, i.e.
     * in ap_filter_{in,out}put_pending(). Set f->r to NULL still for any use
     * after free to crash quite reliably.
     */
    f->r = NULL;
    put_spare(c, f, &x->dead_filters);

    return APR_SUCCESS;
}

static void recycle_dead_filters(conn_rec *c)
{
    struct ap_filter_conn_ctx *x = c->filter_conn_ctx;

    if (!x || !x->dead_filters) {
        return;
    }

    make_spare_ring(&x->spare_filters, c->pool);
    APR_RING_CONCAT(x->spare_filters, x->dead_filters, spare_data, link);
}

static ap_filter_t *add_any_filter_handle(ap_filter_rec_t *frec, void *ctx,
                                          request_rec *r, conn_rec *c,
                                          ap_filter_t **r_filters,
                                          ap_filter_t **p_filters,
                                          ap_filter_t **c_filters)
{
    ap_filter_t *f;
    ap_filter_t **outf;
    struct ap_filter_conn_ctx *x;
    struct ap_filter_private *fp;

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

    x = get_conn_ctx(c);
    f = get_spare(c, x->spare_filters);
    if (f) {
        fp = f->priv;
    }
    else {
        f = apr_palloc(c->pool, sizeof(*f));
        fp = apr_palloc(c->pool, sizeof(*fp));
    }
    memset(f, 0, sizeof(*f));
    memset(fp, 0, sizeof(*fp));
    APR_RING_ELEM_INIT(fp, pending);
    f->priv = fp;
    fp->f = f;

    f->frec = frec;
    f->ctx = ctx;
    /* f->r must always be NULL for connection filters */
    if (r && frec->ftype < AP_FTYPE_CONNECTION) {
        apr_pool_cleanup_register(r->pool, f, request_filter_cleanup,
                                  apr_pool_cleanup_null);
        f->r = r;
    }
    f->c = c;

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

static APR_INLINE int is_pending_filter(ap_filter_t *f)
{
    struct ap_filter_private *fp = f->priv;
    return APR_RING_NEXT(fp, pending) != fp;
}

static apr_status_t pending_filter_cleanup(void *arg)
{
    ap_filter_t *f = arg;
    struct ap_filter_private *fp = f->priv;

    if (is_pending_filter(f)) {
        APR_RING_REMOVE(fp, pending);
        APR_RING_ELEM_INIT(fp, pending);
    }

    if (fp->bb) {
        ap_release_brigade(f->c, fp->bb);
        fp->bb = NULL;
    }

    return APR_SUCCESS;
}

static void remove_any_filter(ap_filter_t *f, ap_filter_t **r_filt, ap_filter_t **p_filt,
                              ap_filter_t **c_filt)
{
    ap_filter_t **curr = r_filt ? r_filt : c_filt;
    ap_filter_t *fscan = *curr;

    pending_filter_cleanup(f);

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
    struct ap_filter_private *fp = f->priv;

    if (fp->deferred_pool) {
        AP_DEBUG_ASSERT(fp->bb);
        apr_brigade_cleanup(fp->bb);
        apr_pool_destroy(fp->deferred_pool);
        fp->deferred_pool = NULL;
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

AP_DECLARE(int) ap_filter_prepare_brigade(ap_filter_t *f)
{
    conn_rec *c = f->c;
    struct ap_filter_conn_ctx *x = get_conn_ctx(c);
    struct ap_filter_private *fp = f->priv, *e;
    struct pending_ring **ref, *pendings;
    ap_filter_t *next;

    if (is_pending_filter(f)) {
        return DECLINED;
    }

    if (!fp->bb) {
        fp->bb = ap_acquire_brigade(c);
        if (f->r) {
            /* Take care of request filters that don't remove themselves
             * from the chain(s), when f->r is being destroyed.
             */
            apr_pool_cleanup_register(f->r->pool, f,
                                      pending_filter_cleanup,
                                      apr_pool_cleanup_null);
        }
        else {
            /* In fp->bb there may be buckets on fp->deferred_pool, so take
             * care to always pre_cleanup the former before the latter.
             */
            apr_pool_pre_cleanup_register(c->pool, f,
                                          pending_filter_cleanup);
        }
    }

    if (f->frec->direction == AP_FILTER_INPUT) {
        ref = &x->pending_input_filters;
    }
    else {
        ref = &x->pending_output_filters;
    }
    pendings = *ref;

    /* Pending reads/writes must happen in the reverse order of the actual
     * in/output filters (in/outer most first), though we still maintain the
     * ring in the same "next" order as filters (walking is backward). So find
     * the first f->next filter already in place and insert before if
     * any, otherwise insert last.
     */
    if (pendings) {
        for (next = f->next; next; next = next->next) {
            for (e = APR_RING_FIRST(pendings);
                 e != APR_RING_SENTINEL(pendings, ap_filter_private, pending);
                 e = APR_RING_NEXT(e, pending)) {
                if (e == next->priv) {
                    APR_RING_INSERT_BEFORE(e, fp, pending);
                    return OK;
                }
            }
        }
    }
    else {
        pendings = *ref = apr_palloc(c->pool, sizeof(*pendings));
        APR_RING_INIT(pendings, ap_filter_private, pending);
    }
    APR_RING_INSERT_TAIL(pendings, fp, ap_filter_private, pending);
    return OK;
}

static apr_status_t save_aside_brigade(struct ap_filter_private *fp,
                                       apr_bucket_brigade *bb)
{
    if (!fp->deferred_pool) {
        apr_pool_create(&fp->deferred_pool, fp->f->c->pool);
        apr_pool_tag(fp->deferred_pool, "deferred_pool");
    }
    return ap_save_brigade(fp->f, &fp->bb, &bb, fp->deferred_pool);
}

AP_DECLARE(apr_status_t) ap_filter_setaside_brigade(ap_filter_t *f,
                                                    apr_bucket_brigade *bb)
{
    apr_status_t rv = APR_SUCCESS;
    struct ap_filter_private *fp = f->priv;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, f->c,
                  "setaside %s brigade to %s brigade in '%s' %sput filter",
                  APR_BRIGADE_EMPTY(bb) ? "empty" : "full",
                  (!fp->bb || APR_BRIGADE_EMPTY(fp->bb)) ? "empty" : "full",
                  f->frec->name,
                  f->frec->direction == AP_FILTER_INPUT ? "in" : "out");

    /* This API is not suitable for request filters */
    if (f->frec->ftype < AP_FTYPE_CONNECTION) {
        return APR_ENOTIMPL;
    }

    if (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket_brigade *tmp_bb = NULL;
        int batched_buckets = 0;
        apr_bucket *e, *next;

        /*
         * Set aside the brigade bb to fp->bb.
         */
        ap_filter_prepare_brigade(f);

        for (e = APR_BRIGADE_FIRST(bb);
             e != APR_BRIGADE_SENTINEL(bb);
             e = next) {
            next = APR_BUCKET_NEXT(e);

            /* Opaque buckets (length == -1) are moved, so assumed to have
             * next EOR's lifetime or at least the lifetime of the connection.
             */
            if (e->length == (apr_size_t)-1) {
                /* First save buckets batched below, if any. */
                if (batched_buckets) {
                    batched_buckets = 0;
                    if (!tmp_bb) {
                        tmp_bb = ap_acquire_brigade(f->c);
                    }
                    apr_brigade_split_ex(bb, e, tmp_bb);
                    rv = save_aside_brigade(fp, bb);
                    APR_BRIGADE_CONCAT(bb, tmp_bb);
                    if (rv != APR_SUCCESS) {
                        break;
                    }
                    AP_DEBUG_ASSERT(APR_BRIGADE_FIRST(bb) == e);
                }
                APR_BUCKET_REMOVE(e);
                APR_BRIGADE_INSERT_TAIL(fp->bb, e);
            }
            else {
                /* Batch successive buckets to save. */
                batched_buckets = 1;
            }
        }
        if (tmp_bb) {
            ap_release_brigade(f->c, tmp_bb);
        }
        if (batched_buckets) {
            /* Save any remainder. */
            rv = save_aside_brigade(fp, bb);
        }
        if (!APR_BRIGADE_EMPTY(bb)) {
            /* Anything left in bb is what we could not save (error), clean up.
             * This destroys anything pipelined so far, including EOR(s), and
             * swallows all data, so from now this filter should only be passed
             * connection close data like TLS close_notify.
             *
             * XXX: Should we cleanup all previous c->output_filters' setaside
             *      brigades?
             */
            AP_DEBUG_ASSERT(rv != APR_SUCCESS);
            f->c->keepalive = AP_CONN_CLOSE;
            apr_brigade_cleanup(bb);
        }
    }
    else if (fp->deferred_pool) {
        /*
         * There are no more requests in the pipeline. We can just clear the
         * pool.
         */
        AP_DEBUG_ASSERT(fp->bb);
        apr_brigade_cleanup(fp->bb);
        apr_pool_clear(fp->deferred_pool);
    }

    return rv;
}

AP_DECLARE(void) ap_filter_adopt_brigade(ap_filter_t *f,
                                         apr_bucket_brigade *bb)
{
    struct ap_filter_private *fp = f->priv;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, f->c,
                  "adopt %s brigade to %s brigade in '%s' %sput filter",
                  APR_BRIGADE_EMPTY(bb) ? "empty" : "full",
                  (!fp->bb || APR_BRIGADE_EMPTY(fp->bb)) ? "empty" : "full",
                  f->frec->name,
                  f->frec->direction == AP_FILTER_INPUT ? "in" : "out");

    if (!APR_BRIGADE_EMPTY(bb)) {
        ap_filter_prepare_brigade(f);
        APR_BRIGADE_CONCAT(fp->bb, bb);
    }
}

AP_DECLARE(apr_status_t) ap_filter_reinstate_brigade(ap_filter_t *f,
                                                     apr_bucket_brigade *bb,
                                                     apr_bucket **flush_upto)
{
    apr_bucket *bucket, *next;
    apr_size_t bytes_in_brigade, memory_bytes_in_brigade;
    int eor_buckets_in_brigade, opaque_buckets_in_brigade;
    struct ap_filter_private *fp = f->priv;
    core_server_config *conf;
 
    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, f->c,
                  "reinstate %s brigade to %s brigade in '%s' %sput filter",
                  (!fp->bb || APR_BRIGADE_EMPTY(fp->bb) ? "empty" : "full"),
                  (APR_BRIGADE_EMPTY(bb) ? "empty" : "full"),
                  f->frec->name,
                  f->frec->direction == AP_FILTER_INPUT ? "in" : "out");

    /* This API is not suitable for request filters */
    if (f->frec->ftype < AP_FTYPE_CONNECTION) {
        return APR_ENOTIMPL;
    }

    /* Buckets in fp->bb are leftover from previous call to setaside, so
     * they happen before anything added here in bb.
     */
    if (fp->bb) {
        APR_BRIGADE_PREPEND(bb, fp->bb);
    }
    if (!flush_upto) {
        /* Just prepend all. */
        return APR_SUCCESS;
    }
 
    *flush_upto = NULL;

    /*
     * Determine if and up to which bucket the caller needs to do a blocking
     * write:
     *
     *  a) The brigade contains at least one flush bucket: do blocking writes
     *     of everything up to the last one.
     *
     *  b) The brigade contains at least flush_max_threshold bytes in memory,
     *     that is non-file and non-opaque (length != -1) buckets: do blocking
     *     writes of everything up the last bucket above flush_max_threshold.
     *     (The point of this rule is to provide flow control, in case a
     *     handler is streaming out lots of data faster than the data can be
     *     sent to the client.)
     *
     *  c) The brigade contains at least flush_max_pipelined EOR buckets: do
     *     blocking writes until after the last EOR above flush_max_pipelined.
     *     (The point of this rule is to prevent too many FDs being kept open
     *     by pipelined requests, possibly allowing a DoS).
     *
     * Morphing buckets (opaque and FILE) use no memory until read, so they
     * don't account for point b) above. Both ap_filter_reinstate_brigade()
     * and setaside_brigade() assume that opaque buckets have an appropriate
     * lifetime (until next EOR for instance), so they are simply setaside or
     * reinstated by moving them from/to fp->bb to/from user bb.
     */

    bytes_in_brigade = 0;
    memory_bytes_in_brigade = 0;
    eor_buckets_in_brigade = 0;
    opaque_buckets_in_brigade = 0;

    conf = ap_get_core_module_config(f->c->base_server->module_config);

    for (bucket = APR_BRIGADE_FIRST(bb); bucket != APR_BRIGADE_SENTINEL(bb);
         bucket = next) {
        next = APR_BUCKET_NEXT(bucket);

        if (AP_BUCKET_IS_EOR(bucket)) {
            eor_buckets_in_brigade++;
        }
        else if (bucket->length == (apr_size_t)-1) {
            opaque_buckets_in_brigade++;
        }
        else if (bucket->length) {
            bytes_in_brigade += bucket->length;
            if (!APR_BUCKET_IS_FILE(bucket)) {
                memory_bytes_in_brigade += bucket->length;
            }
        }

        if (APR_BUCKET_IS_FLUSH(bucket)
            || (memory_bytes_in_brigade > conf->flush_max_threshold)
            || (conf->flush_max_pipelined >= 0
                && eor_buckets_in_brigade > conf->flush_max_pipelined)) {
            /* this segment of the brigade MUST be sent before returning. */

            if (APLOGctrace6(f->c)) {
                char *reason = APR_BUCKET_IS_FLUSH(bucket) ?
                               "FLUSH bucket" :
                               (memory_bytes_in_brigade > conf->flush_max_threshold) ?
                               "max threshold" : "max requests in pipeline";
                ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, f->c,
                              "will flush because of %s", reason);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c,
                              "seen in brigade%s: bytes: %" APR_SIZE_T_FMT
                              ", memory bytes: %" APR_SIZE_T_FMT ", eor "
                              "buckets: %d, opaque buckets: %d",
                              *flush_upto == NULL ? " so far"
                                                  : " since last flush point",
                              bytes_in_brigade,
                              memory_bytes_in_brigade,
                              eor_buckets_in_brigade,
                              opaque_buckets_in_brigade);
            }
            /*
             * Defer the actual blocking write to avoid doing many writes.
             */
            *flush_upto = next;

            bytes_in_brigade = 0;
            memory_bytes_in_brigade = 0;
            eor_buckets_in_brigade = 0;
            opaque_buckets_in_brigade = 0;
        }
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c,
                  "brigade contains%s: bytes: %" APR_SIZE_T_FMT
                  ", non-file bytes: %" APR_SIZE_T_FMT
                  ", eor buckets: %d, opaque buckets: %d",
                  *flush_upto == NULL ? "" : " since last flush point",
                  bytes_in_brigade, memory_bytes_in_brigade,
                  eor_buckets_in_brigade, opaque_buckets_in_brigade);

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
        struct ap_filter_private *fp = f->priv;
        if (fp->bb && !APR_BRIGADE_EMPTY(fp->bb)) {
            return 1;
        }
        f = f->next;
    }
    return 0;
}

AP_DECLARE_NONSTD(int) ap_filter_output_pending(conn_rec *c)
{
    struct ap_filter_conn_ctx *x = c->filter_conn_ctx;
    struct ap_filter_private *fp, *prev;
    apr_bucket_brigade *bb;
    int rc = DECLINED;

    if (!x || !x->pending_output_filters) {
        goto cleanup;
    }

    /* Flush outer most filters first for ap_filter_should_yield(f->next)
     * to be relevant in the previous ones (async filters won't pass their
     * buckets if their next filters yield already).
     */
    bb = ap_acquire_brigade(c);
    for (fp = APR_RING_LAST(x->pending_output_filters);
         fp != APR_RING_SENTINEL(x->pending_output_filters,
                                 ap_filter_private, pending);
         fp = prev) {
        /* If a filter removes itself from the filters stack (when run), it
         * also orphans itself from the ring, so save "prev" here to avoid
         * an infinite loop in this case.
         */
        prev = APR_RING_PREV(fp, pending);

        AP_DEBUG_ASSERT(fp->bb);
        if (!APR_BRIGADE_EMPTY(fp->bb)) {
            ap_filter_t *f = fp->f;
            apr_status_t rv;

            rv = ap_pass_brigade(f, bb);
            apr_brigade_cleanup(bb);

            if (rv != APR_SUCCESS) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO(00470)
                        "write failure in '%s' output filter", f->frec->name);
                rc = AP_FILTER_ERROR;
                break;
            }

            if ((fp->bb && !APR_BRIGADE_EMPTY(fp->bb))
                    || (f->next && ap_filter_should_yield(f->next))) {
                rc = OK;
                break;
            }
        }
    }
    ap_release_brigade(c, bb);

cleanup:
    /* All filters have returned, time to recycle/unleak ap_filter_t-s
     * before leaving (i.e. make them reusable).
     */
    recycle_dead_filters(c);

    return rc;
}

AP_DECLARE_NONSTD(int) ap_filter_input_pending(conn_rec *c)
{
    struct ap_filter_conn_ctx *x = c->filter_conn_ctx;
    struct ap_filter_private *fp;
    int rc = DECLINED;

    if (!x || !x->pending_input_filters) {
        goto cleanup;
    }

    for (fp = APR_RING_LAST(x->pending_input_filters);
         fp != APR_RING_SENTINEL(x->pending_input_filters,
                                 ap_filter_private, pending);
         fp = APR_RING_PREV(fp, pending)) {
        apr_bucket *e;

        /* if there is a leading non-opaque (length != -1) bucket
         * in place, then we have data pending
         */
        AP_DEBUG_ASSERT(fp->bb);
        e = APR_BRIGADE_FIRST(fp->bb);
        if (e != APR_BRIGADE_SENTINEL(fp->bb)
                && e->length != (apr_size_t)(-1)) {
            rc = OK;
            break;
        }
    }

cleanup:
    /* All filters have returned, time to recycle/unleak ap_filter_t-s
     * before leaving (i.e. make them reusable).
     */
    recycle_dead_filters(c);

    return rc;
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
