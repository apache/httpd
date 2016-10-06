/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>
#include <apr_strings.h>
#include <apr_time.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include "mod_http2.h"

#include "h2_private.h"
#include "h2.h"
#include "h2_config.h"
#include "h2_conn.h"
#include "h2_ctx.h"
#include "h2_h2.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_task.h"
#include "h2_util.h"
#include "h2_ngn_shed.h"


typedef struct h2_ngn_entry h2_ngn_entry;
struct h2_ngn_entry {
    APR_RING_ENTRY(h2_ngn_entry) link;
    h2_task *task;
    request_rec *r;
};

#define H2_NGN_ENTRY_NEXT(e)	APR_RING_NEXT((e), link)
#define H2_NGN_ENTRY_PREV(e)	APR_RING_PREV((e), link)
#define H2_NGN_ENTRY_REMOVE(e)	APR_RING_REMOVE((e), link)

#define H2_REQ_ENTRIES_SENTINEL(b)	APR_RING_SENTINEL((b), h2_ngn_entry, link)
#define H2_REQ_ENTRIES_EMPTY(b)	APR_RING_EMPTY((b), h2_ngn_entry, link)
#define H2_REQ_ENTRIES_FIRST(b)	APR_RING_FIRST(b)
#define H2_REQ_ENTRIES_LAST(b)	APR_RING_LAST(b)

#define H2_REQ_ENTRIES_INSERT_HEAD(b, e) do {				\
h2_ngn_entry *ap__b = (e);                                        \
APR_RING_INSERT_HEAD((b), ap__b, h2_ngn_entry, link);	\
} while (0)

#define H2_REQ_ENTRIES_INSERT_TAIL(b, e) do {				\
h2_ngn_entry *ap__b = (e);					\
APR_RING_INSERT_TAIL((b), ap__b, h2_ngn_entry, link);	\
} while (0)

struct h2_req_engine {
    const char *id;        /* identifier */
    const char *type;      /* name of the engine type */
    apr_pool_t *pool;      /* pool for engine specific allocations */
    conn_rec *c;           /* connection this engine is assigned to */
    h2_task *task;         /* the task this engine is base on, running in */
    h2_ngn_shed *shed;

    unsigned int shutdown : 1; /* engine is being shut down */
    unsigned int done : 1;     /* engine has finished */

    APR_RING_HEAD(h2_req_entries, h2_ngn_entry) entries;
    apr_uint32_t capacity;     /* maximum concurrent requests */
    apr_uint32_t no_assigned;  /* # of assigned requests */
    apr_uint32_t no_live;      /* # of live */
    apr_uint32_t no_finished;  /* # of finished */
    
    h2_output_consumed *out_consumed;
    void *out_consumed_ctx;
};

const char *h2_req_engine_get_id(h2_req_engine *engine)
{
    return engine->id;
}

int h2_req_engine_is_shutdown(h2_req_engine *engine)
{
    return engine->shutdown;
}

void h2_req_engine_out_consumed(h2_req_engine *engine, conn_rec *c, 
                                apr_off_t bytes)
{
    if (engine->out_consumed) {
        engine->out_consumed(engine->out_consumed_ctx, c, bytes);
    }
}

h2_ngn_shed *h2_ngn_shed_create(apr_pool_t *pool, conn_rec *c,
                                apr_uint32_t default_capacity, 
                                apr_uint32_t req_buffer_size)
{
    h2_ngn_shed *shed;
    
    shed = apr_pcalloc(pool, sizeof(*shed));
    shed->c = c;
    shed->pool = pool;
    shed->default_capacity = default_capacity;
    shed->req_buffer_size = req_buffer_size;
    shed->ngns = apr_hash_make(pool);
    
    return shed;
}

void h2_ngn_shed_set_ctx(h2_ngn_shed *shed, void *user_ctx)
{
    shed->user_ctx = user_ctx;
}

void *h2_ngn_shed_get_ctx(h2_ngn_shed *shed)
{
    return shed->user_ctx;
}

h2_ngn_shed *h2_ngn_shed_get_shed(h2_req_engine *ngn)
{
    return ngn->shed;
}

void h2_ngn_shed_abort(h2_ngn_shed *shed)
{
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, shed->c, APLOGNO(03394)
                  "h2_ngn_shed(%ld): abort", shed->c->id);
    shed->aborted = 1;
}

static void ngn_add_task(h2_req_engine *ngn, h2_task *task, request_rec *r)
{
    h2_ngn_entry *entry = apr_pcalloc(task->pool, sizeof(*entry));
    APR_RING_ELEM_INIT(entry, link);
    entry->task = task;
    entry->r = r;
    H2_REQ_ENTRIES_INSERT_TAIL(&ngn->entries, entry);
}


apr_status_t h2_ngn_shed_push_request(h2_ngn_shed *shed, const char *ngn_type, 
                                      request_rec *r, 
                                      http2_req_engine_init *einit) 
{
    h2_req_engine *ngn;
    h2_task *task = h2_ctx_rget_task(r);

    ap_assert(task);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, shed->c,
                  "h2_ngn_shed(%ld): PUSHing request (task=%s)", shed->c->id, 
                  task->id);
    if (task->request->serialize) {
        /* Max compatibility, deny processing of this */
        return APR_EOF;
    }
    
    if (task->assigned) {
        --task->assigned->no_assigned;
        --task->assigned->no_live;
        task->assigned = NULL;
    }
    
    ngn = apr_hash_get(shed->ngns, ngn_type, APR_HASH_KEY_STRING);
    if (ngn && !ngn->shutdown) {
        /* this task will be processed in another thread,
         * freeze any I/O for the time being. */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, task->c,
                      "h2_ngn_shed(%ld): pushing request %s to %s", 
                      shed->c->id, task->id, ngn->id);
        if (!h2_task_has_thawed(task)) {
            h2_task_freeze(task);
        }
        ngn_add_task(ngn, task, r);
        ngn->no_assigned++;
        return APR_SUCCESS;
    }
    
    /* no existing engine or being shut down, start a new one */
    if (einit) {
        apr_status_t status;
        apr_pool_t *pool = task->pool;
        h2_req_engine *newngn;
        
        newngn = apr_pcalloc(pool, sizeof(*ngn));
        newngn->pool = pool;
        newngn->id   = apr_psprintf(pool, "ngn-%s", task->id);
        newngn->type = apr_pstrdup(pool, ngn_type);
        newngn->c    = task->c;
        newngn->shed = shed;
        newngn->capacity = shed->default_capacity;
        newngn->no_assigned = 1;
        newngn->no_live = 1;
        APR_RING_INIT(&newngn->entries, h2_ngn_entry, link);
        
        status = einit(newngn, newngn->id, newngn->type, newngn->pool,
                       shed->req_buffer_size, r,
                       &newngn->out_consumed, &newngn->out_consumed_ctx);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, task->c, APLOGNO(03395)
                      "h2_ngn_shed(%ld): create engine %s (%s)", 
                      shed->c->id, newngn->id, newngn->type);
        if (status == APR_SUCCESS) {
            AP_DEBUG_ASSERT(task->engine == NULL);
            newngn->task = task;
            task->engine = newngn;
            task->assigned = newngn;
            apr_hash_set(shed->ngns, newngn->type, APR_HASH_KEY_STRING, newngn);
        }
        return status;
    }
    return APR_EOF;
}

static h2_ngn_entry *pop_detached(h2_req_engine *ngn)
{
    h2_ngn_entry *entry;
    for (entry = H2_REQ_ENTRIES_FIRST(&ngn->entries);
         entry != H2_REQ_ENTRIES_SENTINEL(&ngn->entries);
         entry = H2_NGN_ENTRY_NEXT(entry)) {
        if (h2_task_has_thawed(entry->task) 
            || (entry->task->engine == ngn)) {
            /* The task hosting this engine can always be pulled by it.
             * For other task, they need to become detached, e.g. no longer
             * assigned to another worker. */
            H2_NGN_ENTRY_REMOVE(entry);
            return entry;
        }
    }
    return NULL;
}

apr_status_t h2_ngn_shed_pull_request(h2_ngn_shed *shed, 
                                      h2_req_engine *ngn, 
                                      apr_uint32_t capacity, 
                                      int want_shutdown,
                                      request_rec **pr)
{   
    h2_ngn_entry *entry;
    
    AP_DEBUG_ASSERT(ngn);
    *pr = NULL;
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, shed->c, APLOGNO(03396)
                  "h2_ngn_shed(%ld): pull task for engine %s, shutdown=%d", 
                  shed->c->id, ngn->id, want_shutdown);
    if (shed->aborted) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, shed->c, APLOGNO(03397)
                      "h2_ngn_shed(%ld): abort while pulling requests %s", 
                      shed->c->id, ngn->id);
        ngn->shutdown = 1;
        return APR_ECONNABORTED;
    }
    
    ngn->capacity = capacity;
    if (H2_REQ_ENTRIES_EMPTY(&ngn->entries)) {
        if (want_shutdown) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, shed->c,
                          "h2_ngn_shed(%ld): emtpy queue, shutdown engine %s", 
                          shed->c->id, ngn->id);
            ngn->shutdown = 1;
        }
        return ngn->shutdown? APR_EOF : APR_EAGAIN;
    }
    
    if ((entry = pop_detached(ngn))) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, entry->task->c, APLOGNO(03398)
                      "h2_ngn_shed(%ld): pulled request %s for engine %s", 
                      shed->c->id, entry->task->id, ngn->id);
        ngn->no_live++;
        *pr = entry->r;
        entry->task->assigned = ngn;
        /* task will now run in ngn's own thread. Modules like lua
         * seem to require the correct thread set in the conn_rec.
         * See PR 59542. */
        if (entry->task->c && ngn->c) {
            entry->task->c->current_thread = ngn->c->current_thread;
        }
        if (entry->task->engine == ngn) {
            /* If an engine pushes its own base task, and then pulls
             * it back to itself again, it needs to be thawed.
             */
            h2_task_thaw(entry->task);
        }
        return APR_SUCCESS;
    }
    
    if (1) {
        h2_ngn_entry *entry = H2_REQ_ENTRIES_FIRST(&ngn->entries);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, shed->c, APLOGNO(03399)
                      "h2_ngn_shed(%ld): pull task, nothing, first task %s", 
                      shed->c->id, entry->task->id);
    }
    return APR_EAGAIN;
}
                                 
static apr_status_t ngn_done_task(h2_ngn_shed *shed, h2_req_engine *ngn, 
                                  h2_task *task, int waslive, int aborted)
{
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, shed->c, APLOGNO(03400)
                  "h2_ngn_shed(%ld): task %s %s by %s", 
                  shed->c->id, task->id, aborted? "aborted":"done", ngn->id);
    ngn->no_finished++;
    if (waslive) ngn->no_live--;
    ngn->no_assigned--;
    task->assigned = NULL;
    
    return APR_SUCCESS;
}
                                
apr_status_t h2_ngn_shed_done_task(h2_ngn_shed *shed, 
                                    struct h2_req_engine *ngn, h2_task *task)
{
    return ngn_done_task(shed, ngn, task, 1, 0);
}
                                
void h2_ngn_shed_done_ngn(h2_ngn_shed *shed, struct h2_req_engine *ngn)
{
    if (ngn->done) {
        return;
    }
    
    if (!shed->aborted && !H2_REQ_ENTRIES_EMPTY(&ngn->entries)) {
        h2_ngn_entry *entry;
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, shed->c,
                      "h2_ngn_shed(%ld): exit engine %s (%s), "
                      "has still requests queued, shutdown=%d,"
                      "assigned=%ld, live=%ld, finished=%ld", 
                      shed->c->id, ngn->id, ngn->type,
                      ngn->shutdown, 
                      (long)ngn->no_assigned, (long)ngn->no_live,
                      (long)ngn->no_finished);
        for (entry = H2_REQ_ENTRIES_FIRST(&ngn->entries);
             entry != H2_REQ_ENTRIES_SENTINEL(&ngn->entries);
             entry = H2_NGN_ENTRY_NEXT(entry)) {
            h2_task *task = entry->task;
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, shed->c,
                          "h2_ngn_shed(%ld): engine %s has queued task %s, "
                          "frozen=%d, aborting",
                          shed->c->id, ngn->id, task->id, task->frozen);
            ngn_done_task(shed, ngn, task, 0, 1);
        }
    }
    if (!shed->aborted && (ngn->no_assigned > 1 || ngn->no_live > 1)) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, shed->c,
                      "h2_ngn_shed(%ld): exit engine %s (%s), "
                      "assigned=%ld, live=%ld, finished=%ld", 
                      shed->c->id, ngn->id, ngn->type,
                      (long)ngn->no_assigned, (long)ngn->no_live,
                      (long)ngn->no_finished);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, shed->c,
                      "h2_ngn_shed(%ld): exit engine %s", 
                      shed->c->id, ngn->id);
    }
    
    apr_hash_set(shed->ngns, ngn->type, APR_HASH_KEY_STRING, NULL);
    ngn->done = 1;
}
