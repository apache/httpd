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
#include "h2_config.h"
#include "h2_conn.h"
#include "h2_ctx.h"
#include "h2_h2.h"
#include "h2_int_queue.h"
#include "h2_response.h"
#include "h2_request.h"
#include "h2_task.h"
#include "h2_task_output.h"
#include "h2_util.h"
#include "h2_ngn_shed.h"


typedef struct h2_ngn_entry h2_ngn_entry;
struct h2_ngn_entry {
    APR_RING_ENTRY(h2_ngn_entry) link;
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
    h2_ngn_shed *shed;

    unsigned int shutdown : 1; /* engine is being shut down */

    APR_RING_HEAD(h2_req_entries, h2_ngn_entry) entries;
    apr_uint32_t capacity;     /* maximum concurrent requests */
    apr_uint32_t no_assigned;  /* # of assigned requests */
    apr_uint32_t no_live;      /* # of live */
    apr_uint32_t no_finished;  /* # of finished */

    apr_thread_cond_t *io;     /* condition var for waiting on data */
};

h2_ngn_shed *h2_ngn_shed_create(apr_pool_t *pool, conn_rec *c,
                                apr_uint32_t req_buffer_size)
{
    h2_ngn_shed *shed;
    
    shed = apr_pcalloc(pool, sizeof(*shed));
    shed->c = c;
    shed->pool = pool;
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
    shed->aborted = 1;
}

static apr_status_t ngn_schedule(h2_req_engine *ngn, request_rec *r)
{
    h2_ngn_entry *entry = apr_pcalloc(r->pool, sizeof(*entry));

    APR_RING_ELEM_INIT(entry, link);
    entry->r = r;
    H2_REQ_ENTRIES_INSERT_TAIL(&ngn->entries, entry);
    return APR_SUCCESS;
}


apr_status_t h2_ngn_shed_push_req(h2_ngn_shed *shed, const char *ngn_type, 
                                  h2_task *task, request_rec *r, 
                                  h2_req_engine_init *einit){
    h2_req_engine *ngn;
    apr_status_t status = APR_EOF;

    AP_DEBUG_ASSERT(shed);
    
    apr_table_set(r->connection->notes, H2_TASK_ID_NOTE, task->id);
    if (task->ser_headers) {
        /* Max compatibility, deny processing of this */
        return APR_EOF;
    }
    
    ngn = apr_hash_get(shed->ngns, ngn_type, APR_HASH_KEY_STRING);
    if (ngn) {
        if (ngn->shutdown) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "h2_ngn_shed(%ld): %s in shutdown", 
                          shed->c->id, ngn->id);
            ngn = NULL;
        }
        else if (ngn->no_assigned >= ngn->capacity) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "h2_ngn_shed(%ld): %s over capacity %d/%d", 
                          shed->c->id, ngn->id, ngn->no_assigned,
                          ngn->capacity);
            ngn = NULL;
        }
        else if (ngn_schedule(ngn, r) == APR_SUCCESS) {
            /* this task will be processed in another thread,
             * freeze any I/O for the time being. */
            h2_task_freeze(task, r);
            ngn->no_assigned++;
            status = APR_SUCCESS;
            ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r,
                          "h2_ngn_shed(%ld): pushed request %s to %s", 
                          shed->c->id, task->id, ngn->id);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r,
                          "h2_ngn_shed(%ld): engine error adding req %s", 
                          shed->c->id, ngn->id);
            ngn = NULL;
        }
    }
    
    if (!ngn && einit) {
        ngn = apr_pcalloc(task->c->pool, sizeof(*ngn));
        ngn->id = apr_psprintf(task->c->pool, "ngn-%ld-%d", 
                                   shed->c->id, shed->next_ngn_id++);
        ngn->pool = task->c->pool;
        ngn->type = apr_pstrdup(task->c->pool, ngn_type);
        ngn->c = r->connection;
        APR_RING_INIT(&ngn->entries, h2_ngn_entry, link);
        ngn->shed = shed;
        ngn->capacity = 100;
        ngn->io = task->io;
        ngn->no_assigned = 1;
        ngn->no_live = 1;
        
        status = einit(ngn, ngn->id, ngn->type, ngn->pool,
                       shed->req_buffer_size, r);
        ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r,
                      "h2_ngn_shed(%ld): init engine %s (%s)", 
                      shed->c->id, ngn->id, ngn->type);
        if (status == APR_SUCCESS) {
            apr_hash_set(shed->ngns, ngn->type, APR_HASH_KEY_STRING, ngn);
        }
    }
    return status;
}

static h2_ngn_entry *pop_non_frozen(h2_req_engine *ngn)
{
    h2_ngn_entry *entry;
    h2_task *task;

    for (entry = H2_REQ_ENTRIES_FIRST(&ngn->entries);
         entry != H2_REQ_ENTRIES_SENTINEL(&ngn->entries);
         entry = H2_NGN_ENTRY_NEXT(entry)) {
        task = h2_ctx_rget_task(entry->r);
        AP_DEBUG_ASSERT(task);
        if (!task->frozen) {
            H2_NGN_ENTRY_REMOVE(entry);
            return entry;
        }
    }
    return NULL;
}

apr_status_t h2_ngn_shed_pull_req(h2_ngn_shed *shed, 
                                  h2_req_engine *ngn, 
                                  apr_uint32_t capacity, 
                                  int want_shutdown,
                                  request_rec **pr)
{   
    h2_ngn_entry *entry;
    
    AP_DEBUG_ASSERT(ngn);
    *pr = NULL;
    if (shed->aborted) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, shed->c,
                      "h2_ngn_shed(%ld): abort while pulling requests %s", 
                      shed->c->id, ngn->id);
        return APR_EOF;
    }
    
    ngn->capacity = capacity;
    if (!H2_REQ_ENTRIES_EMPTY(&ngn->entries) 
        && (entry = pop_non_frozen(ngn))) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, entry->r,
                      "h2_ngn_shed(%ld): pulled request %s for engine %s", 
                      shed->c->id, entry->r->the_request, ngn->id);
        ngn->no_live++;
        entry->r->connection->current_thread = ngn->c->current_thread;
        *pr = entry->r;
        return APR_SUCCESS;
    }
    else if (want_shutdown) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, shed->c,
                      "h2_ngn_shed(%ld): emtpy queue, shutdown engine %s", 
                      shed->c->id, ngn->id);
        ngn->shutdown = 1;
        return APR_EOF;
    }
    return APR_EAGAIN;
}
                                 
static apr_status_t ngn_done_task(h2_ngn_shed *shed, h2_req_engine *ngn, h2_task *task, 
                                  int waslive, int aborted)
{
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, shed->c,
                  "h2_ngn_shed(%ld): task %s %s by %s", 
                  shed->c->id, task->id, aborted? "aborted":"done", ngn->id);
    h2_task_output_close(task->output);
    ngn->no_finished++;
    if (waslive) ngn->no_live--;
    ngn->no_assigned--;
    if (task->c != ngn->c) { /* do not release what the engine runs on */
        return APR_SUCCESS;
    }
    return APR_EAGAIN;
}
                                
apr_status_t h2_ngn_shed_done_req(h2_ngn_shed *shed, 
                                  h2_req_engine *ngn, conn_rec *r_conn)
{
    h2_task *task = h2_ctx_cget_task(r_conn);
    if (task) {
        return ngn_done_task(shed, ngn, task, 1, 0);
    }
    return APR_ECONNABORTED;
}
                                
void h2_ngn_shed_done_ngn(h2_ngn_shed *shed, struct h2_req_engine *ngn)
{
    h2_req_engine *existing;
    
    if (!shed->aborted 
        && !H2_REQ_ENTRIES_EMPTY(&ngn->entries)) {
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
            request_rec *r = entry->r;
            h2_task *task = h2_ctx_rget_task(r);
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
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, shed->c,
                      "h2_ngn_shed(%ld): exit engine %s (%s)", 
                      shed->c->id, ngn->id, ngn->type);
    }
    
    existing = apr_hash_get(shed->ngns, ngn->type, APR_HASH_KEY_STRING);
    if (existing == ngn) {
        apr_hash_set(shed->ngns, ngn->type, APR_HASH_KEY_STRING, NULL);
    }
}
