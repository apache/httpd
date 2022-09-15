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
 
#include <apr_lib.h>
#include <apr_atomic.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <apr_buckets.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

#include <httpd.h>
#include <http_protocol.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2_conn_ctx.h"
#include "h2_util.h"
#include "h2_bucket_beam.h"


#define H2_BLIST_INIT(b)        APR_RING_INIT(&(b)->list, apr_bucket, link);
#define H2_BLIST_SENTINEL(b)    APR_RING_SENTINEL(&(b)->list, apr_bucket, link)
#define H2_BLIST_EMPTY(b)       APR_RING_EMPTY(&(b)->list, apr_bucket, link)
#define H2_BLIST_FIRST(b)       APR_RING_FIRST(&(b)->list)
#define H2_BLIST_LAST(b)	APR_RING_LAST(&(b)->list)
#define H2_BLIST_INSERT_HEAD(b, e) do {				\
	apr_bucket *ap__b = (e);                                        \
	APR_RING_INSERT_HEAD(&(b)->list, ap__b, apr_bucket, link);	\
    } while (0)
#define H2_BLIST_INSERT_TAIL(b, e) do {				\
	apr_bucket *ap__b = (e);					\
	APR_RING_INSERT_TAIL(&(b)->list, ap__b, apr_bucket, link);	\
    } while (0)
#define H2_BLIST_CONCAT(a, b) do {					\
        APR_RING_CONCAT(&(a)->list, &(b)->list, apr_bucket, link);	\
    } while (0)
#define H2_BLIST_PREPEND(a, b) do {					\
        APR_RING_PREPEND(&(a)->list, &(b)->list, apr_bucket, link);	\
    } while (0)


/* registry for bucket converting `h2_bucket_beamer` functions */
static apr_array_header_t *beamers;

static apr_status_t cleanup_beamers(void *dummy)
{
    (void)dummy;
    beamers = NULL;
    return APR_SUCCESS;
}

void h2_register_bucket_beamer(h2_bucket_beamer *beamer)
{
    if (!beamers) {
        apr_pool_cleanup_register(apr_hook_global_pool, NULL,
                                  cleanup_beamers, apr_pool_cleanup_null);
        beamers = apr_array_make(apr_hook_global_pool, 10, 
                                 sizeof(h2_bucket_beamer*));
    }
    APR_ARRAY_PUSH(beamers, h2_bucket_beamer*) = beamer;
}

static apr_bucket *h2_beam_bucket(h2_bucket_beam *beam, 
                                  apr_bucket_brigade *dest,
                                  const apr_bucket *src)
{
    apr_bucket *b = NULL;
    int i;
    if (beamers) {
        for (i = 0; i < beamers->nelts && b == NULL; ++i) {
            h2_bucket_beamer *beamer;
            
            beamer = APR_ARRAY_IDX(beamers, i, h2_bucket_beamer*);
            b = beamer(beam, dest, src);
        }
    }
    return b;
}

static int is_empty(h2_bucket_beam *beam);
static apr_off_t get_buffered_data_len(h2_bucket_beam *beam);

static int h2_blist_count(h2_blist *blist)
{
    apr_bucket *b;
    int count = 0;

    for (b = H2_BLIST_FIRST(blist); b != H2_BLIST_SENTINEL(blist);
         b = APR_BUCKET_NEXT(b)) {
        ++count;
    }
    return count;
}

#define H2_BEAM_LOG(beam, c, level, rv, msg, bb) \
    do { \
        if (APLOG_C_IS_LEVEL((c),(level))) { \
            char buffer[4 * 1024]; \
            apr_size_t len, bmax = sizeof(buffer)/sizeof(buffer[0]); \
            len = bb? h2_util_bb_print(buffer, bmax, "", "", bb) : 0; \
            ap_log_cerror(APLOG_MARK, (level), rv, (c), \
                          "BEAM[%s,%s%sdata=%ld,buckets(send/consumed)=%d/%d]: %s %s", \
                          (beam)->name, \
                          (beam)->aborted? "aborted," : "", \
                          is_empty(beam)? "empty," : "", \
                          (long)get_buffered_data_len(beam), \
                          h2_blist_count(&(beam)->buckets_to_send), \
                          h2_blist_count(&(beam)->buckets_consumed), \
                          (msg), len? buffer : ""); \
        } \
    } while (0)


static int bucket_is_mmap(apr_bucket *b)
{
#if APR_HAS_MMAP
    return APR_BUCKET_IS_MMAP(b);
#else
    /* if it is not defined as enabled, it should always be no */
    return 0;
#endif
}

static apr_off_t bucket_mem_used(apr_bucket *b)
{
    if (APR_BUCKET_IS_FILE(b) || bucket_is_mmap(b)) {
        return 0;
    }
    else {
        /* should all have determinate length */
        return (apr_off_t)b->length;
    }
}

static int report_consumption(h2_bucket_beam *beam, int locked)
{
    int rv = 0;
    apr_off_t len = beam->recv_bytes - beam->recv_bytes_reported;
    h2_beam_io_callback *cb = beam->cons_io_cb;
     
    if (len > 0) {
        if (cb) {
            void *ctx = beam->cons_ctx;
            
            if (locked) apr_thread_mutex_unlock(beam->lock);
            cb(ctx, beam, len);
            if (locked) apr_thread_mutex_lock(beam->lock);
            rv = 1;
        }
        beam->recv_bytes_reported += len;
    }
    return rv;
}

static apr_size_t calc_buffered(h2_bucket_beam *beam)
{
    apr_size_t len = 0;
    apr_bucket *b;
    for (b = H2_BLIST_FIRST(&beam->buckets_to_send);
         b != H2_BLIST_SENTINEL(&beam->buckets_to_send);
         b = APR_BUCKET_NEXT(b)) {
        if (b->length == ((apr_size_t)-1)) {
            /* do not count */
        }
        else if (APR_BUCKET_IS_FILE(b) || bucket_is_mmap(b)) {
            /* if unread, has no real mem footprint. */
        }
        else {
            len += b->length;
        }
    }
    return len;
}

static void purge_consumed_buckets(h2_bucket_beam *beam)
{
    apr_bucket *b;
    /* delete all sender buckets in purge brigade, needs to be called
     * from sender thread only */
    while (!H2_BLIST_EMPTY(&beam->buckets_consumed)) {
        b = H2_BLIST_FIRST(&beam->buckets_consumed);
        apr_bucket_delete(b);
    }
}

static apr_size_t calc_space_left(h2_bucket_beam *beam)
{
    if (beam->max_buf_size > 0) {
        apr_size_t len = calc_buffered(beam);
        return (beam->max_buf_size > len? (beam->max_buf_size - len) : 0);
    }
    return APR_SIZE_MAX;
}

static int buffer_is_empty(h2_bucket_beam *beam)
{
    return ((!beam->recv_buffer || APR_BRIGADE_EMPTY(beam->recv_buffer))
            && H2_BLIST_EMPTY(&beam->buckets_to_send));
}

static apr_status_t wait_not_empty(h2_bucket_beam *beam, conn_rec *c, apr_read_type_e block)
{
    apr_status_t rv = APR_SUCCESS;
    
    while (buffer_is_empty(beam) && APR_SUCCESS == rv) {
        if (beam->aborted) {
            rv = APR_ECONNABORTED;
        }
        else if (APR_BLOCK_READ != block) {
            rv = APR_EAGAIN;
        }
        else if (beam->timeout > 0) {
            H2_BEAM_LOG(beam, c, APLOG_TRACE2, rv, "wait_not_empty, timeout", NULL);
            rv = apr_thread_cond_timedwait(beam->change, beam->lock, beam->timeout);
        }
        else {
            H2_BEAM_LOG(beam, c, APLOG_TRACE2, rv, "wait_not_empty, forever", NULL);
            rv = apr_thread_cond_wait(beam->change, beam->lock);
        }
    }
    return rv;
}

static apr_status_t wait_not_full(h2_bucket_beam *beam, conn_rec *c,
                                  apr_read_type_e block,
                                  apr_size_t *pspace_left)
{
    apr_status_t rv = APR_SUCCESS;
    apr_size_t left;
    
    while (0 == (left = calc_space_left(beam)) && APR_SUCCESS == rv) {
        if (beam->aborted) {
            rv = APR_ECONNABORTED;
        }
        else if (block != APR_BLOCK_READ) {
            rv = APR_EAGAIN;
        }
        else {
            if (beam->timeout > 0) {
                H2_BEAM_LOG(beam, c, APLOG_TRACE2, rv, "wait_not_full, timeout", NULL);
                rv = apr_thread_cond_timedwait(beam->change, beam->lock, beam->timeout);
            }
            else {
                H2_BEAM_LOG(beam, c, APLOG_TRACE2, rv, "wait_not_full, forever", NULL);
                rv = apr_thread_cond_wait(beam->change, beam->lock);
            }
        }
    }
    *pspace_left = left;
    return rv;
}

static void h2_blist_cleanup(h2_blist *bl)
{
    apr_bucket *e;

    while (!H2_BLIST_EMPTY(bl)) {
        e = H2_BLIST_FIRST(bl);
        apr_bucket_delete(e);
    }
}

static void recv_buffer_cleanup(h2_bucket_beam *beam)
{
    apr_bucket_brigade *bb = beam->recv_buffer;

    beam->recv_buffer = NULL;

    if (bb && !APR_BRIGADE_EMPTY(bb)) {
        apr_off_t bblen = 0;
        
        apr_brigade_length(bb, 0, &bblen);
        beam->recv_bytes += bblen;
        
        /* need to do this unlocked since bucket destroy might 
         * call this beam again. */
        apr_thread_mutex_unlock(beam->lock);
        apr_brigade_destroy(bb);
        apr_thread_mutex_lock(beam->lock);

        apr_thread_cond_broadcast(beam->change);
        if (beam->recv_cb) {
            beam->recv_cb(beam->recv_ctx, beam);
        }
    }
}

static void beam_shutdown(h2_bucket_beam *beam, apr_shutdown_how_e how)
{
    if (!beam->pool) {
        /* pool being cleared already */
        return;
    }

    /* shutdown both receiver and sender? */
    if (how == APR_SHUTDOWN_READWRITE) {
        beam->cons_io_cb = NULL;
        beam->recv_cb = NULL;
    }

    /* shutdown receiver (or both)? */
    if (how != APR_SHUTDOWN_WRITE) {
        recv_buffer_cleanup(beam);
        beam->recv_cb = NULL;
    }

    /* shutdown sender (or both)? */
    if (how != APR_SHUTDOWN_READ) {
        h2_blist_cleanup(&beam->buckets_to_send);
        purge_consumed_buckets(beam);
    }
}

static apr_status_t beam_cleanup(void *data)
{
    h2_bucket_beam *beam = data;
    beam_shutdown(beam, APR_SHUTDOWN_READWRITE);
    beam->pool = NULL; /* the pool is clearing now */
    return APR_SUCCESS;
}

apr_status_t h2_beam_destroy(h2_bucket_beam *beam, conn_rec *c)
{
    if (beam->pool) {
        H2_BEAM_LOG(beam, c, APLOG_TRACE2, 0, "destroy", NULL);
        apr_pool_cleanup_run(beam->pool, beam, beam_cleanup);
    }
    H2_BEAM_LOG(beam, c, APLOG_TRACE2, 0, "destroyed", NULL);
    return APR_SUCCESS;
}

apr_status_t h2_beam_create(h2_bucket_beam **pbeam, conn_rec *from,
                            apr_pool_t *pool, int id, const char *tag,
                            apr_size_t max_buf_size,
                            apr_interval_time_t timeout)
{
    h2_bucket_beam *beam;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(from);
    apr_status_t rv;
    
    beam = apr_pcalloc(pool, sizeof(*beam));
    beam->pool = pool;
    beam->from = from;
    beam->id = id;
    beam->name = apr_psprintf(pool, "%s-%d-%s",
                              conn_ctx->id, id, tag);

    H2_BLIST_INIT(&beam->buckets_to_send);
    H2_BLIST_INIT(&beam->buckets_consumed);
    beam->tx_mem_limits = 1;
    beam->max_buf_size = max_buf_size;
    beam->timeout = timeout;

    rv = apr_thread_mutex_create(&beam->lock, APR_THREAD_MUTEX_DEFAULT, pool);
    if (APR_SUCCESS != rv) goto cleanup;
    rv = apr_thread_cond_create(&beam->change, pool);
    if (APR_SUCCESS != rv) goto cleanup;
    apr_pool_pre_cleanup_register(pool, beam, beam_cleanup);

cleanup:
    H2_BEAM_LOG(beam, from, APLOG_TRACE2, rv, "created", NULL);
    *pbeam = (APR_SUCCESS == rv)? beam : NULL;
    return rv;
}

void h2_beam_buffer_size_set(h2_bucket_beam *beam, apr_size_t buffer_size)
{
    apr_thread_mutex_lock(beam->lock);
    beam->max_buf_size = buffer_size;
    apr_thread_mutex_unlock(beam->lock);
}

void h2_beam_set_copy_files(h2_bucket_beam * beam, int enabled)
{
    apr_thread_mutex_lock(beam->lock);
    beam->copy_files = enabled;
    apr_thread_mutex_unlock(beam->lock);
}

apr_size_t h2_beam_buffer_size_get(h2_bucket_beam *beam)
{
    apr_size_t buffer_size = 0;
    
    apr_thread_mutex_lock(beam->lock);
    buffer_size = beam->max_buf_size;
    apr_thread_mutex_unlock(beam->lock);
    return buffer_size;
}

apr_interval_time_t h2_beam_timeout_get(h2_bucket_beam *beam)
{
    apr_interval_time_t timeout;

    apr_thread_mutex_lock(beam->lock);
    timeout = beam->timeout;
    apr_thread_mutex_unlock(beam->lock);
    return timeout;
}

void h2_beam_timeout_set(h2_bucket_beam *beam, apr_interval_time_t timeout)
{
    apr_thread_mutex_lock(beam->lock);
    beam->timeout = timeout;
    apr_thread_mutex_unlock(beam->lock);
}

void h2_beam_abort(h2_bucket_beam *beam, conn_rec *c)
{
    apr_thread_mutex_lock(beam->lock);
    beam->aborted = 1;
    if (c == beam->from) {
        /* sender aborts */
        if (beam->was_empty_cb && buffer_is_empty(beam)) {
            beam->was_empty_cb(beam->was_empty_ctx, beam);
        }
        /* no more consumption reporting to sender */
        report_consumption(beam, 1);
        beam->cons_ctx = NULL;

        beam_shutdown(beam, APR_SHUTDOWN_WRITE);
    }
    else {
        /* receiver aborts */
        beam_shutdown(beam, APR_SHUTDOWN_READ);
    }
    apr_thread_cond_broadcast(beam->change);
    apr_thread_mutex_unlock(beam->lock);
}

static apr_status_t append_bucket(h2_bucket_beam *beam,
                                  apr_bucket_brigade *bb,
                                  apr_read_type_e block,
                                  apr_size_t *pspace_left,
                                  apr_off_t *pwritten)
{
    apr_bucket *b;
    const char *data;
    apr_size_t len;
    apr_status_t rv = APR_SUCCESS;
    int can_beam = 0;
    
    (void)block;
    if (beam->aborted) {
        rv = APR_ECONNABORTED;
        goto cleanup;
    }

    ap_assert(beam->pool);

    b = APR_BRIGADE_FIRST(bb);
    if (APR_BUCKET_IS_METADATA(b)) {
        APR_BUCKET_REMOVE(b);
        apr_bucket_setaside(b, beam->pool);
        H2_BLIST_INSERT_TAIL(&beam->buckets_to_send, b);
        goto cleanup;
    }
    /* non meta bucket */

    /* in case of indeterminate length, we need to read the bucket,
     * so that it transforms itself into something stable. */
    if (b->length == ((apr_size_t)-1)) {
        rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) goto cleanup;
    }

    if (APR_BUCKET_IS_FILE(b)) {
        /* For file buckets the problem is their internal readpool that
         * is used on the first read to allocate buffer/mmap.
         * Since setting aside a file bucket will de-register the
         * file cleanup function from the previous pool, we need to
         * call that only from the sender thread.
         *
         * Currently, we do not handle file bucket with refcount > 1 as
         * the beam is then not in complete control of the file's lifetime.
         * Which results in the bug that a file get closed by the receiver
         * while the sender or the beam still have buckets using it. 
         * 
         * Additionally, we allow callbacks to prevent beaming file
         * handles across. The use case for this is to limit the number 
         * of open file handles and rather use a less efficient beam
         * transport. */
        apr_bucket_file *bf = b->data;
        can_beam = !beam->copy_files && (bf->refcount.refcount == 1);
    }
    else if (bucket_is_mmap(b)) {
        can_beam = !beam->copy_files;
    }

    if (b->length == 0) {
        apr_bucket_delete(b);
        rv = APR_SUCCESS;
        goto cleanup;
    }

    if (!*pspace_left) {
        rv = APR_EAGAIN;
        goto cleanup;
    }

    /* bucket is accepted and added to beam->buckets_to_send */
    if (APR_BUCKET_IS_HEAP(b)) {
        /* For heap buckets, a read from a receiver thread is fine. The
         * data will be there and live until the bucket itself is
         * destroyed. */
        rv = apr_bucket_setaside(b, beam->pool);
        if (rv != APR_SUCCESS) goto cleanup;
    }
    else if (can_beam && (APR_BUCKET_IS_FILE(b) || bucket_is_mmap(b))) {
        rv = apr_bucket_setaside(b, beam->pool);
        if (rv != APR_SUCCESS) goto cleanup;
    }
    else {
        /* we know of no special shortcut to transfer the bucket to
         * another pool without copying. So we make it a heap bucket. */
        apr_bucket *b2;

        rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) goto cleanup;
        /* this allocates and copies data */
        b2 = apr_bucket_heap_create(data, len, NULL, bb->bucket_alloc);
        apr_bucket_delete(b);
        b = b2;
        APR_BRIGADE_INSERT_HEAD(bb, b);
    }
    
    APR_BUCKET_REMOVE(b);
    H2_BLIST_INSERT_TAIL(&beam->buckets_to_send, b);
    *pwritten += (apr_off_t)b->length;
    if (b->length > *pspace_left) {
        *pspace_left = 0;
    }
    else {
        *pspace_left -= b->length;
    }

cleanup:
    return rv;
}

apr_status_t h2_beam_send(h2_bucket_beam *beam, conn_rec *from,
                          apr_bucket_brigade *sender_bb, 
                          apr_read_type_e block,
                          apr_off_t *pwritten)
{
    apr_status_t rv = APR_SUCCESS;
    apr_size_t space_left = 0;
    int was_empty;

    ap_assert(beam->pool);

    /* Called from the sender thread to add buckets to the beam */
    apr_thread_mutex_lock(beam->lock);
    ap_assert(beam->from == from);
    ap_assert(sender_bb);
    H2_BEAM_LOG(beam, from, APLOG_TRACE2, rv, "start send", sender_bb);
    purge_consumed_buckets(beam);
    *pwritten = 0;
    was_empty = buffer_is_empty(beam);

    space_left = calc_space_left(beam);
    while (!APR_BRIGADE_EMPTY(sender_bb) && APR_SUCCESS == rv) {
        rv = append_bucket(beam, sender_bb, block, &space_left, pwritten);
        if (!beam->aborted && APR_EAGAIN == rv) {
            /* bucket was not added, as beam buffer has no space left.
             * Trigger event callbacks, so receiver can know there is something
             * to receive before we do a conditional wait. */
            purge_consumed_buckets(beam);
            if (was_empty && beam->was_empty_cb) {
                beam->was_empty_cb(beam->was_empty_ctx, beam);
            }
            rv = wait_not_full(beam, from, block, &space_left);
            if (APR_SUCCESS != rv) {
                break;
            }
            was_empty = buffer_is_empty(beam);
        }
    }

    if (was_empty && beam->was_empty_cb && !buffer_is_empty(beam)) {
        beam->was_empty_cb(beam->was_empty_ctx, beam);
    }
    apr_thread_cond_broadcast(beam->change);

    report_consumption(beam, 1);
    if (beam->aborted) {
        rv = APR_ECONNABORTED;
    }
    H2_BEAM_LOG(beam, from, APLOG_TRACE2, rv, "end send", sender_bb);
    apr_thread_mutex_unlock(beam->lock);
    return rv;
}

apr_status_t h2_beam_receive(h2_bucket_beam *beam,
                             conn_rec *to,
                             apr_bucket_brigade *bb, 
                             apr_read_type_e block,
                             apr_off_t readbytes)
{
    apr_bucket *bsender, *brecv, *ng;
    int transferred = 0;
    apr_status_t rv = APR_SUCCESS;
    apr_off_t remain;
    int consumed_buckets = 0;

    apr_thread_mutex_lock(beam->lock);
    H2_BEAM_LOG(beam, to, APLOG_TRACE2, 0, "start receive", bb);
    if (readbytes <= 0) {
        readbytes = (apr_off_t)APR_SIZE_MAX;
    }
    remain = readbytes;

transfer:
    if (beam->aborted) {
        beam_shutdown(beam, APR_SHUTDOWN_READ);
        rv = APR_ECONNABORTED;
        goto leave;
    }

    ap_assert(beam->pool);

    /* transfer enough buckets from our receiver brigade, if we have one */
    while (remain >= 0
           && beam->recv_buffer
           && !APR_BRIGADE_EMPTY(beam->recv_buffer)) {

        brecv = APR_BRIGADE_FIRST(beam->recv_buffer);
        if (brecv->length > 0 && remain <= 0) {
            break;
        }
        APR_BUCKET_REMOVE(brecv);
        APR_BRIGADE_INSERT_TAIL(bb, brecv);
        remain -= brecv->length;
        ++transferred;
    }

    /* transfer from our sender brigade, transforming sender buckets to
     * receiver ones until we have enough */
    while (remain >= 0 && !H2_BLIST_EMPTY(&beam->buckets_to_send)) {

        brecv = NULL;
        bsender = H2_BLIST_FIRST(&beam->buckets_to_send);
        if (bsender->length > 0 && remain <= 0) {
            break;
        }

        if (APR_BUCKET_IS_METADATA(bsender)) {
            /* we need a real copy into the receivers bucket_alloc */
            if (APR_BUCKET_IS_EOS(bsender)) {
                brecv = apr_bucket_eos_create(bb->bucket_alloc);
            }
            else if (APR_BUCKET_IS_FLUSH(bsender)) {
                brecv = apr_bucket_flush_create(bb->bucket_alloc);
            }
            else if (AP_BUCKET_IS_ERROR(bsender)) {
                ap_bucket_error *eb = (ap_bucket_error *)bsender;
                brecv = ap_bucket_error_create(eb->status, eb->data,
                                                bb->p, bb->bucket_alloc);
            }
            else {
                /* Does someone else know how to make a proxy for
                 * the bucket? Ask the callbacks registered for this. */
                brecv = h2_beam_bucket(beam, bb, bsender);
                while (brecv && brecv != APR_BRIGADE_SENTINEL(bb)) {
                    ++transferred;
                    remain -= brecv->length;
                    brecv = APR_BUCKET_NEXT(brecv);
                }
                brecv = NULL;
            }
        }
        else if (bsender->length == 0) {
            /* nop */
        }
#if APR_HAS_MMAP
        else if (APR_BUCKET_IS_MMAP(bsender)) {
            apr_bucket_mmap *bmmap = bsender->data;
            apr_mmap_t *mmap;
            rv = apr_mmap_dup(&mmap, bmmap->mmap, bb->p);
            if (rv != APR_SUCCESS) goto leave;
            brecv = apr_bucket_mmap_create(mmap, bsender->start, bsender->length, bb->bucket_alloc);
        }
#endif
        else if (APR_BUCKET_IS_FILE(bsender)) {
            /* This is setaside into the target brigade pool so that
             * any read operation messes with that pool and not
             * the sender one. */
            apr_bucket_file *f = (apr_bucket_file *)bsender->data;
            apr_file_t *fd = f->fd;
            int setaside = (f->readpool != bb->p);

            if (setaside) {
                rv = apr_file_setaside(&fd, fd, bb->p);
                if (rv != APR_SUCCESS) goto leave;
            }
            ng = apr_brigade_insert_file(bb, fd, bsender->start, (apr_off_t)bsender->length,
                                         bb->p);
#if APR_HAS_MMAP
            /* disable mmap handling as this leads to segfaults when
             * the underlying file is changed while memory pointer has
             * been handed out. See also PR 59348 */
            apr_bucket_file_enable_mmap(ng, 0);
#endif
            remain -= bsender->length;
            ++transferred;
        }
        else {
            const char *data;
            apr_size_t dlen;
            /* we did that when the bucket was added, so this should
             * give us the same data as before without changing the bucket
             * or anything (pool) connected to it. */
            rv = apr_bucket_read(bsender, &data, &dlen, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) goto leave;
            rv = apr_brigade_write(bb, NULL, NULL, data, dlen);
            if (rv != APR_SUCCESS) goto leave;

            remain -= dlen;
            ++transferred;
        }

        if (brecv) {
            /* we have a proxy that we can give the receiver */
            APR_BRIGADE_INSERT_TAIL(bb, brecv);
            remain -= brecv->length;
            ++transferred;
        }
        APR_BUCKET_REMOVE(bsender);
        H2_BLIST_INSERT_TAIL(&beam->buckets_consumed, bsender);
        beam->recv_bytes += bsender->length;
        ++consumed_buckets;
    }

    if (remain < 0) {
        /* too much, put some back into out recv_buffer */
        remain = readbytes;
        for (brecv = APR_BRIGADE_FIRST(bb);
             brecv != APR_BRIGADE_SENTINEL(bb);
             brecv = APR_BUCKET_NEXT(brecv)) {
            remain -= (beam->tx_mem_limits? bucket_mem_used(brecv)
                       : (apr_off_t)brecv->length);
            if (remain < 0) {
                apr_bucket_split(brecv, (apr_size_t)((apr_off_t)brecv->length+remain));
                beam->recv_buffer = apr_brigade_split_ex(bb,
                                                         APR_BUCKET_NEXT(brecv),
                                                         beam->recv_buffer);
                break;
            }
        }
    }

    if (beam->recv_cb && consumed_buckets > 0) {
        beam->recv_cb(beam->recv_ctx, beam);
    }

    if (transferred) {
        apr_thread_cond_broadcast(beam->change);
        rv = APR_SUCCESS;
    }
    else if (beam->aborted) {
        rv = APR_ECONNABORTED;
    }
    else {
        rv = wait_not_empty(beam, to, block);
        if (rv != APR_SUCCESS) {
            goto leave;
        }
        goto transfer;
    }

leave:
    H2_BEAM_LOG(beam, to, APLOG_TRACE2, rv, "end receive", bb);
    apr_thread_mutex_unlock(beam->lock);
    return rv;
}

void h2_beam_on_consumed(h2_bucket_beam *beam, 
                         h2_beam_io_callback *io_cb, void *ctx)
{
    apr_thread_mutex_lock(beam->lock);
    beam->cons_io_cb = io_cb;
    beam->cons_ctx = ctx;
    apr_thread_mutex_unlock(beam->lock);
}

void h2_beam_on_received(h2_bucket_beam *beam,
                         h2_beam_ev_callback *recv_cb, void *ctx)
{
    apr_thread_mutex_lock(beam->lock);
    beam->recv_cb = recv_cb;
    beam->recv_ctx = ctx;
    apr_thread_mutex_unlock(beam->lock);
}

void h2_beam_on_was_empty(h2_bucket_beam *beam,
                          h2_beam_ev_callback *was_empty_cb, void *ctx)
{
    apr_thread_mutex_lock(beam->lock);
    beam->was_empty_cb = was_empty_cb;
    beam->was_empty_ctx = ctx;
    apr_thread_mutex_unlock(beam->lock);
}


static apr_off_t get_buffered_data_len(h2_bucket_beam *beam)
{
    apr_bucket *b;
    apr_off_t l = 0;

    for (b = H2_BLIST_FIRST(&beam->buckets_to_send);
        b != H2_BLIST_SENTINEL(&beam->buckets_to_send);
        b = APR_BUCKET_NEXT(b)) {
        /* should all have determinate length */
        l += b->length;
    }
    return l;
}

apr_off_t h2_beam_get_buffered(h2_bucket_beam *beam)
{
    apr_off_t l = 0;

    apr_thread_mutex_lock(beam->lock);
    l = get_buffered_data_len(beam);
    apr_thread_mutex_unlock(beam->lock);
    return l;
}

apr_off_t h2_beam_get_mem_used(h2_bucket_beam *beam)
{
    apr_bucket *b;
    apr_off_t l = 0;

    apr_thread_mutex_lock(beam->lock);
    for (b = H2_BLIST_FIRST(&beam->buckets_to_send);
        b != H2_BLIST_SENTINEL(&beam->buckets_to_send);
        b = APR_BUCKET_NEXT(b)) {
        l += bucket_mem_used(b);
    }
    apr_thread_mutex_unlock(beam->lock);
    return l;
}

static int is_empty(h2_bucket_beam *beam)
{
    return (H2_BLIST_EMPTY(&beam->buckets_to_send)
            && (!beam->recv_buffer || APR_BRIGADE_EMPTY(beam->recv_buffer)));
}

int h2_beam_empty(h2_bucket_beam *beam)
{
    int empty = 1;

    apr_thread_mutex_lock(beam->lock);
    empty = is_empty(beam);
    apr_thread_mutex_unlock(beam->lock);
    return empty;
}

int h2_beam_report_consumption(h2_bucket_beam *beam)
{
    int rv = 0;

    apr_thread_mutex_lock(beam->lock);
    rv = report_consumption(beam, 1);
    apr_thread_mutex_unlock(beam->lock);
    return rv;
}
