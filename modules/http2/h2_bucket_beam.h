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

#ifndef h2_bucket_beam_h
#define h2_bucket_beam_h

#include "h2_conn_ctx.h"

struct apr_thread_mutex_t;
struct apr_thread_cond_t;

/**
 * A h2_bucket_beam solves the task of transferring buckets, esp. their data,
 * across threads with as little copying as possible.
 */

typedef void h2_beam_mutex_leave(struct apr_thread_mutex_t *lock);

typedef struct {
    apr_thread_mutex_t *mutex;
    h2_beam_mutex_leave *leave;
} h2_beam_lock;

typedef struct h2_bucket_beam h2_bucket_beam;

typedef apr_status_t h2_beam_mutex_enter(void *ctx, h2_beam_lock *pbl);

typedef void h2_beam_io_callback(void *ctx, h2_bucket_beam *beam,
                                 apr_off_t bytes);
typedef void h2_beam_ev_callback(void *ctx, h2_bucket_beam *beam);

/**
 * h2_blist can hold a list of buckets just like apr_bucket_brigade, but
 * does not to any allocations or related features.
 */
typedef struct {
    APR_RING_HEAD(h2_bucket_list, apr_bucket) list;
} h2_blist;

struct h2_bucket_beam {
    int id;
    const char *name;
    conn_rec *from;
    apr_pool_t *pool;
    h2_blist buckets_to_send;
    h2_blist buckets_consumed;
    apr_bucket_brigade *recv_buffer;
    apr_pool_t *recv_pool;
    
    apr_size_t max_buf_size;
    apr_interval_time_t timeout;

    int aborted;
    int tx_mem_limits; /* only memory size counts on transfers */
    int copy_files;

    struct apr_thread_mutex_t *lock;
    struct apr_thread_cond_t *change;
    
    h2_beam_ev_callback *was_empty_cb; /* event: beam changed to non-empty in h2_beam_send() */
    void *was_empty_ctx;
    h2_beam_ev_callback *recv_cb;      /* event: buckets were transfered in h2_beam_receive() */
    void *recv_ctx;

    apr_off_t recv_bytes;             /* amount of bytes transferred in h2_beam_receive() */
    apr_off_t recv_bytes_reported;    /* amount of bytes reported as received via callback */
    h2_beam_io_callback *cons_io_cb;  /* report: recv_bytes deltas for sender */
    void *cons_ctx;
};

/**
 * Creates a new bucket beam for transfer of buckets across threads.
 *
 * The pool the beam is created with will be protected by the given 
 * mutex and will be used in multiple threads. It needs a pool allocator
 * that is only used inside that same mutex.
 *
 * @param pbeam         will hold the created beam on return
 * @param c_from        connection from which buchets are sent
 * @param pool          pool owning the beam, beam will cleanup when pool released
 * @param id            identifier of the beam
 * @param tag           tag identifying beam for logging
 * @param buffer_size   maximum memory footprint of buckets buffered in beam, or
 *                      0 for no limitation
 * @param timeout       timeout for blocking operations
 */
apr_status_t h2_beam_create(h2_bucket_beam **pbeam,
                            conn_rec *from,
                            apr_pool_t *pool, 
                            int id, const char *tag,
                            apr_size_t buffer_size,
                            apr_interval_time_t timeout);

/**
 * Destroys the beam immediately without cleanup.
 */ 
apr_status_t h2_beam_destroy(h2_bucket_beam *beam, conn_rec *c);

/**
 * Switch copying of file buckets on/off.
 */
void h2_beam_set_copy_files(h2_bucket_beam * beam, int enabled);

/**
 * Send buckets from the given brigade through the beam.
 * This can block of the amount of bucket data is above the buffer limit.
 * @param beam the beam to add buckets to
 * @param from the connection the sender operates on, must be the same as
 *             used to create the beam
 * @param bb the brigade to take buckets from
 * @param block if the sending should block when the buffer is full
 * @param pwritten on return, contains the number of data bytes sent
 * @return APR_SUCCESS when buckets were added to the beam. This can be
 *                     a partial transfer and other buckets may still remain in bb
 *         APR_EAGAIN on non-blocking send when the buffer is full
 *         APR_TIMEUP on blocking semd that time out
 *         APR_ECONNABORTED when beam has been aborted
 */
apr_status_t h2_beam_send(h2_bucket_beam *beam, conn_rec *from,
                          apr_bucket_brigade *bb, 
                          apr_read_type_e block,
                          apr_off_t *pwritten);

/**
 * Receive buckets from the beam into the given brigade. The caller is
 * operating on connection `to`.
 * @param beam the beam to receive buckets from
 * @param to the connection the receiver is working with
 * @param bb the bucket brigade to append to
 * @param block if the read should block when buckets are unavailable
 * @param readbytes the amount of data the receiver wants
 * @return APR_SUCCESS when buckets were appended
 *         APR_EAGAIN on non-blocking read when no buckets are available
 *         APR_TIMEUP on blocking reads that time out
 *         APR_ECONNABORTED when beam has been aborted
 */
apr_status_t h2_beam_receive(h2_bucket_beam *beam, conn_rec *to,
                             apr_bucket_brigade *bb,
                             apr_read_type_e block,
                             apr_off_t readbytes);

/**
 * Determine if beam is empty. 
 */
int h2_beam_empty(h2_bucket_beam *beam);

/**
 * Abort the beam, either from receiving or sending side.
 *
 * @param beam the beam to abort
 * @param c the connection the caller is working with
 */
void h2_beam_abort(h2_bucket_beam *beam, conn_rec *c);

/**
 * Set/get the timeout for blocking sebd/receive operations.
 */
void h2_beam_timeout_set(h2_bucket_beam *beam, 
                         apr_interval_time_t timeout);

apr_interval_time_t h2_beam_timeout_get(h2_bucket_beam *beam);

/**
 * Set/get the maximum buffer size for beam data (memory footprint).
 */
void h2_beam_buffer_size_set(h2_bucket_beam *beam, 
                             apr_size_t buffer_size);
apr_size_t h2_beam_buffer_size_get(h2_bucket_beam *beam);

/**
 * Register a callback to be invoked on the sender side with the
 * amount of bytes that have been consumed by the receiver, since the
 * last callback invocation or reset.
 * @param beam the beam to set the callback on
 * @param io_cb the callback or NULL, called on sender with bytes consumed
 * @param ctx  the context to use in callback invocation
 * 
 * Call from the sender side, io callbacks invoked on sender side, ev callback
 * from any side.
 */
void h2_beam_on_consumed(h2_bucket_beam *beam, 
                         h2_beam_io_callback *io_cb, void *ctx);

/**
 * Register a callback to be invoked on the receiver side whenever
 * buckets have been transfered in a h2_beam_receive() call.
 * @param beam the beam to set the callback on
 * @param recv_cb the callback or NULL, called when buckets are received
 * @param ctx  the context to use in callback invocation
 */
void h2_beam_on_received(h2_bucket_beam *beam,
                         h2_beam_ev_callback *recv_cb, void *ctx);

/**
 * Register a call back from the sender side to be invoked when send
 * has added to a previously empty beam.
 * Unregister by passing a NULL was_empty_cb.
 * @param beam the beam to set the callback on
 * @param was_empty_cb the callback to invoke on blocked send
 * @param ctx  the context to use in callback invocation
 */
void h2_beam_on_was_empty(h2_bucket_beam *beam,
                          h2_beam_ev_callback *was_empty_cb, void *ctx);

/**
 * Call any registered consumed handler, if any changes have happened
 * since the last invocation. 
 * @return !=0 iff a handler has been called
 *
 * Needs to be invoked from the sending side.
 */
int h2_beam_report_consumption(h2_bucket_beam *beam);

/**
 * Get the amount of bytes currently buffered in the beam (unread).
 */
apr_off_t h2_beam_get_buffered(h2_bucket_beam *beam);

/**
 * Get the memory used by the buffered buckets, approximately.
 */
apr_off_t h2_beam_get_mem_used(h2_bucket_beam *beam);

typedef apr_bucket *h2_bucket_beamer(h2_bucket_beam *beam,
                                     apr_bucket_brigade *dest,
                                     const apr_bucket *src);

void h2_register_bucket_beamer(h2_bucket_beamer *beamer);

#endif /* h2_bucket_beam_h */
