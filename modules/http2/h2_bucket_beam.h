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

#ifndef h2_bucket_beam_h
#define h2_bucket_beam_h

struct apr_thread_mutex_t;
struct apr_thread_cond_t;

/*******************************************************************************
 * apr_bucket list without bells and whistles
 ******************************************************************************/
 
/**
 * h2_blist can hold a list of buckets just like apr_bucket_brigade, but
 * does not to any allocations or related features.
 */
typedef struct {
    APR_RING_HEAD(h2_bucket_list, apr_bucket) list;
} h2_blist;

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

/**
 * Print the buckets in the list into the buffer (type and lengths).
 * @param buffer the buffer to print into
 * @param bmax max number of characters to place in buffer, incl. trailing 0
 * @param tag tag string for this bucket list
 * @param sep separator to use
 * @param bl the bucket list to print
 * @return number of characters printed
 */
apr_size_t h2_util_bl_print(char *buffer, apr_size_t bmax, 
                            const char *tag, const char *sep, 
                            h2_blist *bl);

/*******************************************************************************
 * h2_bucket_beam
 ******************************************************************************/

/**
 * A h2_bucket_beam solves the task of transferring buckets, esp. their data,
 * across threads with zero buffer copies.
 *
 * When a thread, let's call it the red thread, wants to send buckets to
 * another, the green thread, it creates a h2_bucket_beam and adds buckets
 * via the h2_beam_send(). It gives the beam to the green thread which then
 * can receive buckets into its own brigade via h2_beam_receive().
 *
 * Sending and receiving can happen concurrently, if a thread mutex is set
 * for the beam, see h2_beam_mutex_set.
 *
 * The beam can limit the amount of data it accepts via the buffer_size. This
 * can also be adjusted during its lifetime. When the beam not only gets a 
 * mutex but als a condition variable (in h2_beam_mutex_set()), sends and
 * receives can be done blocking. A timeout can be set for such blocks.
 *
 * Care needs to be taken when terminating the beam. The beam registers at
 * the pool it was created with and will cleanup after itself. However, if
 * received buckets do still exist, already freed memory might be accessed.
 * The beam does a AP_DEBUG_ASSERT on this condition.
 * 
 * The proper way of shutting down a beam is to first make sure there are no
 * more green buckets out there, then cleanup the beam to purge eventually
 * still existing red buckets and then, possibly, terminate the beam itself
 * (or the pool it was created with).
 *
 * The following restrictions apply to bucket transport:
 * - only EOS and FLUSH meta buckets are copied through. All other meta buckets
 *   are kept in the beams hold.
 * - all kind of data buckets are transported through:
 *   - transient buckets are converted to heap ones on send
 *   - heap and pool buckets require no extra handling
 *   - buckets with indeterminate length are read on send
 *   - file buckets will transfer the file itself into a new bucket, if allowed
 *   - all other buckets are read on send to make sure data is present
 *
 * This assures that when the red thread sends its red buckets, the data
 * is made accessible while still on the red side. The red bucket then enters
 * the beams hold storage.
 * When the green thread calls receive, red buckets in the hold are wrapped
 * into special beam buckets. Beam buckets on read present the data directly
 * from the internal red one, but otherwise live on the green side. When a
 * beam bucket gets destroyed, it notifies its beam that the corresponding
 * red bucket from the hold may be destroyed.
 * Since the destruction of green buckets happens in the green thread, any
 * corresponding red bucket can not immediately be destroyed, as that would
 * result in race conditions.
 * Instead, the beam transfers such red buckets from the hold to the purge
 * storage. Next time there is a call from the red side, the buckets in
 * purge will be deleted.
 *
 * There are callbacks that can be registered with a beam:
 * - a "consumed" callback that gets called on the red side with the
 *   amount of data that has been received by the green side. The amount
 *   is a delta from the last callback invocation. The red side can trigger
 *   these callbacks by calling h2_beam_send() with a NULL brigade.
 * - a "can_beam_file" callback that can prohibit the transfer of file handles
 *   through the beam. This will cause file buckets to be read on send and
 *   its data buffer will then be transports just like a heap bucket would.
 *   When no callback is registered, no restrictions apply and all files are
 *   passed through.
 *   File handles transferred to the green side will stay there until the
 *   receiving brigade's pool is destroyed/cleared. If the pool lives very
 *   long or if many different files are beamed, the process might run out
 *   of available file handles.
 *
 * The name "beam" of course is inspired by good old transporter
 * technology where humans are kept inside the transporter's memory
 * buffers until the transmission is complete. Star gates use a similar trick.
 */

typedef void h2_beam_mutex_leave(void *ctx,  struct apr_thread_mutex_t *lock);

typedef struct {
    apr_thread_mutex_t *mutex;
    h2_beam_mutex_leave *leave;
    void *leave_ctx;
} h2_beam_lock;

typedef struct h2_bucket_beam h2_bucket_beam;

typedef apr_status_t h2_beam_mutex_enter(void *ctx, h2_beam_lock *pbl);

typedef void h2_beam_consumed_callback(void *ctx, h2_bucket_beam *beam,
                                       apr_off_t bytes);

typedef struct h2_beam_proxy h2_beam_proxy;
typedef struct {
    APR_RING_HEAD(h2_beam_proxy_list, h2_beam_proxy) list;
} h2_bproxy_list;

typedef int h2_beam_can_beam_callback(void *ctx, h2_bucket_beam *beam,
                                      apr_file_t *file);

struct h2_bucket_beam {
    int id;
    const char *tag;
    h2_blist red;
    h2_blist hold;
    h2_blist purge;
    apr_bucket_brigade *green;
    h2_bproxy_list proxies;
    apr_pool_t *red_pool;
    
    apr_size_t max_buf_size;
    apr_size_t files_beamed;  /* how many file handles have been set aside */
    apr_file_t *last_beamed;  /* last file beamed */
    apr_off_t sent_bytes;     /* amount of bytes send */
    apr_off_t received_bytes; /* amount of bytes received */
    apr_off_t reported_bytes; /* amount of bytes reported as consumed */
    apr_size_t buckets_sent;
    
    unsigned int aborted : 1;
    unsigned int closed : 1;
    unsigned int close_sent : 1;

    void *m_ctx;
    h2_beam_mutex_enter *m_enter;
    struct apr_thread_cond_t *m_cond;
    apr_interval_time_t timeout;
    
    h2_beam_consumed_callback *consumed_fn;
    void *consumed_ctx;
    h2_beam_can_beam_callback *can_beam_fn;
    void *can_beam_ctx;
};

/**
 * Creates a new bucket beam for transfer of buckets across threads.
 *
 * The pool the beam is created with will be protected by the given 
 * mutex and will be used in multiple threads. It needs a pool allocator
 * that is only used inside that same mutex.
 *
 * @param pbeam will hold the created beam on return
 * @param red_pool      pool usable on red side, beam lifeline
 * @param buffer_size   maximum memory footprint of buckets buffered in beam, or
 *                      0 for no limitation
 *
 * Call from the red side only.
 */
apr_status_t h2_beam_create(h2_bucket_beam **pbeam,
                            apr_pool_t *red_pool, 
                            int id, const char *tag, 
                            apr_size_t buffer_size);

/**
 * Destroys the beam immediately without cleanup.
 *
 * Call from the red side only.
 */ 
apr_status_t h2_beam_destroy(h2_bucket_beam *beam);

/**
 * Send buckets from the given brigade through the beam. Will hold buckets 
 * internally as long as they have not been processed by the receiving side.
 * All accepted buckets are removed from the given brigade. Will return with
 * APR_EAGAIN on non-blocking sends when not all buckets could be accepted.
 * 
 * Call from the red side only.
 */
apr_status_t h2_beam_send(h2_bucket_beam *beam,  
                          apr_bucket_brigade *red_buckets, 
                          apr_read_type_e block);

/**
 * Receive buckets from the beam into the given brigade. Will return APR_EOF
 * when reading past an EOS bucket. Reads can be blocking until data is 
 * available or the beam has been closed. Non-blocking calls return APR_EAGAIN
 * if no data is available.
 *
 * Call from the green side only.
 */
apr_status_t h2_beam_receive(h2_bucket_beam *beam, 
                             apr_bucket_brigade *green_buckets, 
                             apr_read_type_e block,
                             apr_off_t readbytes);

/**
 * Determine if beam is closed. May still contain buffered data. 
 * 
 * Call from red or green side.
 */
int h2_beam_closed(h2_bucket_beam *beam);

/**
 * Determine if beam is empty. 
 * 
 * Call from red or green side.
 */
int h2_beam_empty(h2_bucket_beam *beam);

/**
 * Abort the beam. Will cleanup any buffered buckets and answer all send
 * and receives with APR_ECONNABORTED.
 * 
 * Call from the red side only.
 */
void h2_beam_abort(h2_bucket_beam *beam);

/**
 * Close the beam. Sending an EOS bucket serves the same purpose. 
 * 
 * Call from the red side only.
 */
apr_status_t h2_beam_close(h2_bucket_beam *beam);

/**
 * Empty any buffered data and return APR_SUCCESS when all buckets
 * in transit have been handled. When called with APR_BLOCK_READ and
 * with a mutex installed, will wait until this is the case. Otherwise
 * APR_EAGAIN is returned.
 * If a timeout is set on the beam, waiting might also time out and
 * return APR_ETIMEUP.
 *
 * Call from the red side only.
 */
apr_status_t h2_beam_shutdown(h2_bucket_beam *beam, apr_read_type_e block);

void h2_beam_mutex_set(h2_bucket_beam *beam, 
                       h2_beam_mutex_enter m_enter,
                       struct apr_thread_cond_t *cond,
                       void *m_ctx);

/** 
 * Set/get the timeout for blocking read/write operations. Only works
 * if a mutex has been set for the beam.
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
 * Register a callback to be invoked on the red side with the
 * amount of bytes that have been consumed by the red side, since the
 * last callback invocation or reset.
 * @param beam the beam to set the callback on
 * @param cb   the callback or NULL
 * @param ctx  the context to use in callback invocation
 * 
 * Call from the red side, callbacks invoked on red side.
 */
void h2_beam_on_consumed(h2_bucket_beam *beam, 
                         h2_beam_consumed_callback *cb, void *ctx);

void h2_beam_on_file_beam(h2_bucket_beam *beam, 
                          h2_beam_can_beam_callback *cb, void *ctx);

/**
 * Get the amount of bytes currently buffered in the beam (unread).
 */
apr_off_t h2_beam_get_buffered(h2_bucket_beam *beam);

/**
 * Get the memory used by the buffered buckets, approximately.
 */
apr_off_t h2_beam_get_mem_used(h2_bucket_beam *beam);

/**
 * Return != 0 iff (some) data from the beam has been received.
 */
int h2_beam_was_received(h2_bucket_beam *beam);

apr_size_t h2_beam_get_files_beamed(h2_bucket_beam *beam);

#endif /* h2_bucket_beam_h */
