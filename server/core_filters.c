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

/**
 * @file  core_filters.c
 * @brief Core input/output network filters.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_fnmatch.h"
#include "apr_hash.h"
#include "apr_thread_proc.h"    /* for RLIMIT stuff */

#define APR_WANT_IOVEC
#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h" /* For index_of_response().  Grump. */
#include "http_request.h"
#include "http_vhost.h"
#include "http_main.h"     /* For the default_handler below... */
#include "http_log.h"
#include "util_md5.h"
#include "http_connection.h"
#include "apr_buckets.h"
#include "util_filter.h"
#include "util_ebcdic.h"
#include "mpm_common.h"
#include "scoreboard.h"
#include "mod_core.h"
#include "ap_listen.h"
#include "core.h"

#include "mod_so.h" /* for ap_find_loaded_module_symbol */

#define AP_MIN_SENDFILE_BYTES           (256)

/**
 * Remove all zero length buckets from the brigade.
 */
#define BRIGADE_NORMALIZE(b) \
do { \
    apr_bucket *e = APR_BRIGADE_FIRST(b); \
    while (e != APR_BRIGADE_SENTINEL(b)) { \
        apr_bucket *next = APR_BUCKET_NEXT(e); \
        if (e->length == 0 && !APR_BUCKET_IS_METADATA(e)) { \
            apr_bucket_delete(e); \
        } \
        e = next; \
    } \
} while (0)

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

typedef struct {
    apr_bucket_brigade *empty_bb;
    apr_size_t bytes_written;
    struct iovec *vec;
    apr_size_t nvec;
} core_output_ctx_t;

typedef struct {
    apr_bucket_brigade *bb;
    apr_bucket_brigade *tmpbb;
} core_input_ctx_t;


apr_status_t ap_core_input_filter(ap_filter_t *f, apr_bucket_brigade *b,
                                  ap_input_mode_t mode, apr_read_type_e block,
                                  apr_off_t readbytes)
{
    conn_rec *c = f->c;
    core_input_ctx_t *ctx = f->ctx;
    conn_config_t *cconf = ap_get_core_module_config(c->conn_config);
    apr_status_t rv = APR_SUCCESS;
    const char *str;
    apr_size_t len;

    if (mode == AP_MODE_INIT) {
        /*
         * this mode is for filters that might need to 'initialize'
         * a connection before reading request data from a client.
         * NNTP over SSL for example needs to handshake before the
         * server sends the welcome message.
         * such filters would have changed the mode before this point
         * is reached.  however, protocol modules such as NNTP should
         * not need to know anything about SSL.  given the example, if
         * SSL is not in the filter chain, AP_MODE_INIT is a noop.
         */
        return APR_SUCCESS;
    }

    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(c->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(c->pool, c->bucket_alloc);
        ctx->tmpbb = apr_brigade_create(c->pool, c->bucket_alloc);
        /* seed the brigade with the client socket. */
        rv = ap_run_insert_network_bucket(c, ctx->bb, cconf->socket);
        if (rv != APR_SUCCESS)
            return rv;
    }
    else {
        ap_filter_reinstate_brigade(f, ctx->bb, NULL);
    }

    /* ### This is bad. */
    BRIGADE_NORMALIZE(ctx->bb);

    /* check for empty brigade again *AFTER* BRIGADE_NORMALIZE()
     * If we have lost our socket bucket (see above), we are EOF.
     *
     * Ideally, this should be returning SUCCESS with EOS bucket, but
     * some higher-up APIs (spec. read_request_line via ap_rgetline)
     * want an error code. */
    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        return APR_EOF;
    }

    if (mode == AP_MODE_GETLINE) {
        /* we are reading a single LF line, e.g. the HTTP headers */
        rv = apr_brigade_split_line(b, ctx->bb, block, HUGE_STRING_LEN);
        /* We should treat EAGAIN here the same as we do for EOF (brigade is
         * empty).  We do this by returning whatever we have read.  This may
         * or may not be bogus, but is consistent (for now) with EOF logic.
         */
        if (APR_STATUS_IS_EAGAIN(rv) && block == APR_NONBLOCK_READ) {
            rv = APR_SUCCESS;
        }
        goto cleanup;
    }

    /* ### AP_MODE_PEEK is a horrific name for this mode because we also
     * eat any CRLFs that we see.  That's not the obvious intention of
     * this mode.  Determine whether anyone actually uses this or not. */
    if (mode == AP_MODE_EATCRLF) {
        apr_bucket *e;
        const char *ch;

        /* The purpose of this loop is to ignore any CRLF (or LF) at the end
         * of a request.  Many browsers send extra lines at the end of POST
         * requests.  We use the PEEK method to determine if there is more
         * data on the socket, so that we know if we should delay sending the
         * end of one request until we have served the second request in a
         * pipelined situation.  We don't want to actually delay sending a
         * response if the server finds a CRLF (or LF), becuause that doesn't
         * mean that there is another request, just a blank line.
         */
        while (1) {
            if (APR_BRIGADE_EMPTY(ctx->bb)) {
                rv = APR_EOF;
                goto cleanup;
            }

            e = APR_BRIGADE_FIRST(ctx->bb);
            rv = apr_bucket_read(e, &str, &len, APR_NONBLOCK_READ);
            if (rv != APR_SUCCESS) {
                goto cleanup;
            }

            ch = str;
            while (ch < str + len) {
                if (*ch == APR_ASCII_LF)
                    ch++;
                else if (*ch == APR_ASCII_CR && *(ch + 1) == APR_ASCII_LF)
                    ch += 2;
                else
                    goto cleanup;
            }

            /* If we reach here, we were a bucket just full of CRLFs, so
             * just toss the bucket. */
            /* FIXME: Is this the right thing to do in the core? */
            apr_bucket_delete(e);
        }

        /* UNREACHABLE */
        ap_assert(0);
    }

    /* If mode is EXHAUSTIVE, we want to just read everything until the end
     * of the brigade, which in this case means the end of the socket.
     * To do this, we attach the brigade that has currently been setaside to
     * the brigade that was passed down, and send that brigade back.
     *
     * NOTE:  This is VERY dangerous to use, and should only be done with
     * extreme caution.  FWLIW, this would be needed by an MPM like Perchild;
     * such an MPM can easily request the socket and all data that has been
     * read, which means that it can pass it to the correct child process.
     */
    if (mode == AP_MODE_EXHAUSTIVE) {
        apr_bucket *e;

        /* Tack on any buckets that were set aside. */
        APR_BRIGADE_CONCAT(b, ctx->bb);

        /* Since we've just added all potential buckets (which will most
         * likely simply be the socket bucket) we know this is the end,
         * so tack on an EOS too. */
        /* We have read until the brigade was empty, so we know that we
         * must be EOS. */
        e = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);

        rv = APR_SUCCESS;
        goto cleanup;
    }

    /* read up to the amount they specified. */
    if (mode == AP_MODE_READBYTES || mode == AP_MODE_SPECULATIVE) {
        apr_bucket *e;

        AP_DEBUG_ASSERT(readbytes > 0);

        e = APR_BRIGADE_FIRST(ctx->bb);
        rv = apr_bucket_read(e, &str, &len, block);
        if (rv != APR_SUCCESS) {
            if (APR_STATUS_IS_EAGAIN(rv) && block == APR_NONBLOCK_READ) {
                /* getting EAGAIN for a blocking read is an error; not for a
                 * non-blocking read, return an empty brigade. */
                rv = APR_SUCCESS;
            }
            goto cleanup;
        }
        else if (block == APR_BLOCK_READ && len == 0) {
            /* We wanted to read some bytes in blocking mode.  We read
             * 0 bytes.  Hence, we now assume we are EOS.
             *
             * When we are in normal mode, return an EOS bucket to the
             * caller.
             * When we are in speculative mode, leave ctx->bb empty, so
             * that the next call returns an EOS bucket.
             */
            apr_bucket_delete(e);

            if (mode == AP_MODE_READBYTES) {
                e = apr_bucket_eos_create(c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(b, e);
            }
            goto cleanup;
        }

        /* Have we read as much data as we wanted (be greedy)? */
        if (len < readbytes) {
            apr_size_t bucket_len;

            /* We already registered the data in e in len */
            e = APR_BUCKET_NEXT(e);
            while ((len < readbytes) && (rv == APR_SUCCESS)
                   && (e != APR_BRIGADE_SENTINEL(ctx->bb))) {
                /* Check for the availability of buckets with known length */
                if (e->length != (apr_size_t)-1) {
                    len += e->length;
                    e = APR_BUCKET_NEXT(e);
                }
                else {
                    /*
                     * Read from bucket, but non blocking. If there isn't any
                     * more data, well than this is fine as well, we will
                     * not wait for more since we already got some and we are
                     * only checking if there isn't more.
                     */
                    rv = apr_bucket_read(e, &str, &bucket_len,
                                         APR_NONBLOCK_READ);
                    if (rv == APR_SUCCESS) {
                        len += bucket_len;
                        e = APR_BUCKET_NEXT(e);
                    }
                }
            }
        }

        /* We can only return at most what we read. */
        if (len < readbytes) {
            readbytes = len;
        }

        rv = apr_brigade_partition(ctx->bb, readbytes, &e);
        if (rv != APR_SUCCESS) {
            goto cleanup;
        }

        /* Must do move before CONCAT */
        ctx->tmpbb = apr_brigade_split_ex(ctx->bb, e, ctx->tmpbb);

        if (mode == AP_MODE_READBYTES) {
            APR_BRIGADE_CONCAT(b, ctx->bb);
        }
        else { /* mode == AP_MODE_SPECULATIVE */
            apr_bucket *copy_bucket;

            for (e = APR_BRIGADE_FIRST(ctx->bb);
                 e != APR_BRIGADE_SENTINEL(ctx->bb);
                 e = APR_BUCKET_NEXT(e))
            {
                rv = apr_bucket_copy(e, &copy_bucket);
                if (rv != APR_SUCCESS) {
                    goto cleanup;
                }
                APR_BRIGADE_INSERT_TAIL(b, copy_bucket);
            }
        }

        /* Take what was originally there and place it back on ctx->bb */
        APR_BRIGADE_CONCAT(ctx->bb, ctx->tmpbb);
    }

cleanup:
    ap_filter_adopt_brigade(f, ctx->bb);
    return rv;
}

static apr_status_t send_brigade_nonblocking(apr_socket_t *s,
                                             apr_bucket_brigade *bb,
                                             core_output_ctx_t *ctx,
                                             conn_rec *c);

static apr_status_t writev_nonblocking(apr_socket_t *s,
                                       apr_bucket_brigade *bb,
                                       core_output_ctx_t *ctx,
                                       apr_size_t bytes_to_write,
                                       apr_size_t nvec,
                                       conn_rec *c);

#if APR_HAS_SENDFILE
static apr_status_t sendfile_nonblocking(apr_socket_t *s,
                                         apr_bucket *bucket,
                                         core_output_ctx_t *ctx,
                                         conn_rec *c);
#endif

/* Optional function coming from mod_logio, used for logging of output
 * traffic
 */
extern APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *ap__logio_add_bytes_out;

apr_status_t ap_core_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    conn_rec *c = f->c;
    core_output_ctx_t *ctx = f->ctx;
    conn_config_t *cconf = ap_get_core_module_config(c->conn_config);
    apr_socket_t *sock = cconf->socket;
    apr_interval_time_t sock_timeout = 0;
    apr_status_t rv;

    /* Fail quickly if the connection has already been aborted. */
    if (c->aborted) {
        apr_brigade_cleanup(bb);
        return APR_ECONNABORTED;
    }

    if (ctx == NULL) {
        f->ctx = ctx = apr_pcalloc(c->pool, sizeof(*ctx));
    }

    /* remain compatible with legacy MPMs that passed NULL to this filter */
    if (bb == NULL) {
        if (ctx->empty_bb == NULL) {
            ctx->empty_bb = apr_brigade_create(c->pool, c->bucket_alloc);
        }
        else {
            apr_brigade_cleanup(ctx->empty_bb);
        }
        bb = ctx->empty_bb;
    }

    /* Prepend buckets set aside, if any. */
    ap_filter_reinstate_brigade(f, bb, NULL);
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    /* Non-blocking writes on the socket in any case. */
    apr_socket_timeout_get(sock, &sock_timeout);
    apr_socket_timeout_set(sock, 0);

    do {
        rv = send_brigade_nonblocking(sock, bb, ctx, c);
        if (APR_STATUS_IS_EAGAIN(rv)) {
            /* Scan through the brigade and decide whether we must absolutely
             * flush the remaining data, based on ap_filter_reinstate_brigade()
             * rules. If so, wait for writability and retry, otherwise we did
             * our best already and can wait for the next call.
             */
            apr_bucket *flush_upto;
            ap_filter_reinstate_brigade(f, bb, &flush_upto);
            if (flush_upto) {
                apr_int32_t nfd;
                apr_pollfd_t pfd;
                memset(&pfd, 0, sizeof(pfd));
                pfd.reqevents = APR_POLLOUT;
                pfd.desc_type = APR_POLL_SOCKET;
                pfd.desc.s = sock;
                pfd.p = c->pool;
                do {
                    rv = apr_poll(&pfd, 1, &nfd, sock_timeout);
                } while (APR_STATUS_IS_EINTR(rv));
            }
        }
    } while (rv == APR_SUCCESS && !APR_BRIGADE_EMPTY(bb));

    /* Restore original socket timeout before leaving. */
    apr_socket_timeout_set(sock, sock_timeout);

    if (rv != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(rv)) {
        /* The client has aborted the connection */
        ap_log_cerror(
                APLOG_MARK, APLOG_TRACE1, rv, c,
                "core_output_filter: writing data to the network");
        /*
         * Set c->aborted before apr_brigade_cleanup to have the correct status
         * when logging the request as apr_brigade_cleanup triggers the logging
         * of the request if it contains an EOR bucket.
         */
        c->aborted = 1;
        apr_brigade_cleanup(bb);
        return rv;
    }

    return ap_filter_setaside_brigade(f, bb);
}

#ifndef APR_MAX_IOVEC_SIZE
#define NVEC_MIN 16
#define NVEC_MAX NVEC_MIN
#else
#if APR_MAX_IOVEC_SIZE > 16
#define NVEC_MIN 16
#else
#define NVEC_MIN APR_MAX_IOVEC_SIZE
#endif
#define NVEC_MAX APR_MAX_IOVEC_SIZE
#endif

static APR_INLINE int is_in_memory_bucket(apr_bucket *b)
{
    /* These buckets' data are already in memory. */
    return APR_BUCKET_IS_HEAP(b)
           || APR_BUCKET_IS_POOL(b)
           || APR_BUCKET_IS_TRANSIENT(b)
           || APR_BUCKET_IS_IMMORTAL(b);
}

#if APR_HAS_SENDFILE
static APR_INLINE int can_sendfile_bucket(apr_bucket *b)
{
    /* Use sendfile to send the bucket unless:
     *   - the bucket is not a file bucket, or
     *   - the file is too small for sendfile to be useful, or
     *   - sendfile is disabled in the httpd config via "EnableSendfile off".
     */
    if (APR_BUCKET_IS_FILE(b) && b->length >= AP_MIN_SENDFILE_BYTES) {
        apr_file_t *file = ((apr_bucket_file *)b->data)->fd;
        return apr_file_flags_get(file) & APR_SENDFILE_ENABLED;
    }
    else {
        return 0;
    }
}
#endif

static apr_status_t send_brigade_nonblocking(apr_socket_t *s,
                                             apr_bucket_brigade *bb,
                                             core_output_ctx_t *ctx,
                                             conn_rec *c)
{
    apr_status_t rv = APR_SUCCESS;
    core_server_config *sconf =
        ap_get_core_module_config(c->base_server->module_config);
    apr_size_t nvec = 0, nbytes = 0;
    apr_bucket *bucket, *next;
    const char *data;
    apr_size_t length;

    for (bucket = APR_BRIGADE_FIRST(bb);
         bucket != APR_BRIGADE_SENTINEL(bb);
         bucket = next) {
        next = APR_BUCKET_NEXT(bucket);

#if APR_HAS_SENDFILE
        if (can_sendfile_bucket(bucket)) {
            if (nvec > 0) {
                (void)apr_socket_opt_set(s, APR_TCP_NOPUSH, 1);
                rv = writev_nonblocking(s, bb, ctx, nbytes, nvec, c);
                if (rv != APR_SUCCESS) {
                    goto cleanup;
                }
                nbytes = 0;
                nvec = 0;
            }
            rv = sendfile_nonblocking(s, bucket, ctx, c);
            if (rv != APR_SUCCESS) {
                goto cleanup;
            }
            continue;
        }
#endif /* APR_HAS_SENDFILE */

        if (bucket->length) {
            /* Non-blocking read first, in case this is a morphing
             * bucket type. */
            rv = apr_bucket_read(bucket, &data, &length, APR_NONBLOCK_READ);
            if (APR_STATUS_IS_EAGAIN(rv)) {
                /* Read would block; flush any pending data and retry. */
                if (nvec) {
                    rv = writev_nonblocking(s, bb, ctx, nbytes, nvec, c);
                    if (rv != APR_SUCCESS) {
                        goto cleanup;
                    }
                    nbytes = 0;
                    nvec = 0;
                }
                (void)apr_socket_opt_set(s, APR_TCP_NOPUSH, 0);

                rv = apr_bucket_read(bucket, &data, &length, APR_BLOCK_READ);
            }
            if (rv != APR_SUCCESS) {
                goto cleanup;
            }

            /* reading may have split the bucket, so recompute next: */
            next = APR_BUCKET_NEXT(bucket);
        }

        if (!bucket->length) {
            /* Don't delete empty buckets until all the previous ones have been
             * sent (nvec == 0); this must happen in sequence since metabuckets
             * like EOR could free the data still pointed to by the iovec. So
             * unless the latter is empty, let writev_nonblocking() cleanup the
             * brigade in order.
             */
            if (!nvec) {
                if (AP_BUCKET_IS_EOR(bucket)) {
                    /* Mark the request as flushed since all its
                     * buckets (preceding this EOR) have been sent.
                     */
                    request_rec *r = ap_bucket_eor_request(bucket);
                    ap_assert(r != NULL);
                    r->flushed = 1;
                }
                apr_bucket_delete(bucket);
            }
            continue;
        }

        /* Make sure that these new data fit in our iovec. */
        if (nvec == ctx->nvec) {
            if (nvec == NVEC_MAX) {
                (void)apr_socket_opt_set(s, APR_TCP_NOPUSH, 1);
                rv = writev_nonblocking(s, bb, ctx, nbytes, nvec, c);
                if (rv != APR_SUCCESS) {
                    goto cleanup;
                }
                nbytes = 0;
                nvec = 0;
            }
            else {
                struct iovec *newvec;
                apr_size_t newn = nvec * 2;
                if (newn < NVEC_MIN) {
                    newn = NVEC_MIN;
                }
                else if (newn > NVEC_MAX) {
                    newn = NVEC_MAX;
                }
                newvec = apr_palloc(c->pool, newn * sizeof(struct iovec));
                if (nvec) {
                    memcpy(newvec, ctx->vec, nvec * sizeof(struct iovec));
                }
                ctx->vec = newvec;
                ctx->nvec = newn;
            }
        }
        nbytes += length;
        ctx->vec[nvec].iov_base = (void *)data;
        ctx->vec[nvec].iov_len = length;
        nvec++;

        /* Flush above max threshold, unless the brigade still contains in
         * memory buckets which we want to try writing in the same pass (if
         * we are at the end of the brigade, the write will happen outside
         * the loop anyway).
         */
        if (nbytes > sconf->flush_max_threshold
                && next != APR_BRIGADE_SENTINEL(bb)
                && !is_in_memory_bucket(next)) {
            (void)apr_socket_opt_set(s, APR_TCP_NOPUSH, 1);
            rv = writev_nonblocking(s, bb, ctx, nbytes, nvec, c);
            if (rv != APR_SUCCESS) {
                goto cleanup;
            }
            nbytes = 0;
            nvec = 0;
        }
    }
    if (nvec > 0) {
        rv = writev_nonblocking(s, bb, ctx, nbytes, nvec, c);
    }

cleanup:
    (void)apr_socket_opt_set(s, APR_TCP_NOPUSH, 0);
    return rv;
}

static apr_status_t writev_nonblocking(apr_socket_t *s,
                                       apr_bucket_brigade *bb,
                                       core_output_ctx_t *ctx,
                                       apr_size_t bytes_to_write,
                                       apr_size_t nvec,
                                       conn_rec *c)
{
    apr_status_t rv;
    struct iovec *vec = ctx->vec;
    apr_size_t bytes_written = 0;
    apr_size_t i, offset = 0;

    do {
        apr_size_t n = 0;
        rv = apr_socket_sendv(s, vec + offset, nvec - offset, &n);
        bytes_written += n;

        for (i = offset; i < nvec; ) {
            apr_bucket *bucket = APR_BRIGADE_FIRST(bb);
            if (!bucket->length) {
                if (AP_BUCKET_IS_EOR(bucket)) {
                    /* Mark the request as flushed since all its
                     * buckets (preceding this EOR) have been sent.
                     */
                    request_rec *r = ap_bucket_eor_request(bucket);
                    ap_assert(r != NULL);
                    r->flushed = 1;
                }
                apr_bucket_delete(bucket);
            }
            else if (n >= vec[i].iov_len) {
                apr_bucket_delete(bucket);
                n -= vec[i++].iov_len;
                offset++;
            }
            else {
                if (n) {
                    apr_bucket_split(bucket, n);
                    apr_bucket_delete(bucket);
                    vec[i].iov_len -= n;
                    vec[i].iov_base = (char *) vec[i].iov_base + n;
                }
                break;
            }
        }
    } while (rv == APR_SUCCESS && bytes_written < bytes_to_write);

    if ((ap__logio_add_bytes_out != NULL) && (bytes_written > 0)) {
        ap__logio_add_bytes_out(c, bytes_written);
    }
    ctx->bytes_written += bytes_written;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, rv, c,
                  "writev_nonblocking: %"APR_SIZE_T_FMT"/%"APR_SIZE_T_FMT,
                  bytes_written, bytes_to_write);
    return rv;
}

#if APR_HAS_SENDFILE

static apr_status_t sendfile_nonblocking(apr_socket_t *s,
                                         apr_bucket *bucket,
                                         core_output_ctx_t *ctx,
                                         conn_rec *c)
{
    apr_status_t rv;
    apr_file_t *file = ((apr_bucket_file *)bucket->data)->fd;
    apr_size_t bytes_written = bucket->length; /* bytes_to_write for now */
    apr_off_t file_offset = bucket->start;

    rv = apr_socket_sendfile(s, file, NULL, &file_offset, &bytes_written, 0);
    if ((ap__logio_add_bytes_out != NULL) && (bytes_written > 0)) {
        ap__logio_add_bytes_out(c, bytes_written);
    }
    ctx->bytes_written += bytes_written;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, rv, c,
                  "sendfile_nonblocking: %" APR_SIZE_T_FMT "/%" APR_SIZE_T_FMT,
                  bytes_written, bucket->length);
    if (bytes_written >= bucket->length) {
        apr_bucket_delete(bucket);
    }
    else if (bytes_written > 0) {
        apr_bucket_split(bucket, bytes_written);
        apr_bucket_delete(bucket);
        if (rv == APR_SUCCESS) {
            rv = APR_EAGAIN;
        }
    }
    return rv;
}

#endif
