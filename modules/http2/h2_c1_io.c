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
 
#include <assert.h>
#include <apr_strings.h>
#include <ap_mpm.h>
#include <mpm_common.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_ssl.h>

#include "h2_private.h"
#include "h2_bucket_eos.h"
#include "h2_config.h"
#include "h2_c1.h"
#include "h2_c1_io.h"
#include "h2_protocol.h"
#include "h2_session.h"
#include "h2_util.h"

#define TLS_DATA_MAX          (16*1024) 

/* Calculated like this: assuming MTU 1500 bytes
 * 1500 - 40 (IP) - 20 (TCP) - 40 (TCP options) 
 *      - TLS overhead (60-100) 
 * ~= 1300 bytes */
#define WRITE_SIZE_INITIAL    1300

/* The maximum we'd like to write in one chunk is
 * the max size of a TLS record. When pushing
 * many frames down the h2 connection, this might
 * align differently because of headers and other
 * frames or simply as not sufficient data is
 * in a response body.
 * However keeping frames at or below this limit
 * should make optimizations at the layer that writes
 * to TLS easier.
 */
#define WRITE_SIZE_MAX        (TLS_DATA_MAX) 

#define BUF_REMAIN            ((apr_size_t)(bmax-off))

static void h2_c1_io_bb_log(conn_rec *c, int stream_id, int level,
                            const char *tag, apr_bucket_brigade *bb)
{
    char buffer[16 * 1024];
    const char *line = "(null)";
    int bmax = sizeof(buffer)/sizeof(buffer[0]);
    int off = 0;
    apr_bucket *b;
    
    (void)stream_id;
    if (bb) {
        memset(buffer, 0, bmax--);
        for (b = APR_BRIGADE_FIRST(bb); 
             bmax && (b != APR_BRIGADE_SENTINEL(bb));
             b = APR_BUCKET_NEXT(b)) {
            
            if (APR_BUCKET_IS_METADATA(b)) {
                if (APR_BUCKET_IS_EOS(b)) {
                    off += apr_snprintf(buffer+off, BUF_REMAIN, "eos ");
                }
                else if (APR_BUCKET_IS_FLUSH(b)) {
                    off += apr_snprintf(buffer+off, BUF_REMAIN, "flush ");
                }
                else if (AP_BUCKET_IS_EOR(b)) {
                    off += apr_snprintf(buffer+off, BUF_REMAIN, "eor ");
                }
                else if (H2_BUCKET_IS_H2EOS(b)) {
                    off += apr_snprintf(buffer+off, BUF_REMAIN, "h2eos ");
                }
                else {
                    off += apr_snprintf(buffer+off, BUF_REMAIN, "meta(unknown) ");
                }
            }
            else {
                const char *btype = "data";
                if (APR_BUCKET_IS_FILE(b)) {
                    btype = "file";
                }
                else if (APR_BUCKET_IS_PIPE(b)) {
                    btype = "pipe";
                }
                else if (APR_BUCKET_IS_SOCKET(b)) {
                    btype = "socket";
                }
                else if (APR_BUCKET_IS_HEAP(b)) {
                    btype = "heap";
                }
                else if (APR_BUCKET_IS_TRANSIENT(b)) {
                    btype = "transient";
                }
                else if (APR_BUCKET_IS_IMMORTAL(b)) {
                    btype = "immortal";
                }
#if APR_HAS_MMAP
                else if (APR_BUCKET_IS_MMAP(b)) {
                    btype = "mmap";
                }
#endif
                else if (APR_BUCKET_IS_POOL(b)) {
                    btype = "pool";
                }
                
                off += apr_snprintf(buffer+off, BUF_REMAIN, "%s[%ld] ", 
                                    btype, 
                                    (long)(b->length == ((apr_size_t)-1)? -1UL : b->length));
            }
        }
        line = *buffer? buffer : "(empty)";
    }
    /* Intentional no APLOGNO */
    ap_log_cerror(APLOG_MARK, level, 0, c, "h2_session(%ld)-%s: %s", 
                  c->id, tag, line);

}
#define C1_IO_BB_LOG(c, stream_id, level, tag, bb) \
    if (APLOG_C_IS_LEVEL(c, level)) { \
        h2_c1_io_bb_log((c), (stream_id), (level), (tag), (bb)); \
    }


apr_status_t h2_c1_io_init(h2_c1_io *io, h2_session *session)
{
    conn_rec *c = session->c1;

    io->session = session;
    io->output = apr_brigade_create(c->pool, c->bucket_alloc);
    io->is_tls = ap_ssl_conn_is_ssl(session->c1);
    io->buffer_output  = io->is_tls;
    io->flush_threshold = 4 * (apr_size_t)h2_config_sgeti64(session->s, H2_CONF_STREAM_MAX_MEM);

    if (io->buffer_output) {
        /* This is what we start with, 
         * see https://issues.apache.org/jira/browse/TS-2503 
         */
        io->warmup_size = h2_config_sgeti64(session->s, H2_CONF_TLS_WARMUP_SIZE);
        io->cooldown_usecs = (h2_config_sgeti(session->s, H2_CONF_TLS_COOLDOWN_SECS)
                              * APR_USEC_PER_SEC);
        io->cooldown_usecs = 0;
        io->write_size = (io->cooldown_usecs > 0?
                          WRITE_SIZE_INITIAL : WRITE_SIZE_MAX);
    }
    else {
        io->warmup_size = 0;
        io->cooldown_usecs = 0;
        io->write_size = 0;
    }

    if (APLOGctrace1(c)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c,
                      "h2_c1_io(%ld): init, buffering=%d, warmup_size=%ld, "
                      "cd_secs=%f", c->id, io->buffer_output,
                      (long)io->warmup_size,
                      ((double)io->cooldown_usecs/APR_USEC_PER_SEC));
    }

    return APR_SUCCESS;
}

static void append_scratch(h2_c1_io *io)
{
    if (io->scratch && io->slen > 0) {
        apr_bucket *b = apr_bucket_heap_create(io->scratch, io->slen,
                                               apr_bucket_free,
                                               io->session->c1->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(io->output, b);
        io->buffered_len += io->slen;
        io->scratch = NULL;
        io->slen = io->ssize = 0;
    }
}

static apr_size_t assure_scratch_space(h2_c1_io *io) {
    apr_size_t remain = io->ssize - io->slen; 
    if (io->scratch && remain == 0) {
        append_scratch(io);
    }
    if (!io->scratch) {
        /* we control the size and it is larger than what buckets usually
         * allocate. */
        io->scratch = apr_bucket_alloc(io->write_size, io->session->c1->bucket_alloc);
        io->ssize = io->write_size;
        io->slen = 0;
        remain = io->ssize;
    }
    return remain;
}
    
static apr_status_t read_to_scratch(h2_c1_io *io, apr_bucket *b)
{
    apr_status_t status;
    const char *data;
    apr_size_t len;
    
    if (!b->length) {
        return APR_SUCCESS;
    }
    
    ap_assert(b->length <= (io->ssize - io->slen));
    if (APR_BUCKET_IS_FILE(b)) {
        apr_bucket_file *f = (apr_bucket_file *)b->data;
        apr_file_t *fd = f->fd;
        apr_off_t offset = b->start;
        
        len = b->length;
        /* file buckets will read 8000 byte chunks and split
         * themselves. However, we do know *exactly* how many
         * bytes we need where. So we read the file directly to
         * where we need it.
         */
        status = apr_file_seek(fd, APR_SET, &offset);
        if (status != APR_SUCCESS) {
            return status;
        }
        status = apr_file_read(fd, io->scratch + io->slen, &len);
        if (status != APR_SUCCESS && status != APR_EOF) {
            return status;
        }
        io->slen += len;
    }
    else if (APR_BUCKET_IS_MMAP(b)) {
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, io->session->c1,
                      "h2_c1_io(%ld): seeing mmap bucket of size %ld, scratch remain=%ld",
                      io->session->c1->id, (long)b->length, (long)(io->ssize - io->slen));
        status = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (status == APR_SUCCESS) {
            memcpy(io->scratch+io->slen, data, len);
            io->slen += len;
        }
    }
    else {
        status = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (status == APR_SUCCESS) {
            memcpy(io->scratch+io->slen, data, len);
            io->slen += len;
        }
    }
    return status;
}

static apr_status_t pass_output(h2_c1_io *io, int flush)
{
    conn_rec *c = io->session->c1;
    apr_off_t bblen;
    apr_status_t rv;
    
    append_scratch(io);
    if (flush) {
        if (!APR_BUCKET_IS_FLUSH(APR_BRIGADE_LAST(io->output))) {
            apr_bucket *b = apr_bucket_flush_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(io->output, b);
        }
    }
    if (APR_BRIGADE_EMPTY(io->output)) {
        return APR_SUCCESS;
    }
    
    io->unflushed = !APR_BUCKET_IS_FLUSH(APR_BRIGADE_LAST(io->output));
    apr_brigade_length(io->output, 0, &bblen);
    C1_IO_BB_LOG(c, 0, APLOG_TRACE2, "out", io->output);
    
    rv = ap_pass_brigade(c->output_filters, io->output);
    if (APR_SUCCESS != rv) goto cleanup;

    io->buffered_len = 0;
    io->bytes_written += (apr_size_t)bblen;

    if (io->write_size < WRITE_SIZE_MAX
         && io->bytes_written >= io->warmup_size) {
        /* connection is hot, use max size */
        io->write_size = WRITE_SIZE_MAX;
    }
    else if (io->cooldown_usecs > 0
             && io->write_size > WRITE_SIZE_INITIAL) {
        apr_time_t now = apr_time_now();
        if ((now - io->last_write) >= io->cooldown_usecs) {
            /* long time not written, reset write size */
            io->write_size = WRITE_SIZE_INITIAL;
            io->bytes_written = 0;
        }
        else {
            io->last_write = now;
        }
    }

cleanup:
    if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO(03044)
                      "h2_c1_io(%ld): pass_out brigade %ld bytes",
                      c->id, (long)bblen);
    }
    apr_brigade_cleanup(io->output);
    return rv;
}

int h2_c1_io_needs_flush(h2_c1_io *io)
{
    return io->buffered_len >= io->flush_threshold;
}

int h2_c1_io_pending(h2_c1_io *io)
{
    return !APR_BRIGADE_EMPTY(io->output) || (io->scratch && io->slen > 0);
}

apr_status_t h2_c1_io_pass(h2_c1_io *io)
{
    apr_status_t rv = APR_SUCCESS;

    if (h2_c1_io_pending(io)) {
        rv = pass_output(io, 0);
    }
    return rv;
}

apr_status_t h2_c1_io_assure_flushed(h2_c1_io *io)
{
    apr_status_t rv = APR_SUCCESS;

    if (h2_c1_io_pending(io) || io->unflushed) {
        rv = pass_output(io, 1);
        if (APR_SUCCESS != rv) goto cleanup;
    }
cleanup:
    return rv;
}

apr_status_t h2_c1_io_add_data(h2_c1_io *io, const char *data, size_t length)
{
    apr_status_t status = APR_SUCCESS;
    apr_size_t remain;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, io->session->c1,
                  "h2_c1_io(%ld): adding %ld data bytes",
                  io->session->c1->id, (long)length);
    if (io->buffer_output) {
        while (length > 0) {
            remain = assure_scratch_space(io);
            if (remain >= length) {
                memcpy(io->scratch + io->slen, data, length);
                io->slen += length;
                length = 0;
            }
            else {
                memcpy(io->scratch + io->slen, data, remain);
                io->slen += remain;
                data += remain;
                length -= remain;
            }
        }
    }
    else {
        status = apr_brigade_write(io->output, NULL, NULL, data, length);
        io->buffered_len += length;
    }
    return status;
}

apr_status_t h2_c1_io_append(h2_c1_io *io, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    apr_status_t rv = APR_SUCCESS;

    while (!APR_BRIGADE_EMPTY(bb)) {
        b = APR_BRIGADE_FIRST(bb);
        if (APR_BUCKET_IS_METADATA(b) || APR_BUCKET_IS_MMAP(b)) {
            /* need to finish any open scratch bucket, as meta data
             * needs to be forward "in order". */
            append_scratch(io);
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(io->output, b);
        }
        else if (io->buffer_output) {
            apr_size_t remain = assure_scratch_space(io);
            if (b->length > remain) {
                apr_bucket_split(b, remain);
                if (io->slen == 0) {
                    /* complete write_size bucket, append unchanged */
                    APR_BUCKET_REMOVE(b);
                    APR_BRIGADE_INSERT_TAIL(io->output, b);
                    io->buffered_len += b->length;
                    continue;
                }
            }
            else {
                /* bucket fits in remain, copy to scratch */
                rv = read_to_scratch(io, b);
                apr_bucket_delete(b);
                if (APR_SUCCESS != rv) goto cleanup;
                continue;
            }
        }
        else {
            /* no buffering, forward buckets setaside on flush */
            apr_bucket_setaside(b, io->session->c1->pool);
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(io->output, b);
            io->buffered_len += b->length;
        }
    }
cleanup:
    return rv;
}

static apr_status_t c1_in_feed_bucket(h2_session *session,
                                      apr_bucket *b, apr_ssize_t *inout_len)
{
    apr_status_t rv = APR_SUCCESS;
    apr_size_t len;
    const char *data;
    ssize_t n;

    rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
    while (APR_SUCCESS == rv && len > 0) {
        n = nghttp2_session_mem_recv(session->ngh2, (const uint8_t *)data, len);

        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, session->c1,
                      H2_SSSN_MSG(session, "fed %ld bytes to nghttp2, %ld read"),
                      (long)len, (long)n);
        if (n < 0) {
            if (nghttp2_is_fatal((int)n)) {
                h2_session_event(session, H2_SESSION_EV_PROTO_ERROR,
                                 (int)n, nghttp2_strerror((int)n));
                rv = APR_EGENERAL;
            }
        }
        else {
            *inout_len += n;
            if ((apr_ssize_t)len <= n) {
                break;
            }
            len -= (apr_size_t)n;
            data += n;
        }
    }

    return rv;
}

static apr_status_t c1_in_feed_brigade(h2_session *session,
                                       apr_bucket_brigade *bb,
                                       apr_ssize_t *inout_len)
{
    apr_status_t rv = APR_SUCCESS;
    apr_bucket* b;

    *inout_len = 0;
    while (!APR_BRIGADE_EMPTY(bb)) {
        b = APR_BRIGADE_FIRST(bb);
        if (!APR_BUCKET_IS_METADATA(b)) {
            rv = c1_in_feed_bucket(session, b, inout_len);
            if (APR_SUCCESS != rv) goto cleanup;
        }
        apr_bucket_delete(b);
    }
cleanup:
    apr_brigade_cleanup(bb);
    return rv;
}

static apr_status_t read_and_feed(h2_session *session)
{
    apr_ssize_t bytes_fed, bytes_requested;
    apr_status_t rv;

    bytes_requested = H2MAX(APR_BUCKET_BUFF_SIZE, session->max_stream_mem * 4);
    rv = ap_get_brigade(session->c1->input_filters,
                        session->bbtmp, AP_MODE_READBYTES,
                        APR_NONBLOCK_READ, bytes_requested);

    if (APR_SUCCESS == rv) {
        h2_util_bb_log(session->c1, session->id, APLOG_TRACE2, "c1 in", session->bbtmp);
        rv = c1_in_feed_brigade(session, session->bbtmp, &bytes_fed);
        session->io.bytes_read += bytes_fed;
    }
    return rv;
}

apr_status_t h2_c1_read(h2_session *session)
{
    apr_status_t rv;

    /* H2_IN filter handles all incoming data against the session.
     * We just pull at the filter chain to make it happen */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                  H2_SSSN_MSG(session, "session_read start"));
    rv = read_and_feed(session);

    if (APR_SUCCESS == rv) {
        h2_session_dispatch_event(session, H2_SESSION_EV_INPUT_PENDING, 0, NULL);
    }
    else if (APR_STATUS_IS_EAGAIN(rv)) {
        /* Signal that we have exhausted the input momentarily.
         * This might switch to polling the socket */
        h2_session_dispatch_event(session, H2_SESSION_EV_INPUT_EXHAUSTED, 0, NULL);
    }
    else if (APR_SUCCESS != rv) {
        if (APR_STATUS_IS_ETIMEDOUT(rv)
            || APR_STATUS_IS_ECONNABORTED(rv)
            || APR_STATUS_IS_ECONNRESET(rv)
            || APR_STATUS_IS_EOF(rv)
            || APR_STATUS_IS_EBADF(rv)) {
            /* common status for a client that has left */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, session->c1,
                          H2_SSSN_MSG(session, "input gone"));
        }
        else {
            /* uncommon status, log on INFO so that we see this */
            ap_log_cerror( APLOG_MARK, APLOG_DEBUG, rv, session->c1,
                          H2_SSSN_LOG(APLOGNO(02950), session,
                          "error reading, terminating"));
        }
        h2_session_dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, NULL);
    }

    apr_brigade_cleanup(session->bbtmp);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, session->c1,
                  H2_SSSN_MSG(session, "session_read done"));
    return rv;
}
