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

#include <ap_mpm.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_connection.h>

#include "h2_private.h"
#include "h2_bucket_eoc.h"
#include "h2_config.h"
#include "h2_conn_io.h"
#include "h2_h2.h"
#include "h2_session.h"
#include "h2_util.h"

#define TLS_DATA_MAX          (16*1024) 

/* Calculated like this: assuming MTU 1500 bytes
 * 1500 - 40 (IP) - 20 (TCP) - 40 (TCP options) 
 *      - TLS overhead (60-100) 
 * ~= 1300 bytes */
#define WRITE_SIZE_INITIAL    1300
/* Calculated like this: max TLS record size 16*1024
 *   - 40 (IP) - 20 (TCP) - 40 (TCP options) 
 *    - TLS overhead (60-100) 
 * which seems to create less TCP packets overall
 */
#define WRITE_SIZE_MAX        (TLS_DATA_MAX - 100) 

#define WRITE_BUFFER_SIZE     (8*WRITE_SIZE_MAX)

apr_status_t h2_conn_io_init(h2_conn_io *io, conn_rec *c, 
                             const h2_config *cfg, 
                             apr_pool_t *pool)
{
    io->connection         = c;
    io->output             = apr_brigade_create(pool, c->bucket_alloc);
    io->buflen             = 0;
    io->is_tls             = h2_h2_is_tls(c);
    io->buffer_output      = io->is_tls;
    
    if (io->buffer_output) {
        io->bufsize = WRITE_BUFFER_SIZE;
        io->buffer = apr_pcalloc(pool, io->bufsize);
    }
    else {
        io->bufsize = 0;
    }
    
    if (io->is_tls) {
        /* That is where we start with, 
         * see https://issues.apache.org/jira/browse/TS-2503 */
        io->warmup_size    = h2_config_geti64(cfg, H2_CONF_TLS_WARMUP_SIZE);
        io->cooldown_usecs = (h2_config_geti(cfg, H2_CONF_TLS_COOLDOWN_SECS) 
                              * APR_USEC_PER_SEC);
        io->write_size     = WRITE_SIZE_INITIAL; 
    }
    else {
        io->warmup_size    = 0;
        io->cooldown_usecs = 0;
        io->write_size     = io->bufsize;
    }

    if (APLOGctrace1(c)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, io->connection,
                      "h2_conn_io(%ld): init, buffering=%d, warmup_size=%ld, cd_secs=%f",
                      io->connection->id, io->buffer_output, (long)io->warmup_size,
                      ((float)io->cooldown_usecs/APR_USEC_PER_SEC));
    }

    return APR_SUCCESS;
}

int h2_conn_io_is_buffered(h2_conn_io *io)
{
    return io->bufsize > 0;
}

typedef struct {
    conn_rec *c;
    h2_conn_io *io;
} pass_out_ctx;

static apr_status_t pass_out(apr_bucket_brigade *bb, void *ctx) 
{
    pass_out_ctx *pctx = ctx;
    conn_rec *c = pctx->c;
    apr_status_t status;
    apr_off_t bblen;
    
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }
    
    ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, NULL);
    status = apr_brigade_length(bb, 0, &bblen);
    if (status == APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                      "h2_conn_io(%ld): pass_out brigade %ld bytes",
                      c->id, (long)bblen);
        status = ap_pass_brigade(c->output_filters, bb);
        if (status == APR_SUCCESS && pctx->io) {
            pctx->io->bytes_written += (apr_size_t)bblen;
            pctx->io->last_write = apr_time_now();
        }
    }
    apr_brigade_cleanup(bb);
    return status;
}

/* Bring the current buffer content into the output brigade, appropriately
 * chunked.
 */
static apr_status_t bucketeer_buffer(h2_conn_io *io)
{
    const char *data = io->buffer;
    apr_size_t remaining = io->buflen;
    apr_bucket *b;
    int bcount, i;

    if (io->write_size > WRITE_SIZE_INITIAL 
        && (io->cooldown_usecs > 0)
        && (apr_time_now() - io->last_write) >= io->cooldown_usecs) {
        /* long time not written, reset write size */
        io->write_size = WRITE_SIZE_INITIAL;
        io->bytes_written = 0;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, io->connection,
                      "h2_conn_io(%ld): timeout write size reset to %ld", 
                      (long)io->connection->id, (long)io->write_size);
    }
    else if (io->write_size < WRITE_SIZE_MAX 
             && io->bytes_written >= io->warmup_size) {
        /* connection is hot, use max size */
        io->write_size = WRITE_SIZE_MAX;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, io->connection,
                      "h2_conn_io(%ld): threshold reached, write size now %ld", 
                      (long)io->connection->id, (long)io->write_size);
    }
    
    bcount = (int)(remaining / io->write_size);
    for (i = 0; i < bcount; ++i) {
        b = apr_bucket_transient_create(data, io->write_size, 
                                        io->output->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(io->output, b);
        data += io->write_size;
        remaining -= io->write_size;
    }
    
    if (remaining > 0) {
        b = apr_bucket_transient_create(data, remaining, 
                                        io->output->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(io->output, b);
    }
    return APR_SUCCESS;
}

apr_status_t h2_conn_io_write(h2_conn_io *io, 
                              const char *buf, size_t length)
{
    apr_status_t status = APR_SUCCESS;
    pass_out_ctx ctx;
    
    ctx.c = io->connection;
    ctx.io = io;
    io->unflushed = 1;
    if (io->bufsize > 0) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, io->connection,
                      "h2_conn_io: buffering %ld bytes", (long)length);
                      
        if (!APR_BRIGADE_EMPTY(io->output)) {
            status = h2_conn_io_pass(io);
            io->unflushed = 1;
        }
        
        while (length > 0 && (status == APR_SUCCESS)) {
            apr_size_t avail = io->bufsize - io->buflen;
            if (avail <= 0) {
                
                bucketeer_buffer(io);
                status = pass_out(io->output, &ctx);
                io->buflen = 0;
            }
            else if (length > avail) {
                memcpy(io->buffer + io->buflen, buf, avail);
                io->buflen += avail;
                length -= avail;
                buf += avail;
            }
            else {
                memcpy(io->buffer + io->buflen, buf, length);
                io->buflen += length;
                length = 0;
                break;
            }
        }
        
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, status, io->connection,
                      "h2_conn_io: writing %ld bytes to brigade", (long)length);
        status = apr_brigade_write(io->output, pass_out, &ctx, buf, length);
    }
    
    return status;
}

apr_status_t h2_conn_io_writeb(h2_conn_io *io, apr_bucket *b)
{
    APR_BRIGADE_INSERT_TAIL(io->output, b);
    io->unflushed = 1;
    return APR_SUCCESS;
}

apr_status_t h2_conn_io_consider_flush(h2_conn_io *io)
{
    apr_status_t status = APR_SUCCESS;
    
    /* The HTTP/1.1 network output buffer/flush behaviour does not
     * give optimal performance in the HTTP/2 case, as the pattern of
     * buckets (data/eor/eos) is different.
     * As long as we have not found out the "best" way to deal with
     * this, force a flush at least every WRITE_BUFFER_SIZE amount
     * of data.
     */
    if (io->unflushed) {
        apr_off_t len = 0;
        if (!APR_BRIGADE_EMPTY(io->output)) {
            apr_brigade_length(io->output, 0, &len);
        }
        len += io->buflen;
        if (len >= WRITE_BUFFER_SIZE) {
            return h2_conn_io_pass(io);
        }
    }
    return status;
}

static apr_status_t h2_conn_io_flush_int(h2_conn_io *io, int force, int eoc)
{
    if (io->unflushed || force) {
        pass_out_ctx ctx;
        
        if (io->buflen > 0) {
            /* something in the buffer, put it in the output brigade */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, io->connection,
                          "h2_conn_io: flush, flushing %ld bytes", (long)io->buflen);
            bucketeer_buffer(io);
            io->buflen = 0;
        }
        
        if (force) {
            APR_BRIGADE_INSERT_TAIL(io->output,
                                    apr_bucket_flush_create(io->output->bucket_alloc));
        }
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, io->connection,
                      "h2_conn_io: flush");
        /* Send it out */
        io->unflushed = 0;
        
        ctx.c = io->connection;
        ctx.io = eoc? NULL : io;
        return pass_out(io->output, &ctx);
        /* no more access after this, as we might have flushed an EOC bucket
         * that de-allocated us all. */
    }
    return APR_SUCCESS;
}

apr_status_t h2_conn_io_write_eoc(h2_conn_io *io, apr_bucket *b)
{
    APR_BRIGADE_INSERT_TAIL(io->output, b);
    return h2_conn_io_flush_int(io, 1, 1);
}

apr_status_t h2_conn_io_flush(h2_conn_io *io)
{
    return h2_conn_io_flush_int(io, 1, 0);
}

apr_status_t h2_conn_io_pass(h2_conn_io *io)
{
    return h2_conn_io_flush_int(io, 0, 0);
}

