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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_engine_io.c
 *  I/O Functions
 */
                             /* ``MY HACK: This universe.
                                  Just one little problem:
                                  core keeps dumping.''
                                            -- Unknown    */
#include "ssl_private.h"
#include "mod_ssl.h"
#include "mod_ssl_openssl.h"
#include "apr_date.h"

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, proxy_post_handshake,
                                    (conn_rec *c,SSL *ssl),
                                    (c,ssl),OK,DECLINED);

/*  _________________________________________________________________
**
**  I/O Hooks
**  _________________________________________________________________
*/

/* This file is designed to be the bridge between OpenSSL and httpd.
 * However, we really don't expect anyone (let alone ourselves) to
 * remember what is in this file.  So, first, a quick overview.
 *
 * In this file, you will find:
 * - ssl_io_filter_input    (Apache input filter)
 * - ssl_io_filter_output   (Apache output filter)
 *
 * - bio_filter_in_*        (OpenSSL input filter)
 * - bio_filter_out_*       (OpenSSL output filter)
 *
 * The input chain is roughly:
 *
 * ssl_io_filter_input->ssl_io_input_read->SSL_read->...
 * ...->bio_filter_in_read->ap_get_brigade/next-httpd-filter
 *
 * In mortal terminology, we do the following:
 * - Receive a request for data to the SSL input filter
 * - Call a helper function once we know we should perform a read
 * - Call OpenSSL's SSL_read()
 * - SSL_read() will then call bio_filter_in_read
 * - bio_filter_in_read will then try to fetch data from the next httpd filter
 * - bio_filter_in_read will flatten that data and return it to SSL_read
 * - SSL_read will then decrypt the data
 * - ssl_io_input_read will then receive decrypted data as a char* and
 *   ensure that there were no read errors
 * - The char* is placed in a brigade and returned
 *
 * Since connection-level input filters in httpd need to be able to
 * handle AP_MODE_GETLINE calls (namely identifying LF-terminated strings),
 * ssl_io_input_getline which will handle this special case.
 *
 * Due to AP_MODE_GETLINE and AP_MODE_SPECULATIVE, we may sometimes have
 * 'leftover' decoded data which must be setaside for the next read.  That
 * is currently handled by the char_buffer_{read|write} functions.  So,
 * ssl_io_input_read may be able to fulfill reads without invoking
 * SSL_read().
 *
 * Note that the filter context of ssl_io_filter_input and bio_filter_in_*
 * are shared as bio_filter_in_ctx_t.
 *
 * Note that the filter is by choice limited to reading at most
 * AP_IOBUFSIZE (8192 bytes) per call.
 *
 */

/* this custom BIO allows us to hook SSL_write directly into
 * an apr_bucket_brigade and use transient buckets with the SSL
 * malloc-ed buffer, rather than copying into a mem BIO.
 * also allows us to pass the brigade as data is being written
 * rather than buffering up the entire response in the mem BIO.
 *
 * when SSL needs to flush (e.g. SSL_accept()), it will call BIO_flush()
 * which will trigger a call to bio_filter_out_ctrl() -> bio_filter_out_flush().
 * so we only need to flush the output ourselves if we receive an
 * EOS or FLUSH bucket. this was not possible with the mem BIO where we
 * had to flush all over the place not really knowing when it was required
 * to do so.
 */

typedef struct {
    SSL                *pssl;
    BIO                *pbioRead;
    BIO                *pbioWrite;
    ap_filter_t        *pInputFilter;
    ap_filter_t        *pOutputFilter;
    SSLConnRec         *config;
} ssl_filter_ctx_t;

typedef struct {
    ssl_filter_ctx_t *filter_ctx;
    conn_rec *c;
    apr_bucket_brigade *bb;    /* Brigade used as a buffer. */
    apr_status_t rc;
} bio_filter_out_ctx_t;

static bio_filter_out_ctx_t *bio_filter_out_ctx_new(ssl_filter_ctx_t *filter_ctx,
                                                    conn_rec *c)
{
    bio_filter_out_ctx_t *outctx = apr_palloc(c->pool, sizeof(*outctx));

    outctx->filter_ctx = filter_ctx;
    outctx->c = c;
    outctx->bb = apr_brigade_create(c->pool, c->bucket_alloc);

    return outctx;
}

/* Pass an output brigade down the filter stack; returns 1 on success
 * or -1 on failure. */
static int bio_filter_out_pass(bio_filter_out_ctx_t *outctx)
{
    AP_DEBUG_ASSERT(!APR_BRIGADE_EMPTY(outctx->bb));

    outctx->rc = ap_pass_brigade(outctx->filter_ctx->pOutputFilter->next,
                                 outctx->bb);
    /* Fail if the connection was reset: */
    if (outctx->rc == APR_SUCCESS && outctx->c->aborted) {
        outctx->rc = APR_ECONNRESET;
    }
    return (outctx->rc == APR_SUCCESS) ? 1 : -1;
}

/* Send a FLUSH bucket down the output filter stack; returns 1 on
 * success, -1 on failure. */
static int bio_filter_out_flush(BIO *bio)
{
    bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)BIO_get_data(bio);
    apr_bucket *e;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, outctx->c,
                  "bio_filter_out_write: flush");

    AP_DEBUG_ASSERT(APR_BRIGADE_EMPTY(outctx->bb));

    e = apr_bucket_flush_create(outctx->bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(outctx->bb, e);

    return bio_filter_out_pass(outctx);
}

static int bio_filter_create(BIO *bio)
{
    BIO_set_shutdown(bio, 1);
    BIO_set_init(bio, 1);
#if MODSSL_USE_OPENSSL_PRE_1_1_API
    /* No setter method for OpenSSL 1.1.0 available,
     * but I can't find any functional use of the
     * "num" field there either.
     */
    bio->num = -1;
#endif
    BIO_set_data(bio, NULL);

    return 1;
}

static int bio_filter_destroy(BIO *bio)
{
    if (bio == NULL) {
        return 0;
    }

    /* nothing to free here.
     * apache will destroy the bucket brigade for us
     */
    return 1;
}

static int bio_filter_out_read(BIO *bio, char *out, int outl)
{
    /* this is never called */
    bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)BIO_get_data(bio);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, outctx->c,
                  "BUG: %s() should not be called", "bio_filter_out_read");
    AP_DEBUG_ASSERT(0);
    return -1;
}

static int bio_filter_out_write(BIO *bio, const char *in, int inl)
{
    bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)BIO_get_data(bio);
    apr_bucket *e;
    int need_flush;

    BIO_clear_retry_flags(bio);

    /* Abort early if the client has initiated a renegotiation. */
    if (outctx->filter_ctx->config->reneg_state == RENEG_ABORT) {
        outctx->rc = APR_ECONNABORTED;
        return -1;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, outctx->c,
                  "bio_filter_out_write: %i bytes", inl);

    /* Use a transient bucket for the output data - any downstream
     * filter must setaside if necessary. */
    e = apr_bucket_transient_create(in, inl, outctx->bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(outctx->bb, e);

    /* In theory, OpenSSL should flush as necessary, but it is known
     * not to do so correctly in some cases (< 0.9.8m; see PR 46952),
     * or on the proxy/client side (after ssl23_client_hello(), e.g.
     * ssl/proxy.t test suite).
     *
     * Historically, this flush call was performed only for an SSLv2
     * connection or for a proxy connection.  Calling _out_flush can
     * be expensive in cases where requests/responses are pipelined,
     * so limit the performance impact to handshake time.
     */
#if OPENSSL_VERSION_NUMBER < 0x0009080df
     need_flush = !SSL_is_init_finished(outctx->filter_ctx->pssl);
#else
     need_flush = SSL_in_connect_init(outctx->filter_ctx->pssl);
#endif
    if (need_flush) {
        e = apr_bucket_flush_create(outctx->bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(outctx->bb, e);
    }

    if (bio_filter_out_pass(outctx) < 0) {
        return -1;
    }

    return inl;
}

static long bio_filter_out_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;
    bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)BIO_get_data(bio);

    switch (cmd) {
    case BIO_CTRL_RESET:
    case BIO_CTRL_EOF:
    case BIO_C_SET_BUF_MEM_EOF_RETURN:
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, outctx->c,
                      "output bio: unhandled control %d", cmd);
        ret = 0;
        break;
    case BIO_CTRL_WPENDING:
    case BIO_CTRL_PENDING:
    case BIO_CTRL_INFO:
        ret = 0;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = (long)BIO_get_shutdown(bio);
        break;
      case BIO_CTRL_SET_CLOSE:
        BIO_set_shutdown(bio, (int)num);
        break;
      case BIO_CTRL_FLUSH:
        ret = bio_filter_out_flush(bio);
        break;
      case BIO_CTRL_DUP:
        ret = 1;
        break;
        /* N/A */
      case BIO_C_SET_BUF_MEM:
      case BIO_C_GET_BUF_MEM_PTR:
        /* we don't care */
      case BIO_CTRL_PUSH:
      case BIO_CTRL_POP:
      default:
        ret = 0;
        break;
    }

    return ret;
}

static int bio_filter_out_gets(BIO *bio, char *buf, int size)
{
    /* this is never called */
    bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)BIO_get_data(bio);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, outctx->c,
                  "BUG: %s() should not be called", "bio_filter_out_gets");
    AP_DEBUG_ASSERT(0);
    return -1;
}

static int bio_filter_out_puts(BIO *bio, const char *str)
{
    /* this is never called */
    bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)BIO_get_data(bio);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, outctx->c,
                  "BUG: %s() should not be called", "bio_filter_out_puts");
    AP_DEBUG_ASSERT(0);
    return -1;
}

typedef struct {
    int length;
    char *value;
} char_buffer_t;

typedef struct {
    SSL *ssl;
    BIO *bio_out;
    ap_filter_t *f;
    apr_status_t rc;
    ap_input_mode_t mode;
    apr_read_type_e block;
    apr_bucket_brigade *bb;
    char_buffer_t cbuf;
    apr_pool_t *pool;
    char buffer[AP_IOBUFSIZE];
    ssl_filter_ctx_t *filter_ctx;
} bio_filter_in_ctx_t;

/*
 * this char_buffer api might seem silly, but we don't need to copy
 * any of this data and we need to remember the length.
 */

/* Copy up to INL bytes from the char_buffer BUFFER into IN.  Note
 * that due to the strange way this API is designed/used, the
 * char_buffer object is used to cache a segment of inctx->buffer, and
 * then this function called to copy (part of) that segment to the
 * beginning of inctx->buffer.  So the segments to copy cannot be
 * presumed to be non-overlapping, and memmove must be used. */
static int char_buffer_read(char_buffer_t *buffer, char *in, int inl)
{
    if (!buffer->length) {
        return 0;
    }

    if (buffer->length > inl) {
        /* we have enough to fill the caller's buffer */
        memmove(in, buffer->value, inl);
        buffer->value += inl;
        buffer->length -= inl;
    }
    else {
        /* swallow remainder of the buffer */
        memmove(in, buffer->value, buffer->length);
        inl = buffer->length;
        buffer->value = NULL;
        buffer->length = 0;
    }

    return inl;
}

static int char_buffer_write(char_buffer_t *buffer, char *in, int inl)
{
    buffer->value = in;
    buffer->length = inl;
    return inl;
}

/* This function will read from a brigade and discard the read buckets as it
 * proceeds.  It will read at most *len bytes.
 */
static apr_status_t brigade_consume(apr_bucket_brigade *bb,
                                    apr_read_type_e block,
                                    char *c, apr_size_t *len)
{
    apr_size_t actual = 0;
    apr_status_t status = APR_SUCCESS;

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *b = APR_BRIGADE_FIRST(bb);
        const char *str;
        apr_size_t str_len;
        apr_size_t consume;

        /* Justin points out this is an http-ism that might
         * not fit if brigade_consume is added to APR.  Perhaps
         * apr_bucket_read(eos_bucket) should return APR_EOF?
         * Then this becomes mainline instead of a one-off.
         */
        if (APR_BUCKET_IS_EOS(b)) {
            status = APR_EOF;
            break;
        }

        /* The reason I'm not offering brigade_consume yet
         * across to apr-util is that the following call
         * illustrates how borked that API really is.  For
         * this sort of case (caller provided buffer) it
         * would be much more trivial for apr_bucket_consume
         * to do all the work that follows, based on the
         * particular characteristics of the bucket we are
         * consuming here.
         */
        status = apr_bucket_read(b, &str, &str_len, block);

        if (status != APR_SUCCESS) {
            if (APR_STATUS_IS_EOF(status)) {
                /* This stream bucket was consumed */
                apr_bucket_delete(b);
                continue;
            }
            break;
        }

        if (str_len > 0) {
            /* Do not block once some data has been consumed */
            block = APR_NONBLOCK_READ;

            /* Assure we don't overflow. */
            consume = (str_len + actual > *len) ? *len - actual : str_len;

            memcpy(c, str, consume);

            c += consume;
            actual += consume;

            if (consume >= b->length) {
                /* This physical bucket was consumed */
                apr_bucket_delete(b);
            }
            else {
                /* Only part of this physical bucket was consumed */
                b->start += consume;
                b->length -= consume;
            }
        }
        else if (b->length == 0) {
            apr_bucket_delete(b);
        }

        /* This could probably be actual == *len, but be safe from stray
         * photons. */
        if (actual >= *len) {
            break;
        }
    }

    *len = actual;
    return status;
}

/*
 * this is the function called by SSL_read()
 */
static int bio_filter_in_read(BIO *bio, char *in, int inlen)
{
    apr_size_t inl = inlen;
    bio_filter_in_ctx_t *inctx = (bio_filter_in_ctx_t *)BIO_get_data(bio);
    apr_read_type_e block = inctx->block;

    inctx->rc = APR_SUCCESS;

    /* OpenSSL catches this case, so should we. */
    if (!in)
        return 0;

    BIO_clear_retry_flags(bio);

    /* Abort early if the client has initiated a renegotiation. */
    if (inctx->filter_ctx->config->reneg_state == RENEG_ABORT) {
        inctx->rc = APR_ECONNABORTED;
        return -1;
    }

    if (!inctx->bb) {
        inctx->rc = APR_EOF;
        return -1;
    }

    if (APR_BRIGADE_EMPTY(inctx->bb)) {

        inctx->rc = ap_get_brigade(inctx->f->next, inctx->bb,
                                   AP_MODE_READBYTES, block,
                                   inl);

        /* If the read returns EAGAIN or success with an empty
         * brigade, return an error after setting the retry flag;
         * SSL_read() will then return -1, and SSL_get_error() will
         * indicate SSL_ERROR_WANT_READ. */
        if (APR_STATUS_IS_EAGAIN(inctx->rc) || APR_STATUS_IS_EINTR(inctx->rc)
               || (inctx->rc == APR_SUCCESS && APR_BRIGADE_EMPTY(inctx->bb))) {
            BIO_set_retry_read(bio);
            return -1;
        }

        if (block == APR_BLOCK_READ 
            && APR_STATUS_IS_TIMEUP(inctx->rc)
            && APR_BRIGADE_EMPTY(inctx->bb)) {
            /* don't give up, just return the timeout */
            return -1;
        }
        if (inctx->rc != APR_SUCCESS) {
            /* Unexpected errors discard the brigade */
            apr_brigade_cleanup(inctx->bb);
            inctx->bb = NULL;
            return -1;
        }
    }

    inctx->rc = brigade_consume(inctx->bb, block, in, &inl);

    if (inctx->rc == APR_SUCCESS) {
        return (int)inl;
    }

    if (APR_STATUS_IS_EAGAIN(inctx->rc)
            || APR_STATUS_IS_EINTR(inctx->rc)) {
        BIO_set_retry_read(bio);
        return (int)inl;
    }

    /* Unexpected errors and APR_EOF clean out the brigade.
     * Subsequent calls will return APR_EOF.
     */
    apr_brigade_cleanup(inctx->bb);
    inctx->bb = NULL;

    if (APR_STATUS_IS_EOF(inctx->rc) && inl) {
        /* Provide the results of this read pass,
         * without resetting the BIO retry_read flag
         */
        return (int)inl;
    }

    return -1;
}

static int bio_filter_in_write(BIO *bio, const char *in, int inl)
{
    bio_filter_in_ctx_t *inctx = (bio_filter_in_ctx_t *)BIO_get_data(bio);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, inctx->f->c,
                  "BUG: %s() should not be called", "bio_filter_in_write");
    AP_DEBUG_ASSERT(0);
    return -1;
}

static int bio_filter_in_puts(BIO *bio, const char *str)
{
    bio_filter_in_ctx_t *inctx = (bio_filter_in_ctx_t *)BIO_get_data(bio);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, inctx->f->c,
                  "BUG: %s() should not be called", "bio_filter_in_puts");
    AP_DEBUG_ASSERT(0);
    return -1;
}

static int bio_filter_in_gets(BIO *bio, char *buf, int size)
{
    bio_filter_in_ctx_t *inctx = (bio_filter_in_ctx_t *)BIO_get_data(bio);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, inctx->f->c,
                  "BUG: %s() should not be called", "bio_filter_in_gets");
    AP_DEBUG_ASSERT(0);
    return -1;
}

static long bio_filter_in_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    bio_filter_in_ctx_t *inctx = (bio_filter_in_ctx_t *)BIO_get_data(bio);
    switch (cmd) {
#ifdef BIO_CTRL_EOF
    case BIO_CTRL_EOF:
        return inctx->rc == APR_EOF;
#endif
    default:
        break;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, inctx->f->c,
                  "BUG: bio_filter_in_ctrl() should not be called with cmd=%i",
                  cmd);
    return 0;
}

#if MODSSL_USE_OPENSSL_PRE_1_1_API
        
static BIO_METHOD bio_filter_out_method = {
    BIO_TYPE_MEM,
    "APR output filter",
    bio_filter_out_write,
    bio_filter_out_read,     /* read is never called */
    bio_filter_out_puts,     /* puts is never called */
    bio_filter_out_gets,     /* gets is never called */
    bio_filter_out_ctrl,
    bio_filter_create,
    bio_filter_destroy,
    NULL
};

static BIO_METHOD bio_filter_in_method = {
    BIO_TYPE_MEM,
    "APR input filter",
    bio_filter_in_write,        /* write is never called */
    bio_filter_in_read,
    bio_filter_in_puts,         /* puts is never called */
    bio_filter_in_gets,         /* gets is never called */
    bio_filter_in_ctrl,         /* ctrl is called for EOF check */
    bio_filter_create,
    bio_filter_destroy,
    NULL
};

#else

static BIO_METHOD *bio_filter_out_method = NULL;
static BIO_METHOD *bio_filter_in_method = NULL;

void init_bio_methods(void)
{
    bio_filter_out_method = BIO_meth_new(BIO_TYPE_MEM, "APR output filter");
    BIO_meth_set_write(bio_filter_out_method, &bio_filter_out_write);
    BIO_meth_set_read(bio_filter_out_method, &bio_filter_out_read); /* read is never called */
    BIO_meth_set_puts(bio_filter_out_method, &bio_filter_out_puts); /* puts is never called */
    BIO_meth_set_gets(bio_filter_out_method, &bio_filter_out_gets); /* gets is never called */
    BIO_meth_set_ctrl(bio_filter_out_method, &bio_filter_out_ctrl);
    BIO_meth_set_create(bio_filter_out_method, &bio_filter_create);
    BIO_meth_set_destroy(bio_filter_out_method, &bio_filter_destroy);

    bio_filter_in_method = BIO_meth_new(BIO_TYPE_MEM, "APR input filter");
    BIO_meth_set_write(bio_filter_in_method, &bio_filter_in_write); /* write is never called */
    BIO_meth_set_read(bio_filter_in_method, &bio_filter_in_read);
    BIO_meth_set_puts(bio_filter_in_method, &bio_filter_in_puts);   /* puts is never called */
    BIO_meth_set_gets(bio_filter_in_method, &bio_filter_in_gets);   /* gets is never called */
    BIO_meth_set_ctrl(bio_filter_in_method, &bio_filter_in_ctrl);   /* ctrl is never called */
    BIO_meth_set_create(bio_filter_in_method, &bio_filter_create);
    BIO_meth_set_destroy(bio_filter_in_method, &bio_filter_destroy);
}

void free_bio_methods(void)
{
    BIO_meth_free(bio_filter_out_method);
    BIO_meth_free(bio_filter_in_method);
}
#endif

static apr_status_t ssl_io_input_read(bio_filter_in_ctx_t *inctx,
                                      char *buf,
                                      apr_size_t *len)
{
    apr_size_t wanted = *len;
    apr_size_t bytes = 0;
    int rc;

    *len = 0;

    /* If we have something leftover from last time, try that first. */
    if ((bytes = char_buffer_read(&inctx->cbuf, buf, wanted))) {
        *len = bytes;
        if (inctx->mode == AP_MODE_SPECULATIVE) {
            /* We want to rollback this read. */
            if (inctx->cbuf.length > 0) {
                inctx->cbuf.value -= bytes;
                inctx->cbuf.length += bytes;
            } else {
                char_buffer_write(&inctx->cbuf, buf, (int)bytes);
            }
            return APR_SUCCESS;
        }
        /* This could probably be *len == wanted, but be safe from stray
         * photons.
         */
        if (*len >= wanted) {
            return APR_SUCCESS;
        }
        if (inctx->mode == AP_MODE_GETLINE) {
            if (memchr(buf, APR_ASCII_LF, *len)) {
                return APR_SUCCESS;
            }
        }
        else {
            /* Down to a nonblock pattern as we have some data already
             */
            inctx->block = APR_NONBLOCK_READ;
        }
    }

    while (1) {

        if (!inctx->filter_ctx->pssl) {
            /* Ensure a non-zero error code is returned */
            if (inctx->rc == APR_SUCCESS) {
                inctx->rc = APR_EGENERAL;
            }
            break;
        }

        /* We rely on SSL_get_error() after the read, which requires an empty
         * error queue before the read in order to work properly.
         */
        ERR_clear_error();

        /* SSL_read may not read because we haven't taken enough data
         * from the stack.  This is where we want to consider all of
         * the blocking and SPECULATIVE semantics
         */
        rc = SSL_read(inctx->filter_ctx->pssl, buf + bytes, wanted - bytes);

        if (rc > 0) {
            *len += rc;
            if (inctx->mode == AP_MODE_SPECULATIVE) {
                /* We want to rollback this read. */
                char_buffer_write(&inctx->cbuf, buf, rc);
            }
            return inctx->rc;
        }
        else /* (rc <= 0) */ {
            int ssl_err;
            conn_rec *c;
            if (rc == 0) {
                /* If EAGAIN, we will loop given a blocking read,
                 * otherwise consider ourselves at EOF.
                 */
                if (APR_STATUS_IS_EAGAIN(inctx->rc)
                        || APR_STATUS_IS_EINTR(inctx->rc)) {
                    /* Already read something, return APR_SUCCESS instead.
                     * On win32 in particular, but perhaps on other kernels,
                     * a blocking call isn't 'always' blocking.
                     */
                    if (*len > 0) {
                        inctx->rc = APR_SUCCESS;
                        break;
                    }
                    if (inctx->block == APR_NONBLOCK_READ) {
                        break;
                    }
                }
                else {
                    if (*len > 0) {
                        inctx->rc = APR_SUCCESS;
                        break;
                    }
                }
            }
            ssl_err = SSL_get_error(inctx->filter_ctx->pssl, rc);
            c = (conn_rec*)SSL_get_app_data(inctx->filter_ctx->pssl);

            if (ssl_err == SSL_ERROR_WANT_READ) {
                /*
                 * If OpenSSL wants to read more, and we were nonblocking,
                 * report as an EAGAIN.  Otherwise loop, pulling more
                 * data from network filter.
                 *
                 * (This is usually the case when the client forces an SSL
                 * renegotiation which is handled implicitly by OpenSSL.)
                 */
                inctx->rc = APR_EAGAIN;

                if (*len > 0) {
                    inctx->rc = APR_SUCCESS;
                    break;
                }
                if (inctx->block == APR_NONBLOCK_READ) {
                    break;
                }
                continue;  /* Blocking and nothing yet?  Try again. */
            }
            else if (ssl_err == SSL_ERROR_SYSCALL) {
                if (APR_STATUS_IS_EAGAIN(inctx->rc)
                        || APR_STATUS_IS_EINTR(inctx->rc)) {
                    /* Already read something, return APR_SUCCESS instead. */
                    if (*len > 0) {
                        inctx->rc = APR_SUCCESS;
                        break;
                    }
                    if (inctx->block == APR_NONBLOCK_READ) {
                        break;
                    }
                    continue;  /* Blocking and nothing yet?  Try again. */
                }
                else if (APR_STATUS_IS_TIMEUP(inctx->rc)) {
                    /* just return it, the calling layer might be fine with it,
                       and we do not want to bloat the log. */
                }
                else {
                    ap_log_cerror(APLOG_MARK, APLOG_INFO, inctx->rc, c, APLOGNO(01991)
                                  "SSL input filter read failed.");
                }
            }
            else if (rc == 0 && ssl_err == SSL_ERROR_ZERO_RETURN) {
                inctx->rc = APR_EOF;
                break;
            }
            else /* if (ssl_err == SSL_ERROR_SSL) */ {
                /*
                 * Log SSL errors and any unexpected conditions.
                 */
                ap_log_cerror(APLOG_MARK, APLOG_INFO, inctx->rc, c, APLOGNO(01992)
                              "SSL library error %d reading data", ssl_err);
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_INFO, mySrvFromConn(c));

            }
            if (rc == 0) {
                inctx->rc = APR_EOF;
                break;
            }
            if (inctx->rc == APR_SUCCESS) {
                inctx->rc = APR_EGENERAL;
            }
            break;
        }
    }
    return inctx->rc;
}

/* Read a line of input from the SSL input layer into buffer BUF of
 * length *LEN; updating *len to reflect the length of the line
 * including the LF character. */
static apr_status_t ssl_io_input_getline(bio_filter_in_ctx_t *inctx,
                                         char *buf,
                                         apr_size_t *len)
{
    const char *pos = NULL;
    apr_status_t status;
    apr_size_t tmplen = *len, buflen = *len, offset = 0;

    *len = 0;

    /*
     * in most cases we get all the headers on the first SSL_read.
     * however, in certain cases SSL_read will only get a partial
     * chunk of the headers, so we try to read until LF is seen.
     */

    while (tmplen > 0) {
        status = ssl_io_input_read(inctx, buf + offset, &tmplen);

        if (status != APR_SUCCESS) {
            if (APR_STATUS_IS_EAGAIN(status) && (*len > 0)) {
                /* Save the part of the line we already got */
                char_buffer_write(&inctx->cbuf, buf, *len);
            }
            return status;
        }

        *len += tmplen;

        if ((pos = memchr(buf, APR_ASCII_LF, *len))) {
            break;
        }

        offset += tmplen;
        tmplen = buflen - offset;
    }

    if (pos) {
        char *value;
        int length;
        apr_size_t bytes = pos - buf;

        bytes += 1;
        value = buf + bytes;
        length = *len - bytes;

        char_buffer_write(&inctx->cbuf, value, length);

        *len = bytes;
    }

    return APR_SUCCESS;
}


static apr_status_t ssl_filter_write(ap_filter_t *f,
                                     const char *data,
                                     apr_size_t len)
{
    ssl_filter_ctx_t *filter_ctx = f->ctx;
    bio_filter_out_ctx_t *outctx;
    int res;

    /* write SSL */
    if (filter_ctx->pssl == NULL) {
        return APR_EGENERAL;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, f->c,
                  "ssl_filter_write: %"APR_SIZE_T_FMT" bytes", len);

    /* We rely on SSL_get_error() after the write, which requires an empty error
     * queue before the write in order to work properly.
     */
    ERR_clear_error();

    outctx = (bio_filter_out_ctx_t *)BIO_get_data(filter_ctx->pbioWrite);
    res = SSL_write(filter_ctx->pssl, (unsigned char *)data, len);

    if (res < 0) {
        int ssl_err = SSL_get_error(filter_ctx->pssl, res);
        conn_rec *c = (conn_rec*)SSL_get_app_data(outctx->filter_ctx->pssl);

        if (ssl_err == SSL_ERROR_WANT_WRITE) {
            /*
             * If OpenSSL wants to write more, and we were nonblocking,
             * report as an EAGAIN.  Otherwise loop, pushing more
             * data at the network filter.
             *
             * (This is usually the case when the client forces an SSL
             * renegotiation which is handled implicitly by OpenSSL.)
             */
            outctx->rc = APR_EAGAIN;
        }
        else if (ssl_err == SSL_ERROR_WANT_READ) {
            /*
             * If OpenSSL wants to read during write, and we were
             * nonblocking, set the sense explicitly to read and
             * report as an EAGAIN.
             *
             * (This is usually the case when the client forces an SSL
             * renegotiation which is handled implicitly by OpenSSL.)
             */
            outctx->c->cs->sense = CONN_SENSE_WANT_READ;
            outctx->rc = APR_EAGAIN;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, outctx->c,
                          "Want read during nonblocking write");
        }
        else if (ssl_err == SSL_ERROR_SYSCALL) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, outctx->rc, c, APLOGNO(01993)
                          "SSL output filter write failed.");
        }
        else /* if (ssl_err == SSL_ERROR_SSL) */ {
            /*
             * Log SSL errors
             */
            ap_log_cerror(APLOG_MARK, APLOG_INFO, outctx->rc, c, APLOGNO(01994)
                          "SSL library error %d writing data", ssl_err);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_INFO, mySrvFromConn(c));
        }
        if (outctx->rc == APR_SUCCESS) {
            outctx->rc = APR_EGENERAL;
        }
    }
    else if ((apr_size_t)res != len) {
        conn_rec *c = f->c;
        char *reason = "reason unknown";

        /* XXX: probably a better way to determine this */
        if (SSL_total_renegotiations(filter_ctx->pssl)) {
            reason = "likely due to failed renegotiation";
        }

        ap_log_cerror(APLOG_MARK, APLOG_INFO, outctx->rc, c, APLOGNO(01995)
                      "failed to write %" APR_SSIZE_T_FMT
                      " of %" APR_SIZE_T_FMT " bytes (%s)",
                      len - (apr_size_t)res, len, reason);

        outctx->rc = APR_EGENERAL;
    }
    return outctx->rc;
}

/* Just use a simple request.  Any request will work for this, because
 * we use a flag in the conn_rec->conn_vector now.  The fake request just
 * gets the request back to the Apache core so that a response can be sent.
 * Since we use an HTTP/1.x request, we also have to inject the empty line
 * that terminates the headers, or the core will read more data from the
 * socket.
 */
#define HTTP_ON_HTTPS_PORT \
    "GET / HTTP/1.0" CRLF

#define HTTP_ON_HTTPS_PORT_BUCKET(alloc) \
    apr_bucket_immortal_create(HTTP_ON_HTTPS_PORT, \
                               sizeof(HTTP_ON_HTTPS_PORT) - 1, \
                               alloc)

/* Custom apr_status_t error code, used when a plain HTTP request is
 * received on an SSL port. */
#define MODSSL_ERROR_HTTP_ON_HTTPS (APR_OS_START_USERERR + 0)

/* Custom apr_status_t error code, used when the proxy cannot
 * establish an outgoing SSL connection. */
#define MODSSL_ERROR_BAD_GATEWAY (APR_OS_START_USERERR + 1)

static void ssl_io_filter_disable(SSLConnRec *sslconn,
                                  bio_filter_in_ctx_t *inctx)
{
    SSL_free(inctx->ssl);
    sslconn->ssl = NULL;
    inctx->ssl = NULL;
    inctx->filter_ctx->pssl = NULL;
}

static apr_status_t ssl_io_filter_error(bio_filter_in_ctx_t *inctx,
                                        apr_bucket_brigade *bb,
                                        apr_status_t status,
                                        int is_init)
{
    ap_filter_t *f = inctx->f;
    SSLConnRec *sslconn = myConnConfig(f->c);
    apr_bucket *bucket;
    int send_eos = 1;

    switch (status) {
    case MODSSL_ERROR_HTTP_ON_HTTPS:
            /* log the situation */
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, f->c, APLOGNO(01996)
                         "SSL handshake failed: HTTP spoken on HTTPS port; "
                         "trying to send HTML error page");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_INFO, sslconn->server);

            ssl_io_filter_disable(sslconn, inctx);
            f->c->keepalive = AP_CONN_CLOSE;
            if (is_init) {
                sslconn->non_ssl_request = NON_SSL_SEND_REQLINE;
                return APR_EGENERAL;
            }
            sslconn->non_ssl_request = NON_SSL_SEND_HDR_SEP;

            /* fake the request line */
            bucket = HTTP_ON_HTTPS_PORT_BUCKET(f->c->bucket_alloc);
            send_eos = 0;
            break;

    case MODSSL_ERROR_BAD_GATEWAY:
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, f->c, APLOGNO(01997)
                      "SSL handshake failed: sending 502");
        f->c->aborted = 1;
        return APR_EGENERAL;

    default:
        return status;
    }

    APR_BRIGADE_INSERT_TAIL(bb, bucket);
    if (send_eos) {
        bucket = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
    }
    return APR_SUCCESS;
}

static const char ssl_io_filter[] = "SSL/TLS Filter";
static const char ssl_io_buffer[] = "SSL/TLS Buffer";
static const char ssl_io_coalesce[] = "SSL/TLS Coalescing Filter";

/*
 *  Close the SSL part of the socket connection
 *  (called immediately _before_ the socket is closed)
 *  or called with
 */
static void ssl_filter_io_shutdown(ssl_filter_ctx_t *filter_ctx,
                                   conn_rec *c, int abortive)
{
    SSL *ssl = filter_ctx->pssl;
    const char *type = "";
    SSLConnRec *sslconn = myConnConfig(c);
    int shutdown_type;
    int loglevel = APLOG_DEBUG;
    const char *logno;

    if (!ssl) {
        return;
    }

    /*
     * Now close the SSL layer of the connection. We've to take
     * the TLSv1 standard into account here:
     *
     * | 7.2.1. Closure alerts
     * |
     * | The client and the server must share knowledge that the connection is
     * | ending in order to avoid a truncation attack. Either party may
     * | initiate the exchange of closing messages.
     * |
     * | close_notify
     * |     This message notifies the recipient that the sender will not send
     * |     any more messages on this connection. The session becomes
     * |     unresumable if any connection is terminated without proper
     * |     close_notify messages with level equal to warning.
     * |
     * | Either party may initiate a close by sending a close_notify alert.
     * | Any data received after a closure alert is ignored.
     * |
     * | Each party is required to send a close_notify alert before closing
     * | the write side of the connection. It is required that the other party
     * | respond with a close_notify alert of its own and close down the
     * | connection immediately, discarding any pending writes. It is not
     * | required for the initiator of the close to wait for the responding
     * | close_notify alert before closing the read side of the connection.
     *
     * This means we've to send a close notify message, but haven't to wait
     * for the close notify of the client. Actually we cannot wait for the
     * close notify of the client because some clients (including Netscape
     * 4.x) don't send one, so we would hang.
     */

    /*
     * exchange close notify messages, but allow the user
     * to force the type of handshake via SetEnvIf directive
     */
    if (abortive) {
        shutdown_type = SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN;
        type = "abortive";
        logno = APLOGNO(01998);
        loglevel = APLOG_INFO;
    }
    else switch (sslconn->shutdown_type) {
      case SSL_SHUTDOWN_TYPE_UNCLEAN:
        /* perform no close notify handshake at all
           (violates the SSL/TLS standard!) */
        shutdown_type = SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN;
        type = "unclean";
        logno = APLOGNO(01999);
        break;
      case SSL_SHUTDOWN_TYPE_ACCURATE:
        /* send close notify and wait for clients close notify
           (standard compliant, but usually causes connection hangs) */
        shutdown_type = 0;
        type = "accurate";
        logno = APLOGNO(02000);
        break;
      default:
        /*
         * case SSL_SHUTDOWN_TYPE_UNSET:
         * case SSL_SHUTDOWN_TYPE_STANDARD:
         */
        /* send close notify, but don't wait for clients close notify
           (standard compliant and safe, so it's the DEFAULT!) */
        shutdown_type = SSL_RECEIVED_SHUTDOWN;
        type = "standard";
        logno = APLOGNO(02001);
        break;
    }

    SSL_set_shutdown(ssl, shutdown_type);
    modssl_smart_shutdown(ssl);

    /* and finally log the fact that we've closed the connection */
    if (APLOG_CS_IS_LEVEL(c, mySrvFromConn(c), loglevel)) {
        /* Intentional no APLOGNO */
        /* logno provides APLOGNO */
        ap_log_cserror(APLOG_MARK, loglevel, 0, c, mySrvFromConn(c),
                       "%sConnection closed to child %ld with %s shutdown "
                       "(server %s)",
                       logno, c->id, type,
                       ssl_util_vhostid(c->pool, mySrvFromConn(c)));
    }

    /* deallocate the SSL connection */
    if (sslconn->client_cert) {
        X509_free(sslconn->client_cert);
        sslconn->client_cert = NULL;
    }
    SSL_free(ssl);
    sslconn->ssl = NULL;
    filter_ctx->pssl = NULL; /* so filters know we've been shutdown */

    if (abortive) {
        /* prevent any further I/O */
        c->aborted = 1;
    }
}

static apr_status_t ssl_io_filter_cleanup(void *data)
{
    ssl_filter_ctx_t *filter_ctx = data;

    if (filter_ctx->pssl) {
        conn_rec *c = (conn_rec *)SSL_get_app_data(filter_ctx->pssl);
        SSLConnRec *sslconn = myConnConfig(c);

        SSL_free(filter_ctx->pssl);
        sslconn->ssl = filter_ctx->pssl = NULL;
    }

    return APR_SUCCESS;
}

/*
 * The hook is NOT registered with ap_hook_process_connection. Instead, it is
 * called manually from the churn () before it tries to read any data.
 * There is some problem if I accept conn_rec *. Still investigating..
 * Adv. if conn_rec * can be accepted is we can hook this function using the
 * ap_hook_process_connection hook.
 */

/* Perform the SSL handshake (whether in client or server mode), if
 * necessary, for the given connection. */
static apr_status_t ssl_io_filter_handshake(ssl_filter_ctx_t *filter_ctx)
{
    conn_rec *c         = (conn_rec *)SSL_get_app_data(filter_ctx->pssl);
    SSLConnRec *sslconn = myConnConfig(c);
    SSLSrvConfigRec *sc;
    X509 *cert;
    int n;
    int ssl_err;
    long verify_result;
    server_rec *server;

    if (SSL_is_init_finished(filter_ctx->pssl)) {
        return APR_SUCCESS;
    }

    server = sslconn->server;
    if (c->outgoing) {
#ifdef HAVE_TLSEXT
        apr_ipsubnet_t *ip;
#ifdef HAVE_TLS_ALPN
        const char *alpn_note;
        apr_array_header_t *alpn_proposed = NULL;
        int alpn_empty_ok = 1;
#endif
#endif
        const char *hostname_note = apr_table_get(c->notes,
                                                  "proxy-request-hostname");
        BOOL proxy_ssl_check_peer_ok = TRUE;
        int post_handshake_rc = OK;
        SSLDirConfigRec *dc;

        dc = sslconn->dc;
        sc = mySrvConfig(server);

#ifdef HAVE_TLSEXT
#ifdef HAVE_TLS_ALPN
        alpn_note = apr_table_get(c->notes, "proxy-request-alpn-protos");
        if (alpn_note) {
            char *protos, *s, *p, *last, *proto;
            apr_size_t len;

            /* Transform the note into a protocol formatted byte array:
             * (len-byte proto-char+)*
             * We need the remote server to agree on one of these, unless 'http/1.1'
             * is also among our proposals. Because pre-ALPN remotes will speak this.
             */
            alpn_proposed = apr_array_make(c->pool, 3, sizeof(const char*));
            alpn_empty_ok = 0;
            s = protos = apr_pcalloc(c->pool, strlen(alpn_note)+1);
            p = apr_pstrdup(c->pool, alpn_note);
            while ((p = apr_strtok(p, ", ", &last))) {
                len = last - p - (*last? 1 : 0); 
                if (len > 255) {
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(03309)
                                  "ALPN proxy protocol identifier too long: %s",
                                  p);
                    ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, server);
                    return APR_EGENERAL;
                }
                proto = apr_pstrndup(c->pool, p, len);
                APR_ARRAY_PUSH(alpn_proposed, const char*) = proto;
                if (!strcmp("http/1.1", proto)) {
                    alpn_empty_ok = 1;
                }
                *s++ = (unsigned char)len;
                while (len--) {
                    *s++ = *p++;
                }
                p = NULL;
            }
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, 
                          "setting alpn protos from '%s', protolen=%d", 
                          alpn_note, (int)(s - protos));
            if (protos != s && SSL_set_alpn_protos(filter_ctx->pssl, 
                                                   (unsigned char *)protos, 
                                                   s - protos)) {
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c, APLOGNO(03310)
                              "error setting alpn protos from '%s'", alpn_note);
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_WARNING, server);
                /* If ALPN was requested and we cannot do it, we must fail */
                return MODSSL_ERROR_BAD_GATEWAY;
            }
        }
#endif /* defined HAVE_TLS_ALPN */
        /*
         * Enable SNI for backend requests. Make sure we don't do it for
         * pure SSLv3 connections, and also prevent IP addresses
         * from being included in the SNI extension. (OpenSSL would simply
         * pass them on, but RFC 6066 is quite clear on this: "Literal
         * IPv4 and IPv6 addresses are not permitted".)
         */
        if (hostname_note &&
#ifndef OPENSSL_NO_SSL3
            dc->proxy->protocol != SSL_PROTOCOL_SSLV3 &&
#endif
            apr_ipsubnet_create(&ip, hostname_note, NULL,
                                c->pool) != APR_SUCCESS) {
            if (SSL_set_tlsext_host_name(filter_ctx->pssl, hostname_note)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c,
                              "SNI extension for SSL Proxy request set to '%s'",
                              hostname_note);
            } else {
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c, APLOGNO(02002)
                              "Failed to set SNI extension for SSL Proxy "
                              "request to '%s'", hostname_note);
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_WARNING, server);
            }
        }
#endif /* defined HAVE_TLSEXT */

        if ((n = SSL_connect(filter_ctx->pssl)) <= 0) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(02003)
                          "SSL Proxy connect failed");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_INFO, server);
            /* ensure that the SSL structures etc are freed, etc: */
            ssl_filter_io_shutdown(filter_ctx, c, 1);
            apr_table_setn(c->notes, "SSL_connect_rv", "err");
            return MODSSL_ERROR_BAD_GATEWAY;
        }

        cert = SSL_get_peer_certificate(filter_ctx->pssl);

        if (dc->proxy->ssl_check_peer_expire != FALSE) {
            if (!cert
                || (X509_cmp_current_time(
                     X509_get_notBefore(cert)) >= 0)
                || (X509_cmp_current_time(
                     X509_get_notAfter(cert)) <= 0)) {
                proxy_ssl_check_peer_ok = FALSE;
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(02004)
                              "SSL Proxy: Peer certificate is expired");
            }
        }
        if ((dc->proxy->ssl_check_peer_name != FALSE) &&
            ((dc->proxy->ssl_check_peer_cn != FALSE) ||
             (dc->proxy->ssl_check_peer_name == TRUE)) &&
            hostname_note) {
            if (!cert
                || modssl_X509_match_name(c->pool, cert, hostname_note,
                                          TRUE, server) == FALSE) {
                proxy_ssl_check_peer_ok = FALSE;
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(02411)
                              "SSL Proxy: Peer certificate does not match "
                              "for hostname %s", hostname_note);
            }
        }
        else if ((dc->proxy->ssl_check_peer_cn == TRUE) &&
            hostname_note) {
            const char *hostname;
            int match = 0;

            hostname = ssl_var_lookup(NULL, server, c, NULL,
                                      "SSL_CLIENT_S_DN_CN");

            /* Do string match or simplest wildcard match if that
             * fails. */
            match = strcasecmp(hostname, hostname_note) == 0;
            if (!match && strncmp(hostname, "*.", 2) == 0) {
                const char *p = ap_strchr_c(hostname_note, '.');
                
                match = p && strcasecmp(p, hostname + 1) == 0;
            }

            if (!match) {
                proxy_ssl_check_peer_ok = FALSE;
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(02005)
                              "SSL Proxy: Peer certificate CN mismatch:"
                              " Certificate CN: %s Requested hostname: %s",
                              hostname, hostname_note);
            }
        }

#ifdef HAVE_TLS_ALPN
        /* If we proposed ALPN protocol(s), we need to check if the server
         * agreed to one of them. While <https://www.rfc-editor.org/rfc/rfc7301.txt>
         * chapter 3.2 says the server SHALL error the handshake in such a case,
         * the reality is that some servers fall back to their default, e.g. http/1.1.
         * (we also do this right now)
         * We need to treat this as an error for security reasons.
         */
        if (alpn_proposed && alpn_proposed->nelts > 0) {
            const char *selected;
            unsigned int slen;

            SSL_get0_alpn_selected(filter_ctx->pssl, (const unsigned char**)&selected, &slen);
            if (!selected || !slen) {
                /* No ALPN selection reported by the remote server. This could mean
                 * it does not support ALPN (old server) or that it does not support
                 * any of our proposals (Apache itself up to 2.4.48 at least did that). */
               if (!alpn_empty_ok) {
                    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(10273)
                                  "SSL Proxy: Peer did not select any of our ALPN protocols [%s].",
                                  alpn_note);
                    proxy_ssl_check_peer_ok = FALSE;
               }
            }
            else {
                const char *proto;
                int i, found = 0;
                for (i = 0; !found && i < alpn_proposed->nelts; ++i) {
                    proto = APR_ARRAY_IDX(alpn_proposed, i, const char *);
                    found = !strncmp(selected, proto, slen);
                }
                if (!found) {
                    /* From a conforming peer, this should never happen,
                     * but life always finds a way... */
                    proto = apr_pstrndup(c->pool, selected, slen);
                    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(10274)
                                  "SSL Proxy: Peer proposed ALPN protocol %s which is none "
                                  "of our proposals [%s].", proto, alpn_note);
                    proxy_ssl_check_peer_ok = FALSE;
                }
            }
        }
#endif

        if (proxy_ssl_check_peer_ok == TRUE) {
            /* another chance to fail */
            post_handshake_rc = ssl_run_proxy_post_handshake(c, filter_ctx->pssl);
        }

        if (cert) {
            X509_free(cert);
        }

        if (proxy_ssl_check_peer_ok != TRUE
            || (post_handshake_rc != OK && post_handshake_rc != DECLINED)) {
            /* ensure that the SSL structures etc are freed, etc: */
            ssl_filter_io_shutdown(filter_ctx, c, 1);
            apr_table_setn(c->notes, "SSL_connect_rv", "err");
            return MODSSL_ERROR_BAD_GATEWAY;
        }

        apr_table_setn(c->notes, "SSL_connect_rv", "ok");
        return APR_SUCCESS;
    }

    /* We rely on SSL_get_error() after the accept, which requires an empty
     * error queue before the accept in order to work properly.
     */
    ERR_clear_error();

    if ((n = SSL_accept(filter_ctx->pssl)) <= 0) {
        bio_filter_in_ctx_t *inctx = (bio_filter_in_ctx_t *)
                                     BIO_get_data(filter_ctx->pbioRead);
        bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)
                                       BIO_get_data(filter_ctx->pbioWrite);
        apr_status_t rc = inctx->rc ? inctx->rc : outctx->rc ;
        ssl_err = SSL_get_error(filter_ctx->pssl, n);

        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            /*
             * The case where the connection was closed before any data
             * was transferred. That's not a real error and can occur
             * sporadically with some clients.
             */
            ap_log_cerror(APLOG_MARK, APLOG_INFO, rc, c, APLOGNO(02006)
                         "SSL handshake stopped: connection was closed");
        }
        else if (ssl_err == SSL_ERROR_WANT_READ) {
            /*
             * This is in addition to what was present earlier. It is
             * borrowed from openssl_state_machine.c [mod_tls].
             * TBD.
             */
            outctx->rc = APR_EAGAIN;
            return APR_EAGAIN;
        }
        else if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_SSL &&
                 ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST) {
            /*
             * The case where OpenSSL has recognized a HTTP request:
             * This means the client speaks plain HTTP on our HTTPS port.
             * ssl_io_filter_error will disable the ssl filters when it
             * sees this status code.
             */
            return MODSSL_ERROR_HTTP_ON_HTTPS;
        }
        else if (ssl_err == SSL_ERROR_SYSCALL) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rc, c, APLOGNO(02007)
                          "SSL handshake interrupted by system "
                          "[Hint: Stop button pressed in browser?!]");
        }
        else /* if (ssl_err == SSL_ERROR_SSL) */ {
            /*
             * Log SSL errors and any unexpected conditions.
             */
            ap_log_cerror(APLOG_MARK, APLOG_INFO, rc, c, APLOGNO(02008)
                          "SSL library error %d in handshake "
                          "(server %s)", ssl_err,
                          ssl_util_vhostid(c->pool, server));
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_INFO, server);

        }
        if (inctx->rc == APR_SUCCESS) {
            inctx->rc = APR_EGENERAL;
        }

        ssl_filter_io_shutdown(filter_ctx, c, 1);
        return inctx->rc;
    }
    sc = mySrvConfig(sslconn->server);

    /*
     * Check for failed client authentication
     */
    verify_result = SSL_get_verify_result(filter_ctx->pssl);

    if ((verify_result != X509_V_OK) ||
        sslconn->verify_error)
    {
        if (ssl_verify_error_is_optional(verify_result) &&
            (sc->server->auth.verify_mode == SSL_CVERIFY_OPTIONAL_NO_CA))
        {
            /* leaving this log message as an error for the moment,
             * according to the mod_ssl docs:
             * "level optional_no_ca is actually against the idea
             *  of authentication (but can be used to establish
             * SSL test pages, etc.)"
             * optional_no_ca doesn't appear to work as advertised
             * in 1.x
             */
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(02009)
                          "SSL client authentication failed, "
                          "accepting certificate based on "
                          "\"SSLVerifyClient optional_no_ca\" "
                          "configuration");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_INFO, server);
        }
        else {
            const char *error = sslconn->verify_error ?
                sslconn->verify_error :
                X509_verify_cert_error_string(verify_result);

            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(02010)
                         "SSL client authentication failed: %s",
                         error ? error : "unknown");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_INFO, server);

            ssl_filter_io_shutdown(filter_ctx, c, 1);
            return APR_ECONNABORTED;
        }
    }

    /*
     * Remember the peer certificate's DN
     */
    if ((cert = SSL_get_peer_certificate(filter_ctx->pssl))) {
        if (sslconn->client_cert) {
            X509_free(sslconn->client_cert);
        }
        sslconn->client_cert = cert;
        sslconn->client_dn = NULL;
    }

    /*
     * Make really sure that when a peer certificate
     * is required we really got one... (be paranoid)
     */
    if ((sc->server->auth.verify_mode == SSL_CVERIFY_REQUIRE) &&
        !sslconn->client_cert)
    {
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(02011)
                      "No acceptable peer certificate available");

        ssl_filter_io_shutdown(filter_ctx, c, 1);
        return APR_ECONNABORTED;
    }

    return APR_SUCCESS;
}

static apr_status_t ssl_io_filter_input(ap_filter_t *f,
                                        apr_bucket_brigade *bb,
                                        ap_input_mode_t mode,
                                        apr_read_type_e block,
                                        apr_off_t readbytes)
{
    apr_status_t status;
    bio_filter_in_ctx_t *inctx = f->ctx;
    const char *start = inctx->buffer; /* start of block to return */
    apr_size_t len = sizeof(inctx->buffer); /* length of block to return */
    int is_init = (mode == AP_MODE_INIT);
    apr_bucket *bucket;

    if (f->c->aborted) {
        /* XXX: Ok, if we aborted, we ARE at the EOS.  We also have
         * aborted.  This 'double protection' is probably redundant,
         * but also effective against just about anything.
         */
        bucket = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
        return APR_ECONNABORTED;
    }

    if (!inctx->ssl) {
        SSLConnRec *sslconn = myConnConfig(f->c);
        if (sslconn->non_ssl_request == NON_SSL_SEND_REQLINE) {
            bucket = HTTP_ON_HTTPS_PORT_BUCKET(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, bucket);
            if (mode != AP_MODE_SPECULATIVE) {
                sslconn->non_ssl_request = NON_SSL_SEND_HDR_SEP;
            }
            return APR_SUCCESS;
        }
        if (sslconn->non_ssl_request == NON_SSL_SEND_HDR_SEP) {
            bucket = apr_bucket_immortal_create(CRLF, 2, f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, bucket);
            if (mode != AP_MODE_SPECULATIVE) {
                sslconn->non_ssl_request = NON_SSL_SET_ERROR_MSG;
            }
            return APR_SUCCESS;
        }
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* XXX: we don't currently support anything other than these modes. */
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE &&
        mode != AP_MODE_SPECULATIVE && mode != AP_MODE_INIT) {
        return APR_ENOTIMPL;
    }

    inctx->mode = mode;
    inctx->block = block;

    /* XXX: we could actually move ssl_io_filter_handshake to an
     * ap_hook_process_connection but would still need to call it for
     * AP_MODE_INIT for protocols that may upgrade the connection
     * rather than have SSLEngine On configured.
     */
    if ((status = ssl_io_filter_handshake(inctx->filter_ctx)) != APR_SUCCESS) {
        return ssl_io_filter_error(inctx, bb, status, is_init);
    }

    if (is_init) {
        /* protocol module needs to handshake before sending
         * data to client (e.g. NNTP or FTP)
         */
        return APR_SUCCESS;
    }

    if (inctx->mode == AP_MODE_READBYTES ||
        inctx->mode == AP_MODE_SPECULATIVE) {
        /* Protected from truncation, readbytes < MAX_SIZE_T
         * FIXME: No, it's *not* protected.  -- jre */
        if (readbytes < len) {
            len = (apr_size_t)readbytes;
        }
        status = ssl_io_input_read(inctx, inctx->buffer, &len);
    }
    else if (inctx->mode == AP_MODE_GETLINE) {
        const char *pos;

        /* Satisfy the read directly out of the buffer if possible;
         * invoking ssl_io_input_getline will mean the entire buffer
         * is copied once (unnecessarily) for each GETLINE call. */
        if (inctx->cbuf.length
            && (pos = memchr(inctx->cbuf.value, APR_ASCII_LF,
                             inctx->cbuf.length)) != NULL) {
            start = inctx->cbuf.value;
            len = 1 + pos - start; /* +1 to include LF */
            /* Buffer contents now consumed. */
            inctx->cbuf.value += len;
            inctx->cbuf.length -= len;
            status = APR_SUCCESS;
        }
        else {
            /* Otherwise fall back to the hard way. */
            status = ssl_io_input_getline(inctx, inctx->buffer, &len);
        }
    }
    else {
        /* We have no idea what you are talking about, so return an error. */
        status = APR_ENOTIMPL;
    }

    /* It is possible for mod_ssl's BIO to be used outside of the
     * direct control of mod_ssl's input or output filter -- notably,
     * when mod_ssl initiates a renegotiation.  Switching the BIO mode
     * back to "blocking" here ensures such operations don't fail with
     * SSL_ERROR_WANT_READ. */
    inctx->block = APR_BLOCK_READ;

    /* Handle custom errors. */
    if (status != APR_SUCCESS) {
        return ssl_io_filter_error(inctx, bb, status, 0);
    }

    /* Create a transient bucket out of the decrypted data. */
    if (len > 0) {
        bucket =
            apr_bucket_transient_create(start, len, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
    }

    return APR_SUCCESS;
}


/* ssl_io_filter_output() produces one SSL/TLS record per bucket
 * passed down the output filter stack.  This results in a high
 * overhead (more network packets & TLS processing) for any output
 * comprising many small buckets.  SSI output passed through the HTTP
 * chunk filter, for example, may produce many brigades containing
 * small buckets - [chunk-size CRLF] [chunk-data] [CRLF].
 *
 * Sending HTTP response headers as a separate TLS record to the
 * response body also reveals information to a network observer (the
 * size of headers) which can be significant.
 *
 * The coalescing filter merges data buckets with the aim of producing
 * fewer, larger TLS records - without copying/buffering all content
 * and introducing unnecessary overhead.
 *
 * ### This buffering could be probably be done more comprehensively
 * ### in ssl_io_filter_output itself. 
 * 
 * ### Another possible performance optimisation in particular for the
 * ### [HEAP] [FILE] HTTP response case is using a brigade rather than
 * ### a char array to buffer; using apr_brigade_write() to append
 * ### will use already-allocated memory from the HEAP, reducing # of
 * ### copies.
 */

#define COALESCE_BYTES (AP_IOBUFSIZE)

struct coalesce_ctx {
    char buffer[COALESCE_BYTES];
    apr_size_t bytes; /* number of bytes of buffer used. */
};

static apr_status_t ssl_io_filter_coalesce(ap_filter_t *f,
                                           apr_bucket_brigade *bb)
{
    apr_bucket *e, *upto;
    apr_size_t bytes = 0;
    struct coalesce_ctx *ctx = f->ctx;
    apr_size_t buffered = ctx ? ctx->bytes : 0; /* space used on entry */
    unsigned count = 0;

    /* The brigade consists of zero-or-more small data buckets which
     * can be coalesced (referred to as the "prefix"), followed by the
     * remainder of the brigade.
     *
     * Find the last bucket - if any - of that prefix.  count gives
     * the number of buckets in the prefix.  The "prefix" must contain
     * only data buckets with known length, and must be of a total
     * size which fits into the buffer.
     *
     * N.B.: The process here could be repeated throughout the brigade
     * (coalesce any run of consecutive data buckets) but this would
     * add significant complexity, particularly to memory
     * management. */
    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb)
             && !APR_BUCKET_IS_METADATA(e)
             && e->length != (apr_size_t)-1
             && e->length <= COALESCE_BYTES
             && (buffered + bytes + e->length) <= COALESCE_BYTES;
         e = APR_BUCKET_NEXT(e)) {
        /* don't count zero-length buckets */
        if (e->length) {
            bytes += e->length;
            count++;
        }
    }

    /* If there is room remaining and the next bucket is a data
     * bucket, try to include it in the prefix to coalesce.  For a
     * typical [HEAP] [FILE] HTTP response brigade, this handles
     * merging the headers and the start of the body into a single TLS
     * record. */
    if (bytes + buffered > 0
        && bytes + buffered < COALESCE_BYTES
        && e != APR_BRIGADE_SENTINEL(bb)
        && !APR_BUCKET_IS_METADATA(e)) {
        apr_status_t rv = APR_SUCCESS;

        /* For an indeterminate length bucket (PIPE/CGI/...), try a
         * non-blocking read to have it morph into a HEAP.  If the
         * read fails with EAGAIN, it is harmless to try a split
         * anyway, split is ENOTIMPL for most PIPE-like buckets. */
        if (e->length == (apr_size_t)-1) {
            const char *discard;
            apr_size_t ignore;

            rv = apr_bucket_read(e, &discard, &ignore, APR_NONBLOCK_READ);
            if (rv != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(rv)) {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, f->c, APLOGNO(10232)
                              "coalesce failed to read from %s bucket",
                              e->type->name);
                return AP_FILTER_ERROR;
            }
        }

        if (rv == APR_SUCCESS) {
            /* If the read above made the bucket morph, it may now fit
             * entirely within the buffer.  Otherwise, split it so it does
             * fit. */
            if (e->length > COALESCE_BYTES
                || e->length + buffered + bytes > COALESCE_BYTES) {
                rv = apr_bucket_split(e, COALESCE_BYTES - (buffered + bytes));
            }

            if (rv == APR_SUCCESS && e->length == 0) {
                /* As above, don't count in the prefix if the bucket is
                 * now zero-length. */
            }
            else if (rv == APR_SUCCESS) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, f->c,
                              "coalesce: adding %" APR_SIZE_T_FMT " bytes "
                              "from split %s bucket, total %" APR_SIZE_T_FMT,
                              e->length, e->type->name, bytes + buffered);

                count++;
                bytes += e->length;
                e = APR_BUCKET_NEXT(e);
            }
            else if (rv != APR_ENOTIMPL) {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, f->c, APLOGNO(10233)
                              "coalesce: failed to split data bucket");
                return AP_FILTER_ERROR;
            }
        }
    }

    /* The prefix is zero or more buckets.  upto now points to the
     * bucket AFTER the end of the prefix, which may be the brigade
     * sentinel. */
    upto = e;

    /* Coalesce the prefix, if any of the following are true:
     * 
     * a) the prefix is more than one bucket
     * OR
     * b) the prefix is the entire brigade, which is a single bucket
     *    AND the prefix length is smaller than the buffer size,
     * OR
     * c) the prefix is a single bucket
     *    AND there is buffered data from a previous pass.
     * 
     * The aim with (b) is to buffer a small bucket so it can be
     * coalesced with future invocations of this filter.  e.g.  three
     * calls each with a single 100 byte HEAP bucket should get
     * coalesced together.  But an invocation with a 8192 byte HEAP
     * should pass through untouched.
     */
    if (bytes > 0
        && (count > 1
            || (upto == APR_BRIGADE_SENTINEL(bb)
                && bytes < COALESCE_BYTES)
            || (ctx && ctx->bytes > 0))) {
        /* If coalescing some bytes, ensure a context has been
         * created. */
        if (!ctx) {
            f->ctx = ctx = apr_palloc(f->c->pool, sizeof *ctx);
            ctx->bytes = 0;
        }

        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, f->c,
                      "coalesce: have %" APR_SIZE_T_FMT " bytes, "
                      "adding %" APR_SIZE_T_FMT " more (buckets=%u)",
                      ctx->bytes, bytes, count);

        /* Iterate through the prefix segment.  For non-fatal errors
         * in this loop it is safe to break out and fall back to the
         * normal path of sending the buffer + remaining buckets in
         * brigade.  */
        e = APR_BRIGADE_FIRST(bb);
        while (e != upto) {
            apr_size_t len;
            const char *data;
            apr_bucket *next;

            if (APR_BUCKET_IS_METADATA(e)
                || e->length == (apr_size_t)-1) {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, APLOGNO(02012)
                              "unexpected %s bucket during coalesce",
                              e->type->name);
                break; /* non-fatal error; break out */
            }

            if (e->length) {
                apr_status_t rv;

                /* A blocking read should be fine here for a
                 * known-length data bucket, rather than the usual
                 * non-block/flush/block.  */
                rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
                if (rv) {
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, f->c, APLOGNO(02013)
                                  "coalesce failed to read from data bucket");
                    return AP_FILTER_ERROR;
                }

                /* Be paranoid. */
                if (len > sizeof ctx->buffer
                    || (len + ctx->bytes > sizeof ctx->buffer)) {
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, APLOGNO(02014)
                                  "unexpected coalesced bucket data length");
                    break; /* non-fatal error; break out */
                }

                memcpy(ctx->buffer + ctx->bytes, data, len);
                ctx->bytes += len;
            }

            next = APR_BUCKET_NEXT(e);
            apr_bucket_delete(e);
            e = next;
        }
    }

    if (APR_BRIGADE_EMPTY(bb)) {
        /* If the brigade is now empty, our work here is done. */
        return APR_SUCCESS;
    }

    /* If anything remains in the brigade, it must now be passed down
     * the filter stack, first prepending anything that has been
     * coalesced. */
    if (ctx && ctx->bytes) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, f->c,
                      "coalesce: passing on %" APR_SIZE_T_FMT " bytes", ctx->bytes);

        e = apr_bucket_transient_create(ctx->buffer, ctx->bytes, bb->bucket_alloc);
        APR_BRIGADE_INSERT_HEAD(bb, e);
        ctx->bytes = 0; /* buffer now emptied. */
    }

    return ap_pass_brigade(f->next, bb);
}

static apr_status_t ssl_io_filter_output(ap_filter_t *f,
                                         apr_bucket_brigade *bb)
{
    apr_status_t status = APR_SUCCESS;
    ssl_filter_ctx_t *filter_ctx = f->ctx;
    bio_filter_in_ctx_t *inctx;
    bio_filter_out_ctx_t *outctx;
    apr_read_type_e rblock = APR_NONBLOCK_READ;

    if (f->c->aborted) {
        apr_brigade_cleanup(bb);
        return APR_ECONNABORTED;
    }

    if (!filter_ctx->pssl) {
        /* ssl_filter_io_shutdown was called */
        return ap_pass_brigade(f->next, bb);
    }

    inctx = (bio_filter_in_ctx_t *)BIO_get_data(filter_ctx->pbioRead);
    outctx = (bio_filter_out_ctx_t *)BIO_get_data(filter_ctx->pbioWrite);

    /* When we are the writer, we must initialize the inctx
     * mode so that we block for any required ssl input, because
     * output filtering is always nonblocking.
     */
    inctx->mode = AP_MODE_READBYTES;
    inctx->block = APR_BLOCK_READ;

    if ((status = ssl_io_filter_handshake(filter_ctx)) != APR_SUCCESS) {
        return ssl_io_filter_error(inctx, bb, status, 0);
    }

    while (!APR_BRIGADE_EMPTY(bb) && status == APR_SUCCESS) {
        apr_bucket *bucket = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_METADATA(bucket)) {
            /* Pass through metadata buckets untouched.  EOC is
             * special; terminate the SSL layer first. */
            if (AP_BUCKET_IS_EOC(bucket)) {
                ssl_filter_io_shutdown(filter_ctx, f->c, 0);
            }
            AP_DEBUG_ASSERT(APR_BRIGADE_EMPTY(outctx->bb));

            /* Metadata buckets are passed one per brigade; it might
             * be more efficient (but also more complex) to use
             * outctx->bb as a true buffer and interleave these with
             * data buckets. */
            APR_BUCKET_REMOVE(bucket);
            APR_BRIGADE_INSERT_HEAD(outctx->bb, bucket);
            status = ap_pass_brigade(f->next, outctx->bb);
            if (status == APR_SUCCESS && f->c->aborted)
                status = APR_ECONNRESET;
            apr_brigade_cleanup(outctx->bb);
        }
        else {
            /* Filter a data bucket. */
            const char *data;
            apr_size_t len;

            status = apr_bucket_read(bucket, &data, &len, rblock);

            if (APR_STATUS_IS_EAGAIN(status)) {
                /* No data available: flush... */
                if (bio_filter_out_flush(filter_ctx->pbioWrite) < 0) {
                    status = outctx->rc;
                    break;
                }
                rblock = APR_BLOCK_READ;
                /* and try again with a blocking read. */
                status = APR_SUCCESS;
                continue;
            }

            rblock = APR_NONBLOCK_READ;

            if (!APR_STATUS_IS_EOF(status) && (status != APR_SUCCESS)) {
                break;
            }

            status = ssl_filter_write(f, data, len);
            apr_bucket_delete(bucket);
        }

    }

    return status;
}

struct modssl_buffer_ctx {
    apr_bucket_brigade *bb;
};

int ssl_io_buffer_fill(request_rec *r, apr_size_t maxlen)
{
    conn_rec *c = r->connection;
    struct modssl_buffer_ctx *ctx;
    apr_bucket_brigade *tempb;
    apr_off_t total = 0; /* total length buffered */
    int eos = 0; /* non-zero once EOS is seen */

    /* Create the context which will be passed to the input filter;
     * containing a setaside pool and a brigade which constrain the
     * lifetime of the buffered data. */
    ctx = apr_palloc(r->pool, sizeof *ctx);
    ctx->bb = apr_brigade_create(r->pool, c->bucket_alloc);

    /* ... and a temporary brigade. */
    tempb = apr_brigade_create(r->pool, c->bucket_alloc);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c, "filling buffer, max size "
                  "%" APR_SIZE_T_FMT " bytes", maxlen);

    do {
        apr_status_t rv;
        apr_bucket *e, *next;

        /* The request body is read from the protocol-level input
         * filters; the buffering filter will reinject it from that
         * level, allowing content/resource filters to run later, if
         * necessary. */

        rv = ap_get_brigade(r->proto_input_filters, tempb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, 8192);
        if (rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02015)
                          "could not read request body for SSL buffer");
            return ap_map_http_request_error(rv, HTTP_INTERNAL_SERVER_ERROR);
        }

        /* Iterate through the returned brigade: setaside each bucket
         * into the context's pool and move it into the brigade. */
        for (e = APR_BRIGADE_FIRST(tempb);
             e != APR_BRIGADE_SENTINEL(tempb) && !eos; e = next) {
            const char *data;
            apr_size_t len;

            next = APR_BUCKET_NEXT(e);

            if (APR_BUCKET_IS_EOS(e)) {
                eos = 1;
            } else if (!APR_BUCKET_IS_METADATA(e)) {
                rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
                if (rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02016)
                                  "could not read bucket for SSL buffer");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                total += len;
            }

            rv = apr_bucket_setaside(e, r->pool);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02017)
                              "could not setaside bucket for SSL buffer");
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
        }

        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c,
                      "total of %" APR_OFF_T_FMT " bytes in buffer, eos=%d",
                      total, eos);

        /* Fail if this exceeds the maximum buffer size. */
        if (total > maxlen) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02018)
                          "request body exceeds maximum size (%" APR_SIZE_T_FMT
                          ") for SSL buffer", maxlen);
            return HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

    } while (!eos);

    apr_brigade_destroy(tempb);

    /* After consuming all protocol-level input, remove all protocol-level
     * filters.  It should strictly only be necessary to remove filters
     * at exactly ftype == AP_FTYPE_PROTOCOL, since this filter will
     * precede all > AP_FTYPE_PROTOCOL anyway. */
    while (r->proto_input_filters->frec->ftype < AP_FTYPE_CONNECTION) {
        ap_remove_input_filter(r->proto_input_filters);
    }

    /* Insert the filter which will supply the buffered content. */
    ap_add_input_filter(ssl_io_buffer, ctx, r, c);

    return 0;
}

/* This input filter supplies the buffered request body to the caller
 * from the brigade stored in f->ctx.  Note that the placement of this
 * filter in the filter stack is important; it must be the first
 * r->proto_input_filter; lower-typed filters will not be preserved
 * across internal redirects (see PR 43738).  */
static apr_status_t ssl_io_filter_buffer(ap_filter_t *f,
                                         apr_bucket_brigade *bb,
                                         ap_input_mode_t mode,
                                         apr_read_type_e block,
                                         apr_off_t bytes)
{
    struct modssl_buffer_ctx *ctx = f->ctx;
    apr_status_t rv;
    apr_bucket *e, *d;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, f->c,
                  "read from buffered SSL brigade, mode %d, "
                  "%" APR_OFF_T_FMT " bytes",
                  mode, bytes);

    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
        return APR_ENOTIMPL;
    }

    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        /* Surprisingly (and perhaps, wrongly), the request body can be
         * pulled from the input filter stack more than once; a
         * handler may read it, and ap_discard_request_body() will
         * attempt to do so again after *every* request.  So input
         * filters must be prepared to give up an EOS if invoked after
         * initially reading the request. The HTTP_IN filter does this
         * with its ->eos_sent flag. */

        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->c->bucket_alloc));
        return APR_SUCCESS;
    }

    if (mode == AP_MODE_READBYTES) {
        /* Partition the buffered brigade. */
        rv = apr_brigade_partition(ctx->bb, bytes, &e);
        if (rv && rv != APR_INCOMPLETE) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, f->c, APLOGNO(02019)
                          "could not partition buffered SSL brigade");
            ap_remove_input_filter(f);
            return rv;
        }

        /* If the buffered brigade contains less then the requested
         * length, just pass it all back. */
        if (rv == APR_INCOMPLETE) {
            APR_BRIGADE_CONCAT(bb, ctx->bb);
        } else {
            d = APR_BRIGADE_FIRST(ctx->bb);

            e = APR_BUCKET_PREV(e);

            /* Unsplice the partitioned segment and move it into the
             * passed-in brigade; no convenient way to do this with
             * the APR_BRIGADE_* macros. */
            APR_RING_UNSPLICE(d, e, link);
            APR_RING_SPLICE_HEAD(&bb->list, d, e, apr_bucket, link);

            APR_BRIGADE_CHECK_CONSISTENCY(bb);
            APR_BRIGADE_CHECK_CONSISTENCY(ctx->bb);
        }
    }
    else {
        /* Split a line into the passed-in brigade. */
        rv = apr_brigade_split_line(bb, ctx->bb, block, bytes);

        if (rv) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, f->c, APLOGNO(02020)
                          "could not split line from buffered SSL brigade");
            ap_remove_input_filter(f);
            return rv;
        }
    }

    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        e = APR_BRIGADE_LAST(bb);

        /* Ensure that the brigade is terminated by an EOS if the
         * buffered request body has been entirely consumed. */
        if (e == APR_BRIGADE_SENTINEL(bb) || !APR_BUCKET_IS_EOS(e)) {
            e = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
        }

        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, f->c,
                      "buffered SSL brigade exhausted");
        /* Note that the filter must *not* be removed here; it may be
         * invoked again, see comment above. */
    }

    return APR_SUCCESS;
}

/* The request_rec pointer is passed in here only to ensure that the
 * filter chain is modified correctly when doing a TLS upgrade.  It
 * must *not* be used otherwise. */
static void ssl_io_input_add_filter(ssl_filter_ctx_t *filter_ctx, conn_rec *c,
                                    request_rec *r, SSL *ssl)
{
    bio_filter_in_ctx_t *inctx;

    inctx = apr_palloc(c->pool, sizeof(*inctx));

    filter_ctx->pInputFilter = ap_add_input_filter(ssl_io_filter, inctx, r, c);

#if MODSSL_USE_OPENSSL_PRE_1_1_API
    filter_ctx->pbioRead = BIO_new(&bio_filter_in_method);
#else
    filter_ctx->pbioRead = BIO_new(bio_filter_in_method);
#endif
    BIO_set_data(filter_ctx->pbioRead, (void *)inctx);

    inctx->ssl = ssl;
    inctx->bio_out = filter_ctx->pbioWrite;
    inctx->f = filter_ctx->pInputFilter;
    inctx->rc = APR_SUCCESS;
    inctx->mode = AP_MODE_READBYTES;
    inctx->cbuf.length = 0;
    inctx->bb = apr_brigade_create(c->pool, c->bucket_alloc);
    inctx->block = APR_BLOCK_READ;
    inctx->pool = c->pool;
    inctx->filter_ctx = filter_ctx;
}

/* The request_rec pointer is passed in here only to ensure that the
 * filter chain is modified correctly when doing a TLS upgrade.  It
 * must *not* be used otherwise. */
void ssl_io_filter_init(conn_rec *c, request_rec *r, SSL *ssl)
{
    ssl_filter_ctx_t *filter_ctx;

    filter_ctx = apr_palloc(c->pool, sizeof(ssl_filter_ctx_t));

    filter_ctx->config          = myConnConfig(c);

    ap_add_output_filter(ssl_io_coalesce, NULL, r, c);

    filter_ctx->pOutputFilter   = ap_add_output_filter(ssl_io_filter,
                                                       filter_ctx, r, c);

#if MODSSL_USE_OPENSSL_PRE_1_1_API
    filter_ctx->pbioWrite       = BIO_new(&bio_filter_out_method);
#else
    filter_ctx->pbioWrite       = BIO_new(bio_filter_out_method);
#endif
    BIO_set_data(filter_ctx->pbioWrite, (void *)bio_filter_out_ctx_new(filter_ctx, c));

    /* write is non blocking for the benefit of async mpm */
    if (c->cs) {
        BIO_set_nbio(filter_ctx->pbioWrite, 1);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, c,
                      "Enabling non-blocking writes");
    }

    ssl_io_input_add_filter(filter_ctx, c, r, ssl);

    SSL_set_bio(ssl, filter_ctx->pbioRead, filter_ctx->pbioWrite);
    filter_ctx->pssl            = ssl;

    apr_pool_cleanup_register(c->pool, (void*)filter_ctx,
                              ssl_io_filter_cleanup, apr_pool_cleanup_null);

    if (APLOG_CS_IS_LEVEL(c, mySrvFromConn(c), APLOG_TRACE4)) {
        BIO *rbio = SSL_get_rbio(ssl),
            *wbio = SSL_get_wbio(ssl);
        BIO_set_callback(rbio, ssl_io_data_cb);
        BIO_set_callback_arg(rbio, (void *)ssl);
        if (wbio && wbio != rbio) {
            BIO_set_callback(wbio, ssl_io_data_cb);
            BIO_set_callback_arg(wbio, (void *)ssl);
        }
    }

    return;
}

void ssl_io_filter_register(apr_pool_t *p)
{
    ap_register_input_filter  (ssl_io_filter, ssl_io_filter_input,  NULL, AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter (ssl_io_coalesce, ssl_io_filter_coalesce, NULL, AP_FTYPE_CONNECTION + 4);
    ap_register_output_filter (ssl_io_filter, ssl_io_filter_output, NULL, AP_FTYPE_CONNECTION + 5);

    ap_register_input_filter  (ssl_io_buffer, ssl_io_filter_buffer, NULL, AP_FTYPE_PROTOCOL);

    return;
}

/*  _________________________________________________________________
**
**  I/O Data Debugging
**  _________________________________________________________________
*/

#define DUMP_WIDTH 16

static void ssl_io_data_dump(conn_rec *c, server_rec *s,
                             const char *b, long len)
{
    char buf[256];
    int i, j, rows, trunc, pos;
    unsigned char ch;

    trunc = 0;
    for (; (len > 0) && ((b[len-1] == ' ') || (b[len-1] == '\0')); len--)
        trunc++;
    rows = (len / DUMP_WIDTH);
    if ((rows * DUMP_WIDTH) < len)
        rows++;
    ap_log_cserror(APLOG_MARK, APLOG_TRACE7, 0, c, s,
            "+-------------------------------------------------------------------------+");
    for (i = 0 ; i < rows; i++) {
#if APR_CHARSET_EBCDIC
        char ebcdic_text[DUMP_WIDTH];
        j = DUMP_WIDTH;
        if ((i * DUMP_WIDTH + j) > len)
            j = len % DUMP_WIDTH;
        if (j == 0)
            j = DUMP_WIDTH;
        memcpy(ebcdic_text,(char *)(b) + i * DUMP_WIDTH, j);
        ap_xlate_proto_from_ascii(ebcdic_text, j);
#endif /* APR_CHARSET_EBCDIC */
        pos = 0;
        pos += apr_snprintf(buf, sizeof(buf)-pos, "| %04x: ", i * DUMP_WIDTH);
        for (j = 0; j < DUMP_WIDTH; j++) {
            if (((i * DUMP_WIDTH) + j) >= len)
                pos += apr_snprintf(buf+pos, sizeof(buf)-pos, "   ");
            else {
                ch = ((unsigned char)*((char *)(b) + i * DUMP_WIDTH + j)) & 0xff;
                pos += apr_snprintf(buf+pos, sizeof(buf)-pos, "%02x%c", ch , j==7 ? '-' : ' ');
            }
        }
        pos += apr_snprintf(buf+pos, sizeof(buf)-pos, " ");
        for (j = 0; j < DUMP_WIDTH; j++) {
            if (((i * DUMP_WIDTH) + j) >= len)
                pos += apr_snprintf(buf+pos, sizeof(buf)-pos, " ");
            else {
                ch = ((unsigned char)*((char *)(b) + i * DUMP_WIDTH + j)) & 0xff;
#if APR_CHARSET_EBCDIC
                pos += apr_snprintf(buf+pos, sizeof(buf)-pos, "%c", (ch >= 0x20 && ch <= 0x7F) ? ebcdic_text[j] : '.');
#else /* APR_CHARSET_EBCDIC */
                pos += apr_snprintf(buf+pos, sizeof(buf)-pos, "%c", ((ch >= ' ') && (ch <= '~')) ? ch : '.');
#endif /* APR_CHARSET_EBCDIC */
            }
        }
        pos += apr_snprintf(buf+pos, sizeof(buf)-pos, " |");
        ap_log_cserror(APLOG_MARK, APLOG_TRACE7, 0, c, s, "%s", buf);
    }
    if (trunc > 0)
        ap_log_cserror(APLOG_MARK, APLOG_TRACE7, 0, c, s,
                "| %04ld - <SPACES/NULS>", len + trunc);
    ap_log_cserror(APLOG_MARK, APLOG_TRACE7, 0, c, s,
            "+-------------------------------------------------------------------------+");
}

long ssl_io_data_cb(BIO *bio, int cmd,
                    const char *argp,
                    int argi, long argl, long rc)
{
    SSL *ssl;
    conn_rec *c;
    server_rec *s;

    if ((ssl = (SSL *)BIO_get_callback_arg(bio)) == NULL)
        return rc;
    if ((c = (conn_rec *)SSL_get_app_data(ssl)) == NULL)
        return rc;
    s = mySrvFromConn(c);

    if (   cmd == (BIO_CB_WRITE|BIO_CB_RETURN)
        || cmd == (BIO_CB_READ |BIO_CB_RETURN) ) {
        if (rc >= 0) {
            const char *dump = "";
            if (APLOG_CS_IS_LEVEL(c, s, APLOG_TRACE7)) {
                if (argp != NULL)
                    dump = "(BIO dump follows)";
                else
                    dump = "(Oops, no memory buffer?)";
            }
            ap_log_cserror(APLOG_MARK, APLOG_TRACE4, 0, c, s,
                    "%s: %s %ld/%d bytes %s BIO#%pp [mem: %pp] %s",
                    MODSSL_LIBRARY_NAME,
                    (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "write" : "read"),
                    rc, argi, (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "to" : "from"),
                    bio, argp, dump);
            if (*dump != '\0' && argp != NULL)
                ssl_io_data_dump(c, s, argp, rc);
        }
        else {
            ap_log_cserror(APLOG_MARK, APLOG_TRACE4, 0, c, s,
                    "%s: I/O error, %d bytes expected to %s on BIO#%pp [mem: %pp]",
                    MODSSL_LIBRARY_NAME, argi,
                    (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "write" : "read"),
                    bio, argp);
        }
    }
    return rc;
}
