/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_io.c
**  I/O Functions
*/

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 */
                             /* ``MY HACK: This universe.
                                  Just one little problem:
                                  core keeps dumping.''
                                            -- Unknown    */
#include "mod_ssl.h"

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
} ssl_filter_ctx_t;

typedef struct {
    ssl_filter_ctx_t *filter_ctx;
    conn_rec *c;
    apr_bucket_brigade *bb;
    apr_size_t length;
    char buffer[AP_IOBUFSIZE];
    apr_size_t blen;
    apr_status_t rc;
} bio_filter_out_ctx_t;

static bio_filter_out_ctx_t *bio_filter_out_ctx_new(ssl_filter_ctx_t *filter_ctx,
                                                    conn_rec *c)
{
    bio_filter_out_ctx_t *outctx = apr_palloc(c->pool, sizeof(*outctx));

    outctx->filter_ctx = filter_ctx;
    outctx->c = c;
    outctx->bb = apr_brigade_create(c->pool, c->bucket_alloc);
    outctx->blen = 0;
    outctx->length = 0;

    return outctx;
}

static int bio_filter_out_flush(BIO *bio)
{
    bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)(bio->ptr);
    apr_bucket *e;

    if (!(outctx->blen || outctx->length)) {
        outctx->rc = APR_SUCCESS;
        return 1;
    }

    if (outctx->blen) {
        e = apr_bucket_transient_create(outctx->buffer, outctx->blen,
                                        outctx->bb->bucket_alloc);
        /* we filled this buffer first so add it to the 
         * head of the brigade
         */
        APR_BRIGADE_INSERT_HEAD(outctx->bb, e);
        outctx->blen = 0;
    }

    outctx->length = 0;
    e = apr_bucket_flush_create(outctx->bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(outctx->bb, e);

    outctx->rc = ap_pass_brigade(outctx->filter_ctx->pOutputFilter->next,
                                 outctx->bb);
    return (outctx->rc == APR_SUCCESS) ? 1 : -1;
}

static int bio_filter_create(BIO *bio)
{
    bio->shutdown = 1;
    bio->init = 1;
    bio->num = -1;
    bio->ptr = NULL;

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
    return -1;
}

static int bio_filter_out_write(BIO *bio, const char *in, int inl)
{
    bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)(bio->ptr);

    /* when handshaking we'll have a small number of bytes.
     * max size SSL will pass us here is about 16k.
     * (16413 bytes to be exact)
     */
    BIO_clear_retry_flags(bio);

    if (!outctx->length && (inl + outctx->blen < sizeof(outctx->buffer))) {
        /* the first two SSL_writes (of 1024 and 261 bytes)
         * need to be in the same packet (vec[0].iov_base)
         */
        /* XXX: could use apr_brigade_write() to make code look cleaner
         * but this way we avoid the malloc(APR_BUCKET_BUFF_SIZE)
         * and free() of it later
         */
        memcpy(&outctx->buffer[outctx->blen], in, inl);
        outctx->blen += inl;
    }
    else {
        /* pass along the encrypted data
         * need to flush since we're using SSL's malloc-ed buffer 
         * which will be overwritten once we leave here
         */
        apr_bucket *bucket = apr_bucket_transient_create(in, inl,
                                             outctx->bb->bucket_alloc);

        outctx->length += inl;
        APR_BRIGADE_INSERT_TAIL(outctx->bb, bucket);

        if (bio_filter_out_flush(bio) < 0) {
            return -1;
        }
    }

    return inl;
}

static long bio_filter_out_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;
    char **pptr;

    bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)(bio->ptr);

    switch (cmd) {
      case BIO_CTRL_RESET:
        outctx->blen = outctx->length = 0;
        break;
      case BIO_CTRL_EOF:
        ret = (long)((outctx->blen + outctx->length) == 0);
        break;
      case BIO_C_SET_BUF_MEM_EOF_RETURN:
        outctx->blen = outctx->length = (apr_size_t)num;
        break;
      case BIO_CTRL_INFO:
        ret = (long)(outctx->blen + outctx->length);
        if (ptr) {
            pptr = (char **)ptr;
            *pptr = (char *)&(outctx->buffer[0]);
        }
        break;
      case BIO_CTRL_GET_CLOSE:
        ret = (long)bio->shutdown;
        break;
      case BIO_CTRL_SET_CLOSE:
        bio->shutdown = (int)num;
        break;
      case BIO_CTRL_WPENDING:
        ret = 0L;
        break;
      case BIO_CTRL_PENDING:
        ret = (long)(outctx->blen + outctx->length);
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
    return -1;
}

static int bio_filter_out_puts(BIO *bio, const char *str)
{
    /* this is never called */
    return -1;
}

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
#ifdef OPENSSL_VERSION_NUMBER
    NULL /* sslc does not have the callback_ctrl field */
#endif
};

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
static int char_buffer_read(char_buffer_t *buffer, char *in, int inl)
{
    if (!buffer->length) {
        return 0;
    }

    if (buffer->length > inl) {
        /* we have have enough to fill the caller's buffer */
        memcpy(in, buffer->value, inl);
        buffer->value += inl;
        buffer->length -= inl;
    }
    else {
        /* swallow remainder of the buffer */
        memcpy(in, buffer->value, buffer->length);
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
    bio_filter_in_ctx_t *inctx = (bio_filter_in_ctx_t *)(bio->ptr);
    apr_read_type_e block = inctx->block;
    SSLConnRec *sslconn = myConnConfig(inctx->f->c);

    inctx->rc = APR_SUCCESS;

    /* OpenSSL catches this case, so should we. */
    if (!in)
        return 0;

    /* XXX: flush here only required for SSLv2;
     * OpenSSL calls BIO_flush() at the appropriate times for
     * the other protocols.
     */
    if ((SSL_version(inctx->ssl) == SSL2_VERSION) || sslconn->is_proxy) {
        if (bio_filter_out_flush(inctx->bio_out) < 0) {
            bio_filter_out_ctx_t *outctx = 
                   (bio_filter_out_ctx_t *)(inctx->bio_out->ptr);
            inctx->rc = outctx->rc;
            return -1;
        }
    }

    BIO_clear_retry_flags(bio);

    if (!inctx->bb) {
        inctx->rc = APR_EOF;
        return -1;
    }

    if (APR_BRIGADE_EMPTY(inctx->bb)) {

        inctx->rc = ap_get_brigade(inctx->f->next, inctx->bb,
                                   AP_MODE_READBYTES, block, 
                                   inl);

        /* Not a problem, there was simply no data ready yet.
         */
        if (APR_STATUS_IS_EAGAIN(inctx->rc) || APR_STATUS_IS_EINTR(inctx->rc)
               || (inctx->rc == APR_SUCCESS && APR_BRIGADE_EMPTY(inctx->bb))) {
            BIO_set_retry_read(bio);
            return 0;
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


static BIO_METHOD bio_filter_in_method = {
    BIO_TYPE_MEM,
    "APR input filter",
    NULL,                       /* write is never called */
    bio_filter_in_read,
    NULL,                       /* puts is never called */
    NULL,                       /* gets is never called */
    NULL,                       /* ctrl is never called */
    bio_filter_create,
    bio_filter_destroy,
#ifdef OPENSSL_VERSION_NUMBER
    NULL /* sslc does not have the callback_ctrl field */
#endif
};


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
            inctx->cbuf.value -= bytes;
            inctx->cbuf.length += bytes;
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
            break;
        }

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
        else if (rc == 0) {
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
                }
                else {
                    inctx->rc = APR_EOF;
                }
                break;
            }
        }
        else /* (rc < 0) */ {
            int ssl_err = SSL_get_error(inctx->filter_ctx->pssl, rc);
            conn_rec *c = (conn_rec*)SSL_get_app_data(inctx->filter_ctx->pssl);

            if (ssl_err == SSL_ERROR_WANT_READ) {
                /*
                 * If OpenSSL wants to read more, and we were nonblocking,
                 * report as an EAGAIN.  Otherwise loop, pulling more
                 * data from network filter.
                 *
                 * (This is usually the case when the client forces an SSL
                 * renegotation which is handled implicitly by OpenSSL.)
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
                else {
                    ap_log_error(APLOG_MARK, APLOG_INFO, inctx->rc, c->base_server,
                                "SSL input filter read failed.");
                }
            }
            else /* if (ssl_err == SSL_ERROR_SSL) */ {
                /*
                 * Log SSL errors and any unexpected conditions.
                 */
                ap_log_error(APLOG_MARK, APLOG_INFO, inctx->rc, c->base_server,
                            "SSL library error %d reading data", ssl_err);
                ssl_log_ssl_error(APLOG_MARK, APLOG_INFO, c->base_server);

            }
            if (inctx->rc == APR_SUCCESS) {
                inctx->rc = APR_EGENERAL;
            }
            break;
        }
    }
    return inctx->rc;
}

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
    bio_filter_out_ctx_t *outctx = 
           (bio_filter_out_ctx_t *)(filter_ctx->pbioWrite->ptr);
    int res;

    /* write SSL */
    if (filter_ctx->pssl == NULL) {
        return APR_EGENERAL;
    }

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
             * renegotation which is handled implicitly by OpenSSL.)
             */
            outctx->rc = APR_EAGAIN;
        }
        else if (ssl_err == SSL_ERROR_SYSCALL) {
            ap_log_error(APLOG_MARK, APLOG_INFO, outctx->rc, c->base_server,
                        "SSL output filter write failed.");
        }
        else /* if (ssl_err == SSL_ERROR_SSL) */ {
            /*
             * Log SSL errors
             */
            ap_log_error(APLOG_MARK, APLOG_INFO, outctx->rc, c->base_server,
                         "SSL library error %d writing data", ssl_err);
            ssl_log_ssl_error(APLOG_MARK, APLOG_INFO, c->base_server);
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

        ap_log_error(APLOG_MARK, APLOG_INFO, outctx->rc, c->base_server,
                     "failed to write %d of %d bytes (%s)",
                     len - (apr_size_t)res, len, reason);

        outctx->rc = APR_EGENERAL;
    }
    return outctx->rc;
}

/* Just use a simple request.  Any request will work for this, because
 * we use a flag in the conn_rec->conn_vector now.  The fake request just
 * gets the request back to the Apache core so that a response can be sent.
 *
 * To avoid calling back for more data from the socket, use an HTTP/0.9
 * request, and tack on an EOS bucket.
 */
#define HTTP_ON_HTTPS_PORT \
    "GET /" CRLF

#define HTTP_ON_HTTPS_PORT_BUCKET(alloc) \
    apr_bucket_immortal_create(HTTP_ON_HTTPS_PORT, \
                               sizeof(HTTP_ON_HTTPS_PORT) - 1, \
                               alloc)

static void ssl_io_filter_disable(ap_filter_t *f)
{
    bio_filter_in_ctx_t *inctx = f->ctx;
    inctx->ssl = NULL;
    inctx->filter_ctx->pssl = NULL;
}

static apr_status_t ssl_io_filter_error(ap_filter_t *f,
                                        apr_bucket_brigade *bb,
                                        apr_status_t status)
{
    SSLConnRec *sslconn = myConnConfig(f->c);
    apr_bucket *bucket;

    switch (status) {
      case HTTP_BAD_REQUEST:
            /* log the situation */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                         f->c->base_server,
                         "SSL handshake failed: HTTP spoken on HTTPS port; "
                         "trying to send HTML error page");
            ssl_log_ssl_error(APLOG_MARK, APLOG_INFO, f->c->base_server);

            sslconn->non_ssl_request = 1;
            ssl_io_filter_disable(f);

            /* fake the request line */
            bucket = HTTP_ON_HTTPS_PORT_BUCKET(f->c->bucket_alloc);
            break;

      default:
        return status;
    }

    APR_BRIGADE_INSERT_TAIL(bb, bucket);
    bucket = apr_bucket_eos_create(f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, bucket);

    return APR_SUCCESS;
}

static const char ssl_io_filter[] = "SSL/TLS Filter";

/*
 *  Close the SSL part of the socket connection
 *  (called immediately _before_ the socket is closed)
 *  or called with 
 */
static apr_status_t ssl_filter_io_shutdown(ssl_filter_ctx_t *filter_ctx,
                                           conn_rec *c,
                                           int abortive)
{
    SSL *ssl = filter_ctx->pssl;
    const char *type = "";
    SSLConnRec *sslconn = myConnConfig(c);
    int shutdown_type;

    if (!ssl) {
        return APR_SUCCESS;
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
    }
    else switch (sslconn->shutdown_type) {
      case SSL_SHUTDOWN_TYPE_UNCLEAN:
        /* perform no close notify handshake at all
           (violates the SSL/TLS standard!) */
        shutdown_type = SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN;
        type = "unclean";
        break;
      case SSL_SHUTDOWN_TYPE_ACCURATE:
        /* send close notify and wait for clients close notify
           (standard compliant, but usually causes connection hangs) */
        shutdown_type = 0;
        type = "accurate";
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
        break;
    }

    SSL_set_shutdown(ssl, shutdown_type);
    SSL_smart_shutdown(ssl);

    /* and finally log the fact that we've closed the connection */
    if (c->base_server->loglevel >= APLOG_INFO) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server,
                     "Connection to child %ld closed with %s shutdown"
                     "(server %s, client %s)",
                     c->id, type,
                     ssl_util_vhostid(c->pool, c->base_server),
                     c->remote_ip ? c->remote_ip : "unknown");
    }

    /* deallocate the SSL connection */
    if (sslconn->client_cert) {
        X509_free(sslconn->client_cert);
        sslconn->client_cert = NULL;
    }
    SSL_free(ssl);
    sslconn->ssl = NULL;
    filter_ctx->pssl = NULL; /* so filters know we've been shutdown */

    return APR_SUCCESS;
}

static apr_status_t ssl_io_filter_cleanup(void *data)
{
    apr_status_t ret;
    ssl_filter_ctx_t *filter_ctx = (ssl_filter_ctx_t *)data;
    conn_rec *c;

    if (!filter_ctx->pssl) {
        /* already been shutdown */
        return APR_SUCCESS;
    }

    c = (conn_rec *)SSL_get_app_data(filter_ctx->pssl);
    if ((ret = ssl_filter_io_shutdown(filter_ctx, c, 0)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, ret, NULL,
                     "SSL filter error shutting down I/O");
    }

    return ret;
}

/*
 * The hook is NOT registered with ap_hook_process_connection. Instead, it is
 * called manually from the churn () before it tries to read any data.
 * There is some problem if I accept conn_rec *. Still investigating..
 * Adv. if conn_rec * can be accepted is we can hook this function using the
 * ap_hook_process_connection hook.
 */
static int ssl_io_filter_connect(ssl_filter_ctx_t *filter_ctx)
{
    conn_rec *c         = (conn_rec *)SSL_get_app_data(filter_ctx->pssl);
    SSLConnRec *sslconn = myConnConfig(c);
    SSLSrvConfigRec *sc = mySrvConfig(c->base_server);
    X509 *cert;
    int n;
    int ssl_err;
    long verify_result;

    if (SSL_is_init_finished(filter_ctx->pssl)) {
        return APR_SUCCESS;
    }

    if (sslconn->is_proxy) {
        if ((n = SSL_connect(filter_ctx->pssl)) <= 0) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                         c->base_server,
                         "SSL Proxy connect failed");
            ssl_log_ssl_error(APLOG_MARK, APLOG_INFO, c->base_server);
            return ssl_filter_io_shutdown(filter_ctx, c, 1);
        }

        return APR_SUCCESS;
    }

    if ((n = SSL_accept(filter_ctx->pssl)) <= 0) {
        bio_filter_in_ctx_t *inctx = (bio_filter_in_ctx_t *)
                                     (filter_ctx->pbioRead->ptr);
        bio_filter_out_ctx_t *outctx = (bio_filter_out_ctx_t *)
                                       (filter_ctx->pbioWrite->ptr);
        apr_status_t rc = inctx->rc ? inctx->rc : outctx->rc ;
        ssl_err = SSL_get_error(filter_ctx->pssl, n);
        
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            /*
             * The case where the connection was closed before any data
             * was transferred. That's not a real error and can occur
             * sporadically with some clients.
             */
            ap_log_error(APLOG_MARK, APLOG_INFO, rc,
                         c->base_server,
                         "SSL handshake stopped: connection was closed");
        }
        else if (ssl_err == SSL_ERROR_WANT_READ) {
            /*
             * This is in addition to what was present earlier. It is 
             * borrowed from openssl_state_machine.c [mod_tls].
             * TBD.
             */
            outctx->rc = APR_EAGAIN;
            return SSL_ERROR_WANT_READ;
        }
        else if (ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST) {
            /*
             * The case where OpenSSL has recognized a HTTP request:
             * This means the client speaks plain HTTP on our HTTPS port.
             * ssl_io_filter_error will disable the ssl filters when it
             * sees this status code.
             */
            return HTTP_BAD_REQUEST;
        }
        else if (ssl_err == SSL_ERROR_SYSCALL) {
            ap_log_error(APLOG_MARK, APLOG_INFO, rc, c->base_server,
                         "SSL handshake interrupted by system "
                         "[Hint: Stop button pressed in browser?!]");
        }
        else /* if (ssl_err == SSL_ERROR_SSL) */ {
            /*
             * Log SSL errors and any unexpected conditions.
             */
            ap_log_error(APLOG_MARK, APLOG_INFO, rc, c->base_server,
                         "SSL library error %d in handshake "
                         "(server %s, client %s)", ssl_err,
                         ssl_util_vhostid(c->pool, c->base_server),
                         c->remote_ip ? c->remote_ip : "unknown");
            ssl_log_ssl_error(APLOG_MARK, APLOG_INFO, c->base_server);

        }
        if (inctx->rc == APR_SUCCESS) {
            inctx->rc = APR_EGENERAL;
        }

        return ssl_filter_io_shutdown(filter_ctx, c, 1);
    }

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
            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                         c->base_server,
                         "SSL client authentication failed, "
                         "accepting certificate based on "
                         "\"SSLVerifyClient optional_no_ca\" "
                         "configuration");
            ssl_log_ssl_error(APLOG_MARK, APLOG_INFO, c->base_server);
        }
        else {
            const char *error = sslconn->verify_error ?
                sslconn->verify_error :
                X509_verify_cert_error_string(verify_result);

            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                         c->base_server,
                         "SSL client authentication failed: %s",
                         error ? error : "unknown");
            ssl_log_ssl_error(APLOG_MARK, APLOG_INFO, c->base_server);

            return ssl_filter_io_shutdown(filter_ctx, c, 1);
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
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server,
                     "No acceptable peer certificate available");

        return ssl_filter_io_shutdown(filter_ctx, c, 1);
    }

    return APR_SUCCESS;
}

static apr_status_t ssl_io_filter_Upgrade(ap_filter_t *f,
                                         apr_bucket_brigade *bb)

{
#define SWITCH_STATUS_LINE "HTTP/1.1 101 Switching Protocols"
#define UPGRADE_HEADER "Upgrade: TLS/1.0 HTTP/1.1"
#define CONNECTION_HEADER "Connection: Upgrade"
    const char *upgrade;
    const char *connection;
    apr_bucket_brigade *upgradebb;
    request_rec *r = f->r;
    SSLConnRec *sslconn;
    SSL *ssl;

    /* Just remove the filter, if it doesn't work the first time, it won't
     * work at all for this request.
     */
    ap_remove_output_filter(f);

    /* No need to ensure that this is a server with optional SSL, the filter
     * is only inserted if that is true.
     */

    upgrade = apr_table_get(r->headers_in, "Upgrade");
    if (upgrade == NULL) {
        return ap_pass_brigade(f->next, bb);
    }
    connection = apr_table_get(r->headers_in, "Connection");

    apr_table_unset(r->headers_out, "Upgrade");

    /* XXX: I don't think the requirement that the client sends exactly 
     * "Connection: Upgrade" is correct; the only requirement here is 
     * on the client to send a  Connection header including the "upgrade" 
     * token.
     */
    if (strcmp(connection, "Upgrade") || strcmp(upgrade, "TLS/1.0")) {
        return ap_pass_brigade(f->next, bb);
    }

    if (r->method_number == M_OPTIONS) {
        apr_bucket *b = NULL;
        /* This is a mandatory SSL upgrade. */

        upgradebb = apr_brigade_create(r->pool, f->c->bucket_alloc);

        ap_fputstrs(f->next, upgradebb, SWITCH_STATUS_LINE, CRLF,
                    UPGRADE_HEADER, CRLF, CONNECTION_HEADER, CRLF, CRLF, NULL);

        b = apr_bucket_flush_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(upgradebb, b);

        ap_pass_brigade(f->next, upgradebb);
    }
    else {
        /* This is optional, and should be configurable, for now don't bother
         * doing anything.
         */
        return ap_pass_brigade(f->next, bb);
    }

    ssl_init_ssl_connection(f->c);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                 "Awaiting re-negotiation handshake");

    sslconn = myConnConfig(f->c);
    ssl = sslconn->ssl;

    SSL_set_state(ssl, SSL_ST_ACCEPT);
    SSL_do_handshake(ssl);

    if (SSL_get_state(ssl) != SSL_ST_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "Re-negotiation handshake failed: "
                "Not accepted by client!?");

        return AP_FILTER_ERROR;
    }

    return OK;
}

static apr_status_t ssl_io_filter_input(ap_filter_t *f,
                                        apr_bucket_brigade *bb,
                                        ap_input_mode_t mode,
                                        apr_read_type_e block,
                                        apr_off_t readbytes)
{
    apr_status_t status;
    bio_filter_in_ctx_t *inctx = f->ctx;

    apr_size_t len = sizeof(inctx->buffer);
    int is_init = (mode == AP_MODE_INIT);

    if (f->c->aborted) {
        /* XXX: Ok, if we aborted, we ARE at the EOS.  We also have
         * aborted.  This 'double protection' is probably redundant,
         * but also effective against just about anything.
         */
        apr_bucket *bucket = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
        return APR_ECONNABORTED;
    }

    if (!inctx->ssl) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* XXX: we don't currently support anything other than these modes. */
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE && 
        mode != AP_MODE_SPECULATIVE && mode != AP_MODE_INIT) {
        return APR_ENOTIMPL;
    }

    inctx->mode = mode;
    inctx->block = block;

    /* XXX: we could actually move ssl_io_filter_connect to an
     * ap_hook_process_connection but would still need to call it for
     * AP_MODE_INIT for protocols that may upgrade the connection
     * rather than have SSLEngine On configured.
     */
    if ((status = ssl_io_filter_connect(inctx->filter_ctx)) != APR_SUCCESS) {
        return ssl_io_filter_error(f, bb, status);
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
        status = ssl_io_input_getline(inctx, inctx->buffer, &len);
    }
    else {
        /* We have no idea what you are talking about, so return an error. */
        return APR_ENOTIMPL;
    }

    if (status != APR_SUCCESS) {
        return ssl_io_filter_error(f, bb, status);
    }

    /* Create a transient bucket out of the decrypted data. */
    if (len > 0) {
        apr_bucket *bucket =
            apr_bucket_transient_create(inctx->buffer, len, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
    }

    return APR_SUCCESS;
}

static apr_status_t ssl_io_filter_output(ap_filter_t *f,
                                         apr_bucket_brigade *bb)
{
    apr_status_t status = APR_SUCCESS;
    ssl_filter_ctx_t *filter_ctx = f->ctx;
    bio_filter_in_ctx_t *inctx = (bio_filter_in_ctx_t *)
                                 (filter_ctx->pbioRead->ptr);

    if (f->c->aborted) {
        apr_brigade_cleanup(bb);
        return APR_ECONNABORTED;
    }

    if (!filter_ctx->pssl) {
        /* ssl_filter_io_shutdown was called */
        return ap_pass_brigade(f->next, bb);
    }

    /* When we are the writer, we must initialize the inctx
     * mode so that we block for any required ssl input, because
     * output filtering is always nonblocking.
     */
    inctx->mode = APR_MODE_READBYTES;
    inctx->block = AP_BLOCK_READ;

    if ((status = ssl_io_filter_connect(filter_ctx)) != APR_SUCCESS) {
        return ssl_io_filter_error(f, bb, status);
    }

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *bucket = APR_BRIGADE_FIRST(bb);

        /* If it is a flush or EOS, we need to pass this down. 
         * These types do not require translation by OpenSSL.  
         */
        if (APR_BUCKET_IS_EOS(bucket) || APR_BUCKET_IS_FLUSH(bucket)) {
            if (bio_filter_out_flush(filter_ctx->pbioWrite) < 0) {
                bio_filter_out_ctx_t *outctx = 
                       (bio_filter_out_ctx_t *)(filter_ctx->pbioWrite->ptr);
                status = outctx->rc;
                break;
            }

            if (APR_BUCKET_IS_EOS(bucket)) {
                /*
                 * By definition, nothing can come after EOS.
                 * which also means we can pass the rest of this brigade
                 * without creating a new one since it only contains the
                 * EOS bucket.
                 */

                if ((status = ap_pass_brigade(f->next, bb)) != APR_SUCCESS) {
                    return status;
                }
                break;
            }
            else {
                /* bio_filter_out_flush() already passed down a flush bucket
                 * if there was any data to be flushed.
                 */
                apr_bucket_delete(bucket);
            }
        }
        else {
            /* filter output */
            const char *data;
            apr_size_t len;
            
            status = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);

            if (!APR_STATUS_IS_EOF(status) && (status != APR_SUCCESS)) {
                break;
            }

            status = ssl_filter_write(f, data, len);
            apr_bucket_delete(bucket);

            if (status != APR_SUCCESS) {
                break;
            }
        }
    }

    return status;
}

static void ssl_io_input_add_filter(ssl_filter_ctx_t *filter_ctx, conn_rec *c,
                                    SSL *ssl)
{
    bio_filter_in_ctx_t *inctx;

    inctx = apr_palloc(c->pool, sizeof(*inctx));

    filter_ctx->pInputFilter = ap_add_input_filter(ssl_io_filter, inctx, NULL, c);

    filter_ctx->pbioRead = BIO_new(&bio_filter_in_method);
    filter_ctx->pbioRead->ptr = (void *)inctx;

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

void ssl_io_filter_init(conn_rec *c, SSL *ssl)
{
    ssl_filter_ctx_t *filter_ctx;

    filter_ctx = apr_palloc(c->pool, sizeof(ssl_filter_ctx_t));

    filter_ctx->pOutputFilter   = ap_add_output_filter(ssl_io_filter,
                                                   filter_ctx, NULL, c);

    filter_ctx->pbioWrite       = BIO_new(&bio_filter_out_method);
    filter_ctx->pbioWrite->ptr  = (void *)bio_filter_out_ctx_new(filter_ctx, c);

    ssl_io_input_add_filter(filter_ctx, c, ssl);

    SSL_set_bio(ssl, filter_ctx->pbioRead, filter_ctx->pbioWrite);
    filter_ctx->pssl            = ssl;

    apr_pool_cleanup_register(c->pool, (void*)filter_ctx,
                              ssl_io_filter_cleanup, apr_pool_cleanup_null);

    if (c->base_server->loglevel >= APLOG_DEBUG) {
        BIO_set_callback(SSL_get_rbio(ssl), ssl_io_data_cb);
        BIO_set_callback_arg(SSL_get_rbio(ssl), (void *)ssl);
    }

    return;
}

void ssl_io_filter_register(apr_pool_t *p)
{
    /* This filter MUST be after the HTTP_HEADER filter, but it also must be
     * a resource-level filter so it has the request_rec.
     */
    ap_register_output_filter ("UPGRADE_FILTER", ssl_io_filter_Upgrade, NULL, AP_FTYPE_PROTOCOL + 5);

    ap_register_input_filter  (ssl_io_filter, ssl_io_filter_input,  NULL, AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter (ssl_io_filter, ssl_io_filter_output, NULL, AP_FTYPE_CONNECTION + 5);
    return;
}

/*  _________________________________________________________________
**
**  I/O Data Debugging
**  _________________________________________________________________
*/

#define DUMP_WIDTH 16

static void ssl_io_data_dump(server_rec *srvr,
                             MODSSL_BIO_CB_ARG_TYPE *s,
                             long len)
{
    char buf[256];
    char tmp[64];
    int i, j, rows, trunc;
    unsigned char ch;

    trunc = 0;
    for(; (len > 0) && ((s[len-1] == ' ') || (s[len-1] == '\0')); len--)
        trunc++;
    rows = (len / DUMP_WIDTH);
    if ((rows * DUMP_WIDTH) < len)
        rows++;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, srvr,
            "+-------------------------------------------------------------------------+");
    for(i = 0 ; i< rows; i++) {
        apr_snprintf(tmp, sizeof(tmp), "| %04x: ", i * DUMP_WIDTH);
        apr_cpystrn(buf, tmp, sizeof(buf));
        for (j = 0; j < DUMP_WIDTH; j++) {
            if (((i * DUMP_WIDTH) + j) >= len)
                apr_cpystrn(buf+strlen(buf), "   ", sizeof(buf)-strlen(buf));
            else {
                ch = ((unsigned char)*((char *)(s) + i * DUMP_WIDTH + j)) & 0xff;
                apr_snprintf(tmp, sizeof(tmp), "%02x%c", ch , j==7 ? '-' : ' ');
                apr_cpystrn(buf+strlen(buf), tmp, sizeof(buf)-strlen(buf));
            }
        }
        apr_cpystrn(buf+strlen(buf), " ", sizeof(buf)-strlen(buf));
        for (j = 0; j < DUMP_WIDTH; j++) {
            if (((i * DUMP_WIDTH) + j) >= len)
                apr_cpystrn(buf+strlen(buf), " ", sizeof(buf)-strlen(buf));
            else {
                ch = ((unsigned char)*((char *)(s) + i * DUMP_WIDTH + j)) & 0xff;
                apr_snprintf(tmp, sizeof(tmp), "%c", ((ch >= ' ') && (ch <= '~')) ? ch : '.');
                apr_cpystrn(buf+strlen(buf), tmp, sizeof(buf)-strlen(buf));
            }
        }
        apr_cpystrn(buf+strlen(buf), " |", sizeof(buf)-strlen(buf));
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, srvr,
                     "%s", buf);
    }
    if (trunc > 0)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, srvr,
                "| %04ld - <SPACES/NULS>", len + trunc);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, srvr,
            "+-------------------------------------------------------------------------+");
    return;
}

long ssl_io_data_cb(BIO *bio, int cmd,
                    MODSSL_BIO_CB_ARG_TYPE *argp,
                    int argi, long argl, long rc)
{
    SSL *ssl;
    conn_rec *c;
    server_rec *s;

    if ((ssl = (SSL *)BIO_get_callback_arg(bio)) == NULL)
        return rc;
    if ((c = (conn_rec *)SSL_get_app_data(ssl)) == NULL)
        return rc;
    s = c->base_server;

    if (   cmd == (BIO_CB_WRITE|BIO_CB_RETURN)
        || cmd == (BIO_CB_READ |BIO_CB_RETURN) ) {
        if (rc >= 0) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                    "%s: %s %ld/%d bytes %s BIO#%pp [mem: %pp] %s",
                    SSL_LIBRARY_NAME,
                    (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "write" : "read"),
                    rc, argi, (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "to" : "from"),
                    bio, argp,
                    (argp != NULL ? "(BIO dump follows)" : "(Oops, no memory buffer?)"));
            if (argp != NULL)
                ssl_io_data_dump(s, argp, rc);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                    "%s: I/O error, %d bytes expected to %s on BIO#%pp [mem: %pp]",
                    SSL_LIBRARY_NAME, argi,
                    (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "write" : "read"),
                    bio, argp);
        }
    }
    return rc;
}
