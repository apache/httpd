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
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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
    SSLFilterRec *frec;
    conn_rec *c;
    apr_bucket_brigade *bb;
    apr_size_t length;
    char buffer[AP_IOBUFSIZE];
    apr_size_t blen;
} bio_filter_out_ctx_t;

static bio_filter_out_ctx_t *bio_filter_out_ctx_new(SSLFilterRec *frec, conn_rec *c)
{
    bio_filter_out_ctx_t *outctx = apr_palloc(c->pool, sizeof(*outctx));

    outctx->frec = frec;
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
        return APR_SUCCESS;
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

    return ap_pass_brigade(outctx->frec->pOutputFilter->next, outctx->bb);
}

static int bio_filter_new(BIO *bio)
{
    bio->shutdown = 1;
    bio->init = 1;
    bio->num = -1;
    bio->ptr = NULL;

    return 1;
}

static int bio_filter_free(BIO *bio)
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

        bio_filter_out_flush(bio);
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
        ret = (bio_filter_out_flush(bio) == APR_SUCCESS);
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
    bio_filter_new,
    bio_filter_free,
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
    BIO *wbio;
    ap_filter_t *f;
    apr_status_t rc;
    ap_input_mode_t mode;
    apr_read_type_e block;
    apr_bucket_brigade *bb;
    char_buffer_t cbuf;
    apr_pool_t *pool;
    char buffer[AP_IOBUFSIZE];
    SSLFilterRec *frec;
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

static apr_status_t brigade_consume(apr_bucket_brigade *bb,
                                    apr_read_type_e block,
                                    char *c, apr_size_t *len)
{
    apr_size_t actual = 0;
    apr_status_t status;
 
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
        }

        if (b->start >= 0) {
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
static int bio_filter_in_read(BIO *bio, char *in, int inl)
{
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
        bio_filter_out_flush(inctx->wbio);
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
        return inl;
    }

    if (APR_STATUS_IS_EAGAIN(inctx->rc) 
            || APR_STATUS_IS_EINTR(inctx->rc)) {
        BIO_set_retry_read(bio);
        return inl;
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
        return inl;
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
    bio_filter_new,
    bio_filter_free,
#ifdef OPENSSL_VERSION_NUMBER
    NULL /* sslc does not have the callback_ctrl field */
#endif
};

static const char ssl_io_filter[] = "SSL/TLS Filter";

static int ssl_io_hook_write(SSL *ssl, unsigned char *buf, int len)
{
    int rc;

    if (ssl == NULL) {
        return -1;
    }

    rc = SSL_write(ssl, buf, len);

    if (rc < 0) {
        int ssl_err = SSL_get_error(ssl, rc);

        if (ssl_err == SSL_ERROR_WANT_WRITE) {
            /*
             * Simulate an EINTR in case OpenSSL wants to write more.
             */
            errno = EINTR;
        }
        else if (ssl_err == SSL_ERROR_SSL) {
            /*
             * Log SSL errors
             */
            conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->base_server,
                    "SSL error on writing data");
            ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, c->base_server);
        }
        /*
         * XXX - Just trying to reflect the behaviour in 
         * openssl_state_machine.c [mod_tls]. TBD
         */
        rc = 0;
    }
    return rc;
}

static apr_status_t ssl_filter_write(ap_filter_t *f,
                                     const char *data,
                                     apr_size_t len)
{
    SSLFilterRec *frec = f->ctx;
    apr_size_t n;

    /* write SSL */
    n = ssl_io_hook_write(frec->pssl, (unsigned char *)data, len);

    if (n != len) {
        conn_rec *c = f->c;
        char *reason = "reason unknown";

        /* XXX: probably a better way to determine this */
        if (SSL_total_renegotiations(frec->pssl)) {
            reason = "likely due to failed renegotiation";
        }

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->base_server,
                "failed to write %d of %d bytes (%s)",
                n > 0 ? len - n : len, len, reason);

        return APR_EINVAL;
    }

    return APR_SUCCESS;
}

static apr_status_t ssl_io_filter_Output(ap_filter_t *f,
                                         apr_bucket_brigade *bb)
{
    apr_status_t status = APR_SUCCESS;
    SSLFilterRec *frec = f->ctx;

    if (!frec->pssl) {
        /* ssl_abort() has been called */
        return ap_pass_brigade(f->next, bb);
    }

    if ((status = ssl_hook_process_connection(frec)) != APR_SUCCESS) {
        return status;
    }

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *bucket = APR_BRIGADE_FIRST(bb);

        /* If it is a flush or EOS, we need to pass this down. 
         * These types do not require translation by OpenSSL.  
         */
        if (APR_BUCKET_IS_EOS(bucket) || APR_BUCKET_IS_FLUSH(bucket)) {
            if ((status = bio_filter_out_flush(frec->pbioWrite)) != APR_SUCCESS) {
                return status;
            }

            if (APR_BUCKET_IS_EOS(bucket)) {
                /* By definition, nothing can come after EOS.
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
            /* read filter */
            const char *data;
            apr_size_t len;

            apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
            status = ssl_filter_write(f, data, len);
            apr_bucket_delete(bucket);

            if (status != APR_SUCCESS) {
                break;
            }
        }
    }

    return status;
}

static apr_status_t ssl_io_input_read(bio_filter_in_ctx_t *inctx,
                                      char *buf,
                                      apr_size_t *len)
{
    apr_size_t wanted = *len;
    apr_size_t bytes = 0;
    int rc;

    *len = 0;

    if ((bytes = char_buffer_read(&inctx->cbuf, buf, wanted))) {
        *len = bytes;
        if (inctx->mode == AP_MODE_SPECULATIVE) {
            /* We want to rollback this read. */
            inctx->cbuf.value -= bytes;
            inctx->cbuf.length += bytes;
            return APR_SUCCESS;
        } 
        if ((*len >= wanted) || inctx->mode == AP_MODE_GETLINE) {
            return APR_SUCCESS;
        }
    }

    while (1) {

        /* SSL_read may not read because we haven't taken enough data
         * from the stack.  This is where we want to consider all of
         * the blocking and SPECULATIVE semantics
         */
        rc = SSL_read(inctx->frec->pssl, buf + bytes, wanted - bytes);

        if (rc > 0) {
            *len += rc;
            if (inctx->mode == AP_MODE_SPECULATIVE) {
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
                if (inctx->block == APR_NONBLOCK_READ) {
                    break;
                }
            }
            else {
                inctx->rc = APR_EOF;
                break;
            }
        }
        else /* (rc < 0) */ {
            int ssl_err = SSL_get_error(inctx->frec->pssl, rc);

            if (ssl_err == SSL_ERROR_WANT_READ) {
                /*
                 * If OpenSSL wants to read more, and we were nonblocking,
                 * report as an EAGAIN.  Otherwise loop, pulling more
                 * data from network filter.
                 *
                 * (This is usually the case when the client forces an SSL
                 * renegotation which is handled implicitly by OpenSSL.)
                 */
                if (inctx->block == APR_NONBLOCK_READ) {
                    inctx->rc = APR_EAGAIN;
                    break; /* non fatal error */
                }
            }
            else if (ssl_err == SSL_ERROR_SYSCALL) {
                conn_rec *c = (conn_rec *)SSL_get_app_data(inctx->frec->pssl);
                ap_log_error(APLOG_MARK, APLOG_ERR, inctx->rc, c->base_server,
                            "SSL filter error reading data");
                break;
            }
            else /* if (ssl_err == SSL_ERROR_SSL) */ {
                /*
                 * Log SSL errors and any unexpected conditions.
                 */
                conn_rec *c = (conn_rec *)SSL_get_app_data(inctx->frec->pssl);
                ap_log_error(APLOG_MARK, APLOG_ERR, inctx->rc, c->base_server,
                            "SSL library error reading data");
                ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, c->base_server);

                if (inctx->rc == APR_SUCCESS) {
                    inctx->rc = APR_EGENERAL;
                }
                break;
            }
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
    inctx->frec->pssl = NULL;
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
            ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                         f->c->base_server,
                         "SSL handshake failed: HTTP spoken on HTTPS port; "
                         "trying to send HTML error page");
            ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, f->c->base_server);

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

static apr_status_t ssl_io_filter_Input(ap_filter_t *f,
                                        apr_bucket_brigade *bb,
                                        ap_input_mode_t mode,
                                        apr_read_type_e block,
                                        apr_off_t readbytes)
{
    apr_status_t status;
    bio_filter_in_ctx_t *inctx = f->ctx;

    apr_size_t len = sizeof(inctx->buffer);
    int is_init = (mode == AP_MODE_INIT);

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

    /* XXX: we could actually move ssl_hook_process_connection to an
     * ap_hook_process_connection but would still need to call it for
     * AP_MODE_INIT for protocols that may upgrade the connection
     * rather than have SSLEngine On configured.
     */
    status = ssl_hook_process_connection(inctx->frec);

    if (status != APR_SUCCESS) {
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

    if (len > 0) {
        apr_bucket *bucket =
            apr_bucket_transient_create(inctx->buffer, len, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
    }

    return APR_SUCCESS;
}

static void ssl_io_input_add_filter(SSLFilterRec *frec, conn_rec *c,
                                    SSL *ssl)
{
    bio_filter_in_ctx_t *inctx;

    inctx = apr_palloc(c->pool, sizeof(*inctx));

    frec->pInputFilter = ap_add_input_filter(ssl_io_filter, inctx, NULL, c);

    frec->pbioRead = BIO_new(&bio_filter_in_method);
    frec->pbioRead->ptr = (void *)inctx;

    inctx->frec = frec;
    inctx->ssl = ssl;
    inctx->wbio = frec->pbioWrite;
    inctx->f = frec->pInputFilter;
    inctx->bb = apr_brigade_create(c->pool, c->bucket_alloc);

    inctx->cbuf.length = 0;

    inctx->pool = c->pool;
}

static apr_status_t ssl_io_filter_cleanup (void *data)
{
    apr_status_t ret;
    SSLFilterRec *pRec = (SSLFilterRec *)data;

    if (!pRec->pssl) {
        /* already been shutdown */
        return APR_SUCCESS;
    }

    if ((ret = ssl_hook_CloseConnection(pRec)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, ret, NULL,
                     "Error in ssl_hook_CloseConnection");
    }

    return ret;
}

void ssl_io_filter_init(conn_rec *c, SSL *ssl)
{
    SSLFilterRec *filter;

    filter = apr_palloc(c->pool, sizeof(SSLFilterRec));

    filter->pOutputFilter   = ap_add_output_filter(ssl_io_filter,
                                                   filter, NULL, c);

    filter->pbioWrite       = BIO_new(&bio_filter_out_method);
    filter->pbioWrite->ptr  = (void *)bio_filter_out_ctx_new(filter, c);

    ssl_io_input_add_filter(filter, c, ssl);

    SSL_set_bio(ssl, filter->pbioRead, filter->pbioWrite);
    filter->pssl            = ssl;

    apr_pool_cleanup_register(c->pool, (void*)filter,
                              ssl_io_filter_cleanup, apr_pool_cleanup_null);

    if (c->base_server->loglevel >= APLOG_DEBUG) {
        BIO_set_callback(SSL_get_rbio(ssl), ssl_io_data_cb);
        BIO_set_callback_arg(SSL_get_rbio(ssl), (void *)ssl);
    }

    return;
}

void ssl_io_filter_register(apr_pool_t *p)
{
    ap_register_input_filter  (ssl_io_filter, ssl_io_filter_Input,  NULL, AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter (ssl_io_filter, ssl_io_filter_Output, NULL, AP_FTYPE_CONNECTION + 5);
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
