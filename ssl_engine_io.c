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

/* XXX THIS STUFF NEEDS A MAJOR CLEANUP -RSE XXX */

/* this custom BIO allows us to hook SSL_write directly into 
 * an apr_bucket_brigade and use transient buckets with the SSL
 * malloc-ed buffer, rather than copying into a mem BIO.
 * also allows us to pass the brigade as data is being written
 * rather than buffering up the entire response in the mem BIO.
 *
 * when SSL needs to flush (e.g. SSL_accept()), it will call BIO_flush()
 * which will trigger a call to bio_bucket_ctrl() -> BIO_bucket_flush().
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
} BIO_bucket_t;

static BIO_bucket_t *BIO_bucket_new(SSLFilterRec *frec, conn_rec *c)
{
    BIO_bucket_t *b = apr_palloc(c->pool, sizeof(*b));

    b->frec = frec;
    b->c = c;
    b->bb = apr_brigade_create(c->pool);
    b->blen = 0;
    b->length = 0;

    return b;
}

#define BIO_bucket_ptr(bio) (BIO_bucket_t *)bio->ptr

static int BIO_bucket_flush(BIO *bio)
{
    BIO_bucket_t *b = BIO_bucket_ptr(bio);

    if (!(b->blen || b->length)) {
        return APR_SUCCESS;
    }

    if (b->blen) {
        apr_bucket *bucket = 
            apr_bucket_transient_create(b->buffer,
                                        b->blen);
        /* we filled this buffer first so add it to the 
         * head of the brigade
         */
        APR_BRIGADE_INSERT_HEAD(b->bb, bucket);
        b->blen = 0;
    }

    b->length = 0;
    APR_BRIGADE_INSERT_TAIL(b->bb, apr_bucket_flush_create());

    return ap_pass_brigade(b->frec->pOutputFilter->next, b->bb);
}

static int bio_bucket_new(BIO *bio)
{
    bio->shutdown = 1;
    bio->init = 1;
    bio->num = -1;
    bio->ptr = NULL;

    return 1;
}

static int bio_bucket_free(BIO *bio)
{
    if (bio == NULL) {
        return 0;
    }

    /* nothing to free here.
     * apache will destroy the bucket brigade for us
     */
    return 1;
}
	
static int bio_bucket_read(BIO *bio, char *out, int outl)
{
    /* this is never called */
    return -1;
}

static int bio_bucket_write(BIO *bio, const char *in, int inl)
{
    BIO_bucket_t *b = BIO_bucket_ptr(bio);

    /* when handshaking we'll have a small number of bytes.
     * max size SSL will pass us here is about 16k.
     * (16413 bytes to be exact)
     */
    BIO_clear_retry_flags(bio);

    if (!b->length && (inl + b->blen < sizeof(b->buffer))) {
        /* the first two SSL_writes (of 1024 and 261 bytes)
         * need to be in the same packet (vec[0].iov_base)
         */
        /* XXX: could use apr_brigade_write() to make code look cleaner
         * but this way we avoid the malloc(APR_BUCKET_BUFF_SIZE)
         * and free() of it later
         */
        memcpy(&b->buffer[b->blen], in, inl);
        b->blen += inl;
    }
    else {
        /* pass along the encrypted data
         * need to flush since we're using SSL's malloc-ed buffer 
         * which will be overwritten once we leave here
         */
        apr_bucket *bucket = apr_bucket_transient_create(in, inl);

        b->length += inl;
        APR_BRIGADE_INSERT_TAIL(b->bb, bucket);

        BIO_bucket_flush(bio);
    }

    return inl;
}

static long bio_bucket_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;
    char **pptr;

    BIO_bucket_t *b = BIO_bucket_ptr(bio);

    switch (cmd) {
      case BIO_CTRL_RESET:
        b->blen = b->length = 0;
        break;
      case BIO_CTRL_EOF:
        ret = (long)((b->blen + b->length) == 0);
        break;
      case BIO_C_SET_BUF_MEM_EOF_RETURN:
        b->blen = b->length = (apr_size_t)num;
        break;
      case BIO_CTRL_INFO:
        ret = (long)(b->blen + b->length);
        if (ptr) {
            pptr = (char **)ptr;
            *pptr = (char *)&(b->buffer[0]);
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
        ret = (long)(b->blen + b->length);
        break;
      case BIO_CTRL_FLUSH:
        ret = (BIO_bucket_flush(bio) == APR_SUCCESS);
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

static int bio_bucket_gets(BIO *bio, char *buf, int size)
{
    /* this is never called */
    return -1;
}

static int bio_bucket_puts(BIO *bio, const char *str)
{
    /* this is never called */
    return -1;
}

static BIO_METHOD bio_bucket_method = {
    BIO_TYPE_MEM,
    "APR bucket brigade",
    bio_bucket_write,
    bio_bucket_read,
    bio_bucket_puts,
    bio_bucket_gets,
    bio_bucket_ctrl,
    bio_bucket_new,
    bio_bucket_free,
#ifdef OPENSSL_VERSION_NUMBER
    NULL /* sslc does not have the callback_ctrl field */
#endif
};

static BIO_METHOD *BIO_s_bucket(void)
{
    return &bio_bucket_method;
}

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
    apr_bucket *bucket;
    char_buffer_t cbuf;
} BIO_bucket_in_t;

typedef struct {
    BIO_bucket_in_t inbio;
    char_buffer_t cbuf;
    apr_pool_t *pool;
    char buffer[AP_IOBUFSIZE];
    SSLFilterRec *frec;
} ssl_io_input_ctx_t;

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

/*
 * this is the function called by SSL_read()
 */
#define BIO_bucket_in_ptr(bio) (BIO_bucket_in_t *)bio->ptr

static int bio_bucket_in_read(BIO *bio, char *in, int inl)
{
    BIO_bucket_in_t *inbio = BIO_bucket_in_ptr(bio);
    int len = 0;

    /* XXX: flush here only required for SSLv2;
     * OpenSSL calls BIO_flush() at the appropriate times for
     * the other protocols.
     */
    if (SSL_version(inbio->ssl) == SSL2_VERSION) {
        BIO_bucket_flush(inbio->wbio);
    }

    inbio->rc = APR_SUCCESS;
    
    /* first use data already read from socket if any */
    if ((len = char_buffer_read(&inbio->cbuf, in, inl))) {
        if ((len <= inl) || inbio->mode == AP_MODE_GETLINE) {
            return len;
        }
        inl -= len;
    }

    while (1) {
        const char *buf;
        apr_size_t buf_len = 0;

        if (inbio->bucket) {
            /* all of the data in this bucket has been read,
             * so we can delete it now.
             */
            apr_bucket_delete(inbio->bucket);
            inbio->bucket = NULL;
        }

        if (APR_BRIGADE_EMPTY(inbio->bb)) {
            /* We will always call with READBYTES even if the user wants
             * GETLINE.
             */
            inbio->rc = ap_get_brigade(inbio->f->next, inbio->bb,
                                       AP_MODE_READBYTES, inbio->block, 
                                       inl);

            if ((inbio->rc != APR_SUCCESS) || APR_BRIGADE_EMPTY(inbio->bb))
            {
                break;
            }
        }

        inbio->bucket = APR_BRIGADE_FIRST(inbio->bb);

        inbio->rc = apr_bucket_read(inbio->bucket,
                                    &buf, &buf_len, inbio->block);

        if (inbio->rc != APR_SUCCESS) {
            apr_bucket_delete(inbio->bucket);
            inbio->bucket = NULL;
            return len;
        }

        if (buf_len) {
            /* Protected against len > MAX_INT 
             */
            if ((len + (int)buf_len) >= inl || (int)buf_len < 0) {
                /* we have enough to fill the buffer.
                 * append if we have already written to the buffer.
                 */
                int nibble = inl - len;
                char *value = (char *)buf+nibble;

                int length = buf_len - nibble;
                memcpy(in + len, buf, nibble);

                char_buffer_write(&inbio->cbuf, value, length);
                len += nibble;

                break;
            }
            else {
                /* not enough data,
                 * save what we have and try to read more.
                 */
                memcpy(in + len, buf, buf_len);
                len += buf_len;
            }
        }

        if (inbio->mode == AP_MODE_GETLINE) {
            /* only read from the socket once in getline mode.
             * since callers buffer size is likely much larger than
             * the request headers.  caller can always come back for more
             * if first read didn't get all the headers.
             */
            break;
        }
    }

    return len;
}

static BIO_METHOD bio_bucket_in_method = {
    BIO_TYPE_MEM,
    "APR input bucket brigade",
    NULL,                       /* write is never called */
    bio_bucket_in_read,
    NULL,                       /* puts is never called */
    NULL,                       /* gets is never called */
    NULL,                       /* ctrl is never called */
    bio_bucket_new,
    bio_bucket_free,
#ifdef OPENSSL_VERSION_NUMBER
    NULL /* sslc does not have the callback_ctrl field */
#endif
};

static BIO_METHOD *BIO_s_in_bucket(void)
{
    return &bio_bucket_in_method;
}

static const char ssl_io_filter[] = "SSL/TLS Filter";

static int ssl_io_hook_read(SSL *ssl, char *buf, int len)
{
    int rc;

    if (ssl == NULL) {
        return -1;
    }

    rc = SSL_read(ssl, buf, len);

    if (rc < 0) {
        int ssl_err = SSL_get_error(ssl, rc);

        if (ssl_err == SSL_ERROR_WANT_READ) {
            /*
             * Simulate an EINTR in case OpenSSL wants to read more.
             * (This is usually the case when the client forces an SSL
             * renegotation which is handled implicitly by OpenSSL.)
             */
            errno = EINTR;
        }
        else if (ssl_err == SSL_ERROR_SSL) {
            /*
             * Log SSL errors
             */
            conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
            ssl_log(c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "SSL error on reading data");
        }
        /*
         * XXX - Just trying to reflect the behaviour in 
         * openssl_state_machine.c [mod_tls]. TBD
         */
        rc = -1;
    }
    return rc;
}

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
            ssl_log(c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "SSL error on writing data");
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
    SSLFilterRec *ctx = f->ctx;
    apr_size_t n;

    /* write SSL */
    n = ssl_io_hook_write(ctx->pssl, (unsigned char *)data, len);

    if (n != len) {
        conn_rec *c = f->c;
        char *reason = "reason unknown";

        /* XXX: probably a better way to determine this */
        if (SSL_total_renegotiations(ctx->pssl)) {
            reason = "likely due to failed renegotiation";
        }

        ssl_log(c->base_server, SSL_LOG_ERROR,
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

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *bucket = APR_BRIGADE_FIRST(bb);

        /* If it is a flush or EOS, we need to pass this down. 
         * These types do not require translation by OpenSSL.  
         */
        if (APR_BUCKET_IS_EOS(bucket) || APR_BUCKET_IS_FLUSH(bucket)) {
            SSLFilterRec *ctx = f->ctx;

            if ((status = BIO_bucket_flush(ctx->pbioWrite)) != APR_SUCCESS) {
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
                /* BIO_bucket_flush() already passed down a flush bucket
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

/*
 * ctx->cbuf is leftover plaintext from ssl_io_input_getline,
 * use what we have there first if any,
 * then go for more by calling ssl_io_hook_read.
 */
static apr_status_t ssl_io_input_read(ssl_io_input_ctx_t *ctx,
                                      char *buf,
                                      apr_size_t *len)
{
    apr_size_t wanted = *len;
    apr_size_t bytes = 0;
    int rc;

    *len = 0;

    if ((bytes = char_buffer_read(&ctx->cbuf, buf, wanted))) {
        *len = bytes;
        if (ctx->inbio.mode == AP_MODE_SPECULATIVE) {
            /* We want to rollback this read. */
            ctx->cbuf.value -= bytes;
            ctx->cbuf.length += bytes;
            return APR_SUCCESS;
        } 
        if ((*len >= wanted) || ctx->inbio.mode == AP_MODE_GETLINE) {
            return APR_SUCCESS;
        }
    }

    rc = ssl_io_hook_read(ctx->frec->pssl, buf + bytes, wanted - bytes);

    if (rc > 0) {
        *len += rc;
        if (ctx->inbio.mode == AP_MODE_SPECULATIVE) {
            char_buffer_write(&ctx->cbuf, buf, rc);
        }
    }

    return ctx->inbio.rc;
}

static apr_status_t ssl_io_input_getline(ssl_io_input_ctx_t *ctx,
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
     * /

    while (tmplen > 0) {
        status = ssl_io_input_read(ctx, buf + offset, &tmplen);
        
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

        char_buffer_write(&ctx->cbuf, value, length);

        *len = bytes;
    }

    return APR_SUCCESS;
}

#define HTTP_ON_HTTPS_PORT \
    "GET /mod_ssl:error:HTTP-request HTTP/1.0\r\n\r\n"

#define HTTP_ON_HTTPS_PORT_BUCKET() \
    apr_bucket_immortal_create(HTTP_ON_HTTPS_PORT, \
                               sizeof(HTTP_ON_HTTPS_PORT) - 1)

static apr_status_t ssl_io_filter_error(ap_filter_t *f,
                                        apr_bucket_brigade *bb,
                                        apr_status_t status)
{
    apr_bucket *bucket;

    switch (status) {
      case HTTP_BAD_REQUEST:
            /* log the situation */
            ssl_log(f->c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "SSL handshake failed: HTTP spoken on HTTPS port; "
                    "trying to send HTML error page");

            /* fake the request line */
            bucket = HTTP_ON_HTTPS_PORT_BUCKET();
            break;

      default:
        return status;
    }

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
    ssl_io_input_ctx_t *ctx = f->ctx;

    apr_size_t len = sizeof(ctx->buffer);
    int is_init = (mode == AP_MODE_INIT);

    /* XXX: we don't currently support anything other than these modes. */
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE && 
        mode != AP_MODE_SPECULATIVE && mode != AP_MODE_INIT) {
        return APR_ENOTIMPL;
    }

    ctx->inbio.mode = mode;
    ctx->inbio.block = block;

    /* XXX: we could actually move ssl_hook_process_connection to an
     * ap_hook_process_connection but would still need to call it for
     * AP_MODE_INIT for protocols that may upgrade the connection
     * rather than have SSLEngine On configured.
     */
    status = ssl_hook_process_connection(ctx->frec);

    if (status != APR_SUCCESS) {
        return ssl_io_filter_error(f, bb, status);
    }

    if (is_init) {
        /* protocol module needs to handshake before sending
         * data to client (e.g. NNTP or FTP)
         */
        return APR_SUCCESS;
    }

    if (ctx->inbio.mode == AP_MODE_READBYTES || 
        ctx->inbio.mode == AP_MODE_SPECULATIVE) {
        /* Protected from truncation, readbytes < MAX_SIZE_T 
         * FIXME: No, it's *not* protected.  -- jre */
        if (readbytes < len) {
            len = (apr_size_t)readbytes;
        }
        status = ssl_io_input_read(ctx, ctx->buffer, &len);
    }
    else if (ctx->inbio.mode == AP_MODE_GETLINE) {
        status = ssl_io_input_getline(ctx, ctx->buffer, &len);
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
            apr_bucket_transient_create(ctx->buffer, len);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
    }

    return APR_SUCCESS;
}

static void ssl_io_input_add_filter(SSLFilterRec *frec, conn_rec *c,
                                    SSL *ssl)
{
    ssl_io_input_ctx_t *ctx;

    ctx = apr_palloc(c->pool, sizeof(*ctx));

    frec->pInputFilter = ap_add_input_filter(ssl_io_filter, ctx, NULL, c);

    frec->pbioRead = BIO_new(BIO_s_in_bucket());
    frec->pbioRead->ptr = &ctx->inbio;

    ctx->frec = frec;
    ctx->inbio.ssl = ssl;
    ctx->inbio.wbio = frec->pbioWrite;
    ctx->inbio.f = frec->pInputFilter;
    ctx->inbio.bb = apr_brigade_create(c->pool);
    ctx->inbio.bucket = NULL;
    ctx->inbio.cbuf.length = 0;

    ctx->cbuf.length = 0;

    ctx->pool = c->pool;
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
    SSLSrvConfigRec *sc = mySrvConfig(c->base_server);
    SSLFilterRec *filter;

    filter = apr_palloc(c->pool, sizeof(SSLFilterRec));

    filter->pOutputFilter   = ap_add_output_filter(ssl_io_filter,
                                                   filter, NULL, c);

    filter->pbioWrite       = BIO_new(BIO_s_bucket());
    filter->pbioWrite->ptr  = BIO_bucket_new(filter, c);

    ssl_io_input_add_filter(filter, c, ssl);

    SSL_set_bio(ssl, filter->pbioRead, filter->pbioWrite);
    filter->pssl            = ssl;

    apr_pool_cleanup_register(c->pool, (void*)filter,
                              ssl_io_filter_cleanup, apr_pool_cleanup_null);

    if (sc->nLogLevel >= SSL_LOG_DEBUG) {
        BIO_set_callback(SSL_get_rbio(ssl), ssl_io_data_cb);
        BIO_set_callback_arg(SSL_get_rbio(ssl), ssl);
    }

    return;
}

void ssl_io_filter_register(apr_pool_t *p)
{
    ap_register_input_filter  (ssl_io_filter, ssl_io_filter_Input,  AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter (ssl_io_filter, ssl_io_filter_Output, AP_FTYPE_CONNECTION + 5);
    return;
}

/*  _________________________________________________________________
**
**  I/O Data Debugging
**  _________________________________________________________________
*/

#define DUMP_WIDTH 16

static void ssl_io_data_dump(server_rec *srvr, const char *s, long len)
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
    ssl_log(srvr, SSL_LOG_DEBUG|SSL_NO_TIMESTAMP|SSL_NO_LEVELID,
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
        ssl_log(srvr, SSL_LOG_DEBUG|SSL_NO_TIMESTAMP|SSL_NO_LEVELID, "%s", buf);
    }
    if (trunc > 0)
        ssl_log(srvr, SSL_LOG_DEBUG|SSL_NO_TIMESTAMP|SSL_NO_LEVELID,
                "| %04x - <SPACES/NULS>", len + trunc);
    ssl_log(srvr, SSL_LOG_DEBUG|SSL_NO_TIMESTAMP|SSL_NO_LEVELID,
            "+-------------------------------------------------------------------------+");
    return;
}

long ssl_io_data_cb(BIO *bio, int cmd, const char *argp, int argi, long argl, long rc)
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
            ssl_log(s, SSL_LOG_DEBUG,
                    "%s: %s %ld/%d bytes %s BIO#%08X [mem: %08lX] %s",
                    SSL_LIBRARY_NAME,
                    (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "write" : "read"),
                    rc, argi, (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "to" : "from"),
                    bio, argp,
                    (argp != NULL ? "(BIO dump follows)" : "(Ops, no memory buffer?)"));
            if (argp != NULL)
                ssl_io_data_dump(s, argp, rc);
        }
        else {
            ssl_log(s, SSL_LOG_DEBUG,
                    "%s: I/O error, %d bytes expected to %s on BIO#%08X [mem: %08lX]",
                    SSL_LIBRARY_NAME, argi,
                    (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "write" : "read"),
                    bio, argp);
        }
    }
    return rc;
}
