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
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

    if (!b->length && (inl < (sizeof(b->buffer) - b->blen))) {
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
    NULL,
};

static BIO_METHOD *BIO_s_bucket(void)
{
    return &bio_bucket_method;
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

static apr_status_t churn_output(SSLFilterRec *ctx)
{
    if (!ctx->pssl) {
        /* we've been shutdown */
        return APR_EOF;
    }

    return BIO_bucket_flush(ctx->pbioWrite);
}

#define bio_is_renegotiating(bio) \
(((int)BIO_get_callback_arg(bio)) == SSL_ST_RENEGOTIATE)
#define HTTP_ON_HTTPS_PORT "GET /mod_ssl:error:HTTP-request HTTP/1.0\r\n"

static apr_status_t churn_input(SSLFilterRec *pRec, ap_input_mode_t eMode, 
                                apr_off_t *readbytes)
{
    ap_filter_t *f = pRec->pInputFilter;
    SSLFilterRec *ctx = pRec;
    conn_rec *c = f->c;
    apr_pool_t *p = c->pool;
    apr_bucket *e;
    int found_eos = 0, n;
    char buf[1024];
    apr_status_t rv;
    int do_handshake = (eMode == AP_MODE_INIT);
 
    if (do_handshake) {
        /* protocol module needs to handshake before sending
         * data to client (e.g. NNTP or FTP)
         */
        *readbytes = AP_IOBUFSIZE;
        eMode = AP_MODE_NONBLOCKING;
    }

    /* Flush the output buffers. */
    churn_output(pRec);

    /* We have something in the processed brigade.  Use that first. */
    if (!APR_BRIGADE_EMPTY(ctx->b)) {
        return APR_SUCCESS;
    }

    /* If we have nothing in the raw brigade, get some more. */
    if (APR_BRIGADE_EMPTY(ctx->rawb)) {
        if (do_handshake) {
            /* 
             * ap_get_brigade with AP_MODE_INIT should always be called
             * in non-blocking mode, but we need to block here
             */
            eMode = AP_MODE_BLOCKING;
        }
        rv = ap_get_brigade(f->next, ctx->rawb, eMode, readbytes);

        if (rv != APR_SUCCESS)
            return rv;

        /* Can't make any progress here. */
        if (*readbytes == 0)
        {
            /* This means that we have nothing else to read ever. */
            if (eMode == AP_MODE_BLOCKING) {
                APR_BRIGADE_INSERT_TAIL(ctx->b, apr_bucket_eos_create());
            }
            return APR_SUCCESS;
        }
    }

    /* Process anything we have that we haven't done so already. */
    while (!APR_BRIGADE_EMPTY(ctx->rawb)) {
        const char *data;
        apr_size_t len;

        e = APR_BRIGADE_FIRST(ctx->rawb);

        if (APR_BUCKET_IS_EOS(e)) {
            apr_bucket_delete(e);
            found_eos = 1;
            break;
        }

        /* read from the bucket */
        rv = apr_bucket_read(e, &data, &len, eMode);

        if (rv != APR_SUCCESS)
            return rv;

        /* Write it to our BIO */
	    n = BIO_write(pRec->pbioRead, data, len);
        
        if ((apr_size_t)n != len) {
            /* this should never really happen, since we're just writing
             * into a memory buffer, unless, of course, we run out of 
             * memory
             */
            ssl_log(c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "attempting to write %d bytes to rbio, only wrote %d",
                    len, n);
            return APR_ENOMEM;
        }

        /* If we reached here, we read the bucket successfully, so toss
         * it from the raw brigade. */
        apr_bucket_delete(e);

    }

    /* Flush the output buffers. */
    churn_output(pRec);

    /* Note: ssl_engine_kernel.c calls ap_get_brigade when it wants to 
     * renegotiate.  Therefore, we must handle this by reading from
     * the socket and *NOT* reading into ctx->b from the BIO.  This is a 
     * very special case and needs to be treated as such.
     *
     * We need to tell all of the higher level filters that we didn't
     * return anything.  OpenSSL will know that we did anyway and try to
     * read directly via our BIO.
     */
    if (bio_is_renegotiating(pRec->pbioRead)) {
        return APR_SUCCESS;
    }

    /* Before we actually read any unencrypted data, go ahead and
     * let ssl_hook_process_connection have a shot at it. 
     */
    rv = ssl_hook_process_connection(pRec);

    if (do_handshake && (rv == APR_SUCCESS)) {
        /* don't block after the handshake */
        eMode = AP_MODE_NONBLOCKING;
    }

    /* Flush again. */
    churn_output(pRec);

    if (rv != APR_SUCCESS) {
        /* if process connection says HTTP_BAD_REQUEST, we've seen a 
         * HTTP on HTTPS error.
         *
         * The case where OpenSSL has recognized a HTTP request:
         * This means the client speaks plain HTTP on our HTTPS port.
         * Hmmmm...  At least for this error we can be more friendly
         * and try to provide him with a HTML error page. We have only
         * one problem:OpenSSL has already read some bytes from the HTTP
         * request. So we have to skip the request line manually and
         * instead provide a faked one in order to continue the internal
         * Apache processing.
         *
         */
        if (rv == HTTP_BAD_REQUEST) {
            /* log the situation */
            ssl_log(c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "SSL handshake failed: HTTP spoken on HTTPS port; "
                    "trying to send HTML error page");

            /* fake the request line */
            e = apr_bucket_immortal_create(HTTP_ON_HTTPS_PORT,
                                           sizeof(HTTP_ON_HTTPS_PORT) - 1);
            APR_BRIGADE_INSERT_TAIL(ctx->b, e);
            e = apr_bucket_immortal_create(CRLF, sizeof(CRLF) - 1);
            APR_BRIGADE_INSERT_TAIL(ctx->b, e);

            return APR_SUCCESS;
        }
        if (rv == SSL_ERROR_WANT_READ) {
            /* if eMode was originally AP_MODE_INIT,
             * need to reset before we recurse
             */
            ap_input_mode_t mode = do_handshake ? AP_MODE_INIT : eMode;
            apr_off_t tempread = AP_IOBUFSIZE;
            return churn_input(pRec, mode, &tempread);
        }
        return rv;
    }

    /* try to pass along all of the current BIO to ctx->b */
    /* FIXME: If there's an error and there was EOS, we may not really
     * reach EOS.
     */
    while ((n = ssl_io_hook_read(pRec->pssl, buf, sizeof(buf))) > 0) {
        char *pbuf;

        pbuf = apr_pmemdup(p, buf, n);
        e = apr_bucket_pool_create(pbuf, n, p);
        APR_BRIGADE_INSERT_TAIL(ctx->b, e);

        /* Flush the output buffers. */
        churn_output(pRec);
    }

    if (n < 0 && errno == EINTR && APR_BRIGADE_EMPTY(ctx->b)) {
        apr_off_t tempread = AP_IOBUFSIZE;
        return churn_input(pRec, eMode, &tempread);
    }

    if (found_eos) {
        APR_BRIGADE_INSERT_TAIL(ctx->b, apr_bucket_eos_create());
    }

    return churn_output(pRec);
}

static apr_status_t ssl_io_filter_Output(ap_filter_t *f,
                                         apr_bucket_brigade *bb)
{
    SSLFilterRec *ctx = f->ctx;
    apr_bucket *bucket;
    apr_status_t ret = APR_SUCCESS;

    while (!APR_BRIGADE_EMPTY(bb)) {
        const char *data;
        apr_size_t len, n;

        bucket = APR_BRIGADE_FIRST(bb);

        /* If it is a flush or EOS, we need to pass this down. 
         * These types do not require translation by OpenSSL.  
         */
        if (APR_BUCKET_IS_EOS(bucket) || APR_BUCKET_IS_FLUSH(bucket)) {
            apr_bucket_brigade *outbb;
            int done = APR_BUCKET_IS_EOS(bucket);

            if ((ret = churn_output(ctx)) != APR_SUCCESS) {
                return ret;
            }

            outbb = apr_brigade_create(f->c->pool);
            APR_BUCKET_REMOVE(bucket);
            APR_BRIGADE_INSERT_TAIL(outbb, bucket);
            ret = ap_pass_brigade(f->next, outbb);
            if (ret != APR_SUCCESS) {
                return ret;
            }

            /* By definition, nothing can come after EOS. */
            if (done) {
                break;
            }
        }
        else {
            /* read filter */
            apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);

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

                ret = APR_EINVAL;
                break;
            }

            /* churn the state machine */
            if ((ret = churn_output(ctx)) != APR_SUCCESS) {
                break;
            }

            apr_bucket_delete(bucket);
        }
    }

    apr_brigade_destroy(bb);
    return ret;
}

static apr_status_t ssl_io_filter_Input(ap_filter_t *f,
                                        apr_bucket_brigade *pbbOut,
                                        ap_input_mode_t mode,
                                        apr_off_t *readbytes)
{
    apr_status_t ret;
    SSLFilterRec *ctx = f->ctx;
    apr_status_t rv;
    apr_bucket *e;
    apr_off_t tempread;

    /* XXX: we don't currently support peek or readbytes == -1 */
    if (mode == AP_MODE_PEEK || *readbytes == -1) {
        return APR_ENOTIMPL;
    }

    /* Return the requested amount or less. */
    if (*readbytes)
    {
        apr_bucket_brigade *newbb;

        /* ### This is bad. */
        APR_BRIGADE_NORMALIZE(ctx->b);

        /* churn the state machine */
        ret = churn_input(ctx, mode, readbytes);

        if (ret != APR_SUCCESS)
	        return ret;

        apr_brigade_length(ctx->b, 0, &tempread);

        if (*readbytes < tempread) {
            tempread = *readbytes;
        } 
        else {
            *readbytes = tempread;
        }
        
        apr_brigade_partition(ctx->b, tempread, &e);
        newbb = apr_brigade_split(ctx->b, e);
        APR_BRIGADE_CONCAT(pbbOut, ctx->b);
        APR_BRIGADE_CONCAT(ctx->b, newbb);

        return APR_SUCCESS;
    }
   
    /* Readbytes == 0 implies we only want a LF line. */
    if (APR_BRIGADE_EMPTY(ctx->b)) {
        tempread = AP_IOBUFSIZE;
        rv = churn_input(ctx, mode, &tempread);
        if (rv != APR_SUCCESS)
            return rv;
        /* We have already blocked. */
        mode = AP_MODE_NONBLOCKING;
    }
    while (!APR_BRIGADE_EMPTY(ctx->b)) {
        const char *pos, *str;
        apr_size_t len;

        e = APR_BRIGADE_FIRST(ctx->b);

        /* Sure, we'll call this is a line.  Whatever. */
        if (APR_BUCKET_IS_EOS(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(pbbOut, e);
            break;
        }

        if ((rv = apr_bucket_read(e, &str, &len, 
                                  AP_MODE_NONBLOCKING)) != APR_SUCCESS) {
            return rv;
        }

        pos = memchr(str, APR_ASCII_LF, len);
        /* We found a match. */
        if (pos != NULL) {
            apr_bucket_split(e, pos - str + 1);
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(pbbOut, e);
            *readbytes += pos - str;
            return APR_SUCCESS;
        }
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(pbbOut, e);
        *readbytes += len;

        /* Hey, we're about to be starved - go fetch more data. */
        if (APR_BRIGADE_EMPTY(ctx->b)) {
            tempread = AP_IOBUFSIZE;
            ret = churn_input(ctx, mode, &tempread);
            if (ret != APR_SUCCESS)
	            return ret;
            mode = AP_MODE_NONBLOCKING;
        }
    }

    return APR_SUCCESS;
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

    filter = apr_pcalloc(c->pool, sizeof(SSLFilterRec));
    filter->pInputFilter    = ap_add_input_filter(ssl_io_filter, filter, NULL, c);
    filter->pOutputFilter   = ap_add_output_filter(ssl_io_filter, filter, NULL, c);
    filter->b               = apr_brigade_create(c->pool);
    filter->rawb            = apr_brigade_create(c->pool);
    filter->pbioRead        = BIO_new(BIO_s_mem());
    filter->pbioWrite       = BIO_new(BIO_s_bucket());
    filter->pbioWrite->ptr  = BIO_bucket_new(filter, c);
    SSL_set_bio(ssl, filter->pbioRead, filter->pbioWrite);
    filter->pssl            = ssl;

    apr_pool_cleanup_register(c->pool, (void*)filter,
                              ssl_io_filter_cleanup, apr_pool_cleanup_null);

    if (sc->nLogLevel >= SSL_LOG_DEBUG) {
        /* XXX: this will currently get wiped out if renegotiation
         * happens in ssl_hook_Access
         */
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
