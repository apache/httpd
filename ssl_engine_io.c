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

static const char ssl_io_filter[] = "SSL/TLS Filter";

void ssl_io_register(void)
{
#if 0 /* XXX */
    ap_hook_register("ap::buff::read",   ssl_io_hook_read,  AP_HOOK_NOCTX);
    ap_hook_register("ap::buff::write",  ssl_io_hook_write, AP_HOOK_NOCTX);
#endif /* XXX */
    return;
}

void ssl_io_unregister(void)
{
#if 0 /* XXX */
    ap_hook_unregister("ap::buff::read",   ssl_io_hook_read);
    ap_hook_unregister("ap::buff::write",  ssl_io_hook_write);
#endif /* XXX */
    return;
}

static int ssl_io_hook_read(SSL *ssl, unsigned char *buf, int len)
{
    conn_rec *c;
    int rc;

    if (ssl != NULL) {
        rc = SSL_read(ssl, buf, len);
        /*
         * Simulate an EINTR in case OpenSSL wants to read more.
         * (This is usually the case when the client forces an SSL
         * renegotation which is handled implicitly by OpenSSL.)
         */
        if (rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ)
            errno = EINTR;
        /*
         * Log SSL errors
         */
        if (rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_SSL) {
            c = (conn_rec *)SSL_get_app_data(ssl);
            ssl_log(c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "SSL error on reading data");
        }
        /*
         * read(2) returns only the generic error number -1
         */
        if (rc < 0)
            /*
             * XXX - Just trying to reflect the behaviour in 
             * openssl_state_machine.c [mod_tls]. TBD
             */
            rc = 0;
    }
    else
        rc = -1;
    return rc;
}

static int ssl_io_hook_write(SSL *ssl, unsigned char *buf, int len)
{
    conn_rec *c;
    int rc;

    if (ssl != NULL) {
        rc = SSL_write(ssl, buf, len);
        /*
         * Simulate an EINTR in case OpenSSL wants to write more.
         */
        if (rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_WANT_WRITE)
            errno = EINTR;
        /*
         * Log SSL errors
         */
        if (rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_SSL) {
            c = (conn_rec *)SSL_get_app_data(ssl);
            ssl_log(c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "SSL error on writing data");
        }
        /*
         * write(2) returns only the generic error number -1
         */
        if (rc < 0)
            /*
             * XXX - Just trying to reflect the behaviour in 
             * openssl_state_machine.c [mod_tls]. TBD
             */
            rc = 0;
    }
    else
        rc = -1;
    return rc;
}

static apr_status_t churn_output(SSLFilterRec *pRec)
{
    apr_bucket_brigade *pbbOutput=NULL;
    int done;

    do {
	char buf[1024];
	int n;
	apr_bucket *pbkt;

	done=0;

	if (BIO_pending(pRec->pbioWrite)) {
            n = BIO_read(pRec->pbioWrite,buf,sizeof buf);
            if(n > 0) {
		char *pbuf;

		if(!pbbOutput)
		    pbbOutput=apr_brigade_create(pRec->pOutputFilter->c->pool);

		pbuf=apr_pmemdup(pRec->pOutputFilter->c->pool,buf,n);
		pbkt=apr_bucket_pool_create(pbuf,n,
					    pRec->pOutputFilter->c->pool);
		APR_BRIGADE_INSERT_TAIL(pbbOutput,pbkt);
		done=1;
                /*      } else if(n == 0) {
                        apr_bucket *pbktEOS=apr_bucket_create_eos();
                        APR_BRIGADE_INSERT_TAIL(pbbOutput,pbktEOS);*/
	    }
            assert (n > 0); /* XXX => Check if required */
#if 0 /* XXX */ 
            else if (n == 0)
                done = 1;
            else
                 assert (n > 0);
#endif
	}
#if 0 /* XXX */
        else
        {
            done = 1;
        }
#endif
    } while(done);
    
    /* XXX: check for errors */
    if(pbbOutput) {
	apr_bucket *pbkt;

	/* XXX: it may be possible to not always flush */
	pbkt=apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(pbbOutput,pbkt);
	ap_pass_brigade(pRec->pOutputFilter->next,pbbOutput);
    }

    return APR_SUCCESS;
}

static apr_status_t churn (SSLFilterRec *pRec,
        apr_read_type_e eReadType, apr_off_t *readbytes)
{
    apr_bucket *pbktIn;
    ap_input_mode_t eMode = (eReadType == APR_BLOCK_READ) 
                            ? AP_MODE_BLOCKING : AP_MODE_NONBLOCKING;

    /* XXX : Errrr... bad way of doing things TBD */
    eReadType = APR_BLOCK_READ;
    eMode     = AP_MODE_BLOCKING;

    if(APR_BRIGADE_EMPTY(pRec->pbbInput)) {
	ap_get_brigade(pRec->pInputFilter->next,pRec->pbbInput,eMode,readbytes);
	if(APR_BRIGADE_EMPTY(pRec->pbbInput))
	    return APR_EOF;
    }

    APR_BRIGADE_FOREACH(pbktIn,pRec->pbbInput) {
	const char *data;
	apr_size_t len;
	int n;
	char buf[1024];
	apr_status_t ret;

	if(APR_BUCKET_IS_EOS(pbktIn)) {
	    break;
	}

	/* read filter */
	ret=apr_bucket_read(pbktIn,&data,&len,eReadType);

	APR_BUCKET_REMOVE(pbktIn);

	if(ret == APR_SUCCESS && len == 0 && eReadType == APR_BLOCK_READ)
	    ret=APR_EOF;

	if(len == 0) {
	    /* Lazy frickin browsers just reset instead of shutting down. */
            if(ret == APR_EOF || APR_STATUS_IS_ECONNRESET(ret)) {
		if(APR_BRIGADE_EMPTY(pRec->pbbPendingInput))
		    return APR_EOF;
		else
		    /* Next time around, the incoming brigade will be empty,
		     * so we'll return EOF then
		     */
		    return APR_SUCCESS;
	    }
		
	    if(eReadType != APR_NONBLOCK_READ)
		ap_log_error(APLOG_MARK,APLOG_ERR,ret,NULL,
			     "Read failed in tls_in_filter");
	    assert(eReadType == APR_NONBLOCK_READ);
	    assert(ret == APR_SUCCESS || APR_STATUS_IS_EAGAIN(ret));
	    /* In this case, we have data in the output bucket, or we were
	     * non-blocking, so returning nothing is fine.
	     */
	    return APR_SUCCESS;
	}

	n = BIO_write (pRec->pbioRead, data, len);
        
        assert(n >= 0 && (apr_size_t)n == len);

        ssl_hook_process_connection (pRec);

        n = ssl_io_hook_read(pRec->pssl, (unsigned char *)buf, sizeof(buf));
	if(n > 0) {
	    apr_bucket *pbktOut;
	    char *pbuf;

	    pbuf=apr_pmemdup(pRec->pInputFilter->c->pool,buf,n);
	    /* XXX: should we use a heap bucket instead? Or a transient (in
	     * which case we need a separate brigade for each bucket)?
	     */
	    pbktOut=apr_bucket_pool_create(pbuf,n,pRec->pInputFilter->c->pool);
	    APR_BRIGADE_INSERT_TAIL(pRec->pbbPendingInput,pbktOut);

	    /* Once we've read something, we can move to non-blocking mode (if
	     * we weren't already).
	     */
	    eReadType=APR_NONBLOCK_READ;

	    /* XXX: deal with EOF! */
	    /*	} else if(n == 0) {
	    apr_bucket *pbktEOS=apr_bucket_create_eos();
	    APR_BRIGADE_INSERT_TAIL(pbbInput,pbktEOS);*/
	}
	assert(n >= 0);

	ret=churn_output(pRec);
	if(ret != APR_SUCCESS)
	    return ret;
    }

    return churn_output(pRec);
}

apr_status_t ssl_io_filter_Output(ap_filter_t *f,apr_bucket_brigade *pbbIn)
{
    SSLFilterRec *pRec=f->ctx;
    apr_bucket *pbktIn;

    APR_BRIGADE_FOREACH(pbktIn,pbbIn) {
	const char *data;
	apr_size_t len, n;
	apr_status_t ret;

	if(APR_BUCKET_IS_EOS(pbktIn)) {
	    if ((ret = churn_output(pRec)) != APR_SUCCESS)
            {
                ap_log_error(
                    APLOG_MARK,APLOG_ERR,ret,NULL, "Error in churn_output");
		return ret;
            }

            if ((ret = ssl_hook_CloseConnection (pRec)) != APR_SUCCESS)
                ap_log_error(APLOG_MARK,APLOG_ERR,ret,NULL,
                    "Error in ssl_hook_CloseConnection");
	    break;
	}

	if(APR_BUCKET_IS_FLUSH(pbktIn)) {
	    continue;
	}

	/* read filter */
	apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ);

	/* write SSL */
        n = ssl_io_hook_write(pRec->pssl, (unsigned char *)data, len);
        assert (n == len);

	/* churn the state machine */
	ret=churn_output(pRec);
	if(ret != APR_SUCCESS)
	    return ret;
    }
    return APR_SUCCESS;
}

apr_status_t ssl_io_filter_Input(ap_filter_t *f,apr_bucket_brigade *pbbOut,
                          ap_input_mode_t eMode, apr_off_t *readbytes)
{
    apr_status_t ret;
    SSLFilterRec *pRec        = f->ctx;
    apr_read_type_e eReadType = 
        (eMode == AP_MODE_BLOCKING) ? APR_BLOCK_READ : APR_NONBLOCK_READ;

    /* XXX: we don't currently support peek */
    assert(eMode != AP_MODE_PEEK);

    /* churn the state machine */
    ret = churn(pRec,eReadType,readbytes);
    if(ret != APR_SUCCESS)
	return ret;

    /* XXX: shame that APR_BRIGADE_FOREACH doesn't work here */
    while(!APR_BRIGADE_EMPTY(pRec->pbbPendingInput)) {
	apr_bucket *pbktIn=APR_BRIGADE_FIRST(pRec->pbbPendingInput);
	APR_BUCKET_REMOVE(pbktIn);
	APR_BRIGADE_INSERT_TAIL(pbbOut,pbktIn);
    }

    return APR_SUCCESS;
}

apr_status_t ssl_io_filter_cleanup (void *data)
{
    SSL *ssl = (SSL *)data;
    return APR_SUCCESS;
}

void ssl_io_filter_init(conn_rec *c, SSL *ssl)
{
    SSLFilterRec *filter;

    filter = apr_pcalloc(c->pool, sizeof(SSLFilterRec));
    filter->pInputFilter    = ap_add_input_filter(ssl_io_filter, filter, NULL, c);
    filter->pOutputFilter   = ap_add_output_filter(ssl_io_filter, filter, NULL, c);
    filter->pbbInput        = apr_brigade_create(c->pool);
    filter->pbbPendingInput = apr_brigade_create(c->pool);
    filter->pbioRead        = BIO_new(BIO_s_mem());
    filter->pbioWrite       = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, filter->pbioRead, filter->pbioWrite);
    filter->pssl            = ssl;

    apr_pool_cleanup_register(c->pool, (void*)ssl,
                              ssl_io_filter_cleanup, apr_pool_cleanup_null);

    return;
}

void ssl_io_filter_register(apr_pool_t *p)
{
    ap_register_input_filter  (ssl_io_filter, ssl_io_filter_Input,  AP_FTYPE_NETWORK);
    ap_register_output_filter (ssl_io_filter, ssl_io_filter_Output, AP_FTYPE_NETWORK);
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
