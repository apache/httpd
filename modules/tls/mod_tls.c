/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2001 The Apache Software Foundation.  All rights
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
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#include "httpd.h"
#include "http_config.h"
#include "util_filter.h"
#include "http_connection.h"
#include "openssl_state_machine.h"
#include "apr_strings.h"
#include "http_protocol.h"
#include "http_log.h"

/* temp */
#include <assert.h>

module AP_MODULE_DECLARE_DATA tls_module;
static const char s_szTLSFilterName[]="TLSFilter";
typedef struct
{
    int bEnabled;
    const char *szCertificateFile;
    const char *szKeyFile;
} TLSServerConfig;

typedef struct
{
    SSLStateMachine *pStateMachine;
    ap_filter_t *pInputFilter;
    ap_filter_t *pOutputFilter;
    apr_bucket_brigade *pbbInput;		/* encrypted input */
    apr_bucket_brigade *pbbPendingInput;	/* decrypted input */
} TLSFilterCtx;

static void *create_tls_server_config(apr_pool_t *p, server_rec *s)
{
    TLSServerConfig *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->bEnabled = 0;
    pConfig->szCertificateFile = pConfig->szKeyFile = NULL;

    return pConfig;
}

static const char *tls_on(cmd_parms *cmd, void *dummy, int arg)
{
    TLSServerConfig *pConfig = ap_get_module_config(cmd->server->module_config,
						    &tls_module);
    pConfig->bEnabled = arg;

    return NULL;
}

static const char *tls_cert_file(cmd_parms *cmd, void *dummy, const char *arg)
{
    TLSServerConfig *pConfig = ap_get_module_config(cmd->server->module_config,
						    &tls_module);
    pConfig->szCertificateFile = ap_server_root_relative(cmd->pool, arg);

    /* temp */
    pConfig->szKeyFile=pConfig->szCertificateFile;

    return NULL;
}

static apr_status_t tls_filter_cleanup(void *data)
{
    SSLStateMachine_destroy((SSLStateMachine *)data);
    return APR_SUCCESS;
}

static int tls_filter_inserter(conn_rec *c)
{
    TLSServerConfig *pConfig =
      ap_get_module_config(c->base_server->module_config,
			   &tls_module);
    TLSFilterCtx *pCtx;

    if (!pConfig->bEnabled)
        return DECLINED;

    pCtx=apr_pcalloc(c->pool,sizeof *pCtx);
    pCtx->pStateMachine=SSLStateMachine_new(pConfig->szCertificateFile,
					    pConfig->szKeyFile);

    pCtx->pInputFilter=ap_add_input_filter(s_szTLSFilterName,pCtx,NULL,c);
    pCtx->pOutputFilter=ap_add_output_filter(s_szTLSFilterName,pCtx,NULL,c);
    pCtx->pbbInput=apr_brigade_create(c->pool);
    pCtx->pbbPendingInput=apr_brigade_create(c->pool);

    apr_pool_cleanup_register(c->pool, (void*)pCtx->pStateMachine,
                              tls_filter_cleanup, apr_pool_cleanup_null);

    return OK;
}

static apr_status_t churn_output(TLSFilterCtx *pCtx)
{
    apr_bucket_brigade *pbbOutput=NULL;
    int done;

    do {
	char buf[1024];
	int n;
	apr_bucket *pbkt;

	done=0;

	if(SSLStateMachine_write_can_extract(pCtx->pStateMachine)) {
	    n=SSLStateMachine_write_extract(pCtx->pStateMachine,buf,
					    sizeof buf);
	    if(n > 0) {
		char *pbuf;

		if(!pbbOutput)
		    pbbOutput=apr_brigade_create(pCtx->pOutputFilter->c->pool);

		pbuf=apr_pmemdup(pCtx->pOutputFilter->c->pool,buf,n);
		pbkt=apr_bucket_pool_create(pbuf,n,
					    pCtx->pOutputFilter->c->pool);
		APR_BRIGADE_INSERT_TAIL(pbbOutput,pbkt);
		done=1;
		/*	} else if(n == 0) {
			apr_bucket *pbktEOS=apr_bucket_create_eos();
			APR_BRIGADE_INSERT_TAIL(pbbOutput,pbktEOS);*/
	    }
	    assert(n > 0);
	}
    } while(done);
    
    /* XXX: check for errors */
    if(pbbOutput) {
	apr_bucket *pbkt;

	/* XXX: it may be possible to not always flush */
	pbkt=apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(pbbOutput,pbkt);
	ap_pass_brigade(pCtx->pOutputFilter->next,pbbOutput);
    }

    return APR_SUCCESS;
}

static apr_status_t churn(TLSFilterCtx *pCtx,apr_read_type_e eReadType,apr_size_t *readbytes)
{
    ap_input_mode_t eMode=eReadType == APR_BLOCK_READ ? AP_MODE_BLOCKING
      : AP_MODE_NONBLOCKING;
    apr_bucket *pbktIn;

    if(APR_BRIGADE_EMPTY(pCtx->pbbInput)) {
	ap_get_brigade(pCtx->pInputFilter->next,pCtx->pbbInput,eMode,readbytes);
	if(APR_BRIGADE_EMPTY(pCtx->pbbInput))
	    return APR_EOF;
    }

    APR_BRIGADE_FOREACH(pbktIn,pCtx->pbbInput) {
	const char *data;
	apr_size_t len;
	int n;
	char buf[1024];
	apr_status_t ret;

	if(APR_BUCKET_IS_EOS(pbktIn)) {
	    /* XXX: why can't I reuse pbktIn??? */
	    /* Write eof! */
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
		if(APR_BRIGADE_EMPTY(pCtx->pbbPendingInput))
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

	assert(len > 0);

	/* write SSL */
	SSLStateMachine_read_inject(pCtx->pStateMachine,data,len);

	n=SSLStateMachine_read_extract(pCtx->pStateMachine,buf,sizeof buf);
	if(n > 0) {
	    apr_bucket *pbktOut;
	    char *pbuf;

	    pbuf=apr_pmemdup(pCtx->pInputFilter->c->pool,buf,n);
	    /* XXX: should we use a heap bucket instead? Or a transient (in
	     * which case we need a separate brigade for each bucket)?
	     */
	    pbktOut=apr_bucket_pool_create(pbuf,n,pCtx->pInputFilter->c->pool);
	    APR_BRIGADE_INSERT_TAIL(pCtx->pbbPendingInput,pbktOut);

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

	ret=churn_output(pCtx);
	if(ret != APR_SUCCESS)
	    return ret;
    }

    return churn_output(pCtx);
}

static apr_status_t tls_out_filter(ap_filter_t *f,apr_bucket_brigade *pbbIn)
{
    TLSFilterCtx *pCtx=f->ctx;
    apr_bucket *pbktIn;

    APR_BRIGADE_FOREACH(pbktIn,pbbIn) {
	const char *data;
	apr_size_t len;
	apr_status_t ret;

	if(APR_BUCKET_IS_EOS(pbktIn)) {
	    /* XXX: demote to debug */
	    ap_log_error(APLOG_MARK,APLOG_ERR,0,NULL,"Got EOS on output");
	    SSLStateMachine_write_close(pCtx->pStateMachine);
	    /* XXX: dubious - does this always terminate? Does it return the right thing? */
	    for( ; ; ) {
		ret=churn_output(pCtx);
		if(ret != APR_SUCCESS)
		    return ret;
		ret=churn(pCtx,APR_NONBLOCK_READ,0);
		if(ret != APR_SUCCESS) {
		    if(ret == APR_EOF)
			return APR_SUCCESS;
		    else
			return ret;
		}
	    }
	    break;
	}

	if(APR_BUCKET_IS_FLUSH(pbktIn)) {
	    /* assume that churn will flush (or already has) if there's output */
	    ret=churn(pCtx,APR_NONBLOCK_READ,0);
	    if(ret != APR_SUCCESS)
		return ret;
	    continue;
	}

	/* read filter */
	apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ);

	/* write SSL */
	SSLStateMachine_write_inject(pCtx->pStateMachine,data,len);

	/* churn the state machine */
	ret=churn_output(pCtx);
	if(ret != APR_SUCCESS)
	    return ret;
    }

    return APR_SUCCESS;
}

static apr_status_t tls_in_filter(ap_filter_t *f,apr_bucket_brigade *pbbOut,
				  ap_input_mode_t eMode, apr_size_t *readbytes)
{
    TLSFilterCtx *pCtx=f->ctx;
    apr_read_type_e eReadType=eMode == AP_MODE_BLOCKING ? APR_BLOCK_READ :
      APR_NONBLOCK_READ;
    apr_status_t ret;

    /* XXX: we don't currently support peek */
    assert(eMode != AP_MODE_PEEK);

    /* churn the state machine */
    ret=churn(pCtx,eReadType,readbytes);
    if(ret != APR_SUCCESS)
	return ret;

    /* XXX: shame that APR_BRIGADE_FOREACH doesn't work here */
    while(!APR_BRIGADE_EMPTY(pCtx->pbbPendingInput)) {
	apr_bucket *pbktIn=APR_BRIGADE_FIRST(pCtx->pbbPendingInput);
	APR_BUCKET_REMOVE(pbktIn);
	APR_BRIGADE_INSERT_TAIL(pbbOut,pbktIn);
    }

    return APR_SUCCESS;
}

static const char *tls_method(const request_rec *r)
{
    TLSServerConfig *pConfig =
      ap_get_module_config(r->connection->base_server->module_config,
			   &tls_module);

    if (!pConfig->bEnabled)
        return NULL;

    return "https";
}

static unsigned short tls_port(const request_rec *r)
{
    TLSServerConfig *pConfig =
      ap_get_module_config(r->connection->base_server->module_config,
			   &tls_module);

    if (!pConfig->bEnabled)
        return 0;

    return 443;
}

static const command_rec tls_cmds[] = 
{
  /* XXX: We should be able to add the filter using AddOutputFilter */
    AP_INIT_FLAG("TLSFilter", tls_on, NULL, RSRC_CONF,
                 "Run TLS/SSL on this host"),
    AP_INIT_TAKE1("TLSCertificateFile", tls_cert_file, NULL, RSRC_CONF,
                 "Set the certificate file for this host"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    SSLStateMachine_init();

    ap_register_output_filter(s_szTLSFilterName,tls_out_filter,
			      AP_FTYPE_NETWORK);
    ap_register_input_filter(s_szTLSFilterName,tls_in_filter,
			     AP_FTYPE_NETWORK);
    ap_hook_pre_connection(tls_filter_inserter,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_default_port(tls_port,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_http_method(tls_method,NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA tls_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    create_tls_server_config,	/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    tls_cmds,			/* command apr_table_t */
    register_hooks		/* register hooks */
};
