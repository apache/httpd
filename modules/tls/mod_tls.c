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

// temp
#include <assert.h>

AP_DECLARE_DATA module tls_module;
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
    pConfig->szCertificateFile = arg;

    // temp
    pConfig->szKeyFile=pConfig->szCertificateFile;

    return NULL;
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
    pCtx->pOutputFilter=ap_add_output_filter(s_szTLSFilterName,pCtx,NULL,
						 c);

    return OK;
}

static apr_status_t churn(TLSFilterCtx *pCtx)
{
    apr_bucket_brigade *pbbOutput=NULL;
    int done;

    do {
	char buf[1024];
	int n;
	apr_bucket *pbkt;

	done=0;

	n=SSLStateMachine_write_extract(pCtx->pStateMachine,buf,sizeof buf);
	if(n > 0) {
	    if(!pbbOutput)
		pbbOutput=apr_brigade_create(pCtx->pOutputFilter->c->pool);
	    pbkt=apr_bucket_pool_create(buf,n,pCtx->pOutputFilter->c->pool);
	    APR_BRIGADE_INSERT_TAIL(pbbOutput,pbkt);
	    done=1;
	    /*	} else if(n == 0) {
	    apr_bucket *pbktEOS=apr_bucket_create_eos();
	    APR_BRIGADE_INSERT_TAIL(pbbOutput,pbktEOS);*/
	}
    } while(done);
    
    // XXX: check for errors
    if(pbbOutput) {
	apr_bucket *pbkt;

	// XXX: it may be possible to not always flush
	pbkt=apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(pbbOutput,pbkt);
	ap_pass_brigade(pCtx->pOutputFilter->next,pbbOutput);
    }

    return APR_SUCCESS;
}

static apr_status_t tls_out_filter(ap_filter_t *f,apr_bucket_brigade *pbbIn)
{
    TLSFilterCtx *pCtx=f->ctx;
    apr_bucket *pbktIn;
    int bFlush=0;
    apr_status_t ret;

    APR_BRIGADE_FOREACH(pbktIn,pbbIn) {
	const char *data;
	apr_size_t len;

	if(APR_BUCKET_IS_EOS(pbktIn)) {
	    // XXX: why can't I reuse pbktIn???
	    // XXX: isn't this wrong?
	    // Write eof!
	    break;
	}

	if(APR_BUCKET_IS_FLUSH(pbktIn)) {
	    bFlush=1;
	    continue;
	}

	// read filter
	apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ);

	// write SSL
	SSLStateMachine_write_inject(pCtx->pStateMachine,data,len);

    }

    // churn the state machine
    ret=churn(pCtx);

    if(bFlush) {
	apr_bucket_brigade *pbbOut;
	apr_bucket *pbktOut;

	pbbOut=apr_brigade_create(f->c->pool);
	pbktOut=apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
	// XXX: and what if this returns an error???
	ap_pass_brigade(f->next,pbbOut);
    }
    return ret;
}

static apr_status_t tls_in_filter(ap_filter_t *f,apr_bucket_brigade *pbbOut,
				  ap_input_mode_t eMode)
{
    TLSFilterCtx *pCtx=f->ctx;
    apr_bucket *pbktIn;
    apr_bucket_brigade *pbbIn;
    apr_read_type_e eReadType=eMode == AP_MODE_BLOCKING ? APR_BLOCK_READ :
      APR_NONBLOCK_READ;

    // XXX: we don't currently support peek
    assert(eMode != AP_MODE_PEEK);

    pbbIn=apr_brigade_create(f->c->pool);
    ap_get_brigade(f->next,pbbIn,eMode);

    APR_BRIGADE_FOREACH(pbktIn,pbbIn) {
	const char *data;
	apr_size_t len;
	int n;
	char buf[1024];

	if(APR_BUCKET_IS_EOS(pbktIn)) {
	    // XXX: why can't I reuse pbktIn???
	    // XX: isn't this wrong?
	    // Write eof!
	    break;
	}

	// read filter
	apr_bucket_read(pbktIn,&data,&len,eReadType);

	// presumably this can only happen when we are non-blocking
	if(len == 0) {
	    assert(eReadType == APR_NONBLOCK_READ);
	    break;
	}

	assert(len > 0);

	// write SSL
	SSLStateMachine_read_inject(pCtx->pStateMachine,data,len);

	n=SSLStateMachine_read_extract(pCtx->pStateMachine,buf,sizeof buf);
	if(n > 0) {
	    apr_bucket *pbktOut;
	    char *pbuf;

	    pbuf=apr_memdup(pCtx->pInputFilter->c->pool,buf,n);
	    // XXX: should we use a heap bucket instead? Or a transient (in
	    // which case we need a separate brigade for each bucket)?
	    pbktOut=apr_bucket_pool_create(pbuf,n,pCtx->pInputFilter->c->pool);
	    APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);

	    // Once we've read something, we can move to non-blocking mode (if
	    // we weren't already).
	    eReadType=APR_NONBLOCK_READ;

	    // XXX: deal with EOF!
	    /*	} else if(n == 0) {
	    apr_bucket *pbktEOS=apr_bucket_create_eos();
	    APR_BRIGADE_INSERT_TAIL(pbbInput,pbktEOS);*/
	}
	assert(n >= 0);

	// churn the state machine
	// XXX: check for errors
	churn(pCtx);
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

AP_DECLARE_DATA module tls_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    create_tls_server_config,	/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    tls_cmds,			/* command apr_table_t */
    register_hooks		/* register hooks */
};
