/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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
 */

/*
 * An example input filter - this converts input to upper case. Note that
 * because of the moment it gets inserted it does NOT convert request headers.
 */

#include "httpd.h"
#include "http_config.h"
#include "apr_buckets.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "http_request.h"

#include <ctype.h>

static const char s_szCaseFilterName[] = "CaseFilterIn";
module AP_MODULE_DECLARE_DATA case_filter_in_module;

typedef struct
{
    int bEnabled;
} CaseFilterInConfig;

typedef struct
{
    apr_bucket_brigade *pbbTmp;
} CaseFilterInContext;

static void *CaseFilterInCreateServerConfig(apr_pool_t *p, server_rec *s)
{
    CaseFilterInConfig *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->bEnabled = 0;

    return pConfig;
}

static void CaseFilterInInsertFilter(request_rec *r)
{
    CaseFilterInConfig *pConfig=ap_get_module_config(r->server->module_config,
                                                     &case_filter_in_module);
    if(!pConfig->bEnabled)
        return;

    ap_add_input_filter(s_szCaseFilterName,NULL,r,r->connection);
}

static apr_status_t CaseFilterInFilter(ap_filter_t *f,
                                       apr_bucket_brigade *pbbOut,
                                       ap_input_mode_t eMode,
                                       apr_read_type_e eBlock,
                                       apr_off_t nBytes)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    CaseFilterInContext *pCtx;
    apr_status_t ret;

    if (!(pCtx = f->ctx)) {
        f->ctx = pCtx = apr_palloc(r->pool, sizeof *pCtx);
        pCtx->pbbTmp = apr_brigade_create(r->pool, c->bucket_alloc);
    }

    if (APR_BRIGADE_EMPTY(pCtx->pbbTmp)) {
        ret = ap_get_brigade(f->next, pCtx->pbbTmp, eMode, eBlock, nBytes);

        if (eMode == AP_MODE_EATCRLF || ret != APR_SUCCESS)
            return ret;
    }

    while(!APR_BRIGADE_EMPTY(pCtx->pbbTmp)) {
        apr_bucket *pbktIn = APR_BRIGADE_FIRST(pCtx->pbbTmp);
        apr_bucket *pbktOut;
        const char *data;
        apr_size_t len;
        char *buf;
        int n;

        /* It is tempting to do this...
         * APR_BUCKET_REMOVE(pB);
         * APR_BRIGADE_INSERT_TAIL(pbbOut,pB);
         * and change the case of the bucket data, but that would be wrong
         * for a file or socket buffer, for example...
         */

        if(APR_BUCKET_IS_EOS(pbktIn)) {
            APR_BUCKET_REMOVE(pbktIn);
            APR_BRIGADE_INSERT_TAIL(pbbOut, pbktIn);
            break;
        }

        ret=apr_bucket_read(pbktIn, &data, &len, eBlock);
        if(ret != APR_SUCCESS)
            return ret;

        buf = malloc(len);
        for(n=0 ; n < len ; ++n)
            buf[n] = apr_toupper(data[n]);

        pbktOut = apr_bucket_heap_create(buf, len, 0, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);
        apr_bucket_delete(pbktIn);
    }

    return APR_SUCCESS;
}
            
        
static const char *CaseFilterInEnable(cmd_parms *cmd, void *dummy, int arg)
{
    CaseFilterInConfig *pConfig
      = ap_get_module_config(cmd->server->module_config,
                             &case_filter_in_module);
    pConfig->bEnabled=arg;

    return NULL;
}

static const command_rec CaseFilterInCmds[] = 
{
    AP_INIT_FLAG("CaseFilterIn", CaseFilterInEnable, NULL, RSRC_CONF,
                 "Run an input case filter on this host"),
    { NULL }
};


static void CaseFilterInRegisterHooks(apr_pool_t *p)
{
    ap_hook_insert_filter(CaseFilterInInsertFilter, NULL, NULL, 
                          APR_HOOK_MIDDLE);
    ap_register_input_filter(s_szCaseFilterName, CaseFilterInFilter, NULL,
                             AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA case_filter_in_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    CaseFilterInCreateServerConfig,
    NULL,
    CaseFilterInCmds,
    CaseFilterInRegisterHooks
};
