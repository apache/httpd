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
    CaseFilterInConfig *pConfig = ap_get_module_config(r->server->module_config,
                                                       &case_filter_in_module);
    if (!pConfig->bEnabled)
        return;

    ap_add_input_filter(s_szCaseFilterName, NULL, r, r->connection);
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

    while (!APR_BRIGADE_EMPTY(pCtx->pbbTmp)) {
        apr_bucket *pbktIn = APR_BRIGADE_FIRST(pCtx->pbbTmp);
        apr_bucket *pbktOut;
        const char *data;
        apr_size_t len;
        char *buf;
        apr_size_t n;

        /* It is tempting to do this...
         * APR_BUCKET_REMOVE(pB);
         * APR_BRIGADE_INSERT_TAIL(pbbOut,pB);
         * and change the case of the bucket data, but that would be wrong
         * for a file or socket buffer, for example...
         */

        if (APR_BUCKET_IS_EOS(pbktIn)) {
            APR_BUCKET_REMOVE(pbktIn);
            APR_BRIGADE_INSERT_TAIL(pbbOut, pbktIn);
            break;
        }

        ret=apr_bucket_read(pbktIn, &data, &len, eBlock);
        if (ret != APR_SUCCESS)
            return ret;

        buf = ap_malloc(len);
        for (n=0 ; n < len ; ++n) {
            buf[n] = apr_toupper(data[n]);
        }

        pbktOut = apr_bucket_heap_create(buf, len, free, c->bucket_alloc);
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

AP_DECLARE_MODULE(case_filter_in) =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    CaseFilterInCreateServerConfig,
    NULL,
    CaseFilterInCmds,
    CaseFilterInRegisterHooks
};
