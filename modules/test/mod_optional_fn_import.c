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

#include "httpd.h"
#include "http_config.h"
#include "mod_optional_fn_export.h"
#include "http_protocol.h"

/* The alert will note a strange mirror-image style resemblance to
 * mod_optional_hook_export.c. Yes, I _did_ mean export. Think about it.
 */

static APR_OPTIONAL_FN_TYPE(TestOptionalFn) *pfn;

static int ImportLogTransaction(request_rec *r)
{
    if(pfn)
        return pfn(r->the_request);
    return DECLINED;
}

static void ImportFnRetrieve(void)
{
    pfn=APR_RETRIEVE_OPTIONAL_FN(TestOptionalFn);
}

static void ImportRegisterHooks(apr_pool_t *p)
{
    ap_hook_log_transaction(ImportLogTransaction,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_optional_fn_retrieve(ImportFnRetrieve,NULL,NULL,APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(optional_fn_import) =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ImportRegisterHooks
};
