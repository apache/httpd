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
#include "mod_optional_hook_export.h"
#include "http_protocol.h"

AP_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(int,optional_hook_test,(const char *szStr),
                                    (szStr),OK,DECLINED)

static int ExportLogTransaction(request_rec *r)
{
    return ap_run_optional_hook_test(r->the_request);
}

static void ExportRegisterHooks(apr_pool_t *p)
{
    ap_hook_log_transaction(ExportLogTransaction,NULL,NULL,APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(optional_hook_export) =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ExportRegisterHooks
};
