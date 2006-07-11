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
#include "http_log.h"
#include "mod_optional_fn_export.h"

/* The alert will note a strange mirror-image style resemblance to
 * mod_optional_hook_import.c. Yes, I _did_ mean import. Think about it.
 */

static int TestOptionalFn(const char *szStr)
{
    ap_log_error(APLOG_MARK,APLOG_ERR,OK,NULL,
                 "Optional function test said: %s",szStr);

    return OK;
}

static void ExportRegisterHooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(TestOptionalFn);
}

module AP_MODULE_DECLARE_DATA optional_fn_export_module=
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ExportRegisterHooks
};
