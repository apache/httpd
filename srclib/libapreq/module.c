/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

#include "apreq_module.h"
#include "apreq_error.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_file_io.h"

APREQ_DECLARE(apreq_param_t *)apreq_param(apreq_handle_t *req, const char *key)
{
    apreq_param_t *param = apreq_args_get(req, key);
    if (param == NULL)
        return apreq_body_get(req, key);
    else
        return param;
}

APREQ_DECLARE(apr_table_t *)apreq_params(apreq_handle_t *req, apr_pool_t *p)
{
    const apr_table_t *args, *body;
    apreq_args(req, &args);
    apreq_body(req, &body);

    if (args != NULL)
        if (body != NULL)
            return apr_table_overlay(p, args, body);
        else
            return apr_table_copy(p, args);
    else
        if (body != NULL)
            return apr_table_copy(p, body);
        else
            return NULL;

}

APREQ_DECLARE(apr_table_t *)apreq_cookies(apreq_handle_t *req, apr_pool_t *p)
{
    const apr_table_t *jar;
    apreq_jar(req, &jar);

    if (jar != NULL)
        return apr_table_copy(p, jar);
    else
        return NULL;

}


/** @} */
