/* Copyright 2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_buckets.h"
#include "apr_errno.h"
#include "apr_support.h"
#include "httpd.h"
#include "http_connection.h"
#include "util_filter.h"

apr_status_t ap_mpm_custom_write_filter(ap_filter_t *f,
                                        apr_bucket_brigade *bb)
{
    /* write you own C-O-F here */
    return ap_core_output_filter(f, bb);
}

