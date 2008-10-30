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

#include "apr.h"
#include "apr_pools.h"
#include "apr_poll.h"
#include "apr_hash.h"
#include "apr_ring.h"
#include "apr_thread_pool.h"
#include "apr_buckets.h"
#include "httpd.h"

#ifndef APACHE_MPM_SIMPLE_API_H
#define APACHE_MPM_SIMPLE_API_H

#ifdef __cplusplus
extern "C"
{
#endif

/* Called after child as forked, before child_init, to be used by modules that 
 * wish to chroot or change the processes running UserID before we begin serving requests.
 */
    AP_DECLARE_HOOK(int, simple_drop_privileges,
                    (apr_pool_t * pchild, server_rec * s))
#ifdef __cplusplus
}
#endif

#endif                          /* APACHE_MPM_SIMPLE_API_H */
