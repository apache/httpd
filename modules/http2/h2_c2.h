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

#ifndef __mod_h2__h2_c2__
#define __mod_h2__h2_c2__

#include <http_core.h>

#include "h2.h"

const char *h2_conn_mpm_name(void);
int h2_mpm_supported(void);

/* Initialize this child process for h2 secondary connection work,
 * to be called once during child init before multi processing
 * starts.
 */
apr_status_t h2_c2_child_init(apr_pool_t *pool, server_rec *s);

#if !AP_HAS_RESPONSE_BUCKETS

conn_rec *h2_c2_create(conn_rec *c1, apr_pool_t *parent,
                       apr_bucket_alloc_t *buckt_alloc);

/**
 * Process a secondary connection for a HTTP/2 stream request.
 */
apr_status_t h2_c2_process(conn_rec *c, apr_thread_t *thread, int worker_id);

#endif /* !AP_HAS_RESPONSE_BUCKETS */

void h2_c2_destroy(conn_rec *c2);

/**
 * Abort the I/O processing of a secondary connection. And
 * in-/output beams will return errors and c2->aborted is set.
 * @param c2 the secondary connection to abort
 * @param from the connection this is invoked from
 */
void h2_c2_abort(conn_rec *c2, conn_rec *from);

void h2_c2_register_hooks(void);

#endif /* defined(__mod_h2__h2_c2__) */
