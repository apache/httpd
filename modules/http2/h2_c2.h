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

typedef enum {
    H2_MPM_UNKNOWN,
    H2_MPM_WORKER,
    H2_MPM_EVENT,
    H2_MPM_PREFORK,
    H2_MPM_MOTORZ,
    H2_MPM_SIMPLE,
    H2_MPM_NETWARE,
    H2_MPM_WINNT,
} h2_mpm_type_t;

/* Returns the type of MPM module detected */
h2_mpm_type_t h2_conn_mpm_type(void);
const char *h2_conn_mpm_name(void);
int h2_mpm_supported(void);

/* Initialize this child process for h2 secondary connection work,
 * to be called once during child init before multi processing
 * starts.
 */
apr_status_t h2_c2_child_init(apr_pool_t *pool, server_rec *s);

conn_rec *h2_c2_create(conn_rec *c1, apr_pool_t *parent);
void h2_c2_destroy(conn_rec *c2);

/**
 * Process a secondary connection for a HTTP/2 stream request.
 */
apr_status_t h2_c2_process(conn_rec *c, apr_thread_t *thread, int worker_id);

void h2_c2_register_hooks(void);
/*
 * One time, post config initialization.
 */
apr_status_t h2_c2_init(apr_pool_t *pool, server_rec *s);

extern APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_in) *h2_c2_logio_add_bytes_in;
extern APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *h2_c2_logio_add_bytes_out;

#endif /* defined(__mod_h2__h2_c2__) */
