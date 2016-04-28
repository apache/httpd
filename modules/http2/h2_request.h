/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __mod_h2__h2_request__
#define __mod_h2__h2_request__

#include "h2.h"

h2_request *h2_request_create(int id, apr_pool_t *pool, int serialize);

h2_request *h2_request_createn(int id, apr_pool_t *pool,
                               const char *method, const char *scheme,
                               const char *authority, const char *path,
                               apr_table_t *headers, int serialize);

apr_status_t h2_request_make(h2_request *req, apr_pool_t *pool,
                             const char *method, const char *scheme, 
                             const char *authority, const char *path, 
                             apr_table_t *headers);

apr_status_t h2_request_rwrite(h2_request *req, request_rec *r);

apr_status_t h2_request_add_header(h2_request *req, apr_pool_t *pool,
                                   const char *name, size_t nlen,
                                   const char *value, size_t vlen);

apr_status_t h2_request_add_trailer(h2_request *req, apr_pool_t *pool,
                                    const char *name, size_t nlen,
                                    const char *value, size_t vlen);

apr_status_t h2_request_end_headers(h2_request *req, apr_pool_t *pool, 
                                    int eos, int push);

h2_request *h2_request_clone(apr_pool_t *p, const h2_request *src);

/**
 * Create a request_rec representing the h2_request to be
 * processed on the given connection.
 *
 * @param req the h2 request to process
 * @param conn the connection to process the request on
 * @return the request_rec representing the request
 */
request_rec *h2_request_create_rec(const h2_request *req, conn_rec *conn);


#endif /* defined(__mod_h2__h2_request__) */
