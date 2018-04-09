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

#ifndef __mod_h2__h2_headers__
#define __mod_h2__h2_headers__

#include "h2.h"

struct h2_bucket_beam;

extern const apr_bucket_type_t h2_bucket_type_headers;

#define H2_BUCKET_IS_HEADERS(e)     (e->type == &h2_bucket_type_headers)

apr_bucket * h2_bucket_headers_make(apr_bucket *b, h2_headers *r); 

apr_bucket * h2_bucket_headers_create(apr_bucket_alloc_t *list, 
                                       h2_headers *r);
                                       
h2_headers *h2_bucket_headers_get(apr_bucket *b);

apr_bucket *h2_bucket_headers_beam(struct h2_bucket_beam *beam,
                                    apr_bucket_brigade *dest,
                                    const apr_bucket *src);

/**
 * Create the headers from the given status and headers
 * @param status the headers status
 * @param header the headers of the headers
 * @param notes  the notes carried by the headers
 * @param raw_bytes the raw network bytes (if known) used to transmit these
 * @param pool the memory pool to use
 */
h2_headers *h2_headers_create(int status, apr_table_t *header, 
                              apr_table_t *notes, apr_off_t raw_bytes, 
                              apr_pool_t *pool);

/**
 * Create the headers from the given request_rec.
 * @param r the request record which was processed
 * @param status the headers status
 * @param header the headers of the headers
 * @param pool the memory pool to use
 */
h2_headers *h2_headers_rcreate(request_rec *r, int status, 
                                 apr_table_t *header, apr_pool_t *pool);

/**
 * Clone the headers into another pool. This will not copy any
 * header strings.
 */
h2_headers *h2_headers_copy(apr_pool_t *pool, h2_headers *h);

/**
 * Create the headers for the given error.
 * @param type the error code
 * @param req the original h2_request
 * @param pool the memory pool to use
 */
h2_headers *h2_headers_die(apr_status_t type,
                             const struct h2_request *req, apr_pool_t *pool);

int h2_headers_are_response(h2_headers *headers);

#endif /* defined(__mod_h2__h2_headers__) */
