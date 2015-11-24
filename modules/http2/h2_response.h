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

#ifndef __mod_h2__h2_response__
#define __mod_h2__h2_response__

struct h2_request;
struct h2_push;

typedef struct h2_response {
    int stream_id;
    int rst_error;
    int http_status;
    apr_off_t content_length;
    apr_table_t *headers;
    apr_table_t *trailers;
} h2_response;

/**
 * Create the response from the status and parsed header lines.
 * @param stream_id id of the stream to create the response for
 * @param rst_error error for reset or 0
 * @param http_status  http status code of response
 * @param hlines the text lines of the response header
 * @param pool the memory pool to use
 */
h2_response *h2_response_create(int stream_id,
                                int rst_error,
                                int http_status,
                                apr_array_header_t *hlines,
                                apr_pool_t *pool);

/**
 * Create the response from the given request_rec.
 * @param stream_id id of the stream to create the response for
 * @param r the request record which was processed
 * @param header the headers of the response
 * @param pool the memory pool to use
 */
h2_response *h2_response_rcreate(int stream_id, request_rec *r,
                                 apr_table_t *header, apr_pool_t *pool);

/**
 * Create the response for the given error.
 * @param stream_id id of the stream to create the response for
 * @param type the error code
 * @param req the original h2_request
 * @param pool the memory pool to use
 */
h2_response *h2_response_die(int stream_id, apr_status_t type,
                             const struct h2_request *req, apr_pool_t *pool);

/**
 * Deep copies the response into a new pool.
 * @param pool the pool to use for the clone
 * @param from the response to clone
 * @return the cloned response
 */
h2_response *h2_response_clone(apr_pool_t *pool, h2_response *from);

/**
 * Set the trailers in the reponse. Will replace any existing trailers. Will
 * *not* clone the table.
 *
 * @param response the repsone to set the trailers for
 * @param trailers the trailers to set
 */
void h2_response_set_trailers(h2_response *response, apr_table_t *trailers);

#endif /* defined(__mod_h2__h2_response__) */
