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

#ifndef __mod_h2__h2_from_h1__
#define __mod_h2__h2_from_h1__

/**
 * h2_from_h1 parses a HTTP/1.1 response into
 * - response status
 * - a list of header values
 * - a series of bytes that represent the response body alone, without
 *   any meta data, such as inserted by chunked transfer encoding.
 *
 * All data is allocated from the stream memory pool. 
 *
 * Again, see comments in h2_request: ideally we would take the headers
 * and status from the httpd structures instead of parsing them here, but
 * we need to have all handlers and filters involved in request/response
 * processing, so this seems to be the way for now.
 */
struct h2_headers;
struct h2_task;

apr_status_t h2_from_h1_parse_response(struct h2_task *task, ap_filter_t *f, 
                                       apr_bucket_brigade *bb);

apr_status_t h2_filter_headers_out(ap_filter_t *f, apr_bucket_brigade *bb);

apr_status_t h2_filter_request_in(ap_filter_t* f,
                                  apr_bucket_brigade* brigade,
                                  ap_input_mode_t mode,
                                  apr_read_type_e block,
                                  apr_off_t readbytes);

apr_status_t h2_filter_trailers_out(ap_filter_t *f, apr_bucket_brigade *bb);

#endif /* defined(__mod_h2__h2_from_h1__) */
