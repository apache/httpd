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

/**
 * Adjust r->server and r->connection keepalive handling, update counters
 * and set necessary headers in resp->headers for HTTP/1.x keepalive handling.
 * @param r the request being processed
 * @param resp the response being sent
 */
int http1_set_keepalive(request_rec *r, ap_bucket_response *resp);

/**
 * Tokenize a HTTP/x.x request line.
 * @param r the request for which to parse the line
 * @param line the line to tokenize.
 * @param pmethod the parsed method on return
 * @param puri the parsed uri on return
 * @param pprotocol the parsed protocol on return
 * @return 1 on success, 0 on failure
 */
AP_DECLARE(int) http1_tokenize_request_line(request_rec *r, const char *line,
                                            char **pmethod, char **puri,
                                            char **pprotocol);

/**
 * Context for writing out HTTP/1 protocol fields, such as headers.
 * Passed in iterators, for example.
 */
typedef struct http1_out_ctx_t {
    apr_pool_t *pool;
    apr_bucket_brigade *bb;
} http1_out_ctx_t;

/**
 * Send a single HTTP header field to the client.  Note that this function
 * is used in calls to apr_table_do(), so don't change its interface.
 * It returns true unless there was a write error of some kind.
 */
int http1_write_header_field(http1_out_ctx_t *out,
                             const char *fieldname, const char *fieldval);

/**
 * Write a response `resp` for request `r` in HTTP/1.x format to brigade `bb`.
 */
void http1_write_response(request_rec *r,
                          ap_bucket_response *resp,
                          apr_bucket_brigade *bb);

apr_status_t http1_request_in_filter(ap_filter_t *f,
                                     apr_bucket_brigade *bb,
                                     ap_input_mode_t mode,
                                     apr_read_type_e block,
                                     apr_off_t readbytes);

/* This is the HTTP1_BODY_IN filter for HTTP/1.x requests
 * and responses from proxied servers (mod_proxy).
 * It handles chunked and content-length bodies. This can only
 * be inserted/used after a request has been read on a
 * HTTP/1.x connection.
 */
apr_status_t http1_body_in_filter(ap_filter_t *f,
                                  apr_bucket_brigade *b,
                                  ap_input_mode_t mode,
                                  apr_read_type_e block,
                                  apr_off_t readbytes);


