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

#ifndef __mod_h2__h2_to_h1__
#define __mod_h2__h2_to_h1__

struct h2_mplx;
struct h2_task;
typedef struct h2_to_h1 h2_to_h1;

struct h2_to_h1 {
    int stream_id;
    apr_pool_t *pool;
    h2_mplx *m;

    const char *method;
    const char *path;
    const char *authority;
    
    int chunked;
    int eoh;
    int eos;
    int flushed;
    int seen_host;
    
    apr_off_t content_len;
    apr_off_t remain_len;
    apr_table_t *headers;
    apr_bucket_brigade *bb;
};

/* Create a converter from a HTTP/2 request to a serialzation in
 * HTTP/1.1 format. The serialized data will be written onto the
 * given h2_mplx instance.
 */
h2_to_h1 *h2_to_h1_create(int stream_id, apr_pool_t *pool, 
                          apr_bucket_alloc_t *bucket_alloc, 
                          const char *method, const char *path,
                          const char *authority, struct h2_mplx *m);

/* Destroy the converter and free resources. */
void h2_to_h1_destroy(h2_to_h1 *to_h1);

/* Add a header to the serialization. Only valid to call after start
 * and before end_headers.
 */
apr_status_t h2_to_h1_add_header(h2_to_h1 *to_h1,
                                 const char *name, size_t nlen,
                                 const char *value, size_t vlen);

apr_status_t h2_to_h1_add_headers(h2_to_h1 *to_h1, apr_table_t *headers);

/** End the request headers.
 */
apr_status_t h2_to_h1_end_headers(h2_to_h1 *to_h1, 
                                  struct h2_task *task, int eos);

/* Add request body data.
 */
apr_status_t h2_to_h1_add_data(h2_to_h1 *to_h1,
                               const char *data, size_t len);

/* Flush the converted data onto the h2_mplx instance.
 */
apr_status_t h2_to_h1_flush(h2_to_h1 *to_h1);

/* Close the request, flushed automatically.
 */
apr_status_t h2_to_h1_close(h2_to_h1 *to_h1);

#endif /* defined(__mod_h2__h2_to_h1__) */
