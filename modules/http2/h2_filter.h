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

#ifndef __mod_h2__h2_filter__
#define __mod_h2__h2_filter__

struct h2_stream;
struct h2_session;

typedef apr_status_t h2_filter_cin_cb(void *ctx, 
                                      const char *data, apr_size_t len,
                                      apr_size_t *readlen);

typedef struct h2_filter_cin {
    apr_pool_t *pool;
    apr_bucket_brigade *bb;
    h2_filter_cin_cb *cb;
    void *cb_ctx;
    apr_socket_t *socket;
    apr_interval_time_t timeout;
    apr_time_t start_read;
} h2_filter_cin;

h2_filter_cin *h2_filter_cin_create(apr_pool_t *p, h2_filter_cin_cb *cb, void *ctx);

void h2_filter_cin_timeout_set(h2_filter_cin *cin, apr_interval_time_t timeout);

apr_status_t h2_filter_core_input(ap_filter_t* filter,
                                  apr_bucket_brigade* brigade,
                                  ap_input_mode_t mode,
                                  apr_read_type_e block,
                                  apr_off_t readbytes);

typedef struct h2_sos h2_sos;
typedef apr_status_t h2_sos_data_cb(void *ctx, const char *data, apr_off_t len);

typedef apr_status_t h2_sos_buffer(h2_sos *sos, apr_bucket_brigade *bb);
typedef apr_status_t h2_sos_prepare(h2_sos *sos, apr_off_t *plen, int *peos);
typedef apr_status_t h2_sos_readx(h2_sos *sos, h2_sos_data_cb *cb, 
                                  void *ctx, apr_off_t *plen, int *peos);
typedef apr_status_t h2_sos_read_to(h2_sos *sos, apr_bucket_brigade *bb, 
                                    apr_off_t *plen, int *peos);
typedef apr_table_t *h2_sos_get_trailers(h2_sos *sos);


#define H2_RESP_SOS_NOTE     "h2-sos-filter"

struct h2_sos {
    struct h2_stream *stream;
    h2_sos           *prev;
    struct h2_response *response;
    void             *ctx;
    h2_sos_buffer    *buffer;
    h2_sos_prepare   *prepare;
    h2_sos_readx     *readx;
    h2_sos_read_to   *read_to;
    h2_sos_get_trailers *get_trailers;
};

h2_sos *h2_filter_sos_create(const char *name, struct h2_sos *prev); 

int h2_filter_h2_status_handler(request_rec *r);


#endif /* __mod_h2__h2_filter__ */
