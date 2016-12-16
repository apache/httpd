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

struct h2_bucket_beam;
struct h2_headers;
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

/******* observer bucket ******************************************************/

typedef enum {
    H2_BUCKET_EV_BEFORE_DESTROY,
    H2_BUCKET_EV_BEFORE_MASTER_SEND
} h2_bucket_event;

extern const apr_bucket_type_t h2_bucket_type_observer;

typedef apr_status_t h2_bucket_event_cb(void *ctx, h2_bucket_event event, apr_bucket *b);

#define H2_BUCKET_IS_OBSERVER(e)     (e->type == &h2_bucket_type_observer)

apr_bucket * h2_bucket_observer_make(apr_bucket *b, h2_bucket_event_cb *cb, 
                                     void *ctx); 

apr_bucket * h2_bucket_observer_create(apr_bucket_alloc_t *list, 
                                       h2_bucket_event_cb *cb, void *ctx); 
                                       
apr_status_t h2_bucket_observer_fire(apr_bucket *b, h2_bucket_event event);

apr_bucket *h2_bucket_observer_beam(struct h2_bucket_beam *beam,
                                    apr_bucket_brigade *dest,
                                    const apr_bucket *src);

/******* /.well-known/h2/state handler ****************************************/

int h2_filter_h2_status_handler(request_rec *r);

#endif /* __mod_h2__h2_filter__ */
