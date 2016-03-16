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

#ifndef h2_req_shed_h
#define h2_req_shed_h

struct h2_req_engine;
struct h2_task;

typedef struct h2_ngn_shed h2_ngn_shed;
struct h2_ngn_shed {
    conn_rec *c;
    apr_pool_t *pool;
    apr_hash_t *ngns;
    void *user_ctx;
    
    unsigned int aborted : 1;
    
    apr_uint32_t default_capacity;
    apr_uint32_t req_buffer_size; /* preferred buffer size for responses */
};

const char *h2_req_engine_get_id(h2_req_engine *engine);
int h2_req_engine_is_shutdown(h2_req_engine *engine);

void h2_req_engine_out_consumed(h2_req_engine *engine, conn_rec *c, 
                                apr_off_t bytes);

typedef apr_status_t h2_shed_ngn_init(h2_req_engine *engine, 
                                      const char *id, 
                                      const char *type,
                                      apr_pool_t *pool, 
                                      apr_uint32_t req_buffer_size,
                                      request_rec *r,
                                      h2_output_consumed **pconsumed,
                                      void **pbaton);

h2_ngn_shed *h2_ngn_shed_create(apr_pool_t *pool, conn_rec *c,
                                apr_uint32_t default_capactiy, 
                                apr_uint32_t req_buffer_size); 

void h2_ngn_shed_set_ctx(h2_ngn_shed *shed, void *user_ctx);
void *h2_ngn_shed_get_ctx(h2_ngn_shed *shed);

h2_ngn_shed *h2_ngn_shed_get_shed(struct h2_req_engine *ngn);

void h2_ngn_shed_abort(h2_ngn_shed *shed);

apr_status_t h2_ngn_shed_push_task(h2_ngn_shed *shed, const char *ngn_type, 
                                  struct h2_task *task, 
                                  h2_shed_ngn_init *init_cb);

apr_status_t h2_ngn_shed_pull_task(h2_ngn_shed *shed, h2_req_engine *pub_ngn, 
                                   apr_uint32_t capacity, 
                                   int want_shutdown, struct h2_task **ptask);

apr_status_t h2_ngn_shed_done_task(h2_ngn_shed *shed, 
                                   struct h2_req_engine *ngn, 
                                   struct h2_task *task);

void h2_ngn_shed_done_ngn(h2_ngn_shed *shed, struct h2_req_engine *ngn);


#endif /* h2_req_shed_h */
