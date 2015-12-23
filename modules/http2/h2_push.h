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
#ifndef __mod_h2__h2_push__
#define __mod_h2__h2_push__

struct h2_request;
struct h2_response;
struct h2_ngheader;

typedef enum {
    H2_PUSH_NONE,
    H2_PUSH_DEFAULT,
    H2_PUSH_HEAD,
    H2_PUSH_FAST_LOAD,
} h2_push_policy;

typedef struct h2_push {
    const struct h2_request *req;
} h2_push;


apr_array_header_t *h2_push_collect(apr_pool_t *p, 
                                    const struct h2_request *req, 
                                    const struct h2_response *res);

void h2_push_policy_determine(struct h2_request *req, apr_pool_t *p, int push_enabled);

#endif /* defined(__mod_h2__h2_push__) */
