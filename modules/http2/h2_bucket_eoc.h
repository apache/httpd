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

#ifndef mod_http2_h2_bucket_eoc_h
#define mod_http2_h2_bucket_eoc_h

struct h2_session;

/** End Of HTTP/2 SESSION (H2EOC) bucket */
extern const apr_bucket_type_t h2_bucket_type_eoc;

#define H2_BUCKET_IS_H2EOC(e)     (e->type == &h2_bucket_type_eoc)

apr_bucket * h2_bucket_eoc_make(apr_bucket *b, 
                                struct h2_session *session);

apr_bucket * h2_bucket_eoc_create(apr_bucket_alloc_t *list,
                                  struct h2_session *session);

#endif /* mod_http2_h2_bucket_eoc_h */
