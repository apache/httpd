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

#ifndef mod_http2_h2_bucket_stream_eos_h
#define mod_http2_h2_bucket_stream_eos_h

struct h2_stream;

/** End Of HTTP/2 STREAM (H2EOS) bucket */
extern const apr_bucket_type_t h2_bucket_type_eos;

#define H2_BUCKET_IS_H2EOS(e)     (e->type == &h2_bucket_type_eos)

apr_bucket *h2_bucket_eos_make(apr_bucket *b, struct h2_stream *stream);

apr_bucket *h2_bucket_eos_create(apr_bucket_alloc_t *list, 
                                 struct h2_stream *stream);

#endif /* mod_http2_h2_bucket_stream_eos_h */
