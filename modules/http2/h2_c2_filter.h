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

#ifndef __mod_h2__h2_c2_filter__
#define __mod_h2__h2_c2_filter__

/**
 * Output filter that inspects the request_rec->notes of the request
 * itself and possible internal redirects to detect conditions that
 * merit specific HTTP/2 response codes, such as 421.
 */
apr_status_t h2_c2_filter_notes_out(ap_filter_t *f, apr_bucket_brigade *bb);

/**
 * Input filter on secondary connections that insert the REQUEST bucket
 * with the request to perform and then removes itself.
 */
apr_status_t h2_c2_filter_request_in(ap_filter_t *f,
                                     apr_bucket_brigade *bb,
                                     ap_input_mode_t mode,
                                     apr_read_type_e block,
                                     apr_off_t readbytes);

#endif /* defined(__mod_h2__h2_c2_filter__) */
