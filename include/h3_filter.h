/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef H3_FILTER_H
#define H3_FILTER_H

#include <httpd.h>

#include <apr_buckets.h>

extern ap_filter_rec_t* h3_net_out_filter_handle;
extern ap_filter_rec_t* h3_net_in_filter_handle;
extern ap_filter_rec_t* h3_proto_out_filter_handle;
extern ap_filter_rec_t* h3_proto_in_filter_handle;

apr_status_t h3_filter_out(ap_filter_t* f, apr_bucket_brigade* bb);
apr_status_t h3_filter_out_proto(ap_filter_t* f, apr_bucket_brigade* bb);
apr_status_t h3_filter_in_proto(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);
apr_status_t h3_filter_in(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);

#endif /* H3_FILTER_H */
