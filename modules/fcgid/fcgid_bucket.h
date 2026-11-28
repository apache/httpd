/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

#ifndef FCGID_BUCKET_H
#define FCGID_BUCKET_H
#include "httpd.h"
#include "fcgid_proc.h"

typedef struct fcgid_bucket_ctx_t {
    fcgid_ipc ipc;
    apr_bucket *buffer;
    fcgid_procnode *procnode;
    apr_time_t active_time;
    int has_error;
} fcgid_bucket_ctx;

extern const apr_bucket_type_t ap_bucket_type_fcgid_header;
apr_bucket *ap_bucket_fcgid_header_create(apr_bucket_alloc_t * list,
                                          fcgid_bucket_ctx * ctx);
apr_bucket *ap_bucket_fcgid_header_make(apr_bucket *, fcgid_bucket_ctx *);

#endif
