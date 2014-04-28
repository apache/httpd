// Copyright 2012 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "httpd.h"
#include "apr_buckets.h"
#include "util_filter.h"

// For unit tests, we don't link in Apache's util_filter.c, which defines the
// below functions.  To make our lives easier, we define dummy versions of them
// here that simply report success.

extern "C" {

AP_DECLARE(apr_status_t) ap_pass_brigade(
    ap_filter_t* filter, apr_bucket_brigade* bucket) {
  return APR_SUCCESS;
}

AP_DECLARE(void) ap_remove_output_filter(ap_filter_t* filter) {}

}  // extern "C"
