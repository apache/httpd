// Copyright 2012 Google Inc.
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

#include "mod_spdy/apache/slave_connection_context.h"

#include "base/logging.h"
#include "mod_spdy/common/spdy_stream.h"

namespace mod_spdy {

SlaveConnectionContext::SlaveConnectionContext()
    : using_ssl_(false),
      spdy_version_(spdy::SPDY_VERSION_NONE),
      slave_stream_(NULL),
      output_filter_handle_(NULL),
      output_filter_context_(NULL),
      input_filter_handle_(NULL),
      input_filter_context_(NULL) {
}

SlaveConnectionContext::~SlaveConnectionContext() {}

void SlaveConnectionContext::SetOutputFilter(
    ap_filter_rec_t* handle, void* context) {
  output_filter_handle_ = handle;
  output_filter_context_ = context;
}

void SlaveConnectionContext::SetInputFilter(
    ap_filter_rec_t* handle, void* context) {
  input_filter_handle_ = handle;
  input_filter_context_ = context;
}

}  // namespace mod_spdy
