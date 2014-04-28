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

#include "mod_spdy/apache/pool_util.h"

#include <string>

#include "apr_errno.h"

#include "base/basictypes.h"

namespace mod_spdy {

std::string AprStatusString(apr_status_t status) {
  char buffer[120];
  apr_strerror(status, buffer, arraysize(buffer));
  return std::string(buffer);
}

}  // namespace mod_spdy
