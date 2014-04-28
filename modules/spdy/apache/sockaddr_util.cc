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

#include "mod_spdy/apache/sockaddr_util.h"

#include <cstddef> // for ptrdiff_t
#include <cstring>

#include "apr_strings.h"

namespace mod_spdy {

apr_sockaddr_t* DeepCopySockAddr(const apr_sockaddr_t* in, apr_pool_t* pool) {
  apr_sockaddr_t* out = static_cast<apr_sockaddr_t*>(
      apr_palloc(pool, sizeof(apr_sockaddr_t)));
  std::memcpy(out, in, sizeof(apr_sockaddr_t));
  out->pool = pool;

  if (in->hostname != NULL) {
    out->hostname = apr_pstrdup(pool, in->hostname);
  }

  if (in->servname != NULL) {
    out->servname = apr_pstrdup(pool, in->servname);
  }

  if (in->ipaddr_ptr != NULL) {
    // ipaddr_ptr points inside the struct, towards the bits containing
    // the actual IPv4/IPv6 address (e.g. to ->sa.sin.sin_addr or
    // ->sa.sin6.sin6_addr). We point to the same offset in 'out' as was used
    // in 'in'.
    ptrdiff_t ipaddr_ptr_offset =
        static_cast<char*>(in->ipaddr_ptr) - reinterpret_cast<const char*>(in);
    out->ipaddr_ptr = reinterpret_cast<char*>(out) + ipaddr_ptr_offset;
  }

  if (in->next != NULL) {
    out->next = DeepCopySockAddr(in->next, pool);
  }

  return out;
}

}  // namespace mod_spdy
