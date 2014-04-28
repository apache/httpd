// Copyright 2012 Google Inc
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

#include "mod_spdy/apache/ssl_util.h"

#include "apr_optional.h"
#include "apr_optional_hooks.h"

#include "base/logging.h"

// This file contains some utility functions for communicating to mod_ssl.

// Declaring mod_ssl's optional hooks here (so that we don't need mod_ssl.h).
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec*));
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec*));

namespace mod_spdy {

namespace {

// These global variables store pointers to "optional functions" defined in
// mod_ssl.  See TAMB 10.1.2 for more about optional functions.  These are
// assigned just once, at start-up, so concurrency is not an issue.
int (*gDisableSslForConnection)(conn_rec*) = NULL;
int (*gIsUsingSslForConnection)(conn_rec*) = NULL;

}  // namespace

void RetrieveModSslFunctions() {
  gDisableSslForConnection = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_disable);
  gIsUsingSslForConnection = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
  // If mod_ssl isn't installed, we'll get back NULL for these functions.  Our
  // other hook functions will fail gracefully (i.e. do nothing) if these
  // functions are NULL, but if the user installed mod_spdy without mod_ssl and
  // expected it to do anything, we should warn them otherwise.
  //
  // Note: Alternatively, it may be that there's no mod_ssl, but mod_spdy has
  // been configured to assume SPDY for non-SSL connections, in which case this
  // warning is untrue.  But there's no easy way to check the server config
  // from here, and normal users should never use that config option anyway
  // (it's for debugging), so I don't think the spurious warning is a big deal.
  if (gDisableSslForConnection == NULL &&
      gIsUsingSslForConnection == NULL) {
    LOG(WARNING) << "It seems that mod_spdy is installed but mod_ssl isn't.  "
                 << "Without SSL, the server cannot ever use SPDY.";
  }
  // Whether or not mod_ssl is installed, either both functions should be
  // non-NULL or both functions should be NULL.  Otherwise, something is wrong
  // (like, maybe some kind of bizarre mutant mod_ssl is installed) and
  // mod_spdy probably won't work correctly.
  if ((gDisableSslForConnection == NULL) ^
      (gIsUsingSslForConnection == NULL)) {
    LOG(DFATAL) << "Some, but not all, of mod_ssl's optional functions are "
                << "available.  What's going on?";
  }
}

bool DisableSslForConnection(conn_rec* connection) {
  return (gDisableSslForConnection != NULL) &&
         (gDisableSslForConnection(connection) != 0);
}

bool IsUsingSslForConnection(conn_rec* connection) {
  return (gIsUsingSslForConnection != NULL) &&
         (gIsUsingSslForConnection(connection) != 0);
}

}  // namespace mod_spdy
