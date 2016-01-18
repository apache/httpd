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

#ifndef mod_http2_mod_http2_h
#define mod_http2_mod_http2_h

/** The http2_var_lookup() optional function retrieves HTTP2 environment
 * variables. */
APR_DECLARE_OPTIONAL_FN(char *, http2_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *,
                         char *));

/** An optional function which returns non-zero if the given connection
 * or its master connection is using HTTP/2. */
APR_DECLARE_OPTIONAL_FN(int, http2_is_h2, (conn_rec *));

#endif
