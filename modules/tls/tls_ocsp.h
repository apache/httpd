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
#ifndef tls_ocsp_h
#define tls_ocsp_h

/**
 * Prime the collected certified keys for OCSP response provisioning (aka. Stapling).
 *
 * To be called in the post-config phase of the server before connections are handled.
 * @param gc the global module configuration with the certified_key registry
 * @param p the pool to use for allocations
 * @param s the base server record
 */
apr_status_t tls_ocsp_prime_certs(tls_conf_global_t *gc, apr_pool_t *p, server_rec *s);

/**
 * Provide the OCSP response data for the certified_key into the offered buffer,
 * so available.
 * If not data is available `out_n` is set to 0. Same, if the offered buffer
 * is not large enough to hold the complete response.
 * If OCSP response DER data is copied, the number of copied bytes is given in `out_n`.
 *
 * Note that only keys that have been primed initially will have OCSP data available.
 * @param c the current connection
 * @param certified_key the key to get the OCSP response data for
 * @param buf a buffer which can hold up to `buf_len` bytes
 * @param buf_len the length of `buf`
 * @param out_n the number of OCSP response DER bytes copied or 0.
 */
apr_status_t tls_ocsp_update_key(
    conn_rec *c, const rustls_certified_key *certified_key,
    const rustls_certified_key **key_out);

#endif /* tls_ocsp_h */
