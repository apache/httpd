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

#ifndef mod_md_md_ocsp_h
#define mod_md_md_ocsp_h


int md_ocsp_prime_status(server_rec *s, apr_pool_t *p,
                         const char *id, apr_size_t id_len, const char *pem);

int md_ocsp_provide_status(server_rec *s, conn_rec *c, const char *id, apr_size_t id_len,
                           ap_ssl_ocsp_copy_resp *cb, void *userdata);

/**
 * Start watchdog for retrieving/updating ocsp status.
 */
apr_status_t md_ocsp_start_watching(struct md_mod_conf_t *mc, server_rec *s, apr_pool_t *p);


#endif /* mod_md_md_ocsp_h */
