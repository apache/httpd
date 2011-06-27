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

#ifndef AP_LDAP_PRIVATE_H
#define AP_LDAP_PRIVATE_H

#define LDAP_DECLARE(x) x

#include "ap_ldap.h"

/* Private declarations of API functions accessible only internally by
 * mod_ldap; these are all exported and the corresponding API docs are
 * in ap_ldap_*.h. */

LDAP_DECLARE(int) ap_ldap_get_option(apr_pool_t *pool,
                                     LDAP *ldap,
                                     int option,
                                     void *outvalue,
                                     ap_ldap_err_t **result_err);

LDAP_DECLARE(int) ap_ldap_set_option(apr_pool_t *pool,
                                     LDAP *ldap,
                                     int option,
                                     const void *invalue,
                                     ap_ldap_err_t **result_err);

LDAP_DECLARE(int) ap_ldap_ssl_init(apr_pool_t *pool,
                                      const char *cert_auth_file,
                                      int cert_file_type,
                                      ap_ldap_err_t **result_err);
LDAP_DECLARE(int) ap_ldap_ssl_deinit(void);
LDAP_DECLARE(int) ap_ldap_init(apr_pool_t *pool,
                                  LDAP **ldap,
                                  const char *hostname,
                                  int portno,
                                  int secure,
                                  ap_ldap_err_t **result_err);

LDAP_DECLARE(int) ap_ldap_info(apr_pool_t *pool,
                                  ap_ldap_err_t **result_err);

LDAP_DECLARE(int) ap_ldap_is_ldap_url(const char *url);
LDAP_DECLARE(int) ap_ldap_is_ldaps_url(const char *url);
LDAP_DECLARE(int) ap_ldap_is_ldapi_url(const char *url);
LDAP_DECLARE(int) ap_ldap_url_parse_ext(apr_pool_t *pool,
                                           const char *url_in,
                                           ap_ldap_url_desc_t **ludpp,
                                           ap_ldap_err_t **result_err);
LDAP_DECLARE(int) ap_ldap_url_parse(apr_pool_t *pool,
                                       const char *url_in,
                                       ap_ldap_url_desc_t **ludpp,
                                       ap_ldap_err_t **result_err);

LDAP_DECLARE(apr_status_t) ap_ldap_rebind_init(apr_pool_t *pool);
LDAP_DECLARE(apr_status_t) ap_ldap_rebind_add(apr_pool_t *pool,
                                                 LDAP *ld,
                                                 const char *bindDN,
                                                 const char *bindPW);
LDAP_DECLARE(apr_status_t) ap_ldap_rebind_remove(LDAP *ld);

#endif /* AP_LDAP_PRIVATE_H */
