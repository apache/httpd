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

#ifndef mod_md_mod_md_h
#define mod_md_mod_md_h

#include <openssl/evp.h>
#include <openssl/x509v3.h>

struct server_rec;

APR_DECLARE_OPTIONAL_FN(int, 
                        md_is_managed, (struct server_rec *));

/**
 * Get the certificate/key for the managed domain (md_is_managed != 0).
 * 
 * @return APR_EAGAIN if the real certificate is not available yet
 */
APR_DECLARE_OPTIONAL_FN(apr_status_t, 
                        md_get_certificate, (struct server_rec *, apr_pool_t *,
                                             const char **pkeyfile, 
                                             const char **pcertfile));

APR_DECLARE_OPTIONAL_FN(int, 
                        md_is_challenge, (struct conn_rec *, const char *,
                                          X509 **pcert, EVP_PKEY **pkey));

/* Backward compatibility to older mod_ssl patches, will generate
 * a WARNING in the logs, use 'md_get_certificate' instead */
APR_DECLARE_OPTIONAL_FN(apr_status_t, 
                        md_get_credentials, (struct server_rec *, apr_pool_t *,
                                             const char **pkeyfile, 
                                             const char **pcertfile, 
                                             const char **pchainfile));

#endif /* mod_md_mod_md_h */
