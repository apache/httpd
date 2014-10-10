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

#ifndef SSL_CT_LOG_CONFIG_H
#define SSL_CT_LOG_CONFIG_H

#include "httpd.h"
#include "mod_ssl_openssl.h" /* cheap way to get OpenSSL headers */

typedef struct ct_log_config {
    const char *log_id; /* binary form */
    const char *public_key_pem;
    EVP_PKEY *public_key;
#define DISTRUSTED_UNSET -1
#define TRUSTED           0
#define DISTRUSTED        1
    int distrusted;
    apr_time_t min_valid_time, max_valid_time;
    const char *url;
    const char *uri_str;
    apr_uri_t uri;
} ct_log_config;

int log_config_readable(apr_pool_t *p, const char *logconfig,
                        const char **msg);

apr_status_t read_config_db(apr_pool_t *p, server_rec *s_main,
                            const char *log_config_fname,
                            apr_array_header_t *log_config);

apr_status_t save_log_config_entry(apr_array_header_t *log_config,
                                   apr_pool_t *p,
                                   const char *log_id,
                                   const char *pubkey_fname,
                                   const char *distrusted,
                                   const char *min_time,
                                   const char *max_time,
                                   const char *url);

int log_valid_for_sent_sct(const ct_log_config *l);

int log_valid_for_received_sct(const ct_log_config *l, apr_time_t to_check);

int log_configured_for_fetching_sct(const ct_log_config *l);

#endif /* SSL_CT_LOG_CONFIG_H */
