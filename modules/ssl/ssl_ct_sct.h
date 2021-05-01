/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SSL_CT_SCT_H
#define SSL_CT_SCT_H

#include "apr_pools.h"
#include "apr_tables.h"

#include "httpd.h"
#include "mod_ssl.h"

#include "ssl_ct_log_config.h"

#define LOG_ID_SIZE 32

typedef struct cert_chain {
    apr_pool_t *p;
    apr_array_header_t *cert_arr; /* array of X509 * */
    X509 *leaf;
} cert_chain;

typedef struct {
    unsigned char version;
    unsigned char logid[LOG_ID_SIZE];
    apr_uint64_t timestamp;
    apr_time_t time;
    char timestr[APR_RFC822_DATE_LEN];
    const unsigned char *extensions;
    apr_uint16_t extlen;
    unsigned char hash_alg;
    unsigned char sig_alg;
    apr_uint16_t siglen;
    const unsigned char *sig;
    const unsigned char *signed_data;
    apr_size_t signed_data_len;
} sct_fields_t;

apr_status_t sct_parse(const char *source,
                       server_rec *s, const unsigned char *sct,
                       apr_size_t len, cert_chain *cc,
                       sct_fields_t *fields);

void sct_release(sct_fields_t *sctf);

apr_status_t sct_verify_signature(conn_rec *c, sct_fields_t *sctf,
                                  apr_array_header_t *log_config);

apr_status_t sct_verify_timestamp(conn_rec *c, sct_fields_t *sctf);

#endif /* SSL_CT_SCT_H */
