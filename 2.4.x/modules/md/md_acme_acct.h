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

#ifndef mod_md_md_acme_acct_h
#define mod_md_md_acme_acct_h

struct md_acme_req;
struct md_json_t;
struct md_pkey_t;


/** 
 * An ACME account at an ACME server.
 */
typedef struct md_acme_acct_t md_acme_acct_t;

struct md_acme_acct_t {
    const char *id;                 /* short, unique id for the account */
    const char *url;                /* url of the account, once registered */
    const char *ca_url;             /* url of the ACME protocol endpoint */
    apr_array_header_t *contacts;   /* list of contact uris, e.g. mailto:xxx */
    const char *tos_required;       /* terms of service asked for by CA */
    const char *agreement;          /* terms of service agreed to by user */
    
    struct md_json_t *registration; /* data from server registration */
    int disabled;
};

#define MD_FN_ACCOUNT           "account.json"
#define MD_FN_ACCT_KEY          "account.pem"

/* ACME account private keys are always RSA and have that many bits. Since accounts
 * are expected to live long, better err on the safe side. */
#define MD_ACME_ACCT_PKEY_BITS  3072

#endif /* md_acme_acct_h */
