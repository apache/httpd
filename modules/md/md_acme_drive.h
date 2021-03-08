/* Copyright 2019 greenbytes GmbH (https://www.greenbytes.de)
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

#ifndef md_acme_drive_h
#define md_acme_drive_h

struct apr_array_header_t;
struct md_acme_order_t;
struct md_credentials_t;
struct md_result_t;

typedef struct md_acme_driver_t {
    md_proto_driver_t *driver;
    void *sub_driver;
    
    md_acme_t *acme;
    md_t *md;
    struct apr_array_header_t *domains;
    apr_array_header_t *ca_challenges;
    
    int complete;
    apr_array_header_t *creds;       /* the new md_credentials_t */

    struct md_credentials_t *cred;   /* credentials currently being processed */ 
    const char *chain_up_link;       /* Link header "up" from last chain retrieval,
                                        needs to be followed */

    struct md_acme_order_t *order;
    apr_interval_time_t authz_monitor_timeout;
    
    const char *csr_der_64;
    apr_interval_time_t cert_poll_timeout;
    
} md_acme_driver_t;

apr_status_t md_acme_drive_set_acct(struct md_proto_driver_t *d, 
                                    struct md_result_t *result);
apr_status_t md_acme_drive_setup_cred_chain(struct md_proto_driver_t *d, 
                                            struct md_result_t *result);
apr_status_t md_acme_drive_cert_poll(struct md_proto_driver_t *d, int only_once);

#endif /* md_acme_drive_h */

