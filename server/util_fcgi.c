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

#include "httpd.h"
#include "http_core.h"
#include "http_log.h"
#include "util_fcgi.h"

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

AP_DECLARE(void) ap_fcgi_header_to_array(ap_fcgi_header *h,
                                         unsigned char a[])
{
    a[AP_FCGI_HDR_VERSION_OFFSET]        = h->version;
    a[AP_FCGI_HDR_TYPE_OFFSET]           = h->type;
    a[AP_FCGI_HDR_REQUEST_ID_B1_OFFSET]  = h->requestIdB1;
    a[AP_FCGI_HDR_REQUEST_ID_B0_OFFSET]  = h->requestIdB0;
    a[AP_FCGI_HDR_CONTENT_LEN_B1_OFFSET] = h->contentLengthB1;
    a[AP_FCGI_HDR_CONTENT_LEN_B0_OFFSET] = h->contentLengthB0;
    a[AP_FCGI_HDR_PADDING_LEN_OFFSET]    = h->paddingLength;
    a[AP_FCGI_HDR_RESERVED_OFFSET]       = h->reserved;
}

AP_DECLARE(void) ap_fcgi_header_from_array(ap_fcgi_header *h,
                                           unsigned char a[])
{
    h->version         = a[AP_FCGI_HDR_VERSION_OFFSET];
    h->type            = a[AP_FCGI_HDR_TYPE_OFFSET];
    h->requestIdB1     = a[AP_FCGI_HDR_REQUEST_ID_B1_OFFSET];
    h->requestIdB0     = a[AP_FCGI_HDR_REQUEST_ID_B0_OFFSET];
    h->contentLengthB1 = a[AP_FCGI_HDR_CONTENT_LEN_B1_OFFSET];
    h->contentLengthB0 = a[AP_FCGI_HDR_CONTENT_LEN_B0_OFFSET];
    h->paddingLength   = a[AP_FCGI_HDR_PADDING_LEN_OFFSET];
    h->reserved        = a[AP_FCGI_HDR_RESERVED_OFFSET];
}

AP_DECLARE(void) ap_fcgi_header_fields_from_array(unsigned char *version,
                                                  unsigned char *type,
                                                  apr_uint16_t *request_id,
                                                  apr_uint16_t *content_len,
                                                  unsigned char *padding_len,
                                                  unsigned char a[])
{
    *version         = a[AP_FCGI_HDR_VERSION_OFFSET];
    *type            = a[AP_FCGI_HDR_TYPE_OFFSET];
    *request_id      = (a[AP_FCGI_HDR_REQUEST_ID_B1_OFFSET] << 8)
                     +  a[AP_FCGI_HDR_REQUEST_ID_B0_OFFSET];
    *content_len     = (a[AP_FCGI_HDR_CONTENT_LEN_B1_OFFSET] << 8)
                     +  a[AP_FCGI_HDR_CONTENT_LEN_B0_OFFSET];
    *padding_len     = a[AP_FCGI_HDR_PADDING_LEN_OFFSET];
}

AP_DECLARE(void) ap_fcgi_begin_request_body_to_array(ap_fcgi_begin_request_body *h,
                                                     unsigned char a[])
{
    a[AP_FCGI_BRB_ROLEB1_OFFSET]    = h->roleB1;
    a[AP_FCGI_BRB_ROLEB0_OFFSET]    = h->roleB0;
    a[AP_FCGI_BRB_FLAGS_OFFSET]     = h->flags;
    a[AP_FCGI_BRB_RESERVED0_OFFSET] = h->reserved[0];
    a[AP_FCGI_BRB_RESERVED1_OFFSET] = h->reserved[1];
    a[AP_FCGI_BRB_RESERVED2_OFFSET] = h->reserved[2];
    a[AP_FCGI_BRB_RESERVED3_OFFSET] = h->reserved[3];
    a[AP_FCGI_BRB_RESERVED4_OFFSET] = h->reserved[4];
}

AP_DECLARE(void) ap_fcgi_fill_in_header(ap_fcgi_header *header,
                                        unsigned char type,
                                        apr_uint16_t request_id,
                                        apr_uint16_t content_len,
                                        unsigned char padding_len)
{
    header->version = AP_FCGI_VERSION_1;

    header->type = type;

    header->requestIdB1 = ((request_id >> 8) & 0xff);
    header->requestIdB0 = ((request_id) & 0xff);

    header->contentLengthB1 = ((content_len >> 8) & 0xff);
    header->contentLengthB0 = ((content_len) & 0xff);

    header->paddingLength = padding_len;

    header->reserved = 0;
}

AP_DECLARE(void) ap_fcgi_fill_in_request_body(ap_fcgi_begin_request_body *brb,
                                              int role,
                                              unsigned char flags)
{
    brb->roleB1 = ((role >> 8) & 0xff);
    brb->roleB0 = (role & 0xff);
    brb->flags = flags;
    brb->reserved[0] = 0;
    brb->reserved[1] = 0;
    brb->reserved[2] = 0;
    brb->reserved[3] = 0;
    brb->reserved[4] = 0;
}

AP_DECLARE(apr_size_t) ap_fcgi_encoded_env_len(apr_table_t *env,
                                               apr_size_t maxlen,
                                               int *starting_elem)
{
    const apr_array_header_t *envarr;
    const apr_table_entry_t *elts;
    apr_size_t envlen, actualenvlen;
    int i;

    if (maxlen > AP_FCGI_MAX_CONTENT_LEN) {
        maxlen = AP_FCGI_MAX_CONTENT_LEN;
    }

    envarr = apr_table_elts(env);
    elts = (const apr_table_entry_t *) envarr->elts;

    /* envlen - speculative, may overflow the limit
     * actualenvlen - len required without overflowing
     */
    envlen = actualenvlen = 0;
    for (i = *starting_elem; i < envarr->nelts; ) {
        apr_size_t keylen, vallen;

        if (!elts[i].key) {
            (*starting_elem)++;
            i++;
            continue;
        }

        keylen = strlen(elts[i].key);

        if (keylen >> 7 == 0) {
            envlen += 1;
        }
        else {
            envlen += 4;
        }

        envlen += keylen;

        vallen = elts[i].val ? strlen(elts[i].val) : 0;

        if (vallen >> 7 == 0) {
            envlen += 1;
        }
        else {
            envlen += 4;
        }

        envlen += vallen;

        if (envlen > maxlen) {
            break;
        }

        actualenvlen = envlen;
        (*starting_elem)++;
        i++;
    }

    return actualenvlen;
}

AP_DECLARE(apr_status_t) ap_fcgi_encode_env(request_rec *r,
                                            apr_table_t *env,
                                            void *buffer,
                                            apr_size_t buflen,
                                            int *starting_elem)
{
    apr_status_t rv = APR_SUCCESS;
    const apr_array_header_t *envarr;
    const apr_table_entry_t *elts;
    char *itr;
    int i;

    envarr = apr_table_elts(env);
    elts = (const apr_table_entry_t *) envarr->elts;

    itr = buffer;

    for (i = *starting_elem; i < envarr->nelts; ) {
        apr_size_t keylen, vallen;

        if (!elts[i].key) {
            (*starting_elem)++;
            i++;
            continue;
        }

        keylen = strlen(elts[i].key);

        if (keylen >> 7 == 0) {
            if (buflen < 1) {
                rv = APR_ENOSPC; /* overflow */
                break;
            }
            itr[0] = keylen & 0xff;
            itr += 1;
            buflen -= 1;
        }
        else {
            if (buflen < 4) {
                rv = APR_ENOSPC; /* overflow */
                break;
            }
            itr[0] = ((keylen >> 24) & 0xff) | 0x80;
            itr[1] = ((keylen >> 16) & 0xff);
            itr[2] = ((keylen >> 8) & 0xff);
            itr[3] = ((keylen) & 0xff);
            itr += 4;
            buflen -= 4;
        }

        vallen = elts[i].val ? strlen(elts[i].val) : 0;

        if (vallen >> 7 == 0) {
            if (buflen < 1) {
                rv = APR_ENOSPC; /* overflow */
                break;
            }
            itr[0] = vallen & 0xff;
            itr += 1;
            buflen -= 1;
        }
        else {
            if (buflen < 4) {
                rv = APR_ENOSPC; /* overflow */
                break;
            }
            itr[0] = ((vallen >> 24) & 0xff) | 0x80;
            itr[1] = ((vallen >> 16) & 0xff);
            itr[2] = ((vallen >> 8) & 0xff);
            itr[3] = ((vallen) & 0xff);
            itr += 4;
            buflen -= 4;
        }

        if (buflen < keylen) {
            rv = APR_ENOSPC; /* overflow */
            break;
        }
        memcpy(itr, elts[i].key, keylen);
        itr += keylen;
        buflen -= keylen;

        if (buflen < vallen) {
            rv = APR_ENOSPC; /* overflow */
            break;
        }

        if (elts[i].val) {
            memcpy(itr, elts[i].val, vallen);
            itr += vallen;
        }

        if (buflen == vallen) {
            (*starting_elem)++;
            i++;
            break; /* filled up predicted space, as expected */
        }

        buflen -= vallen;

        (*starting_elem)++;
        i++;
    }

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02492)
                      "ap_fcgi_encode_env: out of space "
                      "encoding environment");
    }

    return rv;
}
