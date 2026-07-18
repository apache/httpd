/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef H3_H
#define H3_H

#include <ap_mmn.h>
#include <apr_version.h>

#include <nghttp3/version.h>

/* Directives default and maximum values. */
#define H3_MAX_CONCURRENT_STREAMS_DEFAULT 100
#define H3_MAX_CONCURRENT_STREAMS_MAX 1000

#define H3_MAX_CONNECTIONS_DEFAULT 256
#define H3_MAX_CONNECTIONS_MAX 10000

#define H3_STREAM_BUFFER_SIZE_DEFAULT (64 * 1024)
#define H3_STREAM_BUFFER_SIZE_MAX (1024 * 1024)

#define H3_MAX_REQUEST_BODY_SIZE_DEFAULT (10 * 1024 * 1024)
#define H3_MAX_REQUEST_BODY_SIZE_MAX (1024UL * 1024 * 1024)

#define H3_MAX_RESPONSE_BODY_SIZE_DEFAULT ((apr_size_t)-1)
#define H3_MAX_RESPONSE_BODY_SIZE_MAX (2UL * 1024 * 1024 * 1024)

#define H3_ALT_SVC_MAX_AGE_DEFAULT 86400
#define H3_ALT_SVC_MAX_AGE_MAX (7UL * 24 * 3600)

#define H3_HANDSHAKE_TIMEOUT_DEFAULT 10
#define H3_HANDSHAKE_TIMEOUT_MAX 600
#define H3_IDLE_TIMEOUT_DEFAULT 300
#define H3_IDLE_TIMEOUT_MAX 86400

/* hidden directives */
#define H3_GOAWAY_GRACE_SECS 3
#define H3_PORT_ACQUIRE_RETRY_MS 200

/* Initial capacity for the doubling-growth request/response body buffers. */
#define H3_BODY_BUF_INIT_CAP (8 * 1024)

#define STREAM_CHUNK_BYTES (4 * 1024)

#define NV_SET(nva, i, n, v) \
    do \
    { \
        (nva)[(i)].name = (uint8_t*)(n); \
        (nva)[(i)].namelen = strlen(n); \
        (nva)[(i)].value = (uint8_t*)(v); \
        (nva)[(i)].valuelen = strlen(v); \
        (nva)[(i)].flags = NGHTTP3_NV_FLAG_NONE; \
    } while (0)

#define IS_H3_CONN(c) (apr_table_get((c)->notes, "IS_mod_http3") != NULL)
#define IS_H3_REQUEST(r) IS_H3_CONN((r)->connection)

#define IS_PSEUDO_TOKEN(t) ((t) == NGHTTP3_QPACK_TOKEN__METHOD || (t) == NGHTTP3_QPACK_TOKEN__SCHEME || (t) == NGHTTP3_QPACK_TOKEN__PATH || (t) == NGHTTP3_QPACK_TOKEN__AUTHORITY)

/* Low two bits of a QUIC stream id encode initiator and direction (RFC 9000). */
#define H3_SID_IS_BIDI(sid) (((sid) & 0x2) == 0)
#define H3_SID_IS_SERVER(sid) (((sid) & 0x1) == 1)

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

#endif /* H3_H */
