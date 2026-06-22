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

#define NV_SET(nva, i, n, v) \
    do \
    { \
        (nva)[(i)].name = (uint8_t*)(n); \
        (nva)[(i)].namelen = strlen(n); \
        (nva)[(i)].value = (uint8_t*)(v); \
        (nva)[(i)].valuelen = strlen(v); \
        (nva)[(i)].flags = NGHTTP3_NV_FLAG_NONE; \
    } while (0)

#define IS_H3_REQUEST(r) (apr_table_get((r)->connection->notes, "IS_mod_http3") != NULL)

#define IS_PSEUDO_TOKEN(t) ((t) == NGHTTP3_QPACK_TOKEN__METHOD || (t) == NGHTTP3_QPACK_TOKEN__SCHEME || (t) == NGHTTP3_QPACK_TOKEN__PATH || (t) == NGHTTP3_QPACK_TOKEN__AUTHORITY)

#define STREAM_CHUNK_BYTES 4096

/* Low two bits of a QUIC stream id encode initiator and direction (RFC 9000). */
#define H3_SID_IS_BIDI(sid) (((sid) & 0x2) == 0)
#define H3_SID_IS_SERVER(sid) (((sid) & 0x1) == 1)

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

#endif /* H3_H */
