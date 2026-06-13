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

#ifndef PATH_MAX
    #define PATH_MAX 255
#endif
#ifndef MAXHEADER
    #define MAXHEADER 255
#endif

#define MAXREQPERCON 10

#define nghttp3_arraylen(A) (sizeof(A) / sizeof(*(A)))

/* status and origin of the streams the possible values are: */
#define CLIENTUNIOPEN (1 << 0)  /* unidirectional open by the client (2, 6 and 10) */
#define CLIENTCLOSED (1 << 1)   /* closed by the client */
#define CLIENTBIDIOPEN (1 << 2) /* bidirectional open by the client (something like 0, 4, 8 ...) */
#define SERVERUNIOPEN (1 << 3)  /* unidirectional open by the server (3, 7 and 11) XXX: Not used ???? */
#define SERVERCLOSED (1 << 4)   /* closed by the server (us) */
#define TOBEREMOVED (1 << 5)    /* marked for removing in read_from_ssl_ids, */
                                /* it will be removed after processing all events */
#define ISLISTENER (1 << 6)     /* the stream is a listener from SSL_new_listener() */
#define ISCONNECTION (1 << 7)   /* the stream is a connection from SSL_accept_connection() */
#define RETRYWRITE (1 << 8)     /* the stream still has some retry to write */

#define MAXSSL_IDS 2000
#define MAXURL 255

/* The different possible terminations */
#define TERM_ECD (1 << 0)
#define TERM_EC (1 << 1)
#define TERM_HLF (1 << 2)
#define TERM_ERR (1 << 3) /* EC and an error */

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

/* -1 is the SSL error, 0 no error all OK */
#define WAIT_DONE 1
#define WAIT_HEADERS 2 /* waiting for headers */
#define WAIT_CLOSE 3   /* waiting for the other side to close */
#define WAIT_RETRY 4   /* waiting for the other side to send more data */
#define TERMINATING 5  /* the connection is terminating / waiting for ECD */
#define CLOSE_DONE 6   /* both side cleanly closed, connection terminated */
#define CLOSE_ERROR 7  /* client closed without request */
#define ERROR_LOGIC 8  /* some internal states were incorrect, process we should exit or abort() */

#endif /* H3_H */
