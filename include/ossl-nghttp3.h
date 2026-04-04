
/*
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

#include <nghttp3/nghttp3.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"
#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"
#endif
#include "scoreboard.h"
#include "mpm_common.h"

#include "apr_strings.h"

/* Context for the request to response logic */
struct h3_conn_ctx_t {
    ap_bucket_response *resp; /* Header part of the response */
    apr_bucket *otherpart;    /* file bucket or something the like */
    char *dataheap;           /* data from the heap bucket (page response built im memory, like error pages) */
    apr_size_t dataheaplen;   /* length of the data head */
    apr_pool_t *c3reqpool;    /* a pool that lives a bit more than the request pool (until the next request for the moment) */
    server_rec *s;            /* mostly for log */
};
typedef struct h3_conn_ctx_t h3_conn_ctx_t;

/* a connection can have many requests */
struct h3_request {
    int64_t id_bidi;        /* streamid used to read request and send response */
    apr_pool_t *h3reqpool;  /* sub pool of the h3ssl->c->pool */
    request_rec *r;         /* request to Apache HTTPD */

    uint64_t totalsendbyte; /* for nghttp3_conn_add_ack_offset */
    int finsend;            /* server has send a packet with fin=1 */
    int endstream;          /* on_end_stream() was called */
    int closestream;        /* on_stream_close() was called */

    int num_headers;          /* number of headers received (for debugging purpose) */
    int end_headers_received; /* h3 header received call back called */
    int datadone;             /* h3 has given openssl all the data of the response */

    uint8_t *ptr_data;        /* pointer to the data to send */
    size_t ldata;             /* amount of bytes to send */
    int offset_data;          /* offset to next data to send */

    struct h3_request *next;  /* the next request in the list */

    h3_conn_ctx_t *h3ctx;     /* pointer to request/response we are processing */
};

struct h3_nvs_t {
    nghttp3_nv *resp;
    size_t cur_nv;
    size_t max_nv;
    apr_pool_t *p;
    server_rec *s;
};
typedef struct h3_nvs_t h3_nvs_t;

struct h3_conn_rec_t {
    conn_rec *c;          /* The httpd one */
    h3_conn_ctx_t *h3ctx; /* our h3ctx context */
};
typedef struct h3_conn_rec_t h3_conn_rec_t;

/* run a h3 server logic using openssl calls */
int server(apr_pool_t *p, server_rec *s, unsigned long port, const char *cert_path, const char *key_path);
/* create an internal connection for Apache httpd */
h3_conn_rec_t *create_connection(apr_pool_t *p, server_rec *s);
/* process an internal connection */
apr_status_t process_connection(apr_pool_t *p, server_rec *s, conn_rec *c);
/* process a request, using a internal connection */
apr_status_t process_request(request_rec *r, h3_conn_ctx_t *h3ctx);
