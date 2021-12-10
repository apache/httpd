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
#ifndef tls_filter_h
#define tls_filter_h

#define TLS_FILTER_RAW    "TLS raw"

typedef struct tls_filter_ctx_t tls_filter_ctx_t;

struct tls_filter_ctx_t {
    conn_rec *c;                         /* connection this context is for */
    tls_conf_conn_t *cc;                 /* tls module configuration of connection */

    ap_filter_t *fin_ctx;                /* Apache's entry into the input filter chain */
    apr_bucket_brigade *fin_tls_bb;      /* TLS encrypted, incoming network data */
    apr_bucket_brigade *fin_tls_buffer_bb; /* TLS encrypted, incoming network data buffering */
    apr_bucket_brigade *fin_plain_bb;    /* decrypted, incoming traffic data */
    apr_off_t fin_bytes_in_rustls;       /* # of input TLS bytes in rustls_connection */
    apr_read_type_e fin_block;           /* Do we block on input reads or not? */

    ap_filter_t *fout_ctx;               /* Apache's entry into the output filter chain */
    char *fout_buf_plain;                /* a buffer to collect plain bytes for output */
    apr_size_t fout_buf_plain_len;       /* the amount of bytes in the buffer */
    apr_size_t fout_buf_plain_size;      /* the total size of the buffer */
    apr_bucket_brigade *fout_tls_bb;     /* TLS encrypted, outgoing network data */
    apr_off_t fout_bytes_in_rustls;      /* # of output plain bytes in rustls_connection */
    apr_off_t fout_bytes_in_tls_bb;      /* # of output tls bytes in our brigade */

    apr_size_t fin_max_in_rustls;         /* how much tls we like to read into rustls */
    apr_size_t fout_max_in_rustls;        /* how much plain bytes we like in rustls */
    apr_size_t fout_max_bucket_size;      /* how large bucket chunks we handle before splitting */
    apr_size_t fout_auto_flush_size;      /* on much outoing TLS data we flush to network */
};

/**
 * Register the in-/output filters for converting TLS to application data and vice versa.
 */
void tls_filter_register(apr_pool_t *pool);

/**
 * Initialize the pre_connection state. Install all filters.
 *
 * @return OK if TLS on connection is enabled, DECLINED otherwise
 */
int tls_filter_pre_conn_init(conn_rec *c);

/**
 * Initialize the connection for use, perform the TLS handshake.
 *
 * Any failure will lead to the connection becoming aborted.
 */
void tls_filter_conn_init(conn_rec *c);

/*
 * <https://tools.ietf.org/html/rfc8449> says:
 * "For large data transfers, small record sizes can materially affect performance."
 * and
 * "For TLS 1.2 and earlier, that limit is 2^14 octets. TLS 1.3 uses a limit of
 * 2^14+1 octets."
 * Maybe future TLS versions will raise that value, but for now these limits stand.
 * Given the choice, we would like rustls to provide traffic data in those chunks.
 */
#define TLS_PREF_PLAIN_CHUNK_SIZE       (16384)

/*
 * When retrieving TLS chunks for rustls, or providing it a buffer
 * to pass out TLS chunks (which are then bucketed and written to the
 * network filters), we ideally would do that in multiples of TLS
 * messages sizes.
 * That would be TLS_PREF_WRITE_SIZE + TLS Message Overhead, such as
 * MAC and padding. But these vary with protocol and ciphers chosen, so
 * we define something which should be "large enough", but not overly so.
 */
#define TLS_REC_EXTRA             (1024)
#define TLS_REC_MAX_SIZE   (TLS_PREF_PLAIN_CHUNK_SIZE + TLS_REC_EXTRA)

#endif /* tls_filter_h */