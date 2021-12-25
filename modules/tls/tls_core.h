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
#ifndef tls_core_h
#define tls_core_h

/* The module's state handling of a connection in normal chronological order,
 */
typedef enum {
    TLS_CONN_ST_INIT,             /* being initialized */
    TLS_CONN_ST_DISABLED,         /* TLS is disabled here */
    TLS_CONN_ST_CLIENT_HELLO,    /* TLS is enabled, prep handshake */
    TLS_CONN_ST_HANDSHAKE,        /* TLS is enabled, handshake ongonig */
    TLS_CONN_ST_TRAFFIC,          /* TLS is enabled, handshake done */
    TLS_CONN_ST_NOTIFIED,         /* TLS is enabled, notification to end sent */
    TLS_CONN_ST_DONE,             /* TLS is enabled, TLS has shut down */
} tls_conn_state_t;

#define TLS_CONN_ST_IS_ENABLED(cc)  (cc && cc->state >= TLS_CONN_ST_CLIENT_HELLO)

struct tls_filter_ctx_t;

/* The modules configuration for a connection. Created at connection
 * start and mutable during the lifetime of the connection.
 * (A conn_rec is only ever processed by one thread at a time.)
 */
typedef struct {
    server_rec *server;               /* the server_rec selected for this connection,
                                       * initially c->base_server, to be negotiated via SNI. */
    tls_conf_dir_t *dc;               /* directory config applying here */
    tls_conn_state_t state;
    int outgoing;                     /* != 0 iff outgoing connection (redundant once c->outgoing is everywhere) */
    int service_unavailable;          /* we 503 all requests on this connection */
    tls_client_auth_t client_auth;    /* how client authentication with certificates is used */
    int client_hello_seen;            /* the client hello has been inspected */

    rustls_connection *rustls_connection; /* the session used on this connection or NULL */
    const rustls_server_config *rustls_server_config; /* the config made for this connection (incoming) or NULL */
    const rustls_client_config *rustls_client_config; /* the config made for this connection (outgoing) or NULL */
    struct tls_filter_ctx_t *filter_ctx; /* the context used by this connection's tls filters */

    apr_array_header_t *local_keys;   /* rustls_certified_key* array of connection specific keys */
    const rustls_certified_key *key;  /* the key selected for the session */
    int key_cloned;                   /* != 0 iff the key is a unique clone, to be freed */
    apr_array_header_t *peer_certs;   /* handshaked peer ceritificates or NULL */
    const char *sni_hostname;         /* the SNI value from the client hello, or NULL */
    const apr_array_header_t *alpn;   /* the protocols proposed via ALPN by the client */
    const char *application_protocol;    /* the ALPN selected protocol or NULL */

    int session_id_cache_hit;         /* if a submitted session id was found in our cache */

    apr_uint16_t tls_protocol_id;      /* the TLS version negotiated */
    const char *tls_protocol_name;     /* the name of the TLS version negotiated */
    apr_uint16_t tls_cipher_id;       /* the TLS cipher suite negotiated */
    const char *tls_cipher_name;      /* the name of TLS cipher suite negotiated */

    const char *user_name;            /* != NULL if we derived a TLSUserName from the client_cert */
    apr_table_t *subprocess_env;      /* common TLS variables for this connection */

    rustls_result last_error;
    const char *last_error_descr;

} tls_conf_conn_t;

/* Get the connection specific module configuration. */
tls_conf_conn_t *tls_conf_conn_get(conn_rec *c);

/* Set the module configuration for a connection. */
void tls_conf_conn_set(conn_rec *c, tls_conf_conn_t *cc);

/* Return OK iff this connection is a TSL connection (or a secondary on a TLS connection). */
int tls_conn_check_ssl(conn_rec *c);

/**
 * Initialize the module's global and server specific settings. This runs
 * in Apache's "post-config" phase, meaning the configuration has been read
 * and checked for syntactic and other easily verifiable errors and now
 * it is time to load everything in and make it ready for traffic.
 * <p>      a memory pool staying with us the whole time until the server stops/reloads.
 * <ptemp>  a temporary pool as a scratch buffer that will be destroyed shortly after.
 * <base_server> the server for the global configuration which links -> next to
 *          all contained virtual hosts configured.
 */
apr_status_t tls_core_init(apr_pool_t *p, apr_pool_t *ptemp, server_rec *base_server);

/**
 * Initialize the module's outgoing connection settings. This runs
 * in Apache's "post-config" phase after mod_proxy.
 */
apr_status_t tls_core_init_outgoing(apr_pool_t *p, apr_pool_t *ptemp, server_rec *base_server);

/**
 * Supply a directory configuration for the connection to work with. This
 * maybe NULL. This can be called several times during the lifetime of a
 * connection and must not change the current TLS state.
 * @param c the connection
 * @param dir_conf optional directory configuration that applies
 */
void tls_core_conn_bind(conn_rec *c, ap_conf_vector_t *dir_conf);

/**
 * Disable TLS on a new connection. Will do nothing on already initialized
 * connections.
 * @param c a new connection
 */
void tls_core_conn_disable(conn_rec *c);

/**
 * Initialize the tls_conf_connt_t for the connection
 * and decide if TLS is enabled or not.
 * @return OK if enabled, DECLINED otherwise
 */
int tls_core_pre_conn_init(conn_rec *c);

/**
 * Initialize the module for a TLS enabled connection.
 * @param c a new connection
 */
apr_status_t tls_core_conn_init(conn_rec *c);

/**
 * Called when the ClientHello has been received and values from it
 * have been extracted into the `tls_conf_conn_t` of the connection.
 *
 * Decides:
 * - which `server_rec` this connection is for (SNI)
 * - which application protocol to use (ALPN)
 * This may be unsuccessful for several reasons. The SNI
 * from the client may not be known or the selected server
 * has not certificates available. etc.
 * On success, a proper `rustls_connection` will have been
 * created and set in the `tls_conf_conn_t` of the connection.
 */
apr_status_t tls_core_conn_seen_client_hello(conn_rec *c);

/**
 * The TLS handshake for the connection has been successfully performed.
 * This means that TLS related properties, such as TLS version and cipher,
 * are known and the props in `tls_conf_conn_t` of the connection
 * can be set.
 */
apr_status_t tls_core_conn_post_handshake(conn_rec *c);

/**
 * After a request has been read, but before processing is started, we
 * check if everything looks good to us:
 * - was an SNI hostname provided by the client when we have vhosts to choose from?
 *   if not, we deny it.
 * - if the SNI hostname and request host are not the same, are they - from TLS
 *   point of view - 'compatible' enough? For example, if one server requires
 *   client certificates and the other not (or with different settings), such
 *   a request will also be denied.
 * returns DECLINED if everything is ok, otherwise an HTTP response code to
 *   generate an error page for.
 */
int tls_core_request_check(request_rec *r);

/**
 * A Rustls error happened while processing the connection. Look up an
 * error description, determine the apr_status_t to use for it and remember
 * this as the last error at tls_conf_conn_t.
 */
apr_status_t tls_core_error(conn_rec *c, rustls_result rr, const char **perrstr);

/**
 * Determine if we handle the TLS for an outgoing connection or not.
 * @param c the connection
 * @return OK if we handle the TLS, DECLINED otherwise.
 */
int tls_core_setup_outgoing(conn_rec *c);

#endif /* tls_core_h */
