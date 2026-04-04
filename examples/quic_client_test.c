/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <apr-1/apr_time.h>

#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <nghttp3/nghttp3.h>

static int done;

static void make_nv(nghttp3_nv *nv, const char *name, const char *value)
{
    nv->name        = (uint8_t *)name;
    nv->value       = (uint8_t *)value;
    nv->namelen     = strlen(name);
    nv->valuelen    = strlen(value);
    nv->flags       = NGHTTP3_NV_FLAG_NONE;
}

static char msg2[16000];

/* HTTP/3 stream management
 * According to HTTP/3 spec, we need:
 * - 3 unidirectional streams: 1 control + 2 QPACK (encoder/decoder)
 * - num_streams bidirectional request streams
 * - Additional streams that the server may create
 */
#define STATUS_NONE 0
#define STATUS_FINSEND (1 << 0)
#define STATUS_FINRECEIVED (1 << 1)

struct ssl_id {
  SSL *s;
  int64_t id;
  int status;
};

static struct ssl_id *ssl_ids = NULL;
static int max_ssl_ids = 0;

/* Calculate max streams needed per HTTP/3 spec:
 * 3 (control + QPACK) + num_streams (requests) + num_streams (server pushes/responses)
 */
static int calculate_max_streams(int num_streams)
{
  return 3 + (num_streams * 2);
}

static void init_id(int num_streams)
{
  max_ssl_ids = calculate_max_streams(num_streams);
  ssl_ids = (struct ssl_id *)calloc(max_ssl_ids, sizeof(struct ssl_id));
  if (ssl_ids == NULL) {
    printf("Failed to allocate ssl_ids array!\n");
    exit(1);
  }
  for (int i=0; i<max_ssl_ids; i++) {
    ssl_ids[i].s = NULL;
    ssl_ids[i].id = -1;
    ssl_ids[i].status = STATUS_NONE;
  }
  printf("HTTP/3 stream tracking initialized: %d streams (3 control/QPACK + %d request streams)\n",
         max_ssl_ids, num_streams);
}

static void cleanup_id()
{
  if (ssl_ids != NULL) {
    free(ssl_ids);
    ssl_ids = NULL;
    max_ssl_ids = 0;
  }
}

static void add_id(SSL *s) {
  for (int i=0; i<max_ssl_ids; i++) {
    if (!ssl_ids[i].s) {
      ssl_ids[i].s = s;
      ssl_ids[i].id = SSL_get_stream_id(s);
      ssl_ids[i].status = STATUS_NONE;
      return;
    }
  }
  printf("Oops too many streams to add!!! (max: %d)\n", max_ssl_ids);
  exit(1);
}
static void del_id(SSL *s) {
  for (int i=0; i<max_ssl_ids; i++) {
    if (ssl_ids[i].s == s) {
      ssl_ids[i].s = NULL;
      ssl_ids[i].id = -1;
      ssl_ids[i].status = STATUS_NONE;
      return;
    }
  }
  printf("Oops del_id: stream not Found!!!\n");
  exit(1);
}

static SSL *get_ssl_from_id(int64_t id)
{
  for (int i=0; i<max_ssl_ids; i++) {
    if (ssl_ids[i].id == id) {
      return ssl_ids[i].s;
    }
  }
  return NULL;
}

/* Accept the new QUIC stream opened by the other side */
static void accept_new_ssl_ids(SSL *s,  BIO *bio) {
  int num = SSL_get_accept_stream_queue_len(s);
  if (num > 0) {
    for (int i=0; i<num; i++) {
      SSL *new_ssl = SSL_accept_stream(s, 0);
      if (new_ssl) {
          printf("accept_new_ssl_ids accepted: SSL_get_stream_id: %d %d\n", SSL_get_stream_id(new_ssl), SSL_get_stream_type(new_ssl));
          add_id(new_ssl);
          SSL_set_msg_callback(new_ssl, SSL_trace);
          SSL_set_msg_callback_arg(new_ssl, bio);
      } else {
          printf("accept_new_ssl_ids NULL, weird\n");
          fflush(stdout);
          exit(1);
      }
    }
  }
}

static void TEST_info(char *fmt, ...)                                                       
{                                                                               
   va_list arg_ptr;                                                             
                                                                                
   va_start(arg_ptr, fmt);                                                      
   vprintf(fmt, arg_ptr);                                                       
   va_end(arg_ptr);                                                             
}
#define TEST_error TEST_info

static int is_want(SSL *s, int ret)
{
    int ec = SSL_get_error(s, ret);

    return ec == SSL_ERROR_WANT_READ || ec == SSL_ERROR_WANT_WRITE || ec == SSL_ERROR_ZERO_RETURN;
}

/* Read and process the data for the ids we have */
static int read_from_ssl_ids(nghttp3_conn *conn)
{
  for (int i=0; i<max_ssl_ids; i++) {
    if (ssl_ids[i].s) {
      int id =  SSL_get_stream_id(ssl_ids[i].s);
      if (id == -1 || id == 2 || id == 6 || id == 10)
          continue; // skip those.
      
      /* try to read */
      size_t l = sizeof(msg2) - 1;
      int ret = SSL_read_ex(ssl_ids[i].s, msg2, sizeof(msg2) - 1, &l);
      if (ret <= 0) {
        if (SSL_get_error(ssl_ids[i].s, ret) == SSL_ERROR_ZERO_RETURN) {
             /* Check status flags */
             printf("\n SSL_ERROR_ZERO_RETURN on %d (status=0x%x)\n", id, ssl_ids[i].status);
             if (ssl_ids[i].status & STATUS_FINSEND) {
                 printf("  STATUS_FINSEND is set on %d\n", id);
             }
             if (ssl_ids[i].status & STATUS_FINRECEIVED) {
                 printf("  STATUS_FINRECEIVED is set on %d\n", id);
             }
             if ((ssl_ids[i].status & (STATUS_FINSEND | STATUS_FINRECEIVED)) == (STATUS_FINSEND | STATUS_FINRECEIVED)) {
                 printf("  Both FIN flags set - stream fully closed on %d\n", id);
                 /* Stream will be closed via cb_h3_end_stream callback */
                 continue;
             }
             /* Notify nghttp3 of EOF only if not already done */
             if (!(ssl_ids[i].status & STATUS_FINRECEIVED)) {
                 ret = nghttp3_conn_read_stream(conn, SSL_get_stream_id(ssl_ids[i].s), NULL, 0, 1);
                 if (ret < 0) {
                     printf("\n SSL_read_ex nghttp3_conn_read_stream %d on %d\n", ret, SSL_get_stream_id(ssl_ids[i].s));
                     fflush(stdout);
                     return -1;
                 }
                 ssl_ids[i].status |= STATUS_FINRECEIVED;
                 printf("  STATUS_FINRECEIVED set via SSL_ERROR_ZERO_RETURN on %d\n", id);
             }
             continue;
         } else if (SSL_get_stream_read_state(ssl_ids[i].s)  == SSL_STREAM_STATE_RESET_REMOTE) {
             printf("\n SSL_read_ex remote reset\n");
         } else if (!(is_want(ssl_ids[i].s, ret))) {
             printf("\n SSL_read_ex FAILED %d on %d!\n", SSL_get_error(ssl_ids[i].s, ret), SSL_get_stream_id(ssl_ids[i].s));
             char buf[256];
             unsigned long err = SSL_get_error(ssl_ids[i].s, ret);
             printf("Detailed Error: %s\n", ERR_error_string(err, buf));
             fflush(stdout);
             continue; // TODO
         }
      } else {
        int32_t flags = NGHTTP3_DATA_FLAG_NONE;
        if (SSL_get_stream_read_state(ssl_ids[i].s) ==  SSL_STREAM_STATE_FINISHED) {
            flags |= NGHTTP3_DATA_FLAG_EOF;
        }

        printf("\nreading something %d on %d\n", l, SSL_get_stream_id(ssl_ids[i].s));
        int r = nghttp3_conn_read_stream(conn, SSL_get_stream_id(ssl_ids[i].s), msg2, l, flags);
        printf("nghttp3_conn_read_stream used %d of %d on %d flag: %d\n", r, l, SSL_get_stream_id(ssl_ids[i].s), flags);
        if (flags & NGHTTP3_DATA_FLAG_EOF) {
            ssl_ids[i].status |= STATUS_FINRECEIVED;
            printf("Status set to FINRECEIVED for stream %d\n", SSL_get_stream_id(ssl_ids[i].s));
        }
      }
    } 
  }
}

static int cb_h3_acked_stream_data(nghttp3_conn *conn, int64_t stream_id,
                             uint64_t datalen, void *conn_user_data,
                             void *stream_user_data)
{
    printf("cb_h3_acked_stream_data! on %d\n", stream_id);
    return 0;
}

static int cb_h3_end_stream(nghttp3_conn *conn, int64_t stream_id,
                             void *conn_user_data, void *stream_user_data)
{
    SSL *stream = get_ssl_from_id(stream_id);
    printf("cb_h3_end_stream! on %d\n", stream_id);
    fflush(stdout);

    if (stream) {
        /* Close the stream in nghttp3 to trigger stream_close callback */
        int ret = nghttp3_conn_close_stream(conn, stream_id, NGHTTP3_H3_NO_ERROR);
        if (ret != 0 && ret != NGHTTP3_ERR_STREAM_NOT_FOUND) {
            printf("  cb_h3_end_stream: nghttp3_conn_close_stream failed: %d on %d\n", ret, stream_id);
        }

        /* Clean up SSL stream */
        del_id(stream);
        SSL_free(stream);
        done--;
    }

    return 0;
}

static int cb_h3_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                             uint64_t datalen, void *user_data,
                             void *stream_user_data) {
    printf("cb_h3_acked_req_body! on %d\n", stream_id);
    return 0;
}
static int cb_h3_stream_close(nghttp3_conn *conn, int64_t stream_id,
                             uint64_t app_error_code, void *conn_user_data,
                             void *stream_user_data)
{
    printf("cb_h3_stream_close! on %d %d\n", stream_id, app_error_code);
    return 0;
}
static int begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                         void *stream_user_data) {
    printf("begin_headers!\n");
    return 0;
}
static int cb_h3_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *conn_user_data, void *stream_user_data) {
    printf("cb_h3_begin_headers! on %d\n", stream_id);
    return 0;
}
static int cb_h3_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                       nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                       void *user_data, void *stream_user_data) {
    printf("cb_h3_recv_header! on %d\n", stream_id);
    nghttp3_vec h3name = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec h3val = nghttp3_rcbuf_get_buf(value);

    if (token == NGHTTP3_QPACK_TOKEN__STATUS) {
        printf("Status %.*s\n", h3val.len, h3val.base);
    } else {
        printf("header %.*s: %.*s\n",  (int)h3name.len, h3name.base, (int)h3val.len, h3val.base);
    }
    return 0;
}
static int cb_h3_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                       void *user_data, void *stream_user_data) {

    printf("cb_h3_end_headers! on %d fin: %d\n", stream_id, fin);
    return 0;
}
static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream_id,
                                 const uint8_t *data, size_t datalen,
                                 void *conn_user_data, void *stream_user_data) {
    printf("cb_h3_recv_data! %d on %d\n", datalen, stream_id);
    printf("cb_h3_recv_data! %.*s\n", datalen, data);
    return 0;
}
static int cb_h3_deferred_consume(nghttp3_conn *conn, int64_t stream3_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
    printf("cb_h3_deferred_consume! on %d\n", stream3_id);
    return 0;
}
static int cb_h3_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
    printf("cb_h3_stop_sending! on %d\n", stream_id);
    return 0;
}
static int cb_h3_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data) {
    printf("cb_h3_reset_stream! on %d\n", stream_id);
    return 0;
}
static int cb_h3_shutdown(nghttp3_conn *conn, int64_t id, void *conn_user_data) {
    printf("cb_h3_shutdown! on %d\n", id);
    return 0;
}
static int cb_h3_recv_settings(nghttp3_conn *conn, const nghttp3_settings *settings, void *conn_user_data) {
    printf("cb_h3_recv_settings!\n");
    printf("cb_h3_recv_settings: max_field_section_size %ld\n", settings->max_field_section_size);
    printf("cb_h3_recv_settings: enable_connect_protocol %d\n", settings->enable_connect_protocol);
    printf("cb_h3_recv_settings: h3_datagram %d\n", settings->h3_datagram);
    return 0;
}


static int jfc_send_stream(SSL *M_ssl, int sveccnt, nghttp3_vec *vec, int fin)
{
    int i;
    int total_written = 0;
    int flagwrite = 0;
    for (i=0; i<sveccnt; i++) {
       size_t written = vec[i].len;
       if (fin && i == sveccnt - 1)
           flagwrite = SSL_WRITE_FLAG_CONCLUDE; 
       int rv = SSL_write_ex2(M_ssl, vec[i].base, vec[i].len, flagwrite, &written);
       printf("jfc_send_stream written %d:%d on %d\n", written, vec[i].len, SSL_get_stream_id(M_ssl));
       if (rv<=0)
           printf("SSL_write failed! %d on %d\n", SSL_get_error(M_ssl, rv), SSL_get_stream_id(M_ssl));
       total_written = total_written + written;
    }
    return total_written;
}

/* Send everything we can */
static void send_all_stream(nghttp3_conn *conn)
{
    for (;;) {
        int64_t stream_id = 0;
        int fin = 0;
        nghttp3_vec vec[256];
        nghttp3_ssize sveccnt = nghttp3_conn_writev_stream(conn, &stream_id, &fin, vec, 256);
        if (sveccnt<0) {
            printf("nghttp3_conn_writev_stream failed %d!\n", sveccnt);
            exit(1);
        } else if (sveccnt == 0 && stream_id == -1) {
            // Too verbose printf("Done with nghttp3_conn_writev_stream\n");
            // fflush(stdout);
            break;
        } else if (sveccnt == 0 && stream_id != -1) {
            printf("Done with nghttp3_conn_writev_stream on %d fin: %d\n", stream_id, fin);
            nghttp3_conn_add_write_offset(conn, stream_id, 0);
            break;
        } else {
            /* We have to write the vec stuff */
            printf("sending %d on %d (fin: %d)\n", sveccnt, stream_id, fin);
            SSL *MY_ssl = get_ssl_from_id(stream_id);
            if (!MY_ssl) {
                 printf("on %d unknown\n", stream_id);
                 exit(1);
            }

            int i = jfc_send_stream(MY_ssl, sveccnt, vec, fin);

            if (i != 0) {
                /* Assume we have written everything */
                printf("sent %d on %d (fin: %d)\n", sveccnt, stream_id, fin);
                nghttp3_conn_add_write_offset(conn, stream_id, (size_t)nghttp3_vec_len(vec, (size_t)sveccnt));
                printf("sent %d on %d (fin: %d)\n", sveccnt, stream_id, fin);
                if (fin) {
                    printf("FIN on %d\n", stream_id);
                    /* Set FINSEND status */
                    for (int j=0; j<max_ssl_ids; j++) {
                        if (ssl_ids[j].id == stream_id) {
                            ssl_ids[j].status |= STATUS_FINSEND;
                            printf("Status set to FINSEND for stream %d\n", stream_id);
                            break;
                        }
                    }
                    // SSL_stream_conclude(MY_ssl, 0);
                }
                // nghttp3_conn_add_ack_offset(conn, stream_id, (size_t)nghttp3_vec_len(vec, (size_t)sveccnt));
                continue;
            } else {
                printf("sending NOTHING %d on %d (fin: %d)\n", sveccnt, stream_id, fin);
            }
        }
    }
}

static int test_quic_client(char *hostname, short port, char *sport, int num_streams)
{
    int testresult = 0, ret;
    int c_fd = -1;
    BIO *c_net_bio = NULL;
    BIO *c_net_bio_own = NULL;
    BIO_ADDR *s_addr_ = NULL;
    struct in_addr ina = {0};
    SSL_CTX *c_ctx = NULL;
    SSL *c_ssl = NULL;
    int c_connected = 0, c_write_done = 0, c_shutdown = 0, c_streamopened = 0;
    SSL **d_ssl = NULL;
    int stream_idx = 0;
    size_t l = 0, c_total_read = 0;
    apr_time_t start_time;
    /* unsigned char alpn[] = { 8, 'h', 't', 't', 'p', '/', '0', '.', '9' }; lol */
    unsigned char alpn[] = { 5, 'h', '3', '-', '2', '9', 2, 'h', '3' };

    struct hostent *hp;

    /* try to use nghttp3 to build a get request */
    nghttp3_conn *conn;
    nghttp3_settings settings;
    nghttp3_callbacks callbacks = {0};
    nghttp3_vec vec[256];
    int64_t stream_id;
    // userdata ud;
    char ud[10];
    int fin;
    const nghttp3_mem *mem = nghttp3_mem_default();

    char authority[128];
    nghttp3_nv nva[16];
    size_t num_nv = 0;

    strcpy(authority, hostname);
    strcat(authority, ":");
    strcat(authority, sport);

    make_nv(&nva[num_nv++], ":method", "GET");
    make_nv(&nva[num_nv++], ":scheme", "https");
    make_nv(&nva[num_nv++], ":authority", authority);
    make_nv(&nva[num_nv++], ":path", "/");
    make_nv(&nva[num_nv++], "user-agent", "openssl-h3-examples/jfclere");
    // make_nv(&nva[num_nv++], "accept", "*/*");

    init_id(num_streams);
    nghttp3_settings_default(&settings);
    memset(&ud, 0, sizeof(ud));

    /* Allocate array for multiple d_ssl streams */
    d_ssl = (SSL **)calloc(num_streams, sizeof(SSL *));
    if (d_ssl == NULL) {
        TEST_error("Failed to allocate d_ssl array\n");
        goto err;
    }

    /* Define our call back */
    callbacks.acked_stream_data = cb_h3_acked_stream_data;
    callbacks.stream_close = cb_h3_stream_close;
    callbacks.recv_data = cb_h3_recv_data;
    callbacks.deferred_consume = cb_h3_deferred_consume;
    callbacks.begin_headers = cb_h3_begin_headers;
    callbacks.recv_header = cb_h3_recv_header;
    callbacks.end_headers = cb_h3_end_headers;
    callbacks.begin_trailers = NULL;
    callbacks.recv_trailer = cb_h3_recv_header; /* Why not ??? */
    callbacks.end_trailers = NULL;
    callbacks.stop_sending = cb_h3_stop_sending;
    callbacks.end_stream = cb_h3_end_stream;
    callbacks.reset_stream = cb_h3_reset_stream;
    callbacks.shutdown = cb_h3_shutdown;
    callbacks.recv_settings = cb_h3_recv_settings;
    
    if (nghttp3_conn_client_new(&conn, &callbacks, &settings, mem, &ud)) {
        printf("nghttp3_conn_client_new failed!\n");
        exit(1);
    }

    hp = gethostbyname(hostname);
    if (hp == NULL)
        goto err;

    memcpy(&ina,hp->h_addr,hp->h_length);
    printf("Connecting to %s:%d\n",  inet_ntoa(ina), port);
    printf("Connecting to authority %s\n", authority);

    TEST_info("Before: BIO_socket\n");
    c_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (c_fd == -1)
        goto err;

    if (!BIO_socket_nbio(c_fd, 1))
        goto err;

    s_addr_ = BIO_ADDR_new();
    if (s_addr_ == NULL)
        goto err;

    TEST_info("Before: BIO_ADDR_rawmake\n");
    if (!(BIO_ADDR_rawmake(s_addr_, AF_INET, &ina, sizeof(ina),
                                    htons(port)))) {
        TEST_error("BIO_ADDR_rawmake failed!\n");
        goto err;
    }

    c_net_bio_own = BIO_new_dgram(c_fd, 0);
    c_net_bio = c_net_bio_own;
    if (c_net_bio == NULL)
        goto err;

    if (!BIO_dgram_set_peer(c_net_bio, s_addr_))
        goto err;

    c_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (c_ctx == NULL)
        goto err;

    /* Enable trust chain verification. */
    SSL_CTX_set_verify(c_ctx, SSL_VERIFY_PEER, NULL);

    /* Load default root CA store. */
    if (!SSL_CTX_load_verify_locations(c_ctx, "/etc/pki/CA/cacert.pem" , "/etc/ssl/certs")) {
        goto err;
    }
/* problems ...
    if (SSL_CTX_set_default_verify_paths(c_ctx) == 0) {
        goto err;
    }
 */

    c_ssl = SSL_new(c_ctx);
    if (c_ssl == NULL)
        goto err;

    SSL_set_tlsext_host_name(c_ssl, hostname); /* (http3) SNI not found in connection from ... */
    SSL_set1_host(c_ssl, hostname); /* check hostname? */
    SSL_set1_initial_peer_addr(c_ssl, s_addr_); /* What about BIO_dgram_set_peer() */

    /* SSL_CTX_set_session_id_context missing ? */
    /*
    int session_id_context = -1;
    SSL_CTX_set_session_id_context(c_ctx, (void *)&session_id_context, sizeof(session_id_context));
     */

    /* 0 is a success for SSL_set_alpn_protos() */
    if (SSL_set_alpn_protos(c_ssl, alpn, sizeof(alpn)))
        goto err;

    /* Takes ownership of our reference to the BIO. */
    SSL_set0_rbio(c_ssl, c_net_bio);

    /* Get another reference to be transferred in the SSL_set0_wbio call. */
    if (!(BIO_up_ref(c_net_bio))) {
        c_net_bio_own = NULL; /* SSL_free will free the first reference. */
        goto err;
    }

    SSL_set0_wbio(c_ssl, c_net_bio);
    c_net_bio_own = NULL;

    if (!(SSL_set_blocking_mode(c_ssl, 0)))
        goto err;

    start_time = apr_time_now();

    // SSL_set_default_stream_mode(c_ssl, SSL_DEFAULT_STREAM_MODE_NONE);
    // SSL_set_default_stream_mode(c_ssl, SSL_DEFAULT_STREAM_MODE_AUTO_BIDI);
    // SSL_set_incoming_stream_policy(c_ssl, SSL_INCOMING_STREAM_POLICY_AUTO, 0);

    // Try traces
    BIO *bio = BIO_new_file("trace.txt", "w");
    SSL_set_msg_callback(c_ssl, SSL_trace);
    SSL_set_msg_callback_arg(c_ssl, bio);

    for (;;) {
        if (apr_time_now() - start_time >= 60000000) {
            TEST_error("timeout while attempting QUIC client test\n");
            goto err;
        }
        /* Check for new QUIC streams and accept them */
        if (c_ssl) {
            accept_new_ssl_ids(c_ssl, bio);
        }


        if (!c_connected) {
            ret = SSL_connect(c_ssl);
            /* printf("SSL_connect returns %d %d\n", ret, is_want(c_ssl, ret)); */
            if (!(ret == 1 || is_want(c_ssl, ret))) {
                TEST_error("SSL_connect failed!\n");
                goto err;
            }

            if (ret == 1) {
                c_connected = 1;
                TEST_info("Connected!");
                printf("Connected!\n");
                add_id(c_ssl);
            }
        }

        if (c_connected && !c_write_done) {
            printf("sending request...\n");
            SSL *C_ssl = SSL_new_stream(c_ssl, SSL_STREAM_FLAG_UNI);
    SSL_set_msg_callback(C_ssl, SSL_trace);
    SSL_set_msg_callback_arg(C_ssl, bio);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(C_ssl), SSL_get_stream_type(C_ssl));
            SSL *p_ssl = SSL_new_stream(c_ssl, SSL_STREAM_FLAG_UNI);
    SSL_set_msg_callback(p_ssl, SSL_trace);
    SSL_set_msg_callback_arg(p_ssl, bio);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(p_ssl), SSL_get_stream_type(p_ssl));
            SSL *r_ssl = SSL_new_stream(c_ssl, SSL_STREAM_FLAG_UNI);
    SSL_set_msg_callback(r_ssl, SSL_trace);
    SSL_set_msg_callback_arg(r_ssl, bio);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(r_ssl), SSL_get_stream_type(r_ssl));

            if (nghttp3_conn_bind_control_stream(conn, SSL_get_stream_id(C_ssl))) {
                printf("nghttp3_conn_bind_control_stream failed!\n");
                exit(1);
            }
            if (nghttp3_conn_bind_qpack_streams(conn, SSL_get_stream_id(p_ssl), SSL_get_stream_id(r_ssl))) {
                printf("nghttp3_conn_bind_qpack_streams failed!\n");
                exit(1);
            }
            printf("control: %d enc %d dec %d\n", SSL_get_stream_id(C_ssl), SSL_get_stream_id(p_ssl), SSL_get_stream_id(r_ssl));
            add_id(C_ssl);
            add_id(p_ssl);
            add_id(r_ssl);

            /* send what we can */
            send_all_stream(conn);
            
            printf("SSL_write started!!!\n");

            c_write_done = 1;
            OSSL_sleep(1);
        }

        if (c_connected && c_write_done && !c_streamopened) {
            /* Create multiple streams */
            printf("Creating %d streams...\n", num_streams);
            done = num_streams;
            for (stream_idx = 0; stream_idx < num_streams; stream_idx++) {
                if (stream_idx > 0 && stream_idx % 100 == 0) {
                    printf("  Created %d/%d streams...\n", stream_idx, num_streams);
                }
                d_ssl[stream_idx] = SSL_new_stream(c_ssl, 0);
                if (d_ssl[stream_idx] == NULL) {
                    TEST_error("SSL_new_stream failed for stream %d (created %d streams successfully)\n",
                               stream_idx, stream_idx);
                    TEST_error("This may be due to OpenSSL/QUIC stream limits or resource constraints\n");
                    goto err;
                }
                SSL_set_msg_callback(d_ssl[stream_idx], SSL_trace);
                SSL_set_msg_callback_arg(d_ssl[stream_idx], bio);
                add_id(d_ssl[stream_idx]);
                if (stream_idx < 10) {
                    printf("Stream %d - SSL_get_stream_id: %d type: %d\n", stream_idx,
                           SSL_get_stream_id(d_ssl[stream_idx]), SSL_get_stream_type(d_ssl[stream_idx]));
                }
                if (nghttp3_conn_submit_request(conn, SSL_get_stream_id(d_ssl[stream_idx]), nva, num_nv, NULL, NULL)) {
                    printf("nghttp3_conn_submit_request failed for stream %d!\n", stream_idx);
                    exit(1);
                }
            }
            printf("Successfully created all %d streams\n", num_streams);
            c_streamopened = 1;

        }

        if (c_write_done && !c_shutdown) {
            ret = read_from_ssl_ids(conn);
            if (ret < 0) {
                printf("\n read_from_ssl_ids() FAILED!!!");
                goto err;
            }
            /* send what we can */
            send_all_stream(conn);
        }

        if (c_shutdown) {
            ret = SSL_shutdown(c_ssl);
            if (ret == 1)
                break;
        }
        if (!done) {
            c_streamopened = 0;
            printf("\nDone next loop!\n");
            // if (!loop)
            //     break;
        }
            

        /*
         * This is inefficient because we spin until things work without
         * blocking but this is just a test.
         */
        OSSL_sleep(10);
        SSL_handle_events(c_ssl);
    }

    testresult = 1;
err:
    cleanup_id();
    if (d_ssl != NULL) {
        free(d_ssl);
    }
    SSL_free(c_ssl);
    SSL_CTX_free(c_ctx);
    BIO_ADDR_free(s_addr_);
    BIO_free(c_net_bio_own);
    if (c_fd != -1)
        BIO_closesocket(c_fd);
    return testresult;
}

/* OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n") */

int main (int argc, char ** argv)
{
    short port;
    int num_streams = 1; /* Default to 1 stream */

    if (argc < 3 || argc > 4) {
        printf("Usage: ./quic_client_test hostname port [num_streams]\n");
        printf("  num_streams: optional, defaults to 1\n");
        exit(1);
    }

    port = atoi(argv[2]);
    if (port<=0) {
        printf("port: %s invalid\n", argv[2]);
        exit(1);
    }

    if (argc == 4) {
        num_streams = atoi(argv[3]);
        if (num_streams <= 0) {
            printf("num_streams: %s invalid (must be > 0)\n", argv[3]);
            exit(1);
        }
        if (num_streams > 100) {
            printf("WARNING: %d streams is very high and may hit OpenSSL/system limits\n", num_streams);
            printf("         Typical HTTP/3 clients use < 100 concurrent streams\n");
        }
    }

    printf("Testing with %d concurrent stream(s)\n", num_streams);
    printf("Will allocate %d stream slots for HTTP/3 (3 control + %d request streams)\n",
           3 + (num_streams * 2), num_streams);

    if (!test_quic_client(argv[1], port, argv[2], num_streams))
        printf("\n test_quic_client failed!!!");
    return 1;
}
