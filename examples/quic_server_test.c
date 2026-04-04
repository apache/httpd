/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is a temporary test server for QUIC. It will eventually be replaced
 * by s_server and removed once we have full QUIC server support.
 */

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "internal/e_os.h"
#include "internal/sockets.h"
#include "internal/quic_tserver.h"
#include "internal/quic_stream_map.h"
#include "internal/time.h"
#include <nghttp3/nghttp3.h>

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)(NAME), (uint8_t *)(VALUE), sizeof((NAME)) - 1,                 \
        sizeof((VALUE)) - 1, NGHTTP3_NV_FLAG_NONE                              \
  }         
#define nghttp3_arraylen(A) (sizeof(A) / sizeof(*(A)))

static BIO *bio_err = NULL;

/* CURL according to trace has 2 more streams 7 and 11 */
struct ssl_id {
  SSL *s;
  int64_t id;
};

#define MAXSSL_IDS 20
struct h3ssl {
   struct ssl_id ssl_ids[MAXSSL_IDS];
   int end_headers_received;
   int datadone;
};

static void init_id(struct h3ssl *h3ssl)
{
  struct ssl_id *ssl_ids;
  ssl_ids = h3ssl->ssl_ids;
  for (int i=0; i<MAXSSL_IDS; i++) {
    ssl_ids[i].s = NULL;
    ssl_ids[i].id = -1;
  }
  h3ssl->end_headers_received = 0;
  h3ssl->datadone = 0;
}

static void add_id(int64_t id, struct h3ssl *h3ssl) {
  struct ssl_id *ssl_ids;
  ssl_ids = h3ssl->ssl_ids;
  for (int i=0; i<MAXSSL_IDS; i++) {
    if (!ssl_ids[i].s) {
      ssl_ids[i].s = (SSL *)1; /* until we get an SSL or a quick channel */
      ssl_ids[i].id = id;
      return;
    }
  }
  printf("Oops too many streams to add!!!\n");
  exit(1);
}

static int cb_h3_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                             uint64_t datalen, void *user_data,
                             void *stream_user_data) {
    printf("cb_h3_acked_req_body!\n");
    return 0;
}
static int cb_h3_stream_close(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
    printf("cb_h3_stream_close!\n");
    return 0;
}
static int begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                         void *stream_user_data) {
    printf("begin_headers!\n");
    return 0;
}
static int cb_h3_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *conn_user_data, void *stream_user_data) {
    printf("cb_h3_begin_headers!\n");
    return 0;
}
static int cb_h3_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                       nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                       void *user_data, void *stream_user_data) {
    printf("cb_h3_recv_header!\n");
    return 0;
}
static int cb_h3_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                       void *user_data, void *stream_user_data) {

    printf("cb_h3_end_headers!\n");
    struct h3ssl *h3ssl = (struct h3ssl *)user_data;
    h3ssl->end_headers_received = 1;
    return 0;
}
static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream_id,
                                 const uint8_t *data, size_t datalen,
                                 void *conn_user_data, void *stream_user_data) {
    printf("cb_h3_recv_data! %d\n", datalen);
    printf("cb_h3_recv_data! %.*s\n", datalen, data);
    return 0;
}
static int cb_h3_deferred_consume(nghttp3_conn *conn, int64_t stream3_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
    printf("cb_h3_deferred_consume!\n");
    return 0;
}
static int cb_h3_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
    printf("cb_h3_stop_sending!\n");
    return 0;
}
static int cb_h3_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data) {
    printf("cb_h3_reset_stream!\n");
    return 0;
}
static int cb_h3_shutdown(nghttp3_conn *conn, int64_t id, void *conn_user_data) {
    printf("cb_h3_shutdown!\n");
    return 0;
}
static int cb_h3_recv_settings(nghttp3_conn *conn, const nghttp3_settings *settings, void *conn_user_data) {
    printf("cb_h3_recv_settings!\n");
    return 0;
}
static int cb_h3_begin_trailers() {
    printf("cb_h3_begin_trailers!\n");
    return 0;
}
static int cb_h3_end_trailers() {
    printf("cb_h3_end_trailers!\n");
    return 0;
}
static int cb_h3_end_stream() {
    printf("cb_h3_end_stream!\n");
    return 0;
}

static nghttp3_callbacks ngh3_callbacks = {
  cb_h3_acked_req_body, /* acked_stream_data */
  cb_h3_stream_close,
  cb_h3_recv_data,
  cb_h3_deferred_consume,
  cb_h3_begin_headers, /* begin_headers */
  cb_h3_recv_header,
  cb_h3_end_headers,
  cb_h3_begin_trailers, /* begin_trailers */
  cb_h3_recv_header,
  cb_h3_end_trailers, /* end_trailers */
  cb_h3_stop_sending,
  cb_h3_end_stream, /* end_stream */
  cb_h3_reset_stream,
  cb_h3_shutdown, /* shutdown */
  cb_h3_recv_settings /* recv_settings */
};

static void wait_for_activity(QUIC_TSERVER *qtserv)
{
    fd_set readfds, writefds;
    fd_set *readfdsp = NULL, *writefdsp = NULL;
    struct timeval timeout, *timeoutp = NULL;
    int width;
    int sock;
    BIO *bio = ossl_quic_tserver_get0_rbio(qtserv);
    OSSL_TIME deadline;

    BIO_get_fd(bio, &sock);

    if (ossl_quic_tserver_get_net_read_desired(qtserv)) {
        readfdsp = &readfds;
        FD_ZERO(readfdsp);
        openssl_fdset(sock, readfdsp);
    }

    if (ossl_quic_tserver_get_net_write_desired(qtserv)) {
        writefdsp = &writefds;
        FD_ZERO(writefdsp);
        openssl_fdset(sock, writefdsp);
    }

    deadline = ossl_quic_tserver_get_deadline(qtserv);

    if (!ossl_time_is_infinite(deadline)) {
        timeout = ossl_time_to_timeval(ossl_time_subtract(deadline,
                                                          ossl_time_now()));
        timeoutp = &timeout;
    }

    width = sock + 1;

    if (readfdsp == NULL && writefdsp == NULL && timeoutp == NULL)
        return;

    int ret = select(width, readfdsp, writefdsp, NULL, timeoutp);
    if (ret <= 0)
        return;
    if (FD_ISSET(sock, readfdsp)) {
        printf("wait_for_activity: read something on %d\n", sock);
        char message[1];
        socklen_t size;
	struct sockaddr addr;
        size = sizeof(addr);
        ret = recvfrom (sock, message, 0, MSG_PEEK, &addr, &size);
        printf("wait_for_activity: read something on %d: %d\n", sock, ret);
        if (ret >= 0) {
            if (addr.sa_family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
                char ipAddress[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(addr_in->sin_addr), ipAddress, INET_ADDRSTRLEN);
                printf("wait_for_activity: read something on %d: %d from %s:%d\n", sock, ret, ipAddress, ntohs(addr_in->sin_port));
            }
            else if (addr.sa_family == AF_INET6) {
                struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *)&addr;
                char ipAddress[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(addr_in->sin6_addr), ipAddress, INET6_ADDRSTRLEN);
                printf("wait_for_activity: read something on %d: %d from %s:%d\n", sock, ret, ipAddress, ntohs(addr_in->sin6_port));
            }
            else
                printf("wait_for_activity: read something on %d: UNKNOWN\n", sock);
        }
    }
     
}

/* Helper function to create a BIO connected to the server */
static BIO *create_dgram_bio(int family, const char *hostname, const char *port)
{
    int sock = -1;
    BIO_ADDRINFO *res;
    const BIO_ADDRINFO *ai = NULL;
    BIO *bio;

    if (BIO_sock_init() != 1)
        return NULL;

    /*
     * Lookup IP address info for the server.
     */
    if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_SERVER, family, SOCK_DGRAM,
                       0, &res))
        return NULL;

    /*
     * Loop through all the possible addresses for the server and find one
     * we can create and start listening on
     */
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        /* Create the UDP socket */
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, 0, 0);
        if (sock == -1)
            continue;

        /* Start listening on the socket */
        if (!BIO_listen(sock, BIO_ADDRINFO_address(ai), 0)) {
            BIO_closesocket(sock);
            continue;
        }

        /* Set to non-blocking mode */
        if (!BIO_socket_nbio(sock, 1)) {
            BIO_closesocket(sock);
            continue;
        }

        break; /* stop searching if we found an addr */
    }

    /* Free the address information resources we allocated earlier */
    BIO_ADDRINFO_free(res);

    /* If we didn't bind any sockets, fail */
    if (ai == NULL)
        return NULL;

    /* Create a BIO to wrap the socket */
    bio = BIO_new(BIO_s_datagram());
    if (bio == NULL) {
        BIO_closesocket(sock);
        return NULL;
    }

    /*
     * Associate the newly created BIO with the underlying socket. By
     * passing BIO_CLOSE here the socket will be automatically closed when
     * the BIO is freed. Alternatively you can use BIO_NOCLOSE, in which
     * case you must close the socket explicitly when it is no longer
     * needed.
     */
    BIO_set_fd(bio, sock, BIO_CLOSE);

    return bio;
}

static void usage(void)
{
    BIO_printf(bio_err, "quicserver [-6][-trace] hostname port certfile keyfile\n");
}

static int64_t waitfornewstream(QUIC_TSERVER *qtserv, struct h3ssl *h3ssl)
{
    int64_t streamid;
    printf("waitfornewstream...\n");
    do {
        streamid = ossl_quic_tserver_pop_incoming_stream(qtserv);
        if (streamid == UINT64_MAX)
            wait_for_activity(qtserv);
        ossl_quic_tserver_tick(qtserv);
        if (ossl_quic_tserver_is_terminated(qtserv)) {
            /* Assume we finished everything the clients wants from us */
            printf("Oops terminated!!!\n");
            return(UINT64_MAX);
        }
    } while(streamid == UINT64_MAX);
    add_id(streamid, h3ssl);
    printf("waitfornewstream: %d type: %d\n", streamid, 0); //  SSL_get_stream_type(streamid));
    return streamid;
}

static int read_from_ssl_ids(nghttp3_conn *conn, QUIC_TSERVER *qtserv, struct h3ssl *h3ssl)
{
  char msg2[16000];
  int hassomething = 0;
  struct ssl_id *ssl_ids;
  ssl_ids = h3ssl->ssl_ids;
  for (int i=0; i<MAXSSL_IDS; i++) {
    if (ssl_ids[i].s) {
      /* try to read */
      size_t l = sizeof(msg2) - 1;
      int ret = ossl_quic_tserver_read(qtserv, ssl_ids[i].id, msg2, sizeof(msg2) - 1, &l);
      if (ret <= 0) {
         printf("ossl_quic_tserver_read on %d failed\n", ssl_ids[i].id);
        continue; // TODO
      } else {
        if (l>0) {
           printf("\nreading something %d on %d\n", l, ssl_ids[i].id);
           int r = nghttp3_conn_read_stream(conn, ssl_ids[i].id, msg2, l, 0);
           printf("nghttp3_conn_read_stream used %d of %d on %d\n", r, l, ssl_ids[i].id);
           hassomething++;
        }
      }
    }
  }
  return hassomething;
}

/* The crappy test wants 20 bytes */
static uint8_t nulldata[20] = "12345678901234567890";
static int datadone = 0;
static nghttp3_ssize step_read_data(nghttp3_conn *conn, int64_t stream_id,
                                    nghttp3_vec *vec, size_t veccnt,
                                    uint32_t *pflags, void *user_data,
                                    void *stream_user_data)
{
  struct h3ssl *h3ssl = (struct h3ssl *)user_data;
  if (h3ssl->datadone) {
      *pflags = NGHTTP3_DATA_FLAG_EOF;
      return 0;
  }
  vec[0].base = nulldata;
  vec[0].len = 20;
  h3ssl->datadone++;

  return 1;
}


static void *process_server(void* par)
{
    int ret = EXIT_FAILURE;

    uint64_t streamid;
    size_t numbytes = 0;
    QUIC_TSERVER *qtserv = (QUIC_TSERVER *) par;
    

    /* try to use nghttp3 to send a response */
    nghttp3_conn *conn;
    nghttp3_settings settings;
    nghttp3_callbacks callbacks;
    struct h3ssl h3ssl;

    const nghttp3_mem *mem = nghttp3_mem_default();
    init_id(&h3ssl);
    nghttp3_settings_default(&settings);
    if (nghttp3_conn_server_new(&conn, &ngh3_callbacks, &settings, mem, &h3ssl)) {
        printf("nghttp3_conn_client_new failed!\n");
        exit(1);
    }
    printf("process_server starting...\n");
    fflush(stdout);

        /* Wait for 3 incoming streams */
        waitfornewstream(qtserv, &h3ssl);
        waitfornewstream(qtserv, &h3ssl);
        waitfornewstream(qtserv, &h3ssl);

        /* we have 3 streams from the client 2, 6 , 10 */

        /* we need 3, 7 and 11 for the server */
/*
        if (nghttp3_conn_bind_control_stream(conn, 3)) {
                printf("nghttp3_conn_bind_control_stream failed!\n");
                exit(1);
            }
 */
        /* get 2 stream to the client */
        uint64_t r_streamid; 
        if (!ossl_quic_tserver_stream_new(qtserv, 1, &r_streamid)) {
            printf("ossl_quic_tserver_stream_new failed!\n");
            ret = EXIT_FAILURE;
            goto end;
        }
        uint64_t p_streamid; 
        if (!ossl_quic_tserver_stream_new(qtserv, 1, &p_streamid)) {
            printf("ossl_quic_tserver_stream_new failed!\n");
            ret = EXIT_FAILURE;
            goto end;
        }
        if (nghttp3_conn_bind_qpack_streams(conn, p_streamid, r_streamid)) {
                printf("nghttp3_conn_bind_qpack_streams failed!\n");
                exit(1);
        }
        printf("control: NONE enc %d dec %d\n", p_streamid, r_streamid);

        /* we need to send that to the client or not ... */
        /* nghttp3_conn_create_stream(conn, &streamid, 0); Weird??? */

        while (!h3ssl.end_headers_received) {
            int hassomething = read_from_ssl_ids(conn, qtserv, &h3ssl);
            if (!hassomething) {
                printf("Nothing(end_headers_received) waiting...\n");
                wait_for_activity(qtserv);
                ossl_quic_tserver_tick(qtserv);
                if (ossl_quic_tserver_is_terminated(qtserv)) {
                    BIO_printf(bio_err, "Failed reading request\n");
                    ret = EXIT_FAILURE;
                    goto end;
                }
            }
            if (!h3ssl.end_headers_received)
                waitfornewstream(qtserv, &h3ssl);
        }

        /* we have receive the request build response and send it */
        nghttp3_nv resp[] = {
            MAKE_NV(":status", "200"),
            MAKE_NV("content-length", "20"),
        };
        nghttp3_data_reader dr;
        dr.read_data = step_read_data;
        if (nghttp3_conn_submit_response(conn, 0, resp, 2, &dr)) {
            printf("nghttp3_conn_submit_response failed!\n");
            ret = EXIT_FAILURE;
            goto end;
        }
        printf("nghttp3_conn_submit_response...\n");
        for (;;) {
            nghttp3_vec vec[256];
            nghttp3_ssize sveccnt;
            int fin;
            sveccnt = nghttp3_conn_writev_stream(conn, &streamid, &fin, vec, nghttp3_arraylen(vec));
            if (sveccnt <= 0) {
                printf("nghttp3_conn_writev_stream done: %d\n", sveccnt);
                break;
            } else {
                printf("nghttp3_conn_writev_stream: %d\n", sveccnt);
            }
            for (int i=0; i<sveccnt; i++) {
                printf("ossl_quic_tserver_write on %d for %d\n", streamid, vec[i].len);
                if (!ossl_quic_tserver_write(qtserv, streamid, vec[i].base , vec[i].len, &numbytes)) {
                    printf("ossl_quic_tserver_write failed!\n");
                    ret = EXIT_FAILURE;
                    goto end;
                }
            }
            if (nghttp3_conn_add_write_offset(conn, streamid, (size_t)nghttp3_vec_len(vec, (size_t)sveccnt))) {
                printf("nghttp3_conn_add_write_offset failed!\n");
                ret = EXIT_FAILURE;
                goto end;
            }
        }
        printf("nghttp3_conn_submit_response DONE!!!\n");
        

        wait_for_activity(qtserv);
        ossl_quic_tserver_tick(qtserv);
        if (ossl_quic_tserver_is_terminated(qtserv)) {
            BIO_printf(bio_err, "Failed reading request\n");
            ret = EXIT_FAILURE;
            goto end;
        }
        printf("nghttp3_conn_submit_response WAITED...\n");

        if (!ossl_quic_tserver_conclude(qtserv, streamid)) {
            printf("ossl_quic_tserver_conclude failed!\n");
            ret = EXIT_FAILURE;
            goto end;
        }
        printf("Done!\n");
        wait_for_activity(qtserv);
        ossl_quic_tserver_tick(qtserv);
        if (ossl_quic_tserver_is_terminated(qtserv)) {
            BIO_printf(bio_err, "Done terminated!\n");
        }

 end:
    /* Free twice because we did an up-ref */
    // BIO_free(bio);
 end2:
    // BIO_free(bio);
    // ossl_quic_tserver_free(qtserv);
    // BIO_free(bio_err);
}

int main(int argc, char *argv[])
{
    QUIC_TSERVER_ARGS tserver_args = {0};
    QUIC_TSERVER *qtserv = NULL;
    QUIC_TSERVER *qtserv1 = NULL;
    int ipv6 = 0, trace = 0;
    int argnext = 1;
    BIO *bio = NULL;
    char *hostname, *port, *certfile, *keyfile;
    int ret = EXIT_FAILURE;
    unsigned char alpn[] = { 5, 'h', '3', '-', '2', '9', 2, 'h', '3' };
    void *thread_status[2];
    pthread_t thread[2];

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    if (argc == 0 || bio_err == NULL)
        goto end2;

    while (argnext < argc) {
        if (argv[argnext][0] != '-')
            break;
        if (strcmp(argv[argnext], "-6") == 0) {
            ipv6 = 1;
        } else if(strcmp(argv[argnext], "-trace") == 0) {
            trace = 1;
        } else {
            BIO_printf(bio_err, "Unrecognised argument %s\n", argv[argnext]);
            usage();
            goto end2;
        }
        argnext++;
    }

    if (argc - argnext != 4) {
        usage();
        goto end2;
    }
    hostname = argv[argnext++];
    port = argv[argnext++];
    certfile = argv[argnext++];
    keyfile = argv[argnext++];

    bio = create_dgram_bio(ipv6 ? AF_INET6 : AF_INET, hostname, port);
    if (bio == NULL || !BIO_up_ref(bio)) {
        BIO_printf(bio_err, "Unable to create server socket\n");
        goto end2;
    }

    tserver_args.libctx = NULL;
    tserver_args.net_rbio = bio;
    tserver_args.net_wbio = bio;
    tserver_args.alpn = alpn;
    tserver_args.alpnlen = sizeof(alpn);
    tserver_args.ctx = NULL;

    qtserv = ossl_quic_tserver_new(&tserver_args, certfile, keyfile);
    if (qtserv == NULL) {
        BIO_printf(bio_err, "Failed to create the QUIC_TSERVER\n");
        goto end;
    }

    BIO_printf(bio_err, "Starting quicserver\n");
    BIO_printf(bio_err,
               "Note that this utility will be removed in a future OpenSSL version.\n");
    BIO_printf(bio_err,
               "For test purposes only. Not for use in a production environment.\n");

    if (trace)
#ifndef OPENSSL_NO_SSL_TRACE
        ossl_quic_tserver_set_msg_callback(qtserv, SSL_trace, bio_err);
#else
        BIO_printf(bio_err,
                   "Warning: -trace specified but no SSL tracing support present\n");
#endif
    qtserv1 = ossl_quic_tserver_new(&tserver_args, certfile, keyfile);
    if (qtserv1 == NULL) {
        BIO_printf(bio_err, "Failed to create the QUIC_TSERVER\n");
        goto end;
    }

    /* Wait for handshake to complete */
    ossl_quic_tserver_tick(qtserv);
    while(!ossl_quic_tserver_is_handshake_confirmed(qtserv)) {
        wait_for_activity(qtserv);
        ossl_quic_tserver_tick(qtserv);
        if (ossl_quic_tserver_is_terminated(qtserv)) {
            BIO_printf(bio_err, "qtserv: Failed waiting for handshake completion\n");
            ret = EXIT_FAILURE;
            goto end;
        }
    }
    pthread_create(&thread[0], NULL, process_server, qtserv);

    /* Wait for handshake to complete */
    ossl_quic_tserver_tick(qtserv1);
    while(!ossl_quic_tserver_is_handshake_confirmed(qtserv1)) {
        wait_for_activity(qtserv1);
        ossl_quic_tserver_tick(qtserv1);
        if (ossl_quic_tserver_is_terminated(qtserv1)) {
            BIO_printf(bio_err, "qtserv1: Failed waiting for handshake completion\n");
            ret = EXIT_FAILURE;
            goto end;
        }
    }
    pthread_create(&thread[1], NULL, process_server, qtserv1);

    /* Ownership of the BIO was passed to qtserv(s_ */
    bio = NULL;
    printf("After handshake completion\n");

    /* wait for the 2 threads we have created */
    pthread_join(thread[1], NULL);
    printf("After pthread_join completion\n");
    pthread_join(thread[0], NULL);
    printf("After pthread_join completion\n");
    
/*
    process_server(qtserv);
    process_server(qtserv1);
 */

 end:
    /* Free twice because we did an up-ref */
    BIO_free(bio);
 end2:
    BIO_free(bio);
    ossl_quic_tserver_free(qtserv);
    /* ossl_quic_tserver_free(qtserv1); will clean same bio twixw */
    BIO_free(bio_err);
    return ret;
}
