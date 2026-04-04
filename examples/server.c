/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <assert.h>
#include <netinet/in.h>
#include <nghttp3/nghttp3.h>
#include <openssl/err.h>
#include <openssl/quic.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define nghttp3_arraylen(A) (sizeof(A) / sizeof(*(A)))

/* The crappy test wants 20 bytes */
static uint8_t nulldata[20] = "12345678901234567890";

/* 3 streams created by the server and 4 by the client (one is bidi) */
struct ssl_id {
    SSL *s;      /* the stream openssl uses in SSL_read(),  SSL_write etc */
    uint64_t id; /* the stream identifier the nghttp3 uses */
    int status;  /* 0, CLIENTUNIOPEN or CLIENTUNIOPEN|CLIENTCLOSED (for the moment) */
};
/* status and origin of the streams the possible values are: */
#define CLIENTUNIOPEN  0x01 /* unidirectional open by the client (2, 6 and 10) */
#define CLIENTCLOSED   0x02 /* closed by the client */
#define CLIENTBIDIOPEN 0x04 /* bidirectional open by the client (something like 0, 4, 8 ...) */
#define SERVERUNIOPEN  0x08 /* unidirectional open by the server (3, 7 and 11) */
#define SERVERCLOSED   0x10 /* closed by the server (us) */

#define MAXSSL_IDS 20
#define MAXURL 255
struct h3ssl {
    struct ssl_id ssl_ids[MAXSSL_IDS];
    int end_headers_received; /* h3 header received call back called */
    int datadone;             /* h3 has given openssl all the data of the response */
    int has_uni;              /* we have the 3 uni directional stream needed */
    int close_done;           /* connection begins terminating EVENT_EC */
    int close_wait;           /* we are wait for a close or a new request */
    int done;                 /* connection terminated EVENT_ECD, after EVENT_EC */
    int received_from_two;    /* workaround for -607 on nghttp3_conn_read_stream on stream 2 */
    int restart;              /* new request/response cycle started */
    uint64_t id_bidi;         /* the id of the stream used to read request and send response */
    char url[MAXURL];         /* url to serve the request */
    uint8_t *ptr_data;        /* pointer to the data to send */
    unsigned int ldata;                /* amount of bytes to send */
    int offset_data;          /* offset to next data to send */
};

static void make_nv(nghttp3_nv *nv, const char *name, const char *value)
{
    nv->name        = (uint8_t *)name;
    nv->value       = (uint8_t *)value;
    nv->namelen     = strlen(name);
    nv->valuelen    = strlen(value);
    nv->flags       = NGHTTP3_NV_FLAG_NONE;
}

static void init_ids(struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        ssl_ids[i].s = NULL;
        ssl_ids[i].id = UINT64_MAX;
        ssl_ids[i].status = 0;
    }
    h3ssl->end_headers_received = 0;
    h3ssl->datadone = 0;
    h3ssl->has_uni = 0;
    h3ssl->close_done = 0;
    h3ssl->close_wait = 0;
    h3ssl->done = 0;
    h3ssl->received_from_two = 0;
    h3ssl->restart = 0;
    memset(h3ssl->url, '\0', sizeof(h3ssl->url));
    h3ssl->ptr_data = NULL;
    h3ssl->offset_data = 0;
    h3ssl->ldata = 0;
    h3ssl->id_bidi = UINT64_MAX;
     
}

static void reuse_h3ssl(struct h3ssl *h3ssl)
{
    h3ssl->end_headers_received = 0;
    h3ssl->datadone = 0;
    h3ssl->close_done = 0;
    h3ssl->close_wait = 0;
    h3ssl->done = 0;
    memset(h3ssl->url, '\0', sizeof(h3ssl->url));
    if (h3ssl->ptr_data != NULL && h3ssl->ptr_data != nulldata)
        free(h3ssl->ptr_data);
    h3ssl->ptr_data = NULL;
    h3ssl->offset_data = 0;
    h3ssl->ldata = 0;
}

static void add_id(uint64_t id, SSL *ssl, struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].s == NULL) {
            ssl_ids[i].s = ssl;
            ssl_ids[i].id = id;
            return;
        }
    }
    printf("Oops too many streams to add!!!\n");
    exit(1);
}

static void remove_id(uint64_t id, struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    if (id == UINT64_MAX)
        return;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == id) {
            printf("remove_id %llu\n", (unsigned long long) ssl_ids[i].id);
            /* XXX: don't work SSL_clear(ssl_ids[i].s); */
            SSL_free(ssl_ids[i].s);
            ssl_ids[i].s = NULL;
            ssl_ids[i].id = UINT64_MAX;
            ssl_ids[i].status = 0;
            return;
        }
    }
}

static void set_id_status(uint64_t id, int status, struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == id) {
            printf("set_id_status: %llu to %d\n", (unsigned long long) ssl_ids[i].id, status);
            ssl_ids[i].status = status;
            return;
        }
    }
    printf("Oops can't set status, can't find stream!!!\n");
    assert(0);
}

static int are_all_clientid_closed(struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].status == CLIENTUNIOPEN) {
            printf("are_all_clientid_closed: %llu open\n", (unsigned long long) ssl_ids[i].id);
            return 0;
        }
    }
    return 1;
}

/*
 * read the next timeout
 */
static int get_next_timeout(struct h3ssl *h3ssl, struct timeval *tv)
{
    struct ssl_id *ssl_ids;
    int is_infinite;

    ssl_ids = h3ssl->ssl_ids;

    /* The timeout is inherited (in fact it is the same for all stream from the connection */
    if (SSL_get_event_timeout(ssl_ids[0].s, tv, &is_infinite)) {
         if (!is_infinite) {
             return 1;
         }
    } else {
        return -1;
    }
    printf("Weird get_next_timeout tells infinite!\n");
    return 0;
}

static int on_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                          nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                          uint8_t flags, void *user_data,
                          void *stream_user_data)
{
    nghttp3_vec vname, vvalue;
    struct h3ssl *h3ssl = (struct h3ssl *)user_data;
    printf("on_recv_header!!!\n");

    /* Received a single HTTP header. */
    vname = nghttp3_rcbuf_get_buf(name);
    vvalue = nghttp3_rcbuf_get_buf(value);

    fwrite(vname.base, vname.len, 1, stderr);
    fprintf(stderr, ": ");
    fwrite(vvalue.base, vvalue.len, 1, stderr);
    fprintf(stderr, "\n");
    if (token == NGHTTP3_QPACK_TOKEN__PATH) {
        memcpy(h3ssl->url, vvalue.base, vvalue.len);
        if (h3ssl->url[0] == '/') {
            if (h3ssl->url[1] == '\0')
                strcpy(h3ssl->url, "index.html");
            else {
                memcpy(h3ssl->url, h3ssl->url+1, vvalue.len-1);
                h3ssl->url[vvalue.len-1] = '\0';
            }
        }
    }

    return 0;
}

static int on_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                          void *user_data, void *stream_user_data)
{
    struct h3ssl *h3ssl = (struct h3ssl *)user_data;

    printf("on_end_headers!!!\n");
    fprintf(stderr, "on_end_headers!\n");
    h3ssl->end_headers_received = 1;
    return 0;
}

static int on_recv_data(nghttp3_conn *conn, int64_t stream_id,
                        const uint8_t *data, size_t datalen,
                        void *conn_user_data, void *stream_user_data)
{
    printf("on_recv_data!!!\n");
    fprintf(stderr, "on_recv_data! %ld\n", (unsigned long)datalen);
    fprintf(stderr, "on_recv_data! %.*s\n", (int)datalen, data);
    return 0;
}

static int on_end_stream(nghttp3_conn *h3conn, int64_t stream_id,
                         void *conn_user_data, void *stream_user_data)
{
    struct h3ssl *h3ssl = (struct h3ssl *)conn_user_data;

    printf("on_end_stream!\n");
    h3ssl->done = 1;
    return 0;
}

/* Read from the stream and push to the h3conn */
static int quic_server_read(nghttp3_conn *h3conn, SSL *stream, uint64_t id, struct h3ssl *h3ssl)
{
    int ret, r;
    uint8_t msg2[16000];
    size_t l = sizeof(msg2);

    if (!SSL_has_pending(stream))
        return 0; /* Nothing to read */

    ret = SSL_read(stream, msg2, l);
    if (ret <= 0) {
        fprintf(stderr, "SSL_read %d on %llu failed\n",
               SSL_get_error(stream, ret),
               (unsigned long long) id);
        if (SSL_get_error(stream, ret) == SSL_ERROR_WANT_READ) {
           return 0; /* retry we need more data */
        }
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* XXX: work around nghttp3_conn_read_stream returning  -607 on stream 2 */
    if (!h3ssl->received_from_two && id != 2 ) {
       r = nghttp3_conn_read_stream(h3conn, id, msg2, ret, 0);
    } else {
       r = ret; /* ignore it for the moment ... */
    }

    printf("nghttp3_conn_read_stream used %d of %d on %llu\n", r,
           ret, (unsigned long long) id);
    if (r != ret) {
        /* chrome returns -607 on stream 2 */
        if (!nghttp3_err_is_fatal(r)) {
            printf("nghttp3_conn_read_stream used %d of %d (not fatal) on %llu\n", r,
                   ret, (unsigned long long) id);
            if (id == 2) {
                h3ssl->received_from_two = 1;
            }
            return 1;
        }
        return -1;
    }
    return 1;
}


/*
 * creates the control stream, the encoding and decoding streams.
 * nghttp3_conn_bind_control_stream() is for the control stream.
 */
static int quic_server_h3streams(nghttp3_conn *h3conn, struct h3ssl *h3ssl)
{
    SSL *rstream;
    SSL *pstream;
    SSL *cstream;
    uint64_t r_streamid, p_streamid, c_streamid;
    struct ssl_id *ssl_ids = h3ssl->ssl_ids;

   rstream = SSL_new_stream(ssl_ids[0].s, SSL_STREAM_FLAG_UNI);
    if (rstream != NULL) {
        fprintf(stderr, "=> Opened on %llu\n",
                (unsigned long long)SSL_get_stream_id(rstream));
        fflush(stderr);
    } else {
        fprintf(stderr, "=> Stream == NULL!\n");
        fflush(stderr);
        return -1;
    }
    pstream = SSL_new_stream(ssl_ids[0].s, SSL_STREAM_FLAG_UNI);
    if (pstream != NULL) {
        fprintf(stderr, "=> Opened on %llu\n",
                (unsigned long long)SSL_get_stream_id(pstream));
        fflush(stderr);
    } else {
        fprintf(stderr, "=> Stream == NULL!\n");
        fflush(stderr);
        return -1;
    }
    cstream = SSL_new_stream(ssl_ids[0].s, SSL_STREAM_FLAG_UNI);
    if (cstream != NULL) {
        fprintf(stderr, "=> Opened on %llu\n",
                (unsigned long long)SSL_get_stream_id(cstream));
        fflush(stderr);
    } else {
        fprintf(stderr, "=> Stream == NULL!\n");
        fflush(stderr);
        return -1;
    }
    r_streamid = SSL_get_stream_id(rstream);
    p_streamid = SSL_get_stream_id(pstream);
    c_streamid = SSL_get_stream_id(cstream);
    if (nghttp3_conn_bind_qpack_streams(h3conn, p_streamid, r_streamid)) {
        fprintf(stderr, "nghttp3_conn_bind_qpack_streams failed!\n");
        return -1;
    }
    if (nghttp3_conn_bind_control_stream(h3conn, c_streamid)) {
        fprintf(stderr, "nghttp3_conn_bind_qpack_streams failed!\n");
        return -1;
    }
    printf("control: %llu enc %llu dec %llu\n",
           (unsigned long long)c_streamid,
           (unsigned long long)p_streamid,
           (unsigned long long)r_streamid);
    add_id(SSL_get_stream_id(rstream), rstream, h3ssl);
    add_id(SSL_get_stream_id(pstream), pstream, h3ssl);
    add_id(SSL_get_stream_id(cstream), cstream, h3ssl);

    return 0;
}

/* Try to read from the streams we have */
static int read_from_ssl_ids(nghttp3_conn *h3conn, struct h3ssl *h3ssl)
{
    int hassomething = 0, i;
    struct ssl_id *ssl_ids = h3ssl->ssl_ids;
    SSL_POLL_ITEM items[MAXSSL_IDS] = {0}, *item = items;
    static const struct timeval nz_timeout = {0, 0};
    size_t result_count = SIZE_MAX;
    int numitem = 0, ret;
    uint64_t processed_event = 0;

    /*
     * Process all the streams
     * the first one is the connection if we get something here is a new stream
     */
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].s != NULL) {
            printf("trying SSL_poll from  on %lld\n", (unsigned long long) ssl_ids[i].id);
            item->desc = SSL_as_poll_descriptor(ssl_ids[i].s);
            item->events = UINT64_MAX;  /* TODO adjust to the event we need process */
            item->revents = UINT64_MAX; /* TODO adjust to the event we need process */
            numitem++;
            item++;
        }
    }

    /*
     * SSL_POLL_FLAG_NO_HANDLE_EVENTS would require to use:
     * SSL_get_event_timeout on the connection stream
     * select/wait using the timeout value (which could be no wait time)
     * SSL_handle_events
     * SSL_poll
     * for the moment we let SSL_poll to performs ticking internally
     * on an automatic basis.
     */
    ret = SSL_poll(items, numitem, sizeof(SSL_POLL_ITEM), &nz_timeout, 0,
                   &result_count);
    if (!ret) {
        fprintf(stderr, "SSL_poll failed\n");
        ERR_print_errors_fp(stderr);
        abort();
        return -1; /* something is wrong */
    }
    printf("read_from_ssl_ids %ld events\n", (unsigned long)result_count);
    if (result_count == 0) {
        /* Timeout may be something somewhere */
        return 0;
    }

    /* We have something */
    item = items;
    /* SSL_accept_stream if anyway */
    if ((item->revents & SSL_POLL_EVENT_ISB) ||
        (item->revents & SSL_POLL_EVENT_ISU)) {
        SSL *stream = SSL_accept_stream(ssl_ids[0].s, 0);
        uint64_t id;
        int r;

        if (stream == NULL) {
            return -1; /* something is wrong */
        }
        id = SSL_get_stream_id(stream);
        printf("=> Received connection on %lld %d\n", (unsigned long long) id,
               SSL_get_stream_type(stream));
        add_id(id, stream, h3ssl);
        if (h3ssl->close_wait) {
            printf("in close_wait so we will have a new request\n");
            reuse_h3ssl(h3ssl);
            h3ssl->restart = 1; /* Checked in wait_close loop */
        }
        if (SSL_get_stream_type(stream) == SSL_STREAM_TYPE_BIDI) {
            /* bidi that is the id  where we have to send the response */
            printf("=> Received connection on %lld ISBIDI\n",
                   (unsigned long long) id);
            if (h3ssl->id_bidi != UINT64_MAX) {
                /* XXX JFCLERE needs to check if closed ... */
                remove_id(h3ssl->id_bidi, h3ssl);
            }
            h3ssl->id_bidi = id;

            /* XXX use it to restart to end_headers_received */
            reuse_h3ssl(h3ssl);
            h3ssl->restart = 1; /* Checked in wait_close loop */
        } else {
           set_id_status(id, CLIENTUNIOPEN, h3ssl);
        }

        r = quic_server_read(h3conn, stream, id, h3ssl);
        if (r == -1) {
            return -1; /* something is wrong */
        }
        if (r == 1) {
            hassomething++;
        }
        if (item->revents & SSL_POLL_EVENT_ISB)
            processed_event = processed_event + SSL_POLL_EVENT_ISB;
        if (item->revents & SSL_POLL_EVENT_ISU)
            processed_event = processed_event + SSL_POLL_EVENT_ISU;
    }
    if (item->revents & SSL_POLL_EVENT_OSB) {
        /* Create new streams when allowed */
        /* at least one bidi */
        processed_event = processed_event + SSL_POLL_EVENT_OSB;
        printf("Create bidi?\n");
    }
    if (item->revents & SSL_POLL_EVENT_OSU) {
        /* at least one uni */
        /* we have 4 streams from the client 2, 6 , 10 and 0 */
        /* need 3 streams to the client */
        printf("Create uni?\n");
        processed_event = processed_event + SSL_POLL_EVENT_OSU;
        if (!h3ssl->has_uni) {
            printf("Create uni\n");
            ret = quic_server_h3streams(h3conn, h3ssl);
            if (ret == -1) {
                fprintf(stderr, "quic_server_h3streams failed!\n");
                return -1;
            }
            h3ssl->has_uni = 1;
            hassomething++;
        }
    }
    if (item->revents & SSL_POLL_EVENT_EC) {
        /* the connection begins terminating */
        printf("Connection terminating restart %d\n", h3ssl->restart);
        if (!h3ssl->restart) {
            printf("Connection terminating NOT restart %d\n", h3ssl->restart);
            if (!h3ssl->close_done) {
                h3ssl->close_done = 1;
            } else {
                h3ssl->done = 1;
            }
        }
        hassomething++;
        processed_event = processed_event + SSL_POLL_EVENT_EC;
    }
    if (item->revents & SSL_POLL_EVENT_ECD) {
        /* the connection is terminated */
        printf("Connection terminated\n");
        h3ssl->done = 1;
        hassomething++;
        processed_event = processed_event + SSL_POLL_EVENT_ECD;
    }
    if (item->revents != processed_event) {
        /* we missed something we need to figure out */
        printf("Missed revent %llu (%d) on %llu\n",
               (unsigned long long)item->revents, SSL_POLL_EVENT_W,
               (unsigned long long)ssl_ids[i].id);
    }
    if (result_count == 1 && !processed_event) {
        printf("read_from_ssl_ids 1 event only!\n");
        return hassomething; /* one event only so we are done */
    }
    /* Well trying... */
    if (numitem <= 1) {
        return hassomething;
    }

    /* Process the other stream */
    for (i = 1; i < numitem; i++) {
        item++;
        processed_event = 0;

        if (item->revents & SSL_POLL_EVENT_R) {
            /* try to read */
            int r;

            printf("revent READ on %llu\n",
                   (unsigned long long)ssl_ids[i].id);
            r = quic_server_read(h3conn, ssl_ids[i].s, ssl_ids[i].id, h3ssl);
            if (r == 0) {
                continue;
            }
            if (r == -1) {
                return -1;
            }
            hassomething++;
            processed_event = processed_event + SSL_POLL_EVENT_R;
        }
        if (item->revents & SSL_POLL_EVENT_ER) {
            /* mark it closed */
            printf("revent exception READ on %llu\n",
                   (unsigned long long)ssl_ids[i].id);
            if (ssl_ids[i].status == CLIENTUNIOPEN) {
                ssl_ids[i].status = ssl_ids[i].status | CLIENTCLOSED;
                hassomething++;
            }
            processed_event = processed_event + SSL_POLL_EVENT_ER;
        }
        if (item->revents & SSL_POLL_EVENT_EW) {
            uint64_t app_error_code;
            uint64_t app_error_code1;
            int unused = SSL_get_stream_write_error_code(ssl_ids[i].s, &app_error_code);
            unused = SSL_get_stream_read_error_code(ssl_ids[i].s, &app_error_code1);
            if (!unused)
                printf("revent SSL_get_stream_read_error_code failed\n");

            printf("revent exception WRITE on %llu reset: %d, %lld %lld\n",
                   (unsigned long long)ssl_ids[i].id,
                   SSL_get_stream_write_state(ssl_ids[i].s),
                   (unsigned long long)app_error_code,
                   (unsigned long long)app_error_code1);
            if (ssl_ids[i].id == h3ssl->id_bidi) {
                /* The bidi is closed if we are in close_wait, we are done */
                if (h3ssl->close_wait) {
                    /* we are done (both size closed) */
                    printf("revent exception WRITE on both sides closed\n");
                    remove_id(ssl_ids[i].id, h3ssl);
                    h3ssl->id_bidi = UINT64_MAX;
                    h3ssl->done = 1;
                    hassomething++;
                    processed_event = processed_event + SSL_POLL_EVENT_EW;
                }
            }
        }
        if (item->revents != processed_event) {
            /* Figure out ??? */
            uint64_t value;
            SSL_get_stream_write_buf_avail(ssl_ids[i].s, &value);
            printf("nghttp3_conn_block_stream available: %ld on %ld\n", value, ssl_ids[i].id);
            printf("revent %llu (%d) on %llu\n",
                   (unsigned long long)item->revents, SSL_POLL_EVENT_W,
                   (unsigned long long)ssl_ids[i].id);
        }
    }
    return hassomething;
}

static int get_file_length(char *filename)
{
    struct stat st;
    if (strcmp(filename, "big") == 0) {
        printf("big!!!\n");
        return INT_MAX;
    }
    if (stat(filename, &st) == 0) {
        /* Only process regular files */
        if (S_ISREG(st.st_mode)) {
            printf("get_file_length %s %ld\n", filename, st.st_size);
            return st.st_size;
        }
    }
    printf("Can't get_file_length %s\n", filename);
    return 0;
}


/* XXX will leak the file size */
static char *get_file_data(char *filename)
{
    int size = get_file_length(filename);
    char *res;
    int fd;

    if (size == 0)
        return NULL;

    res = malloc(size+1);
    res[size] = '\0';
    fd = open(filename, O_RDONLY);
    if (read(fd,res,size)==-1) {
        close(fd);
        free(res);
        return NULL;
    }
    close(fd);
    printf("read from %s : %d\n", filename, size);
    return res;
}
static nghttp3_ssize step_read_data(nghttp3_conn *conn, int64_t stream_id,
                                    nghttp3_vec *vec, size_t veccnt,
                                    uint32_t *pflags, void *user_data,
                                    void *stream_user_data) {
    struct h3ssl *h3ssl = (struct h3ssl *)user_data;

    if (h3ssl->datadone) {
        *pflags = NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    /* send the data */
    printf("step_read_data for %s %d\n", h3ssl->url, h3ssl->ldata);
    if (h3ssl->ldata <= 4096) {
        vec[0].base = &(h3ssl->ptr_data[h3ssl->offset_data]);
        vec[0].len = h3ssl->ldata;
        h3ssl->datadone++;
        *pflags = NGHTTP3_DATA_FLAG_EOF;
    } else {
        vec[0].base = &(h3ssl->ptr_data[h3ssl->offset_data]);
        vec[0].len = 4096;
        if (h3ssl->ldata == INT_MAX) {
            printf("big = endless!\n");
        } else {
            h3ssl->offset_data = h3ssl->offset_data + 4096;
            h3ssl->ldata = h3ssl->ldata - 4096; 
        }
    }

    return 1;
}

static int quic_server_write(struct h3ssl *h3ssl, uint64_t streamid,
                             uint8_t *buff, size_t len, uint64_t flags,
                             size_t *written) {
    struct ssl_id *ssl_ids;
    int i;

    printf("quic_server_write %ld (flags: %lld) on %lld\n",
           (unsigned long)len, (unsigned long long)flags,
           (unsigned long long)streamid);
    ERR_print_errors_fp(stdout);
    fflush(stdout);

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == streamid) {
/* JFC try stuff ...
            int canwrite = 0;
            while (!canwrite) {
                if (!SSL_handle_events(ssl_ids[0].s)) {
                    printf("SSL_handle_events failed!\n");
                    fflush(stdout);
                    abort();
                }
                canwrite = can_write_ssl(ssl_ids[i].s);
                printf("quic_server_write canwrite %d\n", canwrite);
                if (canwrite == -1) {
                    uint64_t app_error_code;
                    SSL_get_stream_write_error_code(ssl_ids[i].s, &app_error_code);
                    printf("quic_server_write reset: %d, %lld\n", SSL_get_stream_write_state(ssl_ids[0].s), (unsigned long long)app_error_code);
                    /0 XXX Probably NOT OK h3ssl->close_wait = 1; 0/
                    return 0;
                }
                if (!canwrite) {
                    if (!SSL_handle_events(ssl_ids[0].s)) {
                        printf("SSL_handle_events failed!\n");
                        fflush(stdout);
                        abort();
                    }
                }
            }
 */
            if (!SSL_write_ex2(ssl_ids[i].s, buff, len, flags, written)) {
                printf("JFC couldn't write on connection SSL_write_ex2 failed %ld on %ld\n", len, ssl_ids[i].id);
                ERR_print_errors_fp(stdout);
                printf("JFC couldn't write on connection SSL_write_ex2 failed\n");
                fflush(stdout);
                if (SSL_get_error(ssl_ids[i].s, 0) == SSL_ERROR_WANT_WRITE) {
                    *written = 0;
                    printf("JFC blocking the stream via nghttp3_conn_block_stream\n");
                    return 0;
                } else {
                    printf("JFC couldn't write on connection\n");
                    ERR_print_errors_fp(stdout);
                    fflush(stdout);
                    fprintf(stderr, "couldn't write on connection\n");
                    ERR_print_errors_fp(stderr);
                    return 0;
                }
            }
            if (*written != len)
                printf("Partial write\n");
            printf("written %ld on %lld flags %lld\n", (unsigned long)len,
                   (unsigned long long)streamid, (unsigned long long)flags);
            return 1;
        }
    }
    printf("quic_server_write %ld on %lld (NOT FOUND!)\n", (unsigned long)len,
           (unsigned long long)streamid);
    return 0;
}

static int id_SSL_get_error(struct h3ssl *h3ssl, uint64_t streamid, int ret)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == streamid) {
            int rc =  SSL_get_error(ssl_ids[i].s, ret);
            return rc;
        }
    }
    return 0;
}

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

/*
 * This is a basic demo of QUIC server functionality in which one connection at
 * a time is accepted in a blocking loop.
 */

/* ALPN string for TLS handshake. We pretent h3-29 and h3 */
static const unsigned char alpn_ossltest[] = { 5,   'h', '3', '-', '2',
                                               '9', 2,   'h', '3' };

/*
 * This callback validates and negotiates the desired ALPN on the server side.
 */
static int select_alpn(SSL *ssl, const unsigned char **out,
                       unsigned char *out_len, const unsigned char *in,
                       unsigned int in_len, void *arg) {
    if (SSL_select_next_proto((unsigned char **)out, out_len, alpn_ossltest,
                              sizeof(alpn_ossltest), in,
                              in_len) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    return SSL_TLSEXT_ERR_OK;
}

/* Create SSL_CTX. */
static SSL_CTX *create_ctx(const char *cert_path, const char *key_path)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL)
        goto err;

    /* Load certificate and corresponding private key. */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        fprintf(stderr, "couldn't load certificate file: %s\n", cert_path);
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "couldn't load key file: %s\n", key_path);
        goto err;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "private key check failed\n");
        goto err;
    }

    /* Setup ALPN negotiation callback. */
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    return ctx;

err:
    SSL_CTX_free(ctx);
    return NULL;
}

/* Create UDP socket using given port. */
static int create_socket(uint16_t port)
{
    int fd = -1;
    struct sockaddr_in sa = {0};

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "cannot create socket");
        goto err;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "cannot bind to %u\n", port);
        goto err;
    }

    return fd;

err:
    if (fd >= 0)
        BIO_closesocket(fd);

    return -1;
}

static int waitsocket(int fd, time_t sec, suseconds_t usec)
{
    fd_set read_fds;
    int fdmax = fd;
    int ret;

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    if (sec || usec) {
        struct timeval tv;
        struct timeval bef, aft;

        /*
         * The usec and sec for SSL_get_event_timeout() need to round up.
         * otherwise we might return too early...
         */
        if (sec == 0) {
            /* add 1000 usec */
            usec = usec + 1000;
        } else {
            sec = sec + 1;
            usec = 0;
        }
        tv.tv_sec = sec;
        tv.tv_usec = usec;
        printf("waitsocket for %ld %ld\n", tv.tv_sec, tv.tv_usec);
        gettimeofday(&bef, NULL);
        ret = select(fdmax + 1, &read_fds, NULL, NULL, &tv);
        gettimeofday(&aft, NULL);
        if (bef.tv_sec != aft.tv_sec) {
            printf("waitsocket WAITED %ld\n", aft.tv_sec - bef.tv_sec);
            fflush(stdout);
            /* XXX: what was the idea???
            if (bef.tv_sec+2 < aft.tv_sec) {
                abort();
            }
             */
        }
    } else {
        printf("waitsocket for ever\n");
        ret = select(fdmax + 1, &read_fds, NULL, NULL, NULL);
    }
    if (ret == -1) {
        fprintf(stderr, "waitsocket failed\n");
        return -2;
    } else if (ret) {
        printf("waitsocket %d\n", FD_ISSET(fd, &read_fds));
        return 0;
    }
    return -1; /* Timeout */
}

/* Main loop for server to accept QUIC connections. */
static int run_quic_server(SSL_CTX *ctx, int fd)
{
    int ok = 0;
    int hassomething = 0;
    SSL *listener = NULL, *conn = NULL;
    int ret;


    /* Create a new QUIC listener. */
    if ((listener = SSL_new_listener(ctx, 0)) == NULL)
        goto err;

    /* Provide the listener with our UDP socket. */
    if (!SSL_set_fd(listener, fd))
        goto err;

    /* Begin listening. */
    if (!SSL_listen(listener))
        goto err;

    /*
     * Listeners, and other QUIC objects, default to operating in blocking mode.
     * The configured behaviour is inherited by child objects.
     * Make sure we won't block as we use select().
     */
    if (!SSL_set_blocking_mode(listener, 0))
        goto err;

    for (;;) {
        nghttp3_conn *h3conn;
        nghttp3_settings settings;
        nghttp3_callbacks callbacks = {0};
        struct h3ssl h3ssl;
        const nghttp3_mem *mem = nghttp3_mem_default();
        nghttp3_nv resp[10];
        size_t num_nv;
        nghttp3_data_reader dr;
        int numtimeout;
        char slength[11];
        size_t written, total_written, total_len;
        nghttp3_ssize sveccnt;
        nghttp3_vec vec[256] = {0};
        int num_nothing = 0;

        if (!hassomething) {
            fprintf(stderr, "waiting on socket\n");
            fflush(stderr);
            ret = waitsocket(fd, 0, 0);
            if (ret == -2) {
                SSL_free(conn);
                printf("waitsocket tells -2\n");
                fflush(stdout);
                goto err;
            }
        }
        fprintf(stderr, "before SSL_accept_connection\n");
        fflush(stderr);

        /*
         * SSL_accept_connection will return NULL if there is nothing to accept
         */
        conn = SSL_accept_connection(listener, 0);
        fprintf(stderr, "after SSL_accept_connection\n");
        fflush(stderr);
        if (conn == NULL) {
            fprintf(stderr, "error while accepting connection\n");
            fflush(stdout);
            hassomething = 0;
            continue;
            /* goto err; */
        }

        /* set the incoming stream policy to accept */
        if (!SSL_set_incoming_stream_policy(
                conn, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0)) {
            fprintf(stderr, "error while setting inccoming stream policy\n");
            goto err;
        }

        /*
         * Service the connection. In a real application this would be done
         * concurrently. In this demonstration program a single connection is
         * accepted and serviced at a time.
         */

        /* try to use nghttp3 to send a response */
        init_ids(&h3ssl);
        nghttp3_settings_default(&settings);

        /* Setup callbacks. */
        callbacks.recv_header = on_recv_header;
        callbacks.end_headers = on_end_headers;
        callbacks.recv_data = on_recv_data;
        callbacks.end_stream = on_end_stream;

        if (nghttp3_conn_server_new(&h3conn, &callbacks, &settings, mem,
                                    &h3ssl)) {
            fprintf(stderr, "nghttp3_conn_client_new failed!\n");
            exit(1);
        }

        /* add accepted SSL conn to the ids we will poll */
        add_id(-1, conn, &h3ssl);
        printf("process_server starting...\n");
        fflush(stdout);

        /* wait until we have received the headers */
restart:
        numtimeout = 0;
        num_nv = 0;
        while (!h3ssl.end_headers_received) {
            if (!hassomething) {
                struct timeval tv;
                ret = get_next_timeout(&h3ssl, &tv);
                printf("get_next_timeout tells %d for %ld %ld\n", ret, tv.tv_sec, tv.tv_usec);
                if (ret == -1)
                    goto err;
                if (ret == 0) {
                    printf("end_headers_received no more events on connection\n");
                    fflush(stdout);
                    goto done_nothing_more; /* Done no more events in the future */
                }
                if (waitsocket(fd, tv.tv_sec, tv.tv_usec)) {
                    printf("waiting for end_headers_received timeout %d\n", numtimeout);
                    numtimeout++;
                    if (numtimeout == 35)
                        goto err;
                } else {
                    printf("waiting for end_headers_received no timeout\n");
                    if (!SSL_handle_events(h3ssl.ssl_ids[0].s)) {
                        printf("SSL_handle_events failed!\n");
                        goto err;
                    }
                }
            }
            hassomething = read_from_ssl_ids(h3conn, &h3ssl);
            if (hassomething == -1) {
                fprintf(stderr, "read_from_ssl_ids hassomething failed\n");
                goto err;
            } else if (hassomething == 0) {
                printf("read_from_ssl_ids hassomething nothing...\n");
            } else {
                numtimeout = 0;
                printf("read_from_ssl_ids hassomething %d...\n", hassomething);
                if (h3ssl.close_done) {
                    /* Other side has closed */
                    break;
                }
                h3ssl.restart = 0;
            }
        }
        if (h3ssl.close_done) {
            printf("Other side close without request\n");
            goto wait_close;
        }
        printf("end_headers_received!!!\n");
        if (!h3ssl.has_uni) {
            /* time to create those otherwise we can't push anything to the client */
            printf("Create uni\n");
            if (quic_server_h3streams(h3conn, &h3ssl) == -1) {
                fprintf(stderr, "quic_server_h3streams failed!\n");
                goto err;
            }
            h3ssl.has_uni = 1;
        }

        /* we have receive the request build the response and send it */
        /* XXX add  MAKE_NV("connection", "close"), to resp[] and recheck */
        make_nv(&resp[num_nv++], ":status", "200");
        h3ssl.ldata = get_file_length(h3ssl.url);
        if (h3ssl.ldata == 0) {
            sprintf(slength, "%d", 20);
            h3ssl.ptr_data = nulldata;
            h3ssl.ldata = 20;
            /* content-type: text/html */
            make_nv(&resp[num_nv++], "content-type", "text/html");
        } else if (h3ssl.ldata == INT_MAX) {
            sprintf(slength, "%d", h3ssl.ldata);
            h3ssl.ptr_data = (uint8_t *) malloc(4096);
            memset(h3ssl.ptr_data, 'A', 4096);
        } else {
            sprintf(slength, "%d", h3ssl.ldata);
            h3ssl.ptr_data = (uint8_t *) get_file_data(h3ssl.url);
            if (h3ssl.ptr_data == NULL)
                abort();
            printf("before nghttp3_conn_submit_response on %llu for %s ...\n", (unsigned long long) h3ssl.id_bidi, h3ssl.url);
            if (strstr(h3ssl.url, ".png"))
                make_nv(&resp[num_nv++], "content-type", "image/png");
            else if (strstr(h3ssl.url, ".ico"))
                make_nv(&resp[num_nv++], "content-type", "image/vnd.microsoft.icon");
            else
                make_nv(&resp[num_nv++], "content-type", "text/html");
        }
        printf("before nghttp3_conn_submit_response on %llu for %s ...\n", (unsigned long long) h3ssl.id_bidi, h3ssl.url);
        make_nv(&resp[num_nv++], "content-length", slength);
        dr.read_data = step_read_data;
        if (nghttp3_conn_submit_response(h3conn, h3ssl.id_bidi, resp, num_nv, &dr)) {
            fprintf(stderr, "nghttp3_conn_submit_response failed!\n");
            goto err;
        }
        printf("nghttp3_conn_submit_response on %llu for %s ...\n", (unsigned long long) h3ssl.id_bidi, h3ssl.url);

sending_data:        
        total_written = 0;
        for (;;) {
            int fin, i;
            int64_t streamid;

            sveccnt = nghttp3_conn_writev_stream(h3conn, &streamid, &fin, vec,
                                                 nghttp3_arraylen(vec));
            if (sveccnt <= 0) {
                total_len = 0;
                num_nothing++;
                printf("nghttp3_conn_writev_stream done: %ld stream: %llu fin %d\n",
                       (long int)sveccnt,
                       (unsigned long long)streamid,
                       fin);
                if (streamid != -1 && fin) {
                    printf("Sending end data on %llu fin %d\n",
                           (unsigned long long) streamid, fin);
                    nghttp3_conn_add_write_offset(h3conn, streamid, 0);
                    continue;
                }
                if (!h3ssl.datadone) {
                    printf("!h3ssl.datadone\n");
                    if (sveccnt < 0)
                        goto err;
                    break; /* We have more todo to send the data... */
                } else
                    break; /* Done */
            }
            printf("nghttp3_conn_writev_stream: (%ld vec) fin: %d for %s\n", (long int)sveccnt, fin, h3ssl.url);

            total_len = nghttp3_vec_len(vec, (size_t) sveccnt);
            total_written = 0;

            for (i = 0; i < sveccnt; i++) {
                size_t numbytes = vec[i].len;
                int flagwrite = 0;

                printf("quic_server_write %ld on %llu\n",
                       (unsigned long)vec[i].len, (unsigned long long)streamid);
                if (fin && i == sveccnt - 1) {
                    flagwrite = SSL_WRITE_FLAG_CONCLUDE;
                }
                written = vec[i].len;
                if (!quic_server_write(&h3ssl, streamid, vec[i].base,
                                       vec[i].len, flagwrite, &numbytes)) {
                    fprintf(stderr, "quic_server_write failed!\n");
                    printf("quic_server_write failed!\n");
                    if (id_SSL_get_error(&h3ssl, streamid, 0) == SSL_ERROR_WANT_WRITE) { 
                        printf("quic_server_write failed calling nghttp3_conn_block_stream...\n");
                        written = 0;
                        nghttp3_conn_block_stream(h3conn, streamid);
                        break;
                    } else {
                        goto done_nothing_more; /* close and restart */
                    }
                    /* JFCLERE According to the trace we might be writting old data (from the previous bidi) after a failure... */
                    /* nghttp3_conn_block_stream(h3conn, streamid); */
                    /* XXX NOT OK ????
                    if (h3ssl.close_wait) {
                        goto wait_close; /0 the bidi was resetted 0/
                    }
                    goto err;
                    */
                } else {
                    total_written += written;
                    nghttp3_conn_unblock_stream(h3conn, streamid);
                }                
            }
            if (total_written > 0) {
                if (nghttp3_conn_add_write_offset(
                        h3conn, streamid, total_written)) {
                    fprintf(stderr, "nghttp3_conn_add_write_offset failed!\n");
                    goto err;
                }
            }
        }

        /* XXX something missing ... */
        /* if (fin && total_written == total_len) { */
        if (total_written == total_len) {
            if (total_len == 0)
                printf("nghttp3_conn_submit_response DONE missing ...!!!\n");
        } else {
            printf("nghttp3_conn_submit_response DONE total_written != total_len %ld %ld...!!!\n", total_written, total_len);
        }

        if (h3ssl.datadone) {
            /*
             * All the data was sent.
             * close stream zero
             */
            if (!h3ssl.close_done) {
                /* chrome doesn't like it??? */
                /* h3close(&h3ssl, h3ssl.id_bidi); */
                h3ssl.close_wait = 1;
            }
        } else {
            printf("nghttp3_conn_submit_response still not finished\n");
            read_from_ssl_ids(h3conn, &h3ssl);
            if (num_nothing == 50) {
                printf("nghttp3_conn_submit_response  nghttp3_conn_unblock_stream...\n");
                nghttp3_conn_unblock_stream(h3conn, h3ssl.id_bidi);
            }
            if (num_nothing == 100) {
                printf("nghttp3_conn_submit_response still not finished GIVING UP\n");
                exit(1);
            }
/*
            if (!SSL_handle_events(h3ssl.ssl_ids[0].s)) {
                printf("SSL_handle_events failed!\n");
                goto err;
            }
 */
            goto sending_data;
        }
        printf("nghttp3_conn_submit_response DONE!!!\n");

        /* wait until closed */
wait_close:
        for (;;) {
            int hasnothing;
            int notimeout = 0;
            struct timeval tv;

            ret = get_next_timeout(&h3ssl, &tv);
            if (ret == -1)
                goto err;
            if (ret == 0) {
                int mode;

                printf("wait_close no more events on connection\n");
                fflush(stdout);
                hassomething = 0;
                /* break; /0 JFC trying ... Done no more events in the future */
                if (!SSL_handle_events(h3ssl.ssl_ids[0].s)) {
                    printf("SSL_handle_events failed!\n");
                    goto err;
                }
                mode = SSL_get_shutdown(h3ssl.ssl_ids[0].s);
                printf("hasnothing nothing SSL_get_shutdown %d!!!!\n", mode);
                if (mode == (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN)) {
                    printf("hasnothing nothing SHUTDOWN!!!!\n");
                    break;
                }
            }

            if (tv.tv_sec != 0 || tv.tv_usec != 0) {
                if (waitsocket(fd, tv.tv_sec, tv.tv_usec)) {
                    printf("wait_close timeout\n");
                    /* May be a timeout event??? */
                    if (!SSL_handle_events(h3ssl.ssl_ids[0].s)) {
                        printf("SSL_handle_events failed!\n");
                        goto err;
                    }
                    
                    /* XXX probably not always OK */
                    /* break; */
                } else {
                    printf("waiting for wait_close no timeout\n");
                    notimeout = 1;
                    if (!SSL_handle_events(h3ssl.ssl_ids[0].s)) {
                        printf("SSL_handle_events failed!\n");
                        goto err;
                    }
                }
            }
            hasnothing = read_from_ssl_ids(h3conn, &h3ssl);
            if (hasnothing == -1) {
                printf("hasnothing failed\n");
                break;
                /* goto err; well in fact not */
            } else if (hasnothing == 0) {
                int mode;
                printf("hasnothing nothing %d %d %d...%d\n", h3ssl.done, h3ssl.restart, h3ssl.close_done, notimeout);
                /* Check if something occurs outside the read_from_ssl_ids */
                if (notimeout) {
                    conn = SSL_accept_connection(listener, 0);
                    if (conn == NULL) {
                        printf("hasnothing nothing no timeout but nothing to accept\n");
                    } else {
                        printf("hasnothing nothing no timeout NEW conn\n");
                    }
                }

                /* detect CURL closing */
                printf("hasnothing nothing...\n");
                if (!SSL_handle_events(h3ssl.ssl_ids[0].s)) {
                    printf("SSL_handle_events failed!\n");
                    goto err;
                }
                mode = SSL_get_shutdown(h3ssl.ssl_ids[0].s);
                printf("hasnothing nothing SSL_get_shutdown %d!!!!\n", mode);
                if (mode == (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN)) {
                    printf("hasnothing nothing SHUTDOWN!!!!\n");
                    break;
                }
                if (h3ssl.done) {
                    printf("hasnothing nothing... DONE\n");
                    if (are_all_clientid_closed(&h3ssl)) {
                        printf("hasnothing nothing... DONE other side closed\n");
                    }
                }
                continue;
            } else {
                int mode;
                printf("hasnothing something %d\n", notimeout);
                if (h3ssl.done) {
                    printf("hasnothing something... DONE\n");
                    hassomething = 1;
                    /* We are ready to get the next request or finish the connection */
                    break;
                }
                if (h3ssl.restart) {
                    printf("hasnothing something... RESTART\n");
                    h3ssl.restart = 0;
                    goto restart;
                }
                if (are_all_clientid_closed(&h3ssl)) {
                    printf("hasnothing something... DONE other side closed\n");
                    /* there might 2 or 3 message we will ignore */
                    /* we might also already have the next connection to accept */
                    hassomething = 1;
                    break;
                }
                mode = SSL_get_shutdown(h3ssl.ssl_ids[0].s);
                printf("hasnothing something SSL_get_shutdown %d!!!!\n", mode);
                if (mode == (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN)) {
                    printf("hasnothing something SHUTDOWN!!!!\n");
                    break;
                }
                if (notimeout) {
                    conn = SSL_accept_connection(listener, 0);
                    if (conn == NULL) {
                        printf("hasnothing something no timeout but nothing to accept\n");
                    } else {
                        printf("hasnothing something no timeout NEW conn\n");
                    }
                }
            }
        }

done_nothing_more:
        /*
         * Free the connection, then loop again, accepting another connection.
         */
        SSL_free(conn);
    }

    ok = 1;
err:
    printf("error!!!\n");
    if (!ok)
        ERR_print_errors_fp(stderr);

    SSL_free(listener);
    return ok;
}

/*
 * demo server... just return a 20 bytes ascii string as response for any
 * request single h3 connection and single threaded.
 */
int main(int argc, char **argv)
{
    int rc = 1;
    SSL_CTX *ctx = NULL;
    int fd = -1;
    unsigned long port;

    if (argc < 4) {
        fprintf(stderr, "usage: %s <port> <server.crt> <server.key>\n",
                argv[0]);
        goto err;
    }

    /* Create SSL_CTX. */
    if ((ctx = create_ctx(argv[2], argv[3])) == NULL)
        goto err;

    /* Parse port number from command line arguments. */
    port = strtoul(argv[1], NULL, 0);
    if (port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "invalid port: %lu\n", port);
        goto err;
    }

    /* Create UDP socket. */
    if ((fd = create_socket((uint16_t)port)) < 0)
        goto err;

    /* Enter QUIC server connection acceptance loop. */
    if (!run_quic_server(ctx, fd))
        goto err;

    rc = 0;
err:
    if (rc != 0)
        ERR_print_errors_fp(stderr);

    SSL_CTX_free(ctx);

    if (fd != -1)
        BIO_closesocket(fd);

    return rc;
}
