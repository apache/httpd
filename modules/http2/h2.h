/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __mod_h2__h2__
#define __mod_h2__h2__

/**
 * The magic PRIamble of RFC 7540 that is always sent when starting
 * a h2 communication.
 */
extern const char *H2_MAGIC_TOKEN;

#define H2_ERR_NO_ERROR             (0x00)
#define H2_ERR_PROTOCOL_ERROR       (0x01)
#define H2_ERR_INTERNAL_ERROR       (0x02)
#define H2_ERR_FLOW_CONTROL_ERROR   (0x03)
#define H2_ERR_SETTINGS_TIMEOUT     (0x04)
#define H2_ERR_STREAM_CLOSED        (0x05)
#define H2_ERR_FRAME_SIZE_ERROR     (0x06)
#define H2_ERR_REFUSED_STREAM       (0x07)
#define H2_ERR_CANCEL               (0x08)
#define H2_ERR_COMPRESSION_ERROR    (0x09)
#define H2_ERR_CONNECT_ERROR        (0x0a)
#define H2_ERR_ENHANCE_YOUR_CALM    (0x0b)
#define H2_ERR_INADEQUATE_SECURITY  (0x0c)
#define H2_ERR_HTTP_1_1_REQUIRED    (0x0d)

#define H2_HEADER_METHOD     ":method"
#define H2_HEADER_METHOD_LEN 7
#define H2_HEADER_SCHEME     ":scheme"
#define H2_HEADER_SCHEME_LEN 7
#define H2_HEADER_AUTH       ":authority"
#define H2_HEADER_AUTH_LEN   10
#define H2_HEADER_PATH       ":path"
#define H2_HEADER_PATH_LEN   5
#define H2_CRLF             "\r\n"

/* Max data size to write so it fits inside a TLS record */
#define H2_DATA_CHUNK_SIZE          ((16*1024) - 100 - 9) 

/* Maximum number of padding bytes in a frame, rfc7540 */
#define H2_MAX_PADLEN               256
/* Initial default window size, RFC 7540 ch. 6.5.2 */
#define H2_INITIAL_WINDOW_SIZE      ((64*1024)-1)

#define H2_STREAM_CLIENT_INITIATED(id)      (id&0x01)

#define H2_ALEN(a)          (sizeof(a)/sizeof((a)[0]))

#define H2MAX(x,y) ((x) > (y) ? (x) : (y))
#define H2MIN(x,y) ((x) < (y) ? (x) : (y))

typedef enum {
    H2_DEPENDANT_AFTER,
    H2_DEPENDANT_INTERLEAVED,
    H2_DEPENDANT_BEFORE,
} h2_dependency;

typedef struct h2_priority {
    h2_dependency dependency;
    int           weight;
} h2_priority;

typedef enum {
    H2_PUSH_NONE,
    H2_PUSH_DEFAULT,
    H2_PUSH_HEAD,
    H2_PUSH_FAST_LOAD,
} h2_push_policy;

typedef enum {
    H2_SESSION_ST_INIT,             /* send initial SETTINGS, etc. */
    H2_SESSION_ST_DONE,             /* finished, connection close */
    H2_SESSION_ST_IDLE,             /* nothing to write, expecting data inc */
    H2_SESSION_ST_BUSY,             /* read/write without stop */
    H2_SESSION_ST_WAIT,             /* waiting for tasks reporting back */
    H2_SESSION_ST_CLEANUP,          /* pool is being cleaned up */
} h2_session_state;

typedef struct h2_session_props {
    int accepted_max;      /* the highest remote stream id was/will be handled */
    int completed_max;     /* the highest remote stream completed */
    int emitted_count;     /* the number of local streams sent */
    int emitted_max;       /* the highest local stream id sent */
    int error;             /* the last session error encountered */
    unsigned int accepting : 1;     /* if the session is accepting new streams */
    unsigned int shutdown : 1;      /* if the final GOAWAY has been sent */
} h2_session_props;

typedef enum h2_stream_state_t {
    H2_SS_IDLE,
    H2_SS_RSVD_R,
    H2_SS_RSVD_L,
    H2_SS_OPEN,
    H2_SS_CLOSED_R,
    H2_SS_CLOSED_L,
    H2_SS_CLOSED,
    H2_SS_CLEANUP,
    H2_SS_MAX
} h2_stream_state_t;

typedef enum {
    H2_SEV_CLOSED_L,
    H2_SEV_CLOSED_R,
    H2_SEV_CANCELLED,
    H2_SEV_EOS_SENT,
    H2_SEV_IN_DATA_PENDING,
} h2_stream_event_t;


/* h2_request is the transformer of HTTP2 streams into HTTP/1.1 internal
 * format that will be fed to various httpd input filters to finally
 * become a request_rec to be handled by soemone.
 */
typedef struct h2_request h2_request;

struct h2_request {
    const char *method; /* pseudo header values, see ch. 8.1.2.3 */
    const char *scheme;
    const char *authority;
    const char *path;
    apr_table_t *headers;

    apr_time_t request_time;
    unsigned int chunked : 1;   /* iff requst body needs to be forwarded as chunked */
    unsigned int serialize : 1; /* iff this request is written in HTTP/1.1 serialization */
};

typedef struct h2_headers h2_headers;

struct h2_headers {
    int         status;
    apr_table_t *headers;
    apr_table_t *notes;
};

typedef apr_status_t h2_io_data_cb(void *ctx, const char *data, apr_off_t len);

typedef int h2_stream_pri_cmp(int stream_id1, int stream_id2, void *ctx);

/* Note key to attach connection task id to conn_rec/request_rec instances */

#define H2_TASK_ID_NOTE         "http2-task-id"
#define H2_FILTER_DEBUG_NOTE    "http2-debug"
#define H2_HDR_CONFORMANCE      "http2-hdr-conformance"
#define H2_HDR_CONFORMANCE_UNSAFE      "unsafe"

#endif /* defined(__mod_h2__h2__) */
