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

#include "ajp_header.h"
#include "ajp.h"

static const char *response_trans_headers[] = {
    "Content-Type",
    "Content-Language",
    "Content-Length",
    "Date",
    "Last-Modified",
    "Location",
    "Set-Cookie",
    "Set-Cookie2",
    "Servlet-Engine",
    "Status",
    "WWW-Authenticate"
};

static const char *long_res_header_for_sc(int sc)
{
    const char *rc = NULL;
    sc = sc & 0X00FF;
    if(sc <= SC_RES_HEADERS_NUM && sc > 0) {
        rc = response_trans_headers[sc - 1];
    }

    return rc;
}

#define UNKNOWN_METHOD (-1)

static int sc_for_req_header(const char *header_name)
{
    char header[16];
    apr_size_t len = strlen(header_name);
    const char *p = header_name;
    int i = 0;

    /* ACCEPT-LANGUAGE is the longest header
     * that is of interest.
     */
    if (len < 4 || len > 15)
        return UNKNOWN_METHOD;

    while (*p)
        header[i++] = apr_toupper(*p++);
    header[i] = '\0';
    p = &header[1];

    switch (header[0]) {
        case 'A':
            if (memcmp(p, "CCEPT", 5) == 0) {
                if (!header[6])
                    return SC_ACCEPT;
                else if (header[6] == '-') {
                    p += 6;
                    if (strcmp(p, "CHARSET") == 0)
                        return SC_ACCEPT_CHARSET;
                    else if (strcmp(p,  "ENCODING") == 0)
                        return SC_ACCEPT_ENCODING;
                    else if (strcmp(p, "LANGUAGE") == 0)
                        return SC_ACCEPT_LANGUAGE;
                    else
                        return UNKNOWN_METHOD;
                }
                else
                    return UNKNOWN_METHOD;
            }
            else if (strcmp(p, "UTHORIZATION") == 0)
                return SC_AUTHORIZATION;
            else
                return UNKNOWN_METHOD;
        break;
        case 'C':
            if(strcmp(p, "OOKIE2") == 0)
                return SC_COOKIE2;
            else if (strcmp(p, "OOKIE") == 0)
                return SC_COOKIE;
            else if(strcmp(p, "ONNECTION") == 0)
                return SC_CONNECTION;
            else if(strcmp(p, "ONTENT-TYPE") == 0)
                return SC_CONTENT_TYPE;
            else if(strcmp(p, "ONTENT-LENGTH") == 0)
                return SC_CONTENT_LENGTH;
            else
                return UNKNOWN_METHOD;
        break;
        case 'H':
            if(strcmp(p, "OST") == 0)
                return SC_HOST;
            else
                return UNKNOWN_METHOD;
        break;
        case 'P':
            if(strcmp(p, "RAGMA") == 0)
                return SC_PRAGMA;
            else
                return UNKNOWN_METHOD;
        break;
        case 'R':
            if(strcmp(p, "EFERER") == 0)
                return SC_REFERER;
            else
                return UNKNOWN_METHOD;
        break;
        case 'U':
            if(strcmp(p, "SER-AGENT") == 0)
                return SC_USER_AGENT;
            else
                return UNKNOWN_METHOD;
        break;
        default:
            return UNKNOWN_METHOD;
    }

    /* NOTREACHED */
}

/* Apache method number to SC methods transform table */
static const unsigned char sc_for_req_method_table[] = {
    SC_M_GET,
    SC_M_PUT,
    SC_M_POST,
    SC_M_DELETE,
    0,                      /* M_DELETE */
    SC_M_OPTIONS,
    SC_M_TRACE,
    0,                      /* M_PATCH  */
    SC_M_PROPFIND,
    SC_M_PROPPATCH,
    SC_M_MKCOL,
    SC_M_COPY,
    SC_M_MOVE,
    SC_M_LOCK,
    SC_M_UNLOCK,
    SC_M_VERSION_CONTROL,
    SC_M_CHECKOUT,
    SC_M_UNCHECKOUT,
    SC_M_CHECKIN,
    SC_M_UPDATE,
    SC_M_LABEL,
    SC_M_REPORT,
    SC_M_MKWORKSPACE,
    SC_M_MKACTIVITY,
    SC_M_BASELINE_CONTROL,
    SC_M_MERGE,
    0                       /* M_INVALID */
};

static int sc_for_req_method_by_id(request_rec *r)
{
    int method_id = r->method_number;
    if (method_id < 0 || method_id > M_INVALID) {
        return UNKNOWN_METHOD;
    }
    else if (r->header_only) {
        return SC_M_HEAD;
    }
    else {
        return sc_for_req_method_table[method_id] ?
               sc_for_req_method_table[method_id] : UNKNOWN_METHOD;
    }
}

/*
 * Message structure
 *
 *
AJPV13_REQUEST/AJPV14_REQUEST=
    request_prefix (1) (byte)
    method         (byte)
    protocol       (string)
    req_uri        (string)
    remote_addr    (string)
    remote_host    (string)
    server_name    (string)
    server_port    (short)
    is_ssl         (boolean)
    num_headers    (short)
    num_headers*(req_header_name header_value)

    ?context       (byte)(string)
    ?servlet_path  (byte)(string)
    ?remote_user   (byte)(string)
    ?auth_type     (byte)(string)
    ?query_string  (byte)(string)
    ?jvm_route     (byte)(string)
    ?ssl_cert      (byte)(string)
    ?ssl_cipher    (byte)(string)
    ?ssl_session   (byte)(string)
    ?ssl_key_size  (byte)(int)      via JkOptions +ForwardKeySize
    request_terminator (byte)
    ?body          content_length*(var binary)

 */

static apr_status_t ajp_marshal_into_msgb(ajp_msg_t *msg,
                                          request_rec *r,
                                          apr_uri_t *uri)
{
    int method;
    apr_uint32_t i, num_headers = 0;
    apr_byte_t is_ssl;
    char *remote_host;
    const char *session_route, *envvar;
    const apr_array_header_t *arr = apr_table_elts(r->subprocess_env);
    const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Into ajp_marshal_into_msgb");

    if ((method = sc_for_req_method_by_id(r)) == UNKNOWN_METHOD) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_marshal_into_msgb - No such method %s",
               r->method);
        return AJP_EBAD_METHOD;
    }

    is_ssl = (apr_byte_t) ap_proxy_conn_is_https(r->connection);

    if (r->headers_in && apr_table_elts(r->headers_in)) {
        const apr_array_header_t *t = apr_table_elts(r->headers_in);
        num_headers = t->nelts;
    }

    remote_host = (char *)ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_HOST, NULL);

    ajp_msg_reset(msg);

    if (ajp_msg_append_uint8(msg, CMD_AJP13_FORWARD_REQUEST)     ||
        ajp_msg_append_uint8(msg, method)                        ||
        ajp_msg_append_string(msg, r->protocol)                  ||
        ajp_msg_append_string(msg, uri->path)                    ||
        ajp_msg_append_string(msg, r->connection->remote_ip)     ||
        ajp_msg_append_string(msg, remote_host)                  ||
        ajp_msg_append_string(msg, ap_get_server_name(r))        ||
        ajp_msg_append_uint16(msg, (apr_uint16_t)r->connection->local_addr->port) ||
        ajp_msg_append_uint8(msg, is_ssl)                        ||
        ajp_msg_append_uint16(msg, (apr_uint16_t) num_headers)) {

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_marshal_into_msgb: "
               "Error appending the message begining");
        return APR_EGENERAL;
    }

    for (i = 0 ; i < num_headers ; i++) {
        int sc;
        const apr_array_header_t *t = apr_table_elts(r->headers_in);
        const apr_table_entry_t *elts = (apr_table_entry_t *)t->elts;

        if ((sc = sc_for_req_header(elts[i].key)) != UNKNOWN_METHOD) {
            if (ajp_msg_append_uint16(msg, (apr_uint16_t)sc)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                       "ajp_marshal_into_msgb: "
                       "Error appending the header name");
                return AJP_EOVERFLOW;
            }
        }
        else {
            if (ajp_msg_append_string(msg, elts[i].key)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                       "ajp_marshal_into_msgb: "
                       "Error appending the header name");
                return AJP_EOVERFLOW;
            }
        }

        if (ajp_msg_append_string(msg, elts[i].val)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "ajp_marshal_into_msgb: "
                   "Error appending the header value");
            return AJP_EOVERFLOW;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                   "ajp_marshal_into_msgb: Header[%d] [%s] = [%s]",
                   i, elts[i].key, elts[i].val);
    }

/* XXXX need to figure out how to do this
    if (s->secret) {
        if (ajp_msg_append_uint8(msg, SC_A_SECRET) ||
            ajp_msg_append_string(msg, s->secret)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "Error ajp_marshal_into_msgb - "
                   "Error appending secret");
            return APR_EGENERAL;
        }
    }
 */

    if (r->user) {
        if (ajp_msg_append_uint8(msg, SC_A_REMOTE_USER) ||
            ajp_msg_append_string(msg, r->user)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "ajp_marshal_into_msgb: "
                   "Error appending the remote user");
            return AJP_EOVERFLOW;
        }
    }
    if (r->ap_auth_type) {
        if (ajp_msg_append_uint8(msg, SC_A_AUTH_TYPE) ||
            ajp_msg_append_string(msg, r->ap_auth_type)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "ajp_marshal_into_msgb: "
                   "Error appending the auth type");
            return AJP_EOVERFLOW;
        }
    }
    /* XXXX  ebcdic (args converted?) */
    if (uri->query) {
        if (ajp_msg_append_uint8(msg, SC_A_QUERY_STRING) ||
            ajp_msg_append_string(msg, uri->query)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "ajp_marshal_into_msgb: "
                   "Error appending the query string");
            return AJP_EOVERFLOW;
        }
    }
    if ((session_route = apr_table_get(r->notes, "session-route"))) {
        if (ajp_msg_append_uint8(msg, SC_A_JVM_ROUTE) ||
            ajp_msg_append_string(msg, session_route)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "ajp_marshal_into_msgb: "
                   "Error appending the jvm route");
            return AJP_EOVERFLOW;
        }
    }
/* XXX: Is the subprocess_env a right place?
 * <Location /examples>
 *   ProxyPass ajp://remote:8009/servlets-examples
 *   SetEnv SSL_SESSION_ID CUSTOM_SSL_SESSION_ID
 * </Location>
 */
    /*
     * Only lookup SSL variables if we are currently running HTTPS.
     * Furthermore ensure that only variables get set in the AJP message
     * that are not NULL and not empty.
     */
    if (is_ssl) {
        if ((envvar = ap_proxy_ssl_val(r->pool, r->server, r->connection, r,
                                       AJP13_SSL_CLIENT_CERT_INDICATOR))
            && envvar[0]) {
            if (ajp_msg_append_uint8(msg, SC_A_SSL_CERT)
                || ajp_msg_append_string(msg, envvar)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "ajp_marshal_into_msgb: "
                             "Error appending the SSL certificates");
                return AJP_EOVERFLOW;
            }
        }

        if ((envvar = ap_proxy_ssl_val(r->pool, r->server, r->connection, r,
                                       AJP13_SSL_CIPHER_INDICATOR))
            && envvar[0]) {
            if (ajp_msg_append_uint8(msg, SC_A_SSL_CIPHER)
                || ajp_msg_append_string(msg, envvar)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "ajp_marshal_into_msgb: "
                             "Error appending the SSL ciphers");
                return AJP_EOVERFLOW;
            }
        }

        if ((envvar = ap_proxy_ssl_val(r->pool, r->server, r->connection, r,
                                       AJP13_SSL_SESSION_INDICATOR))
            && envvar[0]) {
            if (ajp_msg_append_uint8(msg, SC_A_SSL_SESSION)
                || ajp_msg_append_string(msg, envvar)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "ajp_marshal_into_msgb: "
                             "Error appending the SSL session");
                return AJP_EOVERFLOW;
            }
        }

        /* ssl_key_size is required by Servlet 2.3 API */
        if ((envvar = ap_proxy_ssl_val(r->pool, r->server, r->connection, r,
                                       AJP13_SSL_KEY_SIZE_INDICATOR))
            && envvar[0]) {

            if (ajp_msg_append_uint8(msg, SC_A_SSL_KEY_SIZE)
                || ajp_msg_append_uint16(msg, (unsigned short) atoi(envvar))) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "Error ajp_marshal_into_msgb - "
                             "Error appending the SSL key size");
                return APR_EGENERAL;
            }
        }
    }
    /* Forward the remote port information, which was forgotten
     * from the builtin data of the AJP 13 protocol.
     * Since the servlet spec allows to retrieve it via getRemotePort(),
     * we provide the port to the Tomcat connector as a request
     * attribute. Modern Tomcat versions know how to retrieve
     * the remote port from this attribute.
     */
    {
        const char *key = SC_A_REQ_REMOTE_PORT;
        char *val = apr_itoa(r->pool, r->connection->remote_addr->port);
        if (ajp_msg_append_uint8(msg, SC_A_REQ_ATTRIBUTE) ||
            ajp_msg_append_string(msg, key)   ||
            ajp_msg_append_string(msg, val)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                    "ajp_marshal_into_msgb: "
                    "Error appending attribute %s=%s",
                    key, val);
            return AJP_EOVERFLOW;
        }
    }
    /* Use the environment vars prefixed with AJP_
     * and pass it to the header striping that prefix.
     */
    for (i = 0; i < (apr_uint32_t)arr->nelts; i++) {
        if (!strncmp(elts[i].key, "AJP_", 4)) {
            if (ajp_msg_append_uint8(msg, SC_A_REQ_ATTRIBUTE) ||
                ajp_msg_append_string(msg, elts[i].key + 4)   ||
                ajp_msg_append_string(msg, elts[i].val)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                        "ajp_marshal_into_msgb: "
                        "Error appending attribute %s=%s",
                        elts[i].key, elts[i].val);
                return AJP_EOVERFLOW;
            }
        }
    }

    if (ajp_msg_append_uint8(msg, SC_A_ARE_DONE)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_marshal_into_msgb: "
               "Error appending the message end");
        return AJP_EOVERFLOW;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
            "ajp_marshal_into_msgb: Done");
    return APR_SUCCESS;
}

/*
AJPV13_RESPONSE/AJPV14_RESPONSE:=
    response_prefix (2)
    status          (short)
    status_msg      (short)
    num_headers     (short)
    num_headers*(res_header_name header_value)
    *body_chunk
    terminator      boolean <! -- recycle connection or not  -->

req_header_name :=
    sc_req_header_name | (string)

res_header_name :=
    sc_res_header_name | (string)

header_value :=
    (string)

body_chunk :=
    length  (short)
    body    length*(var binary)

 */

static int addit_dammit(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

static apr_status_t ajp_unmarshal_response(ajp_msg_t *msg,
                                           request_rec *r,
                                           proxy_dir_conf *dconf)
{
    apr_uint16_t status;
    apr_status_t rc;
    const char *ptr;
    apr_uint16_t  num_headers;
    int i;

    rc = ajp_msg_get_uint16(msg, &status);

    if (rc != APR_SUCCESS) {
         ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                "ajp_unmarshal_response: Null status");
        return rc;
    }
    r->status = status;

    rc = ajp_msg_get_string(msg, &ptr);
    if (rc == APR_SUCCESS) {
#if defined(AS400) || defined(_OSD_POSIX) /* EBCDIC platforms */
        ptr = apr_pstrdup(r->pool, ptr);
        ap_xlate_proto_from_ascii(ptr, strlen(ptr));
#endif
        r->status_line =  apr_psprintf(r->pool, "%d %s", status, ptr);
    } else {
        r->status_line = NULL;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
           "ajp_unmarshal_response: status = %d", status);

    rc = ajp_msg_get_uint16(msg, &num_headers);
    if (rc == APR_SUCCESS) {
        apr_table_t *save_table;

        /* First, tuck away all already existing cookies */
        /*
         * Could optimize here, but just in case we want to
         * also save other headers, keep this logic.
         */
        save_table = apr_table_make(r->pool, num_headers + 2);
        apr_table_do(addit_dammit, save_table, r->headers_out,
                     "Set-Cookie", NULL);
        r->headers_out = save_table;
    } else {
        r->headers_out = NULL;
        num_headers = 0;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
           "ajp_unmarshal_response: Number of headers is = %d",
           num_headers);

    for(i = 0 ; i < (int) num_headers ; i++) {
        apr_uint16_t name;
        const char *stringname;
        const char *value;
        rc  = ajp_msg_peek_uint16(msg, &name);
        if (rc != APR_SUCCESS) {
            return rc;
        }

        if ((name & 0XFF00) == 0XA000) {
            ajp_msg_get_uint16(msg, &name);
            stringname = long_res_header_for_sc(name);
            if (stringname == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                       "ajp_unmarshal_response: "
                       "No such sc (%08x)",
                       name);
                return AJP_EBAD_HEADER;
            }
        } else {
            name = 0;
            rc = ajp_msg_get_string(msg, &stringname);
            if (rc != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                       "ajp_unmarshal_response: "
                       "Null header name");
                return rc;
            }
#if defined(AS400) || defined(_OSD_POSIX)
            ap_xlate_proto_from_ascii(stringname, strlen(stringname));
#endif
        }

        rc = ajp_msg_get_string(msg, &value);
        if (rc != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "ajp_unmarshal_response: "
                   "Null header value");
            return rc;
        }

        /* Set-Cookie need additional processing */
        if (!strcasecmp(stringname, "Set-Cookie")) {
            value = ap_proxy_cookie_reverse_map(r, dconf, value);
        }
        /* Location, Content-Location, URI and Destination need additional
         * processing */
        else if (!strcasecmp(stringname, "Location")
                 || !strcasecmp(stringname, "Content-Location")
                 || !strcasecmp(stringname, "URI")
                 || !strcasecmp(stringname, "Destination"))
        {
          value = ap_proxy_location_reverse_map(r, dconf, value);
        }

#if defined(AS400) || defined(_OSD_POSIX)
        ap_xlate_proto_from_ascii(value, strlen(value));
#endif
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "ajp_unmarshal_response: Header[%d] [%s] = [%s]",
                       i, stringname, value);

        apr_table_add(r->headers_out, stringname, value);

        /* Content-type needs an additional handling */
        if (strcasecmp(stringname, "Content-Type") == 0) {
             /* add corresponding filter */
            ap_set_content_type(r, apr_pstrdup(r->pool, value));
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "ajp_unmarshal_response: ap_set_content_type done");
        }
    }

    return APR_SUCCESS;
}

/*
 * Build the ajp header message and send it
 */
apr_status_t ajp_send_header(apr_socket_t *sock,
                             request_rec *r,
                             apr_size_t buffsize,
                             apr_uri_t *uri)
{
    ajp_msg_t *msg;
    apr_status_t rc;

    rc = ajp_msg_create(r->pool, buffsize, &msg);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_send_header: ajp_msg_create failed");
        return rc;
    }

    rc = ajp_marshal_into_msgb(msg, r, uri);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_send_header: ajp_marshal_into_msgb failed");
        return rc;
    }

    rc = ajp_ilink_send(sock, msg);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_send_header: ajp_ilink_send failed");
        return rc;
    }

    return APR_SUCCESS;
}

/*
 * Read the ajp message and return the type of the message.
 */
apr_status_t ajp_read_header(apr_socket_t *sock,
                             request_rec  *r,
                             apr_size_t buffsize,
                             ajp_msg_t **msg)
{
    apr_byte_t result;
    apr_status_t rc;

    if (*msg) {
        rc = ajp_msg_reuse(*msg);
        if (rc != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "ajp_read_header: ajp_msg_reuse failed");
            return rc;
        }
    }
    else {
        rc = ajp_msg_create(r->pool, buffsize, msg);
        if (rc != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "ajp_read_header: ajp_msg_create failed");
            return rc;
        }
    }
    ajp_msg_reset(*msg);
    rc = ajp_ilink_receive(sock, *msg);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_read_header: ajp_ilink_receive failed");
        return rc;
    }
    rc = ajp_msg_peek_uint8(*msg, &result);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "ajp_read_header: ajp_ilink_received %02x", result);
    return APR_SUCCESS;
}

/* parse the msg to read the type */
int ajp_parse_type(request_rec  *r, ajp_msg_t *msg)
{
    apr_byte_t result;
    ajp_msg_peek_uint8(msg, &result);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "ajp_parse_type: got %02x", result);
    return (int) result;
}

/* parse the header */
apr_status_t ajp_parse_header(request_rec  *r, proxy_dir_conf *conf,
                              ajp_msg_t *msg)
{
    apr_byte_t result;
    apr_status_t rc;

    rc = ajp_msg_get_uint8(msg, &result);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_parse_headers: ajp_msg_get_byte failed");
        return rc;
    }
    if (result != CMD_AJP13_SEND_HEADERS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_parse_headers: wrong type %02x expecting 0x04", result);
        return AJP_EBAD_HEADER;
    }
    return ajp_unmarshal_response(msg, r, conf);
}

/* parse the body and return data address and length */
apr_status_t  ajp_parse_data(request_rec  *r, ajp_msg_t *msg,
                             apr_uint16_t *len, char **ptr)
{
    apr_byte_t result;
    apr_status_t rc;
    apr_uint16_t expected_len;

    rc = ajp_msg_get_uint8(msg, &result);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_parse_data: ajp_msg_get_byte failed");
        return rc;
    }
    if (result != CMD_AJP13_SEND_BODY_CHUNK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_parse_data: wrong type %02x expecting 0x03", result);
        return AJP_EBAD_HEADER;
    }
    rc = ajp_msg_get_uint16(msg, len);
    if (rc != APR_SUCCESS) {
        return rc;
    }
    /*
     * msg->len contains the complete length of the message including all
     * headers. So the expected length for a CMD_AJP13_SEND_BODY_CHUNK is
     * msg->len minus the sum of
     * AJP_HEADER_LEN    : The length of the header to every AJP message.
     * AJP_HEADER_SZ_LEN : The header giving the size of the chunk.
     * 1                 : The CMD_AJP13_SEND_BODY_CHUNK indicator byte (0x03).
     * 1                 : The last byte of this message always seems to be
     *                     0x00 and is not part of the chunk.
     */
    expected_len = msg->len - (AJP_HEADER_LEN + AJP_HEADER_SZ_LEN + 1 + 1);
    if (*len != expected_len) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_parse_data: Wrong chunk length. Length of chunk is %i,"
               " expected length is %i.", *len, expected_len);
        return AJP_EBAD_HEADER;
    }
    *ptr = (char *)&(msg->buf[msg->pos]);
    return APR_SUCCESS;
}

/*
 * Allocate a msg to send data
 */
apr_status_t  ajp_alloc_data_msg(apr_pool_t *pool, char **ptr, apr_size_t *len,
                                 ajp_msg_t **msg)
{
    apr_status_t rc;

    if ((rc = ajp_msg_create(pool, *len, msg)) != APR_SUCCESS)
        return rc;
    ajp_msg_reset(*msg);
    *ptr = (char *)&((*msg)->buf[6]);
    *len =  *len - 6;

    return APR_SUCCESS;
}

/*
 * Send the data message
 */
apr_status_t  ajp_send_data_msg(apr_socket_t *sock,
                                ajp_msg_t *msg, apr_size_t len)
{

    msg->buf[4] = (apr_byte_t)((len >> 8) & 0xFF);
    msg->buf[5] = (apr_byte_t)(len & 0xFF);

    msg->len += len + 2; /* + 1 XXXX where is '\0' */

    return ajp_ilink_send(sock, msg);

}
