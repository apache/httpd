/*
 *  Copyright 1999-2004 The Apache Software Foundation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
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

    /* ACCEPT-LANGUAGE is the longest headeer
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
                    if (memcmp(p, "CHARSET", 7) == 0)
                        return SC_ACCEPT_CHARSET;
                    else if (memcmp(p,  "ENCODING", 8) == 0)
                        return SC_ACCEPT_ENCODING;
                    else if (memcmp(p, "LANGUAGE", 8) == 0)
                        return SC_ACCEPT_LANGUAGE;
                    else
                        return UNKNOWN_METHOD;
                }
                else
                    return UNKNOWN_METHOD;
            }
            else if (memcmp(p, "UTHORIZATION", 12) == 0)
                return SC_AUTHORIZATION;
            else
                return UNKNOWN_METHOD;
        break;
        case 'C':
            if (memcmp(p, "OOKIE", 5) == 0)
                return SC_COOKIE;
            else if(memcmp(p, "ONNECTION", 9) == 0)
                return SC_CONNECTION;
            else if(memcmp(p, "ONTENT-TYPE", 11) == 0)
                return SC_CONTENT_TYPE;
            else if(memcmp(p, "ONTENT-LENGTH", 13) == 0)
                return SC_CONTENT_LENGTH;
            else if(memcmp(p, "OOKIE2", 6) == 0)
                return SC_COOKIE2;
            else
                return UNKNOWN_METHOD;
        break;
        case 'H':
            if(memcmp(p, "OST", 3) == 0)
                return SC_HOST;
            else
                return UNKNOWN_METHOD;
        break;
        case 'P':
            if(memcmp(p, "RAGMA", 5) == 0)
                return SC_PRAGMA;
            else
                return UNKNOWN_METHOD;
        break;
        case 'R':
            if(memcmp(p, "EFERER", 6) == 0)
                return SC_REFERER;
            else
                return UNKNOWN_METHOD;
        break;
        case 'U':
            if(memcmp(p, "SER-AGENT", 9) == 0)
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

static int sc_for_req_method_by_id(int method_id)
{
    if (method_id < 0 || method_id > M_INVALID)
        return UNKNOWN_METHOD;
    else
        return sc_for_req_method_table[method_id] ?
               sc_for_req_method_table[method_id] : UNKNOWN_METHOD;
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

static apr_status_t ajp_marshal_into_msgb(ajp_msg_t    *msg,
                                 request_rec *r)
{
    int method;
    apr_uint32_t i, num_headers = 0;
    apr_byte_t is_ssl;
    char *remote_host;
    char *uri;
    

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Into ajp_marshal_into_msgb");

    if ((method = sc_for_req_method_by_id(r->method_number)) == UNKNOWN_METHOD) { 
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "Error ajp_marshal_into_msgb - No such method %s",
               r->method);
        return APR_EGENERAL;
    }

    /* XXXX need something */
    is_ssl = (apr_byte_t) 0; /* s->is_ssl */

    if (r->headers_in && apr_table_elts(r->headers_in)) {
        const apr_array_header_t *t = apr_table_elts(r->headers_in);
        num_headers = t->nelts;
    }

    remote_host = (char *)ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_HOST, NULL);

    uri = apr_pstrdup(r->pool, r->uri);
    if (uri != NULL) {
        char *query_str = strchr(uri, '?');
        if (query_str != NULL) {
            *query_str = 0;
        }
    }
    

    ajp_msg_reset(msg);

    if (ajp_msg_append_uint8(msg, CMD_AJP13_FORWARD_REQUEST)     ||
        ajp_msg_append_uint8(msg, method)                        ||
        ajp_msg_append_string(msg, r->protocol)                  ||
        ajp_msg_append_string(msg, uri)                          ||
        ajp_msg_append_string(msg, r->connection->remote_ip)     ||
        ajp_msg_append_string(msg, remote_host)                  ||
        ajp_msg_append_string(msg, ap_get_server_name(r))        ||
        ajp_msg_append_uint16(msg, (apr_uint16_t)r->connection->local_addr->port) ||
        ajp_msg_append_uint8(msg, is_ssl)                        ||
        ajp_msg_append_uint16(msg, (apr_uint16_t) num_headers)) {

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "Error ajp_marshal_into_msgb - "
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
                       "Error ajp_marshal_into_msgb - "
                       "Error appending the header name");
                return APR_EGENERAL;
            }
        }
        else {
            if (ajp_msg_append_string(msg, elts[i].key)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                       "Error ajp_marshal_into_msgb - "
                       "Error appending the header name");
                return APR_EGENERAL;
            }
        }
        
        if (ajp_msg_append_string(msg, elts[i].val)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "Error ajp_marshal_into_msgb - "
                   "Error appending the header value");
            return APR_EGENERAL;
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
                   "Error ajp_marshal_into_msgb - "
                   "Error appending the remote user");
            return APR_EGENERAL;
        }
    }
    if (r->ap_auth_type) {
        if (ajp_msg_append_uint8(msg, SC_A_AUTH_TYPE) ||
            ajp_msg_append_string(msg, r->ap_auth_type)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "Error ajp_marshal_into_msgb - "
                   "Error appending the auth type");
            return APR_EGENERAL;
        }
    }
    /* XXXX  ebcdic (args converted?) */
    if (r->args) {
        if (ajp_msg_append_uint8(msg, SC_A_QUERY_STRING) ||
            ajp_msg_append_string(msg, r->args)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "Error ajp_marshal_into_msgb - "
                   "Error appending the query string");
            return APR_EGENERAL;
        }
    }
/* XXXX ignored for the moment
    if (s->jvm_route) {
        if (ajp_msg_append_uint8(msg, SC_A_JVM_ROUTE) ||
            ajp_msg_append_string(msg, s->jvm_route)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "Error ajp_marshal_into_msgb - "
                   "Error appending the jvm route");
            return APR_EGENERAL;
        }
    }
    if (s->ssl_cert_len) {
        if (ajp_msg_append_uint8(msg, SC_A_SSL_CERT) ||
            ajp_msg_append_string(msg, s->ssl_cert)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "Error ajp_marshal_into_msgb - "
                   "Error appending the SSL certificates");
            return APR_EGENERAL;
        }
    }

    if (s->ssl_cipher) {
        if (ajp_msg_append_uint8(msg, SC_A_SSL_CIPHER) ||
            ajp_msg_append_string(msg, s->ssl_cipher)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "Error ajp_marshal_into_msgb - "
                   "Error appending the SSL ciphers");
            return APR_EGENERAL;
        }
    }
    if (s->ssl_session) {
        if (ajp_msg_append_uint8(msg, SC_A_SSL_SESSION) ||
            ajp_msg_append_string(msg, s->ssl_session)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "Error ajp_marshal_into_msgb - "
                   "Error appending the SSL session");
            return APR_EGENERAL;
        }
    }
 */

    /*
     * ssl_key_size is required by Servlet 2.3 API
     * added support only in ajp14 mode
     * JFC removed: ae->proto == AJP14_PROTO
     */
 /* XXXX ignored for the moment
    if (s->ssl_key_size != -1) {
        if (ajp_msg_append_uint8(msg, SC_A_SSL_KEY_SIZE) ||
            ajp_msg_append_uint16(msg, (unsigned short) s->ssl_key_size)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "Error ajp_marshal_into_msgb - "
                   "Error appending the SSL key size");
            return APR_EGENERAL;
        }
    }
 */

 /* XXXX ignored for the moment
    if (s->num_attributes > 0) {
        for (i = 0 ; i < s->num_attributes ; i++) {
            if (ajp_msg_append_uint8(msg, SC_A_REQ_ATTRIBUTE)       ||
                ajp_msg_append_string(msg, s->attributes_names[i]) ||
                ajp_msg_append_string(msg, s->attributes_values[i])) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                      "Error ajp_marshal_into_msgb - "
                      "Error appending attribute %s=%s",
                      s->attributes_names[i], s->attributes_values[i]);
                return APR_EGENERAL;
            }
        }
    }
  */

    if (ajp_msg_append_uint8(msg, SC_A_ARE_DONE)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "Error ajp_marshal_into_msgb - "
               "Error appending the message end");
        return APR_EGENERAL;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
           "ajp_marshal_into_msgb - Done");
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


static apr_status_t ajp_unmarshal_response(ajp_msg_t   *msg,
                                  request_rec  *r)
{
    apr_uint16_t status;
    apr_status_t rc;
    char *ptr;
    apr_uint16_t  num_headers;
    int i;

    rc = ajp_msg_get_uint16(msg, &status);

    if (rc != APR_SUCCESS) {
         ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "Error ajp_unmarshal_response - Null status");
        return APR_EGENERAL;
    }
    r->status = status;

    rc = ajp_msg_get_string(msg, &ptr);
    if (rc == APR_SUCCESS) {
        r->status_line =  apr_psprintf(r->pool, "%d %s", status, ptr);
#if defined(AS400) || defined(_OSD_POSIX)
        ap_xlate_proto_from_ascii(r->status_line, strlen(r->status_line));
#endif
    } else {
        r->status_line = NULL;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
           "ajp_unmarshal_response: status = %d", status);

    rc = ajp_msg_get_uint16(msg, &num_headers);
    if (rc == APR_SUCCESS) {
        r->headers_out = apr_table_make(r->pool, num_headers);
    } else {
        r->headers_out = NULL;
        num_headers = 0;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
           "ajp_unmarshal_response: Number of headers is = %d",
           num_headers);

    for(i = 0 ; i < (int) num_headers ; i++) {
        apr_uint16_t name;
        char *stringname;
        char *value;
        rc  = ajp_msg_peek_uint16(msg, &name);
        if (rc != APR_SUCCESS) {
            return APR_EGENERAL;
        }
                
        if ((name & 0XFF00) == 0XA000) {
            ajp_msg_peek_uint16(msg, &name);
            stringname = (char *)long_res_header_for_sc(name);
            if (stringname == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                       "Error ajp_unmarshal_response - "
                       "No such sc (%08x)",
                       name);
                return APR_EGENERAL;
            }
        } else {
            name = 0;
            rc = ajp_msg_get_string(msg, &stringname);
            if (rc != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                       "Error ajp_unmarshal_response - "
                       "Null header name");
                return APR_EGENERAL;
            }
#if defined(AS400) || defined(_OSD_POSIX)
            ap_xlate_proto_from_ascii(stringname, strlen(stringname));
#endif
        }

        rc = ajp_msg_get_string(msg, &value);
        if (rc != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                   "Error ajp_unmarshal_response - "
                   "Null header value");
            return APR_EGENERAL;
        }

#if defined(AS400) || defined(_OSD_POSIX)
        ap_xlate_proto_from_ascii(value, strlen(value));
#endif
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "ajp_unmarshal_response: Header[%d] [%s] = [%s]", 
                       i, stringname, value);
        apr_table_add(r->headers_out, stringname, value);

        /* Content-type needs an additional handling */
        if (memcmp(stringname, "Content-Type", 12) == 0) {
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
                                  request_rec  *r)
{
    ajp_msg_t *msg;
    apr_status_t rc;

    rc = ajp_msg_create(r->pool, &msg);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_send_header: ajp_msg_create failed");
        return rc;
    }

    rc = ajp_marshal_into_msgb(msg, r);    
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
                             ajp_msg_t **msg)
{
    apr_byte_t result;
    apr_status_t rc;
    
    rc = ajp_msg_create(r->pool, msg);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_read_header: ajp_msg_create failed");
        return rc;
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
apr_status_t ajp_parse_header(request_rec  *r, ajp_msg_t *msg)
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
        return APR_EGENERAL;
    }
    return ajp_unmarshal_response(msg, r);
}

/* parse the body and return data address and length */
apr_status_t  ajp_parse_data(request_rec  *r, ajp_msg_t *msg,
                             apr_uint16_t *len, char **ptr)
{
    apr_byte_t result;
    apr_status_t rc;

    rc = ajp_msg_get_uint8(msg, &result);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_parse_data: ajp_msg_get_byte failed");
        return rc;
    }
    if (result != CMD_AJP13_SEND_BODY_CHUNK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_parse_data: wrong type %02x expecting 0x03", result);
        return APR_EGENERAL;
    }
    rc = ajp_msg_get_uint16(msg, len);
    if (rc != APR_SUCCESS) {
        return APR_EGENERAL;
    }
    *ptr = (char *)&(msg->buf[msg->pos]);
    return APR_SUCCESS;
}

/*
 * Allocate a msg to send data
 */
apr_status_t  ajp_alloc_data_msg(request_rec *r, char **ptr, apr_size_t *len,
                                 ajp_msg_t **msg)
{
    apr_status_t rc;

    rc = ajp_msg_create(r->pool, msg);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_alloc_data_msg: ajp_msg_create failed");
        return rc;
    }
    ajp_msg_reset(*msg);
    *ptr = (char *)&((*msg)->buf[6]);
    *len = AJP_MSG_BUFFER_SZ-6;

    return APR_SUCCESS;
}

/*
 * Send the data message
 */
apr_status_t  ajp_send_data_msg(apr_socket_t *sock, request_rec  *r,
                                ajp_msg_t *msg, apr_size_t len)
{
    apr_status_t rc;

    msg->buf[4] = (apr_byte_t)((len >> 8) & 0xFF);
    msg->buf[5] = (apr_byte_t)(len & 0xFF);

    msg->len += len + 2; /* + 1 XXXX where is '\0' */

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "ajp_send_data_msg: sending %d", len);

    rc = ajp_ilink_send(sock, msg);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_send_data_msg: ajp_ilink_send failed");
        return rc;
    }

    return APR_SUCCESS;
}
