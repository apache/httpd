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

#include "apr_hash.h"
#include "apr_lib.h"
#include "apr_strings.h"

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "util_script.h"
#include "ap_provider.h"
#include "mod_auth.h"
#include "util_fcgi.h"
#include "ap_mmn.h"

module AP_MODULE_DECLARE_DATA authnz_fcgi_module;

typedef struct {
    const char *name; /* provider name */
    const char *backend; /* backend address, as configured */
    const char *host;
    apr_port_t port;
    apr_sockaddr_t *backend_addrs;
    int is_authn;
    int is_authz;
} fcgi_provider_conf;

typedef struct {
    const char *name; /* provider name */
    const char *default_user; /* this is user if authorizer returns
                               * success and a user expression yields
                               * empty string
                               */
    ap_expr_info_t *user_expr; /* expr to evaluate to set r->user */
    char authoritative; /* fail request if user is rejected? */
    char require_basic_auth; /* fail if client didn't send credentials? */
} fcgi_dir_conf;

typedef struct {
    /* If an "authnz" provider successfully authenticates, record
     * the provider name here for checking during authz.
     */
    const char *successful_authnz_provider;
} fcgi_request_notes;

static apr_hash_t *fcgi_authn_providers, *fcgi_authz_providers;

#define FCGI_IO_TIMEOUT apr_time_from_sec(30)

#ifndef NON200_RESPONSE_BUF_LEN
#define NON200_RESPONSE_BUF_LEN 8192
#endif

/* fcgi://{hostname|IPv4|IPv6}:port[/] */
#define FCGI_BACKEND_REGEX_STR "m%^fcgi://(.*):(\\d{1,5})/?$%"

/*
 * utility function to connect to a peer; generally useful, but 
 * wait for AF_UNIX support in this mod before thinking about how
 * to make it available to other modules
 */
static apr_status_t connect_to_peer(apr_socket_t **newsock,
                                    request_rec *r,
                                    apr_sockaddr_t *backend_addrs,
                                    const char *backend_name,
                                    apr_interval_time_t timeout)
{
    apr_status_t rv = APR_EINVAL; /* returned if no backend addr was provided
                                   */
    int connected = 0;
    apr_sockaddr_t *addr = backend_addrs;

    while (addr && !connected) {
        int loglevel = addr->next ? APLOG_DEBUG : APLOG_ERR;
        rv = apr_socket_create(newsock, addr->family,
                               SOCK_STREAM, 0, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, loglevel, rv, r,
                          APLOGNO(02494) "error creating family %d socket "
                          "for target %s",
                          addr->family, backend_name);
            addr = addr->next;
            continue;
        }

        apr_socket_opt_set(*newsock, APR_TCP_NODELAY, 1);
        apr_socket_timeout_set(*newsock,
                               timeout ? timeout : r->server->timeout);

        rv = apr_socket_connect(*newsock, addr);
        if (rv != APR_SUCCESS) {
            apr_socket_close(*newsock);
            ap_log_rerror(APLOG_MARK, loglevel, rv, r,
                          APLOGNO(02495) "attempt to connect to %pI (%s) "
                          "failed", addr, backend_name);
            addr = addr->next;
            continue;
        }

        connected = 1;
    }

    return rv;
#undef FN_LOG_MARK
}

static void log_provider_info(const fcgi_provider_conf *conf, request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  APLOGNO(02496) "name %s, backend %s, host %s, port %d, "
                  "first address %pI, %c%c",
                  conf->name,
                  conf->backend,
                  conf->host,
                  (int)conf->port,
                  conf->backend_addrs,
                  conf->is_authn ? 'N' : '_',
                  conf->is_authz ? 'Z' : '_');
}

static void setupenv(request_rec *r, const char *password, const char *apache_role)
{
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);
    apr_table_setn(r->subprocess_env, "FCGI_ROLE", AP_FCGI_AUTHORIZER_STR);
    if (apache_role) {
        apr_table_setn(r->subprocess_env, "FCGI_APACHE_ROLE", apache_role);
    }
    if (password) {
        apr_table_setn(r->subprocess_env, "REMOTE_PASSWD", password);
    }
    /* Drop the variables CONTENT_LENGTH, PATH_INFO, PATH_TRANSLATED,
     * SCRIPT_NAME and most Hop-By-Hop headers - EXCEPT we will pass
     * PROXY_AUTH to allow CGI to perform proxy auth for httpd
     */
    apr_table_unset(r->subprocess_env, "CONTENT_LENGTH");
    apr_table_unset(r->subprocess_env, "PATH_INFO");
    apr_table_unset(r->subprocess_env, "PATH_TRANSLATED");
    apr_table_unset(r->subprocess_env, "SCRIPT_NAME");
    apr_table_unset(r->subprocess_env, "HTTP_KEEP_ALIVE");
    apr_table_unset(r->subprocess_env, "HTTP_TE");
    apr_table_unset(r->subprocess_env, "HTTP_TRAILER");
    apr_table_unset(r->subprocess_env, "HTTP_TRANSFER_ENCODING");
    apr_table_unset(r->subprocess_env, "HTTP_UPGRADE");

    /* Connection hop-by-hop header to prevent the CGI from hanging */
    apr_table_setn(r->subprocess_env, "HTTP_CONNECTION", "close");
}

static apr_status_t recv_data(const fcgi_provider_conf *conf,
                              request_rec *r,
                              apr_socket_t *s,
                              char *buf,
                              apr_size_t *buflen)
{
    apr_status_t rv;

    rv = apr_socket_recv(s, buf, buflen);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      APLOGNO(02497) "Couldn't read from backend %s",
                      conf->backend);
        return rv;
    }

#if AP_MODULE_MAGIC_AT_LEAST(20130702,2) 
    ap_log_rdata(APLOG_MARK, APLOG_TRACE5, r, "FastCGI data received",
                 buf, *buflen, AP_LOG_DATA_SHOW_OFFSET);
#endif
    return APR_SUCCESS;
}

static apr_status_t recv_data_full(const fcgi_provider_conf *conf,
                                   request_rec *r,
                                   apr_socket_t *s,
                                   char *buf,
                                   apr_size_t buflen)
{
    apr_size_t readlen;
    apr_size_t cumulative_len = 0;
    apr_status_t rv;

    do {
        readlen = buflen - cumulative_len;
        rv = recv_data(conf, r, s, buf + cumulative_len, &readlen);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        cumulative_len += readlen;
    } while (cumulative_len < buflen);

    return APR_SUCCESS;
}

static apr_status_t sendv_data(const fcgi_provider_conf *conf,
                               request_rec *r,
                               apr_socket_t *s,
                               struct iovec *vec,
                               int nvec,
                               apr_size_t *len)
{
    apr_size_t to_write = 0, written = 0;
    apr_status_t rv = APR_SUCCESS;
    int i, offset;

    for (i = 0; i < nvec; i++) {
        to_write += vec[i].iov_len;
#if AP_MODULE_MAGIC_AT_LEAST(20130702,2) 
        ap_log_rdata(APLOG_MARK, APLOG_TRACE5, r, "FastCGI data sent",
                     vec[i].iov_base, vec[i].iov_len, AP_LOG_DATA_SHOW_OFFSET);
#endif
    }

    offset = 0;
    while (to_write) {
        apr_size_t n = 0;
        rv = apr_socket_sendv(s, vec + offset, nvec - offset, &n);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          APLOGNO(02498) "Sending data to %s failed",
                          conf->backend);
            break;
        }
        if (n > 0) {
            written += n;
            if (written >= to_write)
                break;                 /* short circuit out */
            for (i = offset; i < nvec; ) {
                if (n >= vec[i].iov_len) {
                    offset++;
                    n -= vec[i++].iov_len;
                } else {
                    vec[i].iov_len -= n;
                    vec[i].iov_base = (char *) vec[i].iov_base + n;
                    break;
                }
            }
        }
    }

    *len = written;

    return rv;
}

static apr_status_t send_begin_request(request_rec *r,
                                       const fcgi_provider_conf *conf,
                                       apr_socket_t *s, int role,
                                       apr_uint16_t request_id)
{
    struct iovec vec[2];
    ap_fcgi_header header;
    unsigned char farray[AP_FCGI_HEADER_LEN];
    ap_fcgi_begin_request_body brb;
    unsigned char abrb[AP_FCGI_HEADER_LEN];
    apr_size_t len;

    ap_fcgi_fill_in_header(&header, AP_FCGI_BEGIN_REQUEST, request_id,
                           sizeof(abrb), 0);
    ap_fcgi_fill_in_request_body(&brb, role, 0 /* *NOT* AP_FCGI_KEEP_CONN */);

    ap_fcgi_header_to_array(&header, farray);
    ap_fcgi_begin_request_body_to_array(&brb, abrb);

    vec[0].iov_base = (void *)farray;
    vec[0].iov_len = sizeof(farray);
    vec[1].iov_base = (void *)abrb;
    vec[1].iov_len = sizeof(abrb);

    return sendv_data(conf, r, s, vec, 2, &len);
}

static apr_status_t send_environment(apr_socket_t *s,
                                     const fcgi_provider_conf *conf,
                                     request_rec *r, apr_uint16_t request_id,
                                     apr_pool_t *temp_pool)
{
    const char *fn = "send_environment";
    const apr_array_header_t *envarr;
    const apr_table_entry_t *elts;
    struct iovec vec[2];
    ap_fcgi_header header;
    unsigned char farray[AP_FCGI_HEADER_LEN];
    char *body;
    apr_status_t rv;
    apr_size_t avail_len, len, required_len;
    int i, next_elem, starting_elem;

    envarr = apr_table_elts(r->subprocess_env);
    elts = (const apr_table_entry_t *) envarr->elts;

    if (APLOG_R_IS_LEVEL(r, APLOG_TRACE2)) {

        for (i = 0; i < envarr->nelts; ++i) {
            if (!elts[i].key) {
                continue;
            }
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                          "%s: '%s': '%s'",
                          fn, elts[i].key, 
                          !strcmp(elts[i].key, "REMOTE_PASSWD") ?
                              "XXXXXXXX" : elts[i].val);
        }
    }

    /* Send envvars over in as many FastCGI records as it takes, */
    next_elem = 0; /* starting with the first one */

    avail_len = 16 * 1024; /* our limit per record, which could have been up
                            * to AP_FCGI_MAX_CONTENT_LEN
                            */

    while (next_elem < envarr->nelts) {
        starting_elem = next_elem;
        required_len = ap_fcgi_encoded_env_len(r->subprocess_env,
                                               avail_len,
                                               &next_elem);

        if (!required_len) {
            if (next_elem < envarr->nelts) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              APLOGNO(02499) "couldn't encode envvar '%s' in %"
                              APR_SIZE_T_FMT " bytes",
                              elts[next_elem].key, avail_len);
                /* skip this envvar and continue */
                ++next_elem;
                continue;
            }
            /* only an unused element at the end of the array */
            break;
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      APLOGNO(02500) "required len for encoding envvars: %"
                      APR_SIZE_T_FMT ", %d/%d elems processed so far",
                      required_len, next_elem, envarr->nelts);

        body = apr_palloc(temp_pool, required_len);
        rv = ap_fcgi_encode_env(r, r->subprocess_env, body, required_len,
                                &starting_elem);
        /* we pre-compute, so we can't run out of space */
        ap_assert(rv == APR_SUCCESS);
        /* compute and encode must be in sync */
        ap_assert(starting_elem == next_elem);

        ap_fcgi_fill_in_header(&header, AP_FCGI_PARAMS, request_id,
                               (apr_uint16_t)required_len, 0);
        ap_fcgi_header_to_array(&header, farray);

        vec[0].iov_base = (void *)farray;
        vec[0].iov_len = sizeof(farray);
        vec[1].iov_base = body;
        vec[1].iov_len = required_len;

        rv = sendv_data(conf, r, s, vec, 2, &len);
        apr_pool_clear(temp_pool);

        if (rv) {
            return rv;
        }
    }

    /* Envvars sent, so say we're done */
    ap_fcgi_fill_in_header(&header, AP_FCGI_PARAMS, request_id, 0, 0);
    ap_fcgi_header_to_array(&header, farray);

    vec[0].iov_base = (void *)farray;
    vec[0].iov_len = sizeof(farray);

    return sendv_data(conf, r, s, vec, 1, &len);
}

/*
 * This header-state logic is from mod_proxy_fcgi.
 */
enum {
  HDR_STATE_READING_HEADERS,
  HDR_STATE_GOT_CR,
  HDR_STATE_GOT_CRLF,
  HDR_STATE_GOT_CRLFCR,
  HDR_STATE_GOT_LF,
  HDR_STATE_DONE_WITH_HEADERS
};

/* Try to find the end of the script headers in the response from the back
 * end fastcgi server. STATE holds the current header parsing state for this
 * request.
 *
 * Returns 0 if it can't find the end of the headers, and 1 if it found the
 * end of the headers. */
static int handle_headers(request_rec *r, int *state,
                          const char *readbuf, apr_size_t readlen)
{
    const char *itr = readbuf;

    while (readlen--) {
        if (*itr == '\r') {
            switch (*state) {
                case HDR_STATE_GOT_CRLF:
                    *state = HDR_STATE_GOT_CRLFCR;
                    break;

                default:
                    *state = HDR_STATE_GOT_CR;
                    break;
            }
        }
        else if (*itr == '\n') {
            switch (*state) {
                 case HDR_STATE_GOT_LF:
                     *state = HDR_STATE_DONE_WITH_HEADERS;
                     break;

                 case HDR_STATE_GOT_CR:
                     *state = HDR_STATE_GOT_CRLF;
                     break;

                 case HDR_STATE_GOT_CRLFCR:
                     *state = HDR_STATE_DONE_WITH_HEADERS;
                     break;

                 default:
                     *state = HDR_STATE_GOT_LF;
                     break;
            }
        }
        else {
            *state = HDR_STATE_READING_HEADERS;
        }

        if (*state == HDR_STATE_DONE_WITH_HEADERS)
            break;

        ++itr;
    }

    if (*state == HDR_STATE_DONE_WITH_HEADERS) {
        return 1;
    }

    return 0;
}

/*
 * handle_response() is based on mod_proxy_fcgi's dispatch()
 */
static apr_status_t handle_response(const fcgi_provider_conf *conf,
                                    request_rec *r, apr_socket_t *s,
                                    apr_pool_t *temp_pool,
                                    apr_uint16_t request_id,
                                    char *rspbuf,
                                    apr_size_t *rspbuflen)
{
    apr_bucket *b;
    apr_bucket_brigade *ob;
    apr_size_t orspbuflen = 0;
    apr_status_t rv = APR_SUCCESS;
    const char *fn = "handle_response";
    int header_state = HDR_STATE_READING_HEADERS;
    int seen_end_of_headers = 0, done = 0;

    if (rspbuflen) {
        orspbuflen = *rspbuflen;
        *rspbuflen = 0; /* unless we actually read something */
    }

    ob = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    while (!done && rv == APR_SUCCESS) { /* Keep reading FastCGI records until
                                          * we get AP_FCGI_END_REQUEST (done)
                                          * or an error occurs.
                                          */
        apr_size_t readbuflen;
        apr_uint16_t clen;
        apr_uint16_t rid;
        char readbuf[AP_IOBUFSIZE + 1];
        unsigned char farray[AP_FCGI_HEADER_LEN];
        unsigned char plen;
        unsigned char type;
        unsigned char version;

        rv = recv_data_full(conf, r, s, (char *)farray, AP_FCGI_HEADER_LEN);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          APLOGNO(02501) "%s: Error occurred before reading "
                          "entire header", fn);
            break;
        }

        ap_fcgi_header_fields_from_array(&version, &type, &rid, &clen, &plen,
                                         farray);

        if (version != AP_FCGI_VERSION_1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          APLOGNO(02502) "%s: Got bogus FastCGI header "
                          "version %d", fn, (int)version);
            rv = APR_EINVAL;
            break;
        }

        if (rid != request_id) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          APLOGNO(02503) "%s: Got bogus FastCGI header "
                          "request id %d, expected %d",
                          fn, rid, request_id);
            rv = APR_EINVAL;
            break;
        }

    recv_again: /* if we need to keep reading more of a record's content */

        if (clen > sizeof(readbuf) - 1) {
            readbuflen = sizeof(readbuf) - 1;
        } else {
            readbuflen = clen;
        }

        /*
         * Now get the actual content of the record.
         */
        if (readbuflen != 0) {
            rv = recv_data(conf, r, s, readbuf, &readbuflen);
            if (rv != APR_SUCCESS) {
                break;
            }
            readbuf[readbuflen] = '\0';
        }

        switch (type) {
        case AP_FCGI_STDOUT: /* Response headers and optional body */
            if (clen != 0) {
                b = apr_bucket_transient_create(readbuf,
                                                readbuflen,
                                                r->connection->bucket_alloc);

                APR_BRIGADE_INSERT_TAIL(ob, b);

                if (!seen_end_of_headers) {
                    int st = handle_headers(r, &header_state,
                                            readbuf, readbuflen);

                    if (st == 1) {
                        int status;

                        seen_end_of_headers = 1;

                        status =
                            ap_scan_script_header_err_brigade_ex(r, ob,
                                                                 NULL, 
                                                                 APLOG_MODULE_INDEX);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                      APLOGNO(02504) "%s: script header "
                                      "parsing -> %d/%d",
                                      fn, status, r->status);

                        if (rspbuf) { /* caller wants to see response body,
                                       * if any
                                       */
                            apr_status_t tmprv;

                            if (rspbuflen) {
                                *rspbuflen = orspbuflen;
                            }
                            tmprv = apr_brigade_flatten(ob, rspbuf, rspbuflen);
                            if (tmprv != APR_SUCCESS) {
                                /* should not occur for these bucket types;
                                 * does not indicate overflow
                                 */
                                ap_log_rerror(APLOG_MARK, APLOG_ERR, tmprv, r,
                                              APLOGNO(02505) "%s: error "
                                              "flattening response body",
                                              fn);
                            }
                        }

                        if (status != OK) {
                            r->status = status;
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                          APLOGNO(02506) "%s: Error parsing "
                                          "script headers from %s",
                                          fn, conf->backend);
                            rv = APR_EINVAL;
                            break;
                        }
                        apr_pool_clear(temp_pool);
                    }
                    else {
                        /* We're still looking for the end of the
                         * headers, so this part of the data will need
                         * to persist. */
                        apr_bucket_setaside(b, temp_pool);
                    }
                }

                /* If we didn't read all the data go back and get the
                 * rest of it. */
                if (clen > readbuflen) {
                    clen -= readbuflen;
                    goto recv_again;
                }
            }
            break;

        case AP_FCGI_STDERR: /* Text to log */
            if (clen) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              APLOGNO(02507) "%s: Logged from %s: '%s'",
                              fn, conf->backend, readbuf);
            }

            if (clen > readbuflen) {
                clen -= readbuflen;
                goto recv_again; /* continue reading this record */
            }
            break;

        case AP_FCGI_END_REQUEST:
            done = 1;
            break;

        default:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          APLOGNO(02508) "%s: Got bogus FastCGI record type "
                          "%d", fn, type);
            break;
        }
        /* Leave on above switch's inner error. */
        if (rv != APR_SUCCESS) {
            break;
        }

        /*
         * Read/discard any trailing padding.
         */
        if (plen) {
            rv = recv_data_full(conf, r, s, readbuf, plen);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              APLOGNO(02509) "%s: Error occurred reading "
                              "padding",
                              fn);
                break;
            }
        }
    }

    apr_brigade_cleanup(ob);

    if (rv == APR_SUCCESS && !seen_end_of_headers) {
        rv = APR_EINVAL;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      APLOGNO(02510) "%s: Never reached end of script headers",
                      fn);
    }

    return rv;
}

/* almost from mod_fcgid */
static int mod_fcgid_modify_auth_header(void *vars,
                                        const char *key, const char *val)
{
    /* When the application gives a 200 response, the server ignores response
       headers whose names aren't prefixed with Variable- prefix, and ignores
       any response content */
    if (strncasecmp(key, "Variable-", 9) == 0)
        apr_table_setn(vars, key, val);
    return 1;
}

static int fix_auth_header(void *vr, const char *key, const char *val)
{
    request_rec *r = vr;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "moving %s->%s", key, val);
    apr_table_unset(r->err_headers_out, key);
    apr_table_setn(r->subprocess_env, key + 9, val);
    return 1;
}

static void req_rsp(request_rec *r, const fcgi_provider_conf *conf,
                    const char *password, const char *apache_role,
                    char *rspbuf, apr_size_t *rspbuflen)
{
    const char *fn = "req_rsp";
    apr_pool_t *temp_pool;
    apr_size_t orspbuflen = 0;
    apr_socket_t *s;
    apr_status_t rv;
    apr_table_t *saved_subprocess_env = 
      apr_table_copy(r->pool, r->subprocess_env);

    if (rspbuflen) {
        orspbuflen = *rspbuflen;
        *rspbuflen = 0; /* unless we actually read something */
    }

    apr_pool_create(&temp_pool, r->pool);

    setupenv(r, password, apache_role);

    rv = connect_to_peer(&s, r, conf->backend_addrs,
                         conf->backend, FCGI_IO_TIMEOUT);
    if (rv == APR_SUCCESS) {
        apr_uint16_t request_id = 1;

        rv = send_begin_request(r, conf, s, AP_FCGI_AUTHORIZER, request_id);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          APLOGNO(02511) "%s: Failed writing request to %s",
                          fn, conf->backend);
        }

        if (rv == APR_SUCCESS) {
            rv = send_environment(s, conf, r, request_id, temp_pool);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              APLOGNO(02512) "%s: Failed writing environment "
                              "to %s", fn, conf->backend);
            }
        }

        /* The responder owns the request body, not the authorizer.
         * Don't even send an empty AP_FCGI_STDIN block.  libfcgi doesn't care,
         * but it wasn't sent to authorizers by mod_fastcgi or mod_fcgi and
         * may be unhandled by the app.  Additionally, the FastCGI spec does
         * not mention FCGI_STDIN in the Authorizer description, though it
         * does describe FCGI_STDIN elsewhere in more general terms than
         * simply a wrapper for the client's request body.
         */

        if (rv == APR_SUCCESS) {
            if (rspbuflen) {
                *rspbuflen = orspbuflen;
            }
            rv = handle_response(conf, r, s, temp_pool, request_id, rspbuf,
                                 rspbuflen);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              APLOGNO(02514) "%s: Failed handling response "
                              "from %s", fn, conf->backend);
            }
        }

        apr_socket_close(s);
    }

    if (rv != APR_SUCCESS) {
        /* some sort of mechanical problem */
        r->status = HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      APLOGNO(02515) "%s: Received HTTP status %d",
                      fn, r->status);
    }

    r->subprocess_env = saved_subprocess_env;

    if (r->status == HTTP_OK) {
        /* An Authorizer application's 200 response may include headers
         * whose names are prefixed with Variable-, and they should be
         * available to subsequent phases via subprocess_env (and yanked
         * from the client response).
         */
        apr_table_t *vars = apr_table_make(temp_pool, /* not used to allocate
                                                       * any values that end up
                                                       * in r->(anything)
                                                       */
                                           10);
        apr_table_do(mod_fcgid_modify_auth_header, vars,
                     r->err_headers_out, NULL);
        apr_table_do(fix_auth_header, r, vars, NULL);
    }

    apr_pool_destroy(temp_pool);
}

static int fcgi_check_authn(request_rec *r)
{
    const char *fn = "fcgi_check_authn";
    fcgi_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                &authnz_fcgi_module);
    const char *password = NULL;
    const fcgi_provider_conf *conf;
    const char *prov;
    const char *auth_type;
    char rspbuf[NON200_RESPONSE_BUF_LEN + 1]; /* extra byte for '\0' */
    apr_size_t rspbuflen = sizeof rspbuf - 1;
    int res;

    prov = dconf && dconf->name ? dconf->name : NULL;

    if (!prov || !strcasecmp(prov, "None")) {
        return DECLINED;
    }

    auth_type = ap_auth_type(r);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  APLOGNO(02516) "%s, prov %s, authoritative %s, "
                  "require-basic %s, user expr? %s type %s",
                  fn, prov,
                  dconf->authoritative ? "yes" : "no",
                  dconf->require_basic_auth ? "yes" : "no",
                  dconf->user_expr ? "yes" : "no",
                  auth_type);

    if (auth_type && !strcasecmp(auth_type, "Basic")) {
        if ((res = ap_get_basic_auth_pw(r, &password))) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          APLOGNO(02517) "%s: couldn't retrieve basic auth "
                          "password", fn);
            if (dconf->require_basic_auth) {
                return res;
            }
            password = NULL;
        }
    }

    conf = apr_hash_get(fcgi_authn_providers, prov, APR_HASH_KEY_STRING);
    if (!conf) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      APLOGNO(02518) "%s: can't find config for provider %s",
                      fn, prov);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (APLOGrdebug(r)) {
        log_provider_info(conf, r);
    }

    req_rsp(r, conf, password, AP_FCGI_APACHE_ROLE_AUTHENTICATOR_STR,
            rspbuf, &rspbuflen);

    if (r->status == HTTP_OK) {
        if (dconf->user_expr) {
            const char *err;
            const char *user = ap_expr_str_exec(r, dconf->user_expr,
                                                &err);
            if (user && strlen(user)) {
                r->user = apr_pstrdup(r->pool, user);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              APLOGNO(02519) "%s: Setting user to '%s'",
                              fn, r->user);
            }
            else if (user && dconf->default_user) {
                r->user = apr_pstrdup(r->pool, dconf->default_user);
            }
            else if (user) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              APLOGNO(02520) "%s: Failure extracting user "
                              "after calling authorizer: user expression "
                              "yielded empty string (variable not set?)",
                              fn);
                r->status = HTTP_INTERNAL_SERVER_ERROR;
            }
            else {
                /* unexpected error, not even an empty string was returned */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              APLOGNO(02521) "%s: Failure extracting user "
                              "after calling authorizer: %s",
                              fn, err);
                r->status = HTTP_INTERNAL_SERVER_ERROR;
            }
        }
        if (conf->is_authz) {
            /* combined authn/authz phase, so app won't be invoked for authz
             *
             * Remember that the request was successfully authorized by this
             * provider.
             */
            fcgi_request_notes *rnotes = apr_palloc(r->pool, sizeof(*rnotes));
            rnotes->successful_authnz_provider = conf->name;
            ap_set_module_config(r->request_config, &authnz_fcgi_module,
                                 rnotes);
        }
    }
    else {
        /* From the spec:
         *   For Authorizer response status values other than "200" (OK), the 
         *   Web server denies access and sends the response status, headers,
         *   and content back to the HTTP client.
         * But:
         *   This only makes sense if this authorizer is authoritative.
         */
        if (rspbuflen > 0 && !dconf->authoritative) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          APLOGNO(02522) "%s: Ignoring response body from non-"
                          "authoritative authorizer", fn);
        }
        else if (rspbuflen > 0) {
            if (rspbuflen == sizeof rspbuf - 1) {
                /* apr_brigade_flatten() interface :( */
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              APLOGNO(02523) "%s: possible overflow handling "
                              "response body", fn);
            }
            rspbuf[rspbuflen] = '\0'; /* we reserved an extra byte for '\0' */
            ap_custom_response(r, r->status, rspbuf); /* API makes a copy */
        }
    }

    return r->status == HTTP_OK ? 
        OK : dconf->authoritative ? r->status : DECLINED;
}

static authn_status fcgi_check_password(request_rec *r, const char *user,
                                        const char *password)
{
    const char *fn = "fcgi_check_password";
    const char *prov = apr_table_get(r->notes, AUTHN_PROVIDER_NAME_NOTE);
    const fcgi_provider_conf *conf;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  APLOGNO(02524) "%s(%s, XXX): provider %s",
                  fn, user, prov);

    if (!prov) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      APLOGNO(02525) "%s: provider note isn't set", fn);
        return AUTH_GENERAL_ERROR;
    }

    conf = apr_hash_get(fcgi_authn_providers, prov, APR_HASH_KEY_STRING);
    if (!conf) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      APLOGNO(02526) "%s: can't find config for provider %s",
                      fn, prov);
        return AUTH_GENERAL_ERROR;
    }

    if (APLOGrdebug(r)) {
        log_provider_info(conf, r);
    }

    req_rsp(r, conf, password, 
            /* combined authn and authz: FCGI_APACHE_ROLE not set */
            conf->is_authz ? NULL : AP_FCGI_APACHE_ROLE_AUTHENTICATOR_STR,
            NULL, NULL);

    if (r->status == HTTP_OK) {
        if (conf->is_authz) {
            /* combined authn/authz phase, so app won't be invoked for authz
             *
             * Remember that the request was successfully authorized by this
             * provider.
             */
            fcgi_request_notes *rnotes = apr_palloc(r->pool, sizeof(*rnotes));
            rnotes->successful_authnz_provider = conf->name;
            ap_set_module_config(r->request_config, &authnz_fcgi_module,
                                 rnotes);
        }
        return AUTH_GRANTED;
    }
    else if (r->status == HTTP_INTERNAL_SERVER_ERROR) {
        return AUTH_GENERAL_ERROR;
    }
    else {
        return AUTH_DENIED;
    }
}

static const authn_provider fcgi_authn_provider = {
    &fcgi_check_password,
    NULL /* get-realm-hash not supported */
};

static authz_status fcgi_authz_check(request_rec *r,
                                     const char *require_line,
                                     const void *parsed_require_line)
{
    const char *fn = "fcgi_authz_check";
    const char *prov = apr_table_get(r->notes, AUTHZ_PROVIDER_NAME_NOTE);
    const fcgi_provider_conf *conf;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  APLOGNO(02527) "%s(%s)", fn, require_line);

    if (!prov) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      APLOGNO(02528) "%s: provider note isn't set", fn);
        return AUTHZ_GENERAL_ERROR;
    }

    conf = apr_hash_get(fcgi_authz_providers, prov, APR_HASH_KEY_STRING);
    if (!conf) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      APLOGNO(02529) "%s: can't find config for provider %s",
                      fn, prov);
        return AUTHZ_GENERAL_ERROR;
    }

    if (APLOGrdebug(r)) {
        log_provider_info(conf, r);
    }

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    if (conf->is_authn) {
        /* combined authn/authz phase, so app won't be invoked for authz
         *
         * If the provider already successfully authorized this request, 
         * success.
         */
        fcgi_request_notes *rnotes = ap_get_module_config(r->request_config,
                                                        &authnz_fcgi_module);
        if (rnotes
            && rnotes->successful_authnz_provider
            && !strcmp(rnotes->successful_authnz_provider, conf->name)) {
            return AUTHZ_GRANTED;
        }
        else {
            return AUTHZ_DENIED;
        }
    }
    else {
        req_rsp(r, conf, NULL, AP_FCGI_APACHE_ROLE_AUTHORIZER_STR, NULL, NULL);

        if (r->status == HTTP_OK) {
            return AUTHZ_GRANTED;
        }
        else if (r->status == HTTP_INTERNAL_SERVER_ERROR) {
            return AUTHZ_GENERAL_ERROR;
        }
        else {
            return AUTHZ_DENIED;
        }
    }
}

static const char *fcgi_authz_parse(cmd_parms *cmd, const char *require_line,
                                    const void **parsed_require_line)
{
    /* Allowed form: Require [not] registered-provider-name<EOS>
     */
    if (strcmp(require_line, "")) {
        return "mod_authnz_fcgi doesn't support restrictions on providers "
               "(i.e., multiple require args)";
    }

    return NULL;
}

static const authz_provider fcgi_authz_provider = {
    &fcgi_authz_check,
    &fcgi_authz_parse,
};

static const char *fcgi_check_authn_provider(cmd_parms *cmd,
                                        void *d,
                                        int argc,
                                        char *const argv[])
{
    const char *dname = "AuthnzFcgiCheckAuthnProvider";
    fcgi_dir_conf *dc = d;
    int ca = 0;

    if (ca >= argc) {
        return apr_pstrcat(cmd->pool, dname, ": No provider given", NULL);
    }

    dc->name = argv[ca];
    ca++;

    if (!strcasecmp(dc->name, "None")) {
        if (ca < argc) {
            return "Options aren't supported with \"None\"";
        }
    }

    while (ca < argc) {
        const char *var = argv[ca], *val;
        int badarg = 0;

        ca++;

        /* at present, everything needs an argument */
        if (ca >= argc) {
            return apr_pstrcat(cmd->pool, dname, ": ", var,
                               "needs an argument", NULL);
        }

        val = argv[ca];
        ca++;

        if (!strcasecmp(var, "Authoritative")) {
            if (!strcasecmp(val, "On")) {
                dc->authoritative = 1;
            }
            else if (!strcasecmp(val, "Off")) {
                dc->authoritative = 0;
            }
            else {
                badarg = 1;
            }
        }
        else if (!strcasecmp(var, "DefaultUser")) {
            dc->default_user = val;
        }
        else if (!strcasecmp(var, "RequireBasicAuth")) {
            if (!strcasecmp(val, "On")) {
                dc->require_basic_auth = 1;
            }
            else if (!strcasecmp(val, "Off")) {
                dc->require_basic_auth = 0;
            }
            else {
                badarg = 1;
            }
        }
        else if (!strcasecmp(var, "UserExpr")) {
            const char *err;
            int flags = AP_EXPR_FLAG_DONT_VARY | AP_EXPR_FLAG_RESTRICTED
                | AP_EXPR_FLAG_STRING_RESULT;

            dc->user_expr = ap_expr_parse_cmd(cmd, val,
                                              flags, &err, NULL);
            if (err) {
                return apr_psprintf(cmd->pool, "%s: Error parsing '%s': '%s'",
                                    dname, val, err);
            }
        }
        else {
            return apr_pstrcat(cmd->pool, dname, ": Unexpected option '",
                               var, "'", NULL);
        }
        if (badarg) {
            return apr_pstrcat(cmd->pool, dname, ": Bad argument '",
                               val, "' to option '", var, "'", NULL);
        }
    }

    return NULL;
}

/* AuthnzFcgiAuthDefineProvider {authn|authz|authnz} provider-name \
 *   fcgi://backendhost:backendport/
 */
static const char *fcgi_define_provider(cmd_parms *cmd,
                                        void *d,
                                        int argc,
                                        char *const argv[])
{
    const char *dname = "AuthnzFcgiDefineProvider";
    ap_rxplus_t *fcgi_backend_regex;
    apr_status_t rv;
    char *host;
    const char *err, *stype;
    fcgi_provider_conf *conf = apr_pcalloc(cmd->pool, sizeof(*conf));
    int ca = 0, rc, port;

    fcgi_backend_regex = ap_rxplus_compile(cmd->pool, FCGI_BACKEND_REGEX_STR);
    if (!fcgi_backend_regex) {
        return apr_psprintf(cmd->pool,
                            "%s: failed to compile regexec '%s'",
                            dname, FCGI_BACKEND_REGEX_STR);
    }

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
        return err;

    if (ca >= argc) {
        return apr_pstrcat(cmd->pool, dname, ": No type given", NULL);
    }

    stype = argv[ca];
    ca++;

    if (!strcasecmp(stype, "authn")) {
        conf->is_authn = 1;
    }
    else if (!strcasecmp(stype, "authz")) {
        conf->is_authz = 1;
    }
    else if (!strcasecmp(stype, "authnz")) {
        conf->is_authn = conf->is_authz = 1;
    }
    else {
        return apr_pstrcat(cmd->pool,
                           dname,
                           ": Invalid provider type ",
                           stype,
                           NULL);
    }

    if (ca >= argc) {
        return apr_pstrcat(cmd->pool, dname, ": No provider name given", NULL);
    }
    conf->name = argv[ca];
    ca++;

    if (ca >= argc) {
        return apr_pstrcat(cmd->pool, dname, ": No backend-address given",
                           NULL);
    }

    rc = ap_rxplus_exec(cmd->pool, fcgi_backend_regex, argv[ca], NULL);
    if (!rc || ap_rxplus_nmatch(fcgi_backend_regex) != 3) {
        return apr_pstrcat(cmd->pool,
                           dname, ": backend-address '",
                           argv[ca],
                           "' has invalid form",
                           NULL);
    }

    host = ap_rxplus_pmatch(cmd->pool, fcgi_backend_regex, 1);
    if (host[0] == '[' && host[strlen(host) - 1] == ']') {
        host += 1;
        host[strlen(host) - 1] = '\0';
    }

    port = atoi(ap_rxplus_pmatch(cmd->pool, fcgi_backend_regex, 2));
    if (port > 65535) {
        return apr_pstrcat(cmd->pool,
                           dname, ": backend-address '",
                           argv[ca],
                           "' has invalid port",
                           NULL);
    }

    conf->backend = argv[ca];
    conf->host = host;
    conf->port = port;
    ca++;

    rv = apr_sockaddr_info_get(&conf->backend_addrs, conf->host,
                               APR_UNSPEC, conf->port, 0, cmd->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, rv, NULL,
                     APLOGNO(02530) "Address %s could not be resolved",
                     conf->backend);
        return apr_pstrcat(cmd->pool,
                           dname,
                           ": Error resolving backend address",
                           NULL);
    }

    if (ca != argc) {
        return apr_pstrcat(cmd->pool,
                           dname,
                           ": Unexpected parameter ",
                           argv[ca],
                           NULL);
    }

    if (conf->is_authn) {
        apr_hash_set(fcgi_authn_providers, conf->name, APR_HASH_KEY_STRING,
                     conf);
        ap_register_auth_provider(cmd->pool, AUTHN_PROVIDER_GROUP,
                                  conf->name,
                                  AUTHN_PROVIDER_VERSION,
                                  &fcgi_authn_provider,
                                  AP_AUTH_INTERNAL_PER_CONF);
    }

    if (conf->is_authz) {
        apr_hash_set(fcgi_authz_providers, conf->name, APR_HASH_KEY_STRING,
                     conf);
        ap_register_auth_provider(cmd->pool, AUTHZ_PROVIDER_GROUP,
                                  conf->name,
                                  AUTHZ_PROVIDER_VERSION,
                                  &fcgi_authz_provider,
                                  AP_AUTH_INTERNAL_PER_CONF);
    }

    return NULL;
}

static const command_rec fcgi_cmds[] = {
    AP_INIT_TAKE_ARGV("AuthnzFcgiDefineProvider", 
                      fcgi_define_provider,
                      NULL,
                      RSRC_CONF,
                      "Define a FastCGI authn and/or authz provider"),

    AP_INIT_TAKE_ARGV("AuthnzFcgiCheckAuthnProvider",
                      fcgi_check_authn_provider,
                      NULL,
                      OR_FILEINFO,
                      "Enable/disable a FastCGI authorizer to handle "
                      "check_authn phase"),

    {NULL}
};

static int fcgi_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                           apr_pool_t *ptemp)
{
    fcgi_authn_providers = apr_hash_make(pconf);
    fcgi_authz_providers = apr_hash_make(pconf);

    return OK;
}

static void fcgi_register_hooks(apr_pool_t *p)
{
    static const char * const auth_basic_runs_after_me[] = 
        {"mod_auth_basic.c", NULL}; /* to allow for custom response */

    ap_hook_pre_config(fcgi_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_authn(fcgi_check_authn, NULL, auth_basic_runs_after_me,
                        APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
}

static void *create_dir_conf(apr_pool_t *p, char *dummy)
{
    fcgi_dir_conf *dconf = apr_pcalloc(p, sizeof(fcgi_dir_conf));

    dconf->authoritative = 1;
    return dconf;
}

static void *merge_dir_conf(apr_pool_t *p, void *basev, void *overridesv)
{
    fcgi_dir_conf *a = (fcgi_dir_conf *)apr_pcalloc(p, sizeof(*a));
    fcgi_dir_conf *base = (fcgi_dir_conf *)basev, 
        *over = (fcgi_dir_conf *)overridesv;

    /* currently we just have a single directive applicable to a 
     * directory, so if it is set then grab all fields from fcgi_dir_conf
     */
    if (over->name) {
        memcpy(a, over, sizeof(*a));
    }
    else {
        memcpy(a, base, sizeof(*a));
    }
    
    return a;
}

AP_DECLARE_MODULE(authnz_fcgi) =
{
    STANDARD20_MODULE_STUFF,
    create_dir_conf,                 /* dir config creater */
    merge_dir_conf,                  /* dir merger */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    fcgi_cmds,                       /* command apr_table_t */
    fcgi_register_hooks              /* register hooks */
};
