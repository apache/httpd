/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#include "apr_strings.h"
#include "apr_thread_proc.h"    /* for RLIMIT stuff */

#define APR_WANT_STRFUNC
#include "apr_want.h"

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_protocol.h"	/* For index_of_response().  Grump. */
#include "http_request.h"

#include "util_filter.h"
#include "util_ebcdic.h"
#include "ap_mpm.h"
#include "scoreboard.h"

#include "mod_core.h"

/* Handles for core filters */
AP_DECLARE_DATA ap_filter_rec_t *ap_http_input_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_http_header_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_chunk_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_byterange_filter_handle;

static const char *set_keep_alive_timeout(cmd_parms *cmd, void *dummy,
					  const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    cmd->server->keep_alive_timeout = apr_time_from_sec(atoi(arg));
    return NULL;
}

static const char *set_keep_alive(cmd_parms *cmd, void *dummy,
				  const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    /* We've changed it to On/Off, but used to use numbers
     * so we accept anything but "Off" or "0" as "On"
     */
    if (!strcasecmp(arg, "off") || !strcmp(arg, "0")) {
	cmd->server->keep_alive = 0;
    }
    else {
	cmd->server->keep_alive = 1;
    }
    return NULL;
}

static const char *set_keep_alive_max(cmd_parms *cmd, void *dummy,
				      const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    cmd->server->keep_alive_max = atoi(arg);
    return NULL;
}

static const command_rec http_cmds[] = {
    AP_INIT_TAKE1("KeepAliveTimeout", set_keep_alive_timeout, NULL, RSRC_CONF,
                  "Keep-Alive timeout duration (sec)"),
    AP_INIT_TAKE1("MaxKeepAliveRequests", set_keep_alive_max, NULL, RSRC_CONF,
     "Maximum number of Keep-Alive requests per connection, or 0 for infinite"),
    AP_INIT_TAKE1("KeepAlive", set_keep_alive, NULL, RSRC_CONF,
                  "Whether persistent connections should be On or Off"),
    { NULL }
};

/*
 * HTTP/1.1 chunked transfer encoding filter.
 */
static apr_status_t chunk_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
#define ASCII_CRLF  "\015\012"
#define ASCII_ZERO  "\060"
    conn_rec *c = f->r->connection;
    apr_bucket_brigade *more;
    apr_bucket *e;
    apr_status_t rv;

    for (more = NULL; b; b = more, more = NULL) {
        apr_off_t bytes = 0;
        apr_bucket *eos = NULL;
        apr_bucket *flush = NULL;
        /* XXX: chunk_hdr must remain at this scope since it is used in a 
         *      transient bucket.
         */
        char chunk_hdr[20]; /* enough space for the snprintf below */

        APR_BRIGADE_FOREACH(e, b) {
            if (APR_BUCKET_IS_EOS(e)) {
                /* there shouldn't be anything after the eos */
                eos = e;
                break;
            }
            if (APR_BUCKET_IS_FLUSH(e)) {
                flush = e;
            }
            else if (e->length == (apr_size_t)-1) {
                /* unknown amount of data (e.g. a pipe) */
                const char *data;
                apr_size_t len;

                rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
                if (rv != APR_SUCCESS) {
                    return rv;
                }
                if (len > 0) {
                    /*
                     * There may be a new next bucket representing the
                     * rest of the data stream on which a read() may
                     * block so we pass down what we have so far.
                     */
                    bytes += len;
                    more = apr_brigade_split(b, APR_BUCKET_NEXT(e));
                    break;
                }
                else {
                    /* If there was nothing in this bucket then we can
                     * safely move on to the next one without pausing
                     * to pass down what we have counted up so far.
                     */
                    continue;
                }
            }
            else {
                bytes += e->length;
            }
        }

        /*
         * XXX: if there aren't very many bytes at this point it may
         * be a good idea to set them aside and return for more,
         * unless we haven't finished counting this brigade yet.
         */
        /* if there are content bytes, then wrap them in a chunk */
        if (bytes > 0) {
            apr_size_t hdr_len;
            /*
             * Insert the chunk header, specifying the number of bytes in
             * the chunk.
             */
            /* XXX might be nice to have APR_OFF_T_FMT_HEX */
            hdr_len = apr_snprintf(chunk_hdr, sizeof(chunk_hdr),
                                   "%qx" CRLF, (apr_uint64_t)bytes);
            ap_xlate_proto_to_ascii(chunk_hdr, hdr_len);
            e = apr_bucket_transient_create(chunk_hdr, hdr_len,
                                            c->bucket_alloc);
            APR_BRIGADE_INSERT_HEAD(b, e);

            /*
             * Insert the end-of-chunk CRLF before an EOS or
             * FLUSH bucket, or appended to the brigade
             */
            e = apr_bucket_immortal_create(ASCII_CRLF, 2, c->bucket_alloc);
            if (eos != NULL) {
                APR_BUCKET_INSERT_BEFORE(eos, e);
            }
            else if (flush != NULL) {
                APR_BUCKET_INSERT_BEFORE(flush, e);
            }
            else {
                APR_BRIGADE_INSERT_TAIL(b, e);
            }
        }

        /* RFC 2616, Section 3.6.1
         *
         * If there is an EOS bucket, then prefix it with:
         *   1) the last-chunk marker ("0" CRLF)
         *   2) the trailer
         *   3) the end-of-chunked body CRLF
         *
         * If there is no EOS bucket, then do nothing.
         *
         * XXX: it would be nice to combine this with the end-of-chunk
         * marker above, but this is a bit more straight-forward for
         * now.
         */
        if (eos != NULL) {
            /* XXX: (2) trailers ... does not yet exist */
            e = apr_bucket_immortal_create(ASCII_ZERO ASCII_CRLF
                                           /* <trailers> */
                                           ASCII_CRLF, 5, c->bucket_alloc);
            APR_BUCKET_INSERT_BEFORE(eos, e);
        }

        /* pass the brigade to the next filter. */
        rv = ap_pass_brigade(f->next, b);
        if (rv != APR_SUCCESS || eos != NULL) {
            return rv;
        }
    }
    return APR_SUCCESS;
}

static const char *http_method(const request_rec *r)
    { return "http"; }

static apr_port_t http_port(const request_rec *r)
    { return DEFAULT_HTTP_PORT; }

static int ap_process_http_connection(conn_rec *c)
{
    request_rec *r;
    int csd_set = 0;
    apr_socket_t *csd = NULL;

    /*
     * Read and process each request found on our connection
     * until no requests are left or we decide to close.
     */
 
    ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);
    while ((r = ap_read_request(c)) != NULL) {

        c->keepalive = AP_CONN_UNKNOWN;
        /* process the request if it was read without error */
 
        ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);
        if (r->status == HTTP_OK)
            ap_process_request(r);
 
        if (ap_extended_status)
            ap_increment_counts(c->sbh, r);
 
        if (c->keepalive != AP_CONN_KEEPALIVE || c->aborted)
            break;
 
        ap_update_child_status(c->sbh, SERVER_BUSY_KEEPALIVE, r);
        apr_pool_destroy(r->pool);
 
        if (ap_graceful_stop_signalled())
            break;
        /* Go straight to select() to wait for the next request */
        if (!csd_set) {
            csd = ap_get_module_config(c->conn_config, &core_module);
            csd_set = 1;
        }
        apr_socket_opt_set(csd, APR_INCOMPLETE_READ, 1);
    }
 
    return OK;
}

static int http_create_request(request_rec *r)
{
    if (!r->main && !r->prev) {
        ap_add_output_filter_handle(ap_byterange_filter_handle,
                                    NULL, r, r->connection);
        ap_add_output_filter_handle(ap_content_length_filter_handle,
                                    NULL, r, r->connection);
        ap_add_output_filter_handle(ap_http_header_filter_handle,
                                    NULL, r, r->connection);
    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_process_connection(ap_process_http_connection,NULL,NULL,
			       APR_HOOK_REALLY_LAST);
    ap_hook_map_to_storage(ap_send_http_trace,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_http_method(http_method,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_default_port(http_port,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_create_request(http_create_request, NULL, NULL, APR_HOOK_REALLY_LAST);
    ap_http_input_filter_handle =
        ap_register_input_filter("HTTP_IN", ap_http_filter,
                                 NULL, AP_FTYPE_PROTOCOL);
    ap_http_header_filter_handle =
        ap_register_output_filter("HTTP_HEADER", ap_http_header_filter, 
                                  NULL, AP_FTYPE_PROTOCOL);
    ap_chunk_filter_handle =
        ap_register_output_filter("CHUNK", chunk_filter,
                                  NULL, AP_FTYPE_TRANSCODE);
    ap_byterange_filter_handle =
        ap_register_output_filter("BYTERANGE", ap_byterange_filter,
                                  NULL, AP_FTYPE_PROTOCOL);
    ap_method_registry_init(p);
}

module AP_MODULE_DECLARE_DATA http_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    http_cmds,			/* command apr_table_t */
    register_hooks		/* register hooks */
};
