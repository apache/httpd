/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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
#include "apr_lib.h"
#include "apr_optional.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_connection.h"
#include "http_protocol.h"	/* For index_of_response().  Grump. */
#include "http_request.h"

#include "util_filter.h"
#include "util_ebcdic.h"
#include "ap_mpm.h"
#include "scoreboard.h"

#include "mod_core.h"
#include "../loggers/mod_log_config.h"

static const char *set_keep_alive_timeout(cmd_parms *cmd, void *dummy,
					  const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    cmd->server->keep_alive_timeout = atoi(arg);
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
    apr_bucket_brigade *more = NULL;
    apr_bucket *e;
    apr_status_t rv;

    for (more = NULL; b; b = more, more = NULL) {
	apr_off_t bytes = 0;
        apr_bucket *eos = NULL;
        char chunk_hdr[20]; /* enough space for the snprintf below */

	APR_BRIGADE_FOREACH(e, b) {
	    if (APR_BUCKET_IS_EOS(e)) {
		/* there shouldn't be anything after the eos */
		eos = e;
		break;
	    }
	    else if (e->length == -1) {
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
            e = apr_bucket_transient_create(chunk_hdr, hdr_len);
            APR_BRIGADE_INSERT_HEAD(b, e);

            /*
             * Insert the end-of-chunk CRLF before the EOS bucket, or
             * appended to the brigade
             */
            e = apr_bucket_immortal_create(ASCII_CRLF, 2);
            if (eos != NULL) {
                APR_BUCKET_INSERT_BEFORE(eos, e);
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
            e = apr_bucket_immortal_create(ASCII_ZERO ASCII_CRLF /* <trailers> */ ASCII_CRLF, 5);
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

static unsigned short http_port(const request_rec *r)
    { return DEFAULT_HTTP_PORT; }

static int ap_pre_http_connection(conn_rec *c)
{
    ap_add_input_filter("HTTP_IN", NULL, NULL, c);
    ap_add_input_filter("CORE_IN", NULL, NULL, c);
    ap_add_output_filter("CORE", NULL, NULL, c);
    return OK;
}
 
static int ap_process_http_connection(conn_rec *c)
{
    request_rec *r;
 
    /*
     * Read and process each request found on our connection
     * until no requests are left or we decide to close.
     */
 
    ap_update_child_status(AP_CHILD_THREAD_FROM_ID(c->id), SERVER_BUSY_READ, NULL);
    while ((r = ap_read_request(c)) != NULL) {
 
        /* process the request if it was read without error */
 
        ap_update_child_status(AP_CHILD_THREAD_FROM_ID(c->id), SERVER_BUSY_WRITE, NULL);
        if (r->status == HTTP_OK)
            ap_process_request(r);
 
        if (ap_extended_status)
            ap_increment_counts(AP_CHILD_THREAD_FROM_ID(c->id), r);
 
        if (!c->keepalive || c->aborted)
            break;
 
        ap_update_child_status(AP_CHILD_THREAD_FROM_ID(c->id), SERVER_BUSY_KEEPALIVE, NULL);
        apr_pool_destroy(r->pool);
 
        if (ap_graceful_stop_signalled())
            break;
    }
 
    return OK;
}

static int read_request_line(request_rec *r)
{
    char l[DEFAULT_LIMIT_REQUEST_LINE + 2]; /* getline's two extra for \n\0 */
    const char *ll = l;
    const char *uri;
    const char *pro;
 
    int major = 1, minor = 0;   /* Assume HTTP/1.0 if non-"HTTP" protocol */
    int len;
 
    /* Read past empty lines until we get a real request line,
     * a read error, the connection closes (EOF), or we timeout.
     *
     * We skip empty lines because browsers have to tack a CRLF on to the end
     * of POSTs to support old CERN webservers.  But note that we may not
     * have flushed any previous response completely to the client yet.
     * We delay the flush as long as possible so that we can improve
     * performance for clients that are pipelining requests.  If a request
     * is pipelined then we won't block during the (implicit) read() below.
     * If the requests aren't pipelined, then the client is still waiting
     * for the final buffer flush from us, and we will block in the implicit
     * read().  B_SAFEREAD ensures that the BUFF layer flushes if it will
     * have to block during a read.
     */
 
    while ((len = ap_getline(l, sizeof(l), r, 0)) <= 0) {
        if (len < 0) {             /* includes EOF */
            /* this is a hack to make sure that request time is set,
             * it's not perfect, but it's better than nothing
             */
            r->request_time = apr_time_now();
            return 0;
        }
    }
    /* we've probably got something to do, ignore graceful restart requests */
 
    /* XXX - sigwait doesn't work if the signal has been SIG_IGNed (under
     * linux 2.0 w/ glibc 2.0, anyway), and this step isn't necessary when
     * we're running a sigwait thread anyway. If/when unthreaded mode is
     * put back in, we should make sure to ignore this signal iff a sigwait
     * thread isn't used. - mvsk
 
#ifdef SIGWINCH
    apr_signal(SIGWINCH, SIG_IGN);
#endif
    */
 
    r->request_time = apr_time_now();
    r->the_request = apr_pstrdup(r->pool, l);
    r->method = ap_getword_white(r->pool, &ll);
 
#if 0
/* XXX If we want to keep track of the Method, the protocol module should do
 * it.  That support isn't in the scoreboard yet.  Hopefully next week
 * sometime.   rbb */
    ap_update_connection_status(AP_CHILD_THREAD_FROM_ID(conn->id), "Method", r->method);
#endif
    uri = ap_getword_white(r->pool, &ll);
 
    /* Provide quick information about the request method as soon as known */
 
    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_GET && r->method[0] == 'H') {
        r->header_only = 1;
    }
 
    ap_parse_uri(r, uri);
 
    /* ap_getline returns (size of max buffer - 1) if it fills up the
     * buffer before finding the end-of-line.  This is only going to
     * happen if it exceeds the configured limit for a request-line.
     */
    if (len > r->server->limit_req_line) {
        r->status    = HTTP_REQUEST_URI_TOO_LARGE;
        r->proto_num = HTTP_VERSION(1,0);
        r->protocol  = apr_pstrdup(r->pool, "HTTP/1.0");
        return 0;
    }
 
    if (ll[0]) {
        r->assbackwards = 0;
        pro = ll;
        len = strlen(ll);
    } else {
        r->assbackwards = 1;
        pro = "HTTP/0.9";
        len = 8;
    }
    r->protocol = apr_pstrndup(r->pool, pro, len);
 
    /* XXX ap_update_connection_status(conn->id, "Protocol", r->protocol); */
 
    /* Avoid sscanf in the common case */
    if (len == 8 &&
        pro[0] == 'H' && pro[1] == 'T' && pro[2] == 'T' && pro[3] == 'P' &&
        pro[4] == '/' && apr_isdigit(pro[5]) && pro[6] == '.' &&
        apr_isdigit(pro[7])) {
        r->proto_num = HTTP_VERSION(pro[5] - '0', pro[7] - '0');
    } else if (2 == sscanf(r->protocol, "HTTP/%u.%u", &major, &minor)
               && minor < HTTP_VERSION(1,0))    /* don't allow HTTP/0.1000 */
        r->proto_num = HTTP_VERSION(major, minor);
    else
        r->proto_num = HTTP_VERSION(1,0);
 
    return 1;
}

static int http_create_request(request_rec *r)
{
    ap_http_conn_rec *hconn = ap_get_module_config(r->connection->conn_config, &http_module);
    int keptalive;

    hconn = apr_pcalloc(r->pool, sizeof(*hconn));
    ap_set_module_config(r->connection->conn_config, &http_module, hconn);

    if (!r->main && !r->prev && !r->next) {
        keptalive = r->connection->keepalive == 1;
        r->connection->keepalive    = 0;
 
        /* XXX can we optimize these timeouts at all? gstein */
        apr_setsocketopt(r->connection->client_socket, APR_SO_TIMEOUT,
                         (int)(keptalive
                         ? r->server->keep_alive_timeout * APR_USEC_PER_SEC
                         : r->server->timeout * APR_USEC_PER_SEC));
 
        /* Get the request... */
        if (!read_request_line(r)) {
            if (r->status == HTTP_REQUEST_URI_TOO_LARGE) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                              "request failed: URI too long");
                ap_send_error_response(r, 0);
                ap_run_log_transaction(r);
                return OK;
            }
            return DONE;
        }
        if (keptalive) {
            apr_setsocketopt(r->connection->client_socket,
                             APR_SO_TIMEOUT,
                             (int)(r->server->timeout * APR_USEC_PER_SEC));
        }
    }
    return OK;
}

static const char *log_connection_status(request_rec *r, char *a)
{
    ap_http_conn_rec *hconn = ap_get_module_config(r->connection->conn_config,
                                                &http_module);
    if (r->connection->aborted)
        return "X";
 
    if ((r->connection->keepalive) &&
        ((r->server->keep_alive_max - hconn->keepalives) > 0)) {
        return "+";
    }
 
    return "-";
}

static void http_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

    if (log_pfn_register) {
        log_pfn_register(p, "c", log_connection_status, 0); 
    }
}

static void register_hooks(apr_pool_t *p)
{
    static const char *const pred[] = { "mod_log_config.c", NULL };    

    ap_hook_pre_config(http_pre_config, pred, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(ap_pre_http_connection,NULL,NULL,
			       APR_HOOK_REALLY_LAST);
    ap_hook_process_connection(ap_process_http_connection,NULL,NULL,
			       APR_HOOK_REALLY_LAST);
    ap_hook_http_method(http_method,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_default_port(http_port,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_create_request(http_create_request, NULL, NULL, APR_HOOK_MIDDLE);

    ap_register_input_filter("HTTP_IN", ap_http_filter, AP_FTYPE_CONNECTION);
    ap_register_input_filter("DECHUNK", ap_dechunk_filter, AP_FTYPE_TRANSCODE);
    ap_register_output_filter("HTTP_HEADER", ap_http_header_filter, 
                              AP_FTYPE_HTTP_HEADER);
    ap_register_output_filter("CHUNK", chunk_filter, AP_FTYPE_TRANSCODE);
    ap_register_output_filter("BYTERANGE", ap_byterange_filter,
                              AP_FTYPE_HTTP_HEADER);
}

AP_DECLARE_DATA module http_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    http_cmds,			/* command apr_table_t */
    register_hooks		/* register hooks */
};
