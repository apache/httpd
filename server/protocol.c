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

/*
 * http_protocol.c --- routines which directly communicate with the client.
 *
 * Code originally by Rob McCool; much redone by Robert S. Thau
 * and the Apache Software Foundation.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_signal.h"

#define APR_WANT_STDIO          /* for sscanf */
#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#define CORE_PRIVATE
#include "util_filter.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_request.h"
#include "http_vhost.h"
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "util_charset.h"
#include "util_ebcdic.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif


APR_HOOK_STRUCT(
	    APR_HOOK_LINK(post_read_request)
	    APR_HOOK_LINK(log_transaction)
	    APR_HOOK_LINK(http_method)
	    APR_HOOK_LINK(default_port)
)

AP_DECLARE_DATA ap_filter_rec_t *ap_old_write_func;

/*
 * Builds the content-type that should be sent to the client from the
 * content-type specified.  The following rules are followed:
 *    - if type is NULL, type is set to ap_default_type(r)
 *    - if charset adding is disabled, stop processing and return type.
 *    - then, if there are no parameters on type, add the default charset
 *    - return type
 */
AP_DECLARE(const char *)ap_make_content_type(request_rec *r, const char *type)
{
    static const char *needcset[] = {
	"text/plain",
	"text/html",
	NULL };
    const char **pcset;
    core_dir_config *conf =
	(core_dir_config *)ap_get_module_config(r->per_dir_config,
						&core_module);

    if (!type) {
	type = ap_default_type(r);
    }
    if (conf->add_default_charset != ADD_DEFAULT_CHARSET_ON) {
	return type;
    }

    if (ap_strcasestr(type, "charset=") != NULL) {
	/* already has parameter, do nothing */
	/* XXX we don't check the validity */
	;
    }
    else {
    	/* see if it makes sense to add the charset. At present,
	 * we only add it if the Content-type is one of needcset[]
	 */
	for (pcset = needcset; *pcset ; pcset++) {
	    if (ap_strcasestr(type, *pcset) != NULL) {
		type = apr_pstrcat(r->pool, type, "; charset=", 
				   conf->add_default_charset_name, NULL);
		break;
	    }
	}
    }
    return type;
}

AP_DECLARE(void) ap_set_content_length(request_rec *r, apr_off_t clength)
{
    r->clength = clength;
    apr_table_setn(r->headers_out, "Content-Length",
		   apr_off_t_toa(r->pool, clength));
}

/*
 * Return the latest rational time from a request/mtime (modification time)
 * pair.  We return the mtime unless it's in the future, in which case we
 * return the current time.  We use the request time as a reference in order
 * to limit the number of calls to time().  We don't check for futurosity
 * unless the mtime is at least as new as the reference.
 */
AP_DECLARE(apr_time_t) ap_rationalize_mtime(request_rec *r, apr_time_t mtime)
{
    apr_time_t now;

    /* For all static responses, it's almost certain that the file was
     * last modified before the beginning of the request.  So there's
     * no reason to call time(NULL) again.  But if the response has been
     * created on demand, then it might be newer than the time the request
     * started.  In this event we really have to call time(NULL) again
     * so that we can give the clients the most accurate Last-Modified.  If we
     * were given a time in the future, we return the current time - the
     * Last-Modified can't be in the future.
     */
    now = (mtime < r->request_time) ? r->request_time : apr_time_now();
    return (mtime > now) ? now : mtime;
}

/* Get a line of protocol input, including any continuation lines
 * caused by MIME folding (or broken clients) if fold != 0, and place it
 * in the buffer s, of size n bytes, without the ending newline.
 *
 * Returns: 
 *     the length of s (normal case),
 *     n               (buffer full),
 *    -1               (other errors)
 *
 * Notes: Because the buffer uses 1 char for NUL, the most we can return is 
 *        (n - 1) actual characters.  
 *
 *        If no LF is detected on the last line due to a dropped connection 
 *        or a full buffer, that's considered an error.
 */
AP_DECLARE(int) ap_rgetline(char **s, int n, request_rec *r, int fold)
{
    char *pos;
    char *last_char;
    const char *temp;
    int retval;
    int total = 0;
    int looking_ahead = 0;
    apr_size_t length;
    core_request_config *req_cfg;
    apr_bucket_brigade *b;
    apr_bucket *e;

    req_cfg = (core_request_config *)
                ap_get_module_config(r->request_config, &core_module);
    b = req_cfg->bb;
    /* make sure it's empty unless we're folding */ 
    AP_DEBUG_ASSERT(fold || APR_BRIGADE_EMPTY(b));

    while (1) {
        if (APR_BRIGADE_EMPTY(b)) {
            apr_off_t zero = 0;
            if ((retval = ap_get_brigade(r->input_filters, b,
                                         AP_MODE_BLOCKING,
                                         &zero /* readline */)) != APR_SUCCESS ||
                APR_BRIGADE_EMPTY(b)) {
                apr_brigade_destroy(b);
                return -1;
            }
        }
        e = APR_BRIGADE_FIRST(b); 
        if (APR_BUCKET_IS_EOS(e)) {
            apr_brigade_destroy(b);
            return -1;
        }
        if (e->length == 0) {
            apr_bucket_delete(e);
            continue;
        }
        retval = apr_bucket_read(e, &temp, &length, APR_BLOCK_READ);
        if (retval != APR_SUCCESS) {
            apr_brigade_destroy(b);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, retval, r, "apr_bucket_read() failed");
            if (total) {
                break; /* report previously-read data to caller, do ap_xlate_proto_to_ascii() */
            }
            else {
                return -1;
            }
        }

        if ((looking_ahead) && (*temp != APR_ASCII_BLANK) && (*temp != APR_ASCII_TAB)) { 
            /* can't fold because next line isn't indented, 
             * so return what we have.  lookahead brigade is 
             * stashed on req_cfg->bb
             */
            AP_DEBUG_ASSERT(!APR_BRIGADE_EMPTY(req_cfg->bb));
            break;
        }
        if (length - 1 < n) {
            if (!*s) {
                *s = apr_palloc(r->pool, length + 2); /* +2 for LF, null */
            }
            pos = *s;
            last_char = pos + length - 1;
            memcpy(pos, temp, length);
            apr_bucket_delete(e);
        }
        else {
            /* input line was larger than the caller's buffer */
            apr_brigade_destroy(b); 

            /* don't need to worry about req_cfg->bb being bogus.
             * the request is about to die, and ErrorDocument
             * redirects get a new req_cfg->bb
             */

            return n;
        }
        
        pos = last_char;        /* Point at the last character           */

        if (*pos == APR_ASCII_LF) { /* Did we get a full line of input?      */
                
            if (pos > *s && *(pos - 1) == APR_ASCII_CR) {
                --pos;          /* zap optional CR before LF             */
            }
                
            /*
             * Trim any extra trailing spaces or tabs except for the first
             * space or tab at the beginning of a blank string.  This makes
             * it much easier to check field values for exact matches, and
             * saves memory as well.  Terminate string at end of line.
             */
            while (pos > ((*s) + 1) && 
                   (*(pos - 1) == APR_ASCII_BLANK || *(pos - 1) == APR_ASCII_TAB)) {
                --pos;          /* trim extra trailing spaces or tabs    */
            }
            *pos = '\0';        /* zap end of string                     */
            total = pos - *s;   /* update total string length            */

            /* look ahead another line if line folding is desired 
             * and this line isn't empty
             */
            if (fold && total) {
                looking_ahead = 1;
            }
            else {
                AP_DEBUG_ASSERT(APR_BRIGADE_EMPTY(req_cfg->bb));
                break;
            }
        }
        else {
            /* no LF yet...character mode client (telnet)...keep going
             * bump past last character read,   
             * and set total in case we bail before finding a LF   
             */
            total = ++pos - *s;
            looking_ahead = 0;  /* only appropriate right after LF       */ 
        }
    }
    ap_xlate_proto_from_ascii(*s, total);
    return total;
}

AP_DECLARE(int) ap_getline(char *s, int n, request_rec *r, int fold)
{
    char *tmp_s = s;
    return ap_rgetline(&tmp_s, n, r, fold);
}

/* parse_uri: break apart the uri
 * Side Effects:
 * - sets r->args to rest after '?' (or NULL if no '?')
 * - sets r->uri to request uri (without r->args part)
 * - sets r->hostname (if not set already) from request (scheme://host:port)
 */
AP_CORE_DECLARE(void) ap_parse_uri(request_rec *r, const char *uri)
{
    int status = HTTP_OK;

    r->unparsed_uri = apr_pstrdup(r->pool, uri);

    if (r->method_number == M_CONNECT) {
	status = apr_uri_parse_hostinfo(r->pool, uri, &r->parsed_uri);
    }
    else {
	/* Simple syntax Errors in URLs are trapped by parse_uri_components(). */
	status = apr_uri_parse(r->pool, uri, &r->parsed_uri);
    }

    if (status == APR_SUCCESS) {
	/* if it has a scheme we may need to do absoluteURI vhost stuff */
	if (r->parsed_uri.scheme
	    && !strcasecmp(r->parsed_uri.scheme, ap_http_method(r))) {
	    r->hostname = r->parsed_uri.hostname;
	}
	else if (r->method_number == M_CONNECT) {
	    r->hostname = r->parsed_uri.hostname;
	}
	r->args = r->parsed_uri.query;
	r->uri = r->parsed_uri.path ? r->parsed_uri.path
				    : apr_pstrdup(r->pool, "/");
#if defined(OS2) || defined(WIN32)
	/* Handle path translations for OS/2 and plug security hole.
	 * This will prevent "http://www.wherever.com/..\..\/" from
	 * returning a directory for the root drive.
	 */
	{
	    char *x;

	    for (x = r->uri; (x = strchr(x, '\\')) != NULL; )
		*x = '/';
	}
#endif  /* OS2 || WIN32 */
    }
    else {
	r->args = NULL;
	r->hostname = NULL;
	r->status = HTTP_BAD_REQUEST;             /* set error status */
	r->uri = apr_pstrdup(r->pool, uri);
    }
}

static int read_request_line(request_rec *r)
{
    const char *ll;
    const char *uri;
    const char *pro;

#if 0
    conn_rec *conn = r->connection;
#endif
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

    while ((len = ap_rgetline(&(r->the_request),
                              DEFAULT_LIMIT_REQUEST_LINE + 2, r, 0)) <= 0) {
        if (len < 0) {             /* includes EOF */
	    /* this is a hack to make sure that request time is set,
	     * it's not perfect, but it's better than nothing 
	     */
	    r->request_time = apr_time_now();
            return 0;
        }
    }
    /* we've probably got something to do, ignore graceful restart requests */

    r->request_time = apr_time_now();
    ll = r->the_request;
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
    r->protocol = apr_pstrmemdup(r->pool, pro, len);

    /* XXX ap_update_connection_status(conn->id, "Protocol", r->protocol); */

    /* Avoid sscanf in the common case */
    if (len == 8 &&
        pro[0] == 'H' && pro[1] == 'T' && pro[2] == 'T' && pro[3] == 'P' &&
        pro[4] == '/' && apr_isdigit(pro[5]) && pro[6] == '.' &&
        apr_isdigit(pro[7])) {
 	r->proto_num = HTTP_VERSION(pro[5] - '0', pro[7] - '0');
    } else if (2 == sscanf(r->protocol, "HTTP/%u.%u", &major, &minor)
               && minor < HTTP_VERSION(1,0))	/* don't allow HTTP/0.1000 */
	r->proto_num = HTTP_VERSION(major, minor);
    else
	r->proto_num = HTTP_VERSION(1,0);

    return 1;
}

static void get_mime_headers(request_rec *r)
{
    char* field;
    char *value;
    int len;
    int fields_read = 0;
    apr_table_t *tmp_headers;

    /* We'll use apr_table_overlap later to merge these into r->headers_in. */
    tmp_headers = apr_table_make(r->pool, 50);

    /*
     * Read header lines until we get the empty separator line, a read error,
     * the connection closes (EOF), reach the server limit, or we timeout.
     */
    field = NULL;
    while ((len = ap_rgetline(&field, DEFAULT_LIMIT_REQUEST_FIELDSIZE + 2,
                              r, 1)) > 0) {

        if (r->server->limit_req_fields &&
            (++fields_read > r->server->limit_req_fields)) {
            r->status = HTTP_BAD_REQUEST;
            apr_table_setn(r->notes, "error-notes",
			   "The number of request header fields exceeds "
			   "this server's limit.");
            return;
        }
        /* ap_getline returns (size of max buffer - 1) if it fills up the
         * buffer before finding the end-of-line.  This is only going to
         * happen if it exceeds the configured limit for a field size.
         */
        if (len > r->server->limit_req_fieldsize) {
            r->status = HTTP_BAD_REQUEST;
            apr_table_setn(r->notes, "error-notes",
			   apr_pstrcat(r->pool,
				       "Size of a request header field "
				       "exceeds server limit.<br />\n"
				       "<pre>\n",
				       ap_escape_html(r->pool, field),
				       "</pre>\n", NULL));
            return;
        }

        if (!(value = strchr(field, ':'))) {    /* Find the colon separator */
            r->status = HTTP_BAD_REQUEST;       /* or abort the bad request */
            apr_table_setn(r->notes, "error-notes",
			   apr_pstrcat(r->pool,
				       "Request header field is missing "
				       "colon separator.<br />\n"
				       "<pre>\n",
				       ap_escape_html(r->pool, field),
				       "</pre>\n", NULL));
            return;
        }

        *value = '\0';
        ++value;
        while (*value == ' ' || *value == '\t') {
            ++value;            /* Skip to start of value   */
	}

	apr_table_addn(tmp_headers, field, value);
        field = NULL; /* to cause ap_rgetline to allocate a new one */
    }

    apr_table_overlap(r->headers_in, tmp_headers, APR_OVERLAP_TABLES_MERGE);
}

request_rec *ap_read_request(conn_rec *conn)
{
    request_rec *r;
    apr_pool_t *p;
    const char *expect;
    int access_status;

    apr_pool_create(&p, conn->pool);
    r = apr_pcalloc(p, sizeof(request_rec));
    r->pool            = p;
    r->connection      = conn;
    r->server          = conn->base_server;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in      = apr_table_make(r->pool, 50);
    r->subprocess_env  = apr_table_make(r->pool, 50);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->notes           = apr_table_make(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    /* Must be set before we run create request hook */
    r->output_filters  = conn->output_filters;
    r->input_filters   = conn->input_filters;
    ap_run_create_request(r);
    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_REQUEST_TIME_OUT;  /* Until we get a request */
    r->the_request     = NULL;

    /* Get the request... */
    if (!read_request_line(r)) {
        if (r->status == HTTP_REQUEST_URI_TOO_LARGE) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "request failed: URI too long");
            ap_send_error_response(r, 0);
            ap_run_log_transaction(r);
            return r;
        }
        return NULL;
    }

    if (!r->assbackwards) {
        get_mime_headers(r);
        if (r->status != HTTP_REQUEST_TIME_OUT) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "request failed: error reading the headers");
            ap_send_error_response(r, 0);
            ap_run_log_transaction(r);
            return r;
        }
    }
    else {
        if (r->header_only) {
            /*
             * Client asked for headers only with HTTP/0.9, which doesn't send
             * headers! Have to dink things just to make sure the error message
             * comes through...
             */
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                          "client sent invalid HTTP/0.9 request: HEAD %s",
                          r->uri);
            r->header_only = 0;
            r->status = HTTP_BAD_REQUEST;
            ap_send_error_response(r, 0);
            ap_run_log_transaction(r);
            return r;
        }
    }

    r->status = HTTP_OK;                         /* Until further notice. */

    /* update what we think the virtual host is based on the headers we've
     * now read. may update status.
     */
    ap_update_vhost_from_headers(r);

    /* we may have switched to another server */
    r->per_dir_config = r->server->lookup_defaults;

    if ((!r->hostname && (r->proto_num >= HTTP_VERSION(1,1))) ||
        ((r->proto_num == HTTP_VERSION(1,1)) &&
         !apr_table_get(r->headers_in, "Host"))) {
        /*
         * Client sent us an HTTP/1.1 or later request without telling us the
         * hostname, either with a full URL or a Host: header. We therefore
         * need to (as per the 1.1 spec) send an error.  As a special case,
         * HTTP/1.1 mentions twice (S9, S14.23) that a request MUST contain
         * a Host: header, and the server MUST respond with 400 if it doesn't.
         */
        r->status = HTTP_BAD_REQUEST;
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      "client sent HTTP/1.1 request without hostname "
                      "(see RFC2616 section 14.23): %s", r->uri);
    }
    if (r->status != HTTP_OK) {
        ap_send_error_response(r, 0);
        ap_run_log_transaction(r);
        return r;
    }
    if (((expect = apr_table_get(r->headers_in, "Expect")) != NULL) &&
        (expect[0] != '\0')) {
        /*
         * The Expect header field was added to HTTP/1.1 after RFC 2068
         * as a means to signal when a 100 response is desired and,
         * unfortunately, to signal a poor man's mandatory extension that
         * the server must understand or return 417 Expectation Failed.
         */
        if (strcasecmp(expect, "100-continue") == 0) {
            r->expecting_100 = 1;
        }
        else {
            r->status = HTTP_EXPECTATION_FAILED;
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                          "client sent an unrecognized expectation value of "
                          "Expect: %s", expect);
            ap_send_error_response(r, 0);
            (void) ap_discard_request_body(r);
            ap_run_log_transaction(r);
            return r;
        }
    }

    ap_add_input_filter("HTTP_IN", NULL, r, r->connection);

    if ((access_status = ap_run_post_read_request(r))) {
        ap_die(access_status, r);
        ap_run_log_transaction(r);
        return NULL;
    }

    return r;
}

/*
 * A couple of other functions which initialize some of the fields of
 * a request structure, as appropriate for adjuncts of one kind or another
 * to a request in progress.  Best here, rather than elsewhere, since
 * *someone* has to set the protocol-specific fields...
 */

void ap_set_sub_req_protocol(request_rec *rnew, const request_rec *r)
{
    rnew->the_request     = r->the_request;  /* Keep original request-line */

    rnew->assbackwards    = 1;   /* Don't send headers from this. */
    rnew->no_local_copy   = 1;   /* Don't try to send HTTP_NOT_MODIFIED for a
                                  * fragment. */
    rnew->method          = "GET";
    rnew->method_number   = M_GET;
    rnew->protocol        = "INCLUDED";

    rnew->status          = HTTP_OK;

    rnew->headers_in      = r->headers_in;
    rnew->subprocess_env  = apr_table_copy(rnew->pool, r->subprocess_env);
    rnew->headers_out     = apr_table_make(rnew->pool, 5);
    rnew->err_headers_out = apr_table_make(rnew->pool, 5);
    rnew->notes           = apr_table_make(rnew->pool, 5);

    rnew->expecting_100   = r->expecting_100;
    rnew->read_length     = r->read_length;
    rnew->read_body       = REQUEST_NO_BODY;

    rnew->main = (request_rec *) r;
}

static void end_output_stream(request_rec *r)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool);
    b = apr_bucket_eos_create();
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);
}

void ap_finalize_sub_req_protocol(request_rec *sub)
{
    end_output_stream(sub); 
}

/* finalize_request_protocol is called at completion of sending the
 * response.  Its sole purpose is to send the terminating protocol
 * information for any wrappers around the response message body
 * (i.e., transfer encodings).  It should have been named finalize_response.
 */
AP_DECLARE(void) ap_finalize_request_protocol(request_rec *r)
{
    while (r->next) {
        r = r->next;
    }
    /* tell the filter chain there is no more content coming */
    if (!r->eos_sent) {
        end_output_stream(r);
    }
} 

/*
 * Support for the Basic authentication protocol, and a bit for Digest.
 */

AP_DECLARE(void) ap_note_auth_failure(request_rec *r)
{
    const char *type = ap_auth_type(r);
    if (type) {
        if (!strcasecmp(type, "Basic"))
            ap_note_basic_auth_failure(r);
        else if (!strcasecmp(type, "Digest"))
            ap_note_digest_auth_failure(r);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
                      0, r, "need AuthType to note auth failure: %s", r->uri);
    }
}

AP_DECLARE(void) ap_note_basic_auth_failure(request_rec *r)
{
    const char *type = ap_auth_type(r);
    /* if there is no AuthType configure or it is something other than
     * Basic, let ap_note_auth_failure() deal with it
     */
    if (!type || strcasecmp(type, "Basic"))
        ap_note_auth_failure(r);
    else
        apr_table_setn(r->err_headers_out,
                  (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate" : "WWW-Authenticate",
                  apr_pstrcat(r->pool, "Basic realm=\"", ap_auth_name(r), "\"",
                          NULL));
}

AP_DECLARE(void) ap_note_digest_auth_failure(request_rec *r)
{
    apr_table_setn(r->err_headers_out,
	    (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate" : "WWW-Authenticate",
	    apr_psprintf(r->pool, "Digest realm=\"%s\", nonce=\"%llx\"",
		ap_auth_name(r), r->request_time));
}

AP_DECLARE(int) ap_get_basic_auth_pw(request_rec *r, const char **pw)
{
    const char *auth_line = apr_table_get(r->headers_in,
                                      (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authorization"
                                                  : "Authorization");
    const char *t;

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Basic"))
        return DECLINED;

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
		      0, r, "need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!auth_line) {
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        /* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		      "client used wrong authentication scheme: %s", r->uri);
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    while (*auth_line== ' ' || *auth_line== '\t') {
        auth_line++;
    }

    t = ap_pbase64decode(r->pool, auth_line);
    /* Note that this allocation has to be made from r->connection->pool
     * because it has the lifetime of the connection.  The other allocations
     * are temporary and can be tossed away any time.
     */
    r->user = ap_getword_nulls (r->pool, &t, ':');
    r->ap_auth_type = "Basic";

    *pw = t;

    return OK;
}

struct content_length_ctx {
    apr_bucket_brigade *saved;
    int compute_len;
    apr_size_t curr_len;
};

/* This filter computes the content length, but it also computes the number
 * of bytes sent to the client.  This means that this filter will always run
 * through all of the buckets in all brigades 
 */
AP_CORE_DECLARE_NONSTD(apr_status_t) ap_content_length_filter(ap_filter_t *f,
                                                              apr_bucket_brigade *b)
{
    request_rec *r = f->r;
    struct content_length_ctx *ctx;
    apr_status_t rv;
    apr_bucket *e;
    int eos = 0, flush = 0, partial_send_okay = 0;
    apr_bucket_brigade *more, *split;
    apr_read_type_e eblock = APR_NONBLOCK_READ;

    ctx = f->ctx;
    if (!ctx) { /* first time through */
        f->ctx = ctx = apr_pcalloc(r->pool, sizeof(struct content_length_ctx));
        ctx->compute_len = 1;   /* Assume we will compute the length */
    }

    /* Humm, is this check the best it can be? 
     * - protocol >= HTTP/1.1 implies support for chunking 
     * - non-keepalive implies the end of byte stream will be signaled
     *    by a connection close
     * In both cases, we can send bytes to the client w/o needing to
     * compute content-length. 
     * Todo: 
     * We should be able to force connection close from this filter
     * when we see we are buffering too much. 
     */
    if ((r->proto_num >= HTTP_VERSION(1,1)) ||
        (!f->r->connection->keepalive)) {
        partial_send_okay = 1;
    }

    more = b;
    while (more) {
        b = more;
        more = NULL;
        split = NULL;
        flush = 0;

        APR_BRIGADE_FOREACH(e, b) {
            const char *ignored;
            apr_size_t len;
            len = 0;
            if (APR_BUCKET_IS_EOS(e)) {
                eos = 1;
            }
            else if (APR_BUCKET_IS_FLUSH(e)) {
                if (partial_send_okay) {
                    split = b;
                    more = apr_brigade_split(b, APR_BUCKET_NEXT(e));
                    break;
                }
            }
            else if ((ctx->curr_len > 4*AP_MIN_BYTES_TO_WRITE)) {
                /* If we've accumulated more than 4xAP_MIN_BYTES_TO_WRITE and 
                 * the client supports chunked encoding, send what we have 
                 * and come back for more.
                 */
                if (partial_send_okay) {
                    split = b;
                    more = apr_brigade_split(b, e);
                    break;
                }
            }
            if (e->length == -1) { /* if length unknown */
                rv = apr_bucket_read(e, &ignored, &len, eblock);
                if (rv == APR_SUCCESS) {
                    /* Attempt a nonblocking read next time through */
                    eblock = APR_NONBLOCK_READ;
                }
                else if (APR_STATUS_IS_EAGAIN(rv)) {
                    /* Make the next read blocking.  If the client supports chunked
                     * encoding, flush the filter stack to the network.
                     */
                    eblock = APR_BLOCK_READ;
                    if (partial_send_okay) {
                        split = b;
                        more = apr_brigade_split(b, e);
                        flush = 1;
                        break;
                    }
                }
                else if (rv != APR_EOF) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, 
                        "ap_content_length_filter: apr_bucket_read() failed");
                    return rv;
                }
            }
            else {
                len = e->length;
            }
            ctx->curr_len += len;
            r->bytes_sent += len;
        }

        if (split) {
            ctx->compute_len = 0;  /* Ooops, can't compute the length now */
            ctx->curr_len = 0;
            if (ctx->saved) {
                APR_BRIGADE_CONCAT(ctx->saved, split);
                apr_brigade_destroy(split);
                split = ctx->saved;
                ctx->saved = NULL;
            }
            if (flush) {
                rv = ap_fflush(f->next, split);
            }
            else {
                rv = ap_pass_brigade(f->next, split);
            }
            if (rv != APR_SUCCESS)
                return rv;
        }
    }

    if ((ctx->curr_len < AP_MIN_BYTES_TO_WRITE) && !eos) {
        return ap_save_brigade(f, &ctx->saved, &b, (r->main) ? r->main->pool : r->pool);
    }

    if (ctx->compute_len) {
        /* save the brigade; we can't pass any data to the next
         * filter until we have the entire content length
         */
        if (!eos) {
            return ap_save_brigade(f, &ctx->saved, &b, r->pool);
        }
        ap_set_content_length(r, r->bytes_sent);
    }
    if (ctx->saved) {
        APR_BRIGADE_CONCAT(ctx->saved, b);
        apr_brigade_destroy(b);
        b = ctx->saved;
        ctx->saved = NULL;
    }

    ctx->curr_len = 0;
    return ap_pass_brigade(f->next, b);
}

/*
 * Send the body of a response to the client.
 */
AP_DECLARE(apr_status_t) ap_send_fd(apr_file_t *fd, request_rec *r, apr_off_t offset, 
                                    apr_size_t len, apr_size_t *nbytes) 
{
    apr_bucket_brigade *bb = NULL;
    apr_bucket *b;
    apr_status_t rv;

    bb = apr_brigade_create(r->pool);
    b = apr_bucket_file_create(fd, offset, len, r->pool);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    rv = ap_pass_brigade(r->output_filters, bb);
    if (rv != APR_SUCCESS) {
        *nbytes = 0; /* no way to tell how many were actually sent */
    }
    else {
        *nbytes = len;
    }

    return rv;
}

#if APR_HAS_MMAP
/* send data from an in-memory buffer */
AP_DECLARE(size_t) ap_send_mmap(apr_mmap_t *mm, request_rec *r, size_t offset,
                             size_t length)
{
    apr_bucket_brigade *bb = NULL;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool);
    b = apr_bucket_mmap_create(mm, offset, length);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);

    return mm->size; /* XXX - change API to report apr_status_t? */
}
#endif /* APR_HAS_MMAP */

typedef struct {
    apr_bucket_brigade *bb;
} old_write_filter_ctx;

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_old_write_filter(
    ap_filter_t *f, apr_bucket_brigade *bb)
{
    old_write_filter_ctx *ctx = f->ctx;

    AP_DEBUG_ASSERT(ctx);

    if (ctx->bb != 0) {
        /* whatever is coming down the pipe (we don't care), we
         * can simply insert our buffered data at the front and
         * pass the whole bundle down the chain. 
         */
        APR_BRIGADE_CONCAT(ctx->bb, bb);
    }

    return ap_pass_brigade(f->next, ctx->bb);
}

static apr_status_t buffer_output(request_rec *r,
                                  const char *str, apr_size_t len)
{
    ap_filter_t *f;
    old_write_filter_ctx *ctx;

    if (len == 0)
        return APR_SUCCESS;

    /* future optimization: record some flags in the request_rec to
     * say whether we've added our filter, and whether it is first.
     */

    /* this will typically exit on the first test */
    for (f = r->output_filters; f != NULL; f = f->next)
        if (ap_old_write_func == f->frec)
            break;
    if (f == NULL) {
        /* our filter hasn't been added yet */
        ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ap_add_output_filter("OLD_WRITE", ctx, r, r->connection);
        f = r->output_filters;
    }

    /* if the first filter is not our buffering filter, then we have to
     * deliver the content through the normal filter chain */
    if (f != r->output_filters) {
        apr_bucket_brigade *bb = apr_brigade_create(r->pool);
        apr_bucket *b = apr_bucket_transient_create(str, len);
        APR_BRIGADE_INSERT_TAIL(bb, b);

        return ap_pass_brigade(r->output_filters, bb);
    }

    /* grab the context from our filter */
    ctx = r->output_filters->ctx;

    if (ctx->bb == NULL) {
        ctx->bb = apr_brigade_create(r->pool);
    }

    return ap_fwrite(f->next, ctx->bb, str, len);
}

AP_DECLARE(int) ap_rputc(int c, request_rec *r)
{
    char c2 = (char)c;

    if (r->connection->aborted) {
	return -1;
    }

    if (buffer_output(r, &c2, 1) != APR_SUCCESS)
        return -1;

    return c;
}

AP_DECLARE(int) ap_rputs(const char *str, request_rec *r)
{
    apr_size_t len;

    if (r->connection->aborted)
        return -1;

    if (buffer_output(r, str, len = strlen(str)) != APR_SUCCESS)
        return -1;

    return len;
}

AP_DECLARE(int) ap_rwrite(const void *buf, int nbyte, request_rec *r)
{
    if (r->connection->aborted)
        return -1;

    if (buffer_output(r, buf, nbyte) != APR_SUCCESS)
        return -1;

    return nbyte;
}

struct ap_vrprintf_data {
    apr_vformatter_buff_t vbuff;
    request_rec *r;
    char *buff;
};

static apr_status_t r_flush(apr_vformatter_buff_t *buff)
{
    /* callback function passed to ap_vformatter to be called when
     * vformatter needs to write into buff and buff.curpos > buff.endpos */

    /* ap_vrprintf_data passed as a apr_vformatter_buff_t, which is then
     * "downcast" to an ap_vrprintf_data */
    struct ap_vrprintf_data *vd = (struct ap_vrprintf_data*)buff;

    if (vd->r->connection->aborted)
        return -1;

    /* r_flush is called when vbuff is completely full */
    if (buffer_output(vd->r, vd->buff, AP_IOBUFSIZE)) {
	return -1;
    }

    /* reset the buffer position */
    vd->vbuff.curpos = vd->buff;
    vd->vbuff.endpos = vd->buff + AP_IOBUFSIZE;

    return APR_SUCCESS;
}

AP_DECLARE(int) ap_vrprintf(request_rec *r, const char *fmt, va_list va)
{
    apr_size_t written;
    struct ap_vrprintf_data vd;
    char vrprintf_buf[AP_IOBUFSIZE];

    vd.vbuff.curpos = vrprintf_buf;
    vd.vbuff.endpos = vrprintf_buf + AP_IOBUFSIZE;
    vd.r = r;
    vd.buff = vrprintf_buf;

    if (r->connection->aborted)
        return -1;

    written = apr_vformatter(r_flush, &vd.vbuff, fmt, va);
    /* tack on null terminator on remaining string */
    *(vd.vbuff.curpos) = '\0';

    if (written != -1) {
	int n = vd.vbuff.curpos - vrprintf_buf;

	/* last call to buffer_output, to finish clearing the buffer */
	if (buffer_output(r, vrprintf_buf,n) != APR_SUCCESS)
	    return -1;

	written += n;
    }

    return written;
}

AP_DECLARE_NONSTD(int) ap_rprintf(request_rec *r, const char *fmt, ...)
{
    va_list va;
    int n;

    if (r->connection->aborted)
        return -1;

    va_start(va, fmt);
    n = ap_vrprintf(r, fmt, va);
    va_end(va);

    return n;
}

AP_DECLARE_NONSTD(int) ap_rvputs(request_rec *r, ...)
{
    va_list va;
    const char *s;
    apr_size_t len;
    apr_size_t written = 0;

    if (r->connection->aborted)
        return -1;

    /* ### TODO: if the total output is large, put all the strings
       ### into a single brigade, rather than flushing each time we
       ### fill the buffer */
    va_start(va, r);
    while (1) {
        s = va_arg(va, const char *);
        if (s == NULL)
            break;

        len = strlen(s);
        if (buffer_output(r, s, len) != APR_SUCCESS) {
            return -1;
        }

        written += len;
    }
    va_end(va);

    return written;
}

AP_DECLARE(int) ap_rflush(request_rec *r)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool);
    b = apr_bucket_flush_create();
    APR_BRIGADE_INSERT_TAIL(bb, b);
    if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS)
        return -1;
    return 0;
}

/*
 * This function sets the Last-Modified output header field to the value
 * of the mtime field in the request structure - rationalized to keep it from
 * being in the future.
 */
AP_DECLARE(void) ap_set_last_modified(request_rec *r)
{
    apr_time_t mod_time = ap_rationalize_mtime(r, r->mtime);
    char *datestr = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
    apr_rfc822_date(datestr, mod_time);
    apr_table_setn(r->headers_out, "Last-Modified", datestr);
}

AP_IMPLEMENT_HOOK_RUN_ALL(int,post_read_request,
                          (request_rec *r),(r),OK,DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,log_transaction,
                          (request_rec *r),(r),OK,DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *,http_method,
                            (const request_rec *r),(r),NULL)
AP_IMPLEMENT_HOOK_RUN_FIRST(unsigned short,default_port,
                            (const request_rec *r),(r),0)
