/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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

#define CORE_PRIVATE
#include "ap_config.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_request.h"
#include "http_vhost.h"
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "util_date.h"          /* For parseHTTPdate and BAD_DATE */
#include "util_charset.h"
#include "mpm_status.h"
#ifdef APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

AP_HOOK_STRUCT(
	    AP_HOOK_LINK(post_read_request)
	    AP_HOOK_LINK(log_transaction)
	    AP_HOOK_LINK(http_method)
	    AP_HOOK_LINK(default_port)
)

#define SET_BYTES_SENT(r) \
  do { if (r->sent_bodyct) \
          ap_bgetopt (r->connection->client, BO_BYTECT, &r->bytes_sent); \
  } while (0)


/* if this is the first error, then log an INFO message and shut down the
 * connection.
 */
static void check_first_conn_error(const request_rec *r, const char *operation,
                                   apr_status_t status)
{
    if (!r->connection->aborted) {
        if (status == 0)
            status = ap_berror(r->connection->client);
        ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r,
                      "client stopped connection before %s completed",
                      operation);
        ap_bsetflag(r->connection->client, B_EOUT, 1);
        r->connection->aborted = 1;
    }
}

static int checked_bputstrs(request_rec *r, ...)
{
    va_list va;
    int n;

    if (r->connection->aborted)
        return EOF;

    va_start(va, r);
    n = ap_vbputstrs(r->connection->client, va);
    va_end(va);

    if (n < 0) {
        check_first_conn_error(r, "checked_bputstrs", 0);
        return EOF;
    }

    SET_BYTES_SENT(r);
    return n;
}

static int checked_bflush(request_rec *r)
{
    apr_status_t rv;

    if ((rv = ap_bflush(r->connection->client)) != APR_SUCCESS) {
        check_first_conn_error(r, "checked_bflush", rv);
        return EOF;
    }
    return 0;
}

static int checked_bputs(const char *str, request_rec *r)
{
    int rcode;

    if (r->connection->aborted)
        return EOF;
    
    rcode = ap_bputs(str, r->connection->client);
    if (rcode < 0) {
        check_first_conn_error(r, "checked_bputs", 0);
        return EOF;
    }
    SET_BYTES_SENT(r);
    return rcode;
}

/*
 * Builds the content-type that should be sent to the client from the
 * content-type specified.  The following rules are followed:
 *    - if type is NULL, type is set to ap_default_type(r)
 *    - if charset adding is disabled, stop processing and return type.
 *    - then, if there are no parameters on type, add the default charset
 *    - return type
 */
static const char *make_content_type(request_rec *r, const char *type) {
    static const char *needcset[] = {
	"text/plain",
	"text/html",
	NULL };
    const char **pcset;
    core_dir_config *conf = (core_dir_config *)ap_get_module_config(
	r->per_dir_config, &core_module);

    if (!type)
        type = ap_default_type(r);
    if (conf->add_default_charset != ADD_DEFAULT_CHARSET_ON)
        return type;

    if (ap_strcasestr(type, "charset=") != NULL) {
	/* already has parameter, do nothing */
	/* XXX we don't check the validity */
	;
    } else {
    	/* see if it makes sense to add the charset. At present,
	 * we only add it if the Content-type is one of needcset[]
	 */
	for (pcset = needcset; *pcset ; pcset++)
	    if (ap_strcasestr(type, *pcset) != NULL) {
		type = apr_pstrcat(r->pool, type, "; charset=", 
		    conf->add_default_charset_name, NULL);
		break;
	    }
    }
    return type;
}

static int parse_byterange(char *range, long clength, long *start, long *end)
{
    char *dash = strchr(range, '-');

    if (!dash)
        return 0;

    if ((dash == range)) {
        /* In the form "-5" */
        *start = clength - atol(dash + 1);
        *end = clength - 1;
    }
    else {
        *dash = '\0';
        dash++;
        *start = atol(range);
        if (*dash)
            *end = atol(dash);
        else                    /* "5-" */
            *end = clength - 1;
    }

    if (*start < 0)
	*start = 0;

    if (*end >= clength)
        *end = clength - 1;

    if (*start > *end)
	return 0;

    return (*start > 0 || *end < clength - 1);
}

static int internal_byterange(int, long *, request_rec *, const char **,
			      apr_off_t *, apr_size_t *);

API_EXPORT(int) ap_set_byterange(request_rec *r)
{
    const char *range, *if_range, *match;
    long range_start, range_end;

    if (!r->clength || r->assbackwards)
        return 0;

    /* Check for Range request-header (HTTP/1.1) or Request-Range for
     * backwards-compatibility with second-draft Luotonen/Franks
     * byte-ranges (e.g. Netscape Navigator 2-3).
     *
     * We support this form, with Request-Range, and (farther down) we
     * send multipart/x-byteranges instead of multipart/byteranges for
     * Request-Range based requests to work around a bug in Netscape
     * Navigator 2-3 and MSIE 3.
     */

    if (!(range = apr_table_get(r->headers_in, "Range")))
        range = apr_table_get(r->headers_in, "Request-Range");

    if (!range || strncasecmp(range, "bytes=", 6)) {
        return 0;
    }

    /* Check the If-Range header for Etag or Date.
     * Note that this check will return false (as required) if either
     * of the two etags are weak.
     */
    if ((if_range = apr_table_get(r->headers_in, "If-Range"))) {
        if (if_range[0] == '"') {
            if (!(match = apr_table_get(r->headers_out, "Etag")) ||
                (strcmp(if_range, match) != 0))
                return 0;
        }
        else if (!(match = apr_table_get(r->headers_out, "Last-Modified")) ||
                 (strcmp(if_range, match) != 0))
            return 0;
    }

    if (!ap_strchr_c(range, ',')) {
        /* A single range */
        if (!parse_byterange(apr_pstrdup(r->pool, range + 6), r->clength,
                             &range_start, &range_end))
            return 0;

        r->byterange = 1;

        apr_table_setn(r->headers_out, "Content-Range",
	    apr_psprintf(r->pool, "bytes %ld-%ld/%ld",
		range_start, range_end, r->clength));
        apr_table_setn(r->headers_out, "Content-Length",
	    apr_psprintf(r->pool, "%ld", range_end - range_start + 1));
    }
    else {
        /* a multiple range */
        const char *r_range = apr_pstrdup(r->pool, range + 6);
        long tlength = 0;

        r->byterange = 2;
        r->boundary = apr_psprintf(r->pool, "%llx%lx",
				r->request_time, (long) getpid());
        while (internal_byterange(0, &tlength, r, &r_range, NULL, NULL));
        apr_table_setn(r->headers_out, "Content-Length",
	    apr_psprintf(r->pool, "%ld", tlength));
    }

    r->status = HTTP_PARTIAL_CONTENT;
    r->range = range + 6;

    return 1;
}

API_EXPORT(int) ap_each_byterange(request_rec *r, apr_off_t *offset,
				  apr_size_t *length)
{
    return internal_byterange(1, NULL, r, &r->range, offset, length);
}

/* If this function is called with realreq=1, it will spit out
 * the correct headers for a byterange chunk, and set offset and
 * length to the positions they should be.
 *
 * If it is called with realreq=0, it will add to tlength the length
 * it *would* have used with realreq=1.
 *
 * Either case will return 1 if it should be called again, and 0
 * when done.
 */
static int internal_byterange(int realreq, long *tlength, request_rec *r,
                              const char **r_range, apr_off_t *offset,
			      apr_size_t *length)
{
    long range_start, range_end;
    char *range;
#ifdef APACHE_XLATE
    /* determine current translation handle, set to the one for
     * protocol strings, and reset to original setting before
     * returning
     */
    AP_PUSH_OUTPUTCONVERSION_STATE(r->connection->client,
                                   ap_hdrs_to_ascii);
#endif /*APACHE_XLATE*/

    if (!**r_range) {
        if (r->byterange > 1) {
            if (realreq) {
                /* ### this isn't "content" so we can't use ap_rvputs(), but
                 * ### it should be processed by non-processing filters. We
                 * ### have no "in-between" APIs yet, so send it to the
                 * ### network for now
                 */
                (void) checked_bputstrs(r, CRLF "--", r->boundary, "--" CRLF,
                                        NULL);
            } else {
                *tlength += 4 + strlen(r->boundary) + 4;
            }
        }
#ifdef APACHE_XLATE
        AP_POP_OUTPUTCONVERSION_STATE(r->connection->client);
#endif /*APACHE_XLATE*/
        return 0;
    }

    range = ap_getword(r->pool, r_range, ',');
    if (!parse_byterange(range, r->clength, &range_start, &range_end))
#ifdef APACHE_XLATE
        AP_POP_OUTPUTCONVERSION_STATE(r->connection->client);
#endif /*APACHE_XLATE*/
        /* Skip this one */
        return internal_byterange(realreq, tlength, r, r_range, offset,
                                  length);

    if (r->byterange > 1) {
        const char *ct = make_content_type(r, r->content_type);
        char ts[MAX_STRING_LEN];

        apr_snprintf(ts, sizeof(ts), "%ld-%ld/%ld", range_start, range_end,
                    r->clength);
        if (realreq)
            (void) checked_bputstrs(r, CRLF "--", r->boundary,
                                    CRLF "Content-type: ", ct,
                                    CRLF "Content-range: bytes ", ts,
                                    CRLF CRLF, NULL);
        else
            *tlength += 4 + strlen(r->boundary) + 16 + strlen(ct) + 23 +
                        strlen(ts) + 4;
    }

    if (realreq) {
        *offset = range_start;
        *length = range_end - range_start + 1;
    }
    else {
        *tlength += range_end - range_start + 1;
    }
#ifdef APACHE_XLATE
    AP_POP_OUTPUTCONVERSION_STATE(r->connection->client);
#endif /*APACHE_XLATE*/
    return 1;
}

API_EXPORT(int) ap_set_content_length(request_rec *r, long clength)
{
    r->clength = clength;
    apr_table_setn(r->headers_out, "Content-Length", apr_psprintf(r->pool, "%ld", clength));
    return 0;
}

API_EXPORT(int) ap_set_keepalive(request_rec *r)
{
    int ka_sent = 0;
    int wimpy = ap_find_token(r->pool,
                           apr_table_get(r->headers_out, "Connection"), "close");
    const char *conn = apr_table_get(r->headers_in, "Connection");

#ifdef APACHE_XLATE
    if (r->rrx->to_net && !r->rrx->to_net_sb) {
        /* Translation is not single-byte-only, so we don't know the
         * content length. Zap the Content-Length header before the 
         * following logic, as the absence of the Content-Length header
         * may affect the decision on chunked encoding.
         */
        apr_table_unset(r->headers_out,"Content-Length");
    }
#endif /* APACHE_XLATE */

    /* The following convoluted conditional determines whether or not
     * the current connection should remain persistent after this response
     * (a.k.a. HTTP Keep-Alive) and whether or not the output message
     * body should use the HTTP/1.1 chunked transfer-coding.  In English,
     *
     *   IF  we have not marked this connection as errored;
     *   and the response body has a defined length due to the status code
     *       being 304 or 204, the request method being HEAD, already
     *       having defined Content-Length or Transfer-Encoding: chunked, or
     *       the request version being HTTP/1.1 and thus capable of being set
     *       as chunked [we know the (r->chunked = 1) side-effect is ugly];
     *   and the server configuration enables keep-alive;
     *   and the server configuration has a reasonable inter-request timeout;
     *   and there is no maximum # requests or the max hasn't been reached;
     *   and the response status does not require a close;
     *   and the response generator has not already indicated close;
     *   and the client did not request non-persistence (Connection: close);
     *   and    we haven't been configured to ignore the buggy twit
     *       or they're a buggy twit coming through a HTTP/1.1 proxy
     *   and    the client is requesting an HTTP/1.0-style keep-alive
     *       or the client claims to be HTTP/1.1 compliant (perhaps a proxy);
     *   THEN we can be persistent, which requires more headers be output.
     *
     * Note that the condition evaluation order is extremely important.
     */
    if ((r->connection->keepalive != -1) &&
        ((r->status == HTTP_NOT_MODIFIED) ||
         (r->status == HTTP_NO_CONTENT) ||
         r->header_only ||
         apr_table_get(r->headers_out, "Content-Length") ||
         ap_find_last_token(r->pool,
                         apr_table_get(r->headers_out, "Transfer-Encoding"),
                         "chunked") ||
         ((r->proto_num >= HTTP_VERSION(1,1)) &&
	  (r->chunked = 1))) && /* THIS CODE IS CORRECT, see comment above. */
        r->server->keep_alive &&
        (r->server->keep_alive_timeout > 0) &&
        ((r->server->keep_alive_max == 0) ||
         (r->server->keep_alive_max > r->connection->keepalives)) &&
        !ap_status_drops_connection(r->status) &&
        !wimpy &&
        !ap_find_token(r->pool, conn, "close") &&
        (!apr_table_get(r->subprocess_env, "nokeepalive") ||
         apr_table_get(r->headers_in, "Via")) &&
        ((ka_sent = ap_find_token(r->pool, conn, "keep-alive")) ||
         (r->proto_num >= HTTP_VERSION(1,1)))
       ) {
        int left = r->server->keep_alive_max - r->connection->keepalives;

        r->connection->keepalive = 1;
        r->connection->keepalives++;

        /* If they sent a Keep-Alive token, send one back */
        if (ka_sent) {
            if (r->server->keep_alive_max)
		apr_table_setn(r->headers_out, "Keep-Alive",
		    apr_psprintf(r->pool, "timeout=%d, max=%d",
                            r->server->keep_alive_timeout, left));
            else
		apr_table_setn(r->headers_out, "Keep-Alive",
		    apr_psprintf(r->pool, "timeout=%d",
                            r->server->keep_alive_timeout));
            apr_table_mergen(r->headers_out, "Connection", "Keep-Alive");
        }

        return 1;
    }

    /* Otherwise, we need to indicate that we will be closing this
     * connection immediately after the current response.
     *
     * We only really need to send "close" to HTTP/1.1 clients, but we
     * always send it anyway, because a broken proxy may identify itself
     * as HTTP/1.0, but pass our request along with our HTTP/1.1 tag
     * to a HTTP/1.1 client. Better safe than sorry.
     */
    if (!wimpy)
	apr_table_mergen(r->headers_out, "Connection", "close");

    r->connection->keepalive = 0;

    return 0;
}

/*
 * Return the latest rational time from a request/mtime (modification time)
 * pair.  We return the mtime unless it's in the future, in which case we
 * return the current time.  We use the request time as a reference in order
 * to limit the number of calls to time().  We don't check for futurosity
 * unless the mtime is at least as new as the reference.
 */
API_EXPORT(apr_time_t) ap_rationalize_mtime(request_rec *r, apr_time_t mtime)
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
    now = (mtime < r->request_time) ? r->request_time : apr_now();
    return (mtime > now) ? now : mtime;
}

API_EXPORT(int) ap_meets_conditions(request_rec *r)
{
    const char *etag = apr_table_get(r->headers_out, "ETag");
    const char *if_match, *if_modified_since, *if_unmodified, *if_nonematch;
    apr_time_t mtime;

    /* Check for conditional requests --- note that we only want to do
     * this if we are successful so far and we are not processing a
     * subrequest or an ErrorDocument.
     *
     * The order of the checks is important, since ETag checks are supposed
     * to be more accurate than checks relative to the modification time.
     * However, not all documents are guaranteed to *have* ETags, and some
     * might have Last-Modified values w/o ETags, so this gets a little
     * complicated.
     */

    if (!ap_is_HTTP_SUCCESS(r->status) || r->no_local_copy) {
        return OK;
    }

    /* XXX: we should define a "time unset" constant */
    mtime = (r->mtime != 0) ? r->mtime : apr_now();

    /* If an If-Match request-header field was given
     * AND the field value is not "*" (meaning match anything)
     * AND if our strong ETag does not match any entity tag in that field,
     *     respond with a status of 412 (Precondition Failed).
     */
    if ((if_match = apr_table_get(r->headers_in, "If-Match")) != NULL) {
        if (if_match[0] != '*' &&
            (etag == NULL || etag[0] == 'W' ||
             !ap_find_list_item(r->pool, if_match, etag))) {
            return HTTP_PRECONDITION_FAILED;
        }
    }
    else {
        /* Else if a valid If-Unmodified-Since request-header field was given
         * AND the requested resource has been modified since the time
         * specified in this field, then the server MUST
         *     respond with a status of 412 (Precondition Failed).
         */
        if_unmodified = apr_table_get(r->headers_in, "If-Unmodified-Since");
        if (if_unmodified != NULL) {
            apr_time_t ius = ap_parseHTTPdate(if_unmodified);

            if ((ius != BAD_DATE) && (mtime > ius)) {
                return HTTP_PRECONDITION_FAILED;
            }
        }
    }

    /* If an If-None-Match request-header field was given
     * AND the field value is "*" (meaning match anything)
     *     OR our ETag matches any of the entity tags in that field, fail.
     *
     * If the request method was GET or HEAD, failure means the server
     *    SHOULD respond with a 304 (Not Modified) response.
     * For all other request methods, failure means the server MUST
     *    respond with a status of 412 (Precondition Failed).
     *
     * GET or HEAD allow weak etag comparison, all other methods require
     * strong comparison.  We can only use weak if it's not a range request.
     */
    if_nonematch = apr_table_get(r->headers_in, "If-None-Match");
    if (if_nonematch != NULL) {
        if (r->method_number == M_GET) {
            if (if_nonematch[0] == '*')
                return HTTP_NOT_MODIFIED;
            if (etag != NULL) {
                if (apr_table_get(r->headers_in, "Range")) {
                    if (etag[0] != 'W' &&
                        ap_find_list_item(r->pool, if_nonematch, etag)) {
                        return HTTP_NOT_MODIFIED;
                    }
                }
                else if (ap_strstr_c(if_nonematch, etag)) {
                    return HTTP_NOT_MODIFIED;
                }
            }
        }
        else if (if_nonematch[0] == '*' ||
                 (etag != NULL &&
                  ap_find_list_item(r->pool, if_nonematch, etag))) {
            return HTTP_PRECONDITION_FAILED;
        }
    }
    /* Else if a valid If-Modified-Since request-header field was given
     * AND it is a GET or HEAD request
     * AND the requested resource has not been modified since the time
     * specified in this field, then the server MUST
     *    respond with a status of 304 (Not Modified).
     * A date later than the server's current request time is invalid.
     */
    else if ((r->method_number == M_GET)
             && ((if_modified_since =
                  apr_table_get(r->headers_in, "If-Modified-Since")) != NULL)) {
        apr_time_t ims = ap_parseHTTPdate(if_modified_since);

	if ((ims >= mtime) && (ims <= r->request_time)) {
            return HTTP_NOT_MODIFIED;
        }
    }
    return OK;
}

/*
 * Construct an entity tag (ETag) from resource information.  If it's a real
 * file, build in some of the file characteristics.  If the modification time
 * is newer than (request-time minus 1 second), mark the ETag as weak - it
 * could be modified again in as short an interval.  We rationalize the
 * modification time we're given to keep it from being in the future.
 */
API_EXPORT(char *) ap_make_etag(request_rec *r, int force_weak)
{
    char *etag;
    char *weak;

    /*
     * Make an ETag header out of various pieces of information. We use
     * the last-modified date and, if we have a real file, the
     * length and inode number - note that this doesn't have to match
     * the content-length (i.e. includes), it just has to be unique
     * for the file.
     *
     * If the request was made within a second of the last-modified date,
     * we send a weak tag instead of a strong one, since it could
     * be modified again later in the second, and the validation
     * would be incorrect.
     */
    
    weak = ((r->request_time - r->mtime > AP_USEC_PER_SEC) && !force_weak) ? "" : "W/";

    if (r->finfo.protection != 0) {
        etag = apr_psprintf(r->pool,
                    "%s\"%lx-%lx-%lx\"", weak,
                    (unsigned long) r->finfo.inode,
                    (unsigned long) r->finfo.size,
                    (unsigned long) r->mtime);
    }
    else {
        etag = apr_psprintf(r->pool, "%s\"%lx\"", weak,
                    (unsigned long) r->mtime);
    }

    return etag;
}

API_EXPORT(void) ap_set_etag(request_rec *r)
{
    char *etag;
    char *variant_etag, *vlv;
    int vlv_weak;

    if (!r->vlist_validator) {
        etag = ap_make_etag(r, 0);
    }
    else {
        /* If we have a variant list validator (vlv) due to the
         * response being negotiated, then we create a structured
         * entity tag which merges the variant etag with the variant
         * list validator (vlv).  This merging makes revalidation
         * somewhat safer, ensures that caches which can deal with
         * Vary will (eventually) be updated if the set of variants is
         * changed, and is also a protocol requirement for transparent
         * content negotiation.
         */

        /* if the variant list validator is weak, we make the whole
         * structured etag weak.  If we would not, then clients could
         * have problems merging range responses if we have different
         * variants with the same non-globally-unique strong etag.
         */

        vlv = r->vlist_validator;
        vlv_weak = (vlv[0] == 'W');
               
        variant_etag = ap_make_etag(r, vlv_weak);

        /* merge variant_etag and vlv into a structured etag */

        variant_etag[strlen(variant_etag) - 1] = '\0';
        if (vlv_weak)
            vlv += 3;
        else
            vlv++;
        etag = apr_pstrcat(r->pool, variant_etag, ";", vlv, NULL);
    }

    apr_table_setn(r->headers_out, "ETag", etag);
}

/*
 * This function sets the Last-Modified output header field to the value
 * of the mtime field in the request structure - rationalized to keep it from
 * being in the future.
 */
API_EXPORT(void) ap_set_last_modified(request_rec *r)
{
    apr_time_t mod_time = ap_rationalize_mtime(r, r->mtime);
    char *datestr = apr_palloc(r->pool, AP_RFC822_DATE_LEN);
    apr_rfc822_date(datestr, mod_time);
    apr_table_setn(r->headers_out, "Last-Modified", datestr);
}

/* Get the method number associated with the given string, assumed to
 * contain an HTTP method.  Returns M_INVALID if not recognized.
 *
 * This is the first step toward placing method names in a configurable
 * list.  Hopefully it (and other routines) can eventually be moved to
 * something like a mod_http_methods.c, complete with config stuff.
 */
API_EXPORT(int) ap_method_number_of(const char *method)
{
    switch (*method) {
        case 'H':
           if (strcmp(method, "HEAD") == 0)
               return M_GET;   /* see header_only in request_rec */
           break;
        case 'G':
           if (strcmp(method, "GET") == 0)
               return M_GET;
           break;
        case 'P':
           if (strcmp(method, "POST") == 0)
               return M_POST;
           if (strcmp(method, "PUT") == 0)
               return M_PUT;
           if (strcmp(method, "PATCH") == 0)
               return M_PATCH;
           if (strcmp(method, "PROPFIND") == 0)
               return M_PROPFIND;
           if (strcmp(method, "PROPPATCH") == 0)
               return M_PROPPATCH;
           break;
        case 'D':
           if (strcmp(method, "DELETE") == 0)
               return M_DELETE;
           break;
        case 'C':
           if (strcmp(method, "CONNECT") == 0)
               return M_CONNECT;
           if (strcmp(method, "COPY") == 0)
               return M_COPY;
           break;
        case 'M':
           if (strcmp(method, "MKCOL") == 0)
               return M_MKCOL;
           if (strcmp(method, "MOVE") == 0)
               return M_MOVE;
           break;
        case 'O':
           if (strcmp(method, "OPTIONS") == 0)
               return M_OPTIONS;
           break;
        case 'T':
           if (strcmp(method, "TRACE") == 0)
               return M_TRACE;
           break;
        case 'L':
           if (strcmp(method, "LOCK") == 0)
               return M_LOCK;
           break;
        case 'U':
           if (strcmp(method, "UNLOCK") == 0)
               return M_UNLOCK;
           break;
    }
    return M_INVALID;
}

/* Get a line of protocol input, including any continuation lines
 * caused by MIME folding (or broken clients) if fold != 0, and place it
 * in the buffer s, of size n bytes, without the ending newline.
 *
 * Returns -1 on error, or the length of s.
 *
 * Note: Because bgets uses 1 char for newline and 1 char for NUL,
 *       the most we can get is (n - 2) actual characters if it
 *       was ended by a newline, or (n - 1) characters if the line
 *       length exceeded (n - 1).  So, if the result == (n - 1),
 *       then the actual input line exceeded the buffer length,
 *       and it would be a good idea for the caller to puke 400 or 414.
 */
static int getline(char *s, int n, BUFF *in, int fold)
{
    char *pos, next;
    int retval;
    int total = 0;
#ifdef APACHE_XLATE
    /* When getline() is called, the HTTP protocol is in a state
     * where we MUST be reading "plain text" protocol stuff,
     * (Request line, MIME headers, Chunk sizes) regardless of
     * the MIME type and conversion setting of the document itself.
     * Save the current setting of the translation handle for
     * uploads, then temporarily set it to the one used for headers
     * (and restore it before returning).
     */
    AP_PUSH_INPUTCONVERSION_STATE(in, ap_hdrs_from_ascii);
#endif /*APACHE_XLATE*/

    pos = s;

    do {
        retval = ap_bgets(pos, n, in);
       /* retval == -1 if error, 0 if EOF */

        if (retval <= 0) {
            total = ((retval < 0) && (total == 0)) ? -1 : total;
            break;
        }

        /* retval is the number of characters read, not including NUL      */

        n -= retval;            /* Keep track of how much of s is full     */
        pos += (retval - 1);    /* and where s ends                        */
        total += retval;        /* and how long s has become               */

        if (*pos == '\n') {     /* Did we get a full line of input?        */
            /*
             * Trim any extra trailing spaces or tabs except for the first
             * space or tab at the beginning of a blank string.  This makes
             * it much easier to check field values for exact matches, and
             * saves memory as well.  Terminate string at end of line.
             */
            while (pos > (s + 1) && (*(pos - 1) == ' ' || *(pos - 1) == '\t')) {
                --pos;          /* trim extra trailing spaces or tabs      */
                --total;        /* but not one at the beginning of line    */
                ++n;
            }
            *pos = '\0';
            --total;
            ++n;
        }
        else
            break;       /* if not, input line exceeded buffer size */

        /* Continue appending if line folding is desired and
         * the last line was not empty and we have room in the buffer and
         * the next line begins with a continuation character.
         */
    } while (fold && (retval != 1) && (n > 1)
                  && (next = ap_blookc(in))
                  && ((next == ' ') || (next == '\t')));

#ifdef APACHE_XLATE
    /* restore translation handle */
    AP_POP_INPUTCONVERSION_STATE(in);
#endif /*APACHE_XLATE*/

    return total;
}

/* parse_uri: break apart the uri
 * Side Effects:
 * - sets r->args to rest after '?' (or NULL if no '?')
 * - sets r->uri to request uri (without r->args part)
 * - sets r->hostname (if not set already) from request (scheme://host:port)
 */
CORE_EXPORT(void) ap_parse_uri(request_rec *r, const char *uri)
{
    int status = HTTP_OK;

    r->unparsed_uri = apr_pstrdup(r->pool, uri);

    if (r->method_number == M_CONNECT) {
	status = ap_parse_hostinfo_components(r->pool, uri, &r->parsed_uri);
    } else {
	/* Simple syntax Errors in URLs are trapped by parse_uri_components(). */
	status = ap_parse_uri_components(r->pool, uri, &r->parsed_uri);
    }

    if (ap_is_HTTP_SUCCESS(status)) {
	/* if it has a scheme we may need to do absoluteURI vhost stuff */
	if (r->parsed_uri.scheme
	    && !strcasecmp(r->parsed_uri.scheme, ap_http_method(r))) {
	    r->hostname = r->parsed_uri.hostname;
	} else if (r->method_number == M_CONNECT) {
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
	r->status = status;             /* set error status */
	r->uri = apr_pstrdup(r->pool, uri);
    }
}

static int read_request_line(request_rec *r)
{
    char l[DEFAULT_LIMIT_REQUEST_LINE + 2]; /* getline's two extra for \n\0 */
    const char *ll = l;
    const char *uri;
    conn_rec *conn = r->connection;
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
    ap_bsetflag(conn->client, B_SAFEREAD, 1); 
    ap_bflush(conn->client);
    while ((len = getline(l, sizeof(l), conn->client, 0)) <= 0) {
        if ((len < 0) || ap_bgetflag(conn->client, B_EOF)) {
	    ap_bsetflag(conn->client, B_SAFEREAD, 0);
	    /* this is a hack to make sure that request time is set,
	     * it's not perfect, but it's better than nothing 
	     */
	    r->request_time = apr_now();
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

    ap_bsetflag(conn->client, B_SAFEREAD, 0);

    r->request_time = apr_now();
    r->the_request = apr_pstrdup(r->pool, l);
    r->method = ap_getword_white(r->pool, &ll);
    ap_update_connection_status(conn->id, "Method", r->method);
    uri = ap_getword_white(r->pool, &ll);

    /* Provide quick information about the request method as soon as known */

    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_GET && r->method[0] == 'H') {
        r->header_only = 1;
    }

    ap_parse_uri(r, uri);

    /* getline returns (size of max buffer - 1) if it fills up the
     * buffer before finding the end-of-line.  This is only going to
     * happen if it exceeds the configured limit for a request-line.
     */
    if (len > r->server->limit_req_line) {
        r->status    = HTTP_REQUEST_URI_TOO_LARGE;
        r->proto_num = HTTP_VERSION(1,0);
        r->protocol  = apr_pstrdup(r->pool, "HTTP/1.0");
        return 0;
    }

    r->assbackwards = (ll[0] == '\0');
    r->protocol = apr_pstrdup(r->pool, ll[0] ? ll : "HTTP/0.9");
    ap_update_connection_status(conn->id, "Protocol", r->protocol);

    if (2 == sscanf(r->protocol, "HTTP/%u.%u", &major, &minor)
      && minor < HTTP_VERSION(1,0))	/* don't allow HTTP/0.1000 */
	r->proto_num = HTTP_VERSION(major, minor);
    else
	r->proto_num = HTTP_VERSION(1,0);

    return 1;
}

static void get_mime_headers(request_rec *r)
{
    char field[DEFAULT_LIMIT_REQUEST_FIELDSIZE + 2]; /* getline's two extra */
    conn_rec *c = r->connection;
    char *value;
    char *copy;
    int len;
    unsigned int fields_read = 0;
    apr_table_t *tmp_headers;

    /* We'll use apr_overlap_tables later to merge these into r->headers_in. */
    tmp_headers = apr_make_table(r->pool, 50);

    /*
     * Read header lines until we get the empty separator line, a read error,
     * the connection closes (EOF), reach the server limit, or we timeout.
     */
    while ((len = getline(field, sizeof(field), c->client, 1)) > 0) {

        if (r->server->limit_req_fields &&
            (++fields_read > r->server->limit_req_fields)) {
            r->status = HTTP_BAD_REQUEST;
            apr_table_setn(r->notes, "error-notes",
                          "The number of request header fields exceeds "
                          "this server's limit.<P>\n");
            return;
        }
        /* getline returns (size of max buffer - 1) if it fills up the
         * buffer before finding the end-of-line.  This is only going to
         * happen if it exceeds the configured limit for a field size.
         */
        if (len > r->server->limit_req_fieldsize) {
            r->status = HTTP_BAD_REQUEST;
            apr_table_setn(r->notes, "error-notes", apr_pstrcat(r->pool,
                "Size of a request header field exceeds server limit.<P>\n"
                "<PRE>\n", ap_escape_html(r->pool, field), "</PRE>\n", NULL));
            return;
        }
        copy = apr_palloc(r->pool, len + 1);
        memcpy(copy, field, len + 1);

        if (!(value = strchr(copy, ':'))) {     /* Find the colon separator */
            r->status = HTTP_BAD_REQUEST;       /* or abort the bad request */
            apr_table_setn(r->notes, "error-notes", apr_pstrcat(r->pool,
                "Request header field is missing colon separator.<P>\n"
                "<PRE>\n", ap_escape_html(r->pool, copy), "</PRE>\n", NULL));
            return;
        }

        *value = '\0';
        ++value;
        while (*value == ' ' || *value == '\t')
            ++value;            /* Skip to start of value   */

	apr_table_addn(tmp_headers, copy, value);
    }

    apr_overlap_tables(r->headers_in, tmp_headers, AP_OVERLAP_TABLES_MERGE);
}

request_rec *ap_read_request(conn_rec *conn)
{
    request_rec *r;
    apr_pool_t *p;
    const char *expect;
    int access_status;

    apr_create_pool(&p, conn->pool);
    r = apr_pcalloc(p, sizeof(request_rec));
    r->pool            = p;
    r->connection      = conn;
    r->server          = conn->base_server;

    conn->keptalive    = conn->keepalive == 1;
    conn->keepalive    = 0;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->headers_in      = apr_make_table(r->pool, 50);
    r->subprocess_env  = apr_make_table(r->pool, 50);
    r->headers_out     = apr_make_table(r->pool, 12);
    r->err_headers_out = apr_make_table(r->pool, 5);
    r->notes           = apr_make_table(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_REQUEST_TIME_OUT;  /* Until we get a request */
    r->the_request     = NULL;

#ifdef APACHE_XLATE
    r->rrx = apr_pcalloc(p, sizeof(struct ap_rr_xlate));
    ap_set_content_xlate(r, 1, ap_locale_to_ascii);
    ap_set_content_xlate(r, 0, ap_locale_from_ascii);
#endif /*APACHE_XLATE*/

    ap_bsetopt(conn->client, BO_TIMEOUT,
               conn->keptalive
               ? &r->server->keep_alive_timeout
               : &r->server->timeout);

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
    if (r->connection->keptalive) {
        ap_bsetopt(r->connection->client, BO_TIMEOUT,
            &r->server->timeout);
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

    conn->keptalive = 0;        /* We now have a request to play with */

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
                      "(see RFC2068 section 9, and 14.23): %s", r->uri);
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
    rnew->subprocess_env  = apr_copy_table(rnew->pool, r->subprocess_env);
    rnew->headers_out     = apr_make_table(rnew->pool, 5);
    rnew->err_headers_out = apr_make_table(rnew->pool, 5);
    rnew->notes           = apr_make_table(rnew->pool, 5);

    rnew->expecting_100   = r->expecting_100;
    rnew->read_length     = r->read_length;
    rnew->read_body       = REQUEST_NO_BODY;

    rnew->main = (request_rec *) r;
}

static void end_output_stream(request_rec *r)
{
    /*
    ** ### place holder to tell filters that no more content will be
    ** ### arriving. typically, they will flush any pending content
    */
}

void ap_finalize_sub_req_protocol(request_rec *sub)
{
    /* tell the filter chain there is no more content coming */
    end_output_stream(sub);

    SET_BYTES_SENT(sub->main);
}

/*
 * Support for the Basic authentication protocol, and a bit for Digest.
 */

API_EXPORT(void) ap_note_auth_failure(request_rec *r)
{
    if (!strcasecmp(ap_auth_type(r), "Basic"))
        ap_note_basic_auth_failure(r);
    else if (!strcasecmp(ap_auth_type(r), "Digest"))
        ap_note_digest_auth_failure(r);
}

API_EXPORT(void) ap_note_basic_auth_failure(request_rec *r)
{
    if (strcasecmp(ap_auth_type(r), "Basic"))
        ap_note_auth_failure(r);
    else
        apr_table_setn(r->err_headers_out,
                  r->proxyreq ? "Proxy-Authenticate" : "WWW-Authenticate",
                  apr_pstrcat(r->pool, "Basic realm=\"", ap_auth_name(r), "\"",
                          NULL));
}

API_EXPORT(void) ap_note_digest_auth_failure(request_rec *r)
{
    apr_table_setn(r->err_headers_out,
	    r->proxyreq ? "Proxy-Authenticate" : "WWW-Authenticate",
	    apr_psprintf(r->pool, "Digest realm=\"%s\", nonce=\"%llx\"",
		ap_auth_name(r), r->request_time));
}

API_EXPORT(int) ap_get_basic_auth_pw(request_rec *r, const char **pw)
{
    const char *auth_line = apr_table_get(r->headers_in,
                                      r->proxyreq ? "Proxy-Authorization"
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

    /* APACHE_XLATE Issue's here ?!? Compare with 32/9 instead
     * as we are operating on an octed stream ?
     */
    while (*auth_line== ' ' || *auth_line== '\t')
        auth_line++;

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

/* New Apache routine to map status codes into array indicies
 *  e.g.  100 -> 0,  101 -> 1,  200 -> 2 ...
 * The number of status lines must equal the value of RESPONSE_CODES (httpd.h)
 * and must be listed in order.
 */

#ifdef UTS21
/* The second const triggers an assembler bug on UTS 2.1.
 * Another workaround is to move some code out of this file into another,
 *   but this is easier.  Dave Dykstra, 3/31/99 
 */
static const char * status_lines[RESPONSE_CODES] =
#else
static const char * const status_lines[RESPONSE_CODES] =
#endif
{
    "100 Continue",
    "101 Switching Protocols",
    "102 Processing",
#define LEVEL_200  3
    "200 OK",
    "201 Created",
    "202 Accepted",
    "203 Non-Authoritative Information",
    "204 No Content",
    "205 Reset Content",
    "206 Partial Content",
    "207 Multi-Status",
#define LEVEL_300 11
    "300 Multiple Choices",
    "301 Moved Permanently",
    "302 Found",
    "303 See Other",
    "304 Not Modified",
    "305 Use Proxy",
    "306 unused",
    "307 Temporary Redirect",
#define LEVEL_400 19
    "400 Bad Request",
    "401 Authorization Required",
    "402 Payment Required",
    "403 Forbidden",
    "404 Not Found",
    "405 Method Not Allowed",
    "406 Not Acceptable",
    "407 Proxy Authentication Required",
    "408 Request Time-out",
    "409 Conflict",
    "410 Gone",
    "411 Length Required",
    "412 Precondition Failed",
    "413 Request Entity Too Large",
    "414 Request-URI Too Large",
    "415 Unsupported Media Type",
    "416 Requested Range Not Satisfiable",
    "417 Expectation Failed",
    "418 unused",
    "419 unused",
    "420 unused",
    "421 unused",
    "422 Unprocessable Entity",
    "423 Locked",
    "424 Failed Dependency",
#define LEVEL_500 44
    "500 Internal Server Error",
    "501 Method Not Implemented",
    "502 Bad Gateway",
    "503 Service Temporarily Unavailable",
    "504 Gateway Time-out",
    "505 HTTP Version Not Supported",
    "506 Variant Also Negotiates",
    "507 Insufficient Storage",
    "508 unused",
    "509 unused",
    "510 Not Extended"
};

/* The index is found by its offset from the x00 code of each level.
 * Although this is fast, it will need to be replaced if some nutcase
 * decides to define a high-numbered code before the lower numbers.
 * If that sad event occurs, replace the code below with a linear search
 * from status_lines[shortcut[i]] to status_lines[shortcut[i+1]-1];
 */
API_EXPORT(int) ap_index_of_response(int status)
{
    static int shortcut[6] = {0, LEVEL_200, LEVEL_300, LEVEL_400,
    LEVEL_500, RESPONSE_CODES};
    int i, pos;

    if (status < 100)           /* Below 100 is illegal for HTTP status */
        return LEVEL_500;

    for (i = 0; i < 5; i++) {
        status -= 100;
        if (status < 100) {
            pos = (status + shortcut[i]);
            if (pos < shortcut[i + 1])
                return pos;
            else
                return LEVEL_500;       /* status unknown (falls in gap) */
        }
    }
    return LEVEL_500;           /* 600 or above is also illegal */
}

API_EXPORT(const char *) ap_get_status_line(int status)
{
    return status_lines[ap_index_of_response(status)];
}

/* Send a single HTTP header field to the client.  Note that this function
 * is used in calls to table_do(), so their interfaces are co-dependent.
 * In other words, don't change this one without checking table_do in alloc.c.
 * It returns true unless there was a write error of some kind.
 */
API_EXPORT_NONSTD(int) ap_send_header_field(request_rec *r,
    const char *fieldname, const char *fieldval)
{
    return (0 < checked_bputstrs(r, fieldname, ": ", fieldval, CRLF, NULL));
}

API_EXPORT(void) ap_basic_http_header(request_rec *r)
{
    char *protocol;
    char *date = NULL;

    if (r->assbackwards)
        return;

    if (!r->status_line)
        r->status_line = status_lines[ap_index_of_response(r->status)];

    /* mod_proxy is only HTTP/1.0, so avoid sending HTTP/1.1 error response;
     * kluge around broken browsers when indicated by force-response-1.0
     */
    if (r->proxyreq
        || (r->proto_num == HTTP_VERSION(1,0)
            && apr_table_get(r->subprocess_env, "force-response-1.0"))) {

        protocol = "HTTP/1.0";
        r->connection->keepalive = -1;
    }
    else
        protocol = AP_SERVER_PROTOCOL;

#ifdef APACHE_XLATE
    { AP_PUSH_OUTPUTCONVERSION_STATE(r->connection->client,
                                     ap_hdrs_to_ascii);
#endif /*APACHE_XLATE*/

    /* Output the HTTP/1.x Status-Line and the Date and Server fields */

    (void) checked_bputstrs(r, protocol, " ", r->status_line, CRLF, NULL);

    date = apr_palloc(r->pool, AP_RFC822_DATE_LEN);
    apr_rfc822_date(date, r->request_time);
    ap_send_header_field(r, "Date", date);
    ap_send_header_field(r, "Server", ap_get_server_version());

    apr_table_unset(r->headers_out, "Date");        /* Avoid bogosity */
    apr_table_unset(r->headers_out, "Server");
#ifdef APACHE_XLATE
    AP_POP_OUTPUTCONVERSION_STATE(r->connection->client); }
#endif /*APACHE_XLATE*/
}

/* Navigator versions 2.x, 3.x and 4.0 betas up to and including 4.0b2
 * have a header parsing bug.  If the terminating \r\n occur starting
 * at offset 256, 257 or 258 of output then it will not properly parse
 * the headers.  Curiously it doesn't exhibit this problem at 512, 513.
 * We are guessing that this is because their initial read of a new request
 * uses a 256 byte buffer, and subsequent reads use a larger buffer.
 * So the problem might exist at different offsets as well.
 *
 * This should also work on keepalive connections assuming they use the
 * same small buffer for the first read of each new request.
 *
 * At any rate, we check the bytes written so far and, if we are about to
 * tickle the bug, we instead insert a bogus padding header.  Since the bug
 * manifests as a broken image in Navigator, users blame the server.  :(
 * It is more expensive to check the User-Agent than it is to just add the
 * bytes, so we haven't used the BrowserMatch feature here.
 */
static void terminate_header(request_rec *r)
{
    long int bs;

    ap_bgetopt(r->connection->client, BO_BYTECT, &bs);
    if (bs >= 255 && bs <= 257)
        (void) checked_bputs("X-Pad: avoid browser bug" CRLF, r);

    (void) checked_bputs(CRLF, r);  /* Send the terminating empty line */
}

/* Build the Allow field-value from the request handler method mask.
 * Note that we always allow TRACE, since it is handled below.
 */
static char *make_allow(request_rec *r)
{
    return 2 + apr_pstrcat(r->pool,
                   (r->allowed & (1 << M_GET))       ? ", GET, HEAD" : "",
                   (r->allowed & (1 << M_POST))      ? ", POST"      : "",
                   (r->allowed & (1 << M_PUT))       ? ", PUT"       : "",
                   (r->allowed & (1 << M_DELETE))    ? ", DELETE"    : "",
                   (r->allowed & (1 << M_CONNECT))   ? ", CONNECT"   : "",
                   (r->allowed & (1 << M_OPTIONS))   ? ", OPTIONS"   : "",
                   (r->allowed & (1 << M_PATCH))     ? ", PATCH"     : "",
                   (r->allowed & (1 << M_PROPFIND))  ? ", PROPFIND"  : "",
                   (r->allowed & (1 << M_PROPPATCH)) ? ", PROPPATCH" : "",
                   (r->allowed & (1 << M_MKCOL))     ? ", MKCOL"     : "",
                   (r->allowed & (1 << M_COPY))      ? ", COPY"      : "",
                   (r->allowed & (1 << M_MOVE))      ? ", MOVE"      : "",
                   (r->allowed & (1 << M_LOCK))      ? ", LOCK"      : "",
                   (r->allowed & (1 << M_UNLOCK))    ? ", UNLOCK"    : "",
                   ", TRACE",
                   NULL);
}

API_EXPORT(int) ap_send_http_trace(request_rec *r)
{
    int rv;

    /* Get the original request */
    while (r->prev)
        r = r->prev;

    if ((rv = ap_setup_client_block(r, REQUEST_NO_BODY)))
        return rv;

    r->content_type = "message/http";
    ap_send_http_header(r);

    /* Now we recreate the request, and echo it back */

    ap_rvputs(r, r->the_request, CRLF, NULL);

    apr_table_do((int (*) (void *, const char *, const char *))
                ap_send_header_field, (void *) r, r->headers_in, NULL);
    ap_rputs(CRLF, r);

    return OK;
}

int ap_send_http_options(request_rec *r)
{
    const long int zero = 0L;

    if (r->assbackwards)
        return DECLINED;

    ap_basic_http_header(r);

    apr_table_setn(r->headers_out, "Content-Length", "0");
    apr_table_setn(r->headers_out, "Allow", make_allow(r));
    ap_set_keepalive(r);

    apr_table_do((int (*) (void *, const char *, const char *)) ap_send_header_field,
             (void *) r, r->headers_out, NULL);

    terminate_header(r);

    ap_bsetopt(r->connection->client, BO_BYTECT, &zero);

    return OK;
}

/*
 * Here we try to be compatible with clients that want multipart/x-byteranges
 * instead of multipart/byteranges (also see above), as per HTTP/1.1. We
 * look for the Request-Range header (e.g. Netscape 2 and 3) as an indication
 * that the browser supports an older protocol. We also check User-Agent
 * for Microsoft Internet Explorer 3, which needs this as well.
 */
static int use_range_x(request_rec *r)
{
    const char *ua;
    return (apr_table_get(r->headers_in, "Request-Range") ||
            ((ua = apr_table_get(r->headers_in, "User-Agent"))
             && ap_strstr_c(ua, "MSIE 3")));
}

/* This routine is called by apr_table_do and merges all instances of
 * the passed field values into a single array that will be further
 * processed by some later routine.  Originally intended to help split
 * and recombine multiple Vary fields, though it is generic to any field
 * consisting of comma/space-separated tokens.
 */
static int uniq_field_values(void *d, const char *key, const char *val)
{
    apr_array_header_t *values;
    char *start;
    char *e;
    char **strpp;
    int  i;

    values = (apr_array_header_t *)d;

    e = apr_pstrdup(values->cont, val);

    do {
        /* Find a non-empty fieldname */

        while (*e == ',' || ap_isspace(*e)) {
            ++e;
        }
        if (*e == '\0') {
            break;
        }
        start = e;
        while (*e != '\0' && *e != ',' && !ap_isspace(*e)) {
            ++e;
        }
        if (*e != '\0') {
            *e++ = '\0';
        }

        /* Now add it to values if it isn't already represented.
         * Could be replaced by a ap_array_strcasecmp() if we had one.
         */
        for (i = 0, strpp = (char **) values->elts; i < values->nelts;
             ++i, ++strpp) {
            if (*strpp && strcasecmp(*strpp, start) == 0) {
                break;
            }
        }
        if (i == values->nelts) {  /* if not found */
           *(char **)apr_push_array(values) = start;
        }
    } while (*e != '\0');

    return 1;
}

/*
 * Since some clients choke violently on multiple Vary fields, or
 * Vary fields with duplicate tokens, combine any multiples and remove
 * any duplicates.
 */
static void fixup_vary(request_rec *r)
{
    apr_array_header_t *varies;

    varies = apr_make_array(r->pool, 5, sizeof(char *));

    /* Extract all Vary fields from the headers_out, separate each into
     * its comma-separated fieldname values, and then add them to varies
     * if not already present in the array.
     */
    apr_table_do((int (*)(void *, const char *, const char *))uniq_field_values,
		(void *) varies, r->headers_out, "Vary", NULL);

    /* If we found any, replace old Vary fields with unique-ified value */

    if (varies->nelts > 0) {
	apr_table_setn(r->headers_out, "Vary",
		      apr_array_pstrcat(r->pool, varies, ','));
    }
}

API_EXPORT(void) ap_send_http_header(request_rec *r)
{
    int i;
    const long int zero = 0L;
    char *date = NULL;

    if (r->assbackwards) {
        if (!r->main)
            ap_bsetopt(r->connection->client, BO_BYTECT, &zero);
        r->sent_bodyct = 1;
        return;
    }

#ifdef CHARSET_EBCDIC
    /* By default, we convert all content.  ap_checkconv() can decide
     * that conversion shouldn't be performed.  Also, if the content type
     * contains the "magic" prefix for serving raw ascii
     * (text/x-ascii-{plain,html,...}), the type is corrected to the real
     * text/{plain,html,...} type which goes into the headers.
     * This may not seem like the best place to put this call, but doing
     * it here avoids having to call it in every handler (which is
     * particularly hard to do with handlers in modules which aren't
     * part of the Apache httpd distribution).
     */
    ap_checkconv(r);
#endif
      
    /*
     * Now that we are ready to send a response, we need to combine the two
     * header field tables into a single table.  If we don't do this, our
     * later attempts to set or unset a given fieldname might be bypassed.
     */
    if (!ap_is_empty_table(r->err_headers_out))
        r->headers_out = apr_overlay_tables(r->pool, r->err_headers_out,
                                        r->headers_out);

    /*
     * Remove the 'Vary' header field if the client can't handle it.
     * Since this will have nasty effects on HTTP/1.1 caches, force
     * the response into HTTP/1.0 mode.
     */
    if (apr_table_get(r->subprocess_env, "force-no-vary") != NULL) {
	apr_table_unset(r->headers_out, "Vary");
	r->proto_num = HTTP_VERSION(1,0);
	apr_table_set(r->subprocess_env, "force-response-1.0", "1");
    }
    else {
	fixup_vary(r);
    }

    ap_basic_http_header(r);

#ifdef APACHE_XLATE
    { AP_PUSH_OUTPUTCONVERSION_STATE(r->connection->client,
                                     ap_hdrs_to_ascii);
#endif /*APACHE_XLATE*/

    ap_set_keepalive(r);

    if (r->chunked) {
        apr_table_mergen(r->headers_out, "Transfer-Encoding", "chunked");
        apr_table_unset(r->headers_out, "Content-Length");
    }

    if (r->byterange > 1)
        apr_table_setn(r->headers_out, "Content-Type",
                  apr_pstrcat(r->pool, "multipart", use_range_x(r) ? "/x-" : "/",
                          "byteranges; boundary=", r->boundary, NULL));
    else apr_table_setn(r->headers_out, "Content-Type", make_content_type(r, 
	r->content_type));

    if (r->content_encoding)
        apr_table_setn(r->headers_out, "Content-Encoding", r->content_encoding);

    if (r->content_languages && r->content_languages->nelts) {
        for (i = 0; i < r->content_languages->nelts; ++i) {
            apr_table_mergen(r->headers_out, "Content-Language",
                        ((char **) (r->content_languages->elts))[i]);
        }
    }
    else if (r->content_language)
        apr_table_setn(r->headers_out, "Content-Language", r->content_language);

    /*
     * Control cachability for non-cachable responses if not already set by
     * some other part of the server configuration.
     */
    if (r->no_cache && !apr_table_get(r->headers_out, "Expires")) {
	date = apr_palloc(r->pool, AP_RFC822_DATE_LEN);
        apr_rfc822_date(date, r->request_time);
        apr_table_addn(r->headers_out, "Expires", date);
    }

    /* Send the entire apr_table_t of header fields, terminated by an empty line. */

    apr_table_do((int (*) (void *, const char *, const char *)) ap_send_header_field,
             (void *) r, r->headers_out, NULL);

    terminate_header(r);


    ap_bsetopt(r->connection->client, BO_BYTECT, &zero);
    r->sent_bodyct = 1;         /* Whatever follows is real body stuff... */

    /* Set buffer flags for the body */
    if (r->chunked)
        ap_bsetflag(r->connection->client, B_CHUNK, 1);
#ifdef APACHE_XLATE
    AP_POP_OUTPUTCONVERSION_STATE(r->connection->client); }
#endif /*APACHE_XLATE*/
}

/* finalize_request_protocol is called at completion of sending the
 * response.  It's sole purpose is to send the terminating protocol
 * information for any wrappers around the response message body
 * (i.e., transfer encodings).  It should have been named finalize_response.
 */
API_EXPORT(void) ap_finalize_request_protocol(request_rec *r)
{
    /* tell the filter chain there is no more content coming */
    end_output_stream(r);

    if (r->chunked && !r->connection->aborted) {
#ifdef APACHE_XLATE
	AP_PUSH_OUTPUTCONVERSION_STATE(r->connection->client,
                                       ap_hdrs_to_ascii);
#endif
        /*
         * Turn off chunked encoding --- we can only do this once.
         */
        r->chunked = 0;
        ap_bsetflag(r->connection->client, B_CHUNK, 0);

        (void) checked_bputs("0" CRLF, r);

        /* If we had footer "headers", we'd send them now */
        /* ### these need to be added to allow message digests */

        (void) checked_bputs(CRLF, r);

#ifdef APACHE_XLATE
	AP_POP_OUTPUTCONVERSION_STATE(r->connection->client);
#endif /*APACHE_XLATE*/
    }
}

/* Here we deal with getting the request message body from the client.
 * Whether or not the request contains a body is signaled by the presence
 * of a non-zero Content-Length or by a Transfer-Encoding: chunked.
 *
 * Note that this is more complicated than it was in Apache 1.1 and prior
 * versions, because chunked support means that the module does less.
 *
 * The proper procedure is this:
 *
 * 1. Call setup_client_block() near the beginning of the request
 *    handler. This will set up all the necessary properties, and will
 *    return either OK, or an error code. If the latter, the module should
 *    return that error code. The second parameter selects the policy to
 *    apply if the request message indicates a body, and how a chunked
 *    transfer-coding should be interpreted. Choose one of
 *
 *    REQUEST_NO_BODY          Send 413 error if message has any body
 *    REQUEST_CHUNKED_ERROR    Send 411 error if body without Content-Length
 *    REQUEST_CHUNKED_DECHUNK  If chunked, remove the chunks for me.
 *    REQUEST_CHUNKED_PASS     Pass the chunks to me without removal.
 *
 *    In order to use the last two options, the caller MUST provide a buffer
 *    large enough to hold a chunk-size line, including any extensions.
 *
 * 2. When you are ready to read a body (if any), call should_client_block().
 *    This will tell the module whether or not to read input. If it is 0,
 *    the module should assume that there is no message body to read.
 *    This step also sends a 100 Continue response to HTTP/1.1 clients,
 *    so should not be called until the module is *definitely* ready to
 *    read content. (otherwise, the point of the 100 response is defeated).
 *    Never call this function more than once.
 *
 * 3. Finally, call get_client_block in a loop. Pass it a buffer and its size.
 *    It will put data into the buffer (not necessarily a full buffer), and
 *    return the length of the input block. When it is done reading, it will
 *    return 0 if EOF, or -1 if there was an error.
 *    If an error occurs on input, we force an end to keepalive.
 */

API_EXPORT(int) ap_setup_client_block(request_rec *r, int read_policy)
{
    const char *tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
    const char *lenp = apr_table_get(r->headers_in, "Content-Length");
    unsigned long max_body;

    r->read_body = read_policy;
    r->read_chunked = 0;
    r->remaining = 0;

    if (tenc) {
        if (strcasecmp(tenc, "chunked")) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        "Unknown Transfer-Encoding %s", tenc);
            return HTTP_NOT_IMPLEMENTED;
        }
        if (r->read_body == REQUEST_CHUNKED_ERROR) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        "chunked Transfer-Encoding forbidden: %s", r->uri);
            return (lenp) ? HTTP_BAD_REQUEST : HTTP_LENGTH_REQUIRED;
        }

        r->read_chunked = 1;
    }
    else if (lenp) {
        const char *pos = lenp;

        while (ap_isdigit(*pos) || ap_isspace(*pos))
            ++pos;
        if (*pos != '\0') {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        "Invalid Content-Length %s", lenp);
            return HTTP_BAD_REQUEST;
        }

        r->remaining = atol(lenp);
    }

    if ((r->read_body == REQUEST_NO_BODY) &&
        (r->read_chunked || (r->remaining > 0))) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    "%s with body is not allowed for %s", r->method, r->uri);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    max_body = ap_get_limit_req_body(r);
    if (max_body && (r->remaining > max_body)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
          "Request content-length of %s is larger than the configured "
          "limit of %lu", lenp, max_body);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

#ifdef CHARSET_EBCDIC
    {
        /* @@@ Temporary kludge for guessing the conversion @@@
         * from looking at the MIME header. 
         * If no Content-Type header is found, text conversion is assumed.
         */
        const char *typep = apr_table_get(r->headers_in, "Content-Type");
        int convert_in = (typep == NULL ||
                          strncasecmp(typep, "text/", 5) == 0 ||
                          strncasecmp(typep, "message/", 8) == 0 ||
                          strncasecmp(typep, "multipart/", 10) == 0 ||
                          strcasecmp (typep, "application/x-www-form-urlencoded") == 0
                         );
        /* By default, we translate content on input.  Turn off translation
         * if it isn't text.
         */
        if (!convert_in) {
            ap_set_content_xlate(r, 0, NULL);
        }
    }
#endif /*CHARSET_EBCDIC*/

    return OK;
}

API_EXPORT(int) ap_should_client_block(request_rec *r)
{
    /* First check if we have already read the request body */

    if (r->read_length || (!r->read_chunked && (r->remaining <= 0)))
        return 0;

    if (r->expecting_100 && r->proto_num >= HTTP_VERSION(1,1)) {
        /* sending 100 Continue interim response */
        (void) checked_bputstrs(r, AP_SERVER_PROTOCOL, " ", status_lines[0],
                                CRLF CRLF, NULL);
        (void) checked_bflush(r);
    }

    return 1;
}

static long get_chunk_size(char *b)
{
    long chunksize = 0;

    while (ap_isxdigit(*b)) {
        int xvalue = 0;

        if (*b >= '0' && *b <= '9')
            xvalue = *b - '0';
        else if (*b >= 'A' && *b <= 'F')
            xvalue = *b - 'A' + 0xa;
        else if (*b >= 'a' && *b <= 'f')
            xvalue = *b - 'a' + 0xa;

        chunksize = (chunksize << 4) | xvalue;
        ++b;
    }

    return chunksize;
}

/* get_client_block is called in a loop to get the request message body.
 * This is quite simple if the client includes a content-length
 * (the normal case), but gets messy if the body is chunked. Note that
 * r->remaining is used to maintain state across calls and that
 * r->read_length is the total number of bytes given to the caller
 * across all invocations.  It is messy because we have to be careful not
 * to read past the data provided by the client, since these reads block.
 * Returns 0 on End-of-body, -1 on error or premature chunk end.
 *
 * Reading the chunked encoding requires a buffer size large enough to
 * hold a chunk-size line, including any extensions. For now, we'll leave
 * that to the caller, at least until we can come up with a better solution.
 */
API_EXPORT(long) ap_get_client_block(request_rec *r, char *buffer, int bufsiz)
{
    int c;
    apr_size_t len_to_read;
    apr_ssize_t len_read;
    long chunk_start = 0;
    unsigned long max_body;
    apr_status_t rv;

    if (!r->read_chunked) {     /* Content-length read */
        len_to_read = (r->remaining > bufsiz) ? bufsiz : r->remaining;
        rv = ap_bread(r->connection->client, buffer, len_to_read, &len_read);
        if (len_read == 0) {    /* error or eof */
            if (rv != APR_SUCCESS) {
                r->connection->keepalive = -1;
                return -1;
            }
            return 0;
        }
        r->read_length += len_read;
        r->remaining -= len_read;
        return len_read;
    }

    /*
     * Handle chunked reading Note: we are careful to shorten the input
     * bufsiz so that there will always be enough space for us to add a CRLF
     * (if necessary).
     */
    if (r->read_body == REQUEST_CHUNKED_PASS)
        bufsiz -= 2;
    if (bufsiz <= 0)
        return -1;              /* Cannot read chunked with a small buffer */

    /* Check to see if we have already read too much request data.
     * For efficiency reasons, we only check this at the top of each
     * caller read pass, since the limit exists just to stop infinite
     * length requests and nobody cares if it goes over by one buffer.
     */
    max_body = ap_get_limit_req_body(r);
    if (max_body && (r->read_length > max_body)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
            "Chunked request body is larger than the configured limit of %lu",
            max_body);
        r->connection->keepalive = -1;
        return -1;
    }

    if (r->remaining == 0) {    /* Start of new chunk */

        chunk_start = getline(buffer, bufsiz, r->connection->client, 0);
        if ((chunk_start <= 0) || (chunk_start >= (bufsiz - 1))
            || !ap_isxdigit(*buffer)) {
            r->connection->keepalive = -1;
            return -1;
        }

        len_to_read = get_chunk_size(buffer);

        if (len_to_read == 0) { /* Last chunk indicated, get footers */
            if (r->read_body == REQUEST_CHUNKED_DECHUNK) {
                get_mime_headers(r);
                apr_snprintf(buffer, bufsiz, "%ld", r->read_length);
                apr_table_unset(r->headers_in, "Transfer-Encoding");
                apr_table_setn(r->headers_in, "Content-Length",
                    apr_pstrdup(r->pool, buffer));
                return 0;
            }
            r->remaining = -1;  /* Indicate footers in-progress */
        }
        else {
            r->remaining = len_to_read;
        }
        if (r->read_body == REQUEST_CHUNKED_PASS) {
            buffer[chunk_start++] = CR; /* Restore chunk-size line end  */
            buffer[chunk_start++] = LF;
            buffer += chunk_start;      /* and pass line on to caller   */
            bufsiz -= chunk_start;
        }
        else {
            /* REQUEST_CHUNKED_DECHUNK -- do not include the length of the
             * header in the return value
             */
            chunk_start = 0;
        }
    }
                                /* When REQUEST_CHUNKED_PASS, we are */
    if (r->remaining == -1) {   /* reading footers until empty line  */
        len_read = chunk_start;

        while ((bufsiz > 1) && ((len_read =
                  getline(buffer, bufsiz, r->connection->client, 1)) > 0)) {

            if (len_read != (bufsiz - 1)) {
                buffer[len_read++] = CR;        /* Restore footer line end  */
                buffer[len_read++] = LF;
            }
            chunk_start += len_read;
            buffer += len_read;
            bufsiz -= len_read;
        }
        if (len_read < 0) {
            r->connection->keepalive = -1;
            return -1;
        }

        if (len_read == 0) {    /* Indicates an empty line */
            buffer[0] = CR;
            buffer[1] = LF;
            chunk_start += 2;
            r->remaining = -2;
        }
        r->read_length += chunk_start;
        return chunk_start;
    }
                                /* When REQUEST_CHUNKED_PASS, we     */
    if (r->remaining == -2) {   /* finished footers when last called */
        r->remaining = 0;       /* so now we must signal EOF         */
        return 0;
    }

    /* Otherwise, we are in the midst of reading a chunk of data */

    len_to_read = (r->remaining > bufsiz) ? bufsiz : r->remaining;

    (void) ap_bread(r->connection->client, buffer, len_to_read, &len_read);
    if (len_read == 0) {        /* error or eof */
        r->connection->keepalive = -1;
        return -1;
    }

    r->remaining -= len_read;

    if (r->remaining == 0) {    /* End of chunk, get trailing CRLF */
#ifdef APACHE_XLATE
        /* Chunk end is Protocol stuff! Set conversion = 1 to read CR LF: */
        AP_PUSH_INPUTCONVERSION_STATE(r->connection->client,
                                      ap_hdrs_from_ascii);
#endif /*APACHE_XLATE*/

        if ((c = ap_bgetc(r->connection->client)) == CR) {
            c = ap_bgetc(r->connection->client);
        }

#ifdef APACHE_XLATE
        /* restore previous input translation handle */
        AP_POP_INPUTCONVERSION_STATE(r->connection->client);
#endif /*APACHE_XLATE*/

        if (c != LF) {
            r->connection->keepalive = -1;
            return -1;
        }
        if (r->read_body == REQUEST_CHUNKED_PASS) {
            buffer[len_read++] = CR;
            buffer[len_read++] = LF;
        }
    }
    r->read_length += (chunk_start + len_read);

    return (chunk_start + len_read);
}

/* In HTTP/1.1, any method can have a body.  However, most GET handlers
 * wouldn't know what to do with a request body if they received one.
 * This helper routine tests for and reads any message body in the request,
 * simply discarding whatever it receives.  We need to do this because
 * failing to read the request body would cause it to be interpreted
 * as the next request on a persistent connection.
 *
 * Since we return an error status if the request is malformed, this
 * routine should be called at the beginning of a no-body handler, e.g.,
 *
 *    if ((retval = ap_discard_request_body(r)) != OK)
 *        return retval;
 */
API_EXPORT(int) ap_discard_request_body(request_rec *r)
{
    int rv;

    if ((rv = ap_setup_client_block(r, REQUEST_CHUNKED_PASS)))
        return rv;

    /* In order to avoid sending 100 Continue when we already know the
     * final response status, and yet not kill the connection if there is
     * no request body to be read, we need to duplicate the test from
     * ap_should_client_block() here negated rather than call it directly.
     */
    if ((r->read_length == 0) && (r->read_chunked || (r->remaining > 0))) {
        char dumpbuf[HUGE_STRING_LEN];

        if (r->expecting_100) {
            r->connection->keepalive = -1;
            return OK;
        }

        while ((rv = ap_get_client_block(r, dumpbuf, HUGE_STRING_LEN)) > 0)
            continue;

        if (rv < 0)
            return HTTP_BAD_REQUEST;
    }
    return OK;
}

#if APR_HAS_SENDFILE
static apr_status_t static_send_file(apr_file_t *fd, request_rec *r, apr_off_t offset, 
                                    apr_size_t length, apr_size_t *nbytes) 
{
    apr_int32_t flags = 0;
    apr_status_t rv;
    struct iovec iov;
    apr_hdtr_t hdtr;

    ap_bsetopt(r->connection->client, BO_TIMEOUT,
               r->connection->keptalive
               ? &r->server->keep_alive_timeout
               : &r->server->timeout);

    /*
     * We want to send any data held in the client buffer on the
     * call to iol_sendfile. So hijack it then set outcnt to 0
     * to prevent the data from being sent to the client again
     * when the buffer is flushed to the client at the end of the
     * request.
     */
    iov.iov_base = r->connection->client->outbase;
    iov.iov_len =  r->connection->client->outcnt;
    r->connection->client->outcnt = 0;

    /* initialize the apr_hdtr_t struct */
    hdtr.headers = &iov;
    hdtr.numheaders = 1;
    hdtr.trailers = NULL;
    hdtr.numtrailers = 0;

    if (!r->connection->keepalive) {
        /* Prepare the socket to be reused */
        /* XXX fix me - byteranges? */
        flags |= APR_SENDFILE_DISCONNECT_SOCKET;
    }

    rv = iol_sendfile(r->connection->client->iol, 
                      fd,      /* The file to send */
                      &hdtr,   /* Header and trailer iovecs */
                      &offset, /* Offset in file to begin sending from */
                      &length,
                      flags);

    if (r->connection->keptalive) {
        ap_bsetopt(r->connection->client, BO_TIMEOUT, 
                   &r->server->timeout);
    }

    *nbytes = length;

    return rv;
}
#endif
/*
 * Send the body of a response to the client.
 */
API_EXPORT(apr_status_t) ap_send_fd(apr_file_t *fd, request_rec *r, apr_off_t offset, 
                                   apr_size_t length, apr_size_t *nbytes) 
{
    apr_status_t rv = APR_SUCCESS;
    apr_size_t total_bytes_sent = 0;
    register int o;
    apr_ssize_t n;
    char buf[IOBUFSIZE];

    if ((length == 0) || r->connection->aborted) {
        *nbytes = 0;
        return APR_SUCCESS;
    }

#if APR_HAS_SENDFILE
    /* Chunked encoding must be handled in the BUFF */
    if (!r->chunked) {
        rv = static_send_file(fd, r, offset, length, &total_bytes_sent);
        if (rv == APR_SUCCESS) {
            r->bytes_sent += total_bytes_sent;
            *nbytes = total_bytes_sent;
            return rv;
        }
        /* Don't consider APR_ENOTIMPL a failure */
        if (rv != APR_ENOTIMPL) {
            check_first_conn_error(r, "send_fd", rv);
            r->bytes_sent += total_bytes_sent;
            *nbytes = total_bytes_sent;
            return rv;
        }
    }
#endif

    /* Either sendfile is not defined or it failed with APR_ENOTIMPL */
    if (offset) {
        /* Seek the file to the offset */
        rv = apr_seek(fd, APR_SET, &offset);
        if (rv != APR_SUCCESS) {
            *nbytes = total_bytes_sent;
            /* apr_close(fd); close the file or let the caller handle it? */
            return rv;
        }
    }

    while (!r->connection->aborted) {
        if ((length > 0) && (total_bytes_sent + IOBUFSIZE) > length)
            n = length - total_bytes_sent;
        else
            n = IOBUFSIZE;
        
        do {
            rv = apr_read(fd, buf, &n);
        } while (rv == APR_EINTR && !r->connection->aborted);

        /* Is this still the right check? maybe check for n==0 or rv == APR_EOF? */
        if (n < 1) {
            break;
        }

        o = ap_rwrite(buf, n, r);
        if (o < 0)
            break;
        total_bytes_sent += o;
    }

    SET_BYTES_SENT(r);
    *nbytes = total_bytes_sent;
    return rv;
}

/*
 * Send the body of a response to the client.
 */
API_EXPORT(long) ap_send_fb(BUFF *fb, request_rec *r)
{
    return ap_send_fb_length(fb, r, -1);
}

API_EXPORT(long) ap_send_fb_length(BUFF *fb, request_rec *r, long length)
{
    char buf[IOBUFSIZE];
    long total_bytes_sent = 0;
    long zero_timeout = 0;
    register int o;
    apr_ssize_t n;
    apr_ssize_t bytes_read;
    apr_status_t read_rv;

    if (length == 0) {
        return 0;
    }

    /* This function tries to as much as possible through non-blocking
     * reads so that it can do writes while waiting for the CGI to
     * produce more data. This way, the CGI's output gets to the client
     * as soon as possible */

    ap_bsetopt(fb, BO_TIMEOUT, &zero_timeout);
    while (!r->connection->aborted) {
        read_rv = ap_bread(fb, buf, sizeof(buf), &n);
    got_read:
        bytes_read = n;
        /* Regardless of read errors, EOF, etc, bytes may have been read */
        o = ap_rwrite(buf, n, r);
        if (o < 0)
            break;
        total_bytes_sent += o;
        if (read_rv == APR_SUCCESS) {
            /* Assume a sucessful read of 0 bytes is an EOF 
             * Note: I don't think this is ultimately the right thing.
             * Read functions should explicitly return EOF. 
             * wgs
             */
            if (bytes_read == 0) {
                (void) ap_rflush(r);
                break;
            }
        }
        else if (read_rv == APR_EOF) {
            (void) ap_rflush(r);
            break;
        }
        else if (apr_canonical_error(read_rv) != APR_EAGAIN) {
            r->connection->aborted = 1;
            break;
        }
        else {
            /* next read will block, so flush the client now */
            if (ap_rflush(r) == EOF) {
                break;
            }
            ap_bsetopt(fb, BO_TIMEOUT, &r->server->timeout);
            read_rv = ap_bread(fb, buf, sizeof(buf), &n);
            ap_bsetopt(fb, BO_TIMEOUT, &zero_timeout);
            goto got_read;
        }
    }
    SET_BYTES_SENT(r);
    return total_bytes_sent;
}

#ifdef USE_MMAP_FILES

/* The code writes MMAP_SEGMENT_SIZE bytes at a time.  This is due to Apache's
 * timeout model, which is a timeout per-write rather than a time for the
 * entire transaction to complete.  Essentially this should be small enough
 * so that in one Timeout period, your slowest clients should be reasonably
 * able to receive this many bytes.
 *
 * To take advantage of zero-copy TCP under Solaris 2.6 this should be a
 * multiple of 16k.  (And you need a SunATM2.0 network card.)
 */
#ifndef MMAP_SEGMENT_SIZE
#define MMAP_SEGMENT_SIZE       32768
#endif

/* send data from an in-memory buffer */
API_EXPORT(size_t) ap_send_mmap(apr_mmap_t *mm, request_rec *r, size_t offset,
                             size_t length)
{
    size_t total_bytes_sent = 0;
    int n;
    apr_ssize_t w;
    char *addr;
    
    if (length == 0)
        return 0;


    length += offset;
    while (!r->connection->aborted && offset < length) {
        if (length - offset > MMAP_SEGMENT_SIZE) {
            n = MMAP_SEGMENT_SIZE;
        }
        else {
            n = length - offset;
        }

        apr_mmap_offset((void**)&addr, mm, offset);
        w = ap_rwrite(addr, n, r);
        if (w < 0)
            break;
        total_bytes_sent += w;
        offset += w;
    }

    SET_BYTES_SENT(r);
    return total_bytes_sent;
}
#endif /* USE_MMAP_FILES */

API_EXPORT(int) ap_rputc(int c, request_rec *r)
{
    if (r->connection->aborted)
        return EOF;

    if (ap_bputc(c, r->connection->client) < 0) {
        check_first_conn_error(r, "rputc", 0);
        return EOF;
    }
    SET_BYTES_SENT(r);
    return c;
}

API_EXPORT(int) ap_rputs(const char *str, request_rec *r)
{
    int rcode;

    if (r->connection->aborted)
        return EOF;
    
    rcode = ap_bputs(str, r->connection->client);
    if (rcode < 0) {
        check_first_conn_error(r, "rputs", 0);
        return EOF;
    }
    SET_BYTES_SENT(r);
    return rcode;
}

API_EXPORT(int) ap_rwrite(const void *buf, int nbyte, request_rec *r)
{
    apr_ssize_t n;
    apr_status_t rv;

    if (r->connection->aborted)
        return EOF;

    /* ### should loop to avoid partial writes */
    rv = ap_bwrite(r->connection->client, buf, nbyte, &n);
    if (rv != APR_SUCCESS) {
        check_first_conn_error(r, "rwrite", rv);
        return EOF;
    }
    SET_BYTES_SENT(r);
    return n;
}

API_EXPORT(int) ap_vrprintf(request_rec *r, const char *fmt, va_list va)
{
    int n;

    if (r->connection->aborted)
        return EOF;

    n = ap_vbprintf(r->connection->client, fmt, va);

    if (n < 0) {
        check_first_conn_error(r, "vrprintf", 0);
        return EOF;
    }
    SET_BYTES_SENT(r);
    return n;
}

API_EXPORT_NONSTD(int) ap_rprintf(request_rec *r, const char *fmt, ...)
{
    va_list va;
    int n;

    if (r->connection->aborted)
        return EOF;

    va_start(va, fmt);
    n = ap_vbprintf(r->connection->client, fmt, va);
    va_end(va);

    if (n < 0) {
        check_first_conn_error(r, "rprintf", 0);
        return EOF;
    }
    SET_BYTES_SENT(r);
    return n;
}

API_EXPORT_NONSTD(int) ap_rvputs(request_rec *r, ...)
{
    va_list va;
    int n;

    if (r->connection->aborted)
        return EOF;

    va_start(va, r);
    n = ap_vbputstrs(r->connection->client, va);
    va_end(va);

    if (n < 0) {
        check_first_conn_error(r, "rvputs", 0);
        return EOF;
    }

    SET_BYTES_SENT(r);
    return n;
}

API_EXPORT(int) ap_rflush(request_rec *r)
{
    apr_status_t rv;

    if ((rv = ap_bflush(r->connection->client)) != APR_SUCCESS) {
        check_first_conn_error(r, "rflush", rv);
        return EOF;
    }
    return 0;
}

/* We should have named this send_canned_response, since it is used for any
 * response that can be generated by the server from the request record.
 * This includes all 204 (no content), 3xx (redirect), 4xx (client error),
 * and 5xx (server error) messages that have not been redirected to another
 * handler via the ErrorDocument feature.
 */
API_EXPORT(void) ap_send_error_response(request_rec *r, int recursive_error)
{
    int status = r->status;
    int idx = ap_index_of_response(status);
    char *custom_response;
    const char *location = apr_table_get(r->headers_out, "Location");

    /*
     * It's possible that the Location field might be in r->err_headers_out
     * instead of r->headers_out; use the latter if possible, else the
     * former.
     */
    if (location == NULL) {
	location = apr_table_get(r->err_headers_out, "Location");
    }
    /* We need to special-case the handling of 204 and 304 responses,
     * since they have specific HTTP requirements and do not include a
     * message body.  Note that being assbackwards here is not an option.
     */
    if (status == HTTP_NOT_MODIFIED) {
        if (!ap_is_empty_table(r->err_headers_out))
            r->headers_out = apr_overlay_tables(r->pool, r->err_headers_out,
                                               r->headers_out);
        ap_basic_http_header(r);
        ap_set_keepalive(r);

        apr_table_do((int (*)(void *, const char *, const char *)) ap_send_header_field,
                    (void *) r, r->headers_out,
                    "Connection",
                    "Keep-Alive",
                    "ETag",
                    "Content-Location",
                    "Expires",
                    "Cache-Control",
                    "Vary",
                    "Warning",
                    "WWW-Authenticate",
                    "Proxy-Authenticate",
                    NULL);

        terminate_header(r);

        return;
    }

    if (status == HTTP_NO_CONTENT) {
        ap_send_http_header(r);
        ap_finalize_request_protocol(r);
        return;
    }

    if (!r->assbackwards) {
        apr_table_t *tmp = r->headers_out;

        /* For all HTTP/1.x responses for which we generate the message,
         * we need to avoid inheriting the "normal status" header fields
         * that may have been set by the request handler before the
         * error or redirect, except for Location on external redirects.
         */
        r->headers_out = r->err_headers_out;
        r->err_headers_out = tmp;
        apr_clear_table(r->err_headers_out);

        if (ap_is_HTTP_REDIRECT(status) || (status == HTTP_CREATED)) {
            if ((location != NULL) && *location) {
	        apr_table_setn(r->headers_out, "Location", location);
            }
            else {
                location = "";   /* avoids coredump when printing, below */
            }
        }

        r->content_language = NULL;
        r->content_languages = NULL;
        r->content_encoding = NULL;
        r->clength = 0;
        r->content_type = "text/html; charset=iso-8859-1";

        if ((status == HTTP_METHOD_NOT_ALLOWED)
            || (status == HTTP_NOT_IMPLEMENTED)) {
            apr_table_setn(r->headers_out, "Allow", make_allow(r));
        }

        ap_send_http_header(r);

        if (r->header_only) {
            ap_finalize_request_protocol(r);
            ap_rflush(r);
            return;
        }
    }

#ifdef APACHE_XLATE
    /* Ensure that the proper translation handle (if any) is used when
     * sending the response document to the client.  Note that on an 
     * ASCII machine, ap_hdrs_to_ascii is NULL, so this will turn off 
     * any translation selected by a module for content.
     */
    ap_set_content_xlate(r, 1, ap_hdrs_to_ascii);
#endif

    if ((custom_response = ap_response_code_string(r, idx))) {
        /*
         * We have a custom response output. This should only be
         * a text-string to write back. But if the ErrorDocument
         * was a local redirect and the requested resource failed
         * for any reason, the custom_response will still hold the
         * redirect URL. We don't really want to output this URL
         * as a text message, so first check the custom response
         * string to ensure that it is a text-string (using the
         * same test used in ap_die(), i.e. does it start with a ").
         * If it doesn't, we've got a recursive error, so find
         * the original error and output that as well.
         */
        if (custom_response[0] == '\"') {
            ap_rputs(custom_response + 1, r);
            ap_finalize_request_protocol(r);
            ap_rflush(r);
            return;
        }
        /*
         * Redirect failed, so get back the original error
         */
        while (r->prev && (r->prev->status != HTTP_OK))
            r = r->prev;
    }
    {
        const char *title = status_lines[idx];
        const char *h1;
        const char *error_notes;

        /* Accept a status_line set by a module, but only if it begins
         * with the 3 digit status code
         */
        if (r->status_line != NULL
            && strlen(r->status_line) > 4       /* long enough */
            && ap_isdigit(r->status_line[0])
            && ap_isdigit(r->status_line[1])
            && ap_isdigit(r->status_line[2])
            && ap_isspace(r->status_line[3])
            && ap_isalnum(r->status_line[4])) {
            title = r->status_line;
        }

        /* folks decided they didn't want the error code in the H1 text */
        h1 = &title[4];

        ap_rvputs(r,
                  DOCTYPE_HTML_2_0
                  "<HTML><HEAD>\n<TITLE>", title,
                  "</TITLE>\n</HEAD><BODY>\n<H1>", h1, "</H1>\n",
                  NULL);

	switch (status) {
	case HTTP_MOVED_PERMANENTLY:
	case HTTP_MOVED_TEMPORARILY:
	case HTTP_TEMPORARY_REDIRECT:
	    ap_rvputs(r, "The document has moved <A HREF=\"",
		      ap_escape_html(r->pool, location), "\">here</A>.<P>\n",
		      NULL);
	    break;
	case HTTP_SEE_OTHER:
	    ap_rvputs(r, "The answer to your request is located <A HREF=\"",
		      ap_escape_html(r->pool, location), "\">here</A>.<P>\n",
		      NULL);
	    break;
	case HTTP_USE_PROXY:
	    ap_rvputs(r, "This resource is only accessible "
		      "through the proxy\n",
		      ap_escape_html(r->pool, location),
		      "<BR>\nYou will need to ",
		      "configure your client to use that proxy.<P>\n", NULL);
	    break;
	case HTTP_PROXY_AUTHENTICATION_REQUIRED:
	case HTTP_UNAUTHORIZED:
	    ap_rputs("This server could not verify that you\n"
	             "are authorized to access the document\n"
	             "requested.  Either you supplied the wrong\n"
	             "credentials (e.g., bad password), or your\n"
	             "browser doesn't understand how to supply\n"
	             "the credentials required.<P>\n", r);
	    break;
	case HTTP_BAD_REQUEST:
	    ap_rputs("Your browser sent a request that "
	             "this server could not understand.<P>\n", r);
	    if ((error_notes = apr_table_get(r->notes, "error-notes")) != NULL) {
		ap_rvputs(r, error_notes, "<P>\n", NULL);
	    }
	    break;
	case HTTP_FORBIDDEN:
	    ap_rvputs(r, "You don't have permission to access ",
		      ap_escape_html(r->pool, r->uri),
		      "\non this server.<P>\n", NULL);
	    break;
	case HTTP_NOT_FOUND:
	    ap_rvputs(r, "The requested URL ",
		      ap_escape_html(r->pool, r->uri),
		      " was not found on this server.<P>\n", NULL);
	    break;
	case HTTP_METHOD_NOT_ALLOWED:
	    ap_rvputs(r, "The requested method ", r->method,
		      " is not allowed "
		      "for the URL ", ap_escape_html(r->pool, r->uri),
		      ".<P>\n", NULL);
	    break;
	case HTTP_NOT_ACCEPTABLE:
	    ap_rvputs(r,
		      "An appropriate representation of the "
		      "requested resource ",
		      ap_escape_html(r->pool, r->uri),
		      " could not be found on this server.<P>\n", NULL);
	    /* fall through */
	case HTTP_MULTIPLE_CHOICES:
	    {
		const char *list;
		if ((list = apr_table_get(r->notes, "variant-list")))
		    ap_rputs(list, r);
	    }
	    break;
	case HTTP_LENGTH_REQUIRED:
	    ap_rvputs(r, "A request of the requested method ", r->method,
		      " requires a valid Content-length.<P>\n", NULL);
	    if ((error_notes = apr_table_get(r->notes, "error-notes")) != NULL) {
		ap_rvputs(r, error_notes, "<P>\n", NULL);
	    }
	    break;
	case HTTP_PRECONDITION_FAILED:
	    ap_rvputs(r, "The precondition on the request for the URL ",
		      ap_escape_html(r->pool, r->uri),
		      " evaluated to false.<P>\n", NULL);
	    break;
	case HTTP_NOT_IMPLEMENTED:
	    ap_rvputs(r, ap_escape_html(r->pool, r->method), " to ",
		      ap_escape_html(r->pool, r->uri),
		      " not supported.<P>\n", NULL);
	    if ((error_notes = apr_table_get(r->notes, "error-notes")) != NULL) {
		ap_rvputs(r, error_notes, "<P>\n", NULL);
	    }
	    break;
	case HTTP_BAD_GATEWAY:
	    ap_rputs("The proxy server received an invalid" CRLF
	             "response from an upstream server.<P>" CRLF, r);
	    if ((error_notes = apr_table_get(r->notes, "error-notes")) != NULL) {
		ap_rvputs(r, error_notes, "<P>\n", NULL);
	    }
	    break;
	case HTTP_VARIANT_ALSO_VARIES:
	    ap_rvputs(r, "A variant for the requested resource\n<PRE>\n",
		      ap_escape_html(r->pool, r->uri),
		      "\n</PRE>\nis itself a negotiable resource. "
		      "This indicates a configuration error.<P>\n", NULL);
	    break;
	case HTTP_REQUEST_TIME_OUT:
	    ap_rputs("I'm tired of waiting for your request.\n", r);
	    break;
	case HTTP_GONE:
	    ap_rvputs(r, "The requested resource<BR>",
		      ap_escape_html(r->pool, r->uri),
		      "<BR>\nis no longer available on this server ",
		      "and there is no forwarding address.\n",
		      "Please remove all references to this resource.\n",
		      NULL);
	    break;
	case HTTP_REQUEST_ENTITY_TOO_LARGE:
	    ap_rvputs(r, "The requested resource<BR>",
		      ap_escape_html(r->pool, r->uri), "<BR>\n",
		      "does not allow request data with ", r->method,
		      " requests, or the amount of data provided in\n",
		      "the request exceeds the capacity limit.\n", NULL);
	    break;
	case HTTP_REQUEST_URI_TOO_LARGE:
	    ap_rputs("The requested URL's length exceeds the capacity\n"
	             "limit for this server.<P>\n", r);
	    if ((error_notes = apr_table_get(r->notes, "error-notes")) != NULL) {
		ap_rvputs(r, error_notes, "<P>\n", NULL);
	    }
	    break;
	case HTTP_UNSUPPORTED_MEDIA_TYPE:
	    ap_rputs("The supplied request data is not in a format\n"
	             "acceptable for processing by this resource.\n", r);
	    break;
	case HTTP_RANGE_NOT_SATISFIABLE:
	    ap_rputs("None of the range-specifier values in the Range\n"
	             "request-header field overlap the current extent\n"
	             "of the selected resource.\n", r);
	    break;
	case HTTP_EXPECTATION_FAILED:
	    ap_rvputs(r, "The expectation given in the Expect request-header"
	              "\nfield could not be met by this server.<P>\n"
	              "The client sent<PRE>\n    Expect: ",
	              apr_table_get(r->headers_in, "Expect"), "\n</PRE>\n"
	              "but we only allow the 100-continue expectation.\n",
	              NULL);
	    break;
	case HTTP_UNPROCESSABLE_ENTITY:
	    ap_rputs("The server understands the media type of the\n"
	             "request entity, but was unable to process the\n"
	             "contained instructions.\n", r);
	    break;
	case HTTP_LOCKED:
	    ap_rputs("The requested resource is currently locked.\n"
	             "The lock must be released or proper identification\n"
	             "given before the method can be applied.\n", r);
	    break;
	case HTTP_FAILED_DEPENDENCY:
	    ap_rputs("The method could not be performed on the resource\n"
	             "because the requested action depended on another\n"
	             "action and that other action failed.\n", r);
	    break;
	case HTTP_INSUFFICIENT_STORAGE:
	    ap_rputs("The method could not be performed on the resource\n"
	             "because the server is unable to store the\n"
	             "representation needed to successfully complete the\n"
	             "request.  There is insufficient free space left in\n"
	             "your storage allocation.\n", r);
	    break;
	case HTTP_SERVICE_UNAVAILABLE:
	    ap_rputs("The server is temporarily unable to service your\n"
	             "request due to maintenance downtime or capacity\n"
	             "problems. Please try again later.\n", r);
	    break;
	case HTTP_GATEWAY_TIME_OUT:
	    ap_rputs("The proxy server did not receive a timely response\n"
	             "from the upstream server.\n", r);
	    break;
	case HTTP_NOT_EXTENDED:
	    ap_rputs("A mandatory extension policy in the request is not\n"
	             "accepted by the server for this resource.\n", r);
	    break;
	default:            /* HTTP_INTERNAL_SERVER_ERROR */
	    /*
	     * This comparison to expose error-notes could be modified to
	     * use a configuration directive and export based on that 
	     * directive.  For now "*" is used to designate an error-notes
	     * that is totally safe for any user to see (ie lacks paths,
	     * database passwords, etc.)
	     */
	    if (((error_notes = apr_table_get(r->notes, "error-notes")) != NULL)
		&& (h1 = apr_table_get(r->notes, "verbose-error-to")) != NULL
		&& (strcmp(h1, "*") == 0)) {
	        ap_rvputs(r, error_notes, "<P>\n", NULL);
	    }
	    else {
	        ap_rvputs(r, "The server encountered an internal error or\n"
	             "misconfiguration and was unable to complete\n"
	             "your request.<P>\n"
	             "Please contact the server administrator,\n ",
	             ap_escape_html(r->pool, r->server->server_admin),
	             " and inform them of the time the error occurred,\n"
	             "and anything you might have done that may have\n"
	             "caused the error.<P>\n"
		     "More information about this error may be available\n"
		     "in the server error log.<P>\n", NULL);
	    }
	 /*
	  * It would be nice to give the user the information they need to
	  * fix the problem directly since many users don't have access to
	  * the error_log (think University sites) even though they can easily
	  * get this error by misconfiguring an htaccess file.  However, the
	  * error notes tend to include the real file pathname in this case,
	  * which some people consider to be a breach of privacy.  Until we
	  * can figure out a way to remove the pathname, leave this commented.
	  *
	  * if ((error_notes = apr_table_get(r->notes, "error-notes")) != NULL) {
	  *     ap_rvputs(r, error_notes, "<P>\n", NULL);
	  * }
	  */
	    break;
	}

        if (recursive_error) {
            ap_rvputs(r, "<P>Additionally, a ",
                      status_lines[ap_index_of_response(recursive_error)],
                      "\nerror was encountered while trying to use an "
                      "ErrorDocument to handle the request.\n", NULL);
        }
        ap_rputs(ap_psignature("<HR>\n", r), r);
        ap_rputs("</BODY></HTML>\n", r);
    }
    ap_finalize_request_protocol(r);
    ap_rflush(r);
}

AP_IMPLEMENT_HOOK_RUN_ALL(int,post_read_request,
                          (request_rec *r),(r),OK,DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,log_transaction,
                          (request_rec *r),(r),OK,DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *,http_method,
                            (const request_rec *r),(r),NULL)
AP_IMPLEMENT_HOOK_RUN_FIRST(unsigned short,default_port,
                            (const request_rec *r),(r),0)
