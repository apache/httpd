/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/*
 * http_protocol.c --- routines which directly communicate with the client.
 *
 * Code originally by Rob McCool; much redone by Robert S. Thau
 * and the Apache Group.
 */

#define CORE_PRIVATE
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
#include <stdarg.h>
#include "http_conf_globals.h"

#define SET_BYTES_SENT(r) \
  do { if (r->sent_bodyct) \
          ap_bgetopt (r->connection->client, BO_BYTECT, &r->bytes_sent); \
  } while (0)


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

static int internal_byterange(int, long *, request_rec *, const char **, long *,
                              long *);

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

    if (!(range = ap_table_get(r->headers_in, "Range")))
        range = ap_table_get(r->headers_in, "Request-Range");

    if (!range || strncasecmp(range, "bytes=", 6)) {
        return 0;
    }

    /* Check the If-Range header for Etag or Date */

    if ((if_range = ap_table_get(r->headers_in, "If-Range"))) {
        if (if_range[0] == '"') {
            if (!(match = ap_table_get(r->headers_out, "Etag")) ||
                (strcasecmp(if_range, match) != 0))
                return 0;
        }
        else if (!(match = ap_table_get(r->headers_out, "Last-Modified")) ||
                 (strcasecmp(if_range, match) != 0))
            return 0;
    }

    if (!strchr(range, ',')) {
        /* A single range */
        if (!parse_byterange(ap_pstrdup(r->pool, range + 6), r->clength,
                             &range_start, &range_end))
            return 0;

        r->byterange = 1;

        ap_table_setn(r->headers_out, "Content-Range",
	    ap_psprintf(r->pool, "bytes %ld-%ld/%ld",
		range_start, range_end, r->clength));
        ap_table_setn(r->headers_out, "Content-Length",
	    ap_psprintf(r->pool, "%ld", range_end - range_start + 1));
    }
    else {
        /* a multiple range */
        const char *r_range = ap_pstrdup(r->pool, range + 6);
        long tlength = 0;

        r->byterange = 2;
        r->boundary = ap_psprintf(r->pool, "%lx%lx",
				r->request_time, (long) getpid());
        while (internal_byterange(0, &tlength, r, &r_range, NULL, NULL));
        ap_table_setn(r->headers_out, "Content-Length",
	    ap_psprintf(r->pool, "%ld", tlength));
    }

    r->status = PARTIAL_CONTENT;
    r->range = range + 6;

    return 1;
}

API_EXPORT(int) ap_each_byterange(request_rec *r, long *offset, long *length)
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
                              const char **r_range, long *offset, long *length)
{
    long range_start, range_end;
    char *range;

    if (!**r_range) {
        if (r->byterange > 1) {
            if (realreq)
                ap_rvputs(r, "\015\012--", r->boundary, "--\015\012", NULL);
            else
                *tlength += 4 + strlen(r->boundary) + 4;
        }
        return 0;
    }

    range = ap_getword(r->pool, r_range, ',');
    if (!parse_byterange(range, r->clength, &range_start, &range_end))
        /* Skip this one */
        return internal_byterange(realreq, tlength, r, r_range, offset,
                                  length);

    if (r->byterange > 1) {
        const char *ct = r->content_type ? r->content_type : ap_default_type(r);
        char ts[MAX_STRING_LEN];

        ap_snprintf(ts, sizeof(ts), "%ld-%ld/%ld", range_start, range_end,
                    r->clength);
        if (realreq)
            ap_rvputs(r, "\015\012--", r->boundary, "\015\012Content-type: ",
                   ct, "\015\012Content-range: bytes ", ts, "\015\012\015\012",
                   NULL);
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
    return 1;
}

API_EXPORT(int) ap_set_content_length(request_rec *r, long clength)
{
    r->clength = clength;
    ap_table_setn(r->headers_out, "Content-Length", ap_psprintf(r->pool, "%ld", clength));
    return 0;
}

API_EXPORT(int) ap_set_keepalive(request_rec *r)
{
    int ka_sent = 0;
    int wimpy = ap_find_token(r->pool,
                           ap_table_get(r->headers_out, "Connection"), "close");
    const char *conn = ap_table_get(r->headers_in, "Connection");

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
         ap_table_get(r->headers_out, "Content-Length") ||
         ap_find_last_token(r->pool,
                         ap_table_get(r->headers_out, "Transfer-Encoding"),
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
        (!ap_table_get(r->subprocess_env, "nokeepalive") ||
         ap_table_get(r->headers_in, "Via")) &&
        ((ka_sent = ap_find_token(r->pool, conn, "keep-alive")) ||
         (r->proto_num >= HTTP_VERSION(1,1)))
       ) {
        int left = r->server->keep_alive_max - r->connection->keepalives;

        r->connection->keepalive = 1;
        r->connection->keepalives++;

        /* If they sent a Keep-Alive token, send one back */
        if (ka_sent) {
            if (r->server->keep_alive_max)
		ap_table_setn(r->headers_out, "Keep-Alive",
		    ap_psprintf(r->pool, "timeout=%d, max=%d",
                            r->server->keep_alive_timeout, left));
            else
		ap_table_setn(r->headers_out, "Keep-Alive",
		    ap_psprintf(r->pool, "timeout=%d",
                            r->server->keep_alive_timeout));
            ap_table_mergen(r->headers_out, "Connection", "Keep-Alive");
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
	ap_table_mergen(r->headers_out, "Connection", "close");

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
API_EXPORT(time_t) ap_rationalize_mtime(request_rec *r, time_t mtime)
{
    time_t now;

    /* For all static responses, it's almost certain that the file was
     * last modified before the beginning of the request.  So there's
     * no reason to call time(NULL) again.  But if the response has been
     * created on demand, then it might be newer than the time the request
     * started.  In this event we really have to call time(NULL) again
     * so that we can give the clients the most accurate Last-Modified.  If we
     * were given a time in the future, we return the current time - the
     * Last-Modified can't be in the future.
     */
    now = (mtime < r->request_time) ? r->request_time : time(NULL);
    return (mtime > now) ? now : mtime;
}

API_EXPORT(int) ap_meets_conditions(request_rec *r)
{
    const char *etag = ap_table_get(r->headers_out, "ETag");
    const char *if_match, *if_modified_since, *if_unmodified, *if_nonematch;
    time_t mtime;

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

    mtime = (r->mtime != 0) ? r->mtime : time(NULL);

    /* If an If-Match request-header field was given
     * AND if our ETag does not match any of the entity tags in that field
     * AND the field value is not "*" (meaning match anything), then
     *     respond with a status of 412 (Precondition Failed).
     */
    if ((if_match = ap_table_get(r->headers_in, "If-Match")) != NULL) {
        if ((etag == NULL) ||
            ((if_match[0] != '*') && !ap_find_token(r->pool, if_match, etag))) {
            return HTTP_PRECONDITION_FAILED;
        }
    }
    else {
        /* Else if a valid If-Unmodified-Since request-header field was given
         * AND the requested resource has been modified since the time
         * specified in this field, then the server MUST
         *     respond with a status of 412 (Precondition Failed).
         */
        if_unmodified = ap_table_get(r->headers_in, "If-Unmodified-Since");
        if (if_unmodified != NULL) {
            time_t ius = ap_parseHTTPdate(if_unmodified);

            if ((ius != BAD_DATE) && (mtime > ius)) {
                return HTTP_PRECONDITION_FAILED;
            }
        }
    }

    /* If an If-None-Match request-header field was given
     * AND if our ETag matches any of the entity tags in that field
     * OR if the field value is "*" (meaning match anything), then
     *    if the request method was GET or HEAD, the server SHOULD
     *       respond with a 304 (Not Modified) response.
     *    For all other request methods, the server MUST
     *       respond with a status of 412 (Precondition Failed).
     */
    if_nonematch = ap_table_get(r->headers_in, "If-None-Match");
    if (if_nonematch != NULL) {
        int rstatus;

        if ((if_nonematch[0] == '*')
            || ((etag != NULL) && ap_find_token(r->pool, if_nonematch, etag))) {
            rstatus = (r->method_number == M_GET) ? HTTP_NOT_MODIFIED
                                                  : HTTP_PRECONDITION_FAILED;
            return rstatus;
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
                  ap_table_get(r->headers_in, "If-Modified-Since")) != NULL)) {
        time_t ims = ap_parseHTTPdate(if_modified_since);

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
    
    weak = ((r->request_time - r->mtime > 1) && !force_weak) ? "" : "W/";

    if (r->finfo.st_mode != 0) {
        etag = ap_psprintf(r->pool,
                    "%s\"%lx-%lx-%lx\"", weak,
                    (unsigned long) r->finfo.st_ino,
                    (unsigned long) r->finfo.st_size,
                    (unsigned long) r->mtime);
    }
    else {
        etag = ap_psprintf(r->pool, "%s\"%lx\"", weak,
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
        etag = ap_pstrcat(r->pool, variant_etag, ";", vlv, NULL);
    }

    ap_table_setn(r->headers_out, "ETag", etag);
}

/*
 * This function sets the Last-Modified output header field to the value
 * of the mtime field in the request structure - rationalized to keep it from
 * being in the future.
 */
API_EXPORT(void) ap_set_last_modified(request_rec *r)
{
    time_t mod_time = ap_rationalize_mtime(r, r->mtime);

    ap_table_setn(r->headers_out, "Last-Modified",
              ap_gm_timestr_822(r->pool, mod_time));
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

    pos = s;

    do {
        retval = ap_bgets(pos, n, in);     /* retval == -1 if error, 0 if EOF */

        if (retval <= 0)
            return ((retval < 0) && (total == 0)) ? -1 : total;

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
            return total;       /* if not, input line exceeded buffer size */

        /* Continue appending if line folding is desired and
         * the last line was not empty and we have room in the buffer and
         * the next line begins with a continuation character.
         */
    } while (fold && (retval != 1) && (n > 1)
                  && (ap_blookc(&next, in) == 1)
                  && ((next == ' ') || (next == '\t')));

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

    r->unparsed_uri = ap_pstrdup(r->pool, uri);

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
				    : ap_pstrdup(r->pool, "/");
#if defined(OS2) || defined(WIN32)
	/* Handle path translations for OS/2 and plug security hole.
	 * This will prevent "http://www.wherever.com/..\..\/" from
	 * returning a directory for the root drive.
	 */
	{
	    char *x;

	    for (x = r->uri; (x = strchr(x, '\\')) != NULL; )
		*x = '/';
#ifndef WIN32   /* for OS/2 only: */
	    /* Fix OS/2 HPFS filename case problem. */
	    ap_str_tolower(r->uri);
#endif
	}
#endif  /* OS2 || WIN32 */
    }
    else {
	r->args = NULL;
	r->hostname = NULL;
	r->status = status;             /* set error status */
	r->uri = ap_pstrdup(r->pool, uri);
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
    while ((len = getline(l, sizeof(l), conn->client, 0)) <= 0) {
        if ((len < 0) || ap_bgetflag(conn->client, B_EOF)) {
            ap_bsetflag(conn->client, B_SAFEREAD, 0);
            return 0;
        }
    }
    /* we've probably got something to do, ignore graceful restart requests */
#ifdef SIGUSR1
    signal(SIGUSR1, SIG_IGN);
#endif

    ap_bsetflag(conn->client, B_SAFEREAD, 0);

    r->request_time = time(NULL);
    r->the_request = ap_pstrdup(r->pool, l);
    r->method = ap_getword_white(r->pool, &ll);
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
        r->protocol  = ap_pstrdup(r->pool, "HTTP/1.0");
        return 0;
    }

    r->assbackwards = (ll[0] == '\0');
    r->protocol = ap_pstrdup(r->pool, ll[0] ? ll : "HTTP/0.9");

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
    table *tmp_headers;

    /* We'll use ap_overlap_tables later to merge these into r->headers_in. */
    tmp_headers = ap_make_table(r->pool, 50);

    /*
     * Read header lines until we get the empty separator line, a read error,
     * the connection closes (EOF), reach the server limit, or we timeout.
     */
    while ((len = getline(field, sizeof(field), c->client, 1)) > 0) {

        if (r->server->limit_req_fields &&
            (++fields_read > r->server->limit_req_fields)) {
            r->status = HTTP_BAD_REQUEST;
            ap_table_setn(r->notes, "error-notes",
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
            ap_table_setn(r->notes, "error-notes", ap_pstrcat(r->pool,
                "Size of a request header field exceeds server limit.<P>\n"
                "<PRE>\n", field, "</PRE>\n", NULL));
            return;
        }
        copy = ap_palloc(r->pool, len + 1);
        memcpy(copy, field, len + 1);

        if (!(value = strchr(copy, ':'))) {     /* Find the colon separator */
            r->status = HTTP_BAD_REQUEST;       /* or abort the bad request */
            ap_table_setn(r->notes, "error-notes", ap_pstrcat(r->pool,
                "Request header field is missing colon separator.<P>\n"
                "<PRE>\n", copy, "</PRE>\n", NULL));
            return;
        }

        *value = '\0';
        ++value;
        while (*value == ' ' || *value == '\t')
            ++value;            /* Skip to start of value   */

	ap_table_addn(tmp_headers, copy, value);
    }

    ap_overlap_tables(r->headers_in, tmp_headers, AP_OVERLAP_TABLES_MERGE);
}

request_rec *ap_read_request(conn_rec *conn)
{
    request_rec *r;
    pool *p;
    const char *expect;
    int access_status;

    p = ap_make_sub_pool(conn->pool);
    r = ap_pcalloc(p, sizeof(request_rec));
    r->pool            = p;
    r->connection      = conn;
    conn->server       = conn->base_server;
    r->server          = conn->server;

    conn->keptalive    = conn->keepalive == 1;
    conn->keepalive    = 0;

    conn->user         = NULL;
    conn->ap_auth_type    = NULL;

    r->headers_in      = ap_make_table(r->pool, 50);
    r->subprocess_env  = ap_make_table(r->pool, 50);
    r->headers_out     = ap_make_table(r->pool, 12);
    r->err_headers_out = ap_make_table(r->pool, 5);
    r->notes           = ap_make_table(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_REQUEST_TIME_OUT;  /* Until we get a request */
    r->the_request     = NULL;

#ifdef CHARSET_EBCDIC
    ap_bsetflag(r->connection->client, B_ASCII2EBCDIC|B_EBCDIC2ASCII, 1);
#endif

    /* Get the request... */

    ap_keepalive_timeout("read request line", r);
    if (!read_request_line(r)) {
        ap_kill_timeout(r);
        if (r->status == HTTP_REQUEST_URI_TOO_LARGE) {

            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                         "request failed: URI too long");
            ap_send_error_response(r, 0);
            ap_bflush(r->connection->client);
            ap_log_transaction(r);
            return r;
        }
        return NULL;
    }
    if (!r->assbackwards) {
        ap_hard_timeout("read request headers", r);
        get_mime_headers(r);
        ap_kill_timeout(r);
        if (r->status != HTTP_REQUEST_TIME_OUT) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                         "request failed: error reading the headers");
            ap_send_error_response(r, 0);
            ap_bflush(r->connection->client);
            ap_log_transaction(r);
            return r;
        }
    }
    else {
        ap_kill_timeout(r);

        if (r->header_only) {
            /*
             * Client asked for headers only with HTTP/0.9, which doesn't send
             * headers! Have to dink things just to make sure the error message
             * comes through...
             */
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                          "client sent invalid HTTP/0.9 request: HEAD %s",
                          r->uri);
            r->header_only = 0;
            r->status = HTTP_BAD_REQUEST;
            ap_send_error_response(r, 0);
            ap_bflush(r->connection->client);
            ap_log_transaction(r);
            return r;
        }
    }

    r->status = HTTP_OK;                         /* Until further notice. */

    /* update what we think the virtual host is based on the headers we've
     * now read
     */
    ap_update_vhost_from_headers(r);

    /* we may have switched to another server */
    r->per_dir_config = r->server->lookup_defaults;

    conn->keptalive = 0;        /* We now have a request to play with */

    if ((!r->hostname && (r->proto_num >= HTTP_VERSION(1,1))) ||
        ((r->proto_num == HTTP_VERSION(1,1)) &&
         !ap_table_get(r->headers_in, "Host"))) {
        /*
         * Client sent us an HTTP/1.1 or later request without telling us the
         * hostname, either with a full URL or a Host: header. We therefore
         * need to (as per the 1.1 spec) send an error.  As a special case,
         * HTTP/1.1 mentions twice (S9, S14.23) that a request MUST contain
         * a Host: header, and the server MUST respond with 400 if it doesn't.
         */
        r->status = HTTP_BAD_REQUEST;
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                      "client sent HTTP/1.1 request without hostname "
                      "(see RFC2068 section 9, and 14.23): %s", r->uri);
        ap_send_error_response(r, 0);
        ap_bflush(r->connection->client);
        ap_log_transaction(r);
        return r;
    }
    if (((expect = ap_table_get(r->headers_in, "Expect")) != NULL) &&
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
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r,
                          "client sent an unrecognized expectation value of "
                          "Expect: %s", expect);
            ap_send_error_response(r, 0);
            ap_bflush(r->connection->client);
            (void) ap_discard_request_body(r);
            ap_log_transaction(r);
            return r;
        }
    }

    if ((access_status = ap_run_post_read_request(r))) {
        ap_die(access_status, r);
        ap_log_transaction(r);
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
    rnew->no_local_copy   = 1;   /* Don't try to send USE_LOCAL_COPY for a
                                  * fragment. */
    rnew->method          = "GET";
    rnew->method_number   = M_GET;
    rnew->protocol        = "INCLUDED";

    rnew->status          = HTTP_OK;

    rnew->headers_in      = r->headers_in;
    rnew->subprocess_env  = ap_copy_table(rnew->pool, r->subprocess_env);
    rnew->headers_out     = ap_make_table(rnew->pool, 5);
    rnew->err_headers_out = ap_make_table(rnew->pool, 5);
    rnew->notes           = ap_make_table(rnew->pool, 5);

    rnew->expecting_100   = r->expecting_100;
    rnew->read_length     = r->read_length;
    rnew->read_body       = REQUEST_NO_BODY;

    rnew->main = (request_rec *) r;
}

void ap_finalize_sub_req_protocol(request_rec *sub)
{
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
        ap_table_setn(r->err_headers_out,
                  r->proxyreq ? "Proxy-Authenticate" : "WWW-Authenticate",
                  ap_pstrcat(r->pool, "Basic realm=\"", ap_auth_name(r), "\"",
                          NULL));
}

API_EXPORT(void) ap_note_digest_auth_failure(request_rec *r)
{
    ap_table_setn(r->err_headers_out,
	    r->proxyreq ? "Proxy-Authenticate" : "WWW-Authenticate",
	    ap_psprintf(r->pool, "Digest realm=\"%s\", nonce=\"%lu\"",
		ap_auth_name(r), r->request_time));
}

API_EXPORT(int) ap_get_basic_auth_pw(request_rec *r, const char **pw)
{
    const char *auth_line = ap_table_get(r->headers_in,
                                      r->proxyreq ? "Proxy-Authorization"
                                                  : "Authorization");
    const char *t;

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Basic"))
        return DECLINED;

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
		    r, "need AuthName: %s", r->uri);
        return SERVER_ERROR;
    }

    if (!auth_line) {
        ap_note_basic_auth_failure(r);
        return AUTH_REQUIRED;
    }

    if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        /* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "client used wrong authentication scheme: %s", r->uri);
        ap_note_basic_auth_failure(r);
        return AUTH_REQUIRED;
    }

    t = ap_uudecode(r->pool, auth_line);
    /* Note that this allocation has to be made from r->connection->pool
     * because it has the lifetime of the connection.  The other allocations
     * are temporary and can be tossed away any time.
     */
    r->connection->user = ap_getword_nulls (r->connection->pool, &t, ':');
    r->connection->ap_auth_type = "Basic";

    *pw = t;

    return OK;
}

/* New Apache routine to map status codes into array indicies
 *  e.g.  100 -> 0,  101 -> 1,  200 -> 2 ...
 * The number of status lines must equal the value of RESPONSE_CODES (httpd.h)
 * and must be listed in order.
 */

static char *status_lines[RESPONSE_CODES] = {
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

/* Send a single HTTP header field to the client.  Note that this function
 * is used in calls to table_do(), so their interfaces are co-dependent.
 * In other words, don't change this one without checking table_do in alloc.c.
 * It returns true unless there was a write error of some kind.
 */
API_EXPORT_NONSTD(int) ap_send_header_field(request_rec *r,
    const char *fieldname, const char *fieldval)
{
    return (0 < ap_bvputs(r->connection->client,
                       fieldname, ": ", fieldval, "\015\012", NULL));
}

API_EXPORT(void) ap_basic_http_header(request_rec *r)
{
    char *protocol;
#ifdef CHARSET_EBCDIC
    int convert = ap_bgetflag(r->connection->client, B_EBCDIC2ASCII);
#endif /*CHARSET_EBCDIC*/

    if (r->assbackwards)
        return;

    if (!r->status_line)
        r->status_line = status_lines[ap_index_of_response(r->status)];

    /* mod_proxy is only HTTP/1.0, so avoid sending HTTP/1.1 error response;
     * kluge around broken browsers when indicated by force-response-1.0
     */
    if (r->proxyreq
        || (r->proto_num == HTTP_VERSION(1,0)
            && ap_table_get(r->subprocess_env, "force-response-1.0"))) {

        protocol = "HTTP/1.0";
        r->connection->keepalive = -1;
    }
    else
        protocol = SERVER_PROTOCOL;

#ifdef CHARSET_EBCDIC
    ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, 1);
#endif /*CHARSET_EBCDIC*/

    /* Output the HTTP/1.x Status-Line and the Date and Server fields */

    ap_bvputs(r->connection->client,
           protocol, " ", r->status_line, "\015\012", NULL);

    ap_send_header_field(r, "Date", ap_gm_timestr_822(r->pool, r->request_time));
    ap_send_header_field(r, "Server", ap_get_server_version());

    ap_table_unset(r->headers_out, "Date");        /* Avoid bogosity */
    ap_table_unset(r->headers_out, "Server");
#ifdef CHARSET_EBCDIC
    if (!convert)
        ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, convert);
#endif /*CHARSET_EBCDIC*/
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
static void terminate_header(BUFF *client)
{
    long int bs;

    ap_bgetopt(client, BO_BYTECT, &bs);
    if (bs >= 255 && bs <= 257)
        ap_bputs("X-Pad: avoid browser bug\015\012", client);

    ap_bputs("\015\012", client);  /* Send the terminating empty line */
}

/* Build the Allow field-value from the request handler method mask.
 * Note that we always allow TRACE, since it is handled below.
 */
static char *make_allow(request_rec *r)
{
    return 2 + ap_pstrcat(r->pool,
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

    ap_hard_timeout("send TRACE", r);

    r->content_type = "message/http";
    ap_send_http_header(r);

    /* Now we recreate the request, and echo it back */

    ap_rvputs(r, r->the_request, "\015\012", NULL);

    ap_table_do((int (*) (void *, const char *, const char *)) ap_send_header_field,
             (void *) r, r->headers_in, NULL);
    ap_bputs("\015\012", r->connection->client);

    ap_kill_timeout(r);
    return OK;
}

int ap_send_http_options(request_rec *r)
{
    const long int zero = 0L;

    if (r->assbackwards)
        return DECLINED;

    ap_hard_timeout("send OPTIONS", r);

    ap_basic_http_header(r);

    ap_table_setn(r->headers_out, "Content-Length", "0");
    ap_table_setn(r->headers_out, "Allow", make_allow(r));
    ap_set_keepalive(r);

    ap_table_do((int (*) (void *, const char *, const char *)) ap_send_header_field,
             (void *) r, r->headers_out, NULL);

    terminate_header(r->connection->client);

    ap_kill_timeout(r);
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
    return (ap_table_get(r->headers_in, "Request-Range") ||
            ((ua = ap_table_get(r->headers_in, "User-Agent"))
             && strstr(ua, "MSIE 3")));
}

API_EXPORT(void) ap_send_http_header(request_rec *r)
{
    int i;
    const long int zero = 0L;
#ifdef CHARSET_EBCDIC
    int convert = ap_bgetflag(r->connection->client, B_EBCDIC2ASCII);
#endif /*CHARSET_EBCDIC*/

    if (r->assbackwards) {
        if (!r->main)
            ap_bsetopt(r->connection->client, BO_BYTECT, &zero);
        r->sent_bodyct = 1;
        return;
    }

    /*
     * Now that we are ready to send a response, we need to combine the two
     * header field tables into a single table.  If we don't do this, our
     * later attempts to set or unset a given fieldname might be bypassed.
     */
    if (!ap_is_empty_table(r->err_headers_out))
        r->headers_out = ap_overlay_tables(r->pool, r->err_headers_out,
                                        r->headers_out);

    ap_hard_timeout("send headers", r);

    ap_basic_http_header(r);

#ifdef CHARSET_EBCDIC
    ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, 1);
#endif /*CHARSET_EBCDIC*/

    ap_set_keepalive(r);

    if (r->chunked) {
        ap_table_mergen(r->headers_out, "Transfer-Encoding", "chunked");
        ap_table_unset(r->headers_out, "Content-Length");
    }

    if (r->byterange > 1)
        ap_table_setn(r->headers_out, "Content-Type",
                  ap_pstrcat(r->pool, "multipart", use_range_x(r) ? "/x-" : "/",
                          "byteranges; boundary=", r->boundary, NULL));
    else if (r->content_type)
        ap_table_setn(r->headers_out, "Content-Type", r->content_type);
    else
        ap_table_setn(r->headers_out, "Content-Type", ap_default_type(r));

    if (r->content_encoding)
        ap_table_setn(r->headers_out, "Content-Encoding", r->content_encoding);

    if (r->content_languages && r->content_languages->nelts) {
        for (i = 0; i < r->content_languages->nelts; ++i) {
            ap_table_mergen(r->headers_out, "Content-Language",
                        ((char **) (r->content_languages->elts))[i]);
        }
    }
    else if (r->content_language)
        ap_table_setn(r->headers_out, "Content-Language", r->content_language);

    /*
     * Control cachability for non-cachable responses if not already set by
     * some other part of the server configuration.
     */
    if (r->no_cache && !ap_table_get(r->headers_out, "Expires"))
        ap_table_addn(r->headers_out, "Expires",
                  ap_gm_timestr_822(r->pool, r->request_time));

    /* Send the entire table of header fields, terminated by an empty line. */

    ap_table_do((int (*) (void *, const char *, const char *)) ap_send_header_field,
             (void *) r, r->headers_out, NULL);

    terminate_header(r->connection->client);

    ap_kill_timeout(r);

    ap_bsetopt(r->connection->client, BO_BYTECT, &zero);
    r->sent_bodyct = 1;         /* Whatever follows is real body stuff... */

    /* Set buffer flags for the body */
    if (r->chunked)
        ap_bsetflag(r->connection->client, B_CHUNK, 1);
#ifdef CHARSET_EBCDIC
    if (!convert)
        ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, convert);
#endif /*CHARSET_EBCDIC*/
}

/* finalize_request_protocol is called at completion of sending the
 * response.  It's sole purpose is to send the terminating protocol
 * information for any wrappers around the response message body
 * (i.e., transfer encodings).  It should have been named finalize_response.
 */
API_EXPORT(void) ap_finalize_request_protocol(request_rec *r)
{
    if (r->chunked && !r->connection->aborted) {
        /*
         * Turn off chunked encoding --- we can only do this once.
         */
        r->chunked = 0;
        ap_bsetflag(r->connection->client, B_CHUNK, 0);

        ap_soft_timeout("send ending chunk", r);
        ap_bputs("0\015\012", r->connection->client);
        /* If we had footer "headers", we'd send them now */
        ap_bputs("\015\012", r->connection->client);
        ap_kill_timeout(r);
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
    const char *tenc = ap_table_get(r->headers_in, "Transfer-Encoding");
    const char *lenp = ap_table_get(r->headers_in, "Content-Length");
    unsigned long max_body;

    r->read_body = read_policy;
    r->read_chunked = 0;
    r->remaining = 0;

    if (tenc) {
        if (strcasecmp(tenc, "chunked")) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "Unknown Transfer-Encoding %s", tenc);
            return HTTP_NOT_IMPLEMENTED;
        }
        if (r->read_body == REQUEST_CHUNKED_ERROR) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
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
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                        "Invalid Content-Length %s", lenp);
            return HTTP_BAD_REQUEST;
        }

        r->remaining = atol(lenp);
    }

    if ((r->read_body == REQUEST_NO_BODY) &&
        (r->read_chunked || (r->remaining > 0))) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                    "%s with body is not allowed for %s", r->method, r->uri);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    max_body = ap_get_limit_req_body(r);
    if (max_body && (r->remaining > max_body)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
          "Request content-length of %s is larger than the configured "
          "limit of %lu", lenp, max_body);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    return OK;
}

API_EXPORT(int) ap_should_client_block(request_rec *r)
{
    /* First check if we have already read the request body */

    if (r->read_length || (!r->read_chunked && (r->remaining <= 0)))
        return 0;

    if (r->expecting_100 && r->proto_num >= HTTP_VERSION(1,1)) {
        /* sending 100 Continue interim response */
        ap_bvputs(r->connection->client,
               SERVER_PROTOCOL, " ", status_lines[0], "\015\012\015\012",
               NULL);
        ap_bflush(r->connection->client);
    }

    return 1;
}

static long get_chunk_size(char *b)
{
    long chunksize = 0;

    while (isxdigit(*b)) {
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
    long len_read, len_to_read;
    long chunk_start = 0;
    unsigned long max_body;

    if (!r->read_chunked) {     /* Content-length read */
        len_to_read = (r->remaining > bufsiz) ? bufsiz : r->remaining;
        len_read = ap_bread(r->connection->client, buffer, len_to_read);
        if (len_read <= 0) {
            if (len_read < 0)
                r->connection->keepalive = -1;
            return len_read;
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
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
            "Chunked request body is larger than the configured limit of %lu",
            max_body);
        r->connection->keepalive = -1;
        return -1;
    }

    if (r->remaining == 0) {    /* Start of new chunk */

        chunk_start = getline(buffer, bufsiz, r->connection->client, 0);
        if ((chunk_start <= 0) || (chunk_start >= (bufsiz - 1))
            || !isxdigit(*buffer)) {
            r->connection->keepalive = -1;
            return -1;
        }

        len_to_read = get_chunk_size(buffer);

        if (len_to_read == 0) { /* Last chunk indicated, get footers */
            if (r->read_body == REQUEST_CHUNKED_DECHUNK) {
                get_mime_headers(r);
                ap_snprintf(buffer, bufsiz, "%ld", r->read_length);
                ap_table_unset(r->headers_in, "Transfer-Encoding");
                ap_table_setn(r->headers_in, "Content-Length",
                    ap_pstrdup(r->pool, buffer));
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

    len_read = ap_bread(r->connection->client, buffer, len_to_read);
    if (len_read <= 0) {
        r->connection->keepalive = -1;
        return -1;
    }

    r->remaining -= len_read;

    if (r->remaining == 0) {    /* End of chunk, get trailing CRLF */
        if ((c = ap_bgetc(r->connection->client)) == CR) {
            c = ap_bgetc(r->connection->client);
        }
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

    /* If we are discarding the request body, then we must already know
     * the final status code, therefore disable the sending of 100 continue.
     */
    r->expecting_100 = 0;

    if (ap_should_client_block(r)) {
        char dumpbuf[HUGE_STRING_LEN];

        ap_hard_timeout("reading request body", r);
        while ((rv = ap_get_client_block(r, dumpbuf, HUGE_STRING_LEN)) > 0)
            continue;
        ap_kill_timeout(r);

        if (rv < 0)
            return HTTP_BAD_REQUEST;
    }
    return OK;
}

/*
 * Send the body of a response to the client.
 */
API_EXPORT(long) ap_send_fd(FILE *f, request_rec *r)
{
    return ap_send_fd_length(f, r, -1);
}

API_EXPORT(long) ap_send_fd_length(FILE *f, request_rec *r, long length)
{
    char buf[IOBUFSIZE];
    long total_bytes_sent = 0;
    register int n, w, o, len;

    if (length == 0)
        return 0;

    ap_soft_timeout("send body", r);

    while (!r->connection->aborted) {
        if ((length > 0) && (total_bytes_sent + IOBUFSIZE) > length)
            len = length - total_bytes_sent;
        else
            len = IOBUFSIZE;

        while ((n = fread(buf, sizeof(char), len, f)) < 1
               && ferror(f) && errno == EINTR && !r->connection->aborted)
            continue;

        if (n < 1) {
            break;
        }
        o = 0;

        while (n && !r->connection->aborted) {
            w = ap_bwrite(r->connection->client, &buf[o], n);
            if (w > 0) {
                ap_reset_timeout(r);   /* reset timeout after successful write */
		total_bytes_sent += w;
                n -= w;
                o += w;
            }
            else if (w < 0) {
                if (r->connection->aborted)
                    break;
                else if (errno == EAGAIN)
                    continue;
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, r,
                     "client stopped connection before send body completed");
                    ap_bsetflag(r->connection->client, B_EOUT, 1);
                    r->connection->aborted = 1;
                    break;
                }
            }
        }
    }

    ap_kill_timeout(r);
    SET_BYTES_SENT(r);
    return total_bytes_sent;
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
    register int n, w, o, len, fd;
    fd_set fds;

    if (length == 0)
        return 0;

    /* Make fb unbuffered and non-blocking */
    ap_bsetflag(fb, B_RD, 0);
    ap_bnonblock(fb, B_RD);
    fd = ap_bfileno(fb, B_RD);
#ifndef WIN32
    if (fd >= FD_SETSIZE) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, NULL,
	    "send body: filedescriptor (%u) larger than FD_SETSIZE (%u) "
	    "found, you probably need to rebuild Apache with a "
	    "larger FD_SETSIZE", fd, FD_SETSIZE);
	return 0;
    }
#endif

    ap_soft_timeout("send body", r);

    FD_ZERO(&fds);
    while (!r->connection->aborted) {
#ifdef NDELAY_PIPE_RETURNS_ZERO
	/* Contributed by dwd@bell-labs.com for UTS 2.1.2, where the fcntl */
	/*   O_NDELAY flag causes read to return 0 when there's nothing */
	/*   available when reading from a pipe.  That makes it tricky */
	/*   to detect end-of-file :-(.  This stupid bug is even documented */
	/*   in the read(2) man page where it says that everything but */
	/*   pipes return -1 and EAGAIN.  That makes it a feature, right? */
	int afterselect = 0;
#endif
        if ((length > 0) && (total_bytes_sent + IOBUFSIZE) > length)
            len = length - total_bytes_sent;
        else
            len = IOBUFSIZE;

        do {
            n = ap_bread(fb, buf, len);
#ifdef NDELAY_PIPE_RETURNS_ZERO
	    if ((n > 0) || (n == 0 && afterselect))
		break;
#else
            if (n >= 0)
                break;
#endif
            if (r->connection->aborted)
                break;
            if (n < 0 && errno != EAGAIN)
                break;
            /* we need to block, so flush the output first */
            ap_bflush(r->connection->client);
            if (r->connection->aborted)
                break;
            FD_SET(fd, &fds);
            /*
             * we don't care what select says, we might as well loop back
             * around and try another read
             */
            ap_select(fd + 1, &fds, NULL, NULL, NULL);
#ifdef NDELAY_PIPE_RETURNS_ZERO
	    afterselect = 1;
#endif
        } while (!r->connection->aborted);

        if (n < 1 || r->connection->aborted) {
            break;
        }

        o = 0;
        total_bytes_sent += n;

        while (n && !r->connection->aborted) {
            w = ap_bwrite(r->connection->client, &buf[o], n);
            if (w > 0) {
                ap_reset_timeout(r);       /* reset timeout after successful
                                         * write */
                n -= w;
                o += w;
            }
            else if (w < 0) {
                if (r->connection->aborted)
                    break;
                else if (errno == EAGAIN)
                    continue;
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, r,
                     "client stopped connection before send body completed");
                    ap_bsetflag(r->connection->client, B_EOUT, 1);
                    r->connection->aborted = 1;
                    break;
                }
            }
        }
    }

    ap_kill_timeout(r);
    SET_BYTES_SENT(r);
    return total_bytes_sent;
}



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
API_EXPORT(size_t) ap_send_mmap(void *mm, request_rec *r, size_t offset,
                             size_t length)
{
    size_t total_bytes_sent = 0;
    int n, w;

    if (length == 0)
        return 0;

    ap_soft_timeout("send mmap", r);

    length += offset;
    while (!r->connection->aborted && offset < length) {
        if (length - offset > MMAP_SEGMENT_SIZE) {
            n = MMAP_SEGMENT_SIZE;
        }
        else {
            n = length - offset;
        }

        while (n && !r->connection->aborted) {
            w = ap_bwrite(r->connection->client, (char *) mm + offset, n);
            if (w > 0) {
                ap_reset_timeout(r);   /* reset timeout after successful write */
                total_bytes_sent += w;
                n -= w;
                offset += w;
            }
            else if (w < 0) {
                if (r->connection->aborted)
                    break;
                else if (errno == EAGAIN)
                    continue;
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, r,
                     "client stopped connection before send mmap completed");
                    ap_bsetflag(r->connection->client, B_EOUT, 1);
                    r->connection->aborted = 1;
                    break;
                }
            }
        }
    }

    ap_kill_timeout(r);
    SET_BYTES_SENT(r);
    return total_bytes_sent;
}

API_EXPORT(int) ap_rputc(int c, request_rec *r)
{
    if (r->connection->aborted)
        return EOF;
    ap_bputc(c, r->connection->client);
    SET_BYTES_SENT(r);
    return c;
}

API_EXPORT(int) ap_rputs(const char *str, request_rec *r)
{
    int rcode;

    if (r->connection->aborted)
        return EOF;
    rcode = ap_bputs(str, r->connection->client);
    SET_BYTES_SENT(r);
    return rcode;
}

API_EXPORT(int) ap_rwrite(const void *buf, int nbyte, request_rec *r)
{
    int n;
    if (r->connection->aborted)
        return EOF;
    n = ap_bwrite(r->connection->client, buf, nbyte);
    SET_BYTES_SENT(r);
    return n;
}

API_EXPORT(int) ap_rprintf(request_rec *r, const char *fmt,...)
{
    va_list vlist;
    int n;

    if (r->connection->aborted)
        return EOF;
    va_start(vlist, fmt);
    n = ap_vbprintf(r->connection->client, fmt, vlist);
    va_end(vlist);
    SET_BYTES_SENT(r);
    return n;
}

API_EXPORT_NONSTD(int) ap_rvputs(request_rec *r,...)
{
    va_list args;
    int i, j, k;
    const char *x;
    BUFF *fb = r->connection->client;

    if (r->connection->aborted)
        return EOF;

    va_start(args, r);
    for (k = 0;;) {
        x = va_arg(args, const char *);
        if (x == NULL)
            break;
        j = strlen(x);
        i = ap_bwrite(fb, x, j);
        if (i != j) {
            va_end(args);
            return -1;
        }
        k += i;
    }
    va_end(args);

    SET_BYTES_SENT(r);
    return k;
}

API_EXPORT(int) ap_rflush(request_rec *r)
{
    return ap_bflush(r->connection->client);
}

/* We should have named this send_canned_response, since it is used for any
 * response that can be generated by the server from the request record.
 * This includes all 204 (no content), 3xx (redirect), 4xx (client error),
 * and 5xx (server error) messages that have not been redirected to another
 * handler via the ErrorDocument feature.
 */
void ap_send_error_response(request_rec *r, int recursive_error)
{
    BUFF *fd = r->connection->client;
    int status = r->status;
    int idx = ap_index_of_response(status);
    char *custom_response;
    const char *location = ap_table_get(r->headers_out, "Location");

    /* We need to special-case the handling of 204 and 304 responses,
     * since they have specific HTTP requirements and do not include a
     * message body.  Note that being assbackwards here is not an option.
     */
    if (status == HTTP_NOT_MODIFIED) {
        if (!ap_is_empty_table(r->err_headers_out))
            r->headers_out = ap_overlay_tables(r->pool, r->err_headers_out,
                                               r->headers_out);
        ap_hard_timeout("send 304", r);

        ap_basic_http_header(r);
        ap_set_keepalive(r);

        ap_table_do((int (*)(void *, const char *, const char *)) ap_send_header_field,
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

        terminate_header(r->connection->client);

        ap_kill_timeout(r);
        return;
    }

    if (status == HTTP_NO_CONTENT) {
        ap_send_http_header(r);
        ap_finalize_request_protocol(r);
        return;
    }

    if (!r->assbackwards) {
        table *tmp = r->headers_out;

        /* For all HTTP/1.x responses for which we generate the message,
         * we need to avoid inheriting the "normal status" header fields
         * that may have been set by the request handler before the
         * error or redirect, except for Location on external redirects.
         */
        r->headers_out = r->err_headers_out;
        r->err_headers_out = tmp;
        ap_clear_table(r->err_headers_out);

        if (location && *location
            && (ap_is_HTTP_REDIRECT(status) || status == HTTP_CREATED))
            ap_table_setn(r->headers_out, "Location", location);

        r->content_language = NULL;
        r->content_languages = NULL;
        r->content_encoding = NULL;
        r->clength = 0;
        r->content_type = "text/html";

        if ((status == METHOD_NOT_ALLOWED) || (status == NOT_IMPLEMENTED))
            ap_table_setn(r->headers_out, "Allow", make_allow(r));

        ap_send_http_header(r);

        if (r->header_only) {
            ap_finalize_request_protocol(r);
            return;
        }
    }

    ap_hard_timeout("send error body", r);

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
            ap_bputs(custom_response + 1, fd);
            ap_kill_timeout(r);
            ap_finalize_request_protocol(r);
            return;
        }
        /*
         * Redirect failed, so get back the original error
         */
        while (r->prev && (r->prev->status != HTTP_OK))
            r = r->prev;
    }
    {
        char *title = status_lines[idx];
        char *h1;
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

        ap_bvputs(fd,
                  "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                  "<HTML><HEAD>\n<TITLE>", title,
                  "</TITLE>\n</HEAD><BODY>\n<H1>", h1, "</H1>\n",
                  NULL);

	switch (status) {
	case HTTP_MOVED_PERMANENTLY:
	case HTTP_MOVED_TEMPORARILY:
	case HTTP_TEMPORARY_REDIRECT:
	    ap_bvputs(fd, "The document has moved <A HREF=\"",
		      ap_escape_html(r->pool, location), "\">here</A>.<P>\n",
		      NULL);
	    break;
	case HTTP_SEE_OTHER:
	    ap_bvputs(fd, "The answer to your request is located <A HREF=\"",
		      ap_escape_html(r->pool, location), "\">here</A>.<P>\n",
		      NULL);
	    break;
	case HTTP_USE_PROXY:
	    ap_bvputs(fd, "This resource is only accessible "
		      "through the proxy\n",
		      ap_escape_html(r->pool, location),
		      "<BR>\nYou will need to ",
		      "configure your client to use that proxy.<P>\n", NULL);
	    break;
	case HTTP_PROXY_AUTHENTICATION_REQUIRED:
	case AUTH_REQUIRED:
	    ap_bputs("This server could not verify that you\n", fd);
	    ap_bputs("are authorized to access the document you\n", fd);
	    ap_bputs("requested.  Either you supplied the wrong\n", fd);
	    ap_bputs("credentials (e.g., bad password), or your\n", fd);
	    ap_bputs("browser doesn't understand how to supply\n", fd);
	    ap_bputs("the credentials required.<P>\n", fd);
	    break;
	case BAD_REQUEST:
	    ap_bputs("Your browser sent a request that\n", fd);
	    ap_bputs("this server could not understand.<P>\n", fd);
	    if ((error_notes = ap_table_get(r->notes, "error-notes")) != NULL) {
		ap_bvputs(fd, error_notes, "<P>\n", NULL);
	    }
	    break;
	case HTTP_FORBIDDEN:
	    ap_bvputs(fd, "You don't have permission to access ",
		      ap_escape_html(r->pool, r->uri),
		      "\non this server.<P>\n", NULL);
	    break;
	case NOT_FOUND:
	    ap_bvputs(fd, "The requested URL ",
		      ap_escape_html(r->pool, r->uri),
		      " was not found on this server.<P>\n", NULL);
	    break;
	case METHOD_NOT_ALLOWED:
	    ap_bvputs(fd, "The requested method ", r->method,
		      " is not allowed "
		      "for the URL ", ap_escape_html(r->pool, r->uri),
		      ".<P>\n", NULL);
	    break;
	case NOT_ACCEPTABLE:
	    ap_bvputs(fd,
		      "An appropriate representation of the "
		      "requested resource ",
		      ap_escape_html(r->pool, r->uri),
		      " could not be found on this server.<P>\n", NULL);
	    /* fall through */
	case MULTIPLE_CHOICES:
	    {
		const char *list;
		if ((list = ap_table_get(r->notes, "variant-list")))
		    ap_bputs(list, fd);
	    }
	    break;
	case LENGTH_REQUIRED:
	    ap_bvputs(fd, "A request of the requested method ", r->method,
		      " requires a valid Content-length.<P>\n", NULL);
	    if ((error_notes = ap_table_get(r->notes, "error-notes")) != NULL) {
		ap_bvputs(fd, error_notes, "<P>\n", NULL);
	    }
	    break;
	case PRECONDITION_FAILED:
	    ap_bvputs(fd, "The precondition on the request for the URL ",
		      ap_escape_html(r->pool, r->uri),
		      " evaluated to false.<P>\n", NULL);
	    break;
	case HTTP_NOT_IMPLEMENTED:
	    ap_bvputs(fd, ap_escape_html(r->pool, r->method), " to ",
		      ap_escape_html(r->pool, r->uri),
		      " not supported.<P>\n", NULL);
	    if ((error_notes = ap_table_get(r->notes, "error-notes")) != NULL) {
		ap_bvputs(fd, error_notes, "<P>\n", NULL);
	    }
	    break;
	case BAD_GATEWAY:
	    ap_bputs("The proxy server received an invalid\015\012", fd);
	    ap_bputs("response from an upstream server.<P>\015\012", fd);
	    break;
	case VARIANT_ALSO_VARIES:
	    ap_bvputs(fd, "A variant for the requested resource\n<PRE>\n",
		      ap_escape_html(r->pool, r->uri),
		      "\n</PRE>\nis itself a negotiable resource. "
		      "This indicates a configuration error.<P>\n", NULL);
	    break;
	case HTTP_REQUEST_TIME_OUT:
	    ap_bputs("I'm tired of waiting for your request.\n", fd);
	    break;
	case HTTP_GONE:
	    ap_bvputs(fd, "The requested resource<BR>",
		      ap_escape_html(r->pool, r->uri),
		      "<BR>\nis no longer available on this server ",
		      "and there is no forwarding address.\n",
		      "Please remove all references to this resource.\n",
		      NULL);
	    break;
	case HTTP_REQUEST_ENTITY_TOO_LARGE:
	    ap_bvputs(fd, "The requested resource<BR>",
		      ap_escape_html(r->pool, r->uri), "<BR>\n",
		      "does not allow request data with ", r->method,
		      " requests, or the amount of data provided in\n",
		      "the request exceeds the capacity limit.\n", NULL);
	    break;
	case HTTP_REQUEST_URI_TOO_LARGE:
	    ap_bputs("The requested URL's length exceeds the capacity\n"
	             "limit for this server.<P>\n", fd);
	    if ((error_notes = ap_table_get(r->notes, "error-notes")) != NULL) {
		ap_bvputs(fd, error_notes, "<P>\n", NULL);
	    }
	    break;
	case HTTP_UNSUPPORTED_MEDIA_TYPE:
	    ap_bputs("The supplied request data is not in a format\n"
	             "acceptable for processing by this resource.\n", fd);
	    break;
	case HTTP_RANGE_NOT_SATISFIABLE:
	    ap_bputs("None of the range-specifier values in the Range\n"
	             "request-header field overlap the current extent\n"
	             "of the selected resource.\n", fd);
	    break;
	case HTTP_EXPECTATION_FAILED:
	    ap_bvputs(fd, "The expectation given in the Expect request-header"
	              "\nfield could not be met by this server.<P>\n"
	              "The client sent<PRE>\n    Expect: ",
	              ap_table_get(r->headers_in, "Expect"), "\n</PRE>\n"
	              "but we only allow the 100-continue expectation.\n",
	              NULL);
	    break;
	case HTTP_UNPROCESSABLE_ENTITY:
	    ap_bputs("The server understands the media type of the\n"
	             "request entity, but was unable to process the\n"
	             "contained instructions.\n", fd);
	    break;
	case HTTP_LOCKED:
	    ap_bputs("The requested resource is currently locked.\n"
	             "The lock must be released or proper identification\n"
	             "given before the method can be applied.\n", fd);
	    break;
	case HTTP_FAILED_DEPENDENCY:
	    ap_bputs("The method could not be performed on the resource\n"
	             "because the requested action depended on another\n"
	             "action and that other action failed.\n", fd);
	    break;
	case HTTP_INSUFFICIENT_STORAGE:
	    ap_bputs("The method could not be performed on the resource\n"
	             "because the server is unable to store the\n"
	             "representation needed to successfully complete the\n"
	             "request.  There is insufficient free space left in\n"
	             "your storage allocation.\n", fd);
	    break;
	case HTTP_SERVICE_UNAVAILABLE:
	    ap_bputs("The server is temporarily unable to service your\n"
	             "request due to maintenance downtime or capacity\n"
	             "problems. Please try again later.\n", fd);
	    break;
	case HTTP_GATEWAY_TIME_OUT:
	    ap_bputs("The proxy server did not receive a timely response\n"
	             "from the upstream server.\n", fd);
	    break;
	case HTTP_NOT_EXTENDED:
	    ap_bputs("A mandatory extension policy in the request is not\n"
                     "accepted by the server for this resource.\n", fd);
	    break;
	default:            /* HTTP_INTERNAL_SERVER_ERROR */
	    ap_bvputs(fd, "The server encountered an internal error or\n"
	             "misconfiguration and was unable to complete\n"
	             "your request.<P>\n"
	             "Please contact the server administrator,\n ",
	             ap_escape_html(r->pool, r->server->server_admin),
	             " and inform them of the time the error occurred,\n"
	             "and anything you might have done that may have\n"
	             "caused the error.<P>\n"
		     "More information about this error may be available\n"
		     "in the server error log.<P>\n", NULL);
	 /*
	  * It would be nice to give the user the information they need to
	  * fix the problem directly since many users don't have access to
	  * the error_log (think University sites) even though they can easily
	  * get this error by misconfiguring an htaccess file.  However, the
	  * error notes tend to include the real file pathname in this case,
	  * which some people consider to be a breach of privacy.  Until we
	  * can figure out a way to remove the pathname, leave this commented.
	  *
	  * if ((error_notes = ap_table_get(r->notes, "error-notes")) != NULL) {
	  *     ap_bvputs(fd, error_notes, "<P>\n", NULL);
	  * }
	  */
	    break;
	}

        if (recursive_error) {
            ap_bvputs(fd, "<P>Additionally, a ",
                      status_lines[ap_index_of_response(recursive_error)],
                      "\nerror was encountered while trying to use an "
                      "ErrorDocument to handle the request.\n", NULL);
        }
        ap_bputs(ap_psignature("<HR>\n", r), fd);
        ap_bputs("</BODY></HTML>\n", fd);
    }
    ap_kill_timeout(r);
    ap_finalize_request_protocol(r);
}
