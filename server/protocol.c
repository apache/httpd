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
#include "apr_strmatch.h"

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
#include "mod_core.h"
#include "util_charset.h"
#include "util_ebcdic.h"
#include "scoreboard.h"

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

AP_DECLARE_DATA ap_filter_rec_t *ap_old_write_func = NULL;


/* Patterns to match in ap_make_content_type() */
static const char *needcset[] = {
    "text/plain",
    "text/html",
    NULL
};
static const apr_strmatch_pattern **needcset_patterns;
static const apr_strmatch_pattern *charset_pattern;

AP_DECLARE(void) ap_setup_make_content_type(apr_pool_t *pool)
{
    int i;
    for (i = 0; needcset[i]; i++) {
        continue;
    }
    needcset_patterns = (const apr_strmatch_pattern **)
        apr_palloc(pool, (i + 1) * sizeof(apr_strmatch_pattern *));
    for (i = 0; needcset[i]; i++) {
        needcset_patterns[i] = apr_strmatch_precompile(pool, needcset[i], 0);
    }
    needcset_patterns[i] = NULL;
    charset_pattern = apr_strmatch_precompile(pool, "charset=", 0);
}

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
    const apr_strmatch_pattern **pcset;
    core_dir_config *conf =
        (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &core_module);
    apr_size_t type_len;

    if (!type) {
        type = ap_default_type(r);
    }

    if (conf->add_default_charset != ADD_DEFAULT_CHARSET_ON) {
        return type;
    }

    type_len = strlen(type);

    if (apr_strmatch(charset_pattern, type, type_len) != NULL) {
        /* already has parameter, do nothing */
        /* XXX we don't check the validity */
        ;
    }
    else {
        /* see if it makes sense to add the charset. At present,
         * we only add it if the Content-type is one of needcset[]
         */
        for (pcset = needcset_patterns; *pcset ; pcset++) {
            if (apr_strmatch(*pcset, type, type_len) != NULL) {
                struct iovec concat[3];
                concat[0].iov_base = (void *)type;
                concat[0].iov_len = type_len;
                concat[1].iov_base = (void *)"; charset=";
                concat[1].iov_len = sizeof("; charset=") - 1;
                concat[2].iov_base = (void *)(conf->add_default_charset_name);
                concat[2].iov_len = strlen(conf->add_default_charset_name);
                type = apr_pstrcatv(r->pool, concat, 3, NULL);
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

/* Min # of bytes to allocate when reading a request line */
#define MIN_LINE_ALLOC 80

/* Get a line of protocol input, including any continuation lines
 * caused by MIME folding (or broken clients) if fold != 0, and place it
 * in the buffer s, of size n bytes, without the ending newline.
 *
 * If s is NULL, ap_rgetline_core will allocate necessary memory from r->pool.
 *
 * Returns APR_SUCCESS if there are no problems and sets *read to be
 * the full length of s.
 *
 * APR_ENOSPC is returned if there is not enough buffer space.
 * Other errors may be returned on other errors.
 *
 * The LF is *not* returned in the buffer.  Therefore, a *read of 0
 * indicates that an empty line was read.
 *
 * Notes: Because the buffer uses 1 char for NUL, the most we can return is
 *        (n - 1) actual characters.
 *
 *        If no LF is detected on the last line due to a dropped connection
 *        or a full buffer, that's considered an error.
 */
AP_DECLARE(apr_status_t) ap_rgetline_core(char **s, apr_size_t n,
                                          apr_size_t *read, request_rec *r,
                                          int fold, apr_bucket_brigade *bb)
{
    apr_status_t rv;
    apr_bucket *e;
    apr_size_t bytes_handled = 0, current_alloc = 0;
    char *pos, *last_char = *s;
    int do_alloc = (*s == NULL), saw_eos = 0;

    for (;;) {
    apr_brigade_cleanup(bb);
    rv = ap_get_brigade(r->input_filters, bb, AP_MODE_GETLINE,
                        APR_BLOCK_READ, 0);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    /* Something horribly wrong happened.  Someone didn't block! */
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_EGENERAL;
    }

    APR_BRIGADE_FOREACH(e, bb) {
        const char *str;
        apr_size_t len;

        /* If we see an EOS, don't bother doing anything more. */
        if (APR_BUCKET_IS_EOS(e)) {
            saw_eos = 1;
            break;
        }

        rv = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        if (len == 0) {
            /* no use attempting a zero-byte alloc (hurts when
             * using --with-efence --enable-pool-debug) or
             * doing any of the other logic either
             */
            continue;
        }

        /* Would this overrun our buffer?  If so, we'll die. */
        if (n < bytes_handled + len) {
            *read = bytes_handled;
            return APR_ENOSPC;
        }

        /* Do we have to handle the allocation ourselves? */
        if (do_alloc) {
            /* We'll assume the common case where one bucket is enough. */
            if (!*s) {
                current_alloc = len;
                if (current_alloc < MIN_LINE_ALLOC) {
                    current_alloc = MIN_LINE_ALLOC;
                }
                *s = apr_palloc(r->pool, current_alloc);
            }
            else if (bytes_handled + len > current_alloc) {
                /* Increase the buffer size */
                apr_size_t new_size = current_alloc * 2;
                char *new_buffer;

                if (bytes_handled + len > new_size) {
                    new_size = (bytes_handled + len) * 2;
                }

                new_buffer = apr_palloc(r->pool, new_size);

                /* Copy what we already had. */
                memcpy(new_buffer, *s, bytes_handled);
                current_alloc = new_size;
                *s = new_buffer;
            }
        }

        /* Just copy the rest of the data to the end of the old buffer. */
        pos = *s + bytes_handled;
        memcpy(pos, str, len);
        last_char = pos + len - 1;

        /* We've now processed that new data - update accordingly. */
        bytes_handled += len;
    }

        /* If we got a full line of input, stop reading */
        if (last_char && (*last_char == APR_ASCII_LF)) {
            break;
        }
    }

    /* We now go backwards over any CR (if present) or white spaces.
     *
     * Trim any extra trailing spaces or tabs except for the first
     * space or tab at the beginning of a blank string.  This makes
     * it much easier to check field values for exact matches, and
     * saves memory as well.  Terminate string at end of line.
     */
    pos = last_char;
    if (pos > *s && *(pos - 1) == APR_ASCII_CR) {
        --pos;
    }

    /* Trim any extra trailing spaces or tabs except for the first
     * space or tab at the beginning of a blank string.  This makes
     * it much easier to check field values for exact matches, and
     * saves memory as well.
     */
    while (pos > ((*s) + 1)
           && (*(pos - 1) == APR_ASCII_BLANK || *(pos - 1) == APR_ASCII_TAB)) {
        --pos;
    }

    /* Since we want to remove the LF from the line, we'll go ahead
     * and set this last character to be the term NULL and reset
     * bytes_handled accordingly.
     */
    *pos = '\0';
    last_char = pos;
    bytes_handled = pos - *s;

    /* If we're folding, we have more work to do.
     *
     * Note that if an EOS was seen, we know we can't have another line.
     */
    if (fold && bytes_handled && !saw_eos) {
        for (;;) {
        const char *str;
        apr_size_t len;
        char c;

        /* Clear the temp brigade for this filter read. */
        apr_brigade_cleanup(bb);

        /* We only care about the first byte. */
        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_SPECULATIVE,
                            APR_BLOCK_READ, 1);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        if (APR_BRIGADE_EMPTY(bb)) {
                break;
        }

        e = APR_BRIGADE_FIRST(bb);

        /* If we see an EOS, don't bother doing anything more. */
        if (APR_BUCKET_IS_EOS(e)) {
                break;
        }

        rv = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);

        if (rv != APR_SUCCESS) {
                apr_brigade_cleanup(bb);
            return rv;
        }

        /* Found one, so call ourselves again to get the next line.
         *
         * FIXME: If the folding line is completely blank, should we
         * stop folding?  Does that require also looking at the next
         * char?
         */
            /* When we call destroy, the buckets are deleted, so save that
             * one character we need.  This simplifies our execution paths
             * at the cost of one character read.
             */
            c = *str;
        if (c == APR_ASCII_BLANK || c == APR_ASCII_TAB) {
            /* Do we have enough space? We may be full now. */
                if (bytes_handled >= n) {
                    *read = n;
                    return APR_ENOSPC;
                }
                else {
                apr_size_t next_size, next_len;
                char *tmp;

                /* If we're doing the allocations for them, we have to
                 * give ourselves a NULL and copy it on return.
                 */
                if (do_alloc) {
                    tmp = NULL;
                } else {
                    /* We're null terminated. */
                    tmp = last_char;
                }

                next_size = n - bytes_handled;

                    rv = ap_rgetline_core(&tmp, next_size,
                                          &next_len, r, 0, bb);

                if (rv != APR_SUCCESS) {
                    return rv;
                }

                if (do_alloc && next_len > 0) {
                    char *new_buffer;
                    apr_size_t new_size = bytes_handled + next_len + 1;

                    /* we need to alloc an extra byte for a null */
                    new_buffer = apr_palloc(r->pool, new_size);

                    /* Copy what we already had. */
                    memcpy(new_buffer, *s, bytes_handled);

                    /* copy the new line, including the trailing null */
                    memcpy(new_buffer + bytes_handled, tmp, next_len + 1);
                    *s = new_buffer;
                }

                    bytes_handled += next_len;
            }
            }
            else { /* next character is not tab or space */
                break;
            }
        }
    }

    *read = bytes_handled;
    return APR_SUCCESS;
}

#if APR_CHARSET_EBCDIC
AP_DECLARE(apr_status_t) ap_rgetline(char **s, apr_size_t n,
                                     apr_size_t *read, request_rec *r,
                                     int fold, apr_bucket_brigade *bb)
{
    /* on ASCII boxes, ap_rgetline is a macro which simply invokes
     * ap_rgetline_core with the same parms
     *
     * on EBCDIC boxes, each complete http protocol input line needs to be
     * translated into the code page used by the compiler.  Since
     * ap_rgetline_core uses recursion, we do the translation in a wrapper
     * function to insure that each input character gets translated only once.
     */
    apr_status_t rv;

    rv = ap_rgetline_core(s, n, read, r, fold, bb);
    if (rv == APR_SUCCESS) {
        ap_xlate_proto_from_ascii(*s, *read);
    }
    return rv;
}
#endif

AP_DECLARE(int) ap_getline(char *s, int n, request_rec *r, int fold)
{
    char *tmp_s = s;
    apr_status_t rv;
    apr_size_t len;
    apr_bucket_brigade *tmp_bb;

    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    rv = ap_rgetline(&tmp_s, n, &len, r, fold, tmp_bb);
    apr_brigade_destroy(tmp_bb);

    /* Map the out-of-space condition to the old API. */
    if (rv == APR_ENOSPC) {
        return n;
    }

    /* Anything else is just bad. */
    if (rv != APR_SUCCESS) {
        return -1;
    }

    return (int)len;
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
        /* Simple syntax Errors in URLs are trapped by
         * parse_uri_components().
         */
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
#endif /* OS2 || WIN32 */
    }
    else {
        r->args = NULL;
        r->hostname = NULL;
        r->status = HTTP_BAD_REQUEST;             /* set error status */
        r->uri = apr_pstrdup(r->pool, uri);
    }
}

static int read_request_line(request_rec *r, apr_bucket_brigade *bb)
{
    const char *ll;
    const char *uri;
    const char *pro;

#if 0
    conn_rec *conn = r->connection;
#endif
    int major = 1, minor = 0;   /* Assume HTTP/1.0 if non-"HTTP" protocol */
    char http[5];
    apr_size_t len;
    int num_blank_lines = 0;
    int max_blank_lines = r->server->limit_req_fields;

    if (max_blank_lines <= 0) {
        max_blank_lines = DEFAULT_LIMIT_REQUEST_FIELDS;
    }

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

    do {
        apr_status_t rv;

        /* insure ap_rgetline allocates memory each time thru the loop
         * if there are empty lines
         */
        r->the_request = NULL;
        rv = ap_rgetline(&(r->the_request), DEFAULT_LIMIT_REQUEST_LINE + 2,
                         &len, r, 0, bb);

        if (rv != APR_SUCCESS) {
            r->request_time = apr_time_now();
            return 0;
        }
    } while ((len <= 0) && (++num_blank_lines < max_blank_lines));

    /* we've probably got something to do, ignore graceful restart requests */

    r->request_time = apr_time_now();
    ll = r->the_request;
    r->method = ap_getword_white(r->pool, &ll);

#if 0
/* XXX If we want to keep track of the Method, the protocol module should do
 * it.  That support isn't in the scoreboard yet.  Hopefully next week
 * sometime.   rbb */
    ap_update_connection_status(AP_CHILD_THREAD_FROM_ID(conn->id), "Method",
                                r->method);
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
     * The cast is safe, limit_req_line cannot be negative
     */
    if (len > (apr_size_t)r->server->limit_req_line) {
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
    if (len == 8
        && pro[0] == 'H' && pro[1] == 'T' && pro[2] == 'T' && pro[3] == 'P'
        && pro[4] == '/' && apr_isdigit(pro[5]) && pro[6] == '.'
        && apr_isdigit(pro[7])) {
        r->proto_num = HTTP_VERSION(pro[5] - '0', pro[7] - '0');
    }
    else if (3 == sscanf(r->protocol, "%4s/%u.%u", http, &major, &minor)
             && (strcasecmp("http", http) == 0)
             && (minor < HTTP_VERSION(1, 0)) ) /* don't allow HTTP/0.1000 */
        r->proto_num = HTTP_VERSION(major, minor);
    else
        r->proto_num = HTTP_VERSION(1, 0);

    return 1;
}

AP_DECLARE(void) ap_get_mime_headers_core(request_rec *r, apr_bucket_brigade *bb)
{
    char *last_field = NULL;
    apr_size_t last_len = 0;
    apr_size_t alloc_len = 0;
    char *field;
    char *value;
    apr_size_t len;
    int fields_read = 0;
    char *tmp_field;

    /*
     * Read header lines until we get the empty separator line, a read error,
     * the connection closes (EOF), reach the server limit, or we timeout.
     */
    while(1) {
        apr_status_t rv;
        int folded = 0;

        field = NULL;
        rv = ap_rgetline(&field, r->server->limit_req_fieldsize + 2,
                         &len, r, 0, bb);

        if (rv != APR_SUCCESS) {
            r->status = HTTP_BAD_REQUEST;

            /* ap_rgetline returns APR_ENOSPC if it fills up the buffer before
             * finding the end-of-line.  This is only going to happen if it
             * exceeds the configured limit for a field size.
             */
            if (rv == APR_ENOSPC && field) {
                /* insure ap_escape_html will terminate correctly */
                field[len - 1] = '\0';
                apr_table_setn(r->notes, "error-notes",
                               apr_pstrcat(r->pool,
                                           "Size of a request header field "
                                           "exceeds server limit.<br />\n"
                                           "<pre>\n",
                                           ap_escape_html(r->pool, field),
                                           "</pre>\n", NULL));
            }
            return;
        }

        if (last_field != NULL) {
            if ((len > 0) && ((*field == '\t') || *field == ' ')) {
                /* This line is a continuation of the preceding line(s),
                 * so append it to the line that we've set aside.
                 * Note: this uses a power-of-two allocator to avoid
                 * doing O(n) allocs and using O(n^2) space for
                 * continuations that span many many lines.
                 */
                apr_size_t fold_len = last_len + len + 1; /* trailing null */
                if (fold_len > alloc_len) {
                    char *fold_buf;
                    alloc_len += alloc_len;
                    if (fold_len > alloc_len) {
                        alloc_len = fold_len;
                    }
                    fold_buf = (char *)apr_palloc(r->pool, alloc_len);
                    memcpy(fold_buf, last_field, last_len);
                    last_field = fold_buf;
                }
                memcpy(last_field + last_len, field, len +1); /* +1 for nul */
                last_len += len;
                folded = 1;
            }
            else {

                if (r->server->limit_req_fields
                    && (++fields_read > r->server->limit_req_fields)) {
                    r->status = HTTP_BAD_REQUEST;
                    apr_table_setn(r->notes, "error-notes",
                                   "The number of request header fields "
                                   "exceeds this server's limit.");
                    return;
                }

                if (!(value = strchr(last_field, ':'))) { /* Find ':' or    */
                    r->status = HTTP_BAD_REQUEST;      /* abort bad request */
                    apr_table_setn(r->notes, "error-notes",
                                   apr_pstrcat(r->pool,
                                               "Request header field is "
                                               "missing ':' separator.<br />\n"
                                               "<pre>\n",
                                               ap_escape_html(r->pool,
                                                              last_field),
                                               "</pre>\n", NULL));
                    return;
                }

                *value = '\0';
                tmp_field = value;  /* used to trim the whitespace between key
                                     * token and separator
                                     */
                ++value;
                while (*value == ' ' || *value == '\t') {
                    ++value;            /* Skip to start of value   */
                }

                /* This check is to avoid any invalid memory reference while
                 * traversing backwards in the key. To avoid a case where
                 * the header starts with ':' (or with just some white
                 * space and the ':') followed by the value
                 */
                if (tmp_field > last_field) {
                    --tmp_field;
                    while ((tmp_field > last_field) &&
                           (*tmp_field == ' ' || *tmp_field == '\t')) {
                        --tmp_field;   /* Removing LWS between key and ':' */
                    }
                    ++tmp_field;
                    *tmp_field = '\0';
                }

                apr_table_addn(r->headers_in, last_field, value);

                /* reset the alloc_len so that we'll allocate a new
                 * buffer if we have to do any more folding: we can't
                 * use the previous buffer because its contents are
                 * now part of r->headers_in
                 */
                alloc_len = 0;

            } /* end if current line is not a continuation starting with tab */
        }

        /* Found a blank line, stop. */
        if (len == 0) {
            break;
        }

        /* Keep track of this line so that we can parse it on
         * the next loop iteration.  (In the folded case, last_field
         * has been updated already.)
         */
        if (!folded) {
            last_field = field;
            last_len = len;
        }
    }

    apr_table_compress(r->headers_in, APR_OVERLAP_TABLES_MERGE);
}

AP_DECLARE(void) ap_get_mime_headers(request_rec *r)
{
    apr_bucket_brigade *tmp_bb;
    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    ap_get_mime_headers_core(r, tmp_bb);
    apr_brigade_destroy(tmp_bb);
}

request_rec *ap_read_request(conn_rec *conn)
{
    request_rec *r;
    apr_pool_t *p;
    const char *expect;
    int access_status;
    apr_bucket_brigade *tmp_bb;

    apr_pool_create(&p, conn->pool);
    apr_pool_tag(p, "request");
    r = apr_pcalloc(p, sizeof(request_rec));
    r->pool            = p;
    r->connection      = conn;
    r->server          = conn->base_server;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in      = apr_table_make(r->pool, 25);
    r->subprocess_env  = apr_table_make(r->pool, 25);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->notes           = apr_table_make(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    /* Must be set before we run create request hook */

    r->proto_output_filters = conn->output_filters;
    r->output_filters  = r->proto_output_filters;
    r->proto_input_filters = conn->input_filters;
    r->input_filters   = r->proto_input_filters;
    ap_run_create_request(r);
    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_REQUEST_TIME_OUT;  /* Until we get a request */
    r->the_request     = NULL;

    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    /* Get the request... */
    if (!read_request_line(r, tmp_bb)) {
        if (r->status == HTTP_REQUEST_URI_TOO_LARGE) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "request failed: URI too long");
            ap_send_error_response(r, 0);
            ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
            ap_run_log_transaction(r);
            apr_brigade_destroy(tmp_bb);
            return r;
        }

        apr_brigade_destroy(tmp_bb);
        return NULL;
    }

    if (!r->assbackwards) {
        ap_get_mime_headers_core(r, tmp_bb);
        if (r->status != HTTP_REQUEST_TIME_OUT) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "request failed: error reading the headers");
            ap_send_error_response(r, 0);
            ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
            ap_run_log_transaction(r);
            apr_brigade_destroy(tmp_bb);
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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "client sent invalid HTTP/0.9 request: HEAD %s",
                          r->uri);
            r->header_only = 0;
            r->status = HTTP_BAD_REQUEST;
            ap_send_error_response(r, 0);
            ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
            ap_run_log_transaction(r);
            apr_brigade_destroy(tmp_bb);
            return r;
        }
    }

    apr_brigade_destroy(tmp_bb);

    r->status = HTTP_OK;                         /* Until further notice. */

    /* update what we think the virtual host is based on the headers we've
     * now read. may update status.
     */
    ap_update_vhost_from_headers(r);

    /* we may have switched to another server */
    r->per_dir_config = r->server->lookup_defaults;

    if ((!r->hostname && (r->proto_num >= HTTP_VERSION(1, 1)))
        || ((r->proto_num == HTTP_VERSION(1, 1))
            && !apr_table_get(r->headers_in, "Host"))) {
        /*
         * Client sent us an HTTP/1.1 or later request without telling us the
         * hostname, either with a full URL or a Host: header. We therefore
         * need to (as per the 1.1 spec) send an error.  As a special case,
         * HTTP/1.1 mentions twice (S9, S14.23) that a request MUST contain
         * a Host: header, and the server MUST respond with 400 if it doesn't.
         */
        r->status = HTTP_BAD_REQUEST;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "client sent HTTP/1.1 request without hostname "
                      "(see RFC2616 section 14.23): %s", r->uri);
    }

    if (r->status != HTTP_OK) {
        ap_send_error_response(r, 0);
        ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
        ap_run_log_transaction(r);
        return r;
    }

    if ((access_status = ap_run_post_read_request(r))) {
        ap_die(access_status, r);
        ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
        ap_run_log_transaction(r);
        return NULL;
    }

    if (((expect = apr_table_get(r->headers_in, "Expect")) != NULL)
        && (expect[0] != '\0')) {
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
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "client sent an unrecognized expectation value of "
                          "Expect: %s", expect);
            ap_send_error_response(r, 0);
            ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
            ap_run_log_transaction(r);
            return r;
        }
    }

    ap_add_input_filter_handle(ap_http_input_filter_handle,
                               NULL, r, r->connection);

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
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);
}

void ap_finalize_sub_req_protocol(request_rec *sub)
{
    /* tell the filter chain there is no more content coming */
    if (!sub->eos_sent) {
        end_output_stream(sub);
    }
}

/* finalize_request_protocol is called at completion of sending the
 * response.  Its sole purpose is to send the terminating protocol
 * information for any wrappers around the response message body
 * (i.e., transfer encodings).  It should have been named finalize_response.
 */
AP_DECLARE(void) ap_finalize_request_protocol(request_rec *r)
{
    (void) ap_discard_request_body(r);

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
        ap_log_rerror(APLOG_MARK, APLOG_ERR,
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
                       (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate"
                                                       : "WWW-Authenticate",
                       apr_pstrcat(r->pool, "Basic realm=\"", ap_auth_name(r),
                                   "\"", NULL));
}

AP_DECLARE(void) ap_note_digest_auth_failure(request_rec *r)
{
    apr_table_setn(r->err_headers_out,
                   (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate"
                                                   : "WWW-Authenticate",
                   apr_psprintf(r->pool, "Digest realm=\"%s\", nonce=\""
                                "%" APR_UINT64_T_HEX_FMT "\"",
                                ap_auth_name(r), (apr_uint64_t)r->request_time));
}

AP_DECLARE(int) ap_get_basic_auth_pw(request_rec *r, const char **pw)
{
    const char *auth_line = apr_table_get(r->headers_in,
                                          (PROXYREQ_PROXY == r->proxyreq)
                                              ? "Proxy-Authorization"
                                              : "Authorization");
    const char *t;

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Basic"))
        return DECLINED;

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR,
                      0, r, "need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!auth_line) {
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        /* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "client used wrong authentication scheme: %s", r->uri);
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    while (*auth_line == ' ' || *auth_line == '\t') {
        auth_line++;
    }

    t = ap_pbase64decode(r->pool, auth_line);
    r->user = ap_getword_nulls (r->pool, &t, ':');
    r->ap_auth_type = "Basic";

    *pw = t;

    return OK;
}

struct content_length_ctx {
    int data_sent;  /* true if the C-L filter has already sent at
                     * least one bucket on to the next output filter
                     * for this request
                     */
};

/* This filter computes the content length, but it also computes the number
 * of bytes sent to the client.  This means that this filter will always run
 * through all of the buckets in all brigades
 */
AP_CORE_DECLARE_NONSTD(apr_status_t) ap_content_length_filter(
    ap_filter_t *f,
    apr_bucket_brigade *b)
{
    request_rec *r = f->r;
    struct content_length_ctx *ctx;
    apr_bucket *e;
    int eos = 0;
    apr_read_type_e eblock = APR_NONBLOCK_READ;

    ctx = f->ctx;
    if (!ctx) {
        f->ctx = ctx = apr_palloc(r->pool, sizeof(*ctx));
        ctx->data_sent = 0;
    }

    /* Loop through this set of buckets to compute their length
     */
    e = APR_BRIGADE_FIRST(b);
    while (e != APR_BRIGADE_SENTINEL(b)) {
        if (APR_BUCKET_IS_EOS(e)) {
            eos = 1;
            break;
        }
        if (e->length == (apr_size_t)-1) {
            apr_size_t len;
            const char *ignored;
            apr_status_t rv;

            /* This is probably a pipe bucket.  Send everything
             * prior to this, and then read the data for this bucket.
             */
            rv = apr_bucket_read(e, &ignored, &len, eblock);
            if (rv == APR_SUCCESS) {
                /* Attempt a nonblocking read next time through */
                eblock = APR_NONBLOCK_READ;
                r->bytes_sent += len;
            }
            else if (APR_STATUS_IS_EAGAIN(rv)) {
                /* Output everything prior to this bucket, and then
                 * do a blocking read on the next batch.
                 */
                if (e != APR_BRIGADE_FIRST(b)) {
                    apr_bucket_brigade *split = apr_brigade_split(b, e);
                    apr_bucket *flush = apr_bucket_flush_create(r->connection->bucket_alloc);

                    APR_BRIGADE_INSERT_TAIL(b, flush);
                    rv = ap_pass_brigade(f->next, b);
                    if (rv != APR_SUCCESS || f->c->aborted) {
                        apr_brigade_destroy(split);
                        return rv;
                    }
                    b = split;
                    e = APR_BRIGADE_FIRST(b);

                    ctx->data_sent = 1;
                }
                eblock = APR_BLOCK_READ;
                continue;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "ap_content_length_filter: "
                              "apr_bucket_read() failed");
                return rv;
            }
        }
        else {
            r->bytes_sent += e->length;
        }
        e = APR_BUCKET_NEXT(e);
    }

    /* If we've now seen the entire response and it's otherwise
     * okay to set the C-L in the response header, then do so now.
     *
     * We can only set a C-L in the response header if we haven't already
     * sent any buckets on to the next output filter for this request.
     */
    if (ctx->data_sent == 0 && eos) {
        ap_set_content_length(r, r->bytes_sent);
    }

    ctx->data_sent = 1;
    return ap_pass_brigade(f->next, b);
}

/*
 * Send the body of a response to the client.
 */
AP_DECLARE(apr_status_t) ap_send_fd(apr_file_t *fd, request_rec *r,
                                    apr_off_t offset, apr_size_t len,
                                    apr_size_t *nbytes)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb = NULL;
    apr_bucket *b;
    apr_status_t rv;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    b = apr_bucket_file_create(fd, offset, len, r->pool, c->bucket_alloc);
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
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb = NULL;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    b = apr_bucket_mmap_create(mm, offset, length, c->bucket_alloc);
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
        bb = ctx->bb;
        ctx->bb = NULL;
    }

    return ap_pass_brigade(f->next, bb);
}

static apr_status_t buffer_output(request_rec *r,
                                  const char *str, apr_size_t len)
{
    conn_rec *c = r->connection;
    ap_filter_t *f;
    old_write_filter_ctx *ctx;

    if (len == 0)
        return APR_SUCCESS;

    /* future optimization: record some flags in the request_rec to
     * say whether we've added our filter, and whether it is first.
     */

    /* this will typically exit on the first test */
    for (f = r->output_filters; f != NULL; f = f->next) {
        if (ap_old_write_func == f->frec)
            break;
    }

    if (f == NULL) {
        /* our filter hasn't been added yet */
        ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ap_add_output_filter("OLD_WRITE", ctx, r, r->connection);
        f = r->output_filters;
    }

    /* if the first filter is not our buffering filter, then we have to
     * deliver the content through the normal filter chain
     */
    if (f != r->output_filters) {
        apr_bucket_brigade *bb = apr_brigade_create(r->pool, c->bucket_alloc);
        apr_bucket *b = apr_bucket_transient_create(str, len, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);

        return ap_pass_brigade(r->output_filters, bb);
    }

    /* grab the context from our filter */
    ctx = r->output_filters->ctx;

    if (ctx->bb == NULL) {
        ctx->bb = apr_brigade_create(r->pool, c->bucket_alloc);
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
     * ### into a single brigade, rather than flushing each time we
     * ### fill the buffer
     */
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
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    b = apr_bucket_flush_create(c->bucket_alloc);
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
    if (!r->assbackwards) {
        apr_time_t mod_time = ap_rationalize_mtime(r, r->mtime);
        char *datestr = apr_palloc(r->pool, APR_RFC822_DATE_LEN);

        apr_rfc822_date(datestr, mod_time);
        apr_table_setn(r->headers_out, "Last-Modified", datestr);
    }
}

AP_IMPLEMENT_HOOK_RUN_ALL(int,post_read_request,
                          (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,log_transaction,
                          (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *,http_method,
                            (const request_rec *r), (r), NULL)
AP_IMPLEMENT_HOOK_RUN_FIRST(unsigned short,default_port,
                            (const request_rec *r), (r), 0)
