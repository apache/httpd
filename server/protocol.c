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

/*
 * protocol.c --- routines which directly communicate with the client.
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

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

APR_HOOK_STRUCT(
    APR_HOOK_LINK(pre_read_request)
    APR_HOOK_LINK(post_read_request)
    APR_HOOK_LINK(log_transaction)
    APR_HOOK_LINK(http_scheme)
    APR_HOOK_LINK(default_port)
    APR_HOOK_LINK(note_auth_failure)
    APR_HOOK_LINK(protocol_propose)
    APR_HOOK_LINK(protocol_switch)
    APR_HOOK_LINK(protocol_get)
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
 *    - if type is NULL or "", return NULL (do not set content-type).
 *    - if charset adding is disabled, stop processing and return type.
 *    - then, if there are no parameters on type, add the default charset
 *    - return type
 */
AP_DECLARE(const char *)ap_make_content_type(request_rec *r, const char *type)
{
    const apr_strmatch_pattern **pcset;
    core_dir_config *conf =
        (core_dir_config *)ap_get_core_module_config(r->per_dir_config);
    core_request_config *request_conf;
    apr_size_t type_len;

    if (!type || *type == '\0') {
        return NULL;
    }

    if (conf->add_default_charset != ADD_DEFAULT_CHARSET_ON) {
        return type;
    }

    request_conf = ap_get_core_module_config(r->request_config);
    if (request_conf->suppress_charset) {
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

/* Get a line of protocol input, including any continuation lines
 * caused by MIME folding (or broken clients) if fold != 0, and place it
 * in the buffer s, of size n bytes, without the ending newline.
 * 
 * Pulls from r->proto_input_filters instead of r->input_filters for
 * stricter protocol adherence and better input filter behavior during
 * chunked trailer processing (for http).
 *
 * If s is NULL, ap_rgetline_core will allocate necessary memory from r->pool.
 *
 * Returns APR_SUCCESS if there are no problems and sets *read to be
 * the full length of s.
 *
 * APR_ENOSPC is returned if there is not enough buffer space.
 * Other errors may be returned on other errors.
 *
 * The [CR]LF are *not* returned in the buffer.  Therefore, a *read of 0
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
                                          int flags, apr_bucket_brigade *bb)
{
    apr_status_t rv;
    apr_bucket *e;
    apr_size_t bytes_handled = 0, current_alloc = 0;
    char *pos, *last_char = *s;
    int do_alloc = (*s == NULL), saw_eos = 0;
    int fold = flags & AP_GETLINE_FOLD;
    int crlf = flags & AP_GETLINE_CRLF;
    int nospc_eol = flags & AP_GETLINE_NOSPC_EOL;
    int saw_eol = 0, saw_nospc = 0;

    if (!n) {
        /* Needs room for NUL byte at least */
        *read = 0;
        return APR_BADARG;
    }

    /*
     * Initialize last_char as otherwise a random value will be compared
     * against APR_ASCII_LF at the end of the loop if bb only contains
     * zero-length buckets.
     */
    if (last_char)
        *last_char = '\0';

    do {
        apr_brigade_cleanup(bb);
        rv = ap_get_brigade(r->proto_input_filters, bb, AP_MODE_GETLINE,
                            APR_BLOCK_READ, 0);
        if (rv != APR_SUCCESS) {
            goto cleanup;
        }

        /* Something horribly wrong happened.  Someone didn't block! 
         * (this also happens at the end of each keepalive connection)
         */
        if (APR_BRIGADE_EMPTY(bb)) {
            rv = APR_EGENERAL;
            goto cleanup;
        }

        for (e = APR_BRIGADE_FIRST(bb);
             e != APR_BRIGADE_SENTINEL(bb);
             e = APR_BUCKET_NEXT(e))
        {
            const char *str;
            apr_size_t len;

            /* If we see an EOS, don't bother doing anything more. */
            if (APR_BUCKET_IS_EOS(e)) {
                saw_eos = 1;
                break;
            }

            rv = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                goto cleanup;
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
                /* Before we die, let's fill the buffer up to its limit (i.e.
                 * fall through with the remaining length, if any), setting
                 * saw_eol on LF to stop the outer loop appropriately; we may
                 * come back here once the buffer is filled (no LF seen), and
                 * either be done at that time or continue to wait for LF here
                 * if nospc_eol is set.
                 *
                 * But there is also a corner cases which we want to address,
                 * namely if the buffer is overrun by the final LF only (i.e.
                 * the CR fits in); this is not really an overrun since we'll
                 * strip the CR finally (and use it for NUL byte), but anyway
                 * we have to handle the case so that it's not returned to the
                 * caller as part of the truncated line (it's not!). This is
                 * easier to consider that LF is out of counting and thus fall
                 * through with no error (saw_eol is set to 2 so that we later
                 * ignore LF handling already done here), while folding and
                 * nospc_eol logics continue to work (or fail) appropriately.
                 */
                saw_eol = (str[len - 1] == APR_ASCII_LF);
                if (/* First time around */
                    saw_eol && !saw_nospc
                    /*  Single LF completing the buffered CR, */
                    && ((len == 1 && ((*s)[bytes_handled - 1] == APR_ASCII_CR))
                    /*  or trailing CRLF overuns by LF only */
                        || (len > 1 && str[len - 2] == APR_ASCII_CR
                            && n - bytes_handled + 1 == len))) {
                    /* In both cases *last_char is (to be) the CR stripped by
                     * later 'bytes_handled = last_char - *s'.
                     */
                    saw_eol = 2;
                }
                else {
                    /* In any other case we'd lose data. */
                    rv = APR_ENOSPC;
                    saw_nospc = 1;
                }
                len = n - bytes_handled;
                if (!len) {
                    if (saw_eol) {
                        break;
                    }
                    if (nospc_eol) {
                        continue;
                    }
                    goto cleanup;
                }
            }

            /* Do we have to handle the allocation ourselves? */
            if (do_alloc) {
                /* We'll assume the common case where one bucket is enough. */
                if (!*s) {
                    current_alloc = len;
                    *s = apr_palloc(r->pool, current_alloc + 1);
                }
                else if (bytes_handled + len > current_alloc) {
                    /* Increase the buffer size */
                    apr_size_t new_size = current_alloc * 2;
                    char *new_buffer;

                    if (bytes_handled + len > new_size) {
                        new_size = (bytes_handled + len) * 2;
                    }

                    new_buffer = apr_palloc(r->pool, new_size + 1);

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
            saw_eol = 1;
        }
    } while (!saw_eol);

    if (rv != APR_SUCCESS) {
        /* End of line after APR_ENOSPC above */
        goto cleanup;
    }

    /* Now terminate the string at the end of the line;
     * if the last-but-one character is a CR, terminate there.
     * LF is handled above (not accounted) when saw_eol == 2,
     * the last char is CR to terminate at still.
     */
    if (saw_eol < 2) {
        if (last_char > *s && last_char[-1] == APR_ASCII_CR) {
            last_char--;
        }
        else if (crlf) {
            rv = APR_EINVAL;
            goto cleanup;
        }
    }
    bytes_handled = last_char - *s;

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
            rv = ap_get_brigade(r->proto_input_filters, bb, AP_MODE_SPECULATIVE,
                                APR_BLOCK_READ, 1);
            if (rv != APR_SUCCESS) {
                goto cleanup;
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
                goto cleanup;
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
                    rv = APR_ENOSPC;
                    goto cleanup;
                }
                else {
                    apr_size_t next_size, next_len;
                    char *tmp;

                    /* If we're doing the allocations for them, we have to
                     * give ourselves a NULL and copy it on return.
                     */
                    if (do_alloc) {
                        tmp = NULL;
                    }
                    else {
                        tmp = last_char;
                    }

                    next_size = n - bytes_handled;

                    rv = ap_rgetline_core(&tmp, next_size, &next_len, r,
                                          flags & ~AP_GETLINE_FOLD, bb);
                    if (rv != APR_SUCCESS) {
                        goto cleanup;
                    }

                    if (do_alloc && next_len > 0) {
                        char *new_buffer;
                        apr_size_t new_size = bytes_handled + next_len + 1;

                        /* we need to alloc an extra byte for a null */
                        new_buffer = apr_palloc(r->pool, new_size);

                        /* Copy what we already had. */
                        memcpy(new_buffer, *s, bytes_handled);

                        /* copy the new line, including the trailing null */
                        memcpy(new_buffer + bytes_handled, tmp, next_len);
                        *s = new_buffer;
                    }

                    last_char += next_len;
                    bytes_handled += next_len;
                }
            }
            else { /* next character is not tab or space */
                break;
            }
        }
    }

cleanup:
    if (bytes_handled >= n) {
        bytes_handled = n - 1;
    }

    *read = bytes_handled;
    if (*s) {
        /* ensure the string is NUL terminated */
        (*s)[*read] = '\0';

        /* PR#43039: We shouldn't accept NULL bytes within the line */
        bytes_handled = strlen(*s);
        if (bytes_handled < *read) {
            ap_log_data(APLOG_MARK, APLOG_DEBUG, ap_server_conf,
                        "NULL bytes in header", *s, *read, 0);
            *read = bytes_handled;
            if (rv == APR_SUCCESS) {
                rv = APR_EINVAL;
            }
        }
    }
    return rv;
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
     * function to ensure that each input character gets translated only once.
     */
    apr_status_t rv;

    rv = ap_rgetline_core(s, n, read, r, fold, bb);
    if (rv == APR_SUCCESS || APR_STATUS_IS_ENOSPC(rv)) {
        ap_xlate_proto_from_ascii(*s, *read);
    }
    return rv;
}
#endif

AP_DECLARE(int) ap_getline(char *s, int n, request_rec *r, int flags)
{
    char *tmp_s = s;
    apr_status_t rv;
    apr_size_t len;
    apr_bucket_brigade *tmp_bb;

    if (n < 1) {
        /* Can't work since we always NUL terminate */
        return -1;
    }

    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    rv = ap_rgetline(&tmp_s, n, &len, r, flags, tmp_bb);
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

    /* http://issues.apache.org/bugzilla/show_bug.cgi?id=31875
     * http://issues.apache.org/bugzilla/show_bug.cgi?id=28450
     *
     * This is not in fact a URI, it's a path.  That matters in the
     * case of a leading double-slash.  We need to resolve the issue
     * by normalizing that out before treating it as a URI.
     */
    while ((uri[0] == '/') && (uri[1] == '/')) {
        ++uri ;
    }
    if (r->method_number == M_CONNECT) {
        status = apr_uri_parse_hostinfo(r->pool, uri, &r->parsed_uri);
    }
    else {
        status = apr_uri_parse(r->pool, uri, &r->parsed_uri);
    }

    if (status == APR_SUCCESS) {
        /* if it has a scheme we may need to do absoluteURI vhost stuff */
        if (r->parsed_uri.scheme
            && !ap_cstr_casecmp(r->parsed_uri.scheme, ap_http_scheme(r))) {
            r->hostname = r->parsed_uri.hostname;
        }
        else if (r->method_number == M_CONNECT) {
            r->hostname = r->parsed_uri.hostname;
        }

        r->args = r->parsed_uri.query;
        if (r->parsed_uri.path) {
            r->uri = r->parsed_uri.path;
        }
        else if (r->method_number == M_OPTIONS) {
            r->uri = apr_pstrdup(r->pool, "*");
        }
        else {
            r->uri = apr_pstrdup(r->pool, "/");
        }

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

/* get the length of the field name for logging, but no more than 80 bytes */
#define LOG_NAME_MAX_LEN 80
static int field_name_len(const char *field)
{
    const char *end = ap_strchr_c(field, ':');
    if (end == NULL || end - field > LOG_NAME_MAX_LEN)
        return LOG_NAME_MAX_LEN;
    return end - field;
}

static int read_request_line(request_rec *r, apr_bucket_brigade *bb)
{
    apr_size_t len;
    int num_blank_lines = DEFAULT_LIMIT_BLANK_LINES;
    core_server_config *conf = ap_get_core_module_config(r->server->module_config);
    int strict = (conf->http_conformance != AP_HTTP_CONFORMANCE_UNSAFE);

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

        /* ensure ap_rgetline allocates memory each time thru the loop
         * if there are empty lines
         */
        r->the_request = NULL;
        rv = ap_rgetline(&(r->the_request), (apr_size_t)(r->server->limit_req_line + 2),
                         &len, r, strict ? AP_GETLINE_CRLF : 0, bb);

        if (rv != APR_SUCCESS) {
            r->request_time = apr_time_now();

            /* ap_rgetline returns APR_ENOSPC if it fills up the
             * buffer before finding the end-of-line.  This is only going to
             * happen if it exceeds the configured limit for a request-line.
             */
            if (APR_STATUS_IS_ENOSPC(rv)) {
                r->status = HTTP_REQUEST_URI_TOO_LARGE;
            }
            else if (APR_STATUS_IS_TIMEUP(rv)) {
                r->status = HTTP_REQUEST_TIME_OUT;
            }
            else if (APR_STATUS_IS_EINVAL(rv)) {
                r->status = HTTP_BAD_REQUEST;
            }
            r->proto_num = HTTP_VERSION(1,0);
            r->protocol  = apr_pstrdup(r->pool, "HTTP/1.0");
            return 0;
        }
    } while ((len <= 0) && (--num_blank_lines >= 0));

    /* Set r->request_time before any logging, mod_unique_id needs it. */
    r->request_time = apr_time_now();

    if (APLOGrtrace5(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                      "Request received from client: %s",
                      ap_escape_logitem(r->pool, r->the_request));
    }

    return 1;
}

AP_DECLARE(int) ap_parse_request_line(request_rec *r)
{
    core_server_config *conf = ap_get_core_module_config(r->server->module_config);
    int strict = (conf->http_conformance != AP_HTTP_CONFORMANCE_UNSAFE);
    enum {
        rrl_none, rrl_badmethod, rrl_badwhitespace, rrl_excesswhitespace,
        rrl_missinguri, rrl_baduri, rrl_badprotocol, rrl_trailingtext,
        rrl_badmethod09, rrl_reject09
    } deferred_error = rrl_none;
    apr_size_t len = 0;
    char *uri, *ll;

    r->method = r->the_request;

    /* If there is whitespace before a method, skip it and mark in error */
    if (apr_isspace(*r->method)) {
        deferred_error = rrl_badwhitespace; 
        for ( ; apr_isspace(*r->method); ++r->method)
            ; 
    }

    /* Scan the method up to the next whitespace, ensure it contains only
     * valid http-token characters, otherwise mark in error
     */
    if (strict) {
        ll = (char*) ap_scan_http_token(r->method);
    }
    else {
        ll = (char*) ap_scan_vchar_obstext(r->method);
    }

    if (((ll == r->method) || (*ll && !apr_isspace(*ll)))
            && deferred_error == rrl_none) {
        deferred_error = rrl_badmethod;
        ll = strpbrk(ll, "\t\n\v\f\r ");
    }

    /* Verify method terminated with a single SP, or mark as specific error */
    if (!ll) {
        if (deferred_error == rrl_none)
            deferred_error = rrl_missinguri;
        r->protocol = uri = "";
        goto rrl_done;
    }
    else if (strict && ll[0] && apr_isspace(ll[1])
             && deferred_error == rrl_none) {
        deferred_error = rrl_excesswhitespace; 
    }

    /* Advance uri pointer over leading whitespace, NUL terminate the method
     * If non-SP whitespace is encountered, mark as specific error
     */
    for (uri = ll; apr_isspace(*uri); ++uri) 
        if (*uri != ' ' && deferred_error == rrl_none)
            deferred_error = rrl_badwhitespace; 
    *ll = '\0';

    if (!*uri && deferred_error == rrl_none)
        deferred_error = rrl_missinguri;

    /* Scan the URI up to the next whitespace, ensure it contains no raw
     * control characters, otherwise mark in error
     */
    ll = (char*) ap_scan_vchar_obstext(uri);
    if (ll == uri || (*ll && !apr_isspace(*ll))) {
        deferred_error = rrl_baduri;
        ll = strpbrk(ll, "\t\n\v\f\r ");
    }

    /* Verify URI terminated with a single SP, or mark as specific error */
    if (!ll) {
        r->protocol = "";
        goto rrl_done;
    }
    else if (strict && ll[0] && apr_isspace(ll[1])
             && deferred_error == rrl_none) {
        deferred_error = rrl_excesswhitespace; 
    }

    /* Advance protocol pointer over leading whitespace, NUL terminate the uri
     * If non-SP whitespace is encountered, mark as specific error
     */
    for (r->protocol = ll; apr_isspace(*r->protocol); ++r->protocol) 
        if (*r->protocol != ' ' && deferred_error == rrl_none)
            deferred_error = rrl_badwhitespace; 
    *ll = '\0';

    /* Scan the protocol up to the next whitespace, validation comes later */
    if (!(ll = (char*) ap_scan_vchar_obstext(r->protocol))) {
        len = strlen(r->protocol);
        goto rrl_done;
    }
    len = ll - r->protocol;

    /* Advance over trailing whitespace, if found mark in error,
     * determine if trailing text is found, unconditionally mark in error,
     * finally NUL terminate the protocol string
     */
    if (*ll && !apr_isspace(*ll)) {
        deferred_error = rrl_badprotocol;
    }
    else if (strict && *ll) {
        deferred_error = rrl_excesswhitespace;
    }
    else {
        for ( ; apr_isspace(*ll); ++ll)
            if (*ll != ' ' && deferred_error == rrl_none)
                deferred_error = rrl_badwhitespace; 
        if (*ll && deferred_error == rrl_none)
            deferred_error = rrl_trailingtext;
    }
    *((char *)r->protocol + len) = '\0';

rrl_done:
    /* For internal integrity and palloc efficiency, reconstruct the_request
     * in one palloc, using only single SP characters, per spec.
     */
    r->the_request = apr_pstrcat(r->pool, r->method, *uri ? " " : NULL, uri,
                                 *r->protocol ? " " : NULL, r->protocol, NULL);

    if (len == 8
            && r->protocol[0] == 'H' && r->protocol[1] == 'T'
            && r->protocol[2] == 'T' && r->protocol[3] == 'P'
            && r->protocol[4] == '/' && apr_isdigit(r->protocol[5])
            && r->protocol[6] == '.' && apr_isdigit(r->protocol[7])
            && r->protocol[5] != '0') {
        r->assbackwards = 0;
        r->proto_num = HTTP_VERSION(r->protocol[5] - '0', r->protocol[7] - '0');
    }
    else if (len == 8
                 && (r->protocol[0] == 'H' || r->protocol[0] == 'h')
                 && (r->protocol[1] == 'T' || r->protocol[1] == 't')
                 && (r->protocol[2] == 'T' || r->protocol[2] == 't')
                 && (r->protocol[3] == 'P' || r->protocol[3] == 'p')
                 && r->protocol[4] == '/' && apr_isdigit(r->protocol[5])
                 && r->protocol[6] == '.' && apr_isdigit(r->protocol[7])
                 && r->protocol[5] != '0') {
        r->assbackwards = 0;
        r->proto_num = HTTP_VERSION(r->protocol[5] - '0', r->protocol[7] - '0');
        if (strict && deferred_error == rrl_none)
            deferred_error = rrl_badprotocol;
        else
            memcpy((char*)r->protocol, "HTTP", 4);
    }
    else if (r->protocol[0]) {
        r->proto_num = HTTP_VERSION(0, 9);
        /* Defer setting the r->protocol string till error msg is composed */
        if (deferred_error == rrl_none)
            deferred_error = rrl_badprotocol;
    }
    else {
        r->assbackwards = 1;
        r->protocol  = apr_pstrdup(r->pool, "HTTP/0.9");
        r->proto_num = HTTP_VERSION(0, 9);
    }

    /* Determine the method_number and parse the uri prior to invoking error
     * handling, such that these fields are available for substitution
     */
    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_GET && r->method[0] == 'H')
        r->header_only = 1;

    ap_parse_uri(r, uri);
    if (r->status == HTTP_OK
            && (r->parsed_uri.path != NULL)
            && (r->parsed_uri.path[0] != '/')
            && (r->method_number != M_OPTIONS
                || strcmp(r->parsed_uri.path, "*") != 0)) {
        /* Invalid request-target per RFC 7230 section 5.3 */
        r->status = HTTP_BAD_REQUEST;
    }

    /* With the request understood, we can consider HTTP/0.9 specific errors */
    if (r->proto_num == HTTP_VERSION(0, 9) && deferred_error == rrl_none) {
        if (conf->http09_enable == AP_HTTP09_DISABLE)
            deferred_error = rrl_reject09;
        else if (strict && (r->method_number != M_GET || r->header_only))
            deferred_error = rrl_badmethod09;
    }

    /* Now that the method, uri and protocol are all processed,
     * we can safely resume any deferred error reporting
     */
    if (deferred_error != rrl_none) {
        if (deferred_error == rrl_badmethod)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03445)
                          "HTTP Request Line; Invalid method token: '%.*s'",
                          field_name_len(r->method), r->method);
        else if (deferred_error == rrl_badmethod09)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03444)
                          "HTTP Request Line; Invalid method token: '%.*s'"
                          " (only GET is allowed for HTTP/0.9 requests)",
                          field_name_len(r->method), r->method);
        else if (deferred_error == rrl_missinguri)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03446)
                          "HTTP Request Line; Missing URI");
        else if (deferred_error == rrl_baduri)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03454)
                          "HTTP Request Line; URI incorrectly encoded: '%.*s'",
                          field_name_len(r->unparsed_uri), r->unparsed_uri);
        else if (deferred_error == rrl_badwhitespace)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03447)
                          "HTTP Request Line; Invalid whitespace");
        else if (deferred_error == rrl_excesswhitespace)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03448)
                          "HTTP Request Line; Excess whitespace "
                          "(disallowed by HttpProtocolOptions Strict)");
        else if (deferred_error == rrl_trailingtext)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03449)
                          "HTTP Request Line; Extraneous text found '%.*s' "
                          "(perhaps whitespace was injected?)",
                          field_name_len(ll), ll);
        else if (deferred_error == rrl_reject09)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02401)
                          "HTTP Request Line; Rejected HTTP/0.9 request");
        else if (deferred_error == rrl_badprotocol)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02418)
                          "HTTP Request Line; Unrecognized protocol '%.*s' "
                          "(perhaps whitespace was injected?)",
                          field_name_len(r->protocol), r->protocol);
        r->status = HTTP_BAD_REQUEST;
        goto rrl_failed;
    }

    if (conf->http_methods == AP_HTTP_METHODS_REGISTERED
            && r->method_number == M_INVALID) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02423)
                      "HTTP Request Line; Unrecognized HTTP method: '%.*s' "
                      "(disallowed by RegisteredMethods)",
                      field_name_len(r->method), r->method);
        r->status = HTTP_NOT_IMPLEMENTED;
        /* This can't happen in an HTTP/0.9 request, we verified GET above */
        return 0;
    }

    if (r->status != HTTP_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03450)
                      "HTTP Request Line; Unable to parse URI: '%.*s'",
                      field_name_len(r->uri), r->uri);
        goto rrl_failed;
    }

    if (strict) {
        if (r->parsed_uri.fragment) {
            /* RFC3986 3.5: no fragment */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02421)
                          "HTTP Request Line; URI must not contain a fragment");
            r->status = HTTP_BAD_REQUEST;
            goto rrl_failed;
        }
        if (r->parsed_uri.user || r->parsed_uri.password) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02422)
                          "HTTP Request Line; URI must not contain a "
                          "username/password");
            r->status = HTTP_BAD_REQUEST;
            goto rrl_failed;
        }
    }

    return 1;

rrl_failed:
    if (r->proto_num == HTTP_VERSION(0, 9)) {
        /* Send all parsing and protocol error response with 1.x behavior,
         * and reserve 505 errors for actual HTTP protocols presented.
         * As called out in RFC7230 3.5, any errors parsing the protocol
         * from the request line are nearly always misencoded HTTP/1.x
         * requests. Only a valid 0.9 request with no parsing errors
         * at all may be treated as a simple request, if allowed.
         */
        r->assbackwards = 0;
        r->connection->keepalive = AP_CONN_CLOSE;
        r->proto_num = HTTP_VERSION(1, 0);
        r->protocol  = apr_pstrdup(r->pool, "HTTP/1.0");
    }
    return 0;
}

AP_DECLARE(int) ap_check_request_header(request_rec *r)
{
    core_server_config *conf;
    int strict_host_check;
    const char *expect;
    int access_status;

    conf = ap_get_core_module_config(r->server->module_config);

    /* update what we think the virtual host is based on the headers we've
     * now read. may update status.
     */
    strict_host_check = (conf->strict_host_check == AP_CORE_CONFIG_ON);
    access_status = ap_update_vhost_from_headers_ex(r, strict_host_check);
    if (strict_host_check && access_status != HTTP_OK) { 
        if (r->server == ap_server_conf) { 
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10156)
                          "Requested hostname '%s' did not match any ServerName/ServerAlias "
                          "in the global server configuration ", r->hostname);
        }
        else { 
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10157)
                          "Requested hostname '%s' did not match any ServerName/ServerAlias "
                          "in the matching virtual host (default vhost for "
                          "current connection is %s:%u)", 
                          r->hostname, r->server->defn_name, r->server->defn_line_number);
        }
        r->status = access_status;
    }
    if (r->status != HTTP_OK) { 
        return 0;
    }

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
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00569)
                      "client sent HTTP/1.1 request without hostname "
                      "(see RFC2616 section 14.23): %s", r->uri);
        r->status = HTTP_BAD_REQUEST;
        return 0;
    }

    if (((expect = apr_table_get(r->headers_in, "Expect")) != NULL)
        && (expect[0] != '\0')) {
        /*
         * The Expect header field was added to HTTP/1.1 after RFC 2068
         * as a means to signal when a 100 response is desired and,
         * unfortunately, to signal a poor man's mandatory extension that
         * the server must understand or return 417 Expectation Failed.
         */
        if (ap_cstr_casecmp(expect, "100-continue") == 0) {
            r->expecting_100 = 1;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00570)
                          "client sent an unrecognized expectation value "
                          "of Expect: %s", expect);
            r->status = HTTP_EXPECTATION_FAILED;
            return 0;
        }
    }

    return 1;
}

static int table_do_fn_check_lengths(void *r_, const char *key,
                                     const char *value)
{
    request_rec *r = r_;
    if (value == NULL || r->server->limit_req_fieldsize >= strlen(value) )
        return 1;

    r->status = HTTP_BAD_REQUEST;
    apr_table_setn(r->notes, "error-notes",
                   "Size of a request header field exceeds server limit.");
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00560) "Request "
                  "header exceeds LimitRequestFieldSize after merging: %.*s",
                  field_name_len(key), key);
    return 0;
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
    core_server_config *conf = ap_get_core_module_config(r->server->module_config);
    int strict = (conf->http_conformance != AP_HTTP_CONFORMANCE_UNSAFE);

    /*
     * Read header lines until we get the empty separator line, a read error,
     * the connection closes (EOF), reach the server limit, or we timeout.
     */
    while(1) {
        apr_status_t rv;

        field = NULL;
        rv = ap_rgetline(&field, r->server->limit_req_fieldsize + 2,
                         &len, r, strict ? AP_GETLINE_CRLF : 0, bb);

        if (rv != APR_SUCCESS) {
            if (APR_STATUS_IS_TIMEUP(rv)) {
                r->status = HTTP_REQUEST_TIME_OUT;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                              "Failed to read request header line %s", field);
                r->status = HTTP_BAD_REQUEST;
            }

            /* ap_rgetline returns APR_ENOSPC if it fills up the buffer before
             * finding the end-of-line.  This is only going to happen if it
             * exceeds the configured limit for a field size.
             */
            if (rv == APR_ENOSPC) {
                apr_table_setn(r->notes, "error-notes",
                               "Size of a request header field "
                               "exceeds server limit.");
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00561)
                              "Request header exceeds LimitRequestFieldSize%s"
                              "%.*s",
                              (field && *field) ? ": " : "",
                              (field) ? field_name_len(field) : 0,
                              (field) ? field : "");
            }
            return;
        }

        /* For all header values, and all obs-fold lines, the presence of
         * additional whitespace is a no-op, so collapse trailing whitespace
         * to save buffer allocation and optimize copy operations.
         * Do not remove the last single whitespace under any condition.
         */
        while (len > 1 && (field[len-1] == '\t' || field[len-1] == ' ')) {
            field[--len] = '\0';
        } 

        if (*field == '\t' || *field == ' ') {

            /* Append any newly-read obs-fold line onto the preceding
             * last_field line we are processing
             */
            apr_size_t fold_len;

            if (last_field == NULL) {
                r->status = HTTP_BAD_REQUEST;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03442)
                              "Line folding encountered before first"
                              " header line");
                return;
            }

            if (field[1] == '\0') {
                r->status = HTTP_BAD_REQUEST;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03443)
                              "Empty folded line encountered");
                return;
            }

            /* Leading whitespace on an obs-fold line can be
             * similarly discarded */
            while (field[1] == '\t' || field[1] == ' ') {
                ++field; --len;
            }

            /* This line is a continuation of the preceding line(s),
             * so append it to the line that we've set aside.
             * Note: this uses a power-of-two allocator to avoid
             * doing O(n) allocs and using O(n^2) space for
             * continuations that span many many lines.
             */
            fold_len = last_len + len + 1; /* trailing null */

            if (fold_len >= (apr_size_t)(r->server->limit_req_fieldsize)) {
                r->status = HTTP_BAD_REQUEST;
                /* report what we have accumulated so far before the
                 * overflow (last_field) as the field with the problem
                 */
                apr_table_setn(r->notes, "error-notes",
                               "Size of a request header field "
                               "exceeds server limit.");
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00562)
                              "Request header exceeds LimitRequestFieldSize "
                              "after folding: %.*s",
                              field_name_len(last_field), last_field);
                return;
            }

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
            /* Replace obs-fold w/ SP per RFC 7230 3.2.4 */
            last_field[last_len] = ' ';
            last_len += len;

            /* We've appended this obs-fold line to last_len, proceed to
             * read the next input line
             */
            continue;
        }
        else if (last_field != NULL) {

            /* Process the previous last_field header line with all obs-folded
             * segments already concatenated (this is not operating on the
             * most recently read input line).
             */

            if (r->server->limit_req_fields
                    && (++fields_read > r->server->limit_req_fields)) {
                r->status = HTTP_BAD_REQUEST;
                apr_table_setn(r->notes, "error-notes",
                               "The number of request header fields "
                               "exceeds this server's limit.");
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00563)
                              "Number of request headers exceeds "
                              "LimitRequestFields");
                return;
            }

            if (!strict)
            {
                /* Not Strict ('Unsafe' mode), using the legacy parser */

                if (!(value = strchr(last_field, ':'))) { /* Find ':' or */
                    r->status = HTTP_BAD_REQUEST;   /* abort bad request */
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00564)
                                  "Request header field is missing ':' "
                                  "separator: %.*s", (int)LOG_NAME_MAX_LEN,
                                  last_field);
                    return;
                }

                if (value == last_field) {
                    r->status = HTTP_BAD_REQUEST;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03453)
                                  "Request header field name was empty");
                    return;
                }

                *value++ = '\0'; /* NUL-terminate at colon */

                if (strpbrk(last_field, "\t\n\v\f\r ")) {
                    r->status = HTTP_BAD_REQUEST;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03452)
                                  "Request header field name presented"
                                  " invalid whitespace");
                    return;
                }

                while (*value == ' ' || *value == '\t') {
                     ++value;            /* Skip to start of value   */
                }

                if (strpbrk(value, "\n\v\f\r")) {
                    r->status = HTTP_BAD_REQUEST;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03451)
                                  "Request header field value presented"
                                  " bad whitespace");
                    return;
                }
            }
            else /* Using strict RFC7230 parsing */
            {
                /* Ensure valid token chars before ':' per RFC 7230 3.2.4 */
                value = (char *)ap_scan_http_token(last_field);
                if ((value == last_field) || *value != ':') {
                    r->status = HTTP_BAD_REQUEST;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02426)
                                  "Request header field name is malformed: "
                                  "%.*s", (int)LOG_NAME_MAX_LEN, last_field);
                    return;
                }

                *value++ = '\0'; /* NUL-terminate last_field name at ':' */

                while (*value == ' ' || *value == '\t') {
                    ++value;     /* Skip LWS of value */
                }

                /* Find invalid, non-HT ctrl char, or the trailing NULL */
                tmp_field = (char *)ap_scan_http_field_content(value);

                /* Reject value for all garbage input (CTRLs excluding HT)
                 * e.g. only VCHAR / SP / HT / obs-text are allowed per
                 * RFC7230 3.2.6 - leave all more explicit rule enforcement
                 * for specific header handler logic later in the cycle
                 */
                if (*tmp_field != '\0') {
                    r->status = HTTP_BAD_REQUEST;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02427)
                                  "Request header value is malformed: "
                                  "%.*s", (int)LOG_NAME_MAX_LEN, value);
                    return;
                }
            }

            apr_table_addn(r->headers_in, last_field, value);

            /* This last_field header is now stored in headers_in,
             * resume processing of the current input line.
             */
        }

        /* Found the terminating empty end-of-headers line, stop. */
        if (len == 0) {
            break;
        }

        /* Keep track of this new header line so that we can extend it across
         * any obs-fold or parse it on the next loop iteration. We referenced
         * our previously allocated buffer in r->headers_in,
         * so allocate a fresh buffer if required.
         */
        alloc_len = 0;
        last_field = field;
        last_len = len;
    }

    /* Combine multiple message-header fields with the same
     * field-name, following RFC 2616, 4.2.
     */
    apr_table_compress(r->headers_in, APR_OVERLAP_TABLES_MERGE);

    /* enforce LimitRequestFieldSize for merged headers */
    apr_table_do(table_do_fn_check_lengths, r, r->headers_in, NULL);
}

AP_DECLARE(void) ap_get_mime_headers(request_rec *r)
{
    apr_bucket_brigade *tmp_bb;
    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    ap_get_mime_headers_core(r, tmp_bb);
    apr_brigade_destroy(tmp_bb);
}

AP_DECLARE(request_rec *) ap_create_request(conn_rec *conn)
{
    request_rec *r;
    apr_pool_t *p;

    apr_pool_create(&p, conn->pool);
    apr_pool_tag(p, "request");
    r = apr_pcalloc(p, sizeof(request_rec));
    AP_READ_REQUEST_ENTRY((intptr_t)r, (uintptr_t)conn);
    r->pool            = p;
    r->connection      = conn;
    r->server          = conn->base_server;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in      = apr_table_make(r->pool, 25);
    r->trailers_in     = apr_table_make(r->pool, 5);
    r->subprocess_env  = apr_table_make(r->pool, 25);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->trailers_out    = apr_table_make(r->pool, 5);
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

    r->status          = HTTP_OK;  /* Until further notice */
    r->header_only     = 0;
    r->the_request     = NULL;

    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

    r->useragent_addr = conn->client_addr;
    r->useragent_ip = conn->client_ip;

    return r;
}

/* Apply the server's timeout/config to the connection/request. */
static void apply_server_config(request_rec *r)
{
    apr_socket_t *csd;

    csd = ap_get_conn_socket(r->connection);
    apr_socket_timeout_set(csd, r->server->timeout);

    r->per_dir_config = r->server->lookup_defaults;
}

request_rec *ap_read_request(conn_rec *conn)
{
    int access_status;
    apr_bucket_brigade *tmp_bb;

    request_rec *r = ap_create_request(conn);

    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    conn->keepalive = AP_CONN_UNKNOWN;

    ap_run_pre_read_request(r, conn);

    /* Get the request... */
    if (!read_request_line(r, tmp_bb) || !ap_parse_request_line(r)) {
        apr_brigade_cleanup(tmp_bb);
        switch (r->status) {
        case HTTP_REQUEST_URI_TOO_LARGE:
        case HTTP_BAD_REQUEST:
        case HTTP_VERSION_NOT_SUPPORTED:
        case HTTP_NOT_IMPLEMENTED:
            if (r->status == HTTP_REQUEST_URI_TOO_LARGE) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00565)
                              "request failed: client's request-line exceeds LimitRequestLine (longer than %d)",
                              r->server->limit_req_line);
            }
            else if (r->method == NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00566)
                              "request failed: malformed request line");
            }
            access_status = r->status;
            goto die_unusable_input;

        case HTTP_REQUEST_TIME_OUT:
            /* Just log, no further action on this connection. */
            ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, NULL);
            if (!r->connection->keepalives)
                ap_run_log_transaction(r);
            break;
        }
        /* Not worth dying with. */
        conn->keepalive = AP_CONN_CLOSE;
        apr_pool_destroy(r->pool);
        goto ignore;
    }
    apr_brigade_cleanup(tmp_bb);

    /* We may have been in keep_alive_timeout mode, so toggle back
     * to the normal timeout mode as we fetch the header lines,
     * as necessary.
     */
    apply_server_config(r);

    if (!r->assbackwards) {
        const char *tenc, *clen;

        ap_get_mime_headers_core(r, tmp_bb);
        apr_brigade_cleanup(tmp_bb);
        if (r->status != HTTP_OK) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00567)
                          "request failed: error reading the headers");
            access_status = r->status;
            goto die_unusable_input;
        }

        clen = apr_table_get(r->headers_in, "Content-Length");
        if (clen) {
            apr_off_t cl;

            if (!ap_parse_strict_length(&cl, clen)) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10242)
                              "client sent invalid Content-Length "
                              "(%s): %s", clen, r->uri);
                access_status = HTTP_BAD_REQUEST;
                goto die_unusable_input;
            }
        }

        tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
        if (tenc) {
            /* https://tools.ietf.org/html/rfc7230
             * Section 3.3.3.3: "If a Transfer-Encoding header field is
             * present in a request and the chunked transfer coding is not
             * the final encoding ...; the server MUST respond with the 400
             * (Bad Request) status code and then close the connection".
             */
            if (!ap_is_chunked(r->pool, tenc)) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02539)
                              "client sent unknown Transfer-Encoding "
                              "(%s): %s", tenc, r->uri);
                access_status = HTTP_BAD_REQUEST;
                goto die_unusable_input;
            }

            /* https://tools.ietf.org/html/rfc7230
             * Section 3.3.3.3: "If a message is received with both a
             * Transfer-Encoding and a Content-Length header field, the
             * Transfer-Encoding overrides the Content-Length. ... A sender
             * MUST remove the received Content-Length field".
             */
            if (clen) {
                apr_table_unset(r->headers_in, "Content-Length");

                /* Don't reuse this connection anyway to avoid confusion with
                 * intermediaries and request/reponse spltting.
                 */
                conn->keepalive = AP_CONN_CLOSE;
            }
        }
    }

    /*
     * Add the HTTP_IN filter here to ensure that ap_discard_request_body
     * called by ap_die and by ap_send_error_response works correctly on
     * status codes that do not cause the connection to be dropped and
     * in situations where the connection should be kept alive.
     */
    ap_add_input_filter_handle(ap_http_input_filter_handle,
                               NULL, r, r->connection);

    /* Validate Host/Expect headers and select vhost. */
    if (!ap_check_request_header(r)) {
        /* we may have switched to another server still */
        apply_server_config(r);
        access_status = r->status;
        goto die_before_hooks;
    }

    /* we may have switched to another server */
    apply_server_config(r);

    if ((access_status = ap_post_read_request(r))) {
        goto die;
    }

    AP_READ_REQUEST_SUCCESS((uintptr_t)r, (char *)r->method,
                            (char *)r->uri, (char *)r->server->defn_name,
                            r->status);
    return r;

    /* Everything falls through on failure */

die_unusable_input:
    /* Input filters are in an undeterminate state, cleanup (including
     * CORE_IN's socket) such that any further attempt to read is EOF.
     */
    {
        ap_filter_t *f = conn->input_filters;
        while (f) {
            if (f->frec == ap_core_input_filter_handle) {
                core_net_rec *net = f->ctx;
                apr_brigade_cleanup(net->in_ctx->b);
                break;
            }
            ap_remove_input_filter(f);
            f = f->next;
        }
        conn->input_filters = r->input_filters = f;
        conn->keepalive = AP_CONN_CLOSE;
    }

die_before_hooks:
    /* First call to ap_die() (non recursive) */
    r->status = HTTP_OK;

die:
    ap_die(access_status, r);

    /* ap_die() sent the response through the output filters, we must now
     * end the request with an EOR bucket for stream/pipeline accounting.
     */
    {
        apr_bucket_brigade *eor_bb;
        eor_bb = apr_brigade_create(conn->pool, conn->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(eor_bb,
                                ap_bucket_eor_create(conn->bucket_alloc, r));
        ap_pass_brigade(conn->output_filters, eor_bb);
        apr_brigade_cleanup(eor_bb);
    }

ignore:
    r = NULL;
    AP_READ_REQUEST_FAILURE((uintptr_t)r);
    return NULL;
}

AP_DECLARE(int) ap_post_read_request(request_rec *r)
{
    int status;

    if ((status = ap_run_post_read_request(r))) {
        return status;
    }

    /* Enforce http(s) only scheme for non-forward-proxy requests */
    if (!r->proxyreq
            && r->parsed_uri.scheme
            && (ap_cstr_casecmpn(r->parsed_uri.scheme, "http", 4) != 0
                || (r->parsed_uri.scheme[4] != '\0'
                    && (apr_tolower(r->parsed_uri.scheme[4]) != 's'
                        || r->parsed_uri.scheme[5] != '\0')))) {
        return HTTP_BAD_REQUEST;
    }

    return OK;
}

/* if a request with a body creates a subrequest, remove original request's
 * input headers which pertain to the body which has already been read.
 * out-of-line helper function for ap_set_sub_req_protocol.
 */

static void strip_headers_request_body(request_rec *rnew)
{
    apr_table_unset(rnew->headers_in, "Content-Encoding");
    apr_table_unset(rnew->headers_in, "Content-Language");
    apr_table_unset(rnew->headers_in, "Content-Length");
    apr_table_unset(rnew->headers_in, "Content-Location");
    apr_table_unset(rnew->headers_in, "Content-MD5");
    apr_table_unset(rnew->headers_in, "Content-Range");
    apr_table_unset(rnew->headers_in, "Content-Type");
    apr_table_unset(rnew->headers_in, "Expires");
    apr_table_unset(rnew->headers_in, "Last-Modified");
    apr_table_unset(rnew->headers_in, "Transfer-Encoding");
}

/*
 * A couple of other functions which initialize some of the fields of
 * a request structure, as appropriate for adjuncts of one kind or another
 * to a request in progress.  Best here, rather than elsewhere, since
 * *someone* has to set the protocol-specific fields...
 */

AP_DECLARE(void) ap_set_sub_req_protocol(request_rec *rnew,
                                         const request_rec *r)
{
    rnew->the_request     = r->the_request;  /* Keep original request-line */

    rnew->assbackwards    = 1;   /* Don't send headers from this. */
    rnew->no_local_copy   = 1;   /* Don't try to send HTTP_NOT_MODIFIED for a
                                  * fragment. */
    rnew->method          = "GET";
    rnew->method_number   = M_GET;
    rnew->protocol        = "INCLUDED";

    rnew->status          = HTTP_OK;

    rnew->headers_in      = apr_table_copy(rnew->pool, r->headers_in);
    rnew->trailers_in     = apr_table_copy(rnew->pool, r->trailers_in);

    /* did the original request have a body?  (e.g. POST w/SSI tags)
     * if so, make sure the subrequest doesn't inherit body headers
     */
    if (!r->kept_body && (apr_table_get(r->headers_in, "Content-Length")
        || apr_table_get(r->headers_in, "Transfer-Encoding"))) {
        strip_headers_request_body(rnew);
    }
    rnew->subprocess_env  = apr_table_copy(rnew->pool, r->subprocess_env);
    rnew->headers_out     = apr_table_make(rnew->pool, 5);
    rnew->err_headers_out = apr_table_make(rnew->pool, 5);
    rnew->trailers_out    = apr_table_make(rnew->pool, 5);
    rnew->notes           = apr_table_make(rnew->pool, 5);

    rnew->expecting_100   = r->expecting_100;
    rnew->read_length     = r->read_length;
    rnew->read_body       = REQUEST_NO_BODY;

    rnew->main = (request_rec *) r;
}

static void end_output_stream(request_rec *r, int status)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    if (status != OK) {
        b = ap_bucket_error_create(status, NULL, r->pool, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
    }
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    ap_pass_brigade(r->output_filters, bb);
    apr_brigade_cleanup(bb);
}

AP_DECLARE(void) ap_finalize_sub_req_protocol(request_rec *sub)
{
    /* tell the filter chain there is no more content coming */
    if (!sub->eos_sent) {
        end_output_stream(sub, OK);
    }
}

/* finalize_request_protocol is called at completion of sending the
 * response.  Its sole purpose is to send the terminating protocol
 * information for any wrappers around the response message body
 * (i.e., transfer encodings).  It should have been named finalize_response.
 */
AP_DECLARE(void) ap_finalize_request_protocol(request_rec *r)
{
    int status = ap_discard_request_body(r);

    /* tell the filter chain there is no more content coming */
    if (!r->eos_sent) {
        end_output_stream(r, status);
    }
}

/*
 * Support for the Basic authentication protocol, and a bit for Digest.
 */
AP_DECLARE(void) ap_note_auth_failure(request_rec *r)
{
    const char *type = ap_auth_type(r);
    if (type) {
        ap_run_note_auth_failure(r, type);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00571)
                      "need AuthType to note auth failure: %s", r->uri);
    }
}

AP_DECLARE(void) ap_note_basic_auth_failure(request_rec *r)
{
    ap_note_auth_failure(r);
}

AP_DECLARE(void) ap_note_digest_auth_failure(request_rec *r)
{
    ap_note_auth_failure(r);
}

AP_DECLARE(int) ap_get_basic_auth_pw(request_rec *r, const char **pw)
{
    const char *auth_line = apr_table_get(r->headers_in,
                                          (PROXYREQ_PROXY == r->proxyreq)
                                              ? "Proxy-Authorization"
                                              : "Authorization");
    const char *t;

    if (!(t = ap_auth_type(r)) || ap_cstr_casecmp(t, "Basic"))
        return DECLINED;

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00572) 
                      "need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!auth_line) {
        ap_note_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    if (ap_cstr_casecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        /* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00573)
                      "client used wrong authentication scheme: %s", r->uri);
        ap_note_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    while (*auth_line == ' ' || *auth_line == '\t') {
        auth_line++;
    }

    t = ap_pbase64decode(r->pool, auth_line);
    r->user = ap_getword_nulls (r->pool, &t, ':');
    apr_table_setn(r->notes, AP_GET_BASIC_AUTH_PW_NOTE, "1");
    r->ap_auth_type = "Basic";

    *pw = t;

    return OK;
}

AP_DECLARE(apr_status_t) ap_get_basic_auth_components(const request_rec *r,
                                                      const char **username,
                                                      const char **password)
{
    const char *auth_header;
    const char *credentials;
    const char *decoded;
    const char *user;

    auth_header = (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authorization"
                                                  : "Authorization";
    credentials = apr_table_get(r->headers_in, auth_header);

    if (!credentials) {
        /* No auth header. */
        return APR_EINVAL;
    }

    if (ap_cstr_casecmp(ap_getword(r->pool, &credentials, ' '), "Basic")) {
        /* These aren't Basic credentials. */
        return APR_EINVAL;
    }

    while (*credentials == ' ' || *credentials == '\t') {
        credentials++;
    }

    /* XXX Our base64 decoding functions don't actually error out if the string
     * we give it isn't base64; they'll just silently stop and hand us whatever
     * they've parsed up to that point.
     *
     * Since this function is supposed to be a drop-in replacement for the
     * deprecated ap_get_basic_auth_pw(), don't fix this for 2.4.x.
     */
    decoded = ap_pbase64decode(r->pool, credentials);
    user = ap_getword_nulls(r->pool, &decoded, ':');

    if (username) {
        *username = user;
    }
    if (password) {
        *password = decoded;
    }

    return APR_SUCCESS;
}

struct content_length_ctx {
    int data_sent;  /* true if the C-L filter has already sent at
                     * least one bucket on to the next output filter
                     * for this request
                     */
    apr_bucket_brigade *tmpbb;
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
        ctx->tmpbb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    }

    /* Loop through the brigade to count the length. To avoid
     * arbitrary memory consumption with morphing bucket types, this
     * loop will stop and pass on the brigade when necessary. */
    e = APR_BRIGADE_FIRST(b);
    while (e != APR_BRIGADE_SENTINEL(b)) {
        apr_status_t rv;

        if (APR_BUCKET_IS_EOS(e)) {
            eos = 1;
            break;
        }
        /* For a flush bucket, fall through to pass the brigade and
         * flush now. */
        else if (APR_BUCKET_IS_FLUSH(e)) {
            e = APR_BUCKET_NEXT(e);
        }
        /* For metadata bucket types other than FLUSH, loop. */
        else if (APR_BUCKET_IS_METADATA(e)) {
            e = APR_BUCKET_NEXT(e);
            continue;
        }
        /* For determinate length data buckets, count the length and
         * continue. */
        else if (e->length != (apr_size_t)-1) {
            r->bytes_sent += e->length;
            e = APR_BUCKET_NEXT(e);
            continue;
        }
        /* For indeterminate length data buckets, perform one read. */
        else /* e->length == (apr_size_t)-1 */ {
            apr_size_t len;
            const char *ignored;
        
            rv = apr_bucket_read(e, &ignored, &len, eblock);
            if ((rv != APR_SUCCESS) && !APR_STATUS_IS_EAGAIN(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00574)
                              "ap_content_length_filter: "
                              "apr_bucket_read() failed");
                return rv;
            }
            if (rv == APR_SUCCESS) {
                eblock = APR_NONBLOCK_READ;
                e = APR_BUCKET_NEXT(e);
                r->bytes_sent += len;
            }
            else if (APR_STATUS_IS_EAGAIN(rv)) {
                apr_bucket *flush;

                /* Next read must block. */
                eblock = APR_BLOCK_READ;

                /* Ensure the last bucket to pass down is a flush if
                 * the next read will block. */
                flush = apr_bucket_flush_create(f->c->bucket_alloc);
                APR_BUCKET_INSERT_BEFORE(e, flush);
            }
        }

        /* Optimization: if the next bucket is EOS (directly after a
         * bucket morphed to the heap, or a flush), short-cut to
         * handle EOS straight away - allowing C-L to be determined
         * for content which is already entirely in memory. */
        if (e != APR_BRIGADE_SENTINEL(b) && APR_BUCKET_IS_EOS(e)) {
            continue;
        }

        /* On reaching here, pass on everything in the brigade up to
         * this point. */
        apr_brigade_split_ex(b, e, ctx->tmpbb);
        
        rv = ap_pass_brigade(f->next, b);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        else if (f->c->aborted) {
            return APR_ECONNABORTED;
        }
        apr_brigade_cleanup(b);
        APR_BRIGADE_CONCAT(b, ctx->tmpbb);
        e = APR_BRIGADE_FIRST(b);
        
        ctx->data_sent = 1;
    }

    /* If we've now seen the entire response and it's otherwise
     * okay to set the C-L in the response header, then do so now.
     *
     * We can only set a C-L in the response header if we haven't already
     * sent any buckets on to the next output filter for this request.
     */
    if (ctx->data_sent == 0 && eos &&
        /* don't whack the C-L if it has already been set for a HEAD
         * by something like proxy.  the brigade only has an EOS bucket
         * in this case, making r->bytes_sent zero.
         *
         * if r->bytes_sent > 0 we have a (temporary) body whose length may
         * have been changed by a filter.  the C-L header might not have been
         * updated so we do it here.  long term it would be cleaner to have
         * such filters update or remove the C-L header, and just use it
         * if present.
         */
        !((r->header_only || AP_STATUS_IS_HEADER_ONLY(r->status)) && r->bytes_sent == 0 &&
            apr_table_get(r->headers_out, "Content-Length"))) {
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
    apr_status_t rv;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);

    apr_brigade_insert_file(bb, fd, offset, len, r->pool);

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
AP_DECLARE(apr_size_t) ap_send_mmap(apr_mmap_t *mm,
                                    request_rec *r,
                                    apr_size_t offset,
                                    apr_size_t length)
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
    apr_bucket_brigade *tmpbb;
} old_write_filter_ctx;

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_old_write_filter(
    ap_filter_t *f, apr_bucket_brigade *bb)
{
    old_write_filter_ctx *ctx = f->ctx;

    AP_DEBUG_ASSERT(ctx);

    if (ctx->bb != NULL) {
        /* whatever is coming down the pipe (we don't care), we
         * can simply insert our buffered data at the front and
         * pass the whole bundle down the chain.
         */
        APR_BRIGADE_PREPEND(bb, ctx->bb);
    }

    return ap_pass_brigade(f->next, bb);
}

static ap_filter_t *insert_old_write_filter(request_rec *r)
{
    ap_filter_t *f;
    old_write_filter_ctx *ctx;

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
        ctx->tmpbb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        ap_add_output_filter("OLD_WRITE", ctx, r, r->connection);
        f = r->output_filters;
    }

    return f;
}

static apr_status_t buffer_output(request_rec *r,
                                  const char *str, apr_size_t len)
{
    conn_rec *c = r->connection;
    ap_filter_t *f;
    old_write_filter_ctx *ctx;

    if (len == 0)
        return APR_SUCCESS;

    f = insert_old_write_filter(r);
    ctx = f->ctx;

    /* if the first filter is not our buffering filter, then we have to
     * deliver the content through the normal filter chain
     */
    if (f != r->output_filters) {
        apr_status_t rv;
        apr_bucket *b = apr_bucket_transient_create(str, len, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->tmpbb, b);

        rv = ap_pass_brigade(r->output_filters, ctx->tmpbb);
        apr_brigade_cleanup(ctx->tmpbb);
        return rv;
    }

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

AP_DECLARE(int) ap_rwrite(const void *buf, int nbyte, request_rec *r)
{
    if (nbyte < 0)
        return -1;

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

/* Flush callback for apr_vformatter; returns -1 on error. */
static int r_flush(apr_vformatter_buff_t *buff)
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

    return 0;
}

AP_DECLARE(int) ap_vrprintf(request_rec *r, const char *fmt, va_list va)
{
    int written;
    struct ap_vrprintf_data vd;
    char vrprintf_buf[AP_IOBUFSIZE];

    vd.vbuff.curpos = vrprintf_buf;
    vd.vbuff.endpos = vrprintf_buf + AP_IOBUFSIZE;
    vd.r = r;
    vd.buff = vrprintf_buf;

    if (r->connection->aborted)
        return -1;

    written = apr_vformatter(r_flush, &vd.vbuff, fmt, va);

    if (written != -1) {
        int n = vd.vbuff.curpos - vrprintf_buf;

        /* last call to buffer_output, to finish clearing the buffer */
        if (buffer_output(r, vrprintf_buf, n) != APR_SUCCESS)
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
            va_end(va);
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
    apr_bucket *b;
    ap_filter_t *f;
    old_write_filter_ctx *ctx;
    apr_status_t rv;

    f = insert_old_write_filter(r);
    ctx = f->ctx;

    b = apr_bucket_flush_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(ctx->tmpbb, b);

    rv = ap_pass_brigade(r->output_filters, ctx->tmpbb);
    apr_brigade_cleanup(ctx->tmpbb);
    if (rv != APR_SUCCESS)
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

typedef struct hdr_ptr {
    ap_filter_t *f;
    apr_bucket_brigade *bb;
} hdr_ptr;
 
#if APR_CHARSET_EBCDIC
static int send_header(void *data, const char *key, const char *val)
{
    char *header_line = NULL;
    hdr_ptr *hdr = (hdr_ptr*)data;

    header_line = apr_pstrcat(hdr->bb->p, key, ": ", val, CRLF, NULL);
    ap_xlate_proto_to_ascii(header_line, strlen(header_line));
    ap_fputs(hdr->f, hdr->bb, header_line);
    return 1;
}
#else
static int send_header(void *data, const char *key, const char *val)
{
     ap_fputstrs(((hdr_ptr*)data)->f, ((hdr_ptr*)data)->bb,
                 key, ": ", val, CRLF, NULL);
     return 1;
 }
#endif

AP_DECLARE(void) ap_send_interim_response(request_rec *r, int send_headers)
{
    hdr_ptr x;
    char *response_line = NULL;
    const char *status_line;
    request_rec *rr;

    if (r->proto_num < HTTP_VERSION(1,1)) {
        /* don't send interim response to HTTP/1.0 Client */
        return;
    }
    if (!ap_is_HTTP_INFO(r->status)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00575)
                      "Status is %d - not sending interim response", r->status);
        return;
    }
    if (r->status == HTTP_CONTINUE) {
        if (!r->expecting_100) {
            /*
             * Don't send 100-Continue when there was no Expect: 100-continue
             * in the request headers. For origin servers this is a SHOULD NOT
             * for proxies it is a MUST NOT according to RFC 2616 8.2.3
             */
            return;
        }

        /* if we send an interim response, we're no longer in a state of
         * expecting one.  Also, this could feasibly be in a subrequest,
         * so we need to propagate the fact that we responded.
         */
        for (rr = r; rr != NULL; rr = rr->main) {
            rr->expecting_100 = 0;
        }
    }

    status_line = r->status_line;
    if (status_line == NULL) {
        status_line = ap_get_status_line_ex(r->pool, r->status);
    }
    response_line = apr_pstrcat(r->pool,
                                AP_SERVER_PROTOCOL " ", status_line, CRLF,
                                NULL);
    ap_xlate_proto_to_ascii(response_line, strlen(response_line));

    x.f = r->connection->output_filters;
    x.bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    ap_fputs(x.f, x.bb, response_line);
    if (send_headers) {
        apr_table_do(send_header, &x, r->headers_out, NULL);
        apr_table_clear(r->headers_out);
    }
    ap_fputs(x.f, x.bb, CRLF_ASCII);
    ap_fflush(x.f, x.bb);
    apr_brigade_destroy(x.bb);
}

/*
 * Compare two protocol identifier. Result is similar to strcmp():
 * 0 gives same precedence, >0 means proto1 is preferred.
 */
static int protocol_cmp(const apr_array_header_t *preferences,
                        const char *proto1,
                        const char *proto2)
{
    if (preferences && preferences->nelts > 0) {
        int index1 = ap_array_str_index(preferences, proto1, 0);
        int index2 = ap_array_str_index(preferences, proto2, 0);
        if (index2 > index1) {
            return (index1 >= 0) ? 1 : -1;
        }
        else if (index1 > index2) {
            return (index2 >= 0) ? -1 : 1;
        }
    }
    /* both have the same index (maybe -1 or no pref configured) and we compare
     * the names so that spdy3 gets precedence over spdy2. That makes
     * the outcome at least deterministic. */
    return strcmp(proto1, proto2);
}

AP_DECLARE(const char *) ap_get_protocol(conn_rec *c)
{
    const char *protocol = ap_run_protocol_get(c);
    return protocol? protocol : AP_PROTOCOL_HTTP1;
}

AP_DECLARE(apr_status_t) ap_get_protocol_upgrades(conn_rec *c, request_rec *r, 
                                                  server_rec *s, int report_all, 
                                                  const apr_array_header_t **pupgrades)
{
    apr_pool_t *pool = r? r->pool : c->pool;
    core_server_config *conf;
    const char *existing;
    apr_array_header_t *upgrades = NULL;

    if (!s) {
        s = (r? r->server : c->base_server);
    }
    conf = ap_get_core_module_config(s->module_config);
    
    if (conf->protocols->nelts > 0) {
        existing = ap_get_protocol(c);
        if (conf->protocols->nelts > 1 
            || !ap_array_str_contains(conf->protocols, existing)) {
            int i;
            
            /* possibly more than one choice or one, but not the
             * existing. (TODO: maybe 426 and Upgrade then?) */
            upgrades = apr_array_make(pool, conf->protocols->nelts + 1, 
                                      sizeof(char *));
            for (i = 0; i < conf->protocols->nelts; i++) {
                const char *p = APR_ARRAY_IDX(conf->protocols, i, char *);
                if (strcmp(existing, p)) {
                    /* not the one we have and possible, add in this order */
                    APR_ARRAY_PUSH(upgrades, const char*) = p;
                }
                else if (!report_all) {
                    break;
                }
            }
        }
    }
    
    *pupgrades = upgrades;
    return APR_SUCCESS;
}

AP_DECLARE(const char *) ap_select_protocol(conn_rec *c, request_rec *r, 
                                            server_rec *s,
                                            const apr_array_header_t *choices)
{
    apr_pool_t *pool = r? r->pool : c->pool;
    core_server_config *conf;
    const char *protocol = NULL, *existing;
    apr_array_header_t *proposals;

    if (!s) {
        s = (r? r->server : c->base_server);
    }
    conf = ap_get_core_module_config(s->module_config);
    
    if (APLOGcdebug(c)) {
        const char *p = apr_array_pstrcat(pool, conf->protocols, ',');
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03155) 
                      "select protocol from %s, choices=%s for server %s", 
                      p, apr_array_pstrcat(pool, choices, ','),
                      s->server_hostname);
    }

    if (conf->protocols->nelts <= 0) {
        /* nothing configured, by default, we only allow http/1.1 here.
         * For now...
         */
        if (ap_array_str_contains(choices, AP_PROTOCOL_HTTP1)) {
            return AP_PROTOCOL_HTTP1;
        }
        else {
            return NULL;
        }
    }

    proposals = apr_array_make(pool, choices->nelts + 1, sizeof(char *));
    ap_run_protocol_propose(c, r, s, choices, proposals);

    /* If the existing protocol has not been proposed, but is a choice,
     * add it to the proposals implicitly.
     */
    existing = ap_get_protocol(c);
    if (!ap_array_str_contains(proposals, existing)
        && ap_array_str_contains(choices, existing)) {
        APR_ARRAY_PUSH(proposals, const char*) = existing;
    }

    if (proposals->nelts > 0) {
        int i;
        const apr_array_header_t *prefs = NULL;

        /* Default for protocols_honor_order is 'on' or != 0 */
        if (conf->protocols_honor_order == 0 && choices->nelts > 0) {
            prefs = choices;
        }
        else {
            prefs = conf->protocols;
        }

        /* Select the most preferred protocol */
        if (APLOGcdebug(c)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03156) 
                          "select protocol, proposals=%s preferences=%s configured=%s", 
                          apr_array_pstrcat(pool, proposals, ','),
                          apr_array_pstrcat(pool, prefs, ','),
                          apr_array_pstrcat(pool, conf->protocols, ','));
        }
        for (i = 0; i < proposals->nelts; ++i) {
            const char *p = APR_ARRAY_IDX(proposals, i, const char *);
            if (!ap_array_str_contains(conf->protocols, p)) {
                /* not a configured protocol here */
                continue;
            }
            else if (!protocol 
                     || (protocol_cmp(prefs, protocol, p) < 0)) {
                /* none selected yet or this one has preference */
                protocol = p;
            }
        }
    }
    if (APLOGcdebug(c)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03157)
                      "selected protocol=%s", 
                      protocol? protocol : "(none)");
    }

    return protocol;
}

AP_DECLARE(apr_status_t) ap_switch_protocol(conn_rec *c, request_rec *r, 
                                            server_rec *s,
                                            const char *protocol)
{
    const char *current = ap_get_protocol(c);
    int rc;
    
    if (!strcmp(current, protocol)) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c, APLOGNO(02906)
                      "already at it, protocol_switch to %s", 
                      protocol);
        return APR_SUCCESS;
    }
    
    rc = ap_run_protocol_switch(c, r, s, protocol);
    switch (rc) {
        case DECLINED:
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02907)
                          "no implementation for protocol_switch to %s", 
                          protocol);
            return APR_ENOTIMPL;
        case OK:
        case DONE:
            return APR_SUCCESS;
        default:
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02905)
                          "unexpected return code %d from protocol_switch to %s"
                          , rc, protocol);
            return APR_EOF;
    }    
}

AP_DECLARE(int) ap_is_allowed_protocol(conn_rec *c, request_rec *r,
                                       server_rec *s, const char *protocol)
{
    core_server_config *conf;

    if (!s) {
        s = (r? r->server : c->base_server);
    }
    conf = ap_get_core_module_config(s->module_config);
    
    if (conf->protocols->nelts > 0) {
        return ap_array_str_contains(conf->protocols, protocol);
    }
    return !strcmp(AP_PROTOCOL_HTTP1, protocol);
}


AP_IMPLEMENT_HOOK_VOID(pre_read_request,
                       (request_rec *r, conn_rec *c),
                       (r, c))
AP_IMPLEMENT_HOOK_RUN_ALL(int,post_read_request,
                          (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,log_transaction,
                          (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *,http_scheme,
                            (const request_rec *r), (r), NULL)
AP_IMPLEMENT_HOOK_RUN_FIRST(unsigned short,default_port,
                            (const request_rec *r), (r), 0)
AP_IMPLEMENT_HOOK_RUN_FIRST(int, note_auth_failure,
                            (request_rec *r, const char *auth_type),
                            (r, auth_type), DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,protocol_propose,
                          (conn_rec *c, request_rec *r, server_rec *s,
                           const apr_array_header_t *offers,
                           apr_array_header_t *proposals), 
                          (c, r, s, offers, proposals), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,protocol_switch,
                            (conn_rec *c, request_rec *r, server_rec *s,
                             const char *protocol), 
                            (c, r, s, protocol), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *,protocol_get,
                            (const conn_rec *c), (c), NULL)
