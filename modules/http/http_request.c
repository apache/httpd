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
 * http_request.c: functions to get and process requests
 *
 * Rob McCool 3/21/93
 *
 * Thoroughly revamped by rst for Apache.  NB this file reads
 * best from the bottom up.
 *
 */

#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_fnmatch.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_filter.h"
#include "util_charset.h"
#include "scoreboard.h"

#include "mod_core.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif

APLOG_USE_MODULE(http);

/*****************************************************************
 *
 * Mainline request processing...
 */

/* XXX A cleaner and faster way to do this might be to pass the request_rec
 * down the filter chain as a parameter.  It would need to change for
 * subrequest vs. main request filters; perhaps the subrequest filter could
 * make the switch.
 */
static void update_r_in_filters(ap_filter_t *f,
                                request_rec *from,
                                request_rec *to)
{
    while (f) {
        if (f->r == from) {
            f->r = to;
        }
        f = f->next;
    }
}

static void ap_die_r(int type, request_rec *r, int recursive_error)
{
    char *custom_response;
    request_rec *r_1st_err = r;

    if (type == OK || type == DONE) {
        ap_finalize_request_protocol(r);
        return;
    }

    if (!ap_is_HTTP_VALID_RESPONSE(type)) {
        ap_filter_t *next;

        /*
         * Check if we still have the ap_http_header_filter in place. If
         * this is the case we should not ignore the error here because
         * it means that we have not sent any response at all and never
         * will. This is bad. Sent an internal server error instead.
         */
        next = r->output_filters;
        while (next && (next->frec != ap_http_header_filter_handle)) {
               next = next->next;
        }

        /*
         * If next != NULL then we left the while above because of
         * next->frec == ap_http_header_filter
         */
        if (next) {
            if (type != AP_FILTER_ERROR) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01579)
                              "Invalid response status %i", type);
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02831)
                              "Response from AP_FILTER_ERROR");
            }
            type = HTTP_INTERNAL_SERVER_ERROR;
        }
        else {
            return;
        }
    }

    /*
     * The following takes care of Apache redirects to custom response URLs
     * Note that if we are already dealing with the response to some other
     * error condition, we just report on the original error, and give up on
     * any attempt to handle the other thing "intelligently"...
     */
    if (recursive_error != HTTP_OK) {
        while (r_1st_err->prev && (r_1st_err->prev->status != HTTP_OK))
            r_1st_err = r_1st_err->prev;  /* Get back to original error */

        if (r_1st_err != r) {
            /* The recursive error was caused by an ErrorDocument specifying
             * an internal redirect to a bad URI.  ap_internal_redirect has
             * changed the filter chains to point to the ErrorDocument's
             * request_rec.  Back out those changes so we can safely use the
             * original failing request_rec to send the canned error message.
             *
             * ap_send_error_response gets rid of existing resource filters
             * on the output side, so we can skip those.
             */
            update_r_in_filters(r_1st_err->proto_output_filters, r, r_1st_err);
            update_r_in_filters(r_1st_err->input_filters, r, r_1st_err);
        }

        custom_response = NULL; /* Do NOT retry the custom thing! */
    }
    else {
        int error_index = ap_index_of_response(type);
        custom_response = ap_response_code_string(r, error_index);
        recursive_error = 0;
    }

    r->status = type;

    /*
     * This test is done here so that none of the auth modules needs to know
     * about proxy authentication.  They treat it like normal auth, and then
     * we tweak the status.
     */
    if (HTTP_UNAUTHORIZED == r->status && PROXYREQ_PROXY == r->proxyreq) {
        r->status = HTTP_PROXY_AUTHENTICATION_REQUIRED;
    }

    /* If we don't want to keep the connection, make sure we mark that the
     * connection is not eligible for keepalive.  If we want to keep the
     * connection, be sure that the request body (if any) has been read.
     */
    if (ap_status_drops_connection(r->status)) {
        r->connection->keepalive = AP_CONN_CLOSE;
    }

    /*
     * Two types of custom redirects --- plain text, and URLs. Plain text has
     * a leading '"', so the URL code, here, is triggered on its absence
     */

    if (custom_response && custom_response[0] != '"') {

        if (ap_is_url(custom_response)) {
            /*
             * The URL isn't local, so lets drop through the rest of this
             * apache code, and continue with the usual REDIRECT handler.
             * But note that the client will ultimately see the wrong
             * status...
             */
            r->status = HTTP_MOVED_TEMPORARILY;
            apr_table_setn(r->headers_out, "Location", custom_response);
        }
        else if (custom_response[0] == '/') {
            const char *error_notes, *original_method;
            int original_method_number;
            r->no_local_copy = 1;       /* Do NOT send HTTP_NOT_MODIFIED for
                                         * error documents! */
            /*
             * This redirect needs to be a GET no matter what the original
             * method was.
             */
            apr_table_setn(r->subprocess_env, "REQUEST_METHOD", r->method);

            /*
             * Provide a special method for modules to communicate
             * more informative (than the plain canned) messages to us.
             * Propagate them to ErrorDocuments via the ERROR_NOTES variable:
             */
            if ((error_notes = apr_table_get(r->notes,
                                             "error-notes")) != NULL) {
                apr_table_setn(r->subprocess_env, "ERROR_NOTES", error_notes);
            }
            original_method = r->method;
            original_method_number = r->method_number;
            r->method = "GET";
            r->method_number = M_GET;
            ap_internal_redirect(custom_response, r);
            /* preserve ability to see %<m in the access log */
            r->method = original_method;
            r->method_number = original_method_number;
            return;
        }
        else {
            /*
             * Dumb user has given us a bad url to redirect to --- fake up
             * dying with a recursive server error...
             */
            recursive_error = HTTP_INTERNAL_SERVER_ERROR;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01580)
                        "Invalid error redirection directive: %s",
                        custom_response);
        }
    }
    ap_send_error_response(r_1st_err, recursive_error);
}

AP_DECLARE(void) ap_die(int type, request_rec *r)
{
    ap_die_r(type, r, r->status);
}

AP_DECLARE(apr_status_t) ap_check_pipeline(conn_rec *c, apr_bucket_brigade *bb,
                                           unsigned int max_blank_lines)
{
    apr_status_t rv = APR_EOF;
    ap_input_mode_t mode = AP_MODE_SPECULATIVE;
    unsigned int num_blank_lines = 0;
    apr_size_t cr = 0;
    char buf[2];

    while (c->keepalive != AP_CONN_CLOSE && !c->aborted) {
        apr_size_t len = cr + 1;

        apr_brigade_cleanup(bb);
        rv = ap_get_brigade(c->input_filters, bb, mode,
                            APR_NONBLOCK_READ, len);
        if (rv != APR_SUCCESS || APR_BRIGADE_EMPTY(bb)) {
            if (mode == AP_MODE_READBYTES) {
                /* Unexpected error, stop with this connection */
                ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c, APLOGNO(02967)
                              "Can't consume pipelined empty lines");
                c->keepalive = AP_CONN_CLOSE;
                rv = APR_EGENERAL;
            }
            else if (rv != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(rv)) {
                /* Pipe is dead */
                c->keepalive = AP_CONN_CLOSE;
            }
            else {
                /* Pipe is up and empty */
                rv = APR_EAGAIN;
            }
            break;
        }
        if (!max_blank_lines) {
            apr_off_t n = 0;
            /* Single read asked, (non-meta-)data available? */
            rv = apr_brigade_length(bb, 0, &n);
            if (rv == APR_SUCCESS && n <= 0) {
                rv = APR_EAGAIN;
            }
            break;
        }

        /* Lookup and consume blank lines */
        rv = apr_brigade_flatten(bb, buf, &len);
        if (rv != APR_SUCCESS || len != cr + 1) {
            int log_level;
            if (mode == AP_MODE_READBYTES) {
                /* Unexpected error, stop with this connection */
                c->keepalive = AP_CONN_CLOSE;
                log_level = APLOG_ERR;
                rv = APR_EGENERAL;
            }
            else {
                /* Let outside (non-speculative/blocking) read determine
                 * where this possible failure comes from (metadata,
                 * morphed EOF socket, ...). Debug only here.
                 */
                log_level = APLOG_DEBUG;
                rv = APR_SUCCESS;
            }
            ap_log_cerror(APLOG_MARK, log_level, rv, c, APLOGNO(02968)
                          "Can't check pipelined data");
            break;
        }

        if (mode == AP_MODE_READBYTES) {
            /* [CR]LF consumed, try next */
            mode = AP_MODE_SPECULATIVE;
            cr = 0;
        }
        else if (cr) {
            AP_DEBUG_ASSERT(len == 2 && buf[0] == APR_ASCII_CR);
            if (buf[1] == APR_ASCII_LF) {
                /* consume this CRLF */
                mode = AP_MODE_READBYTES;
                num_blank_lines++;
            }
            else {
                /* CR(?!LF) is data */
                break;
            }
        }
        else {
            if (buf[0] == APR_ASCII_LF) {
                /* consume this LF */
                mode = AP_MODE_READBYTES;
                num_blank_lines++;
            }
            else if (buf[0] == APR_ASCII_CR) {
                cr = 1;
            }
            else {
                /* Not [CR]LF, some data */
                break;
            }
        }
        if (num_blank_lines > max_blank_lines) {
            /* Enough blank lines with this connection,
             * stop and don't recycle it.
             */
            c->keepalive = AP_CONN_CLOSE;
            rv = APR_NOTFOUND;
            break;
        }
    }

    return rv;
}

#define RETRIEVE_BRIGADE_FROM_POOL(bb, key, pool, allocator) do {       \
    apr_pool_userdata_get((void **)&bb, key, pool);                     \
    if (bb == NULL) {                                                   \
        bb = apr_brigade_create(pool, allocator);                       \
        apr_pool_userdata_setn((const void *)bb, key, NULL, pool);      \
    }                                                                   \
    else {                                                              \
        apr_brigade_cleanup(bb);                                        \
    }                                                                   \
} while(0)

AP_DECLARE(void) ap_process_request_after_handler(request_rec *r)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;
    conn_rec *c = r->connection;
    apr_status_t rv;

    /* Send an EOR bucket through the output filter chain.  When
     * this bucket is destroyed, the request will be logged and
     * its pool will be freed
     */
    RETRIEVE_BRIGADE_FROM_POOL(bb, "ap_process_request_after_handler_brigade",
                               c->pool, c->bucket_alloc);
    b = ap_bucket_eor_create(c->bucket_alloc, r);
    APR_BRIGADE_INSERT_HEAD(bb, b);

    ap_pass_brigade(c->output_filters, bb);
    
    /* The EOR bucket has either been handled by an output filter (eg.
     * deleted or moved to a buffered_bb => no more in bb), or an error
     * occured before that (eg. c->aborted => still in bb) and we ought
     * to destroy it now. So cleanup any remaining bucket along with
     * the orphan request (if any).
     */
    apr_brigade_cleanup(bb);

    /* From here onward, it is no longer safe to reference r
     * or r->pool, because r->pool may have been destroyed
     * already by the EOR bucket's cleanup function.
     */

    /* Check pipeline consuming blank lines, they must not be interpreted as
     * the next pipelined request, otherwise we would block on the next read
     * without flushing data, and hence possibly delay pending response(s)
     * until the next/real request comes in or the keepalive timeout expires.
     */
    rv = ap_check_pipeline(c, bb, DEFAULT_LIMIT_BLANK_LINES);
    c->data_in_input_filters = (rv == APR_SUCCESS);
    apr_brigade_cleanup(bb);

    if (c->cs)
        c->cs->state = (c->aborted) ? CONN_STATE_LINGER
                                    : CONN_STATE_WRITE_COMPLETION;
    AP_PROCESS_REQUEST_RETURN((uintptr_t)r, r->uri, r->status);
    if (ap_extended_status) {
        ap_time_process_request(c->sbh, STOP_PREQUEST);
    }
}

void ap_process_async_request(request_rec *r)
{
    conn_rec *c = r->connection;
    int access_status;

    /* Give quick handlers a shot at serving the request on the fast
     * path, bypassing all of the other Apache hooks.
     *
     * This hook was added to enable serving files out of a URI keyed
     * content cache ( e.g., Mike Abbott's Quick Shortcut Cache,
     * described here: http://oss.sgi.com/projects/apache/mod_qsc.html )
     *
     * It may have other uses as well, such as routing requests directly to
     * content handlers that have the ability to grok HTTP and do their
     * own access checking, etc (e.g. servlet engines).
     *
     * Use this hook with extreme care and only if you know what you are
     * doing.
     */
    AP_PROCESS_REQUEST_ENTRY((uintptr_t)r, r->uri);
    if (ap_extended_status) {
        ap_time_process_request(r->connection->sbh, START_PREQUEST);
    }

    if (APLOGrtrace4(r)) {
        int i;
        const apr_array_header_t *t_h = apr_table_elts(r->headers_in);
        const apr_table_entry_t *t_elt = (apr_table_entry_t *)t_h->elts;
        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                      "Headers received from client:");
        for (i = 0; i < t_h->nelts; i++, t_elt++) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "  %s: %s",
                          ap_escape_logitem(r->pool, t_elt->key),
                          ap_escape_logitem(r->pool, t_elt->val));
        }
    }

#if APR_HAS_THREADS
    apr_thread_mutex_create(&r->invoke_mtx, APR_THREAD_MUTEX_DEFAULT, r->pool);
    apr_thread_mutex_lock(r->invoke_mtx);
#endif
    access_status = ap_run_quick_handler(r, 0);  /* Not a look-up request */
    if (access_status == DECLINED) {
        access_status = ap_process_request_internal(r);
        if (access_status == OK) {
            access_status = ap_invoke_handler(r);
        }
    }

    if (access_status == SUSPENDED) {
        /* TODO: Should move these steps into a generic function, so modules
         * working on a suspended request can also call _ENTRY again.
         */
        AP_PROCESS_REQUEST_RETURN((uintptr_t)r, r->uri, access_status);
        if (ap_extended_status) {
            ap_time_process_request(c->sbh, STOP_PREQUEST);
        }
        if (c->cs)
            c->cs->state = CONN_STATE_SUSPENDED;
#if APR_HAS_THREADS
        apr_thread_mutex_unlock(r->invoke_mtx);
#endif
        return;
    }
#if APR_HAS_THREADS
    apr_thread_mutex_unlock(r->invoke_mtx);
#endif

    ap_die_r(access_status, r, HTTP_OK);

    ap_process_request_after_handler(r);
}

AP_DECLARE(void) ap_process_request(request_rec *r)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;
    conn_rec *c = r->connection;
    apr_status_t rv;

    ap_process_async_request(r);

    if (!c->data_in_input_filters) {
        RETRIEVE_BRIGADE_FROM_POOL(bb, "ap_process_request_brigade", 
                                   c->pool, c->bucket_alloc);
        b = apr_bucket_flush_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_HEAD(bb, b);
        rv = ap_pass_brigade(c->output_filters, bb);
        if (APR_STATUS_IS_TIMEUP(rv)) {
            /*
             * Notice a timeout as an error message. This might be
             * valuable for detecting clients with broken network
             * connections or possible DoS attacks.
             */
            ap_log_cerror(APLOG_MARK, APLOG_INFO, rv, c, APLOGNO(01581)
                          "flushing data to the client");
        }
        apr_brigade_cleanup(bb);
    }
    if (ap_extended_status) {
        ap_time_process_request(c->sbh, STOP_PREQUEST);
    }
}

static apr_table_t *rename_original_env(apr_pool_t *p, apr_table_t *t)
{
    const apr_array_header_t *env_arr = apr_table_elts(t);
    const apr_table_entry_t *elts = (const apr_table_entry_t *) env_arr->elts;
    apr_table_t *new = apr_table_make(p, env_arr->nalloc);
    int i;

    for (i = 0; i < env_arr->nelts; ++i) {
        if (!elts[i].key)
            continue;
        apr_table_setn(new, apr_pstrcat(p, "REDIRECT_", elts[i].key, NULL),
                  elts[i].val);
    }

    return new;
}

static request_rec *internal_internal_redirect(const char *new_uri,
                                               request_rec *r) {
    int access_status;
    request_rec *new;
    const char *vary_header;

    if (ap_is_recursion_limit_exceeded(r)) {
        ap_die(HTTP_INTERNAL_SERVER_ERROR, r);
        return NULL;
    }

    new = (request_rec *) apr_pcalloc(r->pool, sizeof(request_rec));

    new->connection = r->connection;
    new->server     = r->server;
    new->pool       = r->pool;

    /*
     * A whole lot of this really ought to be shared with http_protocol.c...
     * another missing cleanup.  It's particularly inappropriate to be
     * setting header_only, etc., here.
     */

    new->method          = r->method;
    new->method_number   = r->method_number;
    new->allowed_methods = ap_make_method_list(new->pool, 2);
    ap_parse_uri(new, new_uri);
    new->parsed_uri.port_str = r->parsed_uri.port_str;
    new->parsed_uri.port = r->parsed_uri.port;

    new->request_config = ap_create_request_config(r->pool);

    new->per_dir_config = r->server->lookup_defaults;

    new->prev = r;
    r->next   = new;

    new->useragent_addr = r->useragent_addr;
    new->useragent_ip = r->useragent_ip;

    /* Must have prev and next pointers set before calling create_request
     * hook.
     */
    ap_run_create_request(new);

    /* Inherit the rest of the protocol info... */

    new->the_request = r->the_request;

    new->allowed         = r->allowed;

    new->status          = r->status;
    new->assbackwards    = r->assbackwards;
    new->header_only     = r->header_only;
    new->protocol        = r->protocol;
    new->proto_num       = r->proto_num;
    new->hostname        = r->hostname;
    new->request_time    = r->request_time;
    new->main            = r->main;

    new->headers_in      = r->headers_in;
    new->trailers_in     = r->trailers_in;
    new->headers_out     = apr_table_make(r->pool, 12);
    if (ap_is_HTTP_REDIRECT(new->status)) {
        const char *location = apr_table_get(r->headers_out, "Location");
        if (location)
            apr_table_setn(new->headers_out, "Location", location);
    }

    /* A module (like mod_rewrite) can force an internal redirect
     * to carry over the Vary header (if present).
     */
    if (apr_table_get(r->notes, "redirect-keeps-vary")) {
        if((vary_header = apr_table_get(r->headers_out, "Vary"))) {
            apr_table_setn(new->headers_out, "Vary", vary_header);
        }
    }

    new->err_headers_out = r->err_headers_out;
    new->trailers_out    = apr_table_make(r->pool, 5);
    new->subprocess_env  = rename_original_env(r->pool, r->subprocess_env);
    new->notes           = apr_table_make(r->pool, 5);

    new->htaccess        = r->htaccess;
    new->no_cache        = r->no_cache;
    new->expecting_100   = r->expecting_100;
    new->no_local_copy   = r->no_local_copy;
    new->read_length     = r->read_length;     /* We can only read it once */
    new->vlist_validator = r->vlist_validator;

    new->proto_output_filters  = r->proto_output_filters;
    new->proto_input_filters   = r->proto_input_filters;

    new->input_filters   = new->proto_input_filters;

    if (new->main) {
        ap_filter_t *f, *nextf;

        /* If this is a subrequest, the filter chain may contain a
         * mixture of filters specific to the old request (r), and
         * some inherited from r->main.  Here, inherit that filter
         * chain, and remove all those which are specific to the old
         * request; ensuring the subreq filter is left in place. */
        new->output_filters = r->output_filters;

        f = new->output_filters;
        do {
            nextf = f->next;

            if (f->r == r && f->frec != ap_subreq_core_filter_handle) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01582)
                              "dropping filter '%s' in internal redirect from %s to %s",
                              f->frec->name, r->unparsed_uri, new_uri);

                /* To remove the filter, first set f->r to the *new*
                 * request_rec, so that ->output_filters on 'new' is
                 * changed (if necessary) when removing the filter. */
                f->r = new;
                ap_remove_output_filter(f);
            }

            f = nextf;

            /* Stop at the protocol filters.  If a protocol filter has
             * been newly installed for this resource, better leave it
             * in place, though it's probably a misconfiguration or
             * filter bug to get into this state. */
        } while (f && f != new->proto_output_filters);
    }
    else {
        /* If this is not a subrequest, clear out all
         * resource-specific filters. */
        new->output_filters  = new->proto_output_filters;
    }

    update_r_in_filters(new->input_filters, r, new);
    update_r_in_filters(new->output_filters, r, new);

    apr_table_setn(new->subprocess_env, "REDIRECT_STATUS",
                   apr_itoa(r->pool, r->status));

    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    new->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

#if APR_HAS_THREADS
    new->invoke_mtx = r->invoke_mtx;
#endif

    /*
     * XXX: hmm.  This is because mod_setenvif and mod_unique_id really need
     * to do their thing on internal redirects as well.  Perhaps this is a
     * misnamed function.
     */
    if ((access_status = ap_post_read_request(new))) {
        ap_die(access_status, new);
        return NULL;
    }

    return new;
}

/* XXX: Is this function is so bogus and fragile that we deep-6 it? */
AP_DECLARE(void) ap_internal_fast_redirect(request_rec *rr, request_rec *r)
{
    /* We need to tell POOL_DEBUG that we're guaranteeing that rr->pool
     * will exist as long as r->pool.  Otherwise we run into troubles because
     * some values in this request will be allocated in r->pool, and others in
     * rr->pool.
     */
    apr_pool_join(r->pool, rr->pool);
    r->proxyreq = rr->proxyreq;
    r->no_cache = (r->no_cache && rr->no_cache);
    r->no_local_copy = (r->no_local_copy && rr->no_local_copy);
    r->mtime = rr->mtime;
    r->uri = rr->uri;
    r->filename = rr->filename;
    r->canonical_filename = rr->canonical_filename;
    r->path_info = rr->path_info;
    r->args = rr->args;
    r->finfo = rr->finfo;
    r->handler = rr->handler;
    ap_set_content_type(r, rr->content_type);
    r->content_encoding = rr->content_encoding;
    r->content_languages = rr->content_languages;
    r->per_dir_config = rr->per_dir_config;
    /* copy output headers from subrequest, but leave negotiation headers */
    r->notes = apr_table_overlay(r->pool, rr->notes, r->notes);
    r->headers_out = apr_table_overlay(r->pool, rr->headers_out,
                                       r->headers_out);
    r->err_headers_out = apr_table_overlay(r->pool, rr->err_headers_out,
                                           r->err_headers_out);
    r->trailers_out = apr_table_overlay(r->pool, rr->trailers_out,
                                           r->trailers_out);
    r->subprocess_env = apr_table_overlay(r->pool, rr->subprocess_env,
                                          r->subprocess_env);

    r->output_filters = rr->output_filters;
    r->input_filters = rr->input_filters;

    /* If any filters pointed at the now-defunct rr, we must point them
     * at our "new" instance of r.  In particular, some of rr's structures
     * will now be bogus (say rr->headers_out).  If a filter tried to modify
     * their f->r structure when it is pointing to rr, the real request_rec
     * will not get updated.  Fix that here.
     */
    update_r_in_filters(r->input_filters, rr, r);
    update_r_in_filters(r->output_filters, rr, r);

    if (r->main) {
        ap_filter_t *next = r->output_filters;
        while (next && (next != r->proto_output_filters)) {
            if (next->frec == ap_subreq_core_filter_handle) {
                break;
            }
            next = next->next;
        }
        if (!next || next == r->proto_output_filters) {
            ap_add_output_filter_handle(ap_subreq_core_filter_handle,
                                        NULL, r, r->connection);
        }
    }
    else {
        /*
         * We need to check if we now have the SUBREQ_CORE filter in our filter
         * chain. If this is the case we need to remove it since we are NO
         * subrequest. But we need to keep in mind that the SUBREQ_CORE filter
         * does not necessarily need to be the first filter in our chain. So we
         * need to go through the chain. But we only need to walk up the chain
         * until the proto_output_filters as the SUBREQ_CORE filter is below the
         * protocol filters.
         */
        ap_filter_t *next;

        next = r->output_filters;
        while (next && (next->frec != ap_subreq_core_filter_handle)
               && (next != r->proto_output_filters)) {
                next = next->next;
        }
        if (next && (next->frec == ap_subreq_core_filter_handle)) {
            ap_remove_output_filter(next);
        }
    }
}

AP_DECLARE(void) ap_internal_redirect(const char *new_uri, request_rec *r)
{
    int access_status;
    request_rec *new = internal_internal_redirect(new_uri, r);

    AP_INTERNAL_REDIRECT(r->uri, new_uri);

    /* ap_die was already called, if an error occured */
    if (!new) {
        return;
    }

    access_status = ap_run_quick_handler(new, 0);  /* Not a look-up request */
    if (access_status == DECLINED) {
        access_status = ap_process_request_internal(new);
        if (access_status == OK) {
            access_status = ap_invoke_handler(new);
        }
    }
    ap_die(access_status, new);
}

/* This function is designed for things like actions or CGI scripts, when
 * using AddHandler, and you want to preserve the content type across
 * an internal redirect.
 */
AP_DECLARE(void) ap_internal_redirect_handler(const char *new_uri, request_rec *r)
{
    int access_status;
    request_rec *new = internal_internal_redirect(new_uri, r);

    /* ap_die was already called, if an error occured */
    if (!new) {
        return;
    }

    if (r->handler)
        ap_set_content_type(new, r->content_type);
    access_status = ap_process_request_internal(new);
    if (access_status == OK) {
        access_status = ap_invoke_handler(new);
    }
    ap_die(access_status, new);
}

AP_DECLARE(void) ap_allow_methods(request_rec *r, int reset, ...)
{
    const char *method;
    va_list methods;

    /*
     * Get rid of any current settings if requested; not just the
     * well-known methods but any extensions as well.
     */
    if (reset) {
        ap_clear_method_list(r->allowed_methods);
    }

    va_start(methods, reset);
    while ((method = va_arg(methods, const char *)) != NULL) {
        ap_method_list_add(r->allowed_methods, method);
    }
    va_end(methods);
}

AP_DECLARE(void) ap_allow_standard_methods(request_rec *r, int reset, ...)
{
    int method;
    va_list methods;
    apr_int64_t mask;

    /*
     * Get rid of any current settings if requested; not just the
     * well-known methods but any extensions as well.
     */
    if (reset) {
        ap_clear_method_list(r->allowed_methods);
    }

    mask = 0;
    va_start(methods, reset);
    while ((method = va_arg(methods, int)) != -1) {
        mask |= (AP_METHOD_BIT << method);
    }
    va_end(methods);

    r->allowed_methods->method_mask |= mask;
}
