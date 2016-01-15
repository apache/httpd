/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stdio.h>

#include <apr_lib.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <util_time.h>

#include "h2_private.h"
#include "h2_response.h"
#include "h2_from_h1.h"
#include "h2_task.h"
#include "h2_task_output.h"
#include "h2_util.h"


static void set_state(h2_from_h1 *from_h1, h2_from_h1_state_t state);

h2_from_h1 *h2_from_h1_create(int stream_id, apr_pool_t *pool)
{
    h2_from_h1 *from_h1 = apr_pcalloc(pool, sizeof(h2_from_h1));
    if (from_h1) {
        from_h1->stream_id = stream_id;
        from_h1->pool = pool;
        from_h1->state = H2_RESP_ST_STATUS_LINE;
        from_h1->hlines = apr_array_make(pool, 10, sizeof(char *));
    }
    return from_h1;
}

apr_status_t h2_from_h1_destroy(h2_from_h1 *from_h1)
{
    from_h1->bb = NULL;
    return APR_SUCCESS;
}

static void set_state(h2_from_h1 *from_h1, h2_from_h1_state_t state)
{
    if (from_h1->state != state) {
        from_h1->state = state;
    }
}

h2_response *h2_from_h1_get_response(h2_from_h1 *from_h1)
{
    return from_h1->response;
}

static apr_status_t make_h2_headers(h2_from_h1 *from_h1, request_rec *r)
{
    from_h1->response = h2_response_create(from_h1->stream_id, 0,
                                           from_h1->http_status, 
                                           from_h1->hlines,
                                           r->notes,
                                           from_h1->pool);
    from_h1->content_length = from_h1->response->content_length;
    from_h1->chunked = r->chunked;
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, r->connection,
                  "h2_from_h1(%d): converted headers, content-length: %d"
                  ", chunked=%d",
                  from_h1->stream_id, (int)from_h1->content_length, 
                  (int)from_h1->chunked);
    
    set_state(from_h1, ((from_h1->chunked || from_h1->content_length > 0)?
                        H2_RESP_ST_BODY : H2_RESP_ST_DONE));
    /* We are ready to be sent to the client */
    return APR_SUCCESS;
}

static apr_status_t parse_header(h2_from_h1 *from_h1, ap_filter_t* f, 
                                 char *line) {
    (void)f;
    
    if (line[0] == ' ' || line[0] == '\t') {
        char **plast;
        /* continuation line from the header before this */
        while (line[0] == ' ' || line[0] == '\t') {
            ++line;
        }
        
        plast = apr_array_pop(from_h1->hlines);
        if (plast == NULL) {
            /* not well formed */
            return APR_EINVAL;
        }
        APR_ARRAY_PUSH(from_h1->hlines, const char*) = apr_psprintf(from_h1->pool, "%s %s", *plast, line);
    }
    else {
        /* new header line */
        APR_ARRAY_PUSH(from_h1->hlines, const char*) = apr_pstrdup(from_h1->pool, line);
    }
    return APR_SUCCESS;
}

static apr_status_t get_line(h2_from_h1 *from_h1, apr_bucket_brigade *bb,
                             ap_filter_t* f, char *line, apr_size_t len)
{
    apr_status_t status;
    if (!from_h1->bb) {
        from_h1->bb = apr_brigade_create(from_h1->pool, f->c->bucket_alloc);
    }
    else {
        apr_brigade_cleanup(from_h1->bb);                
    }
    status = apr_brigade_split_line(from_h1->bb, bb, 
                                                 APR_BLOCK_READ, 
                                                 HUGE_STRING_LEN);
    if (status == APR_SUCCESS) {
        --len;
        status = apr_brigade_flatten(from_h1->bb, line, &len);
        if (status == APR_SUCCESS) {
            /* we assume a non-0 containing line and remove
             * trailing crlf. */
            line[len] = '\0';
            if (len >= 2 && !strcmp(H2_CRLF, line + len - 2)) {
                len -= 2;
                line[len] = '\0';
            }
            
            apr_brigade_cleanup(from_h1->bb);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                          "h2_from_h1(%d): read line: %s",
                          from_h1->stream_id, line);
        }
    }
    return status;
}

apr_status_t h2_from_h1_read_response(h2_from_h1 *from_h1, ap_filter_t* f,
                                      apr_bucket_brigade* bb)
{
    apr_status_t status = APR_SUCCESS;
    char line[HUGE_STRING_LEN];
    
    if ((from_h1->state == H2_RESP_ST_BODY) 
        || (from_h1->state == H2_RESP_ST_DONE)) {
        if (from_h1->chunked) {
            /* The httpd core HTTP_HEADER filter has or will install the 
             * "CHUNK" output transcode filter, which appears further down 
             * the filter chain. We do not want it for HTTP/2.
             * Once we successfully deinstalled it, this filter has no
             * further function and we remove it.
             */
            status = ap_remove_output_filter_byhandle(f->r->output_filters, 
                                                      "CHUNK");
            if (status == APR_SUCCESS) {
                ap_remove_output_filter(f);
            }
        }
        
        return ap_pass_brigade(f->next, bb);
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                  "h2_from_h1(%d): read_response", from_h1->stream_id);
    
    while (!APR_BRIGADE_EMPTY(bb) && status == APR_SUCCESS) {
        
        switch (from_h1->state) {
                
            case H2_RESP_ST_STATUS_LINE:
            case H2_RESP_ST_HEADERS:
                status = get_line(from_h1, bb, f, line, sizeof(line));
                if (status != APR_SUCCESS) {
                    return status;
                }
                if (from_h1->state == H2_RESP_ST_STATUS_LINE) {
                    /* instead of parsing, just take it directly */
                    from_h1->http_status = f->r->status;
                    from_h1->state = H2_RESP_ST_HEADERS;
                }
                else if (line[0] == '\0') {
                    /* end of headers, create the h2_response and
                     * pass the rest of the brigade down the filter
                     * chain.
                     */
                    status = make_h2_headers(from_h1, f->r);
                    if (from_h1->bb) {
                        apr_brigade_destroy(from_h1->bb);
                        from_h1->bb = NULL;
                    }
                    if (!APR_BRIGADE_EMPTY(bb)) {
                        return ap_pass_brigade(f->next, bb);
                    }
                }
                else {
                    status = parse_header(from_h1, f, line);
                }
                break;
                
            default:
                return ap_pass_brigade(f->next, bb);
        }
        
    }
    
    return status;
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
    
    (void)key;
    values = (apr_array_header_t *)d;
    
    e = apr_pstrdup(values->pool, val);
    
    do {
        /* Find a non-empty fieldname */
        
        while (*e == ',' || apr_isspace(*e)) {
            ++e;
        }
        if (*e == '\0') {
            break;
        }
        start = e;
        while (*e != '\0' && *e != ',' && !apr_isspace(*e)) {
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
            if (*strpp && apr_strnatcasecmp(*strpp, start) == 0) {
                break;
            }
        }
        if (i == values->nelts) {  /* if not found */
            *(char **)apr_array_push(values) = start;
        }
    } while (*e != '\0');
    
    return 1;
}

/*
 * Since some clients choke violently on multiple Vary fields, or
 * Vary fields with duplicate tokens, combine any multiples and remove
 * any duplicates.
 */
static void fix_vary(request_rec *r)
{
    apr_array_header_t *varies;
    
    varies = apr_array_make(r->pool, 5, sizeof(char *));
    
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

static void set_basic_http_header(request_rec *r, apr_table_t *headers)
{
    char *date = NULL;
    const char *proxy_date = NULL;
    const char *server = NULL;
    const char *us = ap_get_server_banner();
    
    /*
     * keep the set-by-proxy server and date headers, otherwise
     * generate a new server header / date header
     */
    if (r->proxyreq != PROXYREQ_NONE) {
        proxy_date = apr_table_get(r->headers_out, "Date");
        if (!proxy_date) {
            /*
             * proxy_date needs to be const. So use date for the creation of
             * our own Date header and pass it over to proxy_date later to
             * avoid a compiler warning.
             */
            date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
            ap_recent_rfc822_date(date, r->request_time);
        }
        server = apr_table_get(r->headers_out, "Server");
    }
    else {
        date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
        ap_recent_rfc822_date(date, r->request_time);
    }
    
    apr_table_setn(headers, "Date", proxy_date ? proxy_date : date );
    apr_table_unset(r->headers_out, "Date");
    
    if (!server && *us) {
        server = us;
    }
    if (server) {
        apr_table_setn(headers, "Server", server);
        apr_table_unset(r->headers_out, "Server");
    }
}

static int copy_header(void *ctx, const char *name, const char *value)
{
    apr_table_t *headers = ctx;
    
    apr_table_addn(headers, name, value);
    return 1;
}

static h2_response *create_response(h2_from_h1 *from_h1, request_rec *r)
{
    const char *clheader;
    const char *ctype;
    apr_table_t *headers;
    /*
     * Now that we are ready to send a response, we need to combine the two
     * header field tables into a single table.  If we don't do this, our
     * later attempts to set or unset a given fieldname might be bypassed.
     */
    if (!apr_is_empty_table(r->err_headers_out)) {
        r->headers_out = apr_table_overlay(r->pool, r->err_headers_out,
                                           r->headers_out);
        apr_table_clear(r->err_headers_out);
    }
    
    /*
     * Remove the 'Vary' header field if the client can't handle it.
     * Since this will have nasty effects on HTTP/1.1 caches, force
     * the response into HTTP/1.0 mode.
     */
    if (apr_table_get(r->subprocess_env, "force-no-vary") != NULL) {
        apr_table_unset(r->headers_out, "Vary");
        r->proto_num = HTTP_VERSION(1,0);
        apr_table_setn(r->subprocess_env, "force-response-1.0", "1");
    }
    else {
        fix_vary(r);
    }
    
    /*
     * Now remove any ETag response header field if earlier processing
     * says so (such as a 'FileETag None' directive).
     */
    if (apr_table_get(r->notes, "no-etag") != NULL) {
        apr_table_unset(r->headers_out, "ETag");
    }
    
    /* determine the protocol and whether we should use keepalives. */
    ap_set_keepalive(r);
    
    if (r->chunked) {
        apr_table_unset(r->headers_out, "Content-Length");
    }
    
    ctype = ap_make_content_type(r, r->content_type);
    if (ctype) {
        apr_table_setn(r->headers_out, "Content-Type", ctype);
    }
    
    if (r->content_encoding) {
        apr_table_setn(r->headers_out, "Content-Encoding",
                       r->content_encoding);
    }
    
    if (!apr_is_empty_array(r->content_languages)) {
        unsigned int i;
        char *token;
        char **languages = (char **)(r->content_languages->elts);
        const char *field = apr_table_get(r->headers_out, "Content-Language");
        
        while (field && (token = ap_get_list_item(r->pool, &field)) != NULL) {
            for (i = 0; i < r->content_languages->nelts; ++i) {
                if (!apr_strnatcasecmp(token, languages[i]))
                    break;
            }
            if (i == r->content_languages->nelts) {
                *((char **) apr_array_push(r->content_languages)) = token;
            }
        }
        
        field = apr_array_pstrcat(r->pool, r->content_languages, ',');
        apr_table_setn(r->headers_out, "Content-Language", field);
    }
    
    /*
     * Control cachability for non-cachable responses if not already set by
     * some other part of the server configuration.
     */
    if (r->no_cache && !apr_table_get(r->headers_out, "Expires")) {
        char *date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
        ap_recent_rfc822_date(date, r->request_time);
        apr_table_addn(r->headers_out, "Expires", date);
    }
    
    /* This is a hack, but I can't find anyway around it.  The idea is that
     * we don't want to send out 0 Content-Lengths if it is a head request.
     * This happens when modules try to outsmart the server, and return
     * if they see a HEAD request.  Apache 1.3 handlers were supposed to
     * just return in that situation, and the core handled the HEAD.  In
     * 2.0, if a handler returns, then the core sends an EOS bucket down
     * the filter stack, and the content-length filter computes a C-L of
     * zero and that gets put in the headers, and we end up sending a
     * zero C-L to the client.  We can't just remove the C-L filter,
     * because well behaved 2.0 handlers will send their data down the stack,
     * and we will compute a real C-L for the head request. RBB
     */
    if (r->header_only
        && (clheader = apr_table_get(r->headers_out, "Content-Length"))
        && !strcmp(clheader, "0")) {
        apr_table_unset(r->headers_out, "Content-Length");
    }
    
    headers = apr_table_make(r->pool, 10);
    
    set_basic_http_header(r, headers);
    if (r->status == HTTP_NOT_MODIFIED) {
        apr_table_do((int (*)(void *, const char *, const char *)) copy_header,
                     (void *) headers, r->headers_out,
                     "ETag",
                     "Content-Location",
                     "Expires",
                     "Cache-Control",
                     "Vary",
                     "Warning",
                     "WWW-Authenticate",
                     "Proxy-Authenticate",
                     "Set-Cookie",
                     "Set-Cookie2",
                     NULL);
    }
    else {
        apr_table_do((int (*)(void *, const char *, const char *)) copy_header,
                     (void *) headers, r->headers_out, NULL);
    }
    
    return h2_response_rcreate(from_h1->stream_id, r, headers, r->pool);
}

apr_status_t h2_response_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    h2_task *task = f->ctx;
    h2_from_h1 *from_h1 = task->output? task->output->from_h1 : NULL;
    request_rec *r = f->r;
    apr_bucket *b;
    ap_bucket_error *eb = NULL;

    AP_DEBUG_ASSERT(from_h1 != NULL);
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                  "h2_from_h1(%d): output_filter called", from_h1->stream_id);
    
    if (r->header_only && task->output && from_h1->response) {
        /* throw away any data after we have compiled the response */
        apr_brigade_cleanup(bb);
        return OK;
    }
    
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        if (AP_BUCKET_IS_ERROR(b) && !eb) {
            eb = b->data;
            continue;
        }
        /*
         * If we see an EOC bucket it is a signal that we should get out
         * of the way doing nothing.
         */
        if (AP_BUCKET_IS_EOC(b)) {
            ap_remove_output_filter(f);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, f->c,
                          "h2_from_h1(%d): eoc bucket passed", 
                          from_h1->stream_id);
            return ap_pass_brigade(f->next, bb);
        }
    }
    
    if (eb) {
        int st = eb->status;
        apr_brigade_cleanup(bb);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c,
                      "h2_from_h1(%d): err bucket status=%d", 
                      from_h1->stream_id, st);
        ap_die(st, r);
        return AP_FILTER_ERROR;
    }
    
    from_h1->response = create_response(from_h1, r);
    if (from_h1->response == NULL) {
        ap_log_cerror(APLOG_MARK, APLOG_NOTICE, 0, f->c,
                      "h2_from_h1(%d): unable to create response", 
                      from_h1->stream_id);
        return APR_ENOMEM;
    }
    
    if (r->header_only) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                      "h2_from_h1(%d): header_only, cleanup output brigade", 
                      from_h1->stream_id);
        apr_brigade_cleanup(bb);
        return OK;
    }
    
    r->sent_bodyct = 1;         /* Whatever follows is real body stuff... */
    
    ap_remove_output_filter(f);
    if (APLOGctrace1(f->c)) {
        apr_off_t len = 0;
        apr_brigade_length(bb, 0, &len);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                      "h2_from_h1(%d): removed header filter, passing brigade "
                      "len=%ld", from_h1->stream_id, (long)len);
    }
    return ap_pass_brigade(f->next, bb);
}

apr_status_t h2_response_trailers_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    h2_task *task = f->ctx;
    h2_from_h1 *from_h1 = task->output? task->output->from_h1 : NULL;
    request_rec *r = f->r;
    apr_bucket *b;
 
    if (from_h1 && from_h1->response) {
        /* Detect the EOR bucket and forward any trailers that may have
         * been set to our h2_response.
         */
        for (b = APR_BRIGADE_FIRST(bb);
             b != APR_BRIGADE_SENTINEL(bb);
             b = APR_BUCKET_NEXT(b))
        {
            if (AP_BUCKET_IS_EOR(b)) {
                /* FIXME: need a better test case than this.
                apr_table_setn(r->trailers_out, "X", "1"); */
                if (r->trailers_out && !apr_is_empty_table(r->trailers_out)) {
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c,
                                  "h2_from_h1(%d): trailers filter, saving trailers",
                                  from_h1->stream_id);
                    h2_response_set_trailers(from_h1->response,
                                             apr_table_clone(from_h1->pool, 
                                                             r->trailers_out));
                }
                break;
            }
        }     
    }
     
    return ap_pass_brigade(f->next, bb);
}

