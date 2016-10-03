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
#include "h2_headers.h"
#include "h2_from_h1.h"
#include "h2_task.h"
#include "h2_util.h"


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

void h2_from_h1_set_basic_http_header(apr_table_t *headers, request_rec *r,
                                      apr_pool_t *pool)
{
    char *date = NULL;
    const char *proxy_date = NULL;
    const char *server = NULL;
    const char *us = ap_get_server_banner();
    
    /*
     * keep the set-by-proxy server and date headers, otherwise
     * generate a new server header / date header
     */
    if (r && r->proxyreq != PROXYREQ_NONE) {
        proxy_date = apr_table_get(r->headers_out, "Date");
        if (!proxy_date) {
            /*
             * proxy_date needs to be const. So use date for the creation of
             * our own Date header and pass it over to proxy_date later to
             * avoid a compiler warning.
             */
            date = apr_palloc(pool, APR_RFC822_DATE_LEN);
            ap_recent_rfc822_date(date, r->request_time);
        }
        server = apr_table_get(r->headers_out, "Server");
    }
    else {
        date = apr_palloc(pool, APR_RFC822_DATE_LEN);
        ap_recent_rfc822_date(date, r? r->request_time : apr_time_now());
    }
    
    apr_table_setn(headers, "Date", proxy_date ? proxy_date : date );
    if (r) {
        apr_table_unset(r->headers_out, "Date");
    }
    
    if (!server && *us) {
        server = us;
    }
    if (server) {
        apr_table_setn(headers, "Server", server);
        if (r) {
            apr_table_unset(r->headers_out, "Server");
        }
    }
}

static int copy_header(void *ctx, const char *name, const char *value)
{
    apr_table_t *headers = ctx;
    
    apr_table_addn(headers, name, value);
    return 1;
}

static h2_headers *create_response(h2_task *task, request_rec *r)
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
    
    h2_from_h1_set_basic_http_header(headers, r, r->pool);
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
    
    return h2_headers_rcreate(r, r->status, headers, r->pool);
}

apr_status_t h2_headers_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    h2_task *task = f->ctx;
    request_rec *r = f->r;
    apr_bucket *b, *bresp, *body_bucket = NULL, *next;
    ap_bucket_error *eb = NULL;
    h2_headers *response = NULL;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                  "h2_task(%s): output_filter called", task->id);
    
    if (!task->output.sent_response) {
        /* check, if we need to send the response now. Until we actually
         * see a DATA bucket or some EOS/EOR, we do not do so. */
        for (b = APR_BRIGADE_FIRST(bb);
             b != APR_BRIGADE_SENTINEL(bb);
             b = APR_BUCKET_NEXT(b))
        {
            if (AP_BUCKET_IS_ERROR(b) && !eb) {
                eb = b->data;
            }
            else if (AP_BUCKET_IS_EOC(b)) {
                /* If we see an EOC bucket it is a signal that we should get out
                 * of the way doing nothing.
                 */
                ap_remove_output_filter(f);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, f->c,
                              "h2_task(%s): eoc bucket passed", task->id);
                return ap_pass_brigade(f->next, bb);
            }
            else if (!H2_BUCKET_IS_HEADERS(b) && !APR_BUCKET_IS_FLUSH(b)) { 
                body_bucket = b;
                break;
            }
        }
        
        if (eb) {
            int st = eb->status;
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, APLOGNO(03047)
                          "h2_task(%s): err bucket status=%d", task->id, st);
            /* throw everything away and replace it with the error response
             * generated by ap_die() */
            apr_brigade_cleanup(bb);
            ap_die(st, r);
            return AP_FILTER_ERROR;
        }
        
        if (body_bucket) {
            /* time to insert the response bucket before the body */
            response = create_response(task, r);
            if (response == NULL) {
                ap_log_cerror(APLOG_MARK, APLOG_NOTICE, 0, f->c, APLOGNO(03048)
                              "h2_task(%s): unable to create response", task->id);
                return APR_ENOMEM;
            }
            
            bresp = h2_bucket_headers_create(f->c->bucket_alloc, response);
            APR_BUCKET_INSERT_BEFORE(body_bucket, bresp);
            /*APR_BRIGADE_INSERT_HEAD(bb, bresp);*/
            task->output.sent_response = 1;
            r->sent_bodyct = 1;
        }
    }
    
    if (r->header_only) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                      "h2_task(%s): header_only, cleanup output brigade", 
                      task->id);
        b = body_bucket? body_bucket : APR_BRIGADE_FIRST(bb);
        while (b != APR_BRIGADE_SENTINEL(bb)) {
            next = APR_BUCKET_NEXT(b);
            if (APR_BUCKET_IS_EOS(b) || AP_BUCKET_IS_EOR(b)) {
                break;
            } 
            APR_BUCKET_REMOVE(b);
            apr_bucket_destroy(b);
            b = next;
        }
    }
    else if (task->output.sent_response) {
        /* lets get out of the way, our task is done */
        ap_remove_output_filter(f);
    }
    return ap_pass_brigade(f->next, bb);
}

static void make_chunk(h2_task *task, apr_bucket_brigade *bb, 
                       apr_bucket *first, apr_uint64_t chunk_len, 
                       apr_bucket *tail)
{
    /* Surround the buckets [first, tail[ with new buckets carrying the
     * HTTP/1.1 chunked encoding format. If tail is NULL, the chunk extends
     * to the end of the brigade. */
    char buffer[128];
    apr_bucket *c;
    int len;
    
    len = apr_snprintf(buffer, H2_ALEN(buffer), 
                       "%"APR_UINT64_T_HEX_FMT"\r\n", chunk_len);
    c = apr_bucket_heap_create(buffer, len, NULL, bb->bucket_alloc);
    APR_BUCKET_INSERT_BEFORE(first, c);
    c = apr_bucket_heap_create("\r\n", 2, NULL, bb->bucket_alloc);
    if (tail) {
        APR_BUCKET_INSERT_BEFORE(tail, c);
    }
    else {
        APR_BRIGADE_INSERT_TAIL(bb, c);
    }
}

static int ser_header(void *ctx, const char *name, const char *value) 
{
    apr_bucket_brigade *bb = ctx;
    apr_brigade_printf(bb, NULL, NULL, "%s: %s\r\n", name, value);
    return 1;
}

apr_status_t h2_filter_request_in(ap_filter_t* f,
                                  apr_bucket_brigade* bb,
                                  ap_input_mode_t mode,
                                  apr_read_type_e block,
                                  apr_off_t readbytes)
{
    h2_task *task = f->ctx;
    request_rec *r = f->r;
    apr_status_t status = APR_SUCCESS;
    apr_bucket *b, *next, *first_data = NULL;
    apr_off_t bblen = 0;

    if (!task->input.chunked) {
        status = ap_get_brigade(f->next, bb, mode, block, readbytes);
        /* pipe data through, just take care of trailers */
        for (b = APR_BRIGADE_FIRST(bb); 
             b != APR_BRIGADE_SENTINEL(bb); b = next) {
            next = APR_BUCKET_NEXT(b);
            if (H2_BUCKET_IS_HEADERS(b)) {
                h2_headers *headers = h2_bucket_headers_get(b);
                ap_assert(headers);
                ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                              "h2_task(%s): receiving trailers", task->id);
                r->trailers_in = apr_table_clone(r->pool, headers->headers);
                APR_BUCKET_REMOVE(b);
                apr_bucket_destroy(b);
                ap_remove_input_filter(f);
                break;
            }
        }
        return status;
    }

    /* Things are more complicated. The standard HTTP input filter, which
     * does a lot what we do not want to duplicate, also cares about chunked
     * transfer encoding and trailers.
     * We need to simulate chunked encoding for it to be happy.
     */
    
    if (!task->input.bbchunk) {
        task->input.bbchunk = apr_brigade_create(r->pool, f->c->bucket_alloc);
    }
    if (APR_BRIGADE_EMPTY(task->input.bbchunk)) {
        /* get more data from the lower layer filters. Always do this
         * in larger pieces, since we handle the read modes ourself.
         */
        status = ap_get_brigade(f->next, task->input.bbchunk, 
                                AP_MODE_READBYTES, block, 32*1024);
        if (status == APR_EOF) {
            if (!task->input.eos) {
                status = apr_brigade_puts(bb, NULL, NULL, "0\r\n\r\n");
                task->input.eos = 1;
                return APR_SUCCESS;
            }
            ap_remove_input_filter(f);
            return status;
            
        }
        else if (status != APR_SUCCESS) {
            return status;
        }

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "h2_task(%s): trailers_in inspecting brigade", task->id);
        for (b = APR_BRIGADE_FIRST(task->input.bbchunk); 
             b != APR_BRIGADE_SENTINEL(task->input.bbchunk) && !task->input.eos; 
             b = next) {
            next = APR_BUCKET_NEXT(b);
            if (APR_BUCKET_IS_METADATA(b)) {
                if (first_data) {
                    make_chunk(task, task->input.bbchunk, first_data, bblen, b);
                    first_data = NULL;
                    bblen = 0;
                }
                
                if (H2_BUCKET_IS_HEADERS(b)) {
                    apr_bucket_brigade *tmp;
                    h2_headers *headers = h2_bucket_headers_get(b);
                    
                    ap_assert(headers);
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                                  "h2_task(%s): receiving trailers", task->id);
                    tmp = apr_brigade_split_ex(task->input.bbchunk, b, NULL);
                    if (!apr_is_empty_table(headers->headers)) {
                        status = apr_brigade_puts(task->input.bbchunk, NULL, NULL, "0\r\n");
                        apr_table_do(ser_header, task->input.bbchunk, headers->headers, NULL);
                        status = apr_brigade_puts(task->input.bbchunk, NULL, NULL, "\r\n");
                    }
                    else {
                        status = apr_brigade_puts(task->input.bbchunk, NULL, NULL, "0\r\n\r\n");
                    }
                    APR_BRIGADE_CONCAT(task->input.bbchunk, tmp);
                    apr_brigade_destroy(tmp);
                    r->trailers_in = apr_table_clone(r->pool, headers->headers);
                    APR_BUCKET_REMOVE(b);
                    apr_bucket_destroy(b);
                    task->input.eos = 1;
                }
                else if (APR_BUCKET_IS_EOS(b)) {
                    apr_bucket_brigade *tmp = apr_brigade_split_ex(task->input.bbchunk, b, NULL);
                    status = apr_brigade_puts(task->input.bbchunk, NULL, NULL, "0\r\n\r\n");
                    APR_BRIGADE_CONCAT(task->input.bbchunk, tmp);
                    apr_brigade_destroy(tmp);
                    task->input.eos = 1;
                }
                break;
            }
            else if (b->length == 0) {
                APR_BUCKET_REMOVE(b);
                apr_bucket_destroy(b);
            } 
            else {
                if (!first_data) {
                    first_data = b;
                }
                bblen += b->length;
            }    
        }
        
        if (first_data) {
            make_chunk(task, task->input.bbchunk, first_data, bblen, NULL);
        }            
    }
    
    if (mode == AP_MODE_EXHAUSTIVE) {
        /* return all we have */
        APR_BRIGADE_CONCAT(bb, task->input.bbchunk);
    }
    else if (mode == AP_MODE_READBYTES) {
        status = h2_brigade_concat_length(bb, task->input.bbchunk, readbytes);
    }
    else if (mode == AP_MODE_SPECULATIVE) {
        status = h2_brigade_copy_length(bb, task->input.bbchunk, readbytes);
    }
    else if (mode == AP_MODE_GETLINE) {
        /* we are reading a single LF line, e.g. the HTTP headers. 
         * this has the nasty side effect to split the bucket, even
         * though it ends with CRLF and creates a 0 length bucket */
        status = apr_brigade_split_line(bb, task->input.bbchunk, block, 
                                        HUGE_STRING_LEN);
        if (APLOGctrace1(f->c)) {
            char buffer[1024];
            apr_size_t len = sizeof(buffer)-1;
            apr_brigade_flatten(bb, buffer, &len);
            buffer[len] = 0;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                          "h2_task(%s): getline: %s",
                          task->id, buffer);
        }
    }
    else {
        /* Hmm, well. There is mode AP_MODE_EATCRLF, but we chose not
         * to support it. Seems to work. */
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOTIMPL, f->c,
                      APLOGNO(02942) 
                      "h2_task, unsupported READ mode %d", mode);
        status = APR_ENOTIMPL;
    }
    
    h2_util_bb_log(f->c, task->stream_id, APLOG_TRACE2, "forwarding input", bb);
    return status;
}

apr_status_t h2_filter_trailers_out(ap_filter_t *f, apr_bucket_brigade *bb)
{
    h2_task *task = f->ctx;
    request_rec *r = f->r;
    apr_bucket *b, *e;
 
    if (task && r) {
        /* Detect the EOS/EOR bucket and forward any trailers that may have
         * been set to our h2_headers.
         */
        for (b = APR_BRIGADE_FIRST(bb);
             b != APR_BRIGADE_SENTINEL(bb);
             b = APR_BUCKET_NEXT(b))
        {
            if ((APR_BUCKET_IS_EOS(b) || AP_BUCKET_IS_EOR(b))
                && r->trailers_out && !apr_is_empty_table(r->trailers_out)) {
                h2_headers *headers;
                apr_table_t *trailers;
                
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, APLOGNO(03049)
                              "h2_task(%s): sending trailers", task->id);
                trailers = apr_table_clone(r->pool, r->trailers_out);
                headers = h2_headers_rcreate(r, HTTP_OK, trailers, r->pool);
                e = h2_bucket_headers_create(bb->bucket_alloc, headers);
                APR_BUCKET_INSERT_BEFORE(b, e);
                apr_table_clear(r->trailers_out);
                ap_remove_output_filter(f);
                break;
            }
        }     
    }
     
    return ap_pass_brigade(f->next, bb);
}

