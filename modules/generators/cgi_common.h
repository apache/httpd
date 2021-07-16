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

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_poll.h"

#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#include "httpd.h"
#include "util_filter.h"
#include "util_script.h"

static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *cgi_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *cgi_pfn_ps;

/* These functions provided by mod_cgi.c/mod_cgid.c still. */
static int log_script(request_rec *r, cgi_server_conf * conf, int ret,
                      char *dbuf, const char *sbuf, apr_bucket_brigade *bb,
                      apr_file_t *script_err);
static apr_status_t include_cgi(include_ctx_t *ctx, ap_filter_t *f,
                                apr_bucket_brigade *bb, char *s);
static apr_status_t include_cmd(include_ctx_t *ctx, ap_filter_t *f,
                                apr_bucket_brigade *bb, const char *command);

/* Read and discard all output from the brigade.  Note that with the
 * CGI bucket, the brigade will become empty once the script's stdout
 * is closed (or on error/timeout), but the stderr output may not have
 * been entirely captured at this point. */
static void discard_script_output(apr_bucket_brigade *bb)
{
    apr_bucket *e;
    const char *buf;
    apr_size_t len;

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb) && !APR_BUCKET_IS_EOS(e);
         e = APR_BRIGADE_FIRST(bb))
    {
        if (apr_bucket_read(e, &buf, &len, APR_BLOCK_READ)) {
            break;
        }
        apr_bucket_delete(e);
    }
}

static int log_scripterror(request_rec *r, cgi_server_conf *conf, int ret,
                           apr_status_t rv, const char *logno,
                           const char *error)
{
    apr_file_t *f = NULL;
    apr_finfo_t finfo;
    char time_str[APR_CTIME_LEN];

    /* Intentional no APLOGNO */
    /* Callee provides APLOGNO in error text */
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                  "%sstderr from %s: %s", logno ? logno : "", r->filename, error);

    /* XXX Very expensive mainline case! Open, then getfileinfo! */
    if (!conf->logname ||
        ((apr_stat(&finfo, conf->logname,
                   APR_FINFO_SIZE, r->pool) == APR_SUCCESS) &&
         (finfo.size > conf->logbytes)) ||
        (apr_file_open(&f, conf->logname,
                       APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT,
                       r->pool) != APR_SUCCESS)) {
        return ret;
    }

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgi-bin/printenv HTTP/1.0" */
    apr_ctime(time_str, apr_time_now());
    apr_file_printf(f, "%%%% [%s] %s %s%s%s %s\n", time_str, r->method, r->uri,
                    r->args ? "?" : "", r->args ? r->args : "", r->protocol);
    /* "%% 500 /usr/local/apache/cgi-bin */
    apr_file_printf(f, "%%%% %d %s\n", ret, r->filename);

    apr_file_printf(f, "%%error\n%s\n", error);

    apr_file_close(f);
    return ret;
}

/* Soak up stderr from a script and redirect it to the error log.
 */
static apr_status_t log_script_err(request_rec *r, apr_file_t *script_err)
{
    char argsbuffer[HUGE_STRING_LEN];
    char *newline;
    apr_status_t rv;
    cgi_server_conf *conf = ap_get_module_config(r->server->module_config, &cgi_module);

    while ((rv = apr_file_gets(argsbuffer, HUGE_STRING_LEN,
                               script_err)) == APR_SUCCESS) {

        newline = strchr(argsbuffer, '\n');
        if (newline) {
            char *prev = newline - 1;
            if (prev >= argsbuffer && *prev == '\r') {
                newline = prev;
            }

            *newline = '\0';
        }
        log_scripterror(r, conf, r->status, 0, APLOGNO(01215), argsbuffer);
    }

    return rv;
}

static apr_status_t cgi_handle_exec(include_ctx_t *ctx, ap_filter_t *f,
                                    apr_bucket_brigade *bb)
{
    char *tag = NULL;
    char *tag_val = NULL;
    request_rec *r = f->r;
    char *file = r->filename;
    char parsed_string[MAX_STRING_LEN];

    if (!ctx->argc) {
        ap_log_rerror(APLOG_MARK,
                      (ctx->flags & SSI_FLAG_PRINTING)
                          ? APLOG_ERR : APLOG_WARNING,
                      0, r, APLOGNO(03195)
                      "missing argument for exec element in %s", r->filename);
    }

    if (!(ctx->flags & SSI_FLAG_PRINTING)) {
        return APR_SUCCESS;
    }

    if (!ctx->argc) {
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    if (ctx->flags & SSI_FLAG_NO_EXEC) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01228) "exec used but not allowed "
                      "in %s", r->filename);
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    while (1) {
        cgi_pfn_gtv(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
        if (!tag || !tag_val) {
            break;
        }

        if (!strcmp(tag, "cmd")) {
            apr_status_t rv;

            cgi_pfn_ps(ctx, tag_val, parsed_string, sizeof(parsed_string),
                       SSI_EXPAND_LEAVE_NAME);

            rv = include_cmd(ctx, f, bb, parsed_string);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01229) "execution failure "
                              "for parameter \"%s\" to tag exec in file %s",
                              tag, r->filename);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                break;
            }
        }
        else if (!strcmp(tag, "cgi")) {
            apr_status_t rv;

            cgi_pfn_ps(ctx, tag_val, parsed_string, sizeof(parsed_string),
                       SSI_EXPAND_DROP_NAME);

            rv = include_cgi(ctx, f, bb, parsed_string);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01230) "invalid CGI ref "
                              "\"%s\" in %s", tag_val, file);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                break;
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01231) "unknown parameter "
                          "\"%s\" to tag exec in %s", tag, file);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            break;
        }
    }

    return APR_SUCCESS;
}

/* Hook to register exec= handling with mod_include. */
static void cgi_optfns_retrieve(void)
{
    APR_OPTIONAL_FN_TYPE(ap_register_include_handler) *cgi_pfn_reg_with_ssi;

    cgi_pfn_reg_with_ssi = APR_RETRIEVE_OPTIONAL_FN(ap_register_include_handler);
    cgi_pfn_gtv          = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_get_tag_and_value);
    cgi_pfn_ps           = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_parse_string);

    if (cgi_pfn_reg_with_ssi && cgi_pfn_gtv && cgi_pfn_ps) {
        /* Required by mod_include filter. This is how mod_cgi registers
         *   with mod_include to provide processing of the exec directive.
         */
        cgi_pfn_reg_with_ssi("exec", cgi_handle_exec);
    }
}

#ifdef WANT_CGI_BUCKET
/* A CGI bucket type is needed to catch any output to stderr from the
 * script; see PR 22030. */
static const apr_bucket_type_t bucket_type_cgi;

struct cgi_bucket_data {
    apr_pollset_t *pollset;
    request_rec *r;
    apr_interval_time_t timeout;
};

/* Create a CGI bucket using pipes from script stdout 'out'
 * and stderr 'err', for request 'r'. */
static apr_bucket *cgi_bucket_create(request_rec *r,
                                     apr_interval_time_t timeout,
                                     apr_file_t *out, apr_file_t *err,
                                     apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    apr_status_t rv;
    apr_pollfd_t fd;
    struct cgi_bucket_data *data = apr_palloc(r->pool, sizeof *data);

    /* Disable APR timeout handling since we'll use poll() entirely. */
    apr_file_pipe_timeout_set(out, 0);
    apr_file_pipe_timeout_set(err, 0);
    
    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->type = &bucket_type_cgi;
    b->length = (apr_size_t)(-1);
    b->start = -1;

    /* Create the pollset */
    rv = apr_pollset_create(&data->pollset, 2, r->pool, 0);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01217)
                     "apr_pollset_create(); check system or user limits");
        return NULL;
    }

    fd.desc_type = APR_POLL_FILE;
    fd.reqevents = APR_POLLIN;
    fd.p = r->pool;
    fd.desc.f = out; /* script's stdout */
    fd.client_data = (void *)1;
    rv = apr_pollset_add(data->pollset, &fd);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01218)
                     "apr_pollset_add(); check system or user limits");
        return NULL;
    }

    fd.desc.f = err; /* script's stderr */
    fd.client_data = (void *)2;
    rv = apr_pollset_add(data->pollset, &fd);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01219)
                     "apr_pollset_add(); check system or user limits");
        return NULL;
    }

    data->r = r;
    data->timeout = timeout;
    b->data = data;
    return b;
}

/* Create a duplicate CGI bucket using given bucket data */
static apr_bucket *cgi_bucket_dup(struct cgi_bucket_data *data,
                                  apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->type = &bucket_type_cgi;
    b->length = (apr_size_t)(-1);
    b->start = -1;
    b->data = data;
    return b;
}

/* Handle stdout from CGI child.  Duplicate of logic from the _read
 * method of the real APR pipe bucket implementation. */
static apr_status_t cgi_read_stdout(apr_bucket *a, apr_file_t *out,
                                    const char **str, apr_size_t *len)
{
    char *buf;
    apr_status_t rv;

    *str = NULL;
    *len = APR_BUCKET_BUFF_SIZE;
    buf = apr_bucket_alloc(*len, a->list); /* XXX: check for failure? */

    rv = apr_file_read(out, buf, len);

    if (rv != APR_SUCCESS && rv != APR_EOF) {
        apr_bucket_free(buf);
        return rv;
    }

    if (*len > 0) {
        struct cgi_bucket_data *data = a->data;
        apr_bucket_heap *h;

        /* Change the current bucket to refer to what we read */
        a = apr_bucket_heap_make(a, buf, *len, apr_bucket_free);
        h = a->data;
        h->alloc_len = APR_BUCKET_BUFF_SIZE; /* note the real buffer size */
        *str = buf;
        APR_BUCKET_INSERT_AFTER(a, cgi_bucket_dup(data, a->list));
    }
    else {
        apr_bucket_free(buf);
        a = apr_bucket_immortal_make(a, "", 0);
        *str = a->data;
    }
    return rv;
}

/* Read method of CGI bucket: polls on stderr and stdout of the child,
 * sending any stderr output immediately away to the error log. */
static apr_status_t cgi_bucket_read(apr_bucket *b, const char **str,
                                    apr_size_t *len, apr_read_type_e block)
{
    struct cgi_bucket_data *data = b->data;
    apr_interval_time_t timeout = 0;
    apr_status_t rv;
    int gotdata = 0;

    if (block != APR_NONBLOCK_READ) {
        timeout = data->timeout > 0 ? data->timeout : data->r->server->timeout;
    }

    do {
        const apr_pollfd_t *results;
        apr_int32_t num;

        rv = apr_pollset_poll(data->pollset, timeout, &num, &results);
        if (APR_STATUS_IS_TIMEUP(rv)) {
            if (timeout) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, data->r, APLOGNO(01220)
                              "Timeout waiting for output from CGI script %s",
                              data->r->filename);
                return rv;
            }
            else {
                return APR_EAGAIN;
            }
        }
        else if (APR_STATUS_IS_EINTR(rv)) {
            continue;
        }
        else if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, data->r, APLOGNO(01221)
                          "poll failed waiting for CGI child");
            return rv;
        }

        for (; num; num--, results++) {
            if (results[0].client_data == (void *)1) {
                /* stdout */
                rv = cgi_read_stdout(b, results[0].desc.f, str, len);
                if (APR_STATUS_IS_EOF(rv)) {
                    rv = APR_SUCCESS;
                }
                gotdata = 1;
            } else {
                /* stderr */
                apr_status_t rv2 = log_script_err(data->r, results[0].desc.f);
                if (APR_STATUS_IS_EOF(rv2)) {
                    apr_pollset_remove(data->pollset, &results[0]);
                }
            }
        }

    } while (!gotdata);

    return rv;
}

static const apr_bucket_type_t bucket_type_cgi = {
    "CGI", 5, APR_BUCKET_DATA,
    apr_bucket_destroy_noop,
    cgi_bucket_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_copy_notimpl
};

#endif /* WANT_CGI_BUCKET */

/* Handle the CGI response output, having set up the brigade with the
 * CGI or PIPE bucket as appropriate. */
static int cgi_handle_response(request_rec *r, int nph, apr_bucket_brigade *bb,
                               apr_interval_time_t timeout, cgi_server_conf *conf,
                               char *logdata, apr_file_t *script_err)
{
    apr_status_t rv;
    
    /* Handle script return... */
    if (!nph) {
        const char *location;
        char sbuf[MAX_STRING_LEN];
        int ret;

        ret = ap_scan_script_header_err_brigade_ex(r, bb, sbuf,
                                                   APLOG_MODULE_INDEX);

        /* xCGI has its own body framing mechanism which we don't
         * match against any provided Content-Length, so let the
         * core determine C-L vs T-E based on what's actually sent.
         */
        if (!apr_table_get(r->subprocess_env, AP_TRUST_CGILIKE_CL_ENVVAR))
            apr_table_unset(r->headers_out, "Content-Length");
        apr_table_unset(r->headers_out, "Transfer-Encoding");

        if (ret != OK) {
            /* In the case of a timeout reading script output, clear
             * the brigade to avoid a second attempt to read the
             * output. */
            if (ret == HTTP_GATEWAY_TIME_OUT) {
                apr_brigade_cleanup(bb);
            }

            ret = log_script(r, conf, ret, logdata, sbuf, bb, script_err);

            /*
             * ret could be HTTP_NOT_MODIFIED in the case that the CGI script
             * does not set an explicit status and ap_meets_conditions, which
             * is called by ap_scan_script_header_err_brigade, detects that
             * the conditions of the requests are met and the response is
             * not modified.
             * In this case set r->status and return OK in order to prevent
             * running through the error processing stack as this would
             * break with mod_cache, if the conditions had been set by
             * mod_cache itself to validate a stale entity.
             * BTW: We circumvent the error processing stack anyway if the
             * CGI script set an explicit status code (whatever it is) and
             * the only possible values for ret here are:
             *
             * HTTP_NOT_MODIFIED          (set by ap_meets_conditions)
             * HTTP_PRECONDITION_FAILED   (set by ap_meets_conditions)
             * HTTP_INTERNAL_SERVER_ERROR (if something went wrong during the
             * processing of the response of the CGI script, e.g broken headers
             * or a crashed CGI process).
             */
            if (ret == HTTP_NOT_MODIFIED) {
                r->status = ret;
                return OK;
            }

            return ret;
        }

        location = apr_table_get(r->headers_out, "Location");

        if (location && r->status == 200) {
            /* For a redirect whether internal or not, discard any
             * remaining stdout from the script, and log any remaining
             * stderr output, as normal. */
            discard_script_output(bb);
            apr_brigade_destroy(bb);

            if (script_err) {
                apr_file_pipe_timeout_set(script_err, timeout);
                log_script_err(r, script_err);
            }
        }

        if (location && location[0] == '/' && r->status == 200) {
            /* This redirect needs to be a GET no matter what the original
             * method was.
             */
            r->method = "GET";
            r->method_number = M_GET;

            /* We already read the message body (if any), so don't allow
             * the redirected request to think it has one.  We can ignore
             * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
             */
            apr_table_unset(r->headers_in, "Content-Length");

            ap_internal_redirect_handler(location, r);
            return OK;
        }
        else if (location && r->status == 200) {
            /* XXX: Note that if a script wants to produce its own Redirect
             * body, it now has to explicitly *say* "Status: 302"
             */
            discard_script_output(bb);
            apr_brigade_destroy(bb);
            return HTTP_MOVED_TEMPORARILY;
        }

        rv = ap_pass_brigade(r->output_filters, bb);
    }
    else /* nph */ {
        struct ap_filter_t *cur;

        /* get rid of all filters up through protocol...  since we
         * haven't parsed off the headers, there is no way they can
         * work
         */

        cur = r->proto_output_filters;
        while (cur && cur->frec->ftype < AP_FTYPE_CONNECTION) {
            cur = cur->next;
        }
        r->output_filters = r->proto_output_filters = cur;

        rv = ap_pass_brigade(r->output_filters, bb);
    }

    /* don't soak up script output if errors occurred writing it
     * out...  otherwise, we prolong the life of the script when the
     * connection drops or we stopped sending output for some other
     * reason */
    if (script_err && rv == APR_SUCCESS && !r->connection->aborted) {
        apr_file_pipe_timeout_set(script_err, timeout);
        log_script_err(r, script_err);
    }

    if (script_err) apr_file_close(script_err);

    return OK;                      /* NOT r->status, even if it has changed. */
}

/* Read the request body and write it to fd 'script_out', using 'bb'
 * as temporary bucket brigade.  If 'logbuf' is non-NULL, the first
 * logbufbytes of stdout are stored in logbuf. */
static apr_status_t cgi_handle_request(request_rec *r, apr_file_t *script_out,
                                       apr_bucket_brigade *bb,
                                       char *logbuf, apr_size_t logbufbytes)
{
    int seen_eos = 0;
    int child_stopped_reading = 0;
    apr_status_t rv;
    int dbpos = 0;

    do {
        apr_bucket *bucket;

        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, HUGE_STRING_LEN);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        for (bucket = APR_BRIGADE_FIRST(bb);
             bucket != APR_BRIGADE_SENTINEL(bb);
             bucket = APR_BUCKET_NEXT(bucket))
        {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }

            /* We can't do much with this. */
            if (APR_BUCKET_IS_FLUSH(bucket)) {
                continue;
            }

            /* If the child stopped, we still must read to EOS. */
            if (child_stopped_reading) {
                continue;
            }

            /* read */
            rv = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
            if (rv) {
                return rv;
            }

            if (logbufbytes && dbpos < logbufbytes) {
                int cursize;

                if ((dbpos + len) > logbufbytes) {
                    cursize = logbufbytes - dbpos;
                }
                else {
                    cursize = len;
                }
                memcpy(logbuf + dbpos, data, cursize);
                dbpos += cursize;
            }

            /* Keep writing data to the child until done or too much time
             * elapses with no progress or an error occurs.
             */
            rv = apr_file_write_full(script_out, data, len, NULL);

            if (rv != APR_SUCCESS) {
                /* silly script stopped reading, soak up remaining message */
                child_stopped_reading = 1;
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02651)
                              "Error writing request body to script %s", 
                              r->filename);
            }
        }
        apr_brigade_cleanup(bb);
    }
    while (!seen_eos);

    if (logbuf) {
        logbuf[dbpos] = '\0';
    }

    return APR_SUCCESS;
}
