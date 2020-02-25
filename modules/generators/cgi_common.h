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

        if ((ret = ap_scan_script_header_err_brigade_ex(r, bb, sbuf,
                                                        APLOG_MODULE_INDEX)))
        {
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
