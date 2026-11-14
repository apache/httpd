/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

#include "httpd.h"
#include "http_request.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_pools.h"
#include "apr_file_io.h"
#include "util_script.h"
#include "fcgid_bridge.h"
#include "fcgid_pm.h"
#include "fcgid_proctbl.h"
#include "fcgid_proc.h"
#include "fcgid_conf.h"
#include "fcgid_spawn_ctl.h"
#include "fcgid_protocol.h"
#include "fcgid_bucket.h"
#define FCGID_APPLY_TRY_COUNT 2
#define FCGID_REQUEST_COUNT 32
#define FCGID_BRIGADE_CLEAN_STEP 32

static fcgid_procnode *apply_free_procnode(request_rec *r,
                                           fcgid_command * command)
{
    /* Scan idle list, find a node match inode, deviceid and groupid
       If there is no one there, return NULL */
    fcgid_procnode *previous_node, *current_node, *next_node;
    fcgid_procnode *busy_list_header, *proc_table;
    apr_ino_t inode = command->inode;
    apr_dev_t deviceid = command->deviceid;
    uid_t uid = command->uid;
    gid_t gid = command->gid;
    const char *cmdline = command->cmdline;

    proc_table = proctable_get_table_array();
    previous_node = proctable_get_idle_list();
    busy_list_header = proctable_get_busy_list();

    proctable_lock(r);
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];

        if (current_node->inode == inode
            && current_node->deviceid == deviceid
            && !strcmp(current_node->cmdline, cmdline)
            && current_node->vhost_id == command->vhost_id
            && current_node->uid == uid && current_node->gid == gid) {
            /* Unlink from idle list */
            previous_node->next_index = current_node->next_index;

            /* Link to busy list */
            current_node->next_index = busy_list_header->next_index;
            busy_list_header->next_index = current_node - proc_table;

            proctable_unlock(r);
            return current_node;
        }
        else
            previous_node = current_node;

        current_node = next_node;
    }
    proctable_unlock(r);

    /* Found nothing */
    return NULL;
}

static void
return_procnode(request_rec *r,
                fcgid_procnode *procnode, int communicate_error)
{
    fcgid_procnode *previous_node, *current_node, *next_node;
    fcgid_procnode *proc_table = proctable_get_table_array();
    fcgid_procnode *error_list_header = proctable_get_error_list();
    fcgid_procnode *idle_list_header = proctable_get_idle_list();
    fcgid_procnode *busy_list_header = proctable_get_busy_list();

    proctable_lock(r);

    /* Unlink the node from busy list first */
    previous_node = busy_list_header;
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];
        if (current_node == procnode) {
            /* Unlink from busy list */
            previous_node->next_index = current_node->next_index;
            break;
        }
        else
            previous_node = current_node;
        current_node = next_node;
    }

    /* Return to error list or idle list */
    if (communicate_error) {
        /* Link to error list */
        procnode->next_index = error_list_header->next_index;
        error_list_header->next_index = procnode - proc_table;
    }
    else {
        /* Link to idle list */
        procnode->next_index = idle_list_header->next_index;
        idle_list_header->next_index = procnode - proc_table;
    }

    proctable_unlock(r);
}

static int count_busy_processes(request_rec *r, fcgid_command *command)
{
    int result = 0;
    fcgid_procnode *previous_node, *current_node, *next_node;
    fcgid_procnode *proc_table = proctable_get_table_array();
    fcgid_procnode *busy_list_header = proctable_get_busy_list();

    proctable_lock(r);

    previous_node = busy_list_header;
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        if (current_node->inode == command->inode
            && current_node->deviceid == command->deviceid
            && !strcmp(current_node->cmdline, command->cmdline)
            && current_node->vhost_id == command->vhost_id
            && current_node->uid == command->uid
            && current_node->gid == command->gid) {
            result++;
        }
        next_node = &proc_table[current_node->next_index];
        current_node = next_node;
    }

    proctable_unlock(r);

    return result;
}

apr_status_t bucket_ctx_cleanup(void *thectx)
{
    /* Cleanup jobs:
       1. Free bucket buffer
       2. Return procnode
       NOTE: ipc will be clean when request pool cleanup, so I don't need to close it here
     */
    fcgid_bucket_ctx *ctx = (fcgid_bucket_ctx *) thectx;
    request_rec *r = ctx->ipc.request;

    /* Free bucket buffer */
    if (ctx->buffer) {
        apr_bucket_destroy(ctx->buffer);
        ctx->buffer = NULL;
    }

    /* proc_close_ipc() and ipc_handle_cleanup() do their own sanity
     * checks, but we'll do our own anyway
     */
    if (ctx->ipc.ipc_handle_info) {
        proc_close_ipc(&ctx->ipc);
        ctx->ipc.ipc_handle_info = NULL;
    }

    if (ctx->procnode) {
        ++ctx->procnode->requests_handled;

        /* Return procnode
           I will return this slot to idle(or error) list
         */
        if (ctx->procnode->diewhy == FCGID_DIE_BUSY_TIMEOUT) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_fcgid: %s took longer than busy timeout "
                          "(%d secs)",
                          r->uri,
                          ctx->procnode->cmdopts.busy_timeout);
            return_procnode(r, ctx->procnode, 1 /* busy timeout */ );
        }
        else if (ctx->has_error) {
            ctx->procnode->diewhy = FCGID_DIE_COMM_ERROR;
            return_procnode(r, ctx->procnode, 1 /* communication error */ );
        }
        else if (ctx->procnode->cmdopts.max_requests_per_process
                 && ctx->procnode->requests_handled >=
                 ctx->procnode->cmdopts.max_requests_per_process) {
            ctx->procnode->diewhy = FCGID_DIE_LIFETIME_EXPIRED;
            return_procnode(r, ctx->procnode, 1 /* handled all requests */ );
        }
        else
            return_procnode(r, ctx->procnode, 0 /* communication ok */ );

        ctx->procnode = NULL;
    }

    return APR_SUCCESS;
}

static int getsfunc_fcgid_BRIGADE(char *buf, int len, void *arg)
{
    apr_bucket_brigade *bb = (apr_bucket_brigade *) arg;
    const char *dst_end = buf + len - 1;        /* leave room for terminating null */
    char *dst = buf;
    apr_bucket *e = APR_BRIGADE_FIRST(bb);
    apr_status_t rv;
    int done = 0;
    int getLF = 0;
    int getColon = 0;

    while ((dst < dst_end) && !done && e != APR_BRIGADE_SENTINEL(bb)) {
        const char *bucket_data;
        apr_size_t bucket_data_len;
        const char *src;
        const char *src_end;
        apr_bucket *next;

        rv = apr_bucket_read(e, &bucket_data, &bucket_data_len,
                             APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            return 0;
        }

        /* Move on to next bucket if it's fastcgi header bucket */
        if (e->type == &ap_bucket_type_fcgid_header
            || e->type == &apr_bucket_type_immortal) {
            next = APR_BUCKET_NEXT(e);
            apr_bucket_delete(e);
            e = next;
            if (getLF) {
                done = 1;
            }
            continue;
        }

        if (bucket_data_len == 0)
            return 0;

        /* Base on RFC2616 section 4.2 */
        src = bucket_data;
        src_end = bucket_data + bucket_data_len;
        while ((src < src_end) && (dst < dst_end) && !done) {
            if (*src == ':')
                getColon = 1;

            if (getLF && ((*src != ' ' && *src != '\t') || !getColon)) {
                done = 1;
                getColon = 0;
                break;
            }
            else if (getLF && (*src == ' ' || *src == '\t')) {
                *dst++ = '\r';
                *dst++ = '\n';
                getLF = 0;
            }

            if (*src == '\n') {
                getLF = 1;
            }
            else if (*src != '\r') {
                *dst++ = *src;
            }
            src++;
        }

        if (src < src_end) {
            apr_bucket_split(e, src - bucket_data);
        }
        next = APR_BUCKET_NEXT(e);
        apr_bucket_delete(e);
        e = next;
    }
    *dst = 0;
    return done;
}

static int
handle_request_ipc(request_rec *r, int role,
                   apr_bucket_brigade *output_brigade,
                   fcgid_bucket_ctx *bucket_ctx, const char **location_ptr)
{
    int cond_status;
    apr_status_t rv;
    apr_bucket_brigade *brigade_stdout;
    char sbuf[MAX_STRING_LEN];
    const char *location;

    /* Write output_brigade to fastcgi server */
    if ((rv = proc_write_ipc(&bucket_ctx->ipc,
                             output_brigade)) != APR_SUCCESS) {
        bucket_ctx->has_error = 1;
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Create brigade */
    brigade_stdout =
        apr_brigade_create(r->pool, r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(brigade_stdout,
                            ap_bucket_fcgid_header_create(r->connection->
                                                          bucket_alloc,
                                                          bucket_ctx));

    /* Check the script header first; return immediately on error. */
    if ((cond_status =
         ap_scan_script_header_err_core(r, sbuf, getsfunc_fcgid_BRIGADE,
                                        brigade_stdout))) {
        /*
         * cond_status could be HTTP_NOT_MODIFIED in the case that the FCGI
         * script does not set an explicit status and ap_meets_conditions,
         * which is called by ap_scan_script_header_err_brigade, detects that
         * the conditions of the requests are met and the response is
         * not modified.
         * In this case set r->status and return OK in order to prevent
         * running through the error processing stack as this would
         * break with mod_cache, if the conditions had been set by
         * mod_cache itself to validate a stale entity.
         * BTW: We circumvent the error processing stack anyway if the
         * FCGI script set an explicit status code (whatever it is) and
         * the only possible values for cond_status here are:
         *
         * HTTP_NOT_MODIFIED          (set by ap_meets_conditions)
         * HTTP_PRECONDITION_FAILED   (set by ap_meets_conditions)
         * HTTP_GATEWAY_TIME_OUT      (script timed out, returned no headers)
         * HTTP_INTERNAL_SERVER_ERROR (if something went wrong during the
         * processing of the response of the FCGI script, e.g broken headers
         * or a crashed FCGI process).
         */
        if (cond_status == HTTP_NOT_MODIFIED) {
            /* We need to remove our fcgid_filter before returning this
             * status and code; otherwise, when ap_process_async_request()
             * invokes ap_finalize_request_protocol() and that calls
             * ap_pass_brigade(), fcgid_filter notices it has an empty
             * brigade and returns without calling ap_pass_brigade() itself,
             * which incorrectly circumvents the standard output filters.
             */
            ap_remove_output_filter(r->output_filters);

            r->status = cond_status;
            return OK;
        }

        return cond_status;
    }

    if (role == FCGI_AUTHORIZER) {
        return cond_status;
    }

    /* Check redirect */
    location = apr_table_get(r->headers_out, "Location");

    if (location && location[0] == '/' && r->status == 200) {
        /* This redirect needs to be a GET no matter what the original
         * method was.
         */
        r->method = apr_pstrdup(r->pool, "GET");
        r->method_number = M_GET;

        /* We already read the message body (if any), so don't allow
         * the redirected request to think it has one.  We can ignore
         * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
         */
        apr_table_unset(r->headers_in, "Content-Length");

        /* Setting this Location header value causes handle_request() to
         * invoke ap_internal_redirect_handler(); that calls
         * internal_internal_redirect() which sets the new sub-request's
         * r->output_filters back to r->proto_output_filters before
         * running the sub-request's handler.  Because we return here
         * without invoking ap_pass_brigade(), our fcgid_filter is ignored.
         */
        *location_ptr = location;
        return OK;
    }
    else if (location && r->status == 200) {
        /* XX Note that if a script wants to produce its own Redirect
         * body, it now has to explicitly *say* "Status: 302"
         */

        /* This return code causes ap_process_async_request() to invoke
         * ap_die(); that calls ap_send_error_response(), which resets
         * r->output_filters back to r->proto_output_filters, thus removing
         * our fcgid_filter from the output chain before making a final call
         * to ap_finalize_request_protocol(), which passes the brigade to
         * the standard output filters.
         */
        return HTTP_MOVED_TEMPORARILY;
    }

    /* Now pass any remaining response body data to output filters */
    if ((rv = ap_pass_brigade(r->output_filters,
                              brigade_stdout)) != APR_SUCCESS) {
        if (r->connection->aborted) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                      "mod_fcgid: ap_pass_brigade failed "
                      "(client aborted connection)");
            return OK;
        } 
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                      "mod_fcgid: ap_pass_brigade failed in "
                      "handle_request_ipc function");

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return cond_status;
}

static int
handle_request(request_rec * r, int role, fcgid_cmd_conf *cmd_conf,
               apr_bucket_brigade * output_brigade)
{
    fcgid_command fcgi_request;
    fcgid_bucket_ctx *bucket_ctx;
    int i, j, cond_status;
    const char *location = NULL;

    bucket_ctx = apr_pcalloc(r->pool, sizeof(*bucket_ctx));

    bucket_ctx->ipc.request = r;
    apr_pool_cleanup_register(r->pool, bucket_ctx,
                              bucket_ctx_cleanup, apr_pool_cleanup_null);
    procmgr_init_spawn_cmd(&fcgi_request, r, cmd_conf);

    /* Try to get a connected ipc handle */
    for (i = 0; i < FCGID_REQUEST_COUNT; i++) {
        /* Apply a free process slot, send a spawn request if I can't get one */
        for (j = 0; j < FCGID_APPLY_TRY_COUNT; j++) {
            bucket_ctx->ipc.connect_timeout =
                fcgi_request.cmdopts.ipc_connect_timeout;
            bucket_ctx->ipc.communation_timeout =
                fcgi_request.cmdopts.ipc_comm_timeout;

            /* Apply a process slot */
            bucket_ctx->procnode = apply_free_procnode(r, &fcgi_request);
            if (bucket_ctx->procnode)
                break;

            /* Avoid sleeping the very first time through if there are no
               busy processes; the problem is just that we haven't spawned
               anything yet, so waiting is pointless */
            if (i > 0 || j > 0 || count_busy_processes(r, &fcgi_request)) {
                apr_sleep(apr_time_from_sec(1));

                bucket_ctx->procnode = apply_free_procnode(r, &fcgi_request);
                if (bucket_ctx->procnode)
                    break;
            }

            /* Send a spawn request if I can't get a process slot */
            procmgr_send_spawn_cmd(&fcgi_request, r);
        }

        /* Connect to the fastcgi server */
        if (bucket_ctx->procnode) {
            if (proc_connect_ipc(bucket_ctx->procnode,
                                 &bucket_ctx->ipc) != APR_SUCCESS) {
                proc_close_ipc(&bucket_ctx->ipc);
                bucket_ctx->procnode->diewhy = FCGID_DIE_CONNECT_ERROR;
                return_procnode(r, bucket_ctx->procnode, 1 /* has error */ );
                bucket_ctx->procnode = NULL;
            }
            else
                break;
        }
    }

    /* Now I get a connected ipc handle */
    if (!bucket_ctx->procnode) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_fcgid: can't apply process slot for %s",
                      cmd_conf->cmdline);
        return HTTP_SERVICE_UNAVAILABLE;
    }
    bucket_ctx->active_time = bucket_ctx->procnode->last_active_time =
        apr_time_now();
    bucket_ctx->procnode->diewhy = FCGID_DIE_KILLSELF;

    cond_status = handle_request_ipc(r, role, output_brigade,
                                     bucket_ctx, &location);

    /* Release the process ASAP.  This may already have been done in
     * ap_pass_brigade() by fcgid_header_bucket_read(), but not in the
     * case where handle_request_ipc() returned early without reading
     * the body of the HTTP response.  This could be because of an error,
     * or because of a role or a status code which permits us to ignore
     * the message body.
     *
     * As an example, when handling a request in the FCGI_AUTHORIZER role,
     * we don't read through to the end of the response from the process,
     * we just read the HTTP headers.  That means each phase of the
     * request handling sequence (e.g., authentication, authorization, etc.)
     * will require its own process unless we make sure to always release
     * any process we acquired regardless of whether we're reading the
     * response body.
     *
     * As another example, if we perform or cause an internal redirection
     * (for instance, by returning an error code that invokes a script
     * handler in ap_die() because of an ErrorDocument configuration), then
     * we must also release the process we acquired here so that it is
     * potentially available during the next handling phase.
     */

    apr_pool_cleanup_run(r->pool, bucket_ctx, bucket_ctx_cleanup);

    /* Perform internal redirection if necessary */
    if (location) {
        ap_internal_redirect_handler(location, r);
    }

    /* Return condition status */
    return cond_status;
}

static int add_request_body(request_rec *r, apr_pool_t *request_pool,
                            apr_bucket_brigade *output_brigade,
                            apr_off_t *body_length)
{
    apr_bucket *bucket_input, *bucket_header;
    apr_file_t *fd = NULL;
    apr_off_t cur_pos = 0, request_size = 0;
    apr_status_t rv;
    FCGI_Header *stdin_request_header;
    fcgid_server_conf *sconf = ap_get_module_config(r->server->module_config,
                                                    &fcgid_module);
    int seen_eos = 0;

    /* Stdin header and body */
    /* I have to read all the request into memory before sending it
       to fastcgi application server, this prevents slow clients from
       keeping the server in processing too long.
       But sometimes it's not acceptable (think about uploading a large attachment)
       Request will be stored in tmp file if the size larger than max_mem_request_len
     */

    apr_bucket_brigade *input_brigade = apr_brigade_create(request_pool,
                                                           r->connection->
                                                           bucket_alloc);
    apr_bucket_brigade *tmp_brigade = apr_brigade_create(request_pool,
                                                           r->connection->
                                                           bucket_alloc);

    do {
        int loop_counter = 0;

        if ((rv = ap_get_brigade(r->input_filters, input_brigade,
                                 AP_MODE_READBYTES,
                                 APR_BLOCK_READ,
                                 HUGE_STRING_LEN)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                          "mod_fcgid: can't get data from http client");
            apr_brigade_destroy(output_brigade);
            apr_brigade_destroy(tmp_brigade);
            apr_brigade_destroy(input_brigade);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

	

        while ((bucket_input = APR_BRIGADE_FIRST(input_brigade)) != APR_BRIGADE_SENTINEL(input_brigade)) {
            const char *data;
            apr_size_t len;
            apr_bucket *bucket_stdin;

            ++loop_counter;
            if ((loop_counter % FCGID_BRIGADE_CLEAN_STEP) == 0) {
                apr_brigade_cleanup(tmp_brigade);
            }
            APR_BUCKET_REMOVE(bucket_input);
            APR_BRIGADE_INSERT_TAIL(tmp_brigade, bucket_input);

            if (APR_BUCKET_IS_EOS(bucket_input)) {
                seen_eos = 1;
                break;
            }

            if (APR_BUCKET_IS_METADATA(bucket_input))
                continue;

            if ((rv = apr_bucket_read(bucket_input, &data, &len,
                                      APR_BLOCK_READ)) != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                              "mod_fcgid: can't read request from HTTP client");
                apr_brigade_destroy(input_brigade);
                apr_brigade_destroy(tmp_brigade);
                apr_brigade_destroy(output_brigade);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            /* Append a header, and the the bucket */
            stdin_request_header = apr_bucket_alloc(sizeof(FCGI_Header),
                                                    r->connection->
                                                    bucket_alloc);
            bucket_header =
                apr_bucket_heap_create((const char *) stdin_request_header,
                                       sizeof(*stdin_request_header),
                                       apr_bucket_free,
                                       r->connection->bucket_alloc);

            request_size += len;
            if (request_size > sconf->max_request_len) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              "mod_fcgid: HTTP request length %" APR_OFF_T_FMT
                              " (so far) exceeds MaxRequestLen (%"
                              APR_OFF_T_FMT ")", request_size,
                              sconf->max_request_len);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            if (request_size > sconf->max_mem_request_len) {
                apr_size_t wrote_len;
                static const char *fd_key = "fcgid_fd";

                if (fd == NULL) {
                    void *tmp;
                    apr_pool_userdata_get(&tmp, fd_key, r->connection->pool);
                    fd = tmp;

                    if (fd != NULL) {
                        if ((rv = apr_file_trunc(fd, 0)) != APR_SUCCESS) {
                            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                                          "mod_fcgid: can't truncate existing "
                                          "temporary file");
                            return HTTP_INTERNAL_SERVER_ERROR;
                        }
                    }
                }

                if (fd == NULL) {
                    const char *tempdir = NULL;
                    char *template;

                    rv = apr_temp_dir_get(&tempdir, r->pool);
                    if (rv != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                                      "mod_fcgid: can't get tmp dir");
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }

                    apr_filepath_merge(&template, tempdir,
                                       "fcgid.tmp.XXXXXX",
                                       APR_FILEPATH_NATIVE, r->pool);
                    rv = apr_file_mktemp(&fd, template, 0,
                                         r->connection->pool);
                    if (rv != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                                      "mod_fcgid: can't open tmp file fot stdin request");
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                    apr_pool_userdata_set((const void *) fd, fd_key,
                                          apr_pool_cleanup_null,
                                          r->connection->pool);
                }

                /* Write request to tmp file */
                if ((rv =
                     apr_file_write_full(fd, (const void *) data, len,
                                         &wrote_len)) != APR_SUCCESS
                    || len != wrote_len) {
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING,
                                  rv, r,
                                  "mod_fcgid: can't write tmp file for stdin request");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                /* Create file bucket */
                bucket_stdin =
                    apr_bucket_file_create(fd, cur_pos, len, r->pool,
                                           r->connection->bucket_alloc);
                cur_pos += len;
            }
            else {
                if (APR_BUCKET_IS_HEAP(bucket_input))
                    apr_bucket_copy(bucket_input, &bucket_stdin);
                else {
                    /* mod_ssl have a bug? */
                    char *pcopydata =
                        apr_bucket_alloc(len, r->connection->bucket_alloc);
                    memcpy(pcopydata, data, len);
                    bucket_stdin =
                        apr_bucket_heap_create(pcopydata, len,
                                               apr_bucket_free,
                                               r->connection->bucket_alloc);
                }
            }

            if (!init_header(FCGI_STDIN, 1, len, 0, stdin_request_header)) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              "mod_fcgid: header overflow");
                apr_brigade_destroy(input_brigade);
                apr_brigade_destroy(tmp_brigade);
                apr_brigade_destroy(output_brigade);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            APR_BRIGADE_INSERT_TAIL(output_brigade, bucket_header);
            APR_BRIGADE_INSERT_TAIL(output_brigade, bucket_stdin);
        }

        apr_brigade_cleanup(input_brigade);
        apr_brigade_cleanup(tmp_brigade);
    }
    while (!seen_eos);

    apr_brigade_destroy(input_brigade);
    apr_brigade_destroy(tmp_brigade);

    /* Append an empty body stdin header */
    stdin_request_header = apr_bucket_alloc(sizeof(FCGI_Header),
                                            r->connection->bucket_alloc);
    bucket_header =
        apr_bucket_heap_create((const char *) stdin_request_header,
                               sizeof(*stdin_request_header),
                               apr_bucket_free, r->connection->bucket_alloc);
    if (!init_header(FCGI_STDIN, 1, 0, 0, stdin_request_header)) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_fcgid: header overflow");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    APR_BRIGADE_INSERT_TAIL(output_brigade, bucket_header);

    *body_length = request_size;
    
    return 0;
}

int bridge_request(request_rec * r, int role, fcgid_cmd_conf *cmd_conf)
{
    apr_bucket_brigade *output_brigade, *body_brigade;
    apr_bucket *bucket_eos;
    char **envp;
    int rc;

    /* Create brigade for the request to fastcgi server */
    body_brigade
        = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    output_brigade =
        apr_brigade_create(r->pool, r->connection->bucket_alloc);

    /* In responder mode, handle the request body up front to ensure
     * the content-length is known (even if the request body is
     * chunked) and sent in the header. */
    if (role == FCGI_RESPONDER) {
        apr_off_t body_length;
        
        rc = add_request_body(r, r->pool, body_brigade, &body_length);
        if (rc) {
            return rc;
        }

        if (body_length && !apr_table_get(r->headers_in, "Content-Length")) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "mod_fcgid: dechunked request body length %" APR_OFF_T_FMT,
                          body_length);
        
            apr_table_set(r->subprocess_env, "CONTENT_LENGTH",
                          apr_off_t_toa(r->pool, body_length));
            apr_table_unset(r->subprocess_env, "HTTP_TRANSFER_ENCODING");
        }
    }

    envp = ap_create_environment(r->pool, r->subprocess_env);
          
    /* Build the begin request and environ request, add them to output_brigade */
    if (!build_begin_block
        (role, r, r->connection->bucket_alloc, output_brigade)
        || !build_env_block(r, envp, r->connection->bucket_alloc,
                            output_brigade)) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_fcgid: can't build begin or env request");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Append the body output. */
    APR_BRIGADE_CONCAT(output_brigade, body_brigade);

    /* The eos bucket now */
    bucket_eos = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(output_brigade, bucket_eos);

    /* Bridge the request */
    return handle_request(r, role, cmd_conf, output_brigade);
}
