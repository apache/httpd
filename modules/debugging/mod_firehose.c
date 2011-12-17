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
 * Originally written @ Covalent by Jim Jagielski
 * Modified to support writing to non blocking pipes @ BBC by Graham Leggett
 * Modifications (C) 2011 British Broadcasting Corporation
 */

/*
 * mod_firehose.c:
 *  A request and response sniffer for Apache v2.x. It logs
 *  all filter data right before and after it goes out on the
 *  wire (BUT right before SSL encoded or after SSL decoded).
 *  It can produce a *huge* amount of data.
 */

#include "httpd.h"
#include "http_connection.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "util_ebcdic.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_uuid.h"
#include "mod_proxy.h"

#if APR_HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif
#if APR_HAVE_LINUX_LIMITS_H
#include <linux/limits.h>
#endif
#if APR_HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

module AP_MODULE_DECLARE_DATA firehose_module;

typedef enum proxy_enum
{
    FIREHOSE_PROXY, FIREHOSE_NORMAL
} proxy_enum;

typedef enum request_enum
{
    FIREHOSE_CONNECTION, FIREHOSE_REQUEST
} request_enum;

typedef enum direction_enum
{
    FIREHOSE_IN = '<', FIREHOSE_OUT = '>'
} direction_enum;

typedef struct firehose_conn_t
{
    const char *filename;
    apr_file_t *file;
    proxy_enum proxy;
    direction_enum direction;
    request_enum request;
    int suppress;
} firehose_conn_t;

typedef struct firehose_conf_t
{
    apr_array_header_t *firehoses;
} firehose_conf_t;

typedef struct firehose_ctx_t
{
    firehose_conf_t *conf;
    firehose_conn_t *conn;
    apr_bucket_brigade *bb;
    apr_bucket_brigade *tmp;
    char uuid[APR_UUID_FORMATTED_LENGTH + 1];
    apr_uint64_t count;
    int direction;
    conn_rec *c;
    request_rec *r;
    ap_filter_t *f;
} firehose_ctx_t;

#define HEADER_LEN (sizeof(apr_uint64_t)*6 + APR_UUID_FORMATTED_LENGTH + 7)
#define BODY_LEN (PIPE_BUF - HEADER_LEN - 2)
#define HEADER_FMT "%" APR_UINT64_T_HEX_FMT " %" APR_UINT64_T_HEX_FMT " %c %s %" APR_UINT64_T_HEX_FMT CRLF

apr_status_t logs_cleanup(void *dummy)
{
    apr_file_t *file = (apr_file_t *) dummy;
    apr_file_close(file);
    return APR_SUCCESS;
}

apr_status_t filter_output_cleanup(void *dummy)
{
    ap_filter_t *f = (ap_filter_t *) dummy;
    ap_remove_output_filter(f);
    return APR_SUCCESS;
}

apr_status_t filter_input_cleanup(void *dummy)
{
    ap_filter_t *f = (ap_filter_t *) dummy;
    ap_remove_input_filter(f);
    return APR_SUCCESS;
}

/**
 * Add the terminating empty fragment to indicate end-of-connection.
 */
apr_status_t pumpit_cleanup(void *dummy)
{
    firehose_ctx_t *ctx = (firehose_ctx_t *) dummy;
    apr_status_t rv;
    apr_size_t hdr_len;
    char header[HEADER_LEN + 1];
    apr_size_t bytes;

    if (!ctx->count) {
        return APR_SUCCESS;
    }

    hdr_len = apr_snprintf(header, sizeof(header), HEADER_FMT,
            (apr_uint64_t) 0, (apr_uint64_t) apr_time_now(), ctx->direction,
            ctx->uuid, ctx->count);
    ap_xlate_proto_to_ascii(header, hdr_len);

    rv = apr_file_write_full(ctx->conn->file, header, hdr_len, &bytes);
    if (APR_SUCCESS != rv) {
        if (ctx->conn->suppress) {
            /* ignore the error */
        }
        else if (ctx->r) {
            ap_log_rerror(
                    APLOG_MARK,
                    APLOG_WARNING,
                    rv,
                    ctx->r,
                    "mod_firehose: could not write %" APR_UINT64_T_FMT " bytes to '%s' for '%c' connection '%s' and count '%0" APR_UINT64_T_HEX_FMT "', bytes dropped (further errors will be suppressed)",
                    (apr_uint64_t)(hdr_len), ctx->conn->filename, ctx->conn->direction, ctx->uuid, ctx->count);
        }
        else {
            ap_log_cerror(
                    APLOG_MARK,
                    APLOG_WARNING,
                    rv,
                    ctx->c,
                    "mod_firehose: could not write %" APR_UINT64_T_FMT " bytes to '%s' for '%c' connection '%s' and count '%0" APR_UINT64_T_HEX_FMT "', bytes dropped (further errors will be suppressed)",
                    (apr_uint64_t)(hdr_len), ctx->conn->filename, ctx->conn->direction, ctx->uuid, ctx->count);
        }
        ctx->conn->suppress = 1;
    }
    else {
        ctx->conn->suppress = 0;
    }

    ctx->count = 0;

    return APR_SUCCESS;
}

/*
 * Pump the bucket contents to the pipe.
 *
 * Writes smaller than PIPE_BUF are guaranteed to be atomic when written to
 * pipes. As a result, we break the buckets into packets smaller than PIPE_BUF and
 * send each one in turn.
 *
 * Each packet is marked with the UUID of the connection so that the process that
 * reassembles the packets can put the right packets in the right order.
 *
 * Each packet is numbered with an incrementing counter. If a packet cannot be
 * written we drop the packet on the floor, and the counter will enable dropped
 * packets to be detected.
 */
static apr_status_t pumpit(ap_filter_t *f, apr_bucket *b, firehose_ctx_t *ctx)
{
    apr_status_t rv = APR_SUCCESS;

    if (!(APR_BUCKET_IS_METADATA(b))) {
        const char *buf;
        apr_size_t nbytes, offset = 0;

        rv = apr_bucket_read(b, &buf, &nbytes, APR_BLOCK_READ);

        if (rv == APR_SUCCESS) {
            while (nbytes > 0) {
                char header[HEADER_LEN + 1];
                apr_size_t hdr_len;
                apr_size_t body_len = nbytes < BODY_LEN ? nbytes : BODY_LEN;
                apr_size_t bytes;
                struct iovec vec[3];

                /*
                 * Insert the chunk header, specifying the number of bytes in
                 * the chunk.
                 */
                hdr_len = apr_snprintf(header, sizeof(header), HEADER_FMT,
                        (apr_uint64_t) body_len, (apr_uint64_t) apr_time_now(),
                        ctx->direction, ctx->uuid, ctx->count);
                ap_xlate_proto_to_ascii(header, hdr_len);

                vec[0].iov_base = header;
                vec[0].iov_len = hdr_len;
                vec[1].iov_base = (void *) (buf + offset);
                vec[1].iov_len = body_len;
                vec[2].iov_base = CRLF;
                vec[2].iov_len = 2;

                rv = apr_file_writev_full(ctx->conn->file, vec, 3, &bytes);
                if (APR_SUCCESS != rv) {
                    if (ctx->conn->suppress) {
                        /* ignore the error */
                    }
                    else if (ctx->r) {
                        ap_log_rerror(
                                APLOG_MARK,
                                APLOG_WARNING,
                                rv,
                                ctx->r,
                                "mod_firehose: could not write %" APR_UINT64_T_FMT " bytes to '%s' for '%c' connection '%s' and count '%0" APR_UINT64_T_HEX_FMT "', bytes dropped (further errors will be suppressed)",
                                (apr_uint64_t)(vec[0].iov_len + vec[1].iov_len + vec[2].iov_len), ctx->conn->filename, ctx->conn->direction, ctx->uuid, ctx->count);
                    }
                    else {
                        ap_log_cerror(
                                APLOG_MARK,
                                APLOG_WARNING,
                                rv,
                                ctx->c,
                                "mod_firehose: could not write %" APR_UINT64_T_FMT " bytes to '%s' for '%c' connection '%s' and count '%0" APR_UINT64_T_HEX_FMT "', bytes dropped (further errors will be suppressed)",
                                (apr_uint64_t)(vec[0].iov_len + vec[1].iov_len + vec[2].iov_len), ctx->conn->filename, ctx->conn->direction, ctx->uuid, ctx->count);
                    }
                    ctx->conn->suppress = 1;
                    rv = APR_SUCCESS;
                }
                else {
                    ctx->conn->suppress = 0;
                }

                ctx->count++;
                nbytes -= vec[1].iov_len;
                offset += vec[1].iov_len;
            }
        }

    }
    return rv;
}

static int firehose_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
        ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_bucket *b;
    apr_status_t rv;
    firehose_ctx_t *ctx = f->ctx;

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    rv = ap_get_brigade(f->next, bb, mode, block, readbytes);

    /* if an error was received, bail out now. If the error is
     * EAGAIN and we have not yet seen an EOS, we will definitely
     * be called again, at which point we will send our buffered
     * data. Instead of sending EAGAIN, some filters return an
     * empty brigade instead when data is not yet available. In
     * this case, pass through the APR_SUCCESS and emulate the
     * underlying filter.
     */
    if (rv != APR_SUCCESS || APR_BRIGADE_EMPTY(bb)) {
        return rv;
    }

    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b
            = APR_BUCKET_NEXT(b)) {
        rv = pumpit(f, b, ctx);
        if (APR_SUCCESS != rv) {
            return rv;
        }
    }

    return APR_SUCCESS;
}

static int firehose_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    apr_status_t rv = APR_SUCCESS;
    firehose_ctx_t *ctx = f->ctx;

    while (APR_SUCCESS == rv && !APR_BRIGADE_EMPTY(bb)) {

        b = APR_BRIGADE_FIRST(bb);

        rv = pumpit(f, b, ctx);
        if (APR_SUCCESS != rv) {
            return rv;
        }

        /* pass each bucket down */
        APR_BUCKET_REMOVE(b);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, b);

        /*
         * If we ever see an EOS, make sure to FLUSH.
         */
        if (APR_BUCKET_IS_EOS(b)) {
            apr_bucket *flush = apr_bucket_flush_create(f->c->bucket_alloc);
            APR_BUCKET_INSERT_BEFORE(b, flush);
        }

        rv = ap_pass_brigade(f->next, ctx->bb);

    }

    return rv;
}

/**
 * Create a firehose for each main request.
 */
static int firehose_create_request(request_rec *r)
{
    firehose_conf_t *conf;
    firehose_ctx_t *ctx;
    apr_uuid_t uuid;
    int set = 0;
    ap_filter_t *f;

    if (r->main) {
        return DECLINED;
    }

    conf = ap_get_module_config(r->connection->base_server->module_config,
            &firehose_module);

    f = r->connection->input_filters;
    while (f) {
        if (f->frec->filter_func.in_func == &firehose_input_filter) {
            ctx = (firehose_ctx_t *) f->ctx;
            if (ctx->conn->request == FIREHOSE_REQUEST) {
                pumpit_cleanup(ctx);
                if (!set) {
                    apr_uuid_get(&uuid);
                    set = 1;
                }
                apr_uuid_format(ctx->uuid, &uuid);
            }
        }
        f = f->next;
    }

    f = r->connection->output_filters;
    while (f) {
        if (f->frec->filter_func.out_func == &firehose_output_filter) {
            ctx = (firehose_ctx_t *) f->ctx;
            if (ctx->conn->request == FIREHOSE_REQUEST) {
                pumpit_cleanup(ctx);
                if (!set) {
                    apr_uuid_get(&uuid);
                    set = 1;
                }
                apr_uuid_format(ctx->uuid, &uuid);
            }
        }
        f = f->next;
    }

    return OK;
}

/* TODO: Make sure the connection directives are enforced global only.
 *
 * TODO: An idea for configuration. Let the filename directives be per-directory,
 * with a global hashtable of filename to filehandle mappings. As each directive
 * is parsed, a file is opened at server start. By default, all input is buffered
 * until the header_parser hook, at which point we check if we should be buffering
 * at all. If not, we dump the buffer and remove the filter. If so, we start
 * attempting to write the buffer to the file.
 *
 * TODO: Implement a buffer to allow firehose fragment writes to back up to some
 * threshold before packets are dropped. Flush the buffer on cleanup, waiting a
 * suitable amount of time for the downstream to catch up.
 *
 * TODO: For the request firehose, have an option to set aside request buckets
 * until we decide whether we're going to record this request or not. Allows for
 * targeted firehose by URL space.
 *
 * TODO: Potentially decide on firehose sending based on a variable in the notes
 * table or subprocess_env. Use standard httpd SetEnvIf and friends to decide on
 * whether to include the request or not. Using this, we can react to the value
 * of a flagpole. Run this check in the header_parser hook.
 */

static int firehose_pre_conn(conn_rec *c, void *csd)
{
    firehose_conf_t *conf;
    firehose_ctx_t *ctx;
    apr_uuid_t uuid;
    int i;
    firehose_conn_t *conn;

    conf = ap_get_module_config(c->base_server->module_config,
            &firehose_module);

    if (conf->firehoses->nelts) {
        apr_uuid_get(&uuid);
    }

    conn = (firehose_conn_t *) conf->firehoses->elts;
    for (i = 0; i < conf->firehoses->nelts; i++) {

        if (!conn->file || (conn->proxy == FIREHOSE_NORMAL
                && !c->sbh) || (conn->proxy == FIREHOSE_PROXY && c->sbh)) {
            conn++;
            continue;
        }

        ctx = apr_pcalloc(c->pool, sizeof(firehose_ctx_t));
        apr_uuid_format(ctx->uuid, &uuid);
        ctx->conf = conf;
        ctx->conn = conn;
        ctx->bb = apr_brigade_create(c->pool, c->bucket_alloc);
        ctx->c = c;
        apr_pool_cleanup_register(c->pool, ctx, pumpit_cleanup, pumpit_cleanup);
        if (conn->direction == FIREHOSE_IN) {
            ctx->direction = conn->proxy == FIREHOSE_PROXY ? '>' : '<';
            ctx->f = ap_add_input_filter("FIREHOSE_IN", ctx, NULL, c);
            apr_pool_cleanup_register(c->pool, ctx->f, filter_input_cleanup,
                    filter_input_cleanup);
        }
        if (conn->direction == FIREHOSE_OUT) {
            ctx->direction = conn->proxy == FIREHOSE_PROXY ? '<' : '>';
            ctx->f = ap_add_output_filter("FIREHOSE_OUT", ctx, NULL, c);
            apr_pool_cleanup_register(c->pool, ctx->f, filter_output_cleanup,
                    filter_output_cleanup);
        }

        conn++;
    }

    return OK;
}

static int firehose_open_logs(apr_pool_t *p, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s)
{
    firehose_conf_t *conf;
    apr_status_t rv;
    void *data;
    int i;
    firehose_conn_t *conn;

    /* make sure we only open the files on the second pass for config */
    apr_pool_userdata_get(&data, "mod_firehose", s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *) 1, "mod_firehose",
                apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    while (s) {

        conf = ap_get_module_config(s->module_config,
                &firehose_module);

        conn = (firehose_conn_t *) conf->firehoses->elts;
        for (i = 0; i < conf->firehoses->nelts; i++) {
            /* TODO: make this non blocking behaviour optional, as APR doesn't yet
             * support non blocking opening of files.
             * TODO: make this properly portable.
             */
            apr_os_file_t file = open(conn->filename, O_WRONLY
                    | O_CREAT | O_APPEND | O_NONBLOCK, 0777);
            if (file < 0) {
                rv = APR_FROM_OS_ERROR(apr_get_os_error());
                ap_log_error(APLOG_MARK,
                        APLOG_WARNING,
                        rv, s, "mod_firehose: could not open '%s' for write, disabling firehose %s%s %s filter",
                        conn->filename, conn->proxy == FIREHOSE_PROXY ? "proxy " : "",
                        conn->request == FIREHOSE_REQUEST ? " request" : "connection",
                        conn->direction == FIREHOSE_IN ? "input" : "output");
            }
            else if (APR_SUCCESS != (rv = apr_os_file_put(
                    &conn->file, &file, APR_FOPEN_WRITE
                            | APR_FOPEN_CREATE | APR_FOPEN_APPEND, plog))) {
                close(file);
                ap_log_error(APLOG_MARK,
                        APLOG_WARNING,
                        rv, s, "mod_firehose: could not open '%s' for write, disabling firehose %s%s %s filter",
                        conn->filename, conn->proxy == FIREHOSE_PROXY ? "proxy " : "",
                        conn->request == FIREHOSE_REQUEST ? " request" : "connection",
                        conn->direction == FIREHOSE_IN ? "input" : "output");
            }
            else {
                apr_pool_cleanup_register(plog, conn->file,
                        logs_cleanup, logs_cleanup);
            }
            conn++;
        }

        s = s->next;
    }

    return OK;
}

static void firehose_register_hooks(apr_pool_t *p)
{
    /*
     * We know that SSL is CONNECTION + 5
     */
    ap_register_output_filter("FIREHOSE_OUT", firehose_output_filter, NULL,
            AP_FTYPE_CONNECTION + 3);

    ap_register_input_filter("FIREHOSE_IN", firehose_input_filter, NULL,
            AP_FTYPE_CONNECTION + 3);

    ap_hook_open_logs(firehose_open_logs, NULL, NULL, APR_HOOK_LAST);
    ap_hook_pre_connection(firehose_pre_conn, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_create_request(firehose_create_request, NULL, NULL,
            APR_HOOK_REALLY_LAST + 1);
}

static void *firehose_create_sconfig(apr_pool_t *p, server_rec *s)
{
    firehose_conf_t *ptr = apr_pcalloc(p, sizeof(firehose_conf_t));

    ptr->firehoses = apr_array_make(p, 2, sizeof(firehose_conn_t));

    return ptr;
}

static void *firehose_merge_sconfig(apr_pool_t *p, void *basev,
        void *overridesv)
{
    firehose_conf_t *cconf = apr_pcalloc(p, sizeof(firehose_conf_t));
    firehose_conf_t *base = (firehose_conf_t *) basev;
    firehose_conf_t *overrides = (firehose_conf_t *) overridesv;

    cconf->firehoses = apr_array_append(p, overrides->firehoses,
            base->firehoses);

    return cconf;
}

static void firehose_enable_connection(cmd_parms *cmd, const char *name,
        proxy_enum proxy, direction_enum direction, request_enum request)
{

    firehose_conn_t *firehose;
    firehose_conf_t
            *ptr =
                    (firehose_conf_t *) ap_get_module_config(cmd->server->module_config,
                            &firehose_module);

    firehose = apr_array_push(ptr->firehoses);

    firehose->filename = name;
    firehose->proxy = proxy;
    firehose->direction = direction;
    firehose->request = request;

}

static const char *firehose_enable_connection_input(cmd_parms *cmd,
        void *dummy, const char *name)
{

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE
            | NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    firehose_enable_connection(cmd, name, FIREHOSE_NORMAL, FIREHOSE_IN,
            FIREHOSE_CONNECTION);

    return NULL;
}

static const char *firehose_enable_connection_output(cmd_parms *cmd,
        void *dummy, const char *name)
{

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE
            | NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    firehose_enable_connection(cmd, name, FIREHOSE_NORMAL, FIREHOSE_OUT,
            FIREHOSE_CONNECTION);

    return NULL;
}

static const char *firehose_enable_request_input(cmd_parms *cmd, void *dummy,
        const char *name)
{

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE
            | NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    firehose_enable_connection(cmd, name, FIREHOSE_NORMAL, FIREHOSE_IN,
            FIREHOSE_REQUEST);

    return NULL;
}

static const char *firehose_enable_request_output(cmd_parms *cmd, void *dummy,
        const char *name)
{

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE
            | NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    firehose_enable_connection(cmd, name, FIREHOSE_NORMAL, FIREHOSE_OUT,
            FIREHOSE_REQUEST);

    return NULL;
}

static const char *firehose_enable_proxy_connection_input(cmd_parms *cmd,
        void *dummy, const char *name)
{

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE
            | NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    firehose_enable_connection(cmd, name, FIREHOSE_PROXY, FIREHOSE_IN,
            FIREHOSE_CONNECTION);

    return NULL;
}

static const char *firehose_enable_proxy_connection_output(cmd_parms *cmd,
        void *dummy, const char *name)
{

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE
            | NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    firehose_enable_connection(cmd, name, FIREHOSE_PROXY, FIREHOSE_OUT,
            FIREHOSE_CONNECTION);

    return NULL;
}

static const command_rec firehose_cmds[] =
{
        AP_INIT_TAKE1("FirehoseConnectionInput", firehose_enable_connection_input, NULL,
                RSRC_CONF, "Enable firehose on connection input data written to the given file/pipe"),
        AP_INIT_TAKE1("FirehoseConnectionOutput", firehose_enable_connection_output, NULL,
                RSRC_CONF, "Enable firehose on connection output data written to the given file/pipe"),
        AP_INIT_TAKE1("FirehoseRequestInput", firehose_enable_request_input, NULL,
                RSRC_CONF, "Enable firehose on request input data written to the given file/pipe"),
        AP_INIT_TAKE1("FirehoseRequestOutput", firehose_enable_request_output, NULL,
                RSRC_CONF, "Enable firehose on request output data written to the given file/pipe"),
        AP_INIT_TAKE1("FirehoseProxyConnectionInput", firehose_enable_proxy_connection_input, NULL,
                RSRC_CONF, "Enable firehose on proxied connection input data written to the given file/pipe"),
        AP_INIT_TAKE1("FirehoseProxyConnectionOutput", firehose_enable_proxy_connection_output, NULL,
                RSRC_CONF, "Enable firehose on proxied connection output data written to the given file/pipe"),
        { NULL }
};

AP_DECLARE_MODULE(firehose) =
{
        STANDARD20_MODULE_STUFF,
        NULL,
        NULL,
        firehose_create_sconfig,
        firehose_merge_sconfig,
        firehose_cmds,
        firehose_register_hooks
};
