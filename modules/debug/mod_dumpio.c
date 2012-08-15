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
 */

/*
 * mod_dumpio.c:
 *  Think of this as a filter sniffer for Apache 2.x. It logs
 *  all filter data right before and after it goes out on the
 *  wire (BUT right before SSL encoded or after SSL decoded).
 *  It can produce a *huge* amount of data.
 */


#include "httpd.h"
#include "http_connection.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

module AP_MODULE_DECLARE_DATA dumpio_module ;

typedef struct dumpio_conf_t {
    int enable_input;
    int enable_output;
    int loglevel;
} dumpio_conf_t;

/*
 * Workhorse function: simply log to the current error_log
 * info about the data in the bucket as well as the data itself
 */
static void dumpit(ap_filter_t *f, apr_bucket *b)
{
    conn_rec *c = f->c;
    dumpio_conf_t *ptr =
    (dumpio_conf_t *) ap_get_module_config(c->base_server->module_config,
                                           &dumpio_module);

    ap_log_error(APLOG_MARK, ptr->loglevel, 0, c->base_server,
        "mod_dumpio:  %s (%s-%s): %" APR_SIZE_T_FMT " bytes",
                f->frec->name,
                (APR_BUCKET_IS_METADATA(b)) ? "metadata" : "data",
                b->type->name,
                b->length) ;

    if (!(APR_BUCKET_IS_METADATA(b))) {
        const char *buf;
        apr_size_t nbytes;
        char *obuf;
        if (apr_bucket_read(b, &buf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
            if (nbytes) {
                obuf = malloc(nbytes+1);    /* use pool? */
                memcpy(obuf, buf, nbytes);
#if APR_CHARSET_EBCDIC
                ap_xlate_proto_from_ascii(obuf, nbytes);
#endif
                obuf[nbytes] = '\0';
                ap_log_error(APLOG_MARK, ptr->loglevel, 0, c->base_server,
                     "mod_dumpio:  %s (%s-%s): %s",
                     f->frec->name,
                     (APR_BUCKET_IS_METADATA(b)) ? "metadata" : "data",
                     b->type->name,
                     obuf);
                free(obuf);
            }
        } else {
            ap_log_error(APLOG_MARK, ptr->loglevel, 0, c->base_server,
                 "mod_dumpio:  %s (%s-%s): %s",
                 f->frec->name,
                 (APR_BUCKET_IS_METADATA(b)) ? "metadata" : "data",
                 b->type->name,
                 "error reading data");
        }
    }
}

#define whichmode( mode ) \
 ( (( mode ) == AP_MODE_READBYTES) ? "readbytes" : \
   (( mode ) == AP_MODE_GETLINE) ? "getline" : \
   (( mode ) == AP_MODE_EATCRLF) ? "eatcrlf" : \
   (( mode ) == AP_MODE_SPECULATIVE) ? "speculative" : \
   (( mode ) == AP_MODE_EXHAUSTIVE) ? "exhaustive" : \
   (( mode ) == AP_MODE_INIT) ? "init" : "unknown" \
 )

static int dumpio_input_filter (ap_filter_t *f, apr_bucket_brigade *bb,
    ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{

    apr_bucket *b;
    apr_status_t ret;
    conn_rec *c = f->c;
    dumpio_conf_t *ptr =
    (dumpio_conf_t *) ap_get_module_config(c->base_server->module_config,
                                           &dumpio_module);

    ap_log_error(APLOG_MARK, ptr->loglevel, 0, c->base_server,
        "mod_dumpio: %s [%s-%s] %" APR_OFF_T_FMT " readbytes",
         f->frec->name,
         whichmode(mode),
         ((block) == APR_BLOCK_READ) ? "blocking" : "nonblocking",
         readbytes) ;

    ret = ap_get_brigade(f->next, bb, mode, block, readbytes);

    if (ret == APR_SUCCESS) {
        for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
          dumpit(f, b);
        }
    } else {
        ap_log_error(APLOG_MARK, ptr->loglevel, 0, c->base_server,
        "mod_dumpio: %s - %d", f->frec->name, ret) ;
        return ret;
    }

    return APR_SUCCESS ;
}

static int dumpio_output_filter (ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    conn_rec *c = f->c;
    dumpio_conf_t *ptr =
    (dumpio_conf_t *) ap_get_module_config(c->base_server->module_config,
                                           &dumpio_module);

    ap_log_error(APLOG_MARK, ptr->loglevel, 0, c->base_server, "mod_dumpio: %s", f->frec->name) ;

    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
        /*
         * If we ever see an EOS, make sure to FLUSH.
         */
        if (APR_BUCKET_IS_EOS(b)) {
            apr_bucket *flush = apr_bucket_flush_create(f->c->bucket_alloc);
            APR_BUCKET_INSERT_BEFORE(b, flush);
        }
        dumpit(f, b);
    }

    return ap_pass_brigade(f->next, bb) ;
}

static int dumpio_pre_conn(conn_rec *c, void *csd)
{
    dumpio_conf_t *ptr =
    (dumpio_conf_t *) ap_get_module_config(c->base_server->module_config,
                                           &dumpio_module);

    if (ptr->enable_input)
        ap_add_input_filter("DUMPIO_IN", NULL, NULL, c);
    if (ptr->enable_output)
        ap_add_output_filter("DUMPIO_OUT", NULL, NULL, c);
    return OK;
}

static void dumpio_register_hooks(apr_pool_t *p)
{
/*
 * We know that SSL is CONNECTION + 5
 */
  ap_register_output_filter("DUMPIO_OUT", dumpio_output_filter,
        NULL, AP_FTYPE_CONNECTION + 3) ;

  ap_register_input_filter("DUMPIO_IN", dumpio_input_filter,
        NULL, AP_FTYPE_CONNECTION + 3) ;

  ap_hook_pre_connection(dumpio_pre_conn, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *dumpio_create_sconfig(apr_pool_t *p, server_rec *s)
{
    dumpio_conf_t *ptr = apr_pcalloc(p, sizeof *ptr);
    ptr->enable_input = ptr->enable_output = 0;
    ptr->loglevel = APLOG_DEBUG;
    return ptr;
}

static const char *dumpio_enable_input(cmd_parms *cmd, void *dummy, int arg)
{
    dumpio_conf_t *ptr =
    (dumpio_conf_t *) ap_get_module_config(cmd->server->module_config,
                                           &dumpio_module);

    ptr->enable_input = arg;
    return NULL;
}

static const char *dumpio_enable_output(cmd_parms *cmd, void *dummy, int arg)
{
    dumpio_conf_t *ptr =
    (dumpio_conf_t *) ap_get_module_config(cmd->server->module_config,
                                           &dumpio_module);

    ptr->enable_output = arg;
    return NULL;
}

static const char *set_loglevel(cmd_parms *cmd, void *dummy, const char *arg)
{
    char *str;
    dumpio_conf_t *ptr =
    (dumpio_conf_t *) ap_get_module_config(cmd->server->module_config,
                                           &dumpio_module);

    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    if ((str = ap_getword_conf(cmd->pool, &arg))) {
        if (!strcasecmp(str, "emerg")) {
            ptr->loglevel = APLOG_EMERG;
        }
        else if (!strcasecmp(str, "alert")) {
            ptr->loglevel = APLOG_ALERT;
        }
        else if (!strcasecmp(str, "crit")) {
            ptr->loglevel = APLOG_CRIT;
        }
        else if (!strcasecmp(str, "error")) {
            ptr->loglevel = APLOG_ERR;
        }
        else if (!strcasecmp(str, "warn")) {
            ptr->loglevel = APLOG_WARNING;
        }
        else if (!strcasecmp(str, "notice")) {
            ptr->loglevel = APLOG_NOTICE;
        }
        else if (!strcasecmp(str, "info")) {
            ptr->loglevel = APLOG_INFO;
        }
        else if (!strcasecmp(str, "debug")) {
            ptr->loglevel = APLOG_DEBUG;
        }
        else {
            return "DumpIOLogLevel requires level keyword: one of "
                   "emerg/alert/crit/error/warn/notice/info/debug";
        }
    }
    else {
        return "DumpIOLogLevel requires level keyword";
    }

    return NULL;
}

static const command_rec dumpio_cmds[] = {
    AP_INIT_FLAG("DumpIOInput", dumpio_enable_input, NULL,
                 RSRC_CONF, "Enable I/O Dump on Input Data"),
    AP_INIT_FLAG("DumpIOOutput", dumpio_enable_output, NULL,
                 RSRC_CONF, "Enable I/O Dump on Output Data"),
    AP_INIT_TAKE1("DumpIOLogLevel", set_loglevel, NULL, RSRC_CONF,
                  "Level at which DumpIO info is logged"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA dumpio_module = {
        STANDARD20_MODULE_STUFF,
        NULL,
        NULL,
        dumpio_create_sconfig,
        NULL,
        dumpio_cmds,
        dumpio_register_hooks
};
