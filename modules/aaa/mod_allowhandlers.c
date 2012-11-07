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

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"

module AP_MODULE_DECLARE_DATA allowhandlers_module;

typedef enum {
    AH_ALLOW = 0,
    AH_DENY = 1,
} ah_op_e;
typedef struct {
    apr_table_t *handlers;
    ah_op_e     op;
} ah_conf_t;

static const char * const forbidden_handler = "forbidden";
static const char * const no_handler        = "none";

static int ah_fixups(request_rec *r)
{
    ah_conf_t *conf = ap_get_module_config(r->per_dir_config,
                                         &allowhandlers_module);
    int match = 0;
    const char *handler_name;
    if (!r->handler || r->handler[0] == '\0') {
        handler_name = no_handler;
    }
    else if (strcasecmp(r->handler, forbidden_handler) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      APLOGNO(02398) "Handler 'forbidden' denied by "
                      "server configuration: URI %s (file %s)",
                      r->uri, r->filename);
        return HTTP_FORBIDDEN;
    }
    else {
        handler_name = r->handler;
    }

    if (!conf)
        return DECLINED;
    if (conf->handlers && apr_table_get(conf->handlers, handler_name))
        match = 1;

    if ((match && conf->op == AH_ALLOW) || (!match && conf->op == AH_DENY)) {
        return DECLINED;
    }
    else {
        if (handler_name != no_handler) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          APLOGNO(02399) "Handler '%s' denied by "
                          "server configuration: URI %s (file %s)",
                          r->handler, r->uri, r->filename);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          APLOGNO(02400) "Handler denied by server "
                          "configuration: No handler set for URI %s (file %s)",
                          r->uri, r->filename);
        }
        return HTTP_FORBIDDEN;
    }
}

static void *ah_create_conf(apr_pool_t * p, char *dummy)
{
  ah_conf_t *conf = apr_pcalloc(p, sizeof(ah_conf_t));
  conf->op = AH_DENY;
  return conf;
}

static const char *set_allowed_handlers(cmd_parms *cmd, void *d, int argc, char *const argv[])
{
    int i;
    ah_conf_t* conf = (ah_conf_t*) d;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;
    if (argc == 0)
        return "AllowHandlers: No handler name given";
    conf->op = AH_ALLOW;
    if (conf->handlers)
        apr_table_clear(conf->handlers);
    for (i = 0; i < argc; i++) {
        if (strcasecmp(argv[i], forbidden_handler) == 0 && conf->op != AH_DENY)
            return "Handler name 'forbidden' cannot be changed.";
        if (strcasecmp(argv[i], "all") == 0) {
            if (argc != 1)
                return "'all' not possible with specific handler names";
            conf->op = AH_DENY;
            return NULL;
        }
        else if (strcasecmp(argv[i], "not") == 0) {
            if (i != 0 || argc == 1)
                return "'not' must come before specific handler names";
            conf->op = AH_DENY;
        }
        else {
            if (!conf->handlers)
                conf->handlers = apr_table_make(cmd->pool, 4);
            apr_table_setn(conf->handlers, argv[i], "1");
        }
    }
    return NULL;
}

static void ah_register_hooks(apr_pool_t * p)
{
    ap_hook_fixups(ah_fixups, NULL, NULL, APR_HOOK_REALLY_LAST);
}

static const command_rec ah_cmds[] = {
    AP_INIT_TAKE_ARGV("AllowHandlers", set_allowed_handlers, NULL, ACCESS_CONF,
                      "only allow specific handlers (use 'not' to negate)"),
  {NULL}
};

AP_DECLARE_MODULE(allowhandlers) = {
  STANDARD20_MODULE_STUFF,
  ah_create_conf,
  NULL,
  NULL,
  NULL,
  ah_cmds,
  ah_register_hooks,
};

