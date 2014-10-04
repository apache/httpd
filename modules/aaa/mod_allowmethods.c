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
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "apr_strings.h"

/**
 * This module makes it easy to restrict what HTTP methods can be ran against
 * a server.
 *
 * It provides one comand:
 *    AllowMethods
 * This command takes a list of HTTP methods to allow.
 *
 *  The most common configuration should be like this:
 *   <Directory />
 *    AllowMethods GET HEAD OPTIONS
 *   </Directory>
 *   <Directory /special/cgi-bin>
 *      AllowMethods GET HEAD OPTIONS POST
 *   </Directory>
 *  Non-matching methods will be returned a status 405 (method not allowed)
 *
 *  To allow all methods, and effectively turn off mod_allowmethods, use:
 *    AllowMethods reset
 */

typedef struct am_conf_t {
    int allowed_set;
    apr_int64_t allowed;
} am_conf_t;

module AP_MODULE_DECLARE_DATA allowmethods_module;

static int am_check_access(request_rec *r)
{
    int method = r->method_number;
    am_conf_t *conf;

    conf = (am_conf_t *) ap_get_module_config(r->per_dir_config,
                                              &allowmethods_module);
    if (!conf || conf->allowed == 0) {
        return DECLINED;
    }

    r->allowed = conf->allowed;

    if (conf->allowed & (AP_METHOD_BIT << method)) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01623)
                  "client method denied by server configuration: '%s' to %s%s",
                  r->method,
                  r->filename ? "" : "uri ",
                  r->filename ? r->filename : r->uri);

    return HTTP_METHOD_NOT_ALLOWED;
}

static void *am_create_conf(apr_pool_t *p, char *dummy)
{
    am_conf_t *conf = apr_pcalloc(p, sizeof(am_conf_t));

    conf->allowed = 0;
    conf->allowed_set = 0;
    return conf;
}

static void *am_merge_conf(apr_pool_t *pool, void *a, void *b)
{
    am_conf_t *base = (am_conf_t *)a;
    am_conf_t *add = (am_conf_t *)b;
    am_conf_t *conf = apr_palloc(pool, sizeof(am_conf_t));

    if (add->allowed_set) {
        conf->allowed = add->allowed;
        conf->allowed_set = add->allowed_set;
    }
    else {
        conf->allowed = base->allowed;
        conf->allowed_set = base->allowed_set;
    }

    return conf;
}

static const char *am_allowmethods(cmd_parms *cmd, void *d, int argc,
                                   char *const argv[])
{
    int i;
    am_conf_t *conf = (am_conf_t *)d;

    if (argc == 0) {
        return "AllowMethods: No method or 'reset' keyword given";
    }
    if (argc == 1) {
        if (strcasecmp("reset", argv[0]) == 0) {
            conf->allowed = 0;
            conf->allowed_set = 1;
            return NULL;
        }
    }

    for (i = 0; i < argc; i++) {
        int m;

        m = ap_method_number_of(argv[i]);
        if (m == M_INVALID) {
            return apr_pstrcat(cmd->pool, "AllowMethods: Invalid Method '",
                               argv[i], "'", NULL);
        }

        conf->allowed |= (AP_METHOD_BIT << m);
    }
    conf->allowed_set = 1;
    return NULL;
}

static void am_register_hooks(apr_pool_t * p)
{
    ap_hook_access_checker(am_check_access, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

static const command_rec am_cmds[] = {
    AP_INIT_TAKE_ARGV("AllowMethods", am_allowmethods, NULL,
                      ACCESS_CONF,
                      "only allow specific methods"),
    {NULL}
};

AP_DECLARE_MODULE(allowmethods) = {
    STANDARD20_MODULE_STUFF,
    am_create_conf,
    am_merge_conf,
    NULL,
    NULL,
    am_cmds,
    am_register_hooks,
};
