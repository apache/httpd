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
 * mod_actions.c: executes scripts based on MIME type or HTTP method
 *
 * by Alexei Kosut; based on mod_cgi.c, mod_mime.c and mod_includes.c,
 * adapted by rst from original NCSA code by Rob McCool
 *
 * Usage instructions:
 *
 * Action mime/type /cgi-bin/script
 *
 * will activate /cgi-bin/script when a file of content type mime/type is
 * requested. It sends the URL and file path of the requested document using
 * the standard CGI PATH_INFO and PATH_TRANSLATED environment variables.
 *
 * Script PUT /cgi-bin/script
 *
 * will activate /cgi-bin/script when a request is received with the
 * HTTP method "PUT".  The available method names are defined in httpd.h.
 * If the method is GET, the script will only be activated if the requested
 * URI includes query information (stuff after a ?-mark).
 */

#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"

typedef struct {
    apr_table_t *action_types;       /* Added with Action... */
    const char *scripted[METHODS];   /* Added with Script... */
    int configured;  /* True if Action or Script has been
                      * called at least once
                      */
} action_dir_config;

module AP_MODULE_DECLARE_DATA actions_module;

static void *create_action_dir_config(apr_pool_t *p, char *dummy)
{
    action_dir_config *new =
    (action_dir_config *) apr_pcalloc(p, sizeof(action_dir_config));

    new->action_types = apr_table_make(p, 4);

    return new;
}

static void *merge_action_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    action_dir_config *base = (action_dir_config *) basev;
    action_dir_config *add = (action_dir_config *) addv;
    action_dir_config *new = (action_dir_config *) apr_palloc(p,
                                  sizeof(action_dir_config));
    int i;

    new->action_types = apr_table_overlay(p, add->action_types,
                                       base->action_types);

    for (i = 0; i < METHODS; ++i) {
        new->scripted[i] = add->scripted[i] ? add->scripted[i]
                                            : base->scripted[i];
    }

    new->configured = (base->configured || add->configured);
    return new;
}

static const char *add_action(cmd_parms *cmd, void *m_v,
                              const char *type, const char *script,
                              const char *option)
{
    action_dir_config *m = (action_dir_config *)m_v;

    if (option && strcasecmp(option, "virtual")) {
        return apr_pstrcat(cmd->pool,
                           "unrecognized option '", option, "'", NULL);
    }

    apr_table_setn(m->action_types, type,
                   apr_pstrcat(cmd->pool, option ? "1" : "0", script, NULL));
    m->configured = 1;

    return NULL;
}

static const char *set_script(cmd_parms *cmd, void *m_v,
                              const char *method, const char *script)
{
    action_dir_config *m = (action_dir_config *)m_v;
    int methnum;
    if (cmd->pool == cmd->temp_pool) {
        /* In .htaccess, we can't globally register new methods. */
        methnum = ap_method_number_of(method);
    }
    else {
        /* ap_method_register recognizes already registered methods,
         * so don't bother to check its previous existence explicitly.
         */
        methnum = ap_method_register(cmd->pool, method);
    }

    if (methnum == M_TRACE) {
        return "TRACE not allowed for Script";
    }
    else if (methnum == M_INVALID) {
        return apr_pstrcat(cmd->pool, "Could not register method '", method,
                           "' for Script", NULL);
    }

    m->scripted[methnum] = script;
    m->configured = 1;

    return NULL;
}

static const command_rec action_cmds[] =
{
    AP_INIT_TAKE23("Action", add_action, NULL, OR_FILEINFO,
                  "a media type followed by a script name"),
    AP_INIT_TAKE2("Script", set_script, NULL, ACCESS_CONF | RSRC_CONF,
                  "a method followed by a script name"),
    {NULL}
};

static int action_handler(request_rec *r)
{
    action_dir_config *conf = (action_dir_config *)
        ap_get_module_config(r->per_dir_config, &actions_module);
    const char *t, *action;
    const char *script;
    int i;

    if (!conf->configured) {
        return DECLINED;
    }

    /* Note that this handler handles _all_ types, so handler is unchecked */

    /* Set allowed stuff */
    for (i = 0; i < METHODS; ++i) {
        if (conf->scripted[i])
            r->allowed |= (AP_METHOD_BIT << i);
    }

    /* First, check for the method-handling scripts */
    if (r->method_number == M_GET) {
        if (r->args)
            script = conf->scripted[M_GET];
        else
            script = NULL;
    }
    else {
        script = conf->scripted[r->method_number];
    }

    /* Check for looping, which can happen if the CGI script isn't */
    if (script && r->prev && r->prev->prev)
        return DECLINED;

    /* Second, check for actions (which override the method scripts) */
    action = r->handler;
    if (!action && AP_REQUEST_IS_TRUSTED_CT(r)) {
        action = ap_field_noparam(r->pool, r->content_type);
    }

    if (action && (t = apr_table_get(conf->action_types, action))) {
        int virtual = (*t++ == '0' ? 0 : 1);
        if (!virtual && r->finfo.filetype == APR_NOFILE) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00652)
                          "File does not exist: %s", r->filename);
            return HTTP_NOT_FOUND;
        }

        script = t;
        /* propagate the handler name to the script
         * (will be REDIRECT_HANDLER there)
         */
        apr_table_setn(r->subprocess_env, "HANDLER", action);
        if (virtual) {
            apr_table_setn(r->notes, "virtual_script", "1");
        }
    }

    if (script == NULL)
        return DECLINED;

    ap_internal_redirect_handler(apr_pstrcat(r->pool, script,
                                             ap_escape_uri(r->pool, r->uri),
                                             r->args ? "?" : NULL,
                                             r->args, NULL), r);
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(action_handler,NULL,NULL,APR_HOOK_LAST);
}

AP_DECLARE_MODULE(actions) =
{
    STANDARD20_MODULE_STUFF,
    create_action_dir_config,   /* dir config creater */
    merge_action_dir_configs,   /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    action_cmds,                /* command apr_table_t */
    register_hooks              /* register hooks */
};
