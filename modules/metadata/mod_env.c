/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#include "apr.h"
#include "apr_strings.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"

typedef struct {
    apr_table_t *vars;
    apr_table_t *unsetenv;
} env_dir_config_rec;

module AP_MODULE_DECLARE_DATA env_module;

static void *create_env_dir_config(apr_pool_t *p, char *dummy)
{
    env_dir_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->vars = apr_table_make(p, 10);
    conf->unsetenv = apr_table_make(p, 10);

    return conf;
}

static void *merge_env_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    env_dir_config_rec *base = basev;
    env_dir_config_rec *add = addv;
    env_dir_config_rec *res = apr_palloc(p, sizeof(*res));

    const apr_table_entry_t *elts;
    const apr_array_header_t *arr;

    int i;

    /* 
     * res->vars = copy_table( p, base->vars );
     * foreach $unsetenv ( @add->unsetenv )
     *     table_unset( res->vars, $unsetenv );
     * foreach $element ( @add->vars )
     *     table_set( res->vars, $element.key, $element.val );
     *
     * add->unsetenv already removed the vars from add->vars, 
     * if they preceeded the UnsetEnv directive.
     */
    res->vars = apr_table_copy(p, base->vars);
    res->unsetenv = NULL;

    arr = apr_table_elts(add->unsetenv);
    if (arr) {
        elts = (const apr_table_entry_t *)arr->elts;

        for (i = 0; i < arr->nelts; ++i) {
            apr_table_unset(res->vars, elts[i].key);
        }
    }

    arr = apr_table_elts(add->vars);
    if (arr) {
        elts = (const apr_table_entry_t *)arr->elts;

        for (i = 0; i < arr->nelts; ++i) {
            apr_table_setn(res->vars, elts[i].key, elts[i].val);
        }
    }

    return res;
}

static const char *add_env_module_vars_passed(cmd_parms *cmd, void *sconf_,
                                              const char *arg)
{
    env_dir_config_rec *sconf = sconf_;
    apr_table_t *vars = sconf->vars;
    const char *env_var;
    
    env_var = getenv(arg);
    if (env_var != NULL) {
        apr_table_setn(vars, arg, apr_pstrdup(cmd->pool, env_var));
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                     "PassEnv variable %s was undefined", arg);
    }

    return NULL;
}

static const char *add_env_module_vars_set(cmd_parms *cmd, void *sconf_,
                                           const char *name, const char *value)
{
    env_dir_config_rec *sconf = sconf_;
    
    /* name is mandatory, value is optional.  no value means
     * set the variable to an empty string
     */
    apr_table_setn(sconf->vars, name, value ? value : "");

    return NULL;
}

static const char *add_env_module_vars_unset(cmd_parms *cmd, void *sconf_,
                                             const char *arg)
{
    env_dir_config_rec *sconf = sconf_;

    /* Always UnsetEnv FOO in the same context as {Set,Pass}Env FOO
     * only if this UnsetEnv follows the {Set,Pass}Env.  The merge
     * will only apply unsetenv to the parent env (main server).
     */
    apr_table_set(sconf->unsetenv, arg, NULL);
    apr_table_unset(sconf->vars, arg);

    return NULL;
}

static const command_rec env_module_cmds[] =
{
AP_INIT_ITERATE("PassEnv", add_env_module_vars_passed, NULL,
     OR_FILEINFO, "a list of environment variables to pass to CGI."),
AP_INIT_TAKE12("SetEnv", add_env_module_vars_set, NULL,
     OR_FILEINFO, "an environment variable name and optional value to pass to CGI."),
AP_INIT_ITERATE("UnsetEnv", add_env_module_vars_unset, NULL,
     OR_FILEINFO, "a list of variables to remove from the CGI environment."),
    {NULL},
};

static int fixup_env_module(request_rec *r)
{
    apr_table_t *e = r->subprocess_env;
    env_dir_config_rec *sconf = ap_get_module_config(r->per_dir_config,
                                                     &env_module);
    apr_table_t *vars = sconf->vars;

    if (!apr_table_elts(sconf->vars)->nelts)
        return DECLINED;

    r->subprocess_env = apr_table_overlay(r->pool, e, vars);

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(fixup_env_module, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA env_module =
{
    STANDARD20_MODULE_STUFF,
    create_env_dir_config,      /* dir config creater */
    merge_env_dir_configs,      /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    env_module_cmds,            /* command apr_table_t */
    register_hooks              /* register hooks */
};
