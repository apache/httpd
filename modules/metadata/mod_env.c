/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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

/*
 * mod_env.c
 * version 0.0.5
 * status beta
 * Pass environment variables to CGI/SSI scripts.
 * 
 * Andrew Wilson <Andrew.Wilson@cm.cf.ac.uk> 06.Dec.95
 *
 * Change log:
 * 08.Dec.95 Now allows PassEnv directive to appear more than once in
 *           conf files.
 * 10.Dec.95 optimisation.  getenv() only called at startup and used 
 *           to build a fast-to-access table.  apr_table_t used to build 
 *           per-server environment for each request.
 *           robustness.  better able to handle errors in configuration
 *           files:
 *           1)  PassEnv directive present, but no environment variable listed
 *           2)  PassEnv FOO present, but $FOO not present in environment
 *           3)  no PassEnv directive present
 * 23.Dec.95 Now allows SetEnv directive with same semantics as 'sh' setenv:
 *              SetEnv Var      sets Var to the empty string
 *              SetEnv Var Val  sets Var to the value Val
 *           Values containing whitespace should be quoted, eg:
 *              SetEnv Var "this is some text"
 *           Environment variables take their value from the last instance
 *           of PassEnv / SetEnv to be reached in the configuration file.
 *           For example, the sequence:
 *              PassEnv FOO
 *              SetEnv FOO override
 *           Causes FOO to take the value 'override'.
 * 23.Feb.96 Added UnsetEnv directive to allow environment variables
 *           to be removed.
 *           Virtual hosts now 'inherit' parent server environment which
 *           they're able to overwrite with their own directives or
 *           selectively ignore with UnsetEnv.
 *       *** IMPORTANT - the way that virtual hosts inherit their ***
 *       *** environment variables from the default server's      ***
 *       *** configuration has changed.  You should test your     ***
 *       *** configuration carefully before accepting this        ***
 *       *** version of the module in a live webserver which used ***
 *       *** older versions of the module.                        ***
 */

#include "apr_strings.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

typedef struct {
    apr_table_t *vars;
    const char *unsetenv;
    int vars_present;
} env_dir_config_rec;

module MODULE_VAR_EXPORT env_module;

static void *create_env_dir_config(apr_pool_t *p, char *dummy)
{
    env_dir_config_rec *new =
    (env_dir_config_rec *) apr_palloc(p, sizeof(env_dir_config_rec));
    new->vars = apr_make_table(p, 50);
    new->unsetenv = "";
    new->vars_present = 0;
    return (void *) new;
}

static void *merge_env_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    env_dir_config_rec *base = (env_dir_config_rec *) basev;
    env_dir_config_rec *add = (env_dir_config_rec *) addv;
    env_dir_config_rec *new =
    (env_dir_config_rec *) apr_palloc(p, sizeof(env_dir_config_rec));

    apr_table_t *new_table;
    apr_table_entry_t *elts;
    apr_array_header_t *arr;

    int i;
    const char *uenv, *unset;

    /* 
     * new_table = copy_table( p, base->vars );
     * foreach $element ( @add->vars ) {
     *     table_set( new_table, $element.key, $element.val );
     * };
     * foreach $unsetenv ( @UNSETENV ) {
     *     table_unset( new_table, $unsetenv );
     * }
     */

    new_table = apr_copy_table(p, base->vars);

    arr = ap_table_elts(add->vars);
    elts = (apr_table_entry_t *)arr->elts;

    for (i = 0; i < arr->nelts; ++i) {
        apr_table_setn(new_table, elts[i].key, elts[i].val);
    }

    unset = add->unsetenv;
    uenv = ap_getword_conf(p, &unset);
    while (uenv[0] != '\0') {
        apr_table_unset(new_table, uenv);
        uenv = ap_getword_conf(p, &unset);
    }

    new->vars = new_table;

    new->vars_present = base->vars_present || add->vars_present;

    return new;
}

static const char *add_env_module_vars_passed(cmd_parms *cmd, void *sconf_,
                                              const char *arg)
{
    env_dir_config_rec *sconf=sconf_;
    apr_table_t *vars = sconf->vars;
    char *env_var;
    char *name_ptr;

    while (*arg) {
        name_ptr = ap_getword_conf(cmd->pool, &arg);
        env_var = getenv(name_ptr);
        if (env_var != NULL) {
            sconf->vars_present = 1;
            apr_table_setn(vars, name_ptr, apr_pstrdup(cmd->pool, env_var));
        }
    }
    return NULL;
}

static const char *add_env_module_vars_set(cmd_parms *cmd, void *sconf_,
                                           const char *arg)
{
    env_dir_config_rec *sconf=sconf_;
    apr_table_t *vars = sconf->vars;
    char *name, *value;

    name = ap_getword_conf(cmd->pool, &arg);
    value = ap_getword_conf(cmd->pool, &arg);

    /* name is mandatory, value is optional.  no value means
     * set the variable to an empty string
     */


    if ((*name == '\0') || (*arg != '\0')) {
        return "SetEnv takes one or two arguments.  An environment variable name and an optional value to pass to CGI.";
    }

    sconf->vars_present = 1;
    apr_table_setn(vars, name, value);

    return NULL;
}

static const char *add_env_module_vars_unset(cmd_parms *cmd, void *sconf_,
                                             const char *arg)
{
    env_dir_config_rec *sconf=sconf_;

    sconf->unsetenv = sconf->unsetenv ?
        apr_pstrcat(cmd->pool, sconf->unsetenv, " ", arg, NULL) :
         arg;
    return NULL;
}

static const command_rec env_module_cmds[] =
{
AP_INIT_RAW_ARGS("PassEnv", add_env_module_vars_passed, NULL,
     OR_FILEINFO, "a list of environment variables to pass to CGI."),
AP_INIT_RAW_ARGS("SetEnv", add_env_module_vars_set, NULL,
     OR_FILEINFO, "an environment variable name and a value to pass to CGI."),
AP_INIT_RAW_ARGS("UnsetEnv", add_env_module_vars_unset, NULL,
     OR_FILEINFO, "a list of variables to remove from the CGI environment."),
    {NULL},
};

static int fixup_env_module(request_rec *r)
{
    apr_table_t *e = r->subprocess_env;
    env_dir_config_rec *sconf = ap_get_module_config(r->per_dir_config,
                                                     &env_module);
    apr_table_t *vars = sconf->vars;

    if (!sconf->vars_present)
        return DECLINED;

    r->subprocess_env = apr_overlay_tables(r->pool, e, vars);

    return OK;
}

static void register_hooks(void)
{
    ap_hook_fixups(fixup_env_module,NULL,NULL,AP_HOOK_MIDDLE);
}


module MODULE_VAR_EXPORT env_module =
{
    STANDARD20_MODULE_STUFF,
    create_env_dir_config,      /* dir config creater */
    merge_env_dir_configs,      /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    env_module_cmds,            /* command apr_table_t */
    NULL,                       /* handlers */
    register_hooks              /* register hooks */
};
