/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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


#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_buckets.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "util_script.h"
#include "mod_core.h"
#include "apr_optional.h"
#include "apr_lib.h"
#include "mod_cgi.h"

#ifdef NETWARE


module AP_MODULE_DECLARE_DATA netware_module;

typedef struct {
    apr_table_t *file_type_handlers;    /* CGI map from file types to CGI modules */
    apr_table_t *file_handler_mode;     /* CGI module mode (spawn in same address space or not) */
    apr_table_t *extra_env_vars;        /* Environment variables to be added to the CGI environment */
} netware_dir_config;


static void *create_netware_dir_config(apr_pool_t *p, char *dir)
{
    netware_dir_config *new = (netware_dir_config*) apr_palloc(p, sizeof(netware_dir_config));

    new->file_type_handlers = apr_table_make(p, 10);
    new->file_handler_mode = apr_table_make(p, 10);
    new->extra_env_vars = apr_table_make(p, 10);

    apr_table_set(new->file_type_handlers, "NLM", "OS");

    return new;
}

static void *merge_netware_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    netware_dir_config *base = (netware_dir_config *) basev;
    netware_dir_config *add = (netware_dir_config *) addv;
    netware_dir_config *new = (netware_dir_config *) apr_palloc(p, sizeof(netware_dir_config));

    new->file_type_handlers = apr_table_overlay(p, add->file_type_handlers, base->file_type_handlers);
    new->file_handler_mode = apr_table_overlay(p, add->file_handler_mode, base->file_handler_mode);
    new->extra_env_vars = apr_table_overlay(p, add->extra_env_vars, base->extra_env_vars);

    return new;
}

static const char *set_extension_map(cmd_parms *cmd, netware_dir_config *m,
                                     char *CGIhdlr, char *ext, char *detach)
{
    int i, len;

    if (*ext == '.')
        ++ext;
  
    if (CGIhdlr != NULL) {
        len = strlen(CGIhdlr);    
        for (i=0; i<len; i++) {
            if (CGIhdlr[i] == '\\') {
                CGIhdlr[i] = '/';
            }
        }
    }

    apr_table_set(m->file_type_handlers, ext, CGIhdlr);
    if (detach) {
        apr_table_set(m->file_handler_mode, ext, "y");
    }

    return NULL;
}

static apr_status_t ap_cgi_build_command(const char **cmd, const char ***argv,
                                         request_rec *r, apr_pool_t *p, 
                                         cgi_exec_info_t *e_info)
{
    char *ext = NULL;
    char *cmd_only, *ptr;
    const char *detached = NULL;
    netware_dir_config *d;
    apr_file_t *fh;
    const char *args = "";

    d = (netware_dir_config *)ap_get_module_config(r->per_dir_config, 
                                               &netware_module);

    if (e_info->process_cgi) {
        /* Handle the complete file name, we DON'T want to follow suexec, since
         * an unrooted command is as predictable as shooting craps in Win32.
         *
         * Notice that unlike most mime extension parsing, we have to use the
         * win32 parsing here, therefore the final extension is the only one
         * we will consider
         */
        *cmd = r->filename;
        if (r->args && r->args[0] && !ap_strchr_c(r->args, '=')) {
            args = r->args;
        }
    }

    cmd_only = apr_pstrdup(p, *cmd);
    e_info->cmd_type = APR_PROGRAM;

    /* truncate any arguments from the cmd */
    for (ptr = cmd_only; *ptr && (*ptr != ' '); ptr++);
    *ptr = '\0';

    /* Figure out what the extension is so that we can matche it. */
    ext = strrchr(apr_filepath_name_get(cmd_only), '.');

    /* If there isn't an extension then give it an empty string */
    if (!ext) {
        ext = "";
    }
    
    /* eliminate the '.' if there is one */
    if (*ext == '.')
        ++ext;

    /* check if we have a registered command for the extension*/
    *cmd = apr_table_get(d->file_type_handlers, ext);
    if (*cmd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "Could not find a command associated with the %s extension", ext);
        return APR_EBADF;
    }
    if (!stricmp(*cmd, "OS")) {
        /* If it is an NLM then restore *cmd and just execute it */
        *cmd = cmd_only;
    }
    else {
        /* If we have a registered command then add the file that was passed in as a
          parameter to the registered command. */
        *cmd = apr_pstrcat (p, *cmd, " ", cmd_only, NULL);

        /* Run in its own address space if specified */
        detached = apr_table_get(d->file_handler_mode, ext);
        if (detached) {
            e_info->cmd_type = APR_PROGRAM_ENV;
        }
        else {
            e_info->cmd_type = APR_PROGRAM;
        }
    }

    /* Tokenize the full command string into its arguments */
    apr_tokenize_to_argv(*cmd, (char***)argv, p);
    e_info->detached = 1;

    /* The first argument should be the executible */
    *cmd = ap_server_root_relative(p, *argv[0]);

    return APR_SUCCESS;
}

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(ap_cgi_build_command);
}

static const command_rec netware_cmds[] = {
AP_INIT_TAKE23("CGIMapExtension", set_extension_map, NULL, OR_FILEINFO, 
              "Full path to the CGI NLM module followed by a file extension. If the "
              "first parameter is set to \"OS\" then the following file extension is "
              "treated as NLM. The optional parameter \"detach\" can be specified if "
              "the NLM should be launched in its own address space."),
{ NULL }
};

module AP_MODULE_DECLARE_DATA netware_module = {
   STANDARD20_MODULE_STUFF,
   create_netware_dir_config,     /* create per-dir config */
   merge_netware_dir_configs,     /* merge per-dir config */
   NULL,                        /* server config */
   NULL,                        /* merge server config */
   netware_cmds,                  /* command apr_table_t */
   register_hooks               /* register hooks */
};

#endif
