/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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

#ifdef NETWARE


module AP_MODULE_DECLARE_DATA netware_module;

typedef struct {
    apr_table_t *file_type_handlers;    /* CGI map from file types to CGI modules */
    apr_table_t *extra_env_vars;        /* Environment variables to be added to the CGI environment */
} netware_dir_config;


static void *create_netware_dir_config(apr_pool_t *p, char *dir)
{
    netware_dir_config *new = (netware_dir_config*) apr_palloc(p, sizeof(netware_dir_config));

    new->file_type_handlers = apr_table_make(p, 10);
    new->extra_env_vars = apr_table_make(p, 10);

    return new;
}

static void *merge_netware_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    netware_dir_config *base = (netware_dir_config *) basev;
    netware_dir_config *add = (netware_dir_config *) addv;
    netware_dir_config *new = (netware_dir_config *) apr_palloc(p, sizeof(netware_dir_config));

    new->file_type_handlers = apr_table_overlay(p, add->file_type_handlers, base->file_type_handlers);
    new->extra_env_vars = apr_table_overlay(p, add->extra_env_vars, base->extra_env_vars);

    return new;
}

static const char *set_extension_map(cmd_parms *cmd, netware_dir_config *m, char *CGIhdlr, char *ext)
{
    if (*ext == '.')
        ++ext;
    apr_table_set(m->file_type_handlers, ext, CGIhdlr);
    return NULL;
}


static apr_array_header_t *split_argv(apr_pool_t *p, const char *interp,
                                      const char *cgiprg, const char *cgiargs)
{
    apr_array_header_t *args = apr_array_make(p, 8, sizeof(char*));
    char *d = apr_palloc(p, strlen(interp)+1);
    const char *ch = interp; 
    const char **arg;
    int prgtaken = 0;
    int argtaken = 0;
    int inquo;
    int sl;

    while (*ch) {
        /* Skip on through Deep Space */
        if (isspace(*ch)) {
            ++ch; continue;
        }
        /* One Arg */
        if (((*ch == '$') || (*ch == '%')) && (*(ch + 1) == '*')) {
            const char *cgiarg = cgiargs;
            argtaken = 1;
            for (;;) {
                char *w = ap_getword_nulls(p, &cgiarg, '+');
                if (!*w) {
                    break;
                }
                ap_unescape_url(w);
                arg = (const char**)apr_array_push(args);
                *arg = ap_escape_shell_cmd(p, w);
            }
            ch += 2;
            continue;
        }
        if (((*ch == '$') || (*ch == '%')) && (*(ch + 1) == '1')) {
            /* Todo: Make short name!!! */
            prgtaken = 1;
            arg = (const char**)apr_array_push(args);
            if (*ch == '%') {
                char *repl = apr_pstrdup(p, cgiprg);
                *arg = repl;
                while ((repl = strchr(repl, '/'))) {
                    *repl++ = '\\';
                }
            }
            else {
                *arg = cgiprg;
            }
            ch += 2;
            continue;
        }
        if ((*ch == '\"') && ((*(ch + 1) == '$') 
                              || (*(ch + 1) == '%')) && (*(ch + 2) == '1') 
            && (*(ch + 3) == '\"')) {
            prgtaken = 1;
            arg = (const char**)apr_array_push(args);
            if (*(ch + 1) == '%') {
                char *repl = apr_pstrdup(p, cgiprg);
                *arg = repl;
                while ((repl = strchr(repl, '/'))) {
                    *repl++ = '\\';
                }
            }
            else {
                *arg = cgiprg;
            }
            ch += 4;
            continue;
        }
        arg = (const char**)apr_array_push(args);
        *arg = d;
        inquo = 0;
        while (*ch) {
            if (isspace(*ch) && !inquo) {
                ++ch; break;
            }
            /* Get 'em backslashes */
            for (sl = 0; *ch == '\\'; ++sl) {
                *d++ = *ch++;
            }
            if (sl & 1) {
                /* last unmatched '\' + '"' sequence is a '"' */
                if (*ch == '\"') {
                    *(d - 1) = *ch++;
                }
                continue;
            }
            if (*ch == '\"') {
                /* '""' sequence within quotes is a '"' */
                if (*++ch == '\"' && inquo) {
                    *d++ = *ch++; continue;
                }
                /* Flip quote state */
                inquo = !inquo;
                if (isspace(*ch) && !inquo) {
                    ++ch; break;
                }
                /* All other '"'s are Munched */
                continue;
            }
            /* Anything else is, well, something else */
            *d++ = *ch++;
        }
        /* Term that arg, already pushed on args */
        *d++ = '\0';
    }

    if (!prgtaken) {
        arg = (const char**)apr_array_push(args);
        *arg = cgiprg;
    }

    if (!argtaken) {
        const char *cgiarg = cgiargs;
        for (;;) {
            char *w = ap_getword_nulls(p, &cgiarg, '+');
            if (!*w) {
                break;
            }
            ap_unescape_url(w);
            arg = (const char**)apr_array_push(args);
            *arg = ap_escape_shell_cmd(p, w);
        }
    }

    arg = (const char**)apr_array_push(args);
    *arg = NULL;

    return args;
}


static apr_status_t ap_cgi_build_command(const char **cmd, const char ***argv,
                                         request_rec *r, apr_pool_t *p, 
                                         int process_cgi, apr_cmdtype_e *type)
{
    const char *ext = NULL;
    const char *interpreter = NULL;
    netware_dir_config *d;
    apr_file_t *fh;
    const char *args = "";

    d = (netware_dir_config *)ap_get_module_config(r->per_dir_config, 
                                               &netware_module);

    if (process_cgi) {
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
    ext = strrchr(apr_filename_of_pathname(*cmd), '.');
    
    if (*ext == '.')
        ++ext;

    /* If it is an NLM then just execute it. */
    if (stricmp(ext, "nlm")) {
        *cmd = apr_table_get(d->file_type_handlers, ext);
        if (*cmd == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Could not find a command associated with the %s extension", ext);
            return APR_EBADF;
        }

    }

    apr_tokenize_to_argv(r->filename, (char***)argv, p);
    *type = APR_PROGRAM;

//    /* If the file has an extension and it is not .com and not .exe and
//     * we've been instructed to search the registry, then do so.
//     * Let apr_proc_create do all of the .bat/.cmd dirty work.
//     */
//    if (ext && (!strcasecmp(ext,".exe") || !strcasecmp(ext,".com")
//                || !strcasecmp(ext,".bat") || !strcasecmp(ext,".cmd"))) {
//        interpreter = "";
//    }
//    if (!interpreter && ext 
//          && (d->script_interpreter_source 
//                     == INTERPRETER_SOURCE_REGISTRY
//           || d->script_interpreter_source 
//                     == INTERPRETER_SOURCE_REGISTRY_STRICT)) {
//         /* Check the registry */
//        int strict = (d->script_interpreter_source 
//                      == INTERPRETER_SOURCE_REGISTRY_STRICT);
//        interpreter = get_interpreter_from_win32_registry(r->pool, ext,
//                                                          strict);
//        if (interpreter && *type != APR_SHELLCMD) {
//            *type = APR_PROGRAM_PATH;
//        }
//        else {
//            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
//                 strict ? "No ExecCGI verb found for files of type '%s'."
//                        : "No ExecCGI or Open verb found for files of type '%s'.", 
//                 ext);
//        }
//    }
//    if (!interpreter) {
//        apr_status_t rv;
//        char buffer[1024];
//        apr_size_t bytes = sizeof(buffer);
//        int i;
//
//        /* Need to peek into the file figure out what it really is... 
//         * ### aught to go back and build a cache for this one of these days.
//         */
//        if (((rv = apr_file_open(&fh, *cmd, APR_READ | APR_BUFFERED,
//                                 APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) 
//            || ((rv = apr_file_read(fh, buffer, &bytes)) != APR_SUCCESS)) {
//            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
//                          "Failed to read cgi file %s for testing", *cmd);
//            return rv;
//        }
//        apr_file_close(fh);
//
//        /* Script or executable, that is the question... */
//        if ((buffer[0] == '#') && (buffer[1] == '!')) {
//            /* Assuming file is a script since it starts with a shebang */
//            for (i = 2; i < sizeof(buffer); i++) {
//                if ((buffer[i] == '\r') || (buffer[i] == '\n')) {
//                    buffer[i] = '\0';
//                    break;
//                }
//            }
//            if (i < sizeof(buffer)) {
//                interpreter = buffer + 2;
//                while (isspace(*interpreter)) {
//                    ++interpreter;
//                }
//                if (*type != APR_SHELLCMD) {
//                    *type = APR_PROGRAM_PATH;
//                }
//            }
//        }
//        else {
//            /* Not a script, is it an executable? */
//            IMAGE_DOS_HEADER *hdr = (IMAGE_DOS_HEADER*)buffer;    
//            if ((bytes >= sizeof(IMAGE_DOS_HEADER))
//                && (hdr->e_magic == IMAGE_DOS_SIGNATURE)) {
//                if (hdr->e_lfarlc < 0x40) {
//                    /* Ought to invoke this 16 bit exe by a stub, (cmd /c?) */
//                    interpreter = "";
//                }
//                else {
//                    interpreter = "";
//                }
//            }
//        }
//    }
//    if (!interpreter) {
//        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
//                      "%s is not executable; ensure interpreted scripts have "
//                      "\"#!\" first line", *cmd);
//        return APR_EBADF;
//    }
//
//    *argv = (const char **)(split_argv(p, interpreter, *cmd,
//                                       args)->elts);
//    *cmd = (*argv)[0];
    return APR_SUCCESS;
}

APR_DECLARE_OPTIONAL_FN(apr_status_t, ap_cgi_build_command,
                        (const char **cmd, const char ***argv, 
                         request_rec *r, apr_pool_t *p, 
                         int replace_cmd, apr_cmdtype_e *type));

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(ap_cgi_build_command);
}

static const command_rec netware_cmds[] = {
AP_INIT_ITERATE2("CGIMapExtension", set_extension_map, NULL, OR_FILEINFO, 
              "full path to the CGI NLM module followed by one or more file extensions"),
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
