/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

#ifdef WIN32

/* 
 * CGI Script stuff for Win32...
 */
typedef enum { eFileTypeUNKNOWN, eFileTypeBIN, eFileTypeEXE16, eFileTypeEXE32, 
               eFileTypeSCRIPT } file_type_e;
typedef enum { INTERPRETER_SOURCE_UNSET, INTERPRETER_SOURCE_REGISTRY_STRICT, 
               INTERPRETER_SOURCE_REGISTRY, INTERPRETER_SOURCE_SHEBANG 
             } interpreter_source_e;
AP_DECLARE(file_type_e) ap_get_win32_interpreter(const request_rec *, 
                                                 char **interpreter,
                                                 char **arguments);

module AP_MODULE_DECLARE_DATA win32_module;

typedef struct {
    /* Where to find interpreter to run scripts */
    interpreter_source_e script_interpreter_source;
} win32_dir_conf;

static void *create_win32_dir_config(apr_pool_t *p, char *dir)
{
    win32_dir_conf *conf = (win32_dir_conf*)apr_palloc(p, sizeof(win32_dir_conf));
    conf->script_interpreter_source = INTERPRETER_SOURCE_UNSET;
    return conf;
}

static void *merge_win32_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    win32_dir_conf *new = (win32_dir_conf *) apr_pcalloc(p, sizeof(win32_dir_conf));
    win32_dir_conf *base = (win32_dir_conf *) basev;
    win32_dir_conf *add = (win32_dir_conf *) addv;

    new->script_interpreter_source = (add->script_interpreter_source 
                                           != INTERPRETER_SOURCE_UNSET)
                                   ? add->script_interpreter_source 
                                   : base->script_interpreter_source;
    return new;
}

static const char *set_interpreter_source(cmd_parms *cmd, void *dv,
                                          char *arg)
{
    win32_dir_conf *d = (win32_dir_conf *)dv;
    if (!strcasecmp(arg, "registry")) {
        d->script_interpreter_source = INTERPRETER_SOURCE_REGISTRY;
    } else if (!strcasecmp(arg, "registry-strict")) {
        d->script_interpreter_source = INTERPRETER_SOURCE_REGISTRY_STRICT;
    } else if (!strcasecmp(arg, "script")) {
        d->script_interpreter_source = INTERPRETER_SOURCE_SHEBANG;
    } else {
        return apr_pstrcat(cmd->temp_pool, "ScriptInterpreterSource \"", arg, 
                          "\" must be \"registry\", \"registry-strict\" or "
                          "\"script\"", NULL);
    }
    return NULL;
}

/* Pretty unexciting ... yank a registry value, and explode any envvars
 * that the system has configured (e.g. %SystemRoot%/someapp.exe)
 *
 * XXX: Need Unicode versions for i18n
 */
static apr_status_t get_win32_registry_default_value(apr_pool_t *p, HKEY hkey,
                                                     char* relativepath, 
                                                     char **value)
{
    HKEY hkeyOpen;
    DWORD type;
    DWORD size = 0;
    DWORD result = RegOpenKeyEx(hkey, relativepath, 0, 
                                KEY_QUERY_VALUE, &hkeyOpen);
    
    if (result != ERROR_SUCCESS) 
        return APR_FROM_OS_ERROR(result);

    /* Read to NULL buffer to determine value size */
    result = RegQueryValueEx(hkeyOpen, "", 0, &type, NULL, &size);
    
   if (result == ERROR_SUCCESS) {
        if ((size < 2) || (type != REG_SZ && type != REG_EXPAND_SZ)) {
            result = ERROR_INVALID_PARAMETER;
        }
        else {
            *value = apr_palloc(p, size);
            /* Read value based on size query above */
            result = RegQueryValueEx(hkeyOpen, "", 0, &type, *value, &size);
        }
    }

    /* TODO: This might look fine, but we need to provide some warning
     * somewhere that some environment variables may -not- be translated,
     * seeing as we may have chopped the environment table down somewhat.
     */
    if ((result == ERROR_SUCCESS) && (type == REG_EXPAND_SZ)) 
    {
        char *tmp = *value;
        size = ExpandEnvironmentStrings(tmp, *value, 0);
        if (size) {
            *value = apr_palloc(p, size);
            size = ExpandEnvironmentStrings(tmp, *value, size);
        }
    }

    RegCloseKey(hkeyOpen);
    return APR_FROM_OS_ERROR(result);
}

/* Somewhat more exciting ... figure out where the registry has stashed the
 * ExecCGI or Open command - it may be nested one level deep (or more???)
 */
static char* get_interpreter_from_win32_registry(apr_pool_t *p, 
                                                 const char* ext,
                                                 int strict)
{
    char execcgi_path[] = "SHELL\\EXECCGI\\COMMAND";
    char execopen_path[] = "SHELL\\OPEN\\COMMAND";
    char typeName[MAX_PATH];
    int cmdOfName = FALSE;
    HKEY hkeyName;
    HKEY hkeyType;
    DWORD type;
    int size;
    int result;
    char *buffer;
    
    if (!ext)
        return NULL;
    /* 
     * Future optimization:
     * When the registry is successfully searched, store the strings for
     * interpreter and arguments in an ext hash to speed up subsequent look-ups
     */

    /* Open the key associated with the script filetype extension */
    result = RegOpenKeyEx(HKEY_CLASSES_ROOT, ext, 0, KEY_QUERY_VALUE, 
                          &hkeyType);

    if (result != ERROR_SUCCESS) 
        return NULL;

    /* Retrieve the name of the script filetype extension */
    size = sizeof(typeName);
    result = RegQueryValueEx(hkeyType, "", NULL, &type, typeName, &size);
    
    if (result == ERROR_SUCCESS && type == REG_SZ && typeName[0]) {
        /* Open the key associated with the script filetype extension */
        result = RegOpenKeyEx(HKEY_CLASSES_ROOT, typeName, 0, 
                              KEY_QUERY_VALUE, &hkeyName);

        if (result == ERROR_SUCCESS)
            cmdOfName = TRUE;
    }

    /* Open the key for the script command path by:
     * 
     *   1) the 'named' filetype key for ExecCGI/Command
     *   2) the extension's type key for ExecCGI/Command
     *
     * and if the strict arg is false, then continue trying:
     *
     *   3) the 'named' filetype key for Open/Command
     *   4) the extension's type key for Open/Command
     */

    if (cmdOfName) {
        result = get_win32_registry_default_value(p, hkeyName, 
                                                  execcgi_path, &buffer);
    }

    if (!cmdOfName || (result != ERROR_SUCCESS)) {
        result = get_win32_registry_default_value(p, hkeyType, 
                                                  execcgi_path, &buffer);
    }

    if (!strict && cmdOfName && (result != ERROR_SUCCESS)) {
        result = get_win32_registry_default_value(p, hkeyName, 
                                                  execopen_path, &buffer);
    }

    if (!strict && (result != ERROR_SUCCESS)) {
        result = get_win32_registry_default_value(p, hkeyType, 
                                                  execopen_path, &buffer);
    }

    if (cmdOfName)
        RegCloseKey(hkeyName);

    RegCloseKey(hkeyType);

    if (result != ERROR_SUCCESS  || !buffer[0])
        return NULL;

    return buffer;
}


static apr_array_header_t *split_argv(apr_pool_t *p, const char *interp, const char *cgiprg, const char *cgiargs)
{
    apr_array_header_t *args = apr_array_make(p, 8, sizeof(char*));
    char *d = apr_palloc(p, strlen(interp));
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
                if (!*w)
                    break;
                ap_unescape_url(w);
                arg = (const char**)apr_array_push(args);
                *arg = ap_escape_shell_cmd(p, w);
            }
            ch += 2;
            continue;
        }
        if (((*ch == '$') || (*ch == '%')) && (*(ch + 1) == '1')) {
            prgtaken = 1;
            arg = (const char**)apr_array_push(args);
            *arg = cgiprg;
            ch += 2;
            continue;
        }
        if ((*ch == '\"') && ((*(ch + 1) == '$') 
                           || (*(ch + 1) == '%')) && (*(ch + 2) == '1') 
                                                  && (*(ch + 3) == '\"')) {
            prgtaken = 1;
            arg = (const char**)apr_array_push(args);
            *arg = cgiprg;
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
            for (sl = 0; *ch == '\\'; ++sl)
                *d++ = *ch++;
            if (sl & 1) {
                /* last unmatched '\' + '"' sequence is a '"' */
                if (*ch == '\"')
                    *(d - 1) = *ch++;
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
        char *cgiarg = cgiargs;
        for (;;) {
            char *w = ap_getword_nulls(p, &cgiarg, '+');
            if (!*w)
                break;
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
                                         request_rec *r, apr_pool_t *p)
{
    const char *ext = NULL;
    const char *interpreter = NULL;
    win32_dir_conf *d = 
        (win32_dir_conf *)ap_get_module_config(r->per_dir_config, 
                                               &win32_module);
    apr_file_t *fh;
    const char *args = r->args;

    /* Handle the complete file name, we DON'T want to follow suexec, since
     * an unrooted command is as predictable as shooting craps in Win32.
     *
     * Notice that unlike most mime extension parsing, we have to use the
     * win32 parsing here, therefore the final extension is the only one
     * we will consider
     */
    ext = strrchr(apr_filename_of_pathname(r->filename), '.');
    if (ext)
        ++ext;
    
    /* If the file has an extension and it is not .com and not .exe and
     * we've been instructed to search the registry, then do so.
     */
    if (ext && (!strcasecmp(ext,".exe") || !strcasecmp(ext,".com")
             || !strcasecmp(ext,".bat") || !strcasecmp(ext,".cmd"))) {
        interpreter = "";
    }
    if (!interpreter)
    {
        apr_status_t rv;
        char buffer[1024];
        apr_size_t bytes = sizeof(buffer);
        int i;

        /* Need to peek into the file figure out what it really is... 
         * ### aught to go back and build a cache for this one of these days.
         */
        if (((rv = apr_file_open(&fh, r->filename, APR_READ | APR_BUFFERED,
                                APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) 
         || ((rv = apr_file_read(fh, buffer, &bytes)) != APR_SUCCESS)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "Failed to read cgi file %s for testing", r->filename);
            return rv;
        }
        apr_file_close(fh);

        /* Script or executable, that is the question... */
        if ((buffer[0] == '#') && (buffer[1] == '!')) {
            /* Assuming file is a script since it starts with a shebang */
            for (i = 2; i < sizeof(buffer); i++) {
                if ((buffer[i] == '\r') || (buffer[i] == '\n')) {
                    buffer[i] = '\0';
                    break;
                }
            }
            if (i < sizeof(buffer)) {
                interpreter = buffer + 2;
                while (isspace(*interpreter))
                    ++interpreter;
            }
        }
        else {
            /* Not a script, is it an executable? */
            IMAGE_DOS_HEADER *hdr = (IMAGE_DOS_HEADER*)buffer;    
            if ((bytes >= sizeof(IMAGE_DOS_HEADER)) && (hdr->e_magic == IMAGE_DOS_SIGNATURE)) {
                if (hdr->e_lfarlc < 0x40)
                    /* Aught to invoke this 16 bit exe by a stub, (cmd /c?) */
                    interpreter = "";
                else
                    interpreter = "";
            }
        }
    }
    if (!interpreter && ext &&
        (d->script_interpreter_source == INTERPRETER_SOURCE_REGISTRY ||
         d->script_interpreter_source == INTERPRETER_SOURCE_REGISTRY_STRICT)) {
         /* Check the registry */
        int strict = (d->script_interpreter_source 
                            == INTERPRETER_SOURCE_REGISTRY_STRICT);
        interpreter = get_interpreter_from_win32_registry(r->pool, ext, strict);
        if (!interpreter) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r->server,
                 strict ? "No ExecCGI verb found for files of type '%s'."
                        : "No ExecCGI or Open verb found for files of type '%s'.", 
                 ext);
        }
    }
    if (!interpreter) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                      "%s is not executable; ensure interpreted scripts have "
                      "\"#!\" first line", 
                      r->filename);
        return APR_EBADF;
    }

    if (!args || ap_strchr_c(args, '='))
        args = "";

    *argv = (const char **)(split_argv(p, interpreter, r->filename, args)->elts);
    *cmd = (*argv)[0];
    return APR_SUCCESS;
}

APR_DECLARE_OPTIONAL_FN(apr_status_t, ap_cgi_build_command, (const char **cmd, 
                        const char ***argv, request_rec *r, apr_pool_t *p));

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(ap_cgi_build_command);
}

static const command_rec win32_cmds[] = {
AP_INIT_TAKE1("ScriptInterpreterSource", set_interpreter_source, NULL,
  OR_FILEINFO,
  "Where to find interpreter to run Win32 scripts (Registry or script shebang line)"),
{ NULL }
};

module AP_MODULE_DECLARE_DATA win32_module = {
   STANDARD20_MODULE_STUFF,
   create_win32_dir_config,     /* create per-dir config */
   merge_win32_dir_configs,     /* merge per-dir config */
   NULL,                        /* server config */
   NULL,                        /* merge server config */
   win32_cmds,                  /* command apr_table_t */
   register_hooks               /* register hooks */
};

#endif