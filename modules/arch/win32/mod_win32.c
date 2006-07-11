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

#ifdef WIN32

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
#include "mod_cgi.h"
#include "apr_lib.h"
#include "ap_regkey.h"

extern OSVERSIONINFO osver; /* hiding in mpm_winnt.c */
static int win_nt;

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
    win32_dir_conf *conf;
    conf = (win32_dir_conf*)apr_palloc(p, sizeof(win32_dir_conf));
    conf->script_interpreter_source = INTERPRETER_SOURCE_UNSET;
    return conf;
}

static void *merge_win32_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    win32_dir_conf *new;
    win32_dir_conf *base = (win32_dir_conf *) basev;
    win32_dir_conf *add = (win32_dir_conf *) addv;

    new = (win32_dir_conf *) apr_pcalloc(p, sizeof(win32_dir_conf));
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
    }
    else if (!strcasecmp(arg, "registry-strict")) {
        d->script_interpreter_source = INTERPRETER_SOURCE_REGISTRY_STRICT;
    }
    else if (!strcasecmp(arg, "script")) {
        d->script_interpreter_source = INTERPRETER_SOURCE_SHEBANG;
    }
    else {
        return apr_pstrcat(cmd->temp_pool, "ScriptInterpreterSource \"", arg,
                           "\" must be \"registry\", \"registry-strict\" or "
                           "\"script\"", NULL);
    }
    return NULL;
}

/* XXX: prep_string should translate the string into unicode,
 * such that it is compatible with whatever codepage the client
 * will read characters 80-ff.  For the moment, use the unicode
 * values 0080-00ff.  This isn't trivial, since the code page
 * varies between msdos and Windows applications.
 * For subsystem 2 [GUI] the default is the system Ansi CP.
 * For subsystem 3 [CLI] the default is the system OEM CP.
 */
static void prep_string(const char ** str, apr_pool_t *p)
{
    const char *ch = *str;
    char *ch2;
    apr_size_t widen = 0;

    if (!ch) {
        return;
    }
    while (*ch) {
        if (*(ch++) & 0x80) {
            ++widen;
        }
    }
    if (!widen) {
        return;
    }
    widen += (ch - *str) + 1;
    ch = *str;
    *str = ch2 = apr_palloc(p, widen);
    while (*ch) {
        if (*ch & 0x80) {
            /* sign extension won't hurt us here */
            *(ch2++) = 0xC0 | ((*ch >> 6) & 0x03);
            *(ch2++) = 0x80 | (*(ch++) & 0x3f);
        }
        else {
            *(ch2++) = *(ch++);
        }
    }
    *(ch2++) = '\0';
}

/* Somewhat more exciting ... figure out where the registry has stashed the
 * ExecCGI or Open command - it may be nested one level deep (or more???)
 */
static char* get_interpreter_from_win32_registry(apr_pool_t *p,
                                                 const char* ext,
                                                 int strict)
{
    apr_status_t rv;
    ap_regkey_t *name_key = NULL;
    ap_regkey_t *type_key;
    ap_regkey_t *key;
    char execcgi_path[] = "SHELL\\EXECCGI\\COMMAND";
    char execopen_path[] = "SHELL\\OPEN\\COMMAND";
    char *type_name;
    char *buffer;

    if (!ext) {
        return NULL;
    }
    /*
     * Future optimization:
     * When the registry is successfully searched, store the strings for
     * interpreter and arguments in an ext hash to speed up subsequent look-ups
     */

    /* Open the key associated with the script filetype extension */
    rv = ap_regkey_open(&type_key, AP_REGKEY_CLASSES_ROOT, ext, APR_READ, p);

    if (rv != APR_SUCCESS) {
        return NULL;
    }

    /* Retrieve the name of the script filetype extension */
    rv = ap_regkey_value_get(&type_name, type_key, "", p);

    if (rv == APR_SUCCESS && type_name[0]) {
        /* Open the key associated with the script filetype extension */
        rv = ap_regkey_open(&name_key, AP_REGKEY_CLASSES_ROOT, type_name,
                            APR_READ, p);
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

    if (name_key) {
        if ((rv = ap_regkey_open(&key, name_key, execcgi_path, APR_READ, p))
                == APR_SUCCESS) {
            rv = ap_regkey_value_get(&buffer, key, "", p);
            ap_regkey_close(name_key);
        }
    }

    if (!name_key || (rv != APR_SUCCESS)) {
        if ((rv = ap_regkey_open(&key, type_key, execcgi_path, APR_READ, p))
                == APR_SUCCESS) {
            rv = ap_regkey_value_get(&buffer, key, "", p);
            ap_regkey_close(type_key);
        }
    }

    if (!strict && name_key && (rv != APR_SUCCESS)) {
        if ((rv = ap_regkey_open(&key, name_key, execopen_path, APR_READ, p))
                == APR_SUCCESS) {
            rv = ap_regkey_value_get(&buffer, key, "", p);
            ap_regkey_close(name_key);
        }
    }

    if (!strict && (rv != APR_SUCCESS)) {
        if ((rv = ap_regkey_open(&key, type_key, execopen_path, APR_READ, p))
                == APR_SUCCESS) {
            rv = ap_regkey_value_get(&buffer, key, "", p);
            ap_regkey_close(type_key);
        }
    }

    if (name_key) {
        ap_regkey_close(name_key);
    }

    ap_regkey_close(type_key);

    if (rv != APR_SUCCESS || !buffer[0]) {
        return NULL;
    }

    return buffer;
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
        if (apr_isspace(*ch)) {
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
                if (win_nt) {
                   prep_string(&w, p);
                }
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
            if (apr_isspace(*ch) && !inquo) {
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
                if (apr_isspace(*ch) && !inquo) {
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
            if (win_nt) {
                prep_string(&w, p);
            }
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
                                         cgi_exec_info_t *e_info)
{
    const apr_array_header_t *elts_arr = apr_table_elts(r->subprocess_env);
    const apr_table_entry_t *elts = (apr_table_entry_t *) elts_arr->elts;
    const char *ext = NULL;
    const char *interpreter = NULL;
    win32_dir_conf *d;
    apr_file_t *fh;
    const char *args = "";
    int i;

    d = (win32_dir_conf *)ap_get_module_config(r->per_dir_config,
                                               &win32_module);

    if (e_info->cmd_type) {
        /* We have to consider that the client gets any QUERY_ARGS
         * without any charset interpretation, use prep_string to
         * create a string of the literal QUERY_ARGS bytes.
         */
        *cmd = r->filename;
        if (r->args && r->args[0] && !ap_strchr_c(r->args, '=')) {
            args = r->args;
        }
    }
    /* Handle the complete file name, we DON'T want to follow suexec, since
     * an unrooted command is as predictable as shooting craps in Win32.
     * Notice that unlike most mime extension parsing, we have to use the
     * win32 parsing here, therefore the final extension is the only one
     * we will consider.
     */
    ext = strrchr(apr_filepath_name_get(*cmd), '.');

    /* If the file has an extension and it is not .com and not .exe and
     * we've been instructed to search the registry, then do so.
     * Let apr_proc_create do all of the .bat/.cmd dirty work.
     */
    if (ext && (!strcasecmp(ext,".exe") || !strcasecmp(ext,".com")
                || !strcasecmp(ext,".bat") || !strcasecmp(ext,".cmd"))) {
        interpreter = "";
    }
    if (!interpreter && ext
          && (d->script_interpreter_source
                     == INTERPRETER_SOURCE_REGISTRY
           || d->script_interpreter_source
                     == INTERPRETER_SOURCE_REGISTRY_STRICT)) {
         /* Check the registry */
        int strict = (d->script_interpreter_source
                      == INTERPRETER_SOURCE_REGISTRY_STRICT);
        interpreter = get_interpreter_from_win32_registry(r->pool, ext,
                                                          strict);
        if (interpreter && e_info->cmd_type != APR_SHELLCMD) {
            e_info->cmd_type = APR_PROGRAM_PATH;
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                 strict ? "No ExecCGI verb found for files of type '%s'."
                        : "No ExecCGI or Open verb found for files of type '%s'.",
                 ext);
        }
    }
    if (!interpreter) {
        apr_status_t rv;
        char buffer[1024];
        apr_size_t bytes = sizeof(buffer);
        apr_size_t i;

        /* Need to peek into the file figure out what it really is...
         * ### aught to go back and build a cache for this one of these days.
         */
        if ((rv = apr_file_open(&fh, *cmd, APR_READ | APR_BUFFERED,
                                 APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "Failed to open cgi file %s for testing", *cmd);
            return rv;
        }
        if ((rv = apr_file_read(fh, buffer, &bytes)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "Failed to read cgi file %s for testing", *cmd);
            return rv;
        }
        apr_file_close(fh);

        /* Some twisted character [no pun intended] at MS decided that a
         * zero width joiner as the lead wide character would be ideal for
         * describing Unicode text files.  This was further convoluted to
         * another MSism that the same character mapped into utf-8, EF BB BF
         * would signify utf-8 text files.
         *
         * Since MS configuration files are all protecting utf-8 encoded
         * Unicode path, file and resource names, we already have the correct
         * WinNT encoding.  But at least eat the stupid three bytes up front.
         *
         * ### A more thorough check would also allow UNICODE text in buf, and
         * convert it to UTF-8 for invoking unicode scripts.  Those are few
         * and far between, so leave that code an enterprising soul with a need.
         */
        if ((bytes >= 3) && memcmp(buffer, "\xEF\xBB\xBF", 3) == 0) {
            memmove(buffer, buffer + 3, bytes -= 3);
        }

        /* Script or executable, that is the question... */
        if ((bytes >= 2) && (buffer[0] == '#') && (buffer[1] == '!')) {
            /* Assuming file is a script since it starts with a shebang */
            for (i = 2; i < bytes; i++) {
                if ((buffer[i] == '\r') || (buffer[i] == '\n')) {
                    buffer[i] = '\0';
                    break;
                }
            }
            if (i < bytes) {
                interpreter = buffer + 2;
                while (apr_isspace(*interpreter)) {
                    ++interpreter;
                }
                if (e_info->cmd_type != APR_SHELLCMD) {
                    e_info->cmd_type = APR_PROGRAM_PATH;
                }
            }
        }
        else if (bytes >= sizeof(IMAGE_DOS_HEADER)) {
            /* Not a script, is it an executable? */
            IMAGE_DOS_HEADER *hdr = (IMAGE_DOS_HEADER*)buffer;
            if (hdr->e_magic == IMAGE_DOS_SIGNATURE) {
                if (hdr->e_lfarlc < 0x40) {
                    /* Ought to invoke this 16 bit exe by a stub, (cmd /c?) */
                    interpreter = "";
                }
                else {
                    interpreter = "";
                }
            }
        }
    }
    if (!interpreter) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "%s is not executable; ensure interpreted scripts have "
                      "\"#!\" first line", *cmd);
        return APR_EBADF;
    }

    *argv = (const char **)(split_argv(p, interpreter, *cmd,
                                       args)->elts);
    *cmd = (*argv)[0];

    e_info->detached = 1;

    /* XXX: Must fix r->subprocess_env to follow utf-8 conventions from
     * the client's octets so that win32 apr_proc_create is happy.
     * The -best- way is to determine if the .exe is unicode aware
     * (using 0x0080-0x00ff) or is linked as a command or windows
     * application (following the OEM or Ansi code page in effect.)
     */
    for (i = 0; i < elts_arr->nelts; ++i) {
        if (win_nt && elts[i].key && *elts[i].key
                && (strncmp(elts[i].key, "HTTP_", 5) == 0
                 || strncmp(elts[i].key, "SERVER_", 7) == 0
                 || strncmp(elts[i].key, "REQUEST_", 8) == 0
                 || strcmp(elts[i].key, "QUERY_STRING") == 0
                 || strcmp(elts[i].key, "PATH_INFO") == 0
                 || strcmp(elts[i].key, "PATH_TRANSLATED") == 0)) {
            prep_string((const char**) &elts[i].val, r->pool);
        }
    }
    return APR_SUCCESS;
}

static int win32_pre_config(apr_pool_t *pconf_, apr_pool_t *plog, apr_pool_t *ptemp)
{
    win_nt = (osver.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS);
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(ap_cgi_build_command);
    ap_hook_pre_config(win32_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec win32_cmds[] = {
AP_INIT_TAKE1("ScriptInterpreterSource", set_interpreter_source, NULL,
              OR_FILEINFO,
              "Where to find interpreter to run Win32 scripts "
              "(Registry or script shebang line)"),
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

#endif /* defined WIN32 */
