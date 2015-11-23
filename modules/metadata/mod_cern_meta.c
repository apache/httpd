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
 * mod_cern_meta.c
 * version 0.1.0
 * status beta
 *
 * Andrew Wilson <Andrew.Wilson@cm.cf.ac.uk> 25.Jan.96
 *
 * *** IMPORTANT ***
 * This version of mod_cern_meta.c controls Meta File behaviour on a
 * per-directory basis.  Previous versions of the module defined behaviour
 * on a per-server basis.  The upshot is that you'll need to revisit your
 * configuration files in order to make use of the new module.
 * ***
 *
 * Emulate the CERN HTTPD Meta file semantics.  Meta files are HTTP
 * headers that can be output in addition to the normal range of
 * headers for each file accessed.  They appear rather like the Apache
 * .asis files, and are able to provide a crude way of influencing
 * the Expires: header, as well as providing other curiosities.
 * There are many ways to manage meta information, this one was
 * chosen because there is already a large number of CERN users
 * who can exploit this module.  It should be noted that there are probably
 * more sensitive ways of managing the Expires: header specifically.
 *
 * The module obeys the following directives, which can appear
 * in the server's .conf files and in .htaccess files.
 *
 *  MetaFiles <on|off>
 *
 *    turns on|off meta file processing for any directory.
 *    Default value is off
 *
 *        # turn on MetaFiles in this directory
 *        MetaFiles on
 *
 *  MetaDir <directory name>
 *
 *    specifies the name of the directory in which Apache can find
 *    meta information files.  The directory is usually a 'hidden'
 *    subdirectory of the directory that contains the file being
 *    accessed.  eg:
 *
 *        # .meta files are in the *same* directory as the
 *        # file being accessed
 *        MetaDir .
 *
 *    the default is to look in a '.web' subdirectory. This is the
 *    same as for CERN 3.+ webservers and behaviour is the same as
 *    for the directive:
 *
 *        MetaDir .web
 *
 *  MetaSuffix <meta file suffix>
 *
 *    specifies the file name suffix for the file containing the
 *    meta information.  eg:
 *
 *       # our meta files are suffixed with '.cern_meta'
 *       MetaSuffix .cern_meta
 *
 *    the default is to look for files with the suffix '.meta'.  This
 *    behaviour is the same as for the directive:
 *
 *       MetaSuffix .meta
 *
 * When accessing the file
 *
 *   DOCUMENT_ROOT/somedir/index.html
 *
 * this module will look for the file
 *
 *   DOCUMENT_ROOT/somedir/.web/index.html.meta
 *
 * and will use its contents to generate additional MIME header
 * information.
 *
 * For more information on the CERN Meta file semantics see:
 *
 *   http://www.w3.org/hypertext/WWW/Daemon/User/Config/General.html#MetaDir
 *
 * Change-log:
 * 29.Jan.96 pfopen/pfclose instead of fopen/fclose
 *           DECLINE when real file not found, we may be checking each
 *           of the index.html/index.shtml/index.htm variants and don't
 *           need to report missing ones as spurious errors.
 * 31.Jan.96 log_error reports about a malformed .meta file, rather
 *           than a script error.
 * 20.Jun.96 MetaFiles <on|off> default off, added, so that module
 *           can be configured per-directory.  Prior to this the module
 *           was running for each request anywhere on the server, naughty..
 * 29.Jun.96 All directives made per-directory.
 */

#include "apr.h"
#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "util_script.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"
#include "apr_lib.h"

#define DIR_CMD_PERMS OR_INDEXES

#define DEFAULT_METADIR     ".web"
#define DEFAULT_METASUFFIX  ".meta"
#define DEFAULT_METAFILES   0

module AP_MODULE_DECLARE_DATA cern_meta_module;

typedef struct {
    const char *metadir;
    const char *metasuffix;
    int metafiles;
} cern_meta_dir_config;

static void *create_cern_meta_dir_config(apr_pool_t *p, char *dummy)
{
    cern_meta_dir_config *new =
    (cern_meta_dir_config *) apr_palloc(p, sizeof(cern_meta_dir_config));

    new->metadir = NULL;
    new->metasuffix = NULL;
    new->metafiles = DEFAULT_METAFILES;

    return new;
}

static void *merge_cern_meta_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    cern_meta_dir_config *base = (cern_meta_dir_config *) basev;
    cern_meta_dir_config *add = (cern_meta_dir_config *) addv;
    cern_meta_dir_config *new =
    (cern_meta_dir_config *) apr_palloc(p, sizeof(cern_meta_dir_config));

    new->metadir = add->metadir ? add->metadir : base->metadir;
    new->metasuffix = add->metasuffix ? add->metasuffix : base->metasuffix;
    new->metafiles = add->metafiles;

    return new;
}

static const char *set_metadir(cmd_parms *parms, void *in_dconf, const char *arg)
{
    cern_meta_dir_config *dconf = in_dconf;

    dconf->metadir = arg;
    return NULL;
}

static const char *set_metasuffix(cmd_parms *parms, void *in_dconf, const char *arg)
{
    cern_meta_dir_config *dconf = in_dconf;

    dconf->metasuffix = arg;
    return NULL;
}

static const char *set_metafiles(cmd_parms *parms, void *in_dconf, int arg)
{
    cern_meta_dir_config *dconf = in_dconf;

    dconf->metafiles = arg;
    return NULL;
}


static const command_rec cern_meta_cmds[] =
{
    AP_INIT_FLAG("MetaFiles", set_metafiles, NULL, DIR_CMD_PERMS,
                 "Limited to 'on' or 'off'"),
    AP_INIT_TAKE1("MetaDir", set_metadir, NULL, DIR_CMD_PERMS,
                  "the name of the directory containing meta files"),
    AP_INIT_TAKE1("MetaSuffix", set_metasuffix, NULL, DIR_CMD_PERMS,
                  "the filename suffix for meta files"),
    {NULL}
};

/* XXX: this is very similar to ap_scan_script_header_err_core...
 * are the differences deliberate, or just a result of bit rot?
 */
static int scan_meta_file(request_rec *r, apr_file_t *f)
{
    char w[MAX_STRING_LEN];
    char *l;
    int p;
    apr_table_t *tmp_headers;

    tmp_headers = apr_table_make(r->pool, 5);
    while (apr_file_gets(w, MAX_STRING_LEN - 1, f) == APR_SUCCESS) {

    /* Delete terminal (CR?)LF */
        p = strlen(w);
        if (p > 0 && w[p - 1] == '\n') {
            if (p > 1 && w[p - 2] == '\015')
                w[p - 2] = '\0';
            else
                w[p - 1] = '\0';
        }

        if (w[0] == '\0') {
            return OK;
        }

        /* if we see a bogus header don't ignore it. Shout and scream */

        if (!(l = strchr(w, ':'))) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01560)
                "malformed header in meta file: %s", r->filename);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        *l++ = '\0';
        while (apr_isspace(*l))
            ++l;

        if (!strcasecmp(w, "Content-type")) {
            char *tmp;
            /* Nuke trailing whitespace */

            char *endp = l + strlen(l) - 1;
            while (endp > l && apr_isspace(*endp))
                *endp-- = '\0';

            tmp = apr_pstrdup(r->pool, l);
            ap_content_type_tolower(tmp);
            ap_set_content_type(r, tmp);
        }
        else if (!strcasecmp(w, "Status")) {
            sscanf(l, "%d", &r->status);
            r->status_line = apr_pstrdup(r->pool, l);
        }
        else {
            apr_table_set(tmp_headers, w, l);
        }
    }
    apr_table_overlap(r->headers_out, tmp_headers, APR_OVERLAP_TABLES_SET);
    return OK;
}

static int add_cern_meta_data(request_rec *r)
{
    char *metafilename;
    char *leading_slash;
    char *last_slash;
    char *real_file;
    char *scrap_book;
    apr_file_t *f = NULL;
    apr_status_t retcode;
    cern_meta_dir_config *dconf;
    int rv;
    request_rec *rr;

    dconf = ap_get_module_config(r->per_dir_config, &cern_meta_module);

    if (!dconf->metafiles) {
        return DECLINED;
    }

    /* if ./.web/$1.meta exists then output 'asis' */

    if (r->finfo.filetype == APR_NOFILE) {
        return DECLINED;
    }

    /* is this a directory? */
    if (r->finfo.filetype == APR_DIR || r->uri[strlen(r->uri) - 1] == '/') {
        return DECLINED;
    }

    /* what directory is this file in? */
    scrap_book = apr_pstrdup(r->pool, r->filename);

    leading_slash = strchr(scrap_book, '/');
    last_slash = strrchr(scrap_book, '/');
    if ((last_slash != NULL) && (last_slash != leading_slash)) {
        /* skip over last slash */
        real_file = last_slash;
        real_file++;
        *last_slash = '\0';
    }
    else {
        /* no last slash, buh?! */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01561)
            "internal error in mod_cern_meta: %s", r->filename);
        /* should really barf, but hey, let's be friends... */
        return DECLINED;
    }

    metafilename = apr_pstrcat(r->pool, scrap_book, "/",
               dconf->metadir ? dconf->metadir : DEFAULT_METADIR,
               "/", real_file,
         dconf->metasuffix ? dconf->metasuffix : DEFAULT_METASUFFIX,
               NULL);

    /* It sucks to require this subrequest to complete, because this
     * means people must leave their meta files accessible to the world.
     * A better solution might be a "safe open" feature of pfopen to avoid
     * pipes, symlinks, and crap like that.
     *
     * In fact, this doesn't suck.  Because <Location > blocks are never run
     * against sub_req_lookup_file, the meta can be somewhat protected by
     * either masking it with a <Location > directive or alias, or stowing
     * the file outside of the web document tree, while providing the
     * appropriate directory blocks to allow access to it as a file.
     */
    rr = ap_sub_req_lookup_file(metafilename, r, NULL);
    if (rr->status != HTTP_OK) {
        ap_destroy_sub_req(rr);
        return DECLINED;
    }
    ap_destroy_sub_req(rr);

    retcode = apr_file_open(&f, metafilename, APR_READ, APR_OS_DEFAULT, r->pool);
    if (retcode != APR_SUCCESS) {
        if (APR_STATUS_IS_ENOENT(retcode)) {
            return DECLINED;
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01562)
            "meta file permissions deny server access: %s", metafilename);
        return HTTP_FORBIDDEN;
    }

    /* read the headers in */
    rv = scan_meta_file(r, f);
    apr_file_close(f);

    return rv;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(add_cern_meta_data,NULL,NULL,APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(cern_meta) =
{
    STANDARD20_MODULE_STUFF,
    create_cern_meta_dir_config, /* dir config creater */
    merge_cern_meta_dir_configs, /* dir merger --- default is to override */
    NULL,                        /* server config */
    NULL,                        /* merge server configs */
    cern_meta_cmds,              /* command apr_table_t */
    register_hooks               /* register hooks */
};
