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

/*                       _                            _ _
**   _ __ ___   ___   __| |    _ __ _____      ___ __(_) |_ ___
**  | '_ ` _ \ / _ \ / _` |   | '__/ _ \ \ /\ / / '__| | __/ _ \
**  | | | | | | (_) | (_| |   | | |  __/\ V  V /| |  | | ||  __/
**  |_| |_| |_|\___/ \__,_|___|_|  \___| \_/\_/ |_|  |_|\__\___|
**                       |_____|
**
**  URL Rewriting Module
**
**  This module uses a rule-based rewriting engine (based on a
**  regular-expression parser) to rewrite requested URLs on the fly.
**
**  It supports an unlimited number of additional rule conditions (which can
**  operate on a lot of variables, even on HTTP headers) for granular
**  matching and even external database lookups (either via plain text
**  tables, DBM hash files or even external processes) for advanced URL
**  substitution.
**
**  It operates on the full URLs (including the PATH_INFO part) both in
**  per-server context (httpd.conf) and per-dir context (.htaccess) and even
**  can generate QUERY_STRING parts on result.   The rewriting result finally
**  can lead to internal subprocessing, external request redirection or even
**  to internal proxy throughput.
**
**  This module was originally written in April 1996 and
**  gifted exclusively to the The Apache Software Foundation in July 1997 by
**
**      Ralf S. Engelschall
**      rse@engelschall.com
**      www.engelschall.com
*/

#include "apr.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_user.h"
#include "apr_lib.h"
#include "apr_signal.h"
#include "apr_global_mutex.h"

#define APR_WANT_STRFUNC
#define APR_WANT_IOVEC
#include "apr_want.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "mod_rewrite.h"

#if !defined(OS2) && !defined(WIN32) && !defined(BEOS)  && !defined(NETWARE)
#include "unixd.h"
#endif

/*
** +-------------------------------------------------------+
** |                                                       |
** |             static module configuration
** |                                                       |
** +-------------------------------------------------------+
*/


/*
**  Our interface to the Apache server kernel:
**
**  o  Runtime logic of a request is as following:
**       while(request or subrequest)
**           foreach(stage #0...#9)
**               foreach(module) (**)
**                   try to run hook
**
**  o  the order of modules at (**) is the inverted order as
**     given in the "Configuration" file, i.e. the last module
**     specified is the first one called for each hook!
**     The core module is always the last!
**
**  o  there are two different types of result checking and
**     continue processing:
**     for hook #0,#1,#4,#5,#6,#8:
**         hook run loop stops on first modules which gives
**         back a result != DECLINED, i.e. it usually returns OK
**         which says "OK, module has handled this _stage_" and for #1
**         this have not to mean "Ok, the filename is now valid".
**     for hook #2,#3,#7,#9:
**         all hooks are run, independend of result
**
**  o  at the last stage, the core module always
**       - says "HTTP_BAD_REQUEST" if r->filename does not begin with "/"
**       - prefix URL with document_root or replaced server_root
**         with document_root and sets r->filename
**       - always return a "OK" independed if the file really exists
**         or not!
*/

    /* the module (predeclaration) */
module AP_MODULE_DECLARE_DATA rewrite_module;

    /* rewritemap int: handler function registry */
static apr_hash_t *mapfunc_hash;

    /* the cache */
static cache *cachep;

    /* whether proxy module is available or not */
static int proxy_available;

static const char *lockname;
static apr_global_mutex_t *rewrite_mapr_lock_acquire = NULL;
static apr_global_mutex_t *rewrite_log_lock = NULL;

/*
** +-------------------------------------------------------+
** |                                                       |
** |           configuration directive handling
** |                                                       |
** +-------------------------------------------------------+
*/

/*
**
**  per-server configuration structure handling
**
*/

static void *config_server_create(apr_pool_t *p, server_rec *s)
{
    rewrite_server_conf *a;

    a = (rewrite_server_conf *)apr_pcalloc(p, sizeof(rewrite_server_conf));

    a->state           = ENGINE_DISABLED;
    a->options         = OPTION_NONE;
    a->rewritelogfile  = NULL;
    a->rewritelogfp    = NULL;
    a->rewriteloglevel = 0;
    a->rewritemaps     = apr_array_make(p, 2, sizeof(rewritemap_entry));
    a->rewriteconds    = apr_array_make(p, 2, sizeof(rewritecond_entry));
    a->rewriterules    = apr_array_make(p, 2, sizeof(rewriterule_entry));
    a->server          = s;
    a->redirect_limit  = 0; /* unset (use default) */

    return (void *)a;
}

static void *config_server_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    rewrite_server_conf *a, *base, *overrides;

    a         = (rewrite_server_conf *)apr_pcalloc(p,
                                                   sizeof(rewrite_server_conf));
    base      = (rewrite_server_conf *)basev;
    overrides = (rewrite_server_conf *)overridesv;

    a->state   = overrides->state;
    a->options = overrides->options;
    a->server  = overrides->server;
    a->redirect_limit = overrides->redirect_limit
                          ? overrides->redirect_limit
                          : base->redirect_limit;

    if (a->options & OPTION_INHERIT) {
        /*
         *  local directives override
         *  and anything else is inherited
         */
        a->rewriteloglevel = overrides->rewriteloglevel != 0
                             ? overrides->rewriteloglevel
                             : base->rewriteloglevel;
        a->rewritelogfile  = overrides->rewritelogfile != NULL
                             ? overrides->rewritelogfile
                             : base->rewritelogfile;
        a->rewritelogfp    = overrides->rewritelogfp != NULL
                             ? overrides->rewritelogfp
                             : base->rewritelogfp;
        a->rewritemaps     = apr_array_append(p, overrides->rewritemaps,
                                              base->rewritemaps);
        a->rewriteconds    = apr_array_append(p, overrides->rewriteconds,
                                              base->rewriteconds);
        a->rewriterules    = apr_array_append(p, overrides->rewriterules,
                                              base->rewriterules);
    }
    else {
        /*
         *  local directives override
         *  and anything else gets defaults
         */
        a->rewriteloglevel = overrides->rewriteloglevel;
        a->rewritelogfile  = overrides->rewritelogfile;
        a->rewritelogfp    = overrides->rewritelogfp;
        a->rewritemaps     = overrides->rewritemaps;
        a->rewriteconds    = overrides->rewriteconds;
        a->rewriterules    = overrides->rewriterules;
    }

    return (void *)a;
}


/*
**
**  per-directory configuration structure handling
**
*/

static void *config_perdir_create(apr_pool_t *p, char *path)
{
    rewrite_perdir_conf *a;

    a = (rewrite_perdir_conf *)apr_pcalloc(p, sizeof(rewrite_perdir_conf));

    a->state           = ENGINE_DISABLED;
    a->options         = OPTION_NONE;
    a->baseurl         = NULL;
    a->rewriteconds    = apr_array_make(p, 2, sizeof(rewritecond_entry));
    a->rewriterules    = apr_array_make(p, 2, sizeof(rewriterule_entry));
    a->redirect_limit  = 0; /* unset (use server config) */

    if (path == NULL) {
        a->directory = NULL;
    }
    else {
        /* make sure it has a trailing slash */
        if (path[strlen(path)-1] == '/') {
            a->directory = apr_pstrdup(p, path);
        }
        else {
            a->directory = apr_pstrcat(p, path, "/", NULL);
        }
    }

    return (void *)a;
}

static void *config_perdir_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    rewrite_perdir_conf *a, *base, *overrides;

    a         = (rewrite_perdir_conf *)apr_pcalloc(p,
                                                  sizeof(rewrite_perdir_conf));
    base      = (rewrite_perdir_conf *)basev;
    overrides = (rewrite_perdir_conf *)overridesv;

    a->state     = overrides->state;
    a->options   = overrides->options;
    a->directory = overrides->directory;
    a->baseurl   = overrides->baseurl;
    a->redirect_limit = overrides->redirect_limit
                          ? overrides->redirect_limit
                          : base->redirect_limit;

    if (a->options & OPTION_INHERIT) {
        a->rewriteconds = apr_array_append(p, overrides->rewriteconds,
                                           base->rewriteconds);
        a->rewriterules = apr_array_append(p, overrides->rewriterules,
                                           base->rewriterules);
    }
    else {
        a->rewriteconds = overrides->rewriteconds;
        a->rewriterules = overrides->rewriterules;
    }

    return (void *)a;
}


/*
**
**  the configuration commands
**
*/

static const char *cmd_rewriteengine(cmd_parms *cmd,
                                     void *in_dconf, int flag)
{
    rewrite_perdir_conf *dconf = in_dconf;
    rewrite_server_conf *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    if (cmd->path == NULL) { /* is server command */
        sconf->state = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
    }
    else                   /* is per-directory command */ {
        dconf->state = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
    }

    return NULL;
}

static const char *cmd_rewriteoptions(cmd_parms *cmd,
                                      void *in_dconf, const char *option)
{
    int options = 0, limit = 0;
    char *w;

    while (*option) {
        w = ap_getword_conf(cmd->pool, &option);

        if (!strcasecmp(w, "inherit")) {
            options |= OPTION_INHERIT;
        }
        else if (!strncasecmp(w, "MaxRedirects=", 13)) {
            limit = atoi(&w[13]);
            if (limit <= 0) {
                return "RewriteOptions: MaxRedirects takes a number greater "
                       "than zero.";
            }
        }
        else if (!strcasecmp(w, "MaxRedirects")) { /* be nice */
            return "RewriteOptions: MaxRedirects has the format MaxRedirects"
                   "=n.";
        }
        else {
            return apr_pstrcat(cmd->pool, "RewriteOptions: unknown option '",
                               w, "'", NULL);
        }
    }

    /* put it into the appropriate config */
    if (cmd->path == NULL) { /* is server command */
        rewrite_server_conf *conf =
            ap_get_module_config(cmd->server->module_config,
                                 &rewrite_module);

        conf->options |= options;
        conf->redirect_limit = limit;
    }
    else {                  /* is per-directory command */
        rewrite_perdir_conf *conf = in_dconf;

        conf->options |= options;
        conf->redirect_limit = limit;
    }

    return NULL;
}

static const char *cmd_rewritelog(cmd_parms *cmd, void *dconf, const char *a1)
{
    rewrite_server_conf *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    sconf->rewritelogfile = a1;

    return NULL;
}

static const char *cmd_rewriteloglevel(cmd_parms *cmd, void *dconf,
                                       const char *a1)
{
    rewrite_server_conf *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    sconf->rewriteloglevel = atoi(a1);

    return NULL;
}

static const char *cmd_rewritemap(cmd_parms *cmd, void *dconf, const char *a1,
                                  const char *a2)
{
    rewrite_server_conf *sconf;
    rewritemap_entry *newmap;
    apr_finfo_t st;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    newmap = apr_array_push(sconf->rewritemaps);

    newmap->name = a1;
    newmap->func = NULL;
    if (strncmp(a2, "txt:", 4) == 0) {
        newmap->type      = MAPTYPE_TXT;
        newmap->datafile  = a2+4;
        newmap->checkfile = a2+4;
    }
    else if (strncmp(a2, "rnd:", 4) == 0) {
        newmap->type      = MAPTYPE_RND;
        newmap->datafile  = a2+4;
        newmap->checkfile = a2+4;
    }
    else if (strncmp(a2, "dbm", 3) == 0) {
        const char *ignored_fname;
        int bad = 0;
        apr_status_t rv;

        newmap->type = MAPTYPE_DBM;

        if (a2[3] == ':') {
            newmap->dbmtype    = "default";
            newmap->datafile   = a2+4;
        }
        else if (a2[3] == '=') {
            const char *colon = ap_strchr_c(a2 + 4, ':');

            if (colon) {
                newmap->dbmtype = apr_pstrndup(cmd->pool, a2 + 4,
                                               colon - (a2 + 3) - 1);
                newmap->datafile = colon + 1;
            }
            else {
                ++bad;
            }
        }
        else {
            ++bad;
        }

        if (bad) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad map:",
                               a2, NULL);
        }

        rv = apr_dbm_get_usednames_ex(cmd->pool, newmap->dbmtype,
                                      newmap->datafile, &newmap->checkfile,
                                      &ignored_fname);
        if (rv != APR_SUCCESS) {
            return apr_pstrcat(cmd->pool, "RewriteMap: dbm type ",
                               newmap->dbmtype, " is invalid", NULL);
        }
    }
    else if (strncmp(a2, "prg:", 4) == 0) {
        newmap->type      = MAPTYPE_PRG;
        apr_tokenize_to_argv(a2 + 4, &newmap->argv, cmd->pool);
        newmap->datafile  = NULL;
        newmap->checkfile = newmap->argv[0];

    }
    else if (strncmp(a2, "int:", 4) == 0) {
        newmap->type      = MAPTYPE_INT;
        newmap->datafile  = NULL;
        newmap->checkfile = NULL;
        newmap->func      = (char *(*)(request_rec *,char *))
                            apr_hash_get(mapfunc_hash, a2+4, strlen(a2+4));
        if ((sconf->state == ENGINE_ENABLED) && (newmap->func == NULL)) {
            return apr_pstrcat(cmd->pool, "RewriteMap: internal map not found:",
                               a2+4, NULL);
        }
    }
    else {
        newmap->type      = MAPTYPE_TXT;
        newmap->datafile  = a2;
        newmap->checkfile = a2;
    }
    newmap->fpin  = NULL;
    newmap->fpout = NULL;

    if (newmap->checkfile && (sconf->state == ENGINE_ENABLED)
        && (apr_stat(&st, newmap->checkfile, APR_FINFO_MIN,
                     cmd->pool) != APR_SUCCESS)) {
        return apr_pstrcat(cmd->pool,
                           "RewriteMap: file for map ", newmap->name,
                           " not found:", newmap->checkfile, NULL);
    }

    return NULL;
}

static const char *cmd_rewritelock(cmd_parms *cmd, void *dconf, const char *a1)
{
    const char *error;

    if ((error = ap_check_cmd_context(cmd, GLOBAL_ONLY)) != NULL)
        return error;

    /* fixup the path, especially for rewritelock_remove() */
    lockname = ap_server_root_relative(cmd->pool, a1);

    if (!lockname) {
        return apr_pstrcat(cmd->pool, "Invalid RewriteLock path ", a1);
    }

    return NULL;
}

static const char *cmd_rewritebase(cmd_parms *cmd, void *in_dconf,
                                   const char *a1)
{
    rewrite_perdir_conf *dconf = in_dconf;

    if (cmd->path == NULL || dconf == NULL) {
        return "RewriteBase: only valid in per-directory config files";
    }
    if (a1[0] == '\0') {
        return "RewriteBase: empty URL not allowed";
    }
    if (a1[0] != '/') {
        return "RewriteBase: argument is not a valid URL";
    }

    dconf->baseurl = a1;

    return NULL;
}

static const char *cmd_rewritecond(cmd_parms *cmd, void *in_dconf,
                                   const char *in_str)
{
    rewrite_perdir_conf *dconf = in_dconf;
    char *str = apr_pstrdup(cmd->pool, in_str);
    rewrite_server_conf *sconf;
    rewritecond_entry *newcond;
    regex_t *regexp;
    char *a1;
    char *a2;
    char *a3;
    char *cp;
    const char *err;
    int rc;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    /*  make a new entry in the internal temporary rewrite rule list */
    if (cmd->path == NULL) {   /* is server command */
        newcond = apr_array_push(sconf->rewriteconds);
    }
    else {                     /* is per-directory command */
        newcond = apr_array_push(dconf->rewriteconds);
    }

    /*  parse the argument line ourself */
    if (parseargline(str, &a1, &a2, &a3)) {
        return apr_pstrcat(cmd->pool, "RewriteCond: bad argument line '", str,
                           "'", NULL);
    }

    /*  arg1: the input string */
    newcond->input = apr_pstrdup(cmd->pool, a1);

    /* arg3: optional flags field
       (this have to be first parsed, because we need to
        know if the regex should be compiled with ICASE!) */
    newcond->flags = CONDFLAG_NONE;
    if (a3 != NULL) {
        if ((err = cmd_rewritecond_parseflagfield(cmd->pool, newcond,
                                                  a3)) != NULL) {
            return err;
        }
    }

    /*  arg2: the pattern
        try to compile the regexp to test if is ok */
    cp = a2;
    if (cp[0] == '!') {
        newcond->flags |= CONDFLAG_NOTMATCH;
        cp++;
    }

    /* now be careful: Under the POSIX regex library
       we can compile the pattern for case insensitive matching,
       under the old V8 library we have to do it self via a hack */
    if (newcond->flags & CONDFLAG_NOCASE) {
        rc = ((regexp = ap_pregcomp(cmd->pool, cp, REG_EXTENDED|REG_ICASE))
              == NULL);
    }
    else {
        rc = ((regexp = ap_pregcomp(cmd->pool, cp, REG_EXTENDED)) == NULL);
    }
    if (rc) {
        return apr_pstrcat(cmd->pool,
                           "RewriteCond: cannot compile regular expression '",
                           a2, "'", NULL);
    }

    newcond->pattern = apr_pstrdup(cmd->pool, cp);
    newcond->regexp  = regexp;

    return NULL;
}

static const char *cmd_rewritecond_parseflagfield(apr_pool_t *p,
                                                  rewritecond_entry *cfg,
                                                  char *str)
{
    char *cp;
    char *cp1;
    char *cp2;
    char *cp3;
    char *key;
    char *val;
    const char *err;

    if (str[0] != '[' || str[strlen(str)-1] != ']') {
        return "RewriteCond: bad flag delimiters";
    }

    cp = str+1;
    str[strlen(str)-1] = ','; /* for simpler parsing */
    for ( ; *cp != '\0'; ) {
        /* skip whitespaces */
        for ( ; (*cp == ' ' || *cp == '\t') && *cp != '\0'; cp++)
            ;
        if (*cp == '\0') {
            break;
        }
        cp1 = cp;
        if ((cp2 = strchr(cp, ',')) != NULL) {
            cp = cp2+1;
            for ( ; (*(cp2-1) == ' ' || *(cp2-1) == '\t'); cp2--)
                ;
            *cp2 = '\0';
            if ((cp3 = strchr(cp1, '=')) != NULL) {
                *cp3 = '\0';
                key = cp1;
                val = cp3+1;
            }
            else {
                key = cp1;
                val = "";
            }
            if ((err = cmd_rewritecond_setflag(p, cfg, key, val)) != NULL) {
                return err;
            }
        }
        else {
            break;
        }
    }

    return NULL;
}

static const char *cmd_rewritecond_setflag(apr_pool_t *p,
                                           rewritecond_entry *cfg,
                                           char *key, char *val)
{
    if (   strcasecmp(key, "nocase") == 0
        || strcasecmp(key, "NC") == 0    ) {
        cfg->flags |= CONDFLAG_NOCASE;
    }
    else if (   strcasecmp(key, "ornext") == 0
             || strcasecmp(key, "OR") == 0    ) {
        cfg->flags |= CONDFLAG_ORNEXT;
    }
    else {
        return apr_pstrcat(p, "RewriteCond: unknown flag '", key, "'", NULL);
    }
    return NULL;
}

static const char *cmd_rewriterule(cmd_parms *cmd, void *in_dconf,
                                   const char *in_str)
{
    rewrite_perdir_conf *dconf = in_dconf;
    char *str = apr_pstrdup(cmd->pool, in_str);
    rewrite_server_conf *sconf;
    rewriterule_entry *newrule;
    regex_t *regexp;
    char *a1;
    char *a2;
    char *a3;
    char *cp;
    const char *err;
    int mode;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    /*  make a new entry in the internal rewrite rule list */
    if (cmd->path == NULL) {   /* is server command */
        newrule = apr_array_push(sconf->rewriterules);
    }
    else {                     /* is per-directory command */
        newrule = apr_array_push(dconf->rewriterules);
    }

    /*  parse the argument line ourself */
    if (parseargline(str, &a1, &a2, &a3)) {
        return apr_pstrcat(cmd->pool, "RewriteRule: bad argument line '", str,
                           "'", NULL);
    }

    /* arg3: optional flags field */
    newrule->forced_mimetype     = NULL;
    newrule->forced_responsecode = HTTP_MOVED_TEMPORARILY;
    newrule->flags  = RULEFLAG_NONE;
    newrule->env[0] = NULL;
    newrule->cookie[0] = NULL;
    newrule->skip   = 0;
    if (a3 != NULL) {
        if ((err = cmd_rewriterule_parseflagfield(cmd->pool, newrule,
                                                  a3)) != NULL) {
            return err;
        }
    }

    /*  arg1: the pattern
     *  try to compile the regexp to test if is ok
     */
    cp = a1;
    if (cp[0] == '!') {
        newrule->flags |= RULEFLAG_NOTMATCH;
        cp++;
    }
    mode = REG_EXTENDED;
    if (newrule->flags & RULEFLAG_NOCASE) {
        mode |= REG_ICASE;
    }
    if ((regexp = ap_pregcomp(cmd->pool, cp, mode)) == NULL) {
        return apr_pstrcat(cmd->pool,
                           "RewriteRule: cannot compile regular expression '",
                           a1, "'", NULL);
    }
    newrule->pattern = apr_pstrdup(cmd->pool, cp);
    newrule->regexp  = regexp;

    /*  arg2: the output string
     *  replace the $<N> by \<n> which is needed by the currently
     *  used Regular Expression library
     *
     * TODO: Is this still required for PCRE?  If not, does it *work* with PCRE?
     */
    newrule->output = apr_pstrdup(cmd->pool, a2);

    /* now, if the server or per-dir config holds an
     * array of RewriteCond entries, we take it for us
     * and clear the array
     */
    if (cmd->path == NULL) {  /* is server command */
        newrule->rewriteconds   = sconf->rewriteconds;
        sconf->rewriteconds = apr_array_make(cmd->pool, 2,
                                            sizeof(rewritecond_entry));
    }
    else {                    /* is per-directory command */
        newrule->rewriteconds   = dconf->rewriteconds;
        dconf->rewriteconds = apr_array_make(cmd->pool, 2,
                                            sizeof(rewritecond_entry));
    }

    return NULL;
}

static const char *cmd_rewriterule_parseflagfield(apr_pool_t *p,
                                                  rewriterule_entry *cfg,
                                                  char *str)
{
    char *cp;
    char *cp1;
    char *cp2;
    char *cp3;
    char *key;
    char *val;
    const char *err;

    if (str[0] != '[' || str[strlen(str)-1] != ']') {
        return "RewriteRule: bad flag delimiters";
    }

    cp = str+1;
    str[strlen(str)-1] = ','; /* for simpler parsing */
    for ( ; *cp != '\0'; ) {
        /* skip whitespaces */
        for ( ; (*cp == ' ' || *cp == '\t') && *cp != '\0'; cp++)
            ;
        if (*cp == '\0') {
            break;
        }
        cp1 = cp;
        if ((cp2 = strchr(cp, ',')) != NULL) {
            cp = cp2+1;
            for ( ; (*(cp2-1) == ' ' || *(cp2-1) == '\t'); cp2--)
                ;
            *cp2 = '\0';
            if ((cp3 = strchr(cp1, '=')) != NULL) {
                *cp3 = '\0';
                key = cp1;
                val = cp3+1;
            }
            else {
                key = cp1;
                val = "";
            }
            if ((err = cmd_rewriterule_setflag(p, cfg, key, val)) != NULL) {
                return err;
            }
        }
        else {
            break;
        }
    }

    return NULL;
}

static const char *cmd_rewriterule_setflag(apr_pool_t *p,
                                           rewriterule_entry *cfg,
                                           char *key, char *val)
{
    int status = 0;
    int i;

    if (   strcasecmp(key, "redirect") == 0
        || strcasecmp(key, "R") == 0       ) {
        cfg->flags |= RULEFLAG_FORCEREDIRECT;
        if (strlen(val) > 0) {
            if (strcasecmp(val, "permanent") == 0) {
                status = HTTP_MOVED_PERMANENTLY;
            }
            else if (strcasecmp(val, "temp") == 0) {
                status = HTTP_MOVED_TEMPORARILY;
            }
            else if (strcasecmp(val, "seeother") == 0) {
                status = HTTP_SEE_OTHER;
            }
            else if (apr_isdigit(*val)) {
                status = atoi(val);
            }
            if (!ap_is_HTTP_REDIRECT(status)) {
                return "RewriteRule: invalid HTTP response code "
                       "for flag 'R'";
            }
            cfg->forced_responsecode = status;
        }
    }
    else if (   strcasecmp(key, "noescape") == 0
        || strcasecmp(key, "NE") == 0       ) {
        cfg->flags |= RULEFLAG_NOESCAPE;
    }
    else if (   strcasecmp(key, "last") == 0
             || strcasecmp(key, "L") == 0   ) {
        cfg->flags |= RULEFLAG_LASTRULE;
    }
    else if (   strcasecmp(key, "next") == 0
             || strcasecmp(key, "N") == 0   ) {
        cfg->flags |= RULEFLAG_NEWROUND;
    }
    else if (   strcasecmp(key, "chain") == 0
             || strcasecmp(key, "C") == 0    ) {
        cfg->flags |= RULEFLAG_CHAIN;
    }
    else if (   strcasecmp(key, "type") == 0
             || strcasecmp(key, "T") == 0   ) {
        cfg->forced_mimetype = apr_pstrdup(p, val);
        ap_str_tolower(cfg->forced_mimetype);
    }
    else if (   strcasecmp(key, "env") == 0
             || strcasecmp(key, "E") == 0   ) {
        for (i = 0; (cfg->env[i] != NULL) && (i < MAX_ENV_FLAGS); i++)
            ;
        if (i < MAX_ENV_FLAGS) {
            cfg->env[i] = apr_pstrdup(p, val);
            cfg->env[i+1] = NULL;
        }
        else {
            return "RewriteRule: too many environment flags 'E'";
        }
    }
    else  if ( strcasecmp(key, "cookie") == 0 || strcasecmp(key, "CO") == 0) {
        for (i = 0; (cfg->cookie[i] != NULL) && (i < MAX_COOKIE_FLAGS); i++)
            ;
        if (i < MAX_COOKIE_FLAGS) {
            cfg->cookie[i] = apr_pstrdup(p, val);
            cfg->cookie[i+1] = NULL;
        }
        else {
            return "RewriteRule: too many cookie flags 'CO'";
        }
    }
    else if (   strcasecmp(key, "nosubreq") == 0
             || strcasecmp(key, "NS") == 0      ) {
        cfg->flags |= RULEFLAG_IGNOREONSUBREQ;
    }
    else if (   strcasecmp(key, "proxy") == 0
             || strcasecmp(key, "P") == 0      ) {
        cfg->flags |= RULEFLAG_PROXY;
    }
    else if (   strcasecmp(key, "passthrough") == 0
             || strcasecmp(key, "PT") == 0      ) {
        cfg->flags |= RULEFLAG_PASSTHROUGH;
    }
    else if (   strcasecmp(key, "skip") == 0
             || strcasecmp(key, "S") == 0   ) {
        cfg->skip = atoi(val);
    }
    else if (   strcasecmp(key, "forbidden") == 0
             || strcasecmp(key, "F") == 0   ) {
        cfg->flags |= RULEFLAG_FORBIDDEN;
    }
    else if (   strcasecmp(key, "gone") == 0
             || strcasecmp(key, "G") == 0   ) {
        cfg->flags |= RULEFLAG_GONE;
    }
    else if (   strcasecmp(key, "qsappend") == 0
             || strcasecmp(key, "QSA") == 0   ) {
        cfg->flags |= RULEFLAG_QSAPPEND;
    }
    else if (   strcasecmp(key, "nocase") == 0
             || strcasecmp(key, "NC") == 0    ) {
        cfg->flags |= RULEFLAG_NOCASE;
    }
    else {
        return apr_pstrcat(p, "RewriteRule: unknown flag '", key, "'", NULL);
    }
    return NULL;
}


/*
**
**  Global Module Initialization
**
*/

static int pre_config(apr_pool_t *pconf,
                      apr_pool_t *plog,
                      apr_pool_t *ptemp)
{
    APR_OPTIONAL_FN_TYPE(ap_register_rewrite_mapfunc) *map_pfn_register;

    /* register int: rewritemap handlers */
    mapfunc_hash = apr_hash_make(pconf);
    map_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_rewrite_mapfunc);
    if (map_pfn_register) {
        map_pfn_register("tolower", rewrite_mapfunc_tolower);
        map_pfn_register("toupper", rewrite_mapfunc_toupper);
        map_pfn_register("escape", rewrite_mapfunc_escape);
        map_pfn_register("unescape", rewrite_mapfunc_unescape);
    }
    return OK;
}

static int post_config(apr_pool_t *p,
                       apr_pool_t *plog,
                       apr_pool_t *ptemp,
                       server_rec *s)
{
    apr_status_t rv;
    void *data;
    int first_time = 0;
    const char *userdata_key = "rewrite_init_module";

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        first_time = 1;
        apr_pool_userdata_set((const void *)1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
    }

    /* check if proxy module is available */
    proxy_available = (ap_find_linked_module("mod_proxy.c") != NULL);

    /* create the rewriting lockfiles in the parent */
    if ((rv = apr_global_mutex_create(&rewrite_log_lock, NULL,
                                      APR_LOCK_DEFAULT, p)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "mod_rewrite: could not create rewrite_log_lock");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

#if APR_USE_SYSVSEM_SERIALIZE
    rv = unixd_set_global_mutex_perms(rewrite_log_lock);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "mod_rewrite: Could not set permissions on "
                     "rewrite_log_lock; check User and Group directives");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif

    rv = rewritelock_create(s, p);
    if (rv != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_pool_cleanup_register(p, (void *)s, rewritelock_remove,
                              apr_pool_cleanup_null);

    /* step through the servers and
     * - open each rewriting logfile
     * - open the RewriteMap prg:xxx programs
     */
    for (; s; s = s->next) {
        open_rewritelog(s, p);
        if (!first_time) {
            if (run_rewritemap_programs(s, p) != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }
    return OK;
}


/*
**
**  Per-Child Module Initialization
**  [called after a child process is spawned]
**
*/

static void init_child(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv;

    if (lockname != NULL && *(lockname) != '\0') {
        rv = apr_global_mutex_child_init(&rewrite_mapr_lock_acquire,
                                         lockname, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "mod_rewrite: could not init rewrite_mapr_lock_acquire"
                         " in child");
        }
    }

    rv = apr_global_mutex_child_init(&rewrite_log_lock, NULL, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "mod_rewrite: could not init rewrite log lock in child");
    }
    
    /* create the lookup cache */
    cachep = init_cache(p);
}


/*
** +-------------------------------------------------------+
** |                                                       |
** |                     runtime hooks
** |                                                       |
** +-------------------------------------------------------+
*/

/*
**
**  URI-to-filename hook
**
**  [used for the rewriting engine triggered by
**  the per-server 'RewriteRule' directives]
**
*/

static int hook_uri2file(request_rec *r)
{
    rewrite_server_conf *conf;
    const char *var;
    const char *thisserver;
    char *thisport;
    const char *thisurl;
    char buf[512];
    char docroot[512];
    const char *ccp;
    unsigned int port;
    int rulestatus;
    int n;
    int l;

    /*
     *  retrieve the config structures
     */
    conf = ap_get_module_config(r->server->module_config, &rewrite_module);

    /*
     *  only do something under runtime if the engine is really enabled,
     *  else return immediately!
     */
    if (conf->state == ENGINE_DISABLED) {
        return DECLINED;
    }

    /*
     *  check for the ugly API case of a virtual host section where no
     *  mod_rewrite directives exists. In this situation we became no chance
     *  by the API to setup our default per-server config so we have to
     *  on-the-fly assume we have the default config. But because the default
     *  config has a disabled rewriting engine we are lucky because can
     *  just stop operating now.
     */
    if (conf->server != r->server) {
        return DECLINED;
    }

    /*
     *  add the SCRIPT_URL variable to the env. this is a bit complicated
     *  due to the fact that apache uses subrequests and internal redirects
     */

    if (r->main == NULL) {
         var = apr_pstrcat(r->pool, "REDIRECT_", ENVVAR_SCRIPT_URL, NULL);
         var = apr_table_get(r->subprocess_env, var);
         if (var == NULL) {
             apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URL, r->uri);
         }
         else {
             apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URL, var);
         }
    }
    else {
         var = apr_table_get(r->main->subprocess_env, ENVVAR_SCRIPT_URL);
         apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URL, var);
    }

    /*
     *  create the SCRIPT_URI variable for the env
     */

    /* add the canonical URI of this URL */
    thisserver = ap_get_server_name(r);
    port = ap_get_server_port(r);
    if (ap_is_default_port(port, r)) {
        thisport = "";
    }
    else {
        apr_snprintf(buf, sizeof(buf), ":%u", port);
        thisport = buf;
    }
    thisurl = apr_table_get(r->subprocess_env, ENVVAR_SCRIPT_URL);

    /* set the variable */
    var = apr_pstrcat(r->pool, ap_http_method(r), "://", thisserver, thisport,
                      thisurl, NULL);
    apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URI, var);

    /* if filename was not initially set,
     * we start with the requested URI
     */
    if (r->filename == NULL) {
        r->filename = apr_pstrdup(r->pool, r->uri);
        rewritelog(r, 2, "init rewrite engine with requested uri %s",
                   r->filename);
    }

    /*
     *  now apply the rules ...
     */
    rulestatus = apply_rewrite_list(r, conf->rewriterules, NULL);
    if (rulestatus) {
        unsigned skip;

        if (strlen(r->filename) > 6 &&
            strncmp(r->filename, "proxy:", 6) == 0) {
            /* it should be go on as an internal proxy request */

            /* check if the proxy module is enabled, so
             * we can actually use it!
             */
            if (!proxy_available) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "attempt to make remote request from mod_rewrite "
                              "without proxy enabled: %s", r->filename);
                return HTTP_FORBIDDEN;
            }

            /* make sure the QUERY_STRING and
             * PATH_INFO parts get incorporated
             */
            if (r->path_info != NULL) {
                r->filename = apr_pstrcat(r->pool, r->filename,
                                          r->path_info, NULL);
            }
            if (r->args != NULL &&
                r->uri == r->unparsed_uri) {
                /* see proxy_http:proxy_http_canon() */
                r->filename = apr_pstrcat(r->pool, r->filename,
                                          "?", r->args, NULL);
            }

            /* now make sure the request gets handled by the proxy handler */
            r->proxyreq = PROXYREQ_REVERSE;
            r->handler  = "proxy-server";

            rewritelog(r, 1, "go-ahead with proxy request %s [OK]",
                       r->filename);
            return OK;
        }
        else if ((skip = is_absolute_uri(r->filename)) > 0) {
            /* it was finally rewritten to a remote URL */

            if (rulestatus != ACTION_NOESCAPE) {
                rewritelog(r, 1, "escaping %s for redirect", r->filename);
                r->filename = escape_absolute_uri(r->pool, r->filename, skip);
            }

            /* append the QUERY_STRING part */
            if (r->args) {
                r->filename = apr_pstrcat(r->pool, r->filename, "?",
                                          (rulestatus == ACTION_NOESCAPE)
                                            ? r->args
                                            : ap_escape_uri(r->pool, r->args),
                                          NULL);
            }

            /* determine HTTP redirect response code */
            if (ap_is_HTTP_REDIRECT(r->status)) {
                n = r->status;
                r->status = HTTP_OK; /* make Apache kernel happy */
            }
            else {
                n = HTTP_MOVED_TEMPORARILY;
            }

            /* now do the redirection */
            apr_table_setn(r->headers_out, "Location", r->filename);
            rewritelog(r, 1, "redirect to %s [REDIRECT/%d]", r->filename, n);
            return n;
        }
        else if (strlen(r->filename) > 10 &&
                 strncmp(r->filename, "forbidden:", 10) == 0) {
            /* This URLs is forced to be forbidden for the requester */
            return HTTP_FORBIDDEN;
        }
        else if (strlen(r->filename) > 5 &&
                 strncmp(r->filename, "gone:", 5) == 0) {
            /* This URLs is forced to be gone */
            return HTTP_GONE;
        }
        else if (strlen(r->filename) > 12 &&
                 strncmp(r->filename, "passthrough:", 12) == 0) {
            /*
             * Hack because of underpowered API: passing the current
             * rewritten filename through to other URL-to-filename handlers
             * just as it were the requested URL. This is to enable
             * post-processing by mod_alias, etc.  which always act on
             * r->uri! The difference here is: We do not try to
             * add the document root
             */
            r->uri = apr_pstrdup(r->pool, r->filename+12);
            return DECLINED;
        }
        else {
            /* it was finally rewritten to a local path */

            /* expand "/~user" prefix */
#if APR_HAS_USER
            r->filename = expand_tildepaths(r, r->filename);
#endif
            rewritelog(r, 2, "local path result: %s", r->filename);

            /* the filename must be either an absolute local path or an
             * absolute local URL.
             */
            if (   *r->filename != '/'
                && !ap_os_is_path_absolute(r->pool, r->filename)) {
                return HTTP_BAD_REQUEST;
            }

            /* if there is no valid prefix, we have
             * to emulate the translator from the core and
             * prefix the filename with document_root
             *
             * NOTICE:
             * We cannot leave out the prefix_stat because
             * - when we always prefix with document_root
             *   then no absolute path can be created, e.g. via
             *   emulating a ScriptAlias directive, etc.
             * - when we always NOT prefix with document_root
             *   then the files under document_root have to
             *   be references directly and document_root
             *   gets never used and will be a dummy parameter -
             *   this is also bad
             *
             * BUT:
             * Under real Unix systems this is no problem,
             * because we only do stat() on the first directory
             * and this gets cached by the kernel for along time!
             */
            n = prefix_stat(r->filename, r->pool);
            if (n == 0) {
                if ((ccp = ap_document_root(r)) != NULL) {
                    l = apr_cpystrn(docroot, ccp, sizeof(docroot)) - docroot;

                    /* always NOT have a trailing slash */
                    if (docroot[l-1] == '/') {
                        docroot[l-1] = '\0';
                    }
                    if (r->server->path
                        && !strncmp(r->filename, r->server->path,
                                    r->server->pathlen)) {
                        r->filename = apr_pstrcat(r->pool, docroot,
                                                  (r->filename +
                                                   r->server->pathlen), NULL);
                    }
                    else {
                        r->filename = apr_pstrcat(r->pool, docroot,
                                                  r->filename, NULL);
                    }
                    rewritelog(r, 2, "prefixed with document_root to %s",
                               r->filename);
                }
            }

            rewritelog(r, 1, "go-ahead with %s [OK]", r->filename);
            return OK;
        }
    }
    else {
        rewritelog(r, 1, "pass through %s", r->filename);
        return DECLINED;
    }
}


/*
**
**  MIME-type hook
**
**  [used to support the forced-MIME-type feature]
**
*/

static int hook_mimetype(request_rec *r)
{
    const char *t;

    /* now check if we have to force a MIME-type */
    t = apr_table_get(r->notes, REWRITE_FORCED_MIMETYPE_NOTEVAR);
    if (t == NULL) {
        return DECLINED;
    }
    else {
        rewritelog(r, 1, "force filename %s to have MIME-type '%s'",
                   r->filename, t);
        ap_set_content_type(r, t);
        return OK;
    }
}


/*
**
**  Fixup hook
**
**  [used for the rewriting engine triggered by
**  the per-directory 'RewriteRule' directives]
**
*/

static int hook_fixup(request_rec *r)
{
    rewrite_perdir_conf *dconf;
    char *cp;
    char *cp2;
    const char *ccp;
    char *prefix;
    int l;
    int rulestatus;
    int n;
    char *ofilename;

    dconf = (rewrite_perdir_conf *)ap_get_module_config(r->per_dir_config,
                                                        &rewrite_module);

    /* if there is no per-dir config we return immediately */
    if (dconf == NULL) {
        return DECLINED;
    }

    /* we shouldn't do anything in subrequests */
    if (r->main != NULL) {
        return DECLINED;
    }

    /* if there are no real (i.e. no RewriteRule directives!)
       per-dir config of us, we return also immediately */
    if (dconf->directory == NULL) {
        return DECLINED;
    }

    /*
     *  only do something under runtime if the engine is really enabled,
     *  for this directory, else return immediately!
     */
    if (dconf->state == ENGINE_DISABLED) {
        return DECLINED;
    }

    /*
     *  Do the Options check after engine check, so
     *  the user is able to explicitely turn RewriteEngine Off.
     */
    if (!(ap_allow_options(r) & (OPT_SYM_LINKS | OPT_SYM_OWNER))) {
        /* FollowSymLinks is mandatory! */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                     "Options FollowSymLinks or SymLinksIfOwnerMatch is off "
                     "which implies that RewriteRule directive is forbidden: "
                     "%s", r->filename);
        return HTTP_FORBIDDEN;
    }

    /*
     *  remember the current filename before rewriting for later check
     *  to prevent deadlooping because of internal redirects
     *  on final URL/filename which can be equal to the inital one.
     */
    ofilename = r->filename;

    /*
     *  now apply the rules ...
     */
    rulestatus = apply_rewrite_list(r, dconf->rewriterules, dconf->directory);
    if (rulestatus) {
        unsigned skip;

        if (strlen(r->filename) > 6 &&
            strncmp(r->filename, "proxy:", 6) == 0) {
            /* it should go on as an internal proxy request */

            /* make sure the QUERY_STRING and
             * PATH_INFO parts get incorporated
             * (r->path_info was already appended by the
             * rewriting engine because of the per-dir context!)
             */
            if (r->args != NULL) {
                r->filename = apr_pstrcat(r->pool, r->filename,
                                          "?", r->args, NULL);
            }

            /* now make sure the request gets handled by the proxy handler */
            r->proxyreq = PROXYREQ_REVERSE;
            r->handler  = "proxy-server";

            rewritelog(r, 1, "[per-dir %s] go-ahead with proxy request "
                       "%s [OK]", dconf->directory, r->filename);
            return OK;
        }
        else if ((skip = is_absolute_uri(r->filename)) > 0) {
            /* it was finally rewritten to a remote URL */

            /* because we are in a per-dir context
             * first try to replace the directory with its base-URL
             * if there is a base-URL available
             */
            if (dconf->baseurl != NULL) {
                /* skip 'scheme://' */
                cp = r->filename + skip;

                if ((cp = ap_strchr(cp, '/')) != NULL && *(++cp)) {
                    rewritelog(r, 2,
                               "[per-dir %s] trying to replace "
                               "prefix %s with %s",
                               dconf->directory, dconf->directory,
                               dconf->baseurl);

                    /* I think, that hack needs an explanation:
                     * well, here is it:
                     * mod_rewrite was written for unix systems, were
                     * absolute file-system paths start with a slash.
                     * URL-paths _also_ start with slashes, so they
                     * can be easily compared with system paths.
                     *
                     * the following assumes, that the actual url-path
                     * may be prefixed by the current directory path and
                     * tries to replace the system path with the RewriteBase
                     * URL.
                     * That assumption is true if we use a RewriteRule like
                     *
                     * RewriteRule ^foo bar [R]
                     *
                     * (see apply_rewrite_rule function)
                     * However on systems that don't have a / as system
                     * root this will never match, so we skip the / after the
                     * hostname and compare/substitute only the stuff after it.
                     *
                     * (note that cp was already increased to the right value)
                     */
                    cp2 = subst_prefix_path(r, cp, (*dconf->directory == '/')
                                                   ? dconf->directory + 1
                                                   : dconf->directory,
                                            dconf->baseurl + 1);
                    if (strcmp(cp2, cp) != 0) {
                        *cp = '\0';
                        r->filename = apr_pstrcat(r->pool, r->filename,
                                                  cp2, NULL);
                    }
                }
            }

            /* now prepare the redirect... */
            if (rulestatus != ACTION_NOESCAPE) {
                rewritelog(r, 1, "[per-dir %s] escaping %s for redirect",
                           dconf->directory, r->filename);
                r->filename = escape_absolute_uri(r->pool, r->filename, skip);
            }

            /* append the QUERY_STRING part */
            if (r->args) {
                r->filename = apr_pstrcat(r->pool, r->filename, "?",
                                          (rulestatus == ACTION_NOESCAPE)
                                            ? r->args
                                            : ap_escape_uri(r->pool, r->args),
                                          NULL);
            }

            /* determine HTTP redirect response code */
            if (ap_is_HTTP_REDIRECT(r->status)) {
                n = r->status;
                r->status = HTTP_OK; /* make Apache kernel happy */
            }
            else {
                n = HTTP_MOVED_TEMPORARILY;
            }

            /* now do the redirection */
            apr_table_setn(r->headers_out, "Location", r->filename);
            rewritelog(r, 1, "[per-dir %s] redirect to %s [REDIRECT/%d]",
                       dconf->directory, r->filename, n);
            return n;
        }
        else if (strlen(r->filename) > 10 &&
                 strncmp(r->filename, "forbidden:", 10) == 0) {
            /* This URL is forced to be forbidden for the requester */
            return HTTP_FORBIDDEN;
        }
        else if (strlen(r->filename) > 5 &&
                 strncmp(r->filename, "gone:", 5) == 0) {
            /* This URL is forced to be gone */
            return HTTP_GONE;
        }
        else {
            /* it was finally rewritten to a local path */

            /* if someone used the PASSTHROUGH flag in per-dir
             * context we just ignore it. It is only useful
             * in per-server context
             */
            if (strlen(r->filename) > 12 &&
                strncmp(r->filename, "passthrough:", 12) == 0) {
                r->filename = apr_pstrdup(r->pool, r->filename+12);
            }

            /* the filename must be either an absolute local path or an
             * absolute local URL.
             */
            if (   *r->filename != '/'
                && !ap_os_is_path_absolute(r->pool, r->filename)) {
                return HTTP_BAD_REQUEST;
            }

            /* Check for deadlooping:
             * At this point we KNOW that at least one rewriting
             * rule was applied, but when the resulting URL is
             * the same as the initial URL, we are not allowed to
             * use the following internal redirection stuff because
             * this would lead to a deadloop.
             */
            if (strcmp(r->filename, ofilename) == 0) {
                rewritelog(r, 1, "[per-dir %s] initial URL equal rewritten "
                           "URL: %s [IGNORING REWRITE]",
                           dconf->directory, r->filename);
                return OK;
            }

            /* if there is a valid base-URL then substitute
             * the per-dir prefix with this base-URL if the
             * current filename still is inside this per-dir
             * context. If not then treat the result as a
             * plain URL
             */
            if (dconf->baseurl != NULL) {
                rewritelog(r, 2,
                           "[per-dir %s] trying to replace prefix %s with %s",
                           dconf->directory, dconf->directory, dconf->baseurl);
                r->filename = subst_prefix_path(r, r->filename,
                                                dconf->directory,
                                                dconf->baseurl);
            }
            else {
                /* if no explicit base-URL exists we assume
                 * that the directory prefix is also a valid URL
                 * for this webserver and only try to remove the
                 * document_root if it is prefix
                 */
                if ((ccp = ap_document_root(r)) != NULL) {
                    prefix = apr_pstrdup(r->pool, ccp);
                    /* always NOT have a trailing slash */
                    l = strlen(prefix);
                    if (prefix[l-1] == '/') {
                        prefix[l-1] = '\0';
                        l--;
                    }
                    if (strncmp(r->filename, prefix, l) == 0) {
                        rewritelog(r, 2,
                                   "[per-dir %s] strip document_root "
                                   "prefix: %s -> %s",
                                   dconf->directory, r->filename,
                                   r->filename+l);
                        r->filename = apr_pstrdup(r->pool, r->filename+l);
                    }
                }
            }

            /* now initiate the internal redirect */
            rewritelog(r, 1, "[per-dir %s] internal redirect with %s "
                       "[INTERNAL REDIRECT]", dconf->directory, r->filename);
            r->filename = apr_pstrcat(r->pool, "redirect:", r->filename, NULL);
            r->handler = "redirect-handler";
            return OK;
        }
    }
    else {
        rewritelog(r, 1, "[per-dir %s] pass through %s",
                   dconf->directory, r->filename);
        return DECLINED;
    }
}


/*
**
**  Content-Handlers
**
**  [used for redirect support]
**
*/

static int handler_redirect(request_rec *r)
{
    if (strcmp(r->handler, "redirect-handler")) {
        return DECLINED;
    }

    /* just make sure that we are really meant! */
    if (strncmp(r->filename, "redirect:", 9) != 0) {
        return DECLINED;
    }

    if (is_redirect_limit_exceeded(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_rewrite: maximum number of internal redirects "
                      "reached. Assuming configuration error. Use "
                      "'RewriteOptions MaxRedirects' to increase the limit "
                      "if neccessary.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* now do the internal redirect */
    ap_internal_redirect(apr_pstrcat(r->pool, r->filename+9,
                                     r->args ? "?" : NULL, r->args, NULL), r);

    /* and return gracefully */
    return OK;
}

/*
 * check whether redirect limit is reached
 */
static int is_redirect_limit_exceeded(request_rec *r)
{
    request_rec *top = r;
    rewrite_request_conf *reqc;
    rewrite_perdir_conf *dconf;

    /* we store it in the top request */
    while (top->main) {
        top = top->main;
    }
    while (top->prev) {
        top = top->prev;
    }

    /* fetch our config */
    reqc = (rewrite_request_conf *) ap_get_module_config(top->request_config,
                                                         &rewrite_module);

    /* no config there? create one. */
    if (!reqc) {
        rewrite_server_conf *sconf;

        reqc = apr_palloc(top->pool, sizeof(rewrite_request_conf));
        sconf = ap_get_module_config(r->server->module_config, &rewrite_module);

        reqc->redirects = 0;
        reqc->redirect_limit = sconf->redirect_limit
                                 ? sconf->redirect_limit
                                 : REWRITE_REDIRECT_LIMIT;

        /* associate it with this request */
        ap_set_module_config(top->request_config, &rewrite_module, reqc);
    }

    /* allow to change the limit during redirects. */
    dconf = (rewrite_perdir_conf *)ap_get_module_config(r->per_dir_config,
                                                        &rewrite_module);

    /* 0 == unset; take server conf ... */
    if (dconf->redirect_limit) {
        reqc->redirect_limit = dconf->redirect_limit;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "mod_rewrite's internal redirect status: %d/%d.",
                  reqc->redirects, reqc->redirect_limit);

    /* and now give the caller a hint */
    return (reqc->redirects++ >= reqc->redirect_limit);
}


/*
** +-------------------------------------------------------+
** |                                                       |
** |                  the rewriting engine
** |                                                       |
** +-------------------------------------------------------+
*/

/*
 *  Apply a complete rule set,
 *  i.e. a list of rewrite rules
 */
static int apply_rewrite_list(request_rec *r, apr_array_header_t *rewriterules,
                              char *perdir)
{
    rewriterule_entry *entries;
    rewriterule_entry *p;
    int i;
    int changed;
    int rc;
    int s;

    /*
     *  Iterate over all existing rules
     */
    entries = (rewriterule_entry *)rewriterules->elts;
    changed = 0;
    loop:
    for (i = 0; i < rewriterules->nelts; i++) {
        p = &entries[i];

        /*
         *  Ignore this rule on subrequests if we are explicitly
         *  asked to do so or this is a proxy-throughput or a
         *  forced redirect rule.
         */
        if (r->main != NULL &&
            (p->flags & RULEFLAG_IGNOREONSUBREQ ||
             p->flags & RULEFLAG_PROXY          ||
             p->flags & RULEFLAG_FORCEREDIRECT    )) {
            continue;
        }

        /*
         *  Apply the current rule.
         */
        rc = apply_rewrite_rule(r, p, perdir);
        if (rc) {
            /*
             *  Indicate a change if this was not a match-only rule.
             */
            if (rc != 2) {
                changed = ((p->flags & RULEFLAG_NOESCAPE)
                           ? ACTION_NOESCAPE : ACTION_NORMAL);
            }

            /*
             *  Pass-Through Feature (`RewriteRule .. .. [PT]'):
             *  Because the Apache 1.x API is very limited we
             *  need this hack to pass the rewritten URL to other
             *  modules like mod_alias, mod_userdir, etc.
             */
            if (p->flags & RULEFLAG_PASSTHROUGH) {
                rewritelog(r, 2, "forcing '%s' to get passed through "
                           "to next API URI-to-filename handler", r->filename);
                r->filename = apr_pstrcat(r->pool, "passthrough:",
                                         r->filename, NULL);
                changed = ACTION_NORMAL;
                break;
            }

            /*
             *  Rule has the "forbidden" flag set which means that
             *  we stop processing and indicate this to the caller.
             */
            if (p->flags & RULEFLAG_FORBIDDEN) {
                rewritelog(r, 2, "forcing '%s' to be forbidden", r->filename);
                r->filename = apr_pstrcat(r->pool, "forbidden:",
                                         r->filename, NULL);
                changed = ACTION_NORMAL;
                break;
            }

            /*
             *  Rule has the "gone" flag set which means that
             *  we stop processing and indicate this to the caller.
             */
            if (p->flags & RULEFLAG_GONE) {
                rewritelog(r, 2, "forcing '%s' to be gone", r->filename);
                r->filename = apr_pstrcat(r->pool, "gone:", r->filename, NULL);
                changed = ACTION_NORMAL;
                break;
            }

            /*
             *  Stop processing also on proxy pass-through and
             *  last-rule and new-round flags.
             */
            if (p->flags & RULEFLAG_PROXY) {
                break;
            }
            if (p->flags & RULEFLAG_LASTRULE) {
                break;
            }

            /*
             *  On "new-round" flag we just start from the top of
             *  the rewriting ruleset again.
             */
            if (p->flags & RULEFLAG_NEWROUND) {
                goto loop;
            }

            /*
             *  If we are forced to skip N next rules, do it now.
             */
            if (p->skip > 0) {
                s = p->skip;
                while (   i < rewriterules->nelts
                       && s > 0) {
                    i++;
                    p = &entries[i];
                    s--;
                }
            }
        }
        else {
            /*
             *  If current rule is chained with next rule(s),
             *  skip all this next rule(s)
             */
            while (   i < rewriterules->nelts
                   && p->flags & RULEFLAG_CHAIN) {
                i++;
                p = &entries[i];
            }
        }
    }
    return changed;
}

/*
 *  Apply a single(!) rewrite rule
 */
static int apply_rewrite_rule(request_rec *r, rewriterule_entry *p,
                              char *perdir)
{
    char *uri;
    char *output;
    const char *vary;
    char newuri[MAX_STRING_LEN];
    regex_t *regexp;
    regmatch_t regmatch[MAX_NMATCH];
    backrefinfo *briRR = NULL;
    backrefinfo *briRC = NULL;
    int prefixstrip;
    int failed;
    apr_array_header_t *rewriteconds;
    rewritecond_entry *conds;
    rewritecond_entry *c;
    int i;
    int rc;

    /*
     *  Initialisation
     */
    uri     = r->filename;
    regexp  = p->regexp;
    output  = p->output;

    /*
     *  Add (perhaps splitted away) PATH_INFO postfix to URL to
     *  make sure we really match against the complete URL.
     */
    if (perdir != NULL && r->path_info != NULL && r->path_info[0] != '\0') {
        rewritelog(r, 3, "[per-dir %s] add path info postfix: %s -> %s%s",
                   perdir, uri, uri, r->path_info);
        uri = apr_pstrcat(r->pool, uri, r->path_info, NULL);
    }

    /*
     *  On per-directory context (.htaccess) strip the location
     *  prefix from the URL to make sure patterns apply only to
     *  the local part.  Additionally indicate this special
     *  threatment in the logfile.
     */
    prefixstrip = 0;
    if (perdir != NULL) {
        if (   strlen(uri) >= strlen(perdir)
            && strncmp(uri, perdir, strlen(perdir)) == 0) {
            rewritelog(r, 3, "[per-dir %s] strip per-dir prefix: %s -> %s",
                       perdir, uri, uri+strlen(perdir));
            uri = uri+strlen(perdir);
            prefixstrip = 1;
        }
    }

    /*
     *  Try to match the URI against the RewriteRule pattern
     *  and exit immeddiately if it didn't apply.
     */
    if (perdir == NULL) {
        rewritelog(r, 3, "applying pattern '%s' to uri '%s'",
                   p->pattern, uri);
    }
    else {
        rewritelog(r, 3, "[per-dir %s] applying pattern '%s' to uri '%s'",
                   perdir, p->pattern, uri);
    }
    rc = (ap_regexec(regexp, uri, regexp->re_nsub+1, regmatch, 0) == 0);
    if (! (( rc && !(p->flags & RULEFLAG_NOTMATCH)) ||
           (!rc &&  (p->flags & RULEFLAG_NOTMATCH))   ) ) {
        return 0;
    }

    /*
     *  Else create the RewriteRule `regsubinfo' structure which
     *  holds the substitution information.
     */
    briRR = (backrefinfo *)apr_palloc(r->pool, sizeof(backrefinfo));
    if (!rc && (p->flags & RULEFLAG_NOTMATCH)) {
        /*  empty info on negative patterns  */
        briRR->source = "";
        briRR->nsub   = 0;
    }
    else {
        briRR->source = apr_pstrdup(r->pool, uri);
        briRR->nsub   = regexp->re_nsub;
        memcpy((void *)(briRR->regmatch), (void *)(regmatch),
               sizeof(regmatch));
    }

    /*
     *  Initiallally create the RewriteCond backrefinfo with
     *  empty backrefinfo, i.e. not subst parts
     *  (this one is adjusted inside apply_rewrite_cond() later!!)
     */
    briRC = (backrefinfo *)apr_pcalloc(r->pool, sizeof(backrefinfo));
    briRC->source = "";
    briRC->nsub   = 0;

    /*
     *  Ok, we already know the pattern has matched, but we now
     *  additionally have to check for all existing preconditions
     *  (RewriteCond) which have to be also true. We do this at
     *  this very late stage to avoid unnessesary checks which
     *  would slow down the rewriting engine!!
     */
    rewriteconds = p->rewriteconds;
    conds = (rewritecond_entry *)rewriteconds->elts;
    failed = 0;
    for (i = 0; i < rewriteconds->nelts; i++) {
        c = &conds[i];
        rc = apply_rewrite_cond(r, c, perdir, briRR, briRC);
        if (c->flags & CONDFLAG_ORNEXT) {
            /*
             *  The "OR" case
             */
            if (rc == 0) {
                /*  One condition is false, but another can be
                 *  still true, so we have to continue...
                 */
                apr_table_unset(r->notes, VARY_KEY_THIS);
                continue;
            }
            else {
                /*  One true condition is enough in "or" case, so
                 *  skip the other conditions which are "ornext"
                 *  chained
                 */
                while (   i < rewriteconds->nelts
                       && c->flags & CONDFLAG_ORNEXT) {
                    i++;
                    c = &conds[i];
                }
                continue;
            }
        }
        else {
            /*
             *  The "AND" case, i.e. no "or" flag,
             *  so a single failure means total failure.
             */
            if (rc == 0) {
                failed = 1;
                break;
            }
        }
        vary = apr_table_get(r->notes, VARY_KEY_THIS);
        if (vary != NULL) {
            apr_table_merge(r->notes, VARY_KEY, vary);
            apr_table_unset(r->notes, VARY_KEY_THIS);
        }
    }
    /*  if any condition fails the complete rule fails  */
    if (failed) {
        apr_table_unset(r->notes, VARY_KEY);
        apr_table_unset(r->notes, VARY_KEY_THIS);
        return 0;
    }

    /*
     * Regardless of what we do next, we've found a match.  Check to see
     * if any of the request header fields were involved, and add them
     * to the Vary field of the response.
     */
    if ((vary = apr_table_get(r->notes, VARY_KEY)) != NULL) {
        apr_table_merge(r->headers_out, "Vary", vary);
        apr_table_unset(r->notes, VARY_KEY);
    }

    /*
     *  If this is a pure matching rule (`RewriteRule <pat> -')
     *  we stop processing and return immediately. The only thing
     *  we have not to forget are the environment variables and
     *  cookies:
     *  (`RewriteRule <pat> - [E=...,CO=...]')
     */
    if (strcmp(output, "-") == 0) {
        do_expand_env(r, p->env, briRR, briRC);
        do_expand_cookie(r, p->cookie, briRR, briRC);
        if (p->forced_mimetype != NULL) {
            if (perdir == NULL) {
                /* In the per-server context we can force the MIME-type
                 * the correct way by notifying our MIME-type hook handler
                 * to do the job when the MIME-type API stage is reached.
                 */
                rewritelog(r, 2, "remember %s to have MIME-type '%s'",
                           r->filename, p->forced_mimetype);
                apr_table_setn(r->notes, REWRITE_FORCED_MIMETYPE_NOTEVAR,
                               p->forced_mimetype);
            }
            else {
                /* In per-directory context we operate in the Fixup API hook
                 * which is after the MIME-type hook, so our MIME-type handler
                 * has no chance to set r->content_type. And because we are
                 * in the situation where no substitution takes place no
                 * sub-request will happen (which could solve the
                 * restriction). As a workaround we do it ourself now
                 * immediately although this is not strictly API-conforming.
                 * But it's the only chance we have...
                 */
                rewritelog(r, 1, "[per-dir %s] force %s to have MIME-type "
                           "'%s'", perdir, r->filename, p->forced_mimetype);
                ap_set_content_type(r, p->forced_mimetype);
            }
        }
        return 2;
    }

    /*
     *  Ok, now we finally know all patterns have matched and
     *  that there is something to replace, so we create the
     *  substitution URL string in `newuri'.
     */
    do_expand(r, output, newuri, sizeof(newuri), briRR, briRC);
    if (perdir == NULL) {
        rewritelog(r, 2, "rewrite %s -> %s", uri, newuri);
    }
    else {
        rewritelog(r, 2, "[per-dir %s] rewrite %s -> %s", perdir, uri, newuri);
    }

    /*
     *  Additionally do expansion for the environment variable
     *  strings (`RewriteRule .. .. [E=<string>]').
     */
    do_expand_env(r, p->env, briRR, briRC);

    /*
     *  Also set cookies for any cookie strings
     *  (`RewriteRule .. .. [CO=<string>]').
     */
    do_expand_cookie(r, p->cookie, briRR, briRC);

    /*
     *  Now replace API's knowledge of the current URI:
     *  Replace r->filename with the new URI string and split out
     *  an on-the-fly generated QUERY_STRING part into r->args
     */
    r->filename = apr_pstrdup(r->pool, newuri);
    splitout_queryargs(r, p->flags & RULEFLAG_QSAPPEND);

    /*
     *   Add the previously stripped per-directory location
     *   prefix if the new URI is not a new one for this
     *   location, i.e. if it's not an absolute URL (!) path nor
     *   a fully qualified URL scheme.
     */
    if (prefixstrip && *r->filename != '/'
                    && !is_absolute_uri(r->filename)) {
        rewritelog(r, 3, "[per-dir %s] add per-dir prefix: %s -> %s%s",
                   perdir, r->filename, perdir, r->filename);
        r->filename = apr_pstrcat(r->pool, perdir, r->filename, NULL);
    }

    /*
     *  If this rule is forced for proxy throughput
     *  (`RewriteRule ... ... [P]') then emulate mod_proxy's
     *  URL-to-filename handler to be sure mod_proxy is triggered
     *  for this URL later in the Apache API. But make sure it is
     *  a fully-qualified URL. (If not it is qualified with
     *  ourself).
     */
    if (p->flags & RULEFLAG_PROXY) {
        fully_qualify_uri(r);
        if (perdir == NULL) {
            rewritelog(r, 2, "forcing proxy-throughput with %s", r->filename);
        }
        else {
            rewritelog(r, 2, "[per-dir %s] forcing proxy-throughput with %s",
                       perdir, r->filename);
        }
        r->filename = apr_pstrcat(r->pool, "proxy:", r->filename, NULL);
        return 1;
    }

    /*
     *  If this rule is explicitly forced for HTTP redirection
     *  (`RewriteRule .. .. [R]') then force an external HTTP
     *  redirect. But make sure it is a fully-qualified URL. (If
     *  not it is qualified with ourself).
     */
    if (p->flags & RULEFLAG_FORCEREDIRECT) {
        fully_qualify_uri(r);
        if (perdir == NULL) {
            rewritelog(r, 2,
                       "explicitly forcing redirect with %s", r->filename);
        }
        else {
            rewritelog(r, 2,
                       "[per-dir %s] explicitly forcing redirect with %s",
                       perdir, r->filename);
        }
        r->status = p->forced_responsecode;
        return 1;
    }

    /*
     *  Special Rewriting Feature: Self-Reduction
     *  We reduce the URL by stripping a possible
     *  http[s]://<ourhost>[:<port>] prefix, i.e. a prefix which
     *  corresponds to ourself. This is to simplify rewrite maps
     *  and to avoid recursion, etc. When this prefix is not a
     *  coincidence then the user has to use [R] explicitly (see
     *  above).
     */
    reduce_uri(r);

    /*
     *  If this rule is still implicitly forced for HTTP
     *  redirection (`RewriteRule .. <scheme>://...') then
     *  directly force an external HTTP redirect.
     */
    if (is_absolute_uri(r->filename)) {
        if (perdir == NULL) {
            rewritelog(r, 2,
                       "implicitly forcing redirect (rc=%d) with %s",
                       p->forced_responsecode, r->filename);
        }
        else {
            rewritelog(r, 2, "[per-dir %s] implicitly forcing redirect "
                       "(rc=%d) with %s", perdir, p->forced_responsecode,
                       r->filename);
        }
        r->status = p->forced_responsecode;
        return 1;
    }

    /*
     *  Finally we had to remember if a MIME-type should be
     *  forced for this URL (`RewriteRule .. .. [T=<type>]')
     *  Later in the API processing phase this is forced by our
     *  MIME API-hook function. This time it's no problem even for
     *  the per-directory context (where the MIME-type hook was
     *  already processed) because a sub-request happens ;-)
     */
    if (p->forced_mimetype != NULL) {
        apr_table_setn(r->notes, REWRITE_FORCED_MIMETYPE_NOTEVAR,
                      p->forced_mimetype);
        if (perdir == NULL) {
            rewritelog(r, 2, "remember %s to have MIME-type '%s'",
                       r->filename, p->forced_mimetype);
        }
        else {
            rewritelog(r, 2,
                       "[per-dir %s] remember %s to have MIME-type '%s'",
                       perdir, r->filename, p->forced_mimetype);
        }
    }

    /*
     *  Puuhhhhhhhh... WHAT COMPLICATED STUFF ;_)
     *  But now we're done for this particular rule.
     */
    return 1;
}

static int apply_rewrite_cond(request_rec *r, rewritecond_entry *p,
                              char *perdir, backrefinfo *briRR,
                              backrefinfo *briRC)
{
    char input[MAX_STRING_LEN];
    apr_finfo_t sb;
    request_rec *rsub;
    regmatch_t regmatch[MAX_NMATCH];
    int rc;

    /*
     *   Construct the string we match against
     */

    do_expand(r, p->input, input, sizeof(input), briRR, briRC);

    /*
     *   Apply the patterns
     */

    rc = 0;
    if (strcmp(p->pattern, "-f") == 0) {
        if (apr_stat(&sb, input, APR_FINFO_MIN, r->pool) == APR_SUCCESS) {
            if (sb.filetype == APR_REG) {
                rc = 1;
            }
        }
    }
    else if (strcmp(p->pattern, "-s") == 0) {
        if (apr_stat(&sb, input, APR_FINFO_MIN, r->pool) == APR_SUCCESS) {
            if ((sb.filetype == APR_REG) && sb.size > 0) {
                rc = 1;
            }
        }
    }
    else if (strcmp(p->pattern, "-l") == 0) {
#if !defined(OS2)
        if (apr_lstat(&sb, input, APR_FINFO_MIN, r->pool) == APR_SUCCESS) {
            if (sb.filetype == APR_LNK) {
                rc = 1;
            }
        }
#endif
    }
    else if (strcmp(p->pattern, "-d") == 0) {
        if (apr_stat(&sb, input, APR_FINFO_MIN, r->pool) == APR_SUCCESS) {
            if (sb.filetype == APR_DIR) {
                rc = 1;
            }
        }
    }
    else if (strcmp(p->pattern, "-U") == 0) {
        /* avoid infinite subrequest recursion */
        if (strlen(input) > 0 && subreq_ok(r)) {

            /* run a URI-based subrequest */
            rsub = ap_sub_req_lookup_uri(input, r, NULL);

            /* URI exists for any result up to 3xx, redirects allowed */
            if (rsub->status < 400)
                rc = 1;

            /* log it */
            rewritelog(r, 5, "RewriteCond URI (-U) check: "
                       "path=%s -> status=%d", input, rsub->status);

            /* cleanup by destroying the subrequest */
            ap_destroy_sub_req(rsub);
        }
    }
    else if (strcmp(p->pattern, "-F") == 0) {
        /* avoid infinite subrequest recursion */
        if (strlen(input) > 0 && subreq_ok(r)) {

            /* process a file-based subrequest:
             * this differs from -U in that no path translation is done.
             */
            rsub = ap_sub_req_lookup_file(input, r, NULL);

            /* file exists for any result up to 2xx, no redirects */
            if (rsub->status < 300 &&
                /* double-check that file exists since default result is 200 */
                apr_stat(&sb, rsub->filename, APR_FINFO_MIN,
                         r->pool) == APR_SUCCESS) {
                rc = 1;
            }

            /* log it */
            rewritelog(r, 5, "RewriteCond file (-F) check: path=%s "
                       "-> file=%s status=%d", input, rsub->filename,
                       rsub->status);

            /* cleanup by destroying the subrequest */
            ap_destroy_sub_req(rsub);
        }
    }
    else if (strlen(p->pattern) > 1 && *(p->pattern) == '>') {
        rc = (compare_lexicography(input, p->pattern+1) == 1 ? 1 : 0);
    }
    else if (strlen(p->pattern) > 1 && *(p->pattern) == '<') {
        rc = (compare_lexicography(input, p->pattern+1) == -1 ? 1 : 0);
    }
    else if (strlen(p->pattern) > 1 && *(p->pattern) == '=') {
        if (strcmp(p->pattern+1, "\"\"") == 0) {
            rc = (*input == '\0');
        }
        else {
            rc = (strcmp(input, p->pattern+1) == 0 ? 1 : 0);
        }
    }
    else {
        /* it is really a regexp pattern, so apply it */
        rc = (ap_regexec(p->regexp, input,
                         p->regexp->re_nsub+1, regmatch,0) == 0);

        /* if it isn't a negated pattern and really matched
           we update the passed-through regex subst info structure */
        if (rc && !(p->flags & CONDFLAG_NOTMATCH)) {
            briRC->source = apr_pstrdup(r->pool, input);
            briRC->nsub   = p->regexp->re_nsub;
            memcpy((void *)(briRC->regmatch), (void *)(regmatch),
                   sizeof(regmatch));
        }
    }

    /* if this is a non-matching regexp, just negate the result */
    if (p->flags & CONDFLAG_NOTMATCH) {
        rc = !rc;
    }

    rewritelog(r, 4, "RewriteCond: input='%s' pattern='%s%s' => %s",
               input, (p->flags & CONDFLAG_NOTMATCH ? "!" : ""),
               p->pattern, rc ? "matched" : "not-matched");

    /* end just return the result */
    return rc;
}


/*
** +-------------------------------------------------------+
** |                                                       |
** |              URL transformation functions
** |                                                       |
** +-------------------------------------------------------+
*/


/*
**
**  perform all the expansions on the input string
**  leaving the result in the supplied buffer
**
*/

static void do_expand(request_rec *r, char *input, char *buffer, int nbuf,
                      backrefinfo *briRR, backrefinfo *briRC)
{
    char *inp, *outp;
    apr_size_t span, space;

    /*
     * for security reasons this expansion must be performed in a
     * single pass, otherwise an attacker can arrange for the result
     * of an earlier expansion to include expansion specifiers that
     * are interpreted by a later expansion, producing results that
     * were not intended by the administrator.
     */

    inp = input;
    outp = buffer;
    space = nbuf - 1; /* room for '\0' */

    for (;;) {
        span = strcspn(inp, "\\$%");
        if (span > space) {
            span = space;
        }
        memcpy(outp, inp, span);
        inp += span;
        outp += span;
        space -= span;
        if (space == 0 || *inp == '\0') {
            break;
        }
        /* now we have a '\', '$', or '%' */
        if (inp[0] == '\\') {
            if (inp[1] != '\0') {
                inp++;
                goto skip;
            }
        }
        else if (inp[1] == '{') {
            char *endp;
            endp = find_closing_bracket(inp+2, '{', '}');
            if (endp == NULL) {
                goto skip;
            }
            /*
            * These lookups may be recursive in a very convoluted
            * fashion -- see the LA-U and LA-F variable expansion
            * prefixes -- so we copy lookup keys to a separate buffer
            * rather than adding zero bytes in order to use them in
            * place.
            */
            if (inp[0] == '$') {
                /* ${...} map lookup expansion */
                /*
                * To make rewrite maps useful the lookup key and
                * default values must be expanded, so we make
                * recursive calls to do the work. For security
                * reasons we must never expand a string that includes
                * verbatim data from the network. The recursion here
                * isn't a problem because the result of expansion is
                * only passed to lookup_map() so it cannot be
                * re-expanded, only re-looked-up. Another way of
                * looking at it is that the recursion is entirely
                * driven by the syntax of the nested curly brackets.
                */
                char *map, *key, *dflt, *result;
                char xkey[MAX_STRING_LEN];
                char xdflt[MAX_STRING_LEN];
                key = find_char_in_brackets(inp+2, ':', '{', '}');
                if (key == NULL) {
                    goto skip;
                }
                map  = apr_pstrndup(r->pool, inp+2, key-inp-2);
                dflt = find_char_in_brackets(key+1, '|', '{', '}');
                if (dflt == NULL) {
                    key  = apr_pstrndup(r->pool, key+1, endp-key-1);
                    dflt = "";
                }
                else {
                    key  = apr_pstrndup(r->pool, key+1, dflt-key-1);
                    dflt = apr_pstrndup(r->pool, dflt+1, endp-dflt-1);
                }
                do_expand(r, key,  xkey,  sizeof(xkey),  briRR, briRC);
                result = lookup_map(r, map, xkey);
                if (result) {
                    span = apr_cpystrn(outp, result, space) - outp;
                }
                else {
                    do_expand(r, dflt, xdflt, sizeof(xdflt), briRR, briRC);
                    span = apr_cpystrn(outp, xdflt, space) - outp;
                }
            }
            else if (inp[0] == '%') {
                /* %{...} variable lookup expansion */
                char *var;
                var  = apr_pstrndup(r->pool, inp+2, endp-inp-2);
                span = apr_cpystrn(outp, lookup_variable(r, var), space) - outp;
            }
            else {
                span = 0;
            }
            inp = endp+1;
            outp += span;
            space -= span;
            continue;
        }
        else if (apr_isdigit(inp[1])) {
            int n = inp[1] - '0';
            backrefinfo *bri = NULL;
            if (inp[0] == '$') {
                /* $N RewriteRule regexp backref expansion */
                bri = briRR;
            }
            else if (inp[0] == '%') {
                /* %N RewriteCond regexp backref expansion */
                bri = briRC;
            }
            /* see ap_pregsub() in src/main/util.c */
            if (bri && n <= bri->nsub
                && bri->regmatch[n].rm_eo > bri->regmatch[n].rm_so) {
                span = bri->regmatch[n].rm_eo - bri->regmatch[n].rm_so;
                if (span > space) {
                    span = space;
                }
                memcpy(outp, bri->source + bri->regmatch[n].rm_so, span);
                outp += span;
                space -= span;
            }
            inp += 2;
            continue;
        }
        skip:
        *outp++ = *inp++;
        space--;
    }
    *outp++ = '\0';
}


/*
**
**  perform all the expansions on the environment variables
**
*/

static void do_expand_env(request_rec *r, char *env[],
                          backrefinfo *briRR, backrefinfo *briRC)
{
    int i;
    char buf[MAX_STRING_LEN];

    for (i = 0; env[i] != NULL; i++) {
        do_expand(r, env[i], buf, sizeof(buf), briRR, briRC);
        add_env_variable(r, buf);
    }
}

static void do_expand_cookie( request_rec *r, char *cookie[],
                              backrefinfo *briRR, backrefinfo *briRC)
{
    int i;
    char buf[MAX_STRING_LEN];

    for (i = 0; cookie[i] != NULL; i++) {
        do_expand(r, cookie[i], buf, sizeof(buf), briRR, briRC);
        add_cookie(r, buf);
    }
}


/*
**
**  split out a QUERY_STRING part from
**  the current URI string
**
*/

static void splitout_queryargs(request_rec *r, int qsappend)
{
    char *q;
    char *olduri;

    /* don't touch, unless it's an http or mailto URL.
     * See RFC 1738 and RFC 2368.
     */
    if (   is_absolute_uri(r->filename)
        && strncasecmp(r->filename, "http", 4)
        && strncasecmp(r->filename, "mailto", 6)) {
        r->args = NULL; /* forget the query that's still flying around */
        return;
    }

    q = strchr(r->filename, '?');
    if (q != NULL) {
        olduri = apr_pstrdup(r->pool, r->filename);
        *q++ = '\0';
        if (qsappend) {
            r->args = apr_pstrcat(r->pool, q, "&", r->args, NULL);
        }
        else {
            r->args = apr_pstrdup(r->pool, q);
        }
        if (strlen(r->args) == 0) {
            r->args = NULL;
            rewritelog(r, 3, "split uri=%s -> uri=%s, args=<none>", olduri,
                       r->filename);
        }
        else {
            if (r->args[strlen(r->args)-1] == '&') {
                r->args[strlen(r->args)-1] = '\0';
            }
            rewritelog(r, 3, "split uri=%s -> uri=%s, args=%s", olduri,
                       r->filename, r->args);
        }
    }

    return;
}


/*
**
**  strip 'http[s]://ourhost/' from URI
**
*/

static void reduce_uri(request_rec *r)
{
    char *cp;
    unsigned short port;
    char *portp;
    char *hostp;
    char *url;
    char c;
    char host[LONG_STRING_LEN];
    char buf[MAX_STRING_LEN];
    char *olduri;
    apr_size_t l;

    cp = (char *)ap_http_method(r);
    l  = strlen(cp);
    if (   strlen(r->filename) > l+3
        && strncasecmp(r->filename, cp, l) == 0
        && r->filename[l]   == ':'
        && r->filename[l+1] == '/'
        && r->filename[l+2] == '/'             ) {
        /* there was really a rewrite to a remote path */

        olduri = apr_pstrdup(r->pool, r->filename); /* save for logging */

        /* cut the hostname and port out of the URI */
        apr_cpystrn(buf, r->filename+(l+3), sizeof(buf));
        hostp = buf;
        for (cp = hostp; *cp != '\0' && *cp != '/' && *cp != ':'; cp++)
            ;
        if (*cp == ':') {
            /* set host */
            *cp++ = '\0';
            apr_cpystrn(host, hostp, sizeof(host));
            /* set port */
            portp = cp;
            for (; *cp != '\0' && *cp != '/'; cp++)
                ;
            c = *cp;
            *cp = '\0';
            port = atoi(portp);
            *cp = c;
            /* set remaining url */
            url = cp;
        }
        else if (*cp == '/') {
            /* set host */
            *cp = '\0';
            apr_cpystrn(host, hostp, sizeof(host));
            *cp = '/';
            /* set port */
            port = ap_default_port(r);
            /* set remaining url */
            url = cp;
        }
        else {
            /* set host */
            apr_cpystrn(host, hostp, sizeof(host));
            /* set port */
            port = ap_default_port(r);
            /* set remaining url */
            url = "/";
        }

        /* now check whether we could reduce it to a local path... */
        if (ap_matches_request_vhost(r, host, port)) {
            /* this is our host, so only the URL remains */
            r->filename = apr_pstrdup(r->pool, url);
            rewritelog(r, 3, "reduce %s -> %s", olduri, r->filename);
        }
    }
    return;
}


/*
**
**  add 'http[s]://ourhost[:ourport]/' to URI
**  if URI is still not fully qualified
**
*/

static void fully_qualify_uri(request_rec *r)
{
    char buf[32];
    const char *thisserver;
    char *thisport;
    int port;

    if (!is_absolute_uri(r->filename)) {

        thisserver = ap_get_server_name(r);
        port = ap_get_server_port(r);
        if (ap_is_default_port(port,r)) {
            thisport = "";
        }
        else {
            apr_snprintf(buf, sizeof(buf), ":%u", port);
            thisport = buf;
        }

        if (r->filename[0] == '/') {
            r->filename = apr_psprintf(r->pool, "%s://%s%s%s",
                                       ap_http_method(r), thisserver,
                                       thisport, r->filename);
        }
        else {
            r->filename = apr_psprintf(r->pool, "%s://%s%s/%s",
                                       ap_http_method(r), thisserver,
                                       thisport, r->filename);
        }
    }
    return;
}


/* return number of chars of the scheme (incl. '://')
 * if the URI is absolute (includes a scheme etc.)
 * otherwise 0.
 *
 * NOTE: If you add new schemes here, please have a
 *       look at escape_absolute_uri and splitout_queryargs.
 *       Not every scheme takes query strings and some schemes
 *       may be handled in a special way.
 *
 * XXX: we should consider a scheme registry, perhaps with
 *      appropriate escape callbacks to allow other modules
 *      to extend mod_rewrite at runtime.
 */
static unsigned is_absolute_uri(char *uri)
{
    /* fast exit */
    if (*uri == '/' || strlen(uri) <= 5) {
        return 0;
    }

    switch (*uri++) {
    case 'f':
    case 'F':
        if (!strncasecmp(uri, "tp://", 5)) {        /* ftp://    */
            return 6;
        }
        break;

    case 'g':
    case 'G':
        if (!strncasecmp(uri, "opher://", 8)) {     /* gopher:// */
            return 9;
        }
        break;

    case 'h':
    case 'H':
        if (!strncasecmp(uri, "ttp://", 6)) {       /* http://   */
            return 7;
        }
        else if (!strncasecmp(uri, "ttps://", 7)) { /* https://  */
            return 8;
        }
        break;

    case 'l':
    case 'L':
        if (!strncasecmp(uri, "dap://", 6)) {       /* ldap://   */
            return 7;
        }
        break;

    case 'm':
    case 'M':
        if (!strncasecmp(uri, "ailto:", 6)) {       /* mailto:   */
            return 7;
        }
        break;

    case 'n':
    case 'N':
        if (!strncasecmp(uri, "ews:", 4)) {         /* news:     */
            return 5;
        }
        else if (!strncasecmp(uri, "ntp://", 6)) {  /* nntp://   */
            return 7;
        }
        break;
    }

    return 0;
}


/* escape absolute uri, which may or may not be path oriented.
 * So let's handle them differently.
 */
static char *escape_absolute_uri(apr_pool_t *p, char *uri, unsigned scheme)
{
    char *cp;

    /* be safe.
     * NULL should indicate elsewhere, that something's wrong
     */
    if (!scheme || strlen(uri) < scheme) {
        return NULL;
    }

    cp = uri + scheme;

    /* scheme with authority part? */
    if (cp[-1] == '/') {
        /* skip host part */
        while (*cp && *cp != '/') {
            ++cp;
        }

        /* nothing after the hostpart. ready! */
        if (!*cp || !*++cp) {
            return apr_pstrdup(p, uri);
        }

        /* remember the hostname stuff */
        scheme = cp - uri;

        /* special thing for ldap.
         * The parts are separated by question marks. From RFC 2255:
         *     ldapurl = scheme "://" [hostport] ["/"
         *               [dn ["?" [attributes] ["?" [scope]
         *               ["?" [filter] ["?" extensions]]]]]]
         */
        if (!strncasecmp(uri, "ldap", 4)) {
            char *token[5];
            int c = 0;

            token[0] = cp = apr_pstrdup(p, cp);
            while (*cp && c < 5) {
                if (*cp == '?') {
                    token[++c] = cp + 1;
                    *cp = '\0';
                }
                ++cp;
            }

            return apr_pstrcat(p, apr_pstrndup(p, uri, scheme),
                                          ap_escape_uri(p, token[0]),
                               (c >= 1) ? "?" : NULL,
                               (c >= 1) ? ap_escape_uri(p, token[1]) : NULL,
                               (c >= 2) ? "?" : NULL,
                               (c >= 2) ? ap_escape_uri(p, token[2]) : NULL,
                               (c >= 3) ? "?" : NULL,
                               (c >= 3) ? ap_escape_uri(p, token[3]) : NULL,
                               (c >= 4) ? "?" : NULL,
                               (c >= 4) ? ap_escape_uri(p, token[4]) : NULL,
                               NULL);
        }
    }

    /* Nothing special here. Apply normal escaping. */
    return apr_pstrcat(p, apr_pstrndup(p, uri, scheme),
                       ap_escape_uri(p, cp), NULL);
}


/*
**
**  Expand tilde-paths (/~user) through Unix /etc/passwd
**  database information (or other OS-specific database)
**
*/
#if APR_HAS_USER
static char *expand_tildepaths(request_rec *r, char *uri)
{
    char user[LONG_STRING_LEN];
    char *newuri;
    int i, j;
    char *homedir;

    newuri = uri;
    if (uri != NULL && strlen(uri) > 2 && uri[0] == '/' && uri[1] == '~') {
        /* cut out the username */
        for (j = 0, i = 2; j < sizeof(user)-1
               && uri[i] != '\0'
               && uri[i] != '/'  ; ) {
            user[j++] = uri[i++];
        }
        user[j] = '\0';

        /* lookup username in systems passwd file */
        if (apr_get_home_directory(&homedir, user, r->pool) == APR_SUCCESS) {
            /* ok, user was found, so expand the ~user string */
            if (uri[i] != '\0') {
                /* ~user/anything...  has to be expanded */
                if (homedir[strlen(homedir)-1] == '/') {
                    homedir[strlen(homedir)-1] = '\0';
                }
                newuri = apr_pstrcat(r->pool, homedir, uri+i, NULL);
            }
            else {
                /* only ~user has to be expanded */
                newuri = homedir;
            }
        }
    }
    return newuri;
}
#endif  /* if APR_HAS_USER */



/*
** +-------------------------------------------------------+
** |                                                       |
** |              DBM hashfile support
** |                                                       |
** +-------------------------------------------------------+
*/


static char *lookup_map(request_rec *r, char *name, char *key)
{
    rewrite_server_conf *conf;
    apr_array_header_t *rewritemaps;
    rewritemap_entry *entries;
    rewritemap_entry *s;
    char *value;
    apr_finfo_t st;
    apr_status_t rv;
    int i;

    /* get map configuration */
    conf = ap_get_module_config(r->server->module_config, &rewrite_module);
    rewritemaps = conf->rewritemaps;

    entries = (rewritemap_entry *)rewritemaps->elts;
    for (i = 0; i < rewritemaps->nelts; i++) {
        s = &entries[i];
        if (strcmp(s->name, name) == 0) {
            if (s->type == MAPTYPE_TXT) {
                if ((rv = apr_stat(&st, s->checkfile,
                                   APR_FINFO_MIN, r->pool)) != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                  "mod_rewrite: can't access text RewriteMap "
                                  "file %s", s->checkfile);
                    rewritelog(r, 1, "can't open RewriteMap file, "
                               "see error log");
                    return NULL;
                }
                value = get_cache_string(cachep, s->name, CACHEMODE_TS,
                                         st.mtime, key);
                if (value == NULL) {
                    rewritelog(r, 6, "cache lookup FAILED, forcing new "
                               "map lookup");
                    if ((value =
                         lookup_map_txtfile(r, s->datafile, key)) != NULL) {
                        rewritelog(r, 5, "map lookup OK: map=%s key=%s[txt] "
                                   "-> val=%s", s->name, key, value);
                        set_cache_string(cachep, s->name, CACHEMODE_TS,
                                         st.mtime, key, value);
                        return value;
                    }
                    else {
                        rewritelog(r, 5, "map lookup FAILED: map=%s[txt] "
                                   "key=%s", s->name, key);
                        set_cache_string(cachep, s->name, CACHEMODE_TS,
                                         st.mtime, key, "");
                        return NULL;
                    }
                }
                else {
                    rewritelog(r, 5, "cache lookup OK: map=%s[txt] key=%s "
                               "-> val=%s", s->name, key, value);
                    return value[0] != '\0' ? value : NULL;
                }
            }
            else if (s->type == MAPTYPE_DBM) {
                if ((rv = apr_stat(&st, s->checkfile,
                                   APR_FINFO_MIN, r->pool)) != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                  "mod_rewrite: can't access DBM RewriteMap "
                                  "file %s", s->checkfile);
                    rewritelog(r, 1, "can't open DBM RewriteMap file, "
                               "see error log");
                    return NULL;
                }
                value = get_cache_string(cachep, s->name, CACHEMODE_TS,
                                         st.mtime, key);
                if (value == NULL) {
                    rewritelog(r, 6,
                               "cache lookup FAILED, forcing new map lookup");
                    if ((value =
                         lookup_map_dbmfile(r, s->datafile, s->dbmtype, key)) != NULL) {
                        rewritelog(r, 5, "map lookup OK: map=%s[dbm] key=%s "
                                   "-> val=%s", s->name, key, value);
                        set_cache_string(cachep, s->name, CACHEMODE_TS,
                                         st.mtime, key, value);
                        return value;
                    }
                    else {
                        rewritelog(r, 5, "map lookup FAILED: map=%s[dbm] "
                                   "key=%s", s->name, key);
                        set_cache_string(cachep, s->name, CACHEMODE_TS,
                                         st.mtime, key, "");
                        return NULL;
                    }
                }
                else {
                    rewritelog(r, 5, "cache lookup OK: map=%s[dbm] key=%s "
                               "-> val=%s", s->name, key, value);
                    return value[0] != '\0' ? value : NULL;
                }
            }
            else if (s->type == MAPTYPE_PRG) {
                if ((value =
                     lookup_map_program(r, s->fpin, s->fpout, key)) != NULL) {
                    rewritelog(r, 5, "map lookup OK: map=%s key=%s -> val=%s",
                               s->name, key, value);
                    return value;
                }
                else {
                    rewritelog(r, 5, "map lookup FAILED: map=%s key=%s",
                               s->name, key);
                }
            }
            else if (s->type == MAPTYPE_INT) {
                if ((value = s->func(r, key)) != NULL) {
                    rewritelog(r, 5, "map lookup OK: map=%s key=%s -> val=%s",
                               s->name, key, value);
                    return value;
                }
                else {
                    rewritelog(r, 5, "map lookup FAILED: map=%s key=%s",
                               s->name, key);
                }
            }
            else if (s->type == MAPTYPE_RND) {
                if ((rv = apr_stat(&st, s->checkfile,
                                   APR_FINFO_MIN, r->pool)) != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                  "mod_rewrite: can't access text RewriteMap "
                                  "file %s", s->checkfile);
                    rewritelog(r, 1, "can't open RewriteMap file, "
                               "see error log");
                    return NULL;
                }
                value = get_cache_string(cachep, s->name, CACHEMODE_TS,
                                         st.mtime, key);
                if (value == NULL) {
                    rewritelog(r, 6, "cache lookup FAILED, forcing new "
                               "map lookup");
                    if ((value =
                         lookup_map_txtfile(r, s->datafile, key)) != NULL) {
                        rewritelog(r, 5, "map lookup OK: map=%s key=%s[txt] "
                                   "-> val=%s", s->name, key, value);
                        set_cache_string(cachep, s->name, CACHEMODE_TS,
                                         st.mtime, key, value);
                    }
                    else {
                        rewritelog(r, 5, "map lookup FAILED: map=%s[txt] "
                                   "key=%s", s->name, key);
                        set_cache_string(cachep, s->name, CACHEMODE_TS,
                                         st.mtime, key, "");
                        return NULL;
                    }
                }
                else {
                    rewritelog(r, 5, "cache lookup OK: map=%s[txt] key=%s "
                               "-> val=%s", s->name, key, value);
                }
                if (value[0] != '\0') {
                   value = select_random_value_part(r, value);
                   rewritelog(r, 5, "randomly choosen the subvalue `%s'",
                              value);
                }
                else {
                    value = NULL;
                }
                return value;
            }
        }
    }
    return NULL;
}

static char *lookup_map_txtfile(request_rec *r, const char *file, char *key)
{
    apr_file_t *fp = NULL;
    apr_status_t rc;
    char line[1024];
    char *value = NULL;
    char *cpT;
    apr_size_t skip;
    char *curkey;
    char *curval;

    rc = apr_file_open(&fp, file, APR_READ, APR_OS_DEFAULT, r->pool);
    if (rc != APR_SUCCESS) {
       return NULL;
    }

    while (apr_file_gets(line, sizeof(line), fp) == APR_SUCCESS) {
        if (line[0] == '#') {
            continue; /* ignore comments */
        }
        cpT = line;
        curkey = cpT;
        skip = strcspn(cpT," \t\r\n");
        if (skip == 0) {
            continue; /* ignore lines that start with a space, tab, CR, or LF */
        }
        cpT += skip;
        *cpT = '\0';
        if (strcmp(curkey, key) != 0) {
            continue; /* key does not match... */
        }

        /* found a matching key; now extract and return the value */
        ++cpT;
        skip = strspn(cpT, " \t\r\n");
        cpT += skip;
        curval = cpT;
        skip = strcspn(cpT, " \t\r\n");
        if (skip == 0) {
            continue; /* no value... */
        }
        cpT += skip;
        *cpT = '\0';
        value = apr_pstrdup(r->pool, curval);
        break;
    }
    apr_file_close(fp);
    return value;
}

static char *lookup_map_dbmfile(request_rec *r, const char *file,
                                const char *dbmtype, char *key)
{
    apr_dbm_t *dbmfp = NULL;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    char *value = NULL;
    char buf[MAX_STRING_LEN];
    apr_status_t rv;

    dbmkey.dptr  = key;
    dbmkey.dsize = strlen(key);
    if ((rv = apr_dbm_open_ex(&dbmfp, dbmtype, file, APR_DBM_READONLY,
                              0 /* irrelevant when reading */,
                              r->pool)) == APR_SUCCESS) {
        rv = apr_dbm_fetch(dbmfp, dbmkey, &dbmval);
        if (rv == APR_SUCCESS && dbmval.dptr) {
            memcpy(buf, dbmval.dptr,
                   dbmval.dsize < sizeof(buf)-1 ?
                   dbmval.dsize : sizeof(buf)-1  );
            buf[dbmval.dsize] = '\0';
            value = apr_pstrdup(r->pool, buf);
        }
        apr_dbm_close(dbmfp);
    }
    return value;
}

static char *lookup_map_program(request_rec *r, apr_file_t *fpin,
                                apr_file_t *fpout, char *key)
{
    char buf[LONG_STRING_LEN];
    char c;
    int i;
    apr_size_t nbytes;
    apr_status_t rv;

#ifndef NO_WRITEV
    struct iovec iova[2];
    apr_size_t niov;
#endif

    /* when `RewriteEngine off' was used in the per-server
     * context then the rewritemap-programs were not spawned.
     * In this case using such a map (usually in per-dir context)
     * is useless because it is not available.
     */
    if (fpin == NULL || fpout == NULL) {
        return NULL;
    }

    /* take the lock */

    if (rewrite_mapr_lock_acquire) {
        rv = apr_global_mutex_lock(rewrite_mapr_lock_acquire);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "apr_global_mutex_lock(rewrite_mapr_lock_acquire) "
                          "failed");
            return NULL; /* Maybe this should be fatal? */
        }
    }

    /* write out the request key */
#ifdef NO_WRITEV
    nbytes = strlen(key);
    apr_file_write(fpin, key, &nbytes);
    nbytes = 1;
    apr_file_write(fpin, "\n", &nbytes);
#else
    iova[0].iov_base = key;
    iova[0].iov_len = strlen(key);
    iova[1].iov_base = "\n";
    iova[1].iov_len = 1;

    niov = 2;
    apr_file_writev(fpin, iova, niov, &nbytes);
#endif

    /* read in the response value */
    i = 0;
    nbytes = 1;
    apr_file_read(fpout, &c, &nbytes);
    while (nbytes == 1 && (i < LONG_STRING_LEN-1)) {
        if (c == '\n') {
            break;
        }
        buf[i++] = c;

        apr_file_read(fpout, &c, &nbytes);
    }
    buf[i] = '\0';

    /* give the lock back */
    if (rewrite_mapr_lock_acquire) {
        rv = apr_global_mutex_unlock(rewrite_mapr_lock_acquire);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "apr_global_mutex_unlock(rewrite_mapr_lock_acquire) "
                          "failed");
            return NULL; /* Maybe this should be fatal? */
        }
    }

    if (strcasecmp(buf, "NULL") == 0) {
        return NULL;
    }
    else {
        return apr_pstrdup(r->pool, buf);
    }
}

static void ap_register_rewrite_mapfunc(char *name, rewrite_mapfunc_t *func)
{
    apr_hash_set(mapfunc_hash, name, strlen(name), (const void *)func);
}

static char *rewrite_mapfunc_toupper(request_rec *r, char *key)
{
    char *value, *cp;

    for (cp = value = apr_pstrdup(r->pool, key); cp != NULL && *cp != '\0';
         cp++) {
        *cp = apr_toupper(*cp);
    }
    return value;
}

static char *rewrite_mapfunc_tolower(request_rec *r, char *key)
{
    char *value, *cp;

    for (cp = value = apr_pstrdup(r->pool, key); cp != NULL && *cp != '\0';
         cp++) {
        *cp = apr_tolower(*cp);
    }
    return value;
}

static char *rewrite_mapfunc_escape(request_rec *r, char *key)
{
    char *value;

    value = ap_escape_uri(r->pool, key);
    return value;
}

static char *rewrite_mapfunc_unescape(request_rec *r, char *key)
{
    char *value;

    value = apr_pstrdup(r->pool, key);
    ap_unescape_url(value);
    return value;
}

static int rewrite_rand_init_done = 0;

static void rewrite_rand_init(void)
{
    if (!rewrite_rand_init_done) {
        srand((unsigned)(getpid()));
        rewrite_rand_init_done = 1;
    }
    return;
}

static int rewrite_rand(int l, int h)
{
    rewrite_rand_init();

    /* Get [0,1) and then scale to the appropriate range. Note that using
     * a floating point value ensures that we use all bits of the rand()
     * result. Doing an integer modulus would only use the lower-order bits
     * which may not be as uniformly random.
     */
    return (int)(((double)(rand() % RAND_MAX) / RAND_MAX) * (h - l + 1) + l);
}

static char *select_random_value_part(request_rec *r, char *value)
{
    char *buf;
    int n, i, k;

    /*  count number of distinct values  */
    for (n = 1, i = 0; value[i] != '\0'; i++) {
        if (value[i] == '|') {
            n++;
        }
    }

    /*  when only one value we have no option to choose  */
    if (n == 1) {
        return value;
    }

    /*  else randomly select one  */
    k = rewrite_rand(1, n);

    /*  and grep it out  */
    for (n = 1, i = 0; value[i] != '\0'; i++) {
        if (n == k) {
            break;
        }
        if (value[i] == '|') {
            n++;
        }
    }
    buf = apr_pstrdup(r->pool, &value[i]);
    for (i = 0; buf[i] != '\0' && buf[i] != '|'; i++)
        ;
    buf[i] = '\0';
    return buf;
}


/*
** +-------------------------------------------------------+
** |                                                       |
** |              rewriting logfile support
** |                                                       |
** +-------------------------------------------------------+
*/


static void open_rewritelog(server_rec *s, apr_pool_t *p)
{
    rewrite_server_conf *conf;
    const char *fname;
    apr_status_t rc;
    piped_log *pl;
    int rewritelog_flags = ( APR_WRITE | APR_APPEND | APR_CREATE );
    apr_fileperms_t rewritelog_mode = ( APR_UREAD | APR_UWRITE |
                                        APR_GREAD | APR_WREAD );

    conf = ap_get_module_config(s->module_config, &rewrite_module);

    if (conf->rewritelogfile == NULL) {
        return;
    }
    if (*(conf->rewritelogfile) == '\0') {
        return;
    }
    if (conf->rewritelogfp != NULL) {
        return; /* virtual log shared w/ main server */
    }

    if (*conf->rewritelogfile == '|') {
        if ((pl = ap_open_piped_log(p, conf->rewritelogfile+1)) == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mod_rewrite: could not open reliable pipe "
                         "to RewriteLog filter %s", conf->rewritelogfile+1);
            exit(1);
        }
        conf->rewritelogfp = ap_piped_log_write_fd(pl);
    }
    else if (*conf->rewritelogfile != '\0') {
        fname = ap_server_root_relative(p, conf->rewritelogfile);
        if (!fname) {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
                         "mod_rewrite: Invalid RewriteLog "
                         "path %s", conf->rewritelogfile);
            exit(1);
        }
        if ((rc = apr_file_open(&conf->rewritelogfp, fname,
                                rewritelog_flags, rewritelog_mode, p))
                != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rc, s,
                         "mod_rewrite: could not open RewriteLog "
                         "file %s", fname);
            exit(1);
        }
    }
    return;
}

static void rewritelog(request_rec *r, int level, const char *text, ...)
{
    rewrite_server_conf *conf;
    conn_rec *conn;
    char *str1;
    char str2[512];
    char str3[1024];
    const char *type;
    char redir[20]; /* enough for "/redir#%d" if int is 32 bit */
    va_list ap;
    int i;
    apr_size_t nbytes;
    request_rec *req;
    char *ruser;
    const char *rhost;
    apr_status_t rv;

    va_start(ap, text);
    conf = ap_get_module_config(r->server->module_config, &rewrite_module);
    conn = r->connection;

    if (conf->rewritelogfp == NULL) {
        return;
    }
    if (conf->rewritelogfile == NULL) {
        return;
    }
    if (*(conf->rewritelogfile) == '\0') {
        return;
    }

    if (level > conf->rewriteloglevel) {
        return;
    }

    if (r->user == NULL) {
        ruser = "-";
    }
    else if (strlen(r->user) != 0) {
        ruser = r->user;
    }
    else {
        ruser = "\"\"";
    }

    rhost = ap_get_remote_host(conn, r->per_dir_config,
                               REMOTE_NOLOOKUP, NULL);
    if (rhost == NULL) {
        rhost = "UNKNOWN-HOST";
    }

    str1 = apr_pstrcat(r->pool, rhost, " ",
                      (conn->remote_logname != NULL ?
                      conn->remote_logname : "-"), " ",
                      ruser, NULL);
    apr_vsnprintf(str2, sizeof(str2), text, ap);

    if (r->main == NULL) {
        type = "initial";
    }
    else {
        type = "subreq";
    }

    for (i = 0, req = r; req->prev != NULL; req = req->prev) {
        i++;
    }
    if (i == 0) {
        redir[0] = '\0';
    }
    else {
        apr_snprintf(redir, sizeof(redir), "/redir#%d", i);
    }

    apr_snprintf(str3, sizeof(str3),
                "%s %s [%s/sid#%lx][rid#%lx/%s%s] (%d) %s" APR_EOL_STR, str1,
                current_logtime(r), ap_get_server_name(r),
                (unsigned long)(r->server), (unsigned long)r,
                type, redir, level, str2);

    rv = apr_global_mutex_lock(rewrite_log_lock);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "apr_global_mutex_lock(rewrite_log_lock) failed");
        /* XXX: Maybe this should be fatal? */
    }
    nbytes = strlen(str3);
    apr_file_write(conf->rewritelogfp, str3, &nbytes);
    rv = apr_global_mutex_unlock(rewrite_log_lock);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "apr_global_mutex_unlock(rewrite_log_lock) failed");
        /* XXX: Maybe this should be fatal? */
    }

    va_end(ap);
    return;
}

static char *current_logtime(request_rec *r)
{
    apr_time_exp_t t;
    char tstr[80];
    apr_size_t len;

    apr_time_exp_lt(&t, apr_time_now());

    apr_strftime(tstr, &len, 80, "[%d/%b/%Y:%H:%M:%S ", &t);
    apr_snprintf(tstr + strlen(tstr), 80-strlen(tstr), "%c%.2d%.2d]",
                 t.tm_gmtoff < 0 ? '-' : '+',
                 t.tm_gmtoff / (60*60), t.tm_gmtoff % (60*60));
    return apr_pstrdup(r->pool, tstr);
}




/*
** +-------------------------------------------------------+
** |                                                       |
** |              rewriting lockfile support
** |                                                       |
** +-------------------------------------------------------+
*/

#define REWRITELOCK_MODE ( APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD )

static apr_status_t rewritelock_create(server_rec *s, apr_pool_t *p)
{
    apr_status_t rc;

    /* only operate if a lockfile is used */
    if (lockname == NULL || *(lockname) == '\0') {
        return APR_SUCCESS;
    }

    /* create the lockfile */
    rc = apr_global_mutex_create(&rewrite_mapr_lock_acquire, lockname,
                                 APR_LOCK_DEFAULT, p);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rc, s,
                     "mod_rewrite: Parent could not create RewriteLock "
                     "file %s", lockname);
        return rc;
    }

#if APR_USE_SYSVSEM_SERIALIZE
    rc = unixd_set_global_mutex_perms(rewrite_mapr_lock_acquire);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rc, s,
                     "mod_rewrite: Parent could not set permissions "
                     "on RewriteLock; check User and Group directives");
        return rc;
    }
#endif

    return APR_SUCCESS;
}

static apr_status_t rewritelock_remove(void *data)
{
    /* only operate if a lockfile is used */
    if (lockname == NULL || *(lockname) == '\0') {
        return APR_SUCCESS;
    }

    /* destroy the rewritelock */
    apr_global_mutex_destroy (rewrite_mapr_lock_acquire);
    rewrite_mapr_lock_acquire = NULL;
    lockname = NULL;
    return(0);
}


/*
** +-------------------------------------------------------+
** |                                                       |
** |                  program map support
** |                                                       |
** +-------------------------------------------------------+
*/

static apr_status_t run_rewritemap_programs(server_rec *s, apr_pool_t *p)
{
    rewrite_server_conf *conf;
    apr_array_header_t *rewritemaps;
    rewritemap_entry *entries;
    int i;
    apr_status_t rc;

    conf = ap_get_module_config(s->module_config, &rewrite_module);

    /*  If the engine isn't turned on,
     *  don't even try to do anything.
     */
    if (conf->state == ENGINE_DISABLED) {
        return APR_SUCCESS;
    }

    rewritemaps = conf->rewritemaps;
    entries = (rewritemap_entry *)rewritemaps->elts;
    for (i = 0; i < rewritemaps->nelts; i++) {
        apr_file_t *fpin = NULL;
        apr_file_t *fpout = NULL;
        rewritemap_entry *map = &entries[i];

        if (map->type != MAPTYPE_PRG) {
            continue;
        }
        if (map->argv[0] == NULL
            || *(map->argv[0]) == '\0'
            || map->fpin  != NULL
            || map->fpout != NULL        ) {
            continue;
        }
        rc = rewritemap_program_child(p, map->argv[0], map->argv,
                                      &fpout, &fpin);
        if (rc != APR_SUCCESS || fpin == NULL || fpout == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rc, s,
                         "mod_rewrite: could not start RewriteMap "
                         "program %s", map->checkfile);
            return rc;
        }
        map->fpin  = fpin;
        map->fpout = fpout;
    }
    return APR_SUCCESS;
}

/* child process code */

static void rewrite_child_errfn(apr_pool_t *p, apr_status_t err,
                                const char *desc)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, err, NULL,
                 "%s", desc);
}

static apr_status_t rewritemap_program_child(apr_pool_t *p,
                                             const char *progname, char **argv,
                                             apr_file_t **fpout,
                                             apr_file_t **fpin)
{
    apr_status_t rc;
    apr_procattr_t *procattr;
    apr_proc_t *procnew;

    if (((rc = apr_procattr_create(&procattr, p)) != APR_SUCCESS) ||
        ((rc = apr_procattr_io_set(procattr, APR_FULL_BLOCK, APR_FULL_BLOCK,
                                   APR_NO_PIPE)) != APR_SUCCESS) ||
        ((rc = apr_procattr_dir_set(procattr,
                                   ap_make_dirstr_parent(p, argv[0])))
         != APR_SUCCESS) ||
        ((rc = apr_procattr_cmdtype_set(procattr, APR_PROGRAM)) != APR_SUCCESS) ||
        ((rc = apr_procattr_child_errfn_set(procattr, rewrite_child_errfn)) != APR_SUCCESS) ||
        ((rc = apr_procattr_error_check_set(procattr, 1)) != APR_SUCCESS) ||
        ((rc = apr_procattr_cmdtype_set(procattr, APR_PROGRAM)) != APR_SUCCESS)) {
        /* Something bad happened, give up and go away. */
    }
    else {
        procnew = apr_pcalloc(p, sizeof(*procnew));
        rc = apr_proc_create(procnew, argv[0], (const char **)argv, NULL,
                             procattr, p);

        if (rc == APR_SUCCESS) {
            apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);

            if (fpin) {
                (*fpin) = procnew->in;
            }

            if (fpout) {
                (*fpout) = procnew->out;
            }
        }
    }

    return (rc);
}




/*
** +-------------------------------------------------------+
** |                                                       |
** |             environment variable support
** |                                                       |
** +-------------------------------------------------------+
*/


static char *lookup_variable(request_rec *r, char *var)
{
    const char *result;
    char resultbuf[LONG_STRING_LEN];
    apr_time_exp_t tm;
    request_rec *rsub;

    result = NULL;

    /* HTTP headers */
    if (strcasecmp(var, "HTTP_USER_AGENT") == 0) {
        result = lookup_header(r, "User-Agent");
    }
    else if (strcasecmp(var, "HTTP_REFERER") == 0) {
        result = lookup_header(r, "Referer");
    }
    else if (strcasecmp(var, "HTTP_COOKIE") == 0) {
        result = lookup_header(r, "Cookie");
    }
    else if (strcasecmp(var, "HTTP_FORWARDED") == 0) {
        result = lookup_header(r, "Forwarded");
    }
    else if (strcasecmp(var, "HTTP_HOST") == 0) {
        result = lookup_header(r, "Host");
    }
    else if (strcasecmp(var, "HTTP_PROXY_CONNECTION") == 0) {
        result = lookup_header(r, "Proxy-Connection");
    }
    else if (strcasecmp(var, "HTTP_ACCEPT") == 0) {
        result = lookup_header(r, "Accept");
    }
    /* all other headers from which we are still not know about */
    else if (strlen(var) > 5 && strncasecmp(var, "HTTP:", 5) == 0) {
        result = lookup_header(r, var+5);
    }

    /* connection stuff */
    else if (strcasecmp(var, "REMOTE_ADDR") == 0) {
        result = r->connection->remote_ip;
    }
    else if (strcasecmp(var, "REMOTE_HOST") == 0) {
        result = (char *)ap_get_remote_host(r->connection,
                                            r->per_dir_config, REMOTE_NAME, NULL);
    }
    else if (strcasecmp(var, "REMOTE_USER") == 0) {
        result = r->user;
    }
    else if (strcasecmp(var, "REMOTE_IDENT") == 0) {
        result = (char *)ap_get_remote_logname(r);
    }

    /* request stuff */
    else if (strcasecmp(var, "THE_REQUEST") == 0) { /* non-standard */
        result = r->the_request;
    }
    else if (strcasecmp(var, "REQUEST_METHOD") == 0) {
        result = r->method;
    }
    else if (strcasecmp(var, "REQUEST_URI") == 0) { /* non-standard */
        result = r->uri;
    }
    else if (strcasecmp(var, "SCRIPT_FILENAME") == 0 ||
             strcasecmp(var, "REQUEST_FILENAME") == 0  ) {
        result = r->filename;
    }
    else if (strcasecmp(var, "PATH_INFO") == 0) {
        result = r->path_info;
    }
    else if (strcasecmp(var, "QUERY_STRING") == 0) {
        result = r->args;
    }
    else if (strcasecmp(var, "AUTH_TYPE") == 0) {
        result = r->ap_auth_type;
    }
    else if (strcasecmp(var, "IS_SUBREQ") == 0) { /* non-standard */
        result = (r->main != NULL ? "true" : "false");
    }

    /* internal server stuff */
    else if (strcasecmp(var, "DOCUMENT_ROOT") == 0) {
        result = ap_document_root(r);
    }
    else if (strcasecmp(var, "SERVER_ADMIN") == 0) {
        result = r->server->server_admin;
    }
    else if (strcasecmp(var, "SERVER_NAME") == 0) {
        result = ap_get_server_name(r);
    }
    else if (strcasecmp(var, "SERVER_ADDR") == 0) { /* non-standard */
        result = r->connection->local_ip;
    }
    else if (strcasecmp(var, "SERVER_PORT") == 0) {
        apr_snprintf(resultbuf, sizeof(resultbuf), "%u", ap_get_server_port(r));
        result = resultbuf;
    }
    else if (strcasecmp(var, "SERVER_PROTOCOL") == 0) {
        result = r->protocol;
    }
    else if (strcasecmp(var, "SERVER_SOFTWARE") == 0) {
        result = ap_get_server_version();
    }
    else if (strcasecmp(var, "API_VERSION") == 0) { /* non-standard */
        apr_snprintf(resultbuf, sizeof(resultbuf), "%d:%d",
                     MODULE_MAGIC_NUMBER_MAJOR, MODULE_MAGIC_NUMBER_MINOR);
        result = resultbuf;
    }

/* XXX: wow this has gotta be slow if you actually use it for a lot, recalculates exploded time for each variable */
    /* underlaying Unix system stuff */
    else if (strcasecmp(var, "TIME_YEAR") == 0) {
        apr_time_exp_lt(&tm, apr_time_now());
        apr_snprintf(resultbuf, sizeof(resultbuf), "%04d", tm.tm_year + 1900);
        result = resultbuf;
    }
#define MKTIMESTR(format, tmfield) \
    apr_time_exp_lt(&tm, apr_time_now()); \
    apr_snprintf(resultbuf, sizeof(resultbuf), format, tm.tmfield); \
    result = resultbuf;
    else if (strcasecmp(var, "TIME_MON") == 0) {
        MKTIMESTR("%02d", tm_mon+1)
    }
    else if (strcasecmp(var, "TIME_DAY") == 0) {
        MKTIMESTR("%02d", tm_mday)
    }
    else if (strcasecmp(var, "TIME_HOUR") == 0) {
        MKTIMESTR("%02d", tm_hour)
    }
    else if (strcasecmp(var, "TIME_MIN") == 0) {
        MKTIMESTR("%02d", tm_min)
    }
    else if (strcasecmp(var, "TIME_SEC") == 0) {
        MKTIMESTR("%02d", tm_sec)
    }
    else if (strcasecmp(var, "TIME_WDAY") == 0) {
        MKTIMESTR("%d", tm_wday)
    }
    else if (strcasecmp(var, "TIME") == 0) {
        apr_time_exp_lt(&tm, apr_time_now());
        apr_snprintf(resultbuf, sizeof(resultbuf),
                     "%04d%02d%02d%02d%02d%02d", tm.tm_year + 1900,
                     tm.tm_mon+1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
        result = resultbuf;
        rewritelog(r, 1, "RESULT='%s'", result);
    }

    /* all other env-variables from the parent Apache process */
    else if (strlen(var) > 4 && strncasecmp(var, "ENV:", 4) == 0) {
        /* first try the internal Apache notes structure */
        result = apr_table_get(r->notes, var+4);
        /* second try the internal Apache env structure  */
        if (result == NULL) {
            result = apr_table_get(r->subprocess_env, var+4);
        }
        /* third try the external OS env */
        if (result == NULL) {
            result = getenv(var+4);
        }
    }

#define LOOKAHEAD(subrecfunc, input) \
        if ( \
          /* filename is safe to use */ \
          (input) != NULL \
              /* - and we're either not in a subrequest */ \
              && ( r->main == NULL \
                  /* - or in a subrequest where paths are non-NULL... */ \
                    || ( r->main->uri != NULL && r->uri != NULL \
                        /*   ...and sub and main paths differ */ \
                        && strcmp(r->main->uri, r->uri) != 0))) { \
            /* process a file-based subrequest */ \
            rsub = subrecfunc((input), r, NULL); \
            /* now recursively lookup the variable in the sub_req */ \
            result = lookup_variable(rsub, var+5); \
            /* copy it up to our scope before we destroy sub_req's apr_pool_t */ \
            result = apr_pstrdup(r->pool, result); \
            /* cleanup by destroying the subrequest */ \
            ap_destroy_sub_req(rsub); \
            /* log it */ \
            rewritelog(r, 5, "lookahead: path=%s var=%s -> val=%s", \
                       (input), var+5, result); \
            /* return ourself to prevent re-pstrdup */ \
            return (char *)result; \
        }

    /* look-ahead for parameter through URI-based sub-request */
    else if (strlen(var) > 5 && strncasecmp(var, "LA-U:", 5) == 0) {
        LOOKAHEAD(ap_sub_req_lookup_uri, r->uri)
    }
    /* look-ahead for parameter through file-based sub-request */
    else if (strlen(var) > 5 && strncasecmp(var, "LA-F:", 5) == 0) {
        LOOKAHEAD(ap_sub_req_lookup_file, r->filename)
    }

    /* file stuff */
    else if (strcasecmp(var, "SCRIPT_USER") == 0) {
        result = "<unknown>";
        if (r->finfo.valid & APR_FINFO_USER) {
            apr_get_username((char **)&result, r->finfo.user, r->pool);
        }
    }
    else if (strcasecmp(var, "SCRIPT_GROUP") == 0) {
        result = "<unknown>";
        if (r->finfo.valid & APR_FINFO_GROUP) {
            apr_group_name_get((char **)&result, r->finfo.group, r->pool);
        }
    }

    if (result == NULL) {
        return apr_pstrdup(r->pool, "");
    }
    else {
        return apr_pstrdup(r->pool, result);
    }
}

static char *lookup_header(request_rec *r, const char *name)
{
    const apr_array_header_t *hdrs_arr;
    const apr_table_entry_t *hdrs;
    int i;

    hdrs_arr = apr_table_elts(r->headers_in);
    hdrs = (const apr_table_entry_t *)hdrs_arr->elts;
    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (hdrs[i].key == NULL) {
            continue;
        }
        if (strcasecmp(hdrs[i].key, name) == 0) {
            apr_table_merge(r->notes, VARY_KEY_THIS, name);
            return hdrs[i].val;
        }
    }
    return NULL;
}




/*
** +-------------------------------------------------------+
** |                                                       |
** |                    caching support
** |                                                       |
** +-------------------------------------------------------+
*/


static cache *init_cache(apr_pool_t *p)
{
    cache *c;

    c = (cache *)apr_palloc(p, sizeof(cache));
    if (apr_pool_create(&c->pool, p) != APR_SUCCESS) {
        return NULL;
    }
    c->lists = apr_array_make(c->pool, 2, sizeof(cachelist));
#if APR_HAS_THREADS
    (void)apr_thread_mutex_create(&(c->lock), APR_THREAD_MUTEX_DEFAULT, p);
#endif
    return c;
}

static void set_cache_string(cache *c, const char *res, int mode, apr_time_t t,
                             char *key, char *value)
{
    cacheentry ce;

    ce.time  = t;
    ce.key   = key;
    ce.value = value;
    store_cache_string(c, res, &ce);
    return;
}

static char *get_cache_string(cache *c, const char *res, int mode,
                              apr_time_t t, char *key)
{
    cacheentry *ce;

    ce = retrieve_cache_string(c, res, key);
    if (ce == NULL) {
        return NULL;
    }
    if (mode & CACHEMODE_TS) {
        if (t != ce->time) {
            return NULL;
        }
    }
    else if (mode & CACHEMODE_TTL) {
        if (t > ce->time) {
            return NULL;
        }
    }
    return apr_pstrdup(c->pool, ce->value);
}

static int cache_tlb_hash(char *key)
{
    unsigned long n;
    char *p;

    n = 0;
    for (p = key; *p != '\0'; p++) {
        n = ((n << 5) + n) ^ (unsigned long)(*p++);
    }

    return n % CACHE_TLB_ROWS;
}

static cacheentry *cache_tlb_lookup(cachetlbentry *tlb, cacheentry *elt,
                                    char *key)
{
    int ix = cache_tlb_hash(key);
    int i;
    int j;

    for (i=0; i < CACHE_TLB_COLS; ++i) {
        j = tlb[ix].t[i];
        if (j < 0)
            return NULL;
        if (strcmp(elt[j].key, key) == 0)
            return &elt[j];
    }
    return NULL;
}

static void cache_tlb_replace(cachetlbentry *tlb, cacheentry *elt,
                              cacheentry *e)
{
    int ix = cache_tlb_hash(e->key);
    int i;

    tlb = &tlb[ix];

    for (i=1; i < CACHE_TLB_COLS; ++i)
        tlb->t[i] = tlb->t[i-1];

    tlb->t[0] = e - elt;
}

static void store_cache_string(cache *c, const char *res, cacheentry *ce)
{
    int i;
    int j;
    cachelist *l;
    cacheentry *e;
    cachetlbentry *t;
    int found_list;

#if APR_HAS_THREADS
    apr_thread_mutex_lock(c->lock);
#endif

    found_list = 0;
    /* first try to edit an existing entry */
    for (i = 0; i < c->lists->nelts; i++) {
        l = &(((cachelist *)c->lists->elts)[i]);
        if (strcmp(l->resource, res) == 0) {
            found_list = 1;

            e = cache_tlb_lookup((cachetlbentry *)l->tlb->elts,
                                 (cacheentry *)l->entries->elts, ce->key);
            if (e != NULL) {
                e->time  = ce->time;
                e->value = apr_pstrdup(c->pool, ce->value);
#if APR_HAS_THREADS
                apr_thread_mutex_unlock(c->lock);
#endif
                return;
            }

            for (j = 0; j < l->entries->nelts; j++) {
                e = &(((cacheentry *)l->entries->elts)[j]);
                if (strcmp(e->key, ce->key) == 0) {
                    e->time  = ce->time;
                    e->value = apr_pstrdup(c->pool, ce->value);
                    cache_tlb_replace((cachetlbentry *)l->tlb->elts,
                                      (cacheentry *)l->entries->elts, e);
#if APR_HAS_THREADS
                    apr_thread_mutex_unlock(c->lock);
#endif
                    return;
                }
            }
        }
    }

    /* create a needed new list */
    if (!found_list) {
        l = apr_array_push(c->lists);
        l->resource = apr_pstrdup(c->pool, res);
        l->entries  = apr_array_make(c->pool, 2, sizeof(cacheentry));
        l->tlb      = apr_array_make(c->pool, CACHE_TLB_ROWS,
                                    sizeof(cachetlbentry));
        for (i=0; i<CACHE_TLB_ROWS; ++i) {
            t = &((cachetlbentry *)l->tlb->elts)[i];
                for (j=0; j<CACHE_TLB_COLS; ++j)
                    t->t[j] = -1;
        }
    }

    /* create the new entry */
    for (i = 0; i < c->lists->nelts; i++) {
        l = &(((cachelist *)c->lists->elts)[i]);
        if (strcmp(l->resource, res) == 0) {
            e = apr_array_push(l->entries);
            e->time  = ce->time;
            e->key   = apr_pstrdup(c->pool, ce->key);
            e->value = apr_pstrdup(c->pool, ce->value);
            cache_tlb_replace((cachetlbentry *)l->tlb->elts,
                              (cacheentry *)l->entries->elts, e);
#if APR_HAS_THREADS
            apr_thread_mutex_unlock(c->lock);
#endif
            return;
        }
    }

    /* not reached, but when it is no problem... */
#if APR_HAS_THREADS
    apr_thread_mutex_unlock(c->lock);
#endif
    return;
}

static cacheentry *retrieve_cache_string(cache *c, const char *res, char *key)
{
    int i;
    int j;
    cachelist *l;
    cacheentry *e;

#if APR_HAS_THREADS
    apr_thread_mutex_lock(c->lock);
#endif

    for (i = 0; i < c->lists->nelts; i++) {
        l = &(((cachelist *)c->lists->elts)[i]);
        if (strcmp(l->resource, res) == 0) {

            e = cache_tlb_lookup((cachetlbentry *)l->tlb->elts,
                                 (cacheentry *)l->entries->elts, key);
            if (e != NULL) {
#if APR_HAS_THREADS
                apr_thread_mutex_unlock(c->lock);
#endif
                return e;
            }

            for (j = 0; j < l->entries->nelts; j++) {
                e = &(((cacheentry *)l->entries->elts)[j]);
                if (strcmp(e->key, key) == 0) {
#if APR_HAS_THREADS
                    apr_thread_mutex_unlock(c->lock);
#endif
                    return e;
                }
            }
        }
    }
#if APR_HAS_THREADS
    apr_thread_mutex_unlock(c->lock);
#endif
    return NULL;
}




/*
** +-------------------------------------------------------+
** |                                                       |
** |                    misc functions
** |                                                       |
** +-------------------------------------------------------+
*/

static char *subst_prefix_path(request_rec *r, char *input, char *match,
                               const char *subst)
{
    char matchbuf[LONG_STRING_LEN];
    char substbuf[LONG_STRING_LEN];
    char *output;
    int l;

    output = input;

    /* first create a match string which always has a trailing slash */
    l = apr_cpystrn(matchbuf, match, sizeof(matchbuf) - 1) - matchbuf;
    if (!l || matchbuf[l-1] != '/') {
       matchbuf[l] = '/';
       matchbuf[l+1] = '\0';
       l++;
    }
    /* now compare the prefix */
    if (strncmp(input, matchbuf, l) == 0) {
        rewritelog(r, 5, "strip matching prefix: %s -> %s", output, output+l);
        output = apr_pstrdup(r->pool, output+l);

        /* and now add the base-URL as replacement prefix */
        l = apr_cpystrn(substbuf, subst, sizeof(substbuf) - 1) - substbuf;
        if (!l || substbuf[l-1] != '/') {
           substbuf[l] = '/';
           substbuf[l+1] = '\0';
           l++;
        }
        if (output[0] == '/') {
            rewritelog(r, 4, "add subst prefix: %s -> %s%s",
                       output, substbuf, output+1);
            output = apr_pstrcat(r->pool, substbuf, output+1, NULL);
        }
        else {
            rewritelog(r, 4, "add subst prefix: %s -> %s%s",
                       output, substbuf, output);
            output = apr_pstrcat(r->pool, substbuf, output, NULL);
        }
    }
    return output;
}


/*
**
**  own command line parser which don't have the '\\' problem
**
*/

static int parseargline(char *str, char **a1, char **a2, char **a3)
{
    char *cp;
    int isquoted;

#define SKIP_WHITESPACE(cp) \
    for ( ; *cp == ' ' || *cp == '\t'; ) { \
        cp++; \
    };

#define CHECK_QUOTATION(cp,isquoted) \
    isquoted = 0; \
    if (*cp == '"') { \
        isquoted = 1; \
        cp++; \
    }

#define DETERMINE_NEXTSTRING(cp,isquoted) \
    for ( ; *cp != '\0'; cp++) { \
        if (   (isquoted    && (*cp     == ' ' || *cp     == '\t')) \
            || (*cp == '\\' && (*(cp+1) == ' ' || *(cp+1) == '\t'))) { \
            cp++; \
            continue; \
        } \
        if (   (!isquoted && (*cp == ' ' || *cp == '\t')) \
            || (isquoted  && *cp == '"')                  ) { \
            break; \
        } \
    }

    cp = str;
    SKIP_WHITESPACE(cp);

    /*  determine first argument */
    CHECK_QUOTATION(cp, isquoted);
    *a1 = cp;
    DETERMINE_NEXTSTRING(cp, isquoted);
    if (*cp == '\0') {
        return 1;
    }
    *cp++ = '\0';

    SKIP_WHITESPACE(cp);

    /*  determine second argument */
    CHECK_QUOTATION(cp, isquoted);
    *a2 = cp;
    DETERMINE_NEXTSTRING(cp, isquoted);
    if (*cp == '\0') {
        *cp++ = '\0';
        *a3 = NULL;
        return 0;
    }
    *cp++ = '\0';

    SKIP_WHITESPACE(cp);

    /* again check if there are only two arguments */
    if (*cp == '\0') {
        *cp++ = '\0';
        *a3 = NULL;
        return 0;
    }

    /*  determine second argument */
    CHECK_QUOTATION(cp, isquoted);
    *a3 = cp;
    DETERMINE_NEXTSTRING(cp, isquoted);
    *cp++ = '\0';

    return 0;
}


static void add_env_variable(request_rec *r, char *s)
{
    char var[MAX_STRING_LEN];
    char val[MAX_STRING_LEN];
    char *cp;
    int n;

    if ((cp = strchr(s, ':')) != NULL) {
        n = ((cp-s) > MAX_STRING_LEN-1 ? MAX_STRING_LEN-1 : (cp-s));
        memcpy(var, s, n);
        var[n] = '\0';
        apr_cpystrn(val, cp+1, sizeof(val));
        apr_table_set(r->subprocess_env, var, val);
        rewritelog(r, 5, "setting env variable '%s' to '%s'", var, val);
    }
}

static void add_cookie(request_rec *r, char *s)
{
    char *var;
    char *val;
    char *domain;
    char *expires;
    char *path;

    char *tok_cntx;
    char *cookie;

    if (s) {
        var = apr_strtok(s, ":", &tok_cntx);
        val = apr_strtok(NULL, ":", &tok_cntx);
        domain = apr_strtok(NULL, ":", &tok_cntx);
        /** the line below won't hit the token ever **/
        expires = apr_strtok(NULL, ":", &tok_cntx);
        if (expires) {
            path = apr_strtok(NULL,":", &tok_cntx);
        }
        else {
            path = NULL;
        }

        if (var && val && domain) {
            /* FIX: use cached time similar to how logging does it */
            request_rec *rmain = r;
            char *notename;
            void *data;
            while (rmain->main) {
                rmain = rmain->main;
            }

            notename = apr_pstrcat(rmain->pool, var, "_rewrite", NULL);
            apr_pool_userdata_get(&data, notename, rmain->pool);
            if (data == NULL) {
                cookie = apr_pstrcat(rmain->pool,
                                     var, "=", val,
                                     "; path=", (path)? path : "/",
                                     "; domain=", domain,
                                     (expires)? "; expires=" : NULL,
                                     (expires)?
                                     ap_ht_time(r->pool,
                                                r->request_time +
                                                apr_time_from_sec((60 *
                                                               atol(expires))),
                                                "%a, %d-%b-%Y %T GMT", 1)
                                              : NULL,
                                     NULL);
                /*
                 * XXX: should we add it to err_headers_out as well ?
                 * if we do we need to be careful that only ONE gets sent out
                 */
                apr_table_add(rmain->err_headers_out, "Set-Cookie", cookie);
                apr_pool_userdata_set("set", notename, NULL, rmain->pool);
                rewritelog(rmain, 5, "setting cookie '%s'", cookie);
            }
            else {
                rewritelog(rmain, 5, "skipping already set cookie '%s'", var);
            }
        }
    }
}


/*
**
**  check that a subrequest won't cause infinite recursion
**
*/

static int subreq_ok(request_rec *r)
{
    /*
     * either not in a subrequest, or in a subrequest
     * and URIs aren't NULL and sub/main URIs differ
     */
    return (r->main == NULL
            || (r->main->uri != NULL
                && r->uri != NULL
                && strcmp(r->main->uri, r->uri) != 0));
}


/*
**
**  stat() for only the prefix of a path
**
*/

static int prefix_stat(const char *path, apr_pool_t *pool)
{
    const char *curpath = path;
    const char *root;
    const char *slash;
    char *statpath;
    apr_status_t rv;

    rv = apr_filepath_root(&root, &curpath, APR_FILEPATH_TRUENAME, pool);

    if (rv != APR_SUCCESS) {
        return 0;
    }

    /* let's recognize slashes only, the mod_rewrite semantics are opaque
     * enough.
     */
    if ((slash = ap_strchr_c(curpath, '/')) != NULL) {
        rv = apr_filepath_merge(&statpath, root,
                                apr_pstrndup(pool, curpath,
                                             (apr_size_t)(slash - curpath)),
                                APR_FILEPATH_NOTABOVEROOT |
                                APR_FILEPATH_NOTRELATIVE, pool);
    }
    else {
        rv = apr_filepath_merge(&statpath, root, curpath,
                                APR_FILEPATH_NOTABOVEROOT |
                                APR_FILEPATH_NOTRELATIVE, pool);
    }

    if (rv == APR_SUCCESS) {
        apr_finfo_t sb;
        
        if (apr_stat(&sb, statpath, APR_FINFO_MIN, pool) == APR_SUCCESS) {
            return 1;
        }
    }

    return 0;
}


/*
**
**  Lexicographic Compare
**
*/

static int compare_lexicography(char *cpNum1, char *cpNum2)
{
    int i;
    int n1, n2;

    n1 = strlen(cpNum1);
    n2 = strlen(cpNum2);
    if (n1 > n2) {
        return 1;
    }
    if (n1 < n2) {
        return -1;
    }
    for (i = 0; i < n1; i++) {
        if (cpNum1[i] > cpNum2[i]) {
            return 1;
        }
        if (cpNum1[i] < cpNum2[i]) {
            return -1;
        }
    }
    return 0;
}

/*
**
**  Bracketed expression handling
**  s points after the opening bracket
**
*/

static char *find_closing_bracket(char *s, int left, int right)
{
    int depth;

    for (depth = 1; *s; ++s) {
        if (*s == right && --depth == 0) {
            return s;
        }
        else if (*s == left) {
            ++depth;
        }
    }
    return NULL;
}

static char *find_char_in_brackets(char *s, int c, int left, int right)
{
    int depth;

    for (depth = 1; *s; ++s) {
        if (*s == c && depth == 1) {
            return s;
        }
        else if (*s == right && --depth == 0) {
            return NULL;
        }
        else if (*s == left) {
            ++depth;
        }
    }
    return NULL;
}

/*
**
** Module paraphernalia
**
*/

    /* the apr_table_t of commands we provide */
static const command_rec command_table[] = {
    AP_INIT_FLAG(    "RewriteEngine",   cmd_rewriteengine,  NULL, OR_FILEINFO,
                     "On or Off to enable or disable (default) the whole "
                     "rewriting engine"),
    AP_INIT_ITERATE( "RewriteOptions",  cmd_rewriteoptions,  NULL, OR_FILEINFO,
                     "List of option strings to set"),
    AP_INIT_TAKE1(   "RewriteBase",     cmd_rewritebase,     NULL, OR_FILEINFO,
                     "the base URL of the per-directory context"),
    AP_INIT_RAW_ARGS("RewriteCond",     cmd_rewritecond,     NULL, OR_FILEINFO,
                     "an input string and a to be applied regexp-pattern"),
    AP_INIT_RAW_ARGS("RewriteRule",     cmd_rewriterule,     NULL, OR_FILEINFO,
                     "an URL-applied regexp-pattern and a substitution URL"),
    AP_INIT_TAKE2(   "RewriteMap",      cmd_rewritemap,      NULL, RSRC_CONF,
                     "a mapname and a filename"),
    AP_INIT_TAKE1(   "RewriteLock",     cmd_rewritelock,     NULL, RSRC_CONF,
                     "the filename of a lockfile used for inter-process "
                     "synchronization"),
    AP_INIT_TAKE1(   "RewriteLog",      cmd_rewritelog,      NULL, RSRC_CONF,
                     "the filename of the rewriting logfile"),
    AP_INIT_TAKE1(   "RewriteLogLevel", cmd_rewriteloglevel, NULL, RSRC_CONF,
                     "the level of the rewriting logfile verbosity "
                     "(0=none, 1=std, .., 9=max)"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    /* fixup after mod_proxy, so that the proxied url will not
     * escaped accidentally by mod_proxy's fixup.
     */
    static const char * const aszPre[]={ "mod_proxy.c", NULL };

    /* check type before mod_mime, so that [T=foo/bar] will not be
     * overridden by AddType definitions.
     */
    static const char * const ct_aszSucc[]={ "mod_mime.c", NULL };

    APR_REGISTER_OPTIONAL_FN(ap_register_rewrite_mapfunc);

    ap_hook_handler(handler_redirect, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(init_child, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_fixups(hook_fixup, aszPre, NULL, APR_HOOK_FIRST);
    ap_hook_translate_name(hook_uri2file, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_type_checker(hook_mimetype, NULL, ct_aszSucc, APR_HOOK_MIDDLE);
}

    /* the main config structure */
module AP_MODULE_DECLARE_DATA rewrite_module = {
   STANDARD20_MODULE_STUFF,
   config_perdir_create,        /* create per-dir    config structures */
   config_perdir_merge,         /* merge  per-dir    config structures */
   config_server_create,        /* create per-server config structures */
   config_server_merge,         /* merge  per-server config structures */
   command_table,               /* table of config file commands       */
   register_hooks               /* register hooks                      */
};

/*EOF*/
