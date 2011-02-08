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
 * mod_userdir... implement the UserDir command.  Broken away from the
 * Alias stuff for a couple of good and not-so-good reasons:
 *
 * 1) It shows a real minimal working example of how to do something like
 *    this.
 * 2) I know people who are actually interested in changing this *particular*
 *    aspect of server functionality without changing the rest of it.  That's
 *    what this whole modular arrangement is supposed to be good at...
 *
 * Modified by Alexei Kosut to support the following constructs
 * (server running at www.foo.com, request for /~bar/one/two.html)
 *
 * UserDir public_html      -> ~bar/public_html/one/two.html
 * UserDir /usr/web         -> /usr/web/bar/one/two.html
 * UserDir /home/ * /www     -> /home/bar/www/one/two.html
 *  NOTE: theses ^ ^ space only added allow it to work in a comment, ignore
 * UserDir http://x/users   -> (302) http://x/users/bar/one/two.html
 * UserDir http://x/ * /y     -> (302) http://x/bar/y/one/two.html
 *  NOTE: here also ^ ^
 *
 * In addition, you can use multiple entries, to specify alternate
 * user directories (a la Directory Index). For example:
 *
 * UserDir public_html /usr/web http://www.xyz.com/users
 *
 * Modified by Ken Coar to provide for the following:
 *
 * UserDir disable[d] username ...
 * UserDir enable[d] username ...
 *
 * If "disabled" has no other arguments, *all* ~<username> references are
 * disabled, except those explicitly turned on with the "enabled" keyword.
 */

#include "apr_strings.h"
#include "apr_user.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"

#if !defined(WIN32) && !defined(OS2) && !defined(BEOS) && !defined(NETWARE)
#define HAVE_UNIX_SUEXEC
#endif

#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"        /* Contains the suexec_identity hook used on Unix */
#endif


/*
 * The default directory in user's home dir
 * In the default install, the module is disabled
 */
#ifndef DEFAULT_USER_DIR
#define DEFAULT_USER_DIR NULL
#endif

#define O_DEFAULT 0
#define O_ENABLE 1
#define O_DISABLE 2

module AP_MODULE_DECLARE_DATA userdir_module;

typedef struct {
    int globally_disabled;
    char *userdir;
    apr_table_t *enabled_users;
    apr_table_t *disabled_users;
} userdir_config;

/*
 * Server config for this module: global disablement flag, a list of usernames
 * ineligible for UserDir access, a list of those immune to global (but not
 * explicit) disablement, and the replacement string for all others.
 */

static void *create_userdir_config(apr_pool_t *p, server_rec *s)
{
    userdir_config *newcfg = apr_pcalloc(p, sizeof(*newcfg));

    newcfg->globally_disabled = O_DEFAULT;
    newcfg->userdir = DEFAULT_USER_DIR;
    newcfg->enabled_users = apr_table_make(p, 4);
    newcfg->disabled_users = apr_table_make(p, 4);

    return newcfg;
}

static void *merge_userdir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    userdir_config *cfg = apr_pcalloc(p, sizeof(userdir_config));
    userdir_config *base = basev, *overrides = overridesv;
 
    cfg->globally_disabled = (overrides->globally_disabled != O_DEFAULT) ? overrides->globally_disabled : base->globally_disabled;
    cfg->userdir = (overrides->userdir != DEFAULT_USER_DIR) ? overrides->userdir : base->userdir;
 
    /* not merged */
    cfg->enabled_users = overrides->enabled_users;
    cfg->disabled_users = overrides->disabled_users;
    
    return cfg;
}


static const char *set_user_dir(cmd_parms *cmd, void *dummy, const char *arg)
{
    userdir_config *s_cfg = ap_get_module_config(cmd->server->module_config,
                                                 &userdir_module);
    char *username;
    const char *usernames = arg;
    char *kw = ap_getword_conf(cmd->pool, &usernames);
    apr_table_t *usertable;

    /* Since we are a raw argument, it is possible for us to be called with
     * zero arguments.  So that we aren't ambiguous, flat out reject this.
     */
    if (*kw == '\0') {
        return "UserDir requires an argument.";
    }

    /*
     * Let's do the comparisons once.
     */
    if ((!strcasecmp(kw, "disable")) || (!strcasecmp(kw, "disabled"))) {
        /*
         * If there are no usernames specified, this is a global disable - we
         * need do no more at this point than record the fact.
         */
        if (strlen(usernames) == 0) {
            s_cfg->globally_disabled = O_DISABLE;
            return NULL;
        }
        usertable = s_cfg->disabled_users;
    }
    else if ((!strcasecmp(kw, "enable")) || (!strcasecmp(kw, "enabled"))) {
        if (strlen(usernames) == 0) {
            s_cfg->globally_disabled = O_ENABLE;
            return NULL;
        }
        usertable = s_cfg->enabled_users;
    }
    else {
        /*
         * If the first (only?) value isn't one of our keywords, just copy
         * the string to the userdir string.
         */
        s_cfg->userdir = apr_pstrdup(cmd->pool, arg);
        return NULL;
    }
    /*
     * Now we just take each word in turn from the command line and add it to
     * the appropriate table.
     */
    while (*usernames) {
        username = ap_getword_conf(cmd->pool, &usernames);
        apr_table_setn(usertable, username, kw);
    }
    return NULL;
}

static const command_rec userdir_cmds[] = {
    AP_INIT_RAW_ARGS("UserDir", set_user_dir, NULL, RSRC_CONF,
                     "the public subdirectory in users' home directories, or "
                     "'disabled', or 'disabled username username...', or "
                     "'enabled username username...'"),
    {NULL}
};

static int translate_userdir(request_rec *r)
{
    ap_conf_vector_t *server_conf;
    const userdir_config *s_cfg;
    char *name = r->uri;
    const char *userdirs;
    const char *w, *dname;
    char *redirect;
    apr_finfo_t statbuf;

    /*
     * If the URI doesn't match our basic pattern, we've nothing to do with
     * it.
     */
    if (name[0] != '/' || name[1] != '~') {
        return DECLINED;
    }
    server_conf = r->server->module_config;
    s_cfg = ap_get_module_config(server_conf, &userdir_module);
    userdirs = s_cfg->userdir;
    if (userdirs == NULL) {
        return DECLINED;
    }

    dname = name + 2;
    w = ap_getword(r->pool, &dname, '/');

    /*
     * The 'dname' funny business involves backing it up to capture the '/'
     * delimiting the "/~user" part from the rest of the URL, in case there
     * was one (the case where there wasn't being just "GET /~user HTTP/1.0",
     * for which we don't want to tack on a '/' onto the filename).
     */

    if (dname[-1] == '/') {
        --dname;
    }

    /*
     * If there's no username, it's not for us.  Ignore . and .. as well.
     */
    if (w[0] == '\0' || (w[1] == '.' && (w[2] == '\0' || (w[2] == '.' && w[3] == '\0')))) {
        return DECLINED;
    }
    /*
     * Nor if there's an username but it's in the disabled list.
     */
    if (apr_table_get(s_cfg->disabled_users, w) != NULL) {
        return DECLINED;
    }
    /*
     * If there's a global interdiction on UserDirs, check to see if this
     * name is one of the Blessed.
     */
    if (s_cfg->globally_disabled == O_DISABLE
        && apr_table_get(s_cfg->enabled_users, w) == NULL) {
        return DECLINED;
    }

    /*
     * Special cases all checked, onward to normal substitution processing.
     */

    while (*userdirs) {
        const char *userdir = ap_getword_conf(r->pool, &userdirs);
        char *filename = NULL, *x = NULL;
        apr_status_t rv;
        int is_absolute = ap_os_is_path_absolute(r->pool, userdir);

        if (ap_strchr_c(userdir, '*'))
            x = ap_getword(r->pool, &userdir, '*');

        if (userdir[0] == '\0' || is_absolute) {
            if (x) {
#ifdef HAVE_DRIVE_LETTERS
                /*
                 * Crummy hack. Need to figure out whether we have been
                 * redirected to a URL or to a file on some drive. Since I
                 * know of no protocols that are a single letter, ignore
                 * a : as the first or second character, and assume a file
                 * was specified
                 */
                if (strchr(x + 2, ':'))
#else
                if (strchr(x, ':') && !is_absolute)
#endif /* HAVE_DRIVE_LETTERS */
                {
                    redirect = apr_pstrcat(r->pool, x, w, userdir, dname, NULL);
                    apr_table_setn(r->headers_out, "Location", redirect);
                    return HTTP_MOVED_TEMPORARILY;
                }
                else
                    filename = apr_pstrcat(r->pool, x, w, userdir, NULL);
            }
            else
                filename = apr_pstrcat(r->pool, userdir, "/", w, NULL);
        }
        else if (x && ap_strchr_c(x, ':')) {
            redirect = apr_pstrcat(r->pool, x, w, dname, NULL);
            apr_table_setn(r->headers_out, "Location", redirect);
            return HTTP_MOVED_TEMPORARILY;
        }
        else {
#if APR_HAS_USER
            char *homedir;

            if (apr_uid_homepath_get(&homedir, w, r->pool) == APR_SUCCESS) {
                filename = apr_pstrcat(r->pool, homedir, "/", userdir, NULL);
            }
#else
            return DECLINED;
#endif
        }

        /*
         * Now see if it exists, or we're at the last entry. If we are at the
         * last entry, then use the filename generated (if there is one)
         * anyway, in the hope that some handler might handle it. This can be
         * used, for example, to run a CGI script for the user.
         */
        if (filename && (!*userdirs
                      || ((rv = apr_stat(&statbuf, filename, APR_FINFO_MIN,
                                         r->pool)) == APR_SUCCESS
                                             || rv == APR_INCOMPLETE))) {
            r->filename = apr_pstrcat(r->pool, filename, dname, NULL);
            /* XXX: Does this walk us around FollowSymLink rules?
             * When statbuf contains info on r->filename we can save a syscall
             * by copying it to r->finfo
             */
            if (*userdirs && dname[0] == 0)
                r->finfo = statbuf;

            /* For use in the get_suexec_identity phase */
            apr_table_setn(r->notes, "mod_userdir_user", w);

            return OK;
        }
    }

    return DECLINED;
}

#ifdef HAVE_UNIX_SUEXEC
static ap_unix_identity_t *get_suexec_id_doer(const request_rec *r)
{
    ap_unix_identity_t *ugid = NULL;
#if APR_HAS_USER
    const char *username = apr_table_get(r->notes, "mod_userdir_user");

    if (username == NULL) {
        return NULL;
    }

    if ((ugid = apr_palloc(r->pool, sizeof(*ugid))) == NULL) {
        return NULL;
    }

    if (apr_uid_get(&ugid->uid, &ugid->gid, username, r->pool) != APR_SUCCESS) {
        return NULL;
    }

    ugid->userdir = 1;
#endif
    return ugid;
}
#endif /* HAVE_UNIX_SUEXEC */

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszPre[]={ "mod_alias.c",NULL };
    static const char * const aszSucc[]={ "mod_vhost_alias.c",NULL };

    ap_hook_translate_name(translate_userdir,aszPre,aszSucc,APR_HOOK_MIDDLE);
#ifdef HAVE_UNIX_SUEXEC
    ap_hook_get_suexec_identity(get_suexec_id_doer,NULL,NULL,APR_HOOK_FIRST);
#endif
}

module AP_MODULE_DECLARE_DATA userdir_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    create_userdir_config,      /* server config */
    merge_userdir_config,       /* merge server config */
    userdir_cmds,               /* command apr_table_t */
    register_hooks              /* register hooks */
};
