/* ====================================================================
 * Copyright (c) 1995-1998 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
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

#include "httpd.h"
#include "http_config.h"

module userdir_module;

typedef struct userdir_config {
    int globally_disabled;
    char *userdir;
    table *enabled_users;
    table *disabled_users;
}              userdir_config;

/*
 * Server config for this module: global disablement flag, a list of usernames
 * ineligible for UserDir access, a list of those immune to global (but not
 * explicit) disablement, and the replacement string for all others.
 */

static void *create_userdir_config(pool *p, server_rec *s)
{
    userdir_config
    * newcfg = (userdir_config *) ap_pcalloc(p, sizeof(userdir_config));

    newcfg->globally_disabled = 0;
    newcfg->userdir = DEFAULT_USER_DIR;
    newcfg->enabled_users = ap_make_table(p, 4);
    newcfg->disabled_users = ap_make_table(p, 4);
    return (void *) newcfg;
}

#define O_DEFAULT 0
#define O_ENABLE 1
#define O_DISABLE 2

static const char *set_user_dir(cmd_parms *cmd, void *dummy, char *arg)
{
    userdir_config
    * s_cfg = (userdir_config *) ap_get_module_config
    (
     cmd->server->module_config,
     &userdir_module
    );
    char *username;
    const char
        *usernames = arg;
    char *kw = ap_getword_conf(cmd->pool, &usernames);
    table *usertable;

    /*
     * Let's do the comparisons once.
     */
    if ((!strcasecmp(kw, "disable")) || (!strcasecmp(kw, "disabled"))) {
        /*
         * If there are no usernames specified, this is a global disable - we
         * need do no more at this point than record the fact.
         */
        if (strlen(usernames) == 0) {
            s_cfg->globally_disabled = 1;
            return NULL;
        }
        usertable = s_cfg->disabled_users;
    }
    else if ((!strcasecmp(kw, "enable")) || (!strcasecmp(kw, "enabled"))) {
        /*
         * The "disable" keyword can stand alone or take a list of names, but
         * the "enable" keyword requires the list.  Whinge if it doesn't have
         * it.
         */
        if (strlen(usernames) == 0) {
            return "UserDir \"enable\" keyword requires a list of usernames";
        }
        usertable = s_cfg->enabled_users;
    }
    else {
        /*
         * If the first (only?) value isn't one of our keywords, just copy
         * the string to the userdir string.
         */
        s_cfg->userdir = ap_pstrdup(cmd->pool, arg);
        return NULL;
    }
    /*
     * Now we just take each word in turn from the command line and add it to
     * the appropriate table.
     */
    while (*usernames) {
        username = ap_getword_conf(cmd->pool, &usernames);
        ap_table_setn(usertable, username, kw);
    }
    return NULL;
}

static const command_rec userdir_cmds[] = {
    {"UserDir", set_user_dir, NULL, RSRC_CONF, RAW_ARGS,
    "the public subdirectory in users' home directories, or 'disabled', or 'disabled username username...', or 'enabled username username...'"},
    {NULL}
};

static int translate_userdir(request_rec *r)
{
    void *server_conf = r->server->module_config;
    const userdir_config *s_cfg =
    (userdir_config *) ap_get_module_config(server_conf, &userdir_module);
    char *name = r->uri;
    const char *userdirs = s_cfg->userdir;
    const char *w, *dname;
    char *redirect;
    char *x = NULL;
    struct stat statbuf;

    /*
     * If the URI doesn't match our basic pattern, we've nothing to do with
     * it.
     */
    if (
        (s_cfg->userdir == NULL) ||
        (name[0] != '/') ||
        (name[1] != '~')
        ) {
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
    if (ap_table_get(s_cfg->disabled_users, w) != NULL) {
        return DECLINED;
    }
    /*
     * If there's a global interdiction on UserDirs, check to see if this
     * name is one of the Blessed.
     */
    if (
        s_cfg->globally_disabled &&
        (ap_table_get(s_cfg->enabled_users, w) == NULL)
        ) {
        return DECLINED;
    }

    /*
     * Special cases all checked, onward to normal substitution processing.
     */

    while (*userdirs) {
        const char *userdir = ap_getword_conf(r->pool, &userdirs);
        char *filename = NULL;

        if (strchr(userdir, '*'))
            x = ap_getword(r->pool, &userdir, '*');

	if (userdir[0] == '\0' || ap_os_is_path_absolute(userdir)) {
            if (x) {
#ifdef WIN32
                /*
                 * Crummy hack. Need to figure out whether we have been
                 * redirected to a URL or to a file on some drive. Since I
                 * know of no protocols that are a single letter, if the : is
                 * the second character, I will assume a file was specified
                 */
                if (strchr(x + 2, ':'))
#else
                if (strchr(x, ':'))
#endif                          /* WIN32 */
		{
                    redirect = ap_pstrcat(r->pool, x, w, userdir, dname, NULL);
                    ap_table_setn(r->headers_out, "Location", redirect);
                    return REDIRECT;
                }
                else
                    filename = ap_pstrcat(r->pool, x, w, userdir, NULL);
            }
            else
                filename = ap_pstrcat(r->pool, userdir, "/", w, NULL);
        }
        else if (strchr(userdir, ':')) {
            redirect = ap_pstrcat(r->pool, userdir, "/", w, dname, NULL);
            ap_table_setn(r->headers_out, "Location", redirect);
            return REDIRECT;
        }
        else {
#ifdef WIN32
            /* Need to figure out home dirs on NT */
            return DECLINED;
#else                           /* WIN32 */
            struct passwd *pw;
            if ((pw = getpwnam(w))) {
#ifdef OS2
                /* Need to manually add user name for OS/2 */
                filename = ap_pstrcat(r->pool, pw->pw_dir, w, "/", userdir, NULL);
#else
                filename = ap_pstrcat(r->pool, pw->pw_dir, "/", userdir, NULL);
#endif
            }
#endif                          /* WIN32 */
        }

        /*
         * Now see if it exists, or we're at the last entry. If we are at the
         * last entry, then use the filename generated (if there is one)
         * anyway, in the hope that some handler might handle it. This can be
         * used, for example, to run a CGI script for the user.
         */
        if (filename && (!*userdirs || stat(filename, &statbuf) != -1)) {
            r->filename = ap_pstrcat(r->pool, filename, dname, NULL);
	    /* when statbuf contains info on r->filename we can save a syscall
	     * by copying it to r->finfo
	     */
	    if (*userdirs && dname[0] == 0)
		r->finfo = statbuf;
            return OK;
        }
    }

    return DECLINED;
}

module userdir_module = {
    STANDARD_MODULE_STUFF,
    NULL,                       /* initializer */
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    create_userdir_config,      /* server config */
    NULL,                       /* merge server config */
    userdir_cmds,               /* command table */
    NULL,                       /* handlers */
    translate_userdir,          /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    NULL                        /* post read-request */
};
