
/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
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
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
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
 */

#include "httpd.h"
#include "http_config.h"

module userdir_module;

/*
 * Sever config for this module is a little unconventional...
 * It's just one string anyway, so why pretend?
 */

void *create_userdir_config (pool *dummy, server_rec *s) { 
    return (void*)DEFAULT_USER_DIR; 
}

char *set_user_dir (cmd_parms *cmd, void *dummy, char *arg)
{
    void *server_conf = cmd->server->module_config;
    
    set_module_config (server_conf, &userdir_module, pstrdup (cmd->pool, arg));
    return NULL;
}

command_rec userdir_cmds[] = {
{ "UserDir", set_user_dir, NULL, RSRC_CONF, RAW_ARGS,
    "the public subdirectory in users' home directories, or 'disabled'" },
{ NULL }
};

int translate_userdir (request_rec *r)
{
    void *server_conf = r->server->module_config;
    char *userdirs = (char *)get_module_config(server_conf, &userdir_module);
    char *name = r->uri;
    char *w, *dname, *redirect;
    char *x = NULL;

    if (userdirs == NULL || !strcasecmp(userdirs, "disabled") ||
        (name[0] != '/') || (name[1] != '~')) {
      return DECLINED;
    }

    while (*userdirs) {
      char *userdir = getword_conf (r->pool, &userdirs);
      char *filename = NULL;

      dname = name + 2;
      w = getword(r->pool, &dname, '/');

      if (!strcmp(w, ""))
	return DECLINED;

      /* The 'dname' funny business involves backing it up to capture
       * the '/' delimiting the "/~user" part from the rest of the URL,
       * in case there was one (the case where there wasn't being just
       * "GET /~user HTTP/1.0", for which we don't want to tack on a
       * '/' onto the filename).
       */
	
      if (dname[-1] == '/') --dname;

      if (strchr(userdir, '*'))
	x = getword(r->pool, &userdir, '*');

      if (userdir[0] == '/') {
	if (x) {
	  if (strchr(x, ':')) {
	    redirect = pstrcat(r->pool, x, w, userdir, dname, NULL);
	    table_set (r->headers_out, "Location", redirect);
	    return REDIRECT;
	  }
	  else
	    filename = pstrcat (r->pool, x, w, userdir, NULL);
	}
	else
	  filename = pstrcat (r->pool, userdir, "/", w, NULL);
      }
      else if (strchr(userdir, ':')) {
	redirect = pstrcat(r->pool, userdir, "/", w, dname, NULL);
	table_set (r->headers_out, "Location", redirect);
	return REDIRECT;
      }
      else {
	struct passwd *pw;
	if((pw=getpwnam(w)))
#ifdef __EMX__
	  /* Need to manually add user name for OS/2 */
	  filename = pstrcat (r->pool, pw->pw_dir, w, "/", userdir, NULL);
#else
	  filename = pstrcat (r->pool, pw->pw_dir, "/", userdir, NULL);
#endif

      }

      /* Now see if it exists, or we're at the last entry. If we are at the
       last entry, then use the filename generated (if there is one) anyway,
       in the hope that some handler might handle it. This can be used, for
       example, to run a CGI script for the user. 
       */
      if (filename && (!*userdirs || stat(filename, &r->finfo) != -1)) {
	r->filename = pstrcat(r->pool, filename, dname, NULL);
	return OK;
      }
    }

  return DECLINED;    
}
    
module userdir_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   NULL,			/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   create_userdir_config,	/* server config */
   NULL,			/* merge server config */
   userdir_cmds,		/* command table */
   NULL,			/* handlers */
   translate_userdir,		/*filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
