
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


/* Netscape Cookies Fixup
 *
 * This is a module for Shambhala for handling Netscape cookies.
 *
 * On each request look for a Cookie: header.
 * If we don't find one then send a Set-Cookie: header out with the request
 * Future requests from the same client should keep the same Cookie line.
 * Using the cookie log you can track the path a user takes through your
 * files.
 *
 * The cookie and request are logged to a file.  Use the directive
 * "CookieLog somefilename" in one of the config files to enable.
 *
 * Netscape 1.0+ is the only known browser to support cookies.  This
 * code is lazy and doesn't bother creating cookies for other browsers.
 *
 * Mark Cox, mark@telescope.org, 6 July 95
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include <sys/time.h>

module cookies_module;

/* Now we have to generate something that is going to be
 * pretty unique.  We can base it on the pid, time, hostip */

void make_cookie(request_rec *r)
{
    struct timeval tv;
    char new_cookie[100];	/* blurgh */
    char *dot;
    char *rname = get_remote_host(r->connection, r->per_dir_config,
				  REMOTE_NAME);
    struct timezone tz = { 0 , 0 };

    if ((dot = strchr(rname,'.'))) *dot='\0';	/* First bit of hostname */
    gettimeofday(&tv, &tz);
    sprintf(new_cookie,"s=%s%d%ld%d; path=/",
        rname,
        (int)getpid(),  
        (long)tv.tv_sec, (int)tv.tv_usec/1000 );

    table_set(r->headers_out,"Set-Cookie",new_cookie);
    return;
}

int spot_cookie(request_rec *r)
{
    char *cookie, *agent;

    if (!(agent = table_get(r->headers_in,"User-Agent")))
        return DECLINED;              /* No user-agent = No cookie */
    if (strncmp(agent,"Mozilla",7))   /* Don't bother creating a cookie */
        return DECLINED;              /* unless browser is Netscape fudge */
    if ((cookie = table_get (r->headers_in, "Cookie")))
        return DECLINED;              /* Theres already a cookie, no new one */
    make_cookie(r);
    return OK;                        /* We set our cookie */
}

static int cookie_flags = ( O_WRONLY | O_APPEND | O_CREAT );

#ifdef __EMX__
/* OS/2 lacks support for users and groups */
static mode_t cookie_mode = ( S_IREAD | S_IWRITE );
#else
static mode_t cookie_mode = ( S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
#endif

typedef struct {
    char *fname;
    int log_fd;
} cookie_log_state;

void *make_cookie_log_state (pool *p, server_rec *s)
{
    cookie_log_state *cls =
      (cookie_log_state *)palloc (p, sizeof (cookie_log_state));

    cls->fname = "";
    cls->log_fd = -1;

    return (void *)cls;
}

char *set_cookie_log (cmd_parms *parms, void *dummy, char *arg)
{
    cookie_log_state *cls = get_module_config (parms->server->module_config,
                           &cookies_module);
    cls->fname = arg;
    return NULL;
}

command_rec cookie_log_cmds[] = {
{ "CookieLog", set_cookie_log, NULL, RSRC_CONF, TAKE1,
    "the filename of the cookie log" },
{ NULL }
};

void open_cookie_log (server_rec *s, pool *p)
{
    cookie_log_state *cls = get_module_config (s->module_config,
                           &cookies_module);
    char *fname = server_root_relative (p, cls->fname);

    if (cls->log_fd > 0) return; 
    if(*cls->fname != '\0') {
      if((cls->log_fd = popenf(p, fname, cookie_flags, cookie_mode)) < 0) {
	fprintf(stderr, "httpd: could not open cookie log file %s.\n", fname);
	perror("open");
	exit(1);
      }
    }
}

void init_cookie_log (server_rec *s, pool *p)
{
    for (; s; s = s->next) open_cookie_log (s, p);
}

int cookie_log_transaction(request_rec *orig)
{
    cookie_log_state *cls = get_module_config (orig->server->module_config,
                           &cookies_module);
    char *str;
    long timz;
    struct tm *t;
    char tstr[MAX_STRING_LEN],sign;
    request_rec *r;
    char *cookie;

    for (r = orig; r->next; r = r->next)
        continue;
    if (*cls->fname == '\0')	/* Don't log cookies */
      return DECLINED;

    if (!(cookie = table_get (r->headers_in, "Cookie")))
        return DECLINED;    /* Theres no cookie, don't bother logging */
    if (strncmp(cookie,"s=",2)) /* Only log cookies we generated! */
        return DECLINED;
    t = get_gmtoff(&timz);
    sign = (timz < 0 ? '-' : '+');
    if(timz < 0) 
        timz = -timz;

    strftime(tstr,MAX_STRING_LEN,"\" [%d/%b/%Y:%H:%M:%S ",t);
    if (r->status != -1)
	sprintf(&tstr[strlen(tstr)], "%c%02ld%02ld] %d\n", sign, timz/3600,
		timz%3600, r->status);
	sprintf(&tstr[strlen(tstr)], "%c%02ld%02ld] -\n", sign, timz/3600,
		timz%3600);

/* ignore s= on cookie */
    str = pstrcat(orig->pool, cookie + 2, " \"", orig->the_request, tstr, NULL);
    
    write(cls->log_fd, str, strlen(str));

    return OK;
}


module cookies_module = {
   STANDARD_MODULE_STUFF,
   init_cookie_log,				/* initializer */
   NULL,						/* dir config creater */
   NULL,						/* dir merger --- default is to override */
   make_cookie_log_state,		/* server config */
   NULL,						/* merge server configs */
   cookie_log_cmds,				/* command table */
   NULL,						/* handlers */
   NULL,						/* filename translation */
   NULL,						/* check_user_id */
   NULL,						/* check auth */
   NULL,						/* check access */
   NULL,						/* type_checker */
   spot_cookie,					/* fixups */
   cookie_log_transaction,		/* logger */
};
