/* ====================================================================
 * Copyright (c) 1995, 1996 The Apache Group.  All rights reserved.
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

/* $Id: mod_cookies.c,v 1.13 1996/08/24 14:36:14 ben Exp $ */

/* User Tracking Module
 *
 * This Apache module is designed to track users paths through a site.
 * It uses the client-side state ("Cookie") protocol developed by Netscape.
 * It is known to work on Netscape browsers, Microsoft Internet 
 * Explorer and others currently being developed.
 *
 * Each time a page is requested we look to see if the browser is sending
 * us a Cookie: header that we previously generated.
 *
 * If we don't find one then the user hasn't been to this site since
 * starting their browser or their browser doesn't support cookies.  So
 * we generate a unique Cookie for the transaction and send it back to
 * the browser (via a "Set-Cookie" header)
 * Future requests from the same browser should keep the same Cookie line.
 *
 * The cookie and request are logged to a file.  Use the directive
 * "CookieLog somefilename" in one of the config files to enable the Cookie
 * module.  By matching up all the requests with the same cookie you can
 * work out exactly what path a user took through your site.
 *
 * Notes:
 * 1.  This code doesn't log the initial transaction (the one that created
 *     the cookie to start with).  If it did then the cookie log file would
 *     be bigger than a normal access log.
 * 2.  This module has been designed to not interfere with other Cookies
 *     your site may be using; just avoid sending out cookies with
 *     the name "Apache=" or things will get confused.
 * 3.  If you want you can modify the Set-Cookie line so that the Cookie
 *     never expires.  You would then get the same Cookie each time the
 *     user revisits your site.
 *
 * Mark Cox, mark@ukweb.com, http://www.ukweb.com/~mark/, 6 July 95
 *
 * 6.12.95  MJC Now be more friendly.  Allow our cookies to overlap with
 *              others the site may be using.  Use a more descriptive 
 *              cookie name.
 * 18.3.96  MJC Generate cookies for EVERY request no matter what the 
 *              browser.  We never know when a new browser writer will
 *              add cookie support.
 * 31.3.95 JimC Allow the log to be sent to a pipe.  Copies the relevant
 *              code from mod_log_agent.c.
 * 24.5.96  MJC Improved documentation after receiving comments from users
 *  4.7.96  MJC Bug, "else" missing since February caused logging twice
 * 19.7.96  AEK Added CookieExpires and CookieEnable directives
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include <sys/time.h>

module cookies_module;

typedef struct {
    char *fname;
    int log_fd;
    int always;
    time_t expires;
} cookie_log_state;

/* Define this to allow post-2000 cookies. Cookies use two-digit dates,
 * so it might be dicey. (Netscape does it correctly, but others may not)
 */
#define MILLENIAL_COOKIES

/* Make Cookie: Now we have to generate something that is going to be
 * pretty unique.  We can base it on the pid, time, hostip */

#define COOKIE_NAME "Apache="

void make_cookie(request_rec *r)
{
    cookie_log_state *cls = get_module_config (r->server->module_config,
					       &cookies_module);
    struct timeval tv;
    char new_cookie[100];	/* blurgh */
    char *dot;
    const char *rname = pstrdup(r->pool, 
		       	    get_remote_host(r->connection, r->per_dir_config,
						REMOTE_NAME));
    
    struct timezone tz = { 0 , 0 };

    if ((dot = strchr(rname,'.'))) *dot='\0';	/* First bit of hostname */
    gettimeofday(&tv, &tz);

    if (cls->expires) {
      static const char *const days[7]=
          {"Sun","Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
      struct tm *tms;
      time_t when = time(NULL) + cls->expires;

#ifndef MILLENIAL_COOKIES      
      /* Only two-digit date string, so we can't trust "00" or more.
       * Therefore, we knock it all back to just before midnight on
       * 1/1/2000 (which is 946684799)
       */

      if (when > 946684799)
	when = 946684799;
#endif
      tms = gmtime(&when);



      /* Cookie with date; as strftime '%a, %d-%h-%y %H:%M:%S GMT' */
      sprintf(new_cookie,
	   "%s%s%d%ld%d; path=/; expires=%s, %.2d-%s-%.2d %.2d:%.2d:%.2d GMT",
	      COOKIE_NAME, rname, (int)getpid(),  
	      (long)tv.tv_sec, (int)tv.tv_usec/1000, days[tms->tm_wday],
	      tms->tm_mday, month_snames[tms->tm_mon],
	      (tms->tm_year >= 100) ? tms->tm_year - 100 : tms->tm_year,
	      tms->tm_hour, tms->tm_min, tms->tm_sec);
    }
    else
      sprintf(new_cookie,"%s%s%d%ld%d; path=/",
	      COOKIE_NAME, rname,
	      (int)getpid(),  
	      (long)tv.tv_sec, (int)tv.tv_usec/1000 );

    table_set(r->headers_out,"Set-Cookie",new_cookie);
    return;
}

int spot_cookie(request_rec *r)
{
    int *disable = (int *)get_module_config(r->per_dir_config,
					    &cookies_module);
    char *cookie;

    if (*disable) return DECLINED;

    if ((cookie = table_get (r->headers_in, "Cookie")))
        if (strstr(cookie,COOKIE_NAME))
            return DECLINED;          /* Theres already a cookie, no new one */
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

void *make_cookie_log_state (pool *p, server_rec *s)
{
    cookie_log_state *cls =
      (cookie_log_state *)palloc (p, sizeof (cookie_log_state));

    cls->fname = "";
    cls->log_fd = -1;
    cls->expires = 0;

    return (void *)cls;
}

void *make_cookie_dir (pool *p, char *d) {
    return (void *)pcalloc(p, sizeof(int));
}

char *set_cookie_disable (cmd_parms *cmd, int *c, int arg)
{
fprintf(stderr,"%p\n",c);
    *c = !arg;
    return NULL;
}

char *set_cookie_log (cmd_parms *parms, void *dummy, char *arg)
{
    cookie_log_state *cls = get_module_config (parms->server->module_config,
                           &cookies_module);
    cls->fname = arg;
    return NULL;
}

char *set_cookie_exp (cmd_parms *parms, void *dummy, char *arg)
{
    cookie_log_state *cls = get_module_config (parms->server->module_config,
                           &cookies_module);
    time_t factor, modifier = 0;
    time_t num = 0;
    char *word;

    /* The simple case first - all numbers (we assume) */
    if (isdigit(arg[0]) && isdigit(arg[strlen(arg)-1])) {
      cls->expires = atol(arg);
      return NULL;
    }

    /* The harder case - stolen from mod_expires
     * CookieExpires "[plus] {<num> <type>}*"
     */

    word = getword_conf( parms->pool, &arg );
    if ( !strncasecmp( word, "plus", 1 ) ) {
        word = getword_conf( parms->pool, &arg );
    };

    /* {<num> <type>}* */
    while ( word[0] ) {
        /* <num> */
        if ( index("0123456789", word[0]) != NULL )
	  num = atoi( word );
	else
	  return "bad expires code, numeric value expected.";
      
	/* <type> */
	word = getword_conf( parms->pool, &arg );
	if (!word[0] )
	  return "bad expires code, missing <type>";
	  
	factor = 0;
	if ( !strncasecmp( word, "years", 1 ) )
	  factor = 60*60*24*365;
	else if ( !strncasecmp( word, "months", 2 ) )
	  factor = 60*60*24*30;
	else if ( !strncasecmp( word, "weeks", 1 ) )
	  factor = 60*60*24*7;
	else if ( !strncasecmp( word, "days", 1 ) )
	  factor = 60*60*24;
	else if ( !strncasecmp( word, "hours", 1 ) )
	  factor = 60*60;
	else if ( !strncasecmp( word, "minutes", 2 ) )
	  factor = 60;
	else if ( !strncasecmp( word, "seconds", 1 ) )
	  factor = 1;
	else
	  return "bad expires code, unrecognized type";

	modifier = modifier + factor * num;

	/* next <num> */
	word = getword_conf( parms->pool, &arg );
    }

    cls->expires = modifier;

    return NULL;
}

command_rec cookie_log_cmds[] = {
{ "CookieLog", set_cookie_log, NULL, RSRC_CONF, TAKE1,
    "the filename of the cookie log" },
{ "CookieExpires", set_cookie_exp, NULL, RSRC_CONF, TAKE1,
    "an expiry date code" },
{ "CookieEnable", set_cookie_disable, NULL, OR_FILEINFO, FLAG,
    "whether or not to enable cookies" },
{ NULL }
};

void cookie_log_child (void *cmd)
{
    /* Child process code for 'CookieLog "|..."';
     * may want a common framework for this, since I expect it will
     * be common for other foo-loggers to want this sort of thing...
     */
    
    cleanup_for_exec();
    signal (SIGHUP, SIG_IGN);
    execl (SHELL_PATH, SHELL_PATH, "-c", (char *)cmd, NULL);
    exit (1);
}

void open_cookie_log (server_rec *s, pool *p)
{
    cookie_log_state *cls = get_module_config (s->module_config,
                           &cookies_module);
    char *fname = server_root_relative (p, cls->fname);

    if (cls->log_fd > 0) return; 

    if (*cls->fname == '|') {
      FILE *dummy;
      
      spawn_child(p, cookie_log_child, (void *)(cls->fname+1),
                kill_after_timeout, &dummy, NULL);
      
      if (dummy == NULL) {
      fprintf (stderr, "Couldn't fork child for CookieLog process\n");
      exit (1);
      }
      
      cls->log_fd = fileno (dummy);
    }
    else if(*cls->fname != '\0') {
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
    char *cookie,*cookiebuf,*cookieend;
    char *value;

    for (r = orig; r->next; r = r->next)
        continue;
    if (*cls->fname == '\0')	/* Don't log cookies */
      return DECLINED;

    if (!(cookie = table_get (r->headers_in, "Cookie")))
        return DECLINED;    /* Theres no cookie, don't bother logging */
    value=strstr(cookie,COOKIE_NAME);
    if (!value) /* Only log cookies we generated! */
        return DECLINED;
    value+=strlen(COOKIE_NAME);
    cookiebuf=pstrdup( r->pool, value );
    cookieend=strchr(cookiebuf,';');
    if (cookieend) *cookieend='\0';	/* Ignore anything after a ; */

    t = get_gmtoff(&timz);
    sign = (timz < 0 ? '-' : '+');
    if(timz < 0) 
        timz = -timz;

    strftime(tstr,MAX_STRING_LEN,"\" [%d/%b/%Y:%H:%M:%S ",t);
    if (r->status != -1)
	sprintf(&tstr[strlen(tstr)], "%c%02ld%02ld] %d\n", sign, timz/3600,
		timz%3600, r->status);
    else
	sprintf(&tstr[strlen(tstr)], "%c%02ld%02ld] -\n", sign, timz/3600,
		timz%3600);

    str = pstrcat(orig->pool, cookiebuf, " \"", orig->the_request, tstr, NULL);
    
    write(cls->log_fd, str, strlen(str));

    return OK;
}


module cookies_module = {
   STANDARD_MODULE_STUFF,
   init_cookie_log,				/* initializer */
   make_cookie_dir,    		       		/* dir config creater */
   NULL,	      			/* dir merger --- default is to override */
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
