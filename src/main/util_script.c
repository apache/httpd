
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



#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_core.h"		/* For document_root.  Sigh... */
#include "http_request.h"       /* for sub_req_lookup_uri() */
#include "util_script.h"

/*
 * Various utility functions which are common to a whole lot of
 * script-type extensions mechanisms, and might as well be gathered
 * in one place (if only to avoid creating inter-module dependancies
 * where there don't have to be).
 */
 
#define MALFORMED_MESSAGE "malformed header from script. Bad header="
#define MALFORMED_HEADER_LENGTH_TO_SHOW 30

char **create_argv(pool *p, char *av0, char *args) {
    register int x,n;
    char **av;
    char *w;

    for(x=0,n=2;args[x];x++)
        if(args[x] == '+') ++n;

    av = (char **)palloc(p, (n+1)*sizeof(char *));
    av[0] = av0;

    for(x=1;x<n;x++) {
        w = getword_nulls(p, &args, '+');
        unescape_url(w);
        av[x] = escape_shell_cmd(p, w);
    }
    av[n] = NULL;
    return av;
}

static char *http2env(pool *a, char *w)
{
    char *res = pstrcat (a, "HTTP_", w, NULL);
    char *cp = res;
  
    while (*++cp)
      if (*cp == '-') *cp = '_';
      else *cp = toupper(*cp);

    return res;
}

char **create_environment(pool *p, table *t)
{
    array_header *env_arr = table_elts (t);
    table_entry *elts = (table_entry *)env_arr->elts;
    char **env = (char **)palloc (p, (env_arr->nelts + 2) *sizeof (char *));
    int i, j;
    char *tz;

    j = 0;
    tz = getenv("TZ");
    if (tz!= NULL) env[j++] = pstrcat(p, "TZ=", tz, NULL);
    for (i = 0; i < env_arr->nelts; ++i) {
        if (!elts[i].key) continue;
	env[j++] = pstrcat (p, elts[i].key, "=", elts[i].val, NULL);
    }

    env[j] = NULL;
    return env;
}

void add_common_vars(request_rec *r)
{
    table *e = r->subprocess_env;
    server_rec *s = r->server;
    conn_rec *c = r->connection;
    const char *rem_logname;
    
    char port[40],*env_path;
    
    array_header *hdrs_arr = table_elts (r->headers_in);
    table_entry *hdrs = (table_entry *)hdrs_arr->elts;
    int i;
    
    /* First, add environment vars from headers... this is as per
     * CGI specs, though other sorts of scripting interfaces see
     * the same vars...
     */
    
    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key) continue;

	/* A few headers are special cased --- Authorization to prevent
	 * rogue scripts from capturing passwords; content-type and -length
	 * for no particular reason.
	 */
	
	if (!strcasecmp (hdrs[i].key, "Content-type")) 
	    table_set (e, "CONTENT_TYPE", hdrs[i].val);
	else if (!strcasecmp (hdrs[i].key, "Content-length"))
	    table_set (e, "CONTENT_LENGTH", hdrs[i].val);
	else if (!strcasecmp (hdrs[i].key, "Authorization"))
	    continue;
	else
	    table_set (e, http2env (r->pool, hdrs[i].key), hdrs[i].val);
    }
    
    sprintf(port, "%d", s->port);

    if(!(env_path = getenv("PATH")))
        env_path=DEFAULT_PATH;
    
    table_set (e, "PATH", env_path);
    table_set (e, "SERVER_SOFTWARE", SERVER_VERSION);
    table_set (e, "SERVER_NAME", s->server_hostname);
    table_set (e, "SERVER_PORT", port);
    table_set (e, "REMOTE_HOST",
	       get_remote_host(c, r->per_dir_config, REMOTE_NAME));
    table_set (e, "REMOTE_ADDR", c->remote_ip);
    table_set (e, "DOCUMENT_ROOT", document_root(r)); /* Apache */
    table_set (e, "SERVER_ADMIN", s->server_admin); /* Apache */
    table_set (e, "SCRIPT_FILENAME", r->filename); /* Shambhala */
    
    if (c->user) table_set(e, "REMOTE_USER", c->user);
    if (c->auth_type) table_set(e, "AUTH_TYPE", c->auth_type);
    rem_logname = get_remote_logname(r);
    if (rem_logname) table_set(e, "REMOTE_IDENT", rem_logname);
    
    /* Apache custom error responses. If we have redirected set two new vars */
    
    if (r->prev) {
        if (r->prev->args) table_set(e,"REDIRECT_QUERY_STRING", r->prev->args);
	if (r->prev->uri) table_set (e, "REDIRECT_URL", r->prev->uri);
    }
}


void add_cgi_vars(request_rec *r)
{
    table *e = r->subprocess_env;

    table_set (e, "GATEWAY_INTERFACE","CGI/1.1");
    table_set (e, "SERVER_PROTOCOL", r->protocol);
    table_set (e, "REQUEST_METHOD", r->method);
    table_set (e, "QUERY_STRING", r->args ? r->args : "");
    
    /* Note that the code below special-cases scripts run from includes,
     * because it "knows" that the sub_request has been hacked to have the
     * args and path_info of the original request, and not any that may have
     * come with the script URI in the include command.  Ugh.
     */
    
    if (!r->path_info || !*r->path_info || !strcmp (r->protocol, "INCLUDED")) {
        table_set (e, "SCRIPT_NAME", r->uri);
    } else {
        int path_info_start = strlen (r->uri) - strlen (r->path_info);
	
	r->uri[path_info_start] = '\0';
	table_set (e, "SCRIPT_NAME", r->uri);
	r->uri[path_info_start] = '/';
    }
	
    if (r->path_info && r->path_info[0]) {
	/*
 	 * To get PATH_TRANSLATED, treat PATH_INFO as a URI path.
	 * Need to re-escape it for this, since the entire URI was
	 * un-escaped before we determined where the PATH_INFO began.
 	 */
	request_rec *pa_req = sub_req_lookup_uri(
				    escape_uri(r->pool, r->path_info), r);
      
        table_set (e, "PATH_INFO", r->path_info);

	/* Don't bother destroying pa_req --- it's only created in
	 * child processes which are about to jettison their address
	 * space anyway.  BTW, we concatenate filename and path_info
	 * from the sub_request to be compatible in case the PATH_INFO
	 * is pointing to an object which doesn't exist.
	 */
	
	if (pa_req->filename)
	    table_set (e, "PATH_TRANSLATED",
		       pstrcat (r->pool, pa_req->filename, pa_req->path_info,
				NULL));
    }
}

int scan_script_header(request_rec *r, FILE *f)
{
    char w[MAX_STRING_LEN];
    char *l;
    int p;

    hard_timeout ("read script header", r);
    
    while(1) {

	if (fgets(w, MAX_STRING_LEN-1, f) == NULL) {
	    log_reason ("Premature end of script headers", r->filename, r);
	    return SERVER_ERROR;
        }

	/* Delete terminal (CR?)LF */
	
	p = strlen(w);
	if (p > 0 && w[p-1] == '\n')
	{
	    if (p > 1 && w[p-2] == '\015') w[p-2] = '\0';
	    else w[p-1] = '\0';
	}

        if(w[0] == '\0') {
	    kill_timeout (r);
	    return OK;
	}
                                   
	/* if we see a bogus header don't ignore it. Shout and scream */
	
        if(!(l = strchr(w,':'))) {
	    char malformed[(sizeof MALFORMED_MESSAGE)+1+MALFORMED_HEADER_LENGTH_TO_SHOW];
            strcpy(malformed, MALFORMED_MESSAGE);
            strncat(malformed, w, MALFORMED_HEADER_LENGTH_TO_SHOW);
            /* Soak up all the script output --- may save an outright kill */
	    while (fgets(w, MAX_STRING_LEN-1, f) != NULL)
	        continue;
	    
	    kill_timeout (r);
	    log_reason (malformed, r->filename, r);
	    return SERVER_ERROR;
        }

        *l++ = '\0';
	while (*l && isspace (*l)) ++l;
	
        if(!strcasecmp(w,"Content-type")) {

	    /* Nuke trailing whitespace */
	    
	    char *endp = l + strlen(l) - 1;
	    while (endp > l && isspace(*endp)) *endp-- = '\0';
	    
	    r->content_type = pstrdup (r->pool, l);
	}
        else if(!strcasecmp(w,"Status")) {
            sscanf(l, "%d", &r->status);
            r->status_line = pstrdup(r->pool, l);
        }
        else if(!strcasecmp(w,"Location")) {
	    table_set (r->headers_out, w, l);
        }   

/* The HTTP specification says that it is legal to merge duplicate
 * headers into one.  Some browsers that support Cookies don't like
 * merged headers and prefer that each Set-Cookie header is sent
 * separately.  Lets humour those browsers.
 */
	else if(!strcasecmp(w, "Set-Cookie")) {
	    table_add(r->err_headers_out, w, l);
	}
        else {
	    table_merge (r->err_headers_out, w, l);
        }
    }
}

void send_size(size_t size, request_rec *r) {
    char ss[20];

    if(size == -1) 
        strcpy(ss, "    -");
    else if(!size) 
        strcpy(ss, "   0k");
    else if(size < 1024) 
        strcpy(ss, "   1k");
    else if(size < 1048576)
        sprintf(ss, "%4dk", size / 1024);
    else
        sprintf(ss, "%4dM", size / 1048576);
    rputs(ss, r);
}

#ifdef __EMX__
char **create_argv_cmd(pool *p, char *av0, char *args, char *path) {
    register int x,n;
    char **av;
    char *w;

    for(x=0,n=2;args[x];x++)
        if(args[x] == '+') ++n;

    /* Add extra strings to array. */
    n = n + 2;

    av = (char **)palloc(p, (n+1)*sizeof(char *));
    av[0] = av0;

    /* Now insert the extra strings we made room for above. */
    av[1] = strdup("/C");
    av[2] = strdup(path);

    for(x=(1+2);x<n;x++) {
        w = getword(p, &args, '+');
        unescape_url(w);
        av[x] = escape_shell_cmd(p, w);
    }
    av[n] = NULL;
    return av;
}
#endif

