/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_conf_globals.h"
#include "http_main.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_core.h"		/* For document_root.  Sigh... */
#include "http_request.h"	/* for sub_req_lookup_uri() */
#include "util_script.h"
#include "util_date.h"		/* For parseHTTPdate() */

/*
 * Various utility functions which are common to a whole lot of
 * script-type extensions mechanisms, and might as well be gathered
 * in one place (if only to avoid creating inter-module dependancies
 * where there don't have to be).
 */

#define MALFORMED_MESSAGE "malformed header from script. Bad header="
#define MALFORMED_HEADER_LENGTH_TO_SHOW 30

/* If a request includes query info in the URL (stuff after "?"), and
 * the query info does not contain "=" (indicative of a FORM submission),
 * then this routine is called to create the argument list to be passed
 * to the CGI script.  When suexec is enabled, the suexec path, user, and
 * group are the first three arguments to be passed; if not, all three
 * must be NULL.  The query info is split into separate arguments, where
 * "+" is the separator between keyword arguments.
 */
static char **create_argv(pool *p, char *path, char *user, char *group,
			  char *av0, const char *args)
{
    int x, numwords;
    char **av;
    char *w;
    int idx = 0;

    /* count the number of keywords */

    for (x = 0, numwords = 1; args[x]; x++)
	if (args[x] == '+')
	    ++numwords;

    if (numwords > APACHE_ARG_MAX - 5) {
	numwords = APACHE_ARG_MAX - 5;	/* Truncate args to prevent overrun */
    }
    av = (char **) palloc(p, (numwords + 5) * sizeof(char *));

    if (path)
	av[idx++] = path;
    if (user)
	av[idx++] = user;
    if (group)
	av[idx++] = group;

    av[idx++] = av0;

    for (x = 1; x <= numwords; x++) {
	w = getword_nulls(p, &args, '+');
	unescape_url(w);
	av[idx++] = escape_shell_cmd(p, w);
    }
    av[idx] = NULL;
    return av;
}


static char *http2env(pool *a, char *w)
{
    char *res = pstrcat(a, "HTTP_", w, NULL);
    char *cp = res;

    while (*++cp)
	if (*cp == '-')
	    *cp = '_';
	else
	    *cp = toupper(*cp);

    return res;
}

API_EXPORT(char **) create_environment(pool *p, table *t)
{
    array_header *env_arr = table_elts(t);
    table_entry *elts = (table_entry *) env_arr->elts;
    char **env = (char **) palloc(p, (env_arr->nelts + 2) * sizeof(char *));
    int i, j;
    char *tz;

    j = 0;
    tz = getenv("TZ");
    if (tz != NULL)
	env[j++] = pstrcat(p, "TZ=", tz, NULL);
    for (i = 0; i < env_arr->nelts; ++i) {
	if (!elts[i].key)
	    continue;
	env[j++] = pstrcat(p, elts[i].key, "=", elts[i].val, NULL);
    }

    env[j] = NULL;
    return env;
}

API_EXPORT(void) add_common_vars(request_rec *r)
{
    table *e = r->subprocess_env;
    server_rec *s = r->server;
    conn_rec *c = r->connection;
    const char *rem_logname;

    char port[40], *env_path;

    array_header *hdrs_arr = table_elts(r->headers_in);
    table_entry *hdrs = (table_entry *) hdrs_arr->elts;
    int i;

    /* First, add environment vars from headers... this is as per
     * CGI specs, though other sorts of scripting interfaces see
     * the same vars...
     */

    for (i = 0; i < hdrs_arr->nelts; ++i) {
	if (!hdrs[i].key)
	    continue;

	/* A few headers are special cased --- Authorization to prevent
	 * rogue scripts from capturing passwords; content-type and -length
	 * for no particular reason.
	 */

	if (!strcasecmp(hdrs[i].key, "Content-type"))
	    table_set(e, "CONTENT_TYPE", hdrs[i].val);
	else if (!strcasecmp(hdrs[i].key, "Content-length"))
	    table_set(e, "CONTENT_LENGTH", hdrs[i].val);
	else if (!strcasecmp(hdrs[i].key, "Authorization"))
	    continue;
	else
	    table_set(e, http2env(r->pool, hdrs[i].key), hdrs[i].val);
    }

    ap_snprintf(port, sizeof(port), "%u", s->port);

    if (!(env_path = getenv("PATH")))
	env_path = DEFAULT_PATH;

    table_set(e, "PATH", env_path);
    table_set(e, "SERVER_SOFTWARE", SERVER_VERSION);
    table_set(e, "SERVER_NAME", s->server_hostname);
    table_set(e, "SERVER_PORT", port);
    table_set(e, "REMOTE_HOST",
	      get_remote_host(c, r->per_dir_config, REMOTE_NAME));
    table_set(e, "REMOTE_ADDR", c->remote_ip);
    table_set(e, "DOCUMENT_ROOT", document_root(r));	/* Apache */
    table_set(e, "SERVER_ADMIN", s->server_admin);	/* Apache */
    table_set(e, "SCRIPT_FILENAME", r->filename);	/* Apache */

    ap_snprintf(port, sizeof(port), "%d", ntohs(c->remote_addr.sin_port));
    table_set(e, "REMOTE_PORT", port);	/* Apache */

    if (c->user)
	table_set(e, "REMOTE_USER", c->user);
    if (c->auth_type)
	table_set(e, "AUTH_TYPE", c->auth_type);
    rem_logname = get_remote_logname(r);
    if (rem_logname)
	table_set(e, "REMOTE_IDENT", rem_logname);

    /* Apache custom error responses. If we have redirected set two new vars */

    if (r->prev) {
	if (r->prev->args)
	    table_set(e, "REDIRECT_QUERY_STRING", r->prev->args);
	if (r->prev->uri)
	    table_set(e, "REDIRECT_URL", r->prev->uri);
    }
}

/* This "cute" little function comes about because the path info on
 * filenames and URLs aren't always the same. So we take the two,
 * and find as much of the two that match as possible.
 */

API_EXPORT(int) find_path_info(char *uri, char *path_info)
{
    int lu = strlen(uri);
    int lp = strlen(path_info);

    while (lu-- && lp-- && uri[lu] == path_info[lp]);

    if (lu == -1)
	lu = 0;

    while (uri[lu] != '\0' && uri[lu] != '/')
	lu++;

    return lu;
}

/* Obtain the Request-URI from the original request-line, returning
 * a new string from the request pool containing the URI or "".
 */
static char *original_uri(request_rec *r)
{
    char *first, *last;

    if (r->the_request == NULL)
	return (char *) pcalloc(r->pool, 1);

    first = r->the_request;	/* use the request-line */

    while (*first && !isspace(*first))
	++first;		/* skip over the method */
    while (isspace(*first))
	++first;		/*   and the space(s)   */

    last = first;
    while (*last && !isspace(*last))
	++last;			/* end at next whitespace */

    return pstrndup(r->pool, first, last - first);
}

API_EXPORT(void) add_cgi_vars(request_rec *r)
{
    table *e = r->subprocess_env;

    table_set(e, "GATEWAY_INTERFACE", "CGI/1.1");
    table_set(e, "SERVER_PROTOCOL", r->protocol);
    table_set(e, "REQUEST_METHOD", r->method);
    table_set(e, "QUERY_STRING", r->args ? r->args : "");
    table_set(e, "REQUEST_URI", original_uri(r));

    /* Note that the code below special-cases scripts run from includes,
     * because it "knows" that the sub_request has been hacked to have the
     * args and path_info of the original request, and not any that may have
     * come with the script URI in the include command.  Ugh.
     */

    if (!strcmp(r->protocol, "INCLUDED")) {
	table_set(e, "SCRIPT_NAME", r->uri);
	if (r->path_info && *r->path_info)
	    table_set(e, "PATH_INFO", r->path_info);
    }
    else if (!r->path_info || !*r->path_info) {
	table_set(e, "SCRIPT_NAME", r->uri);
    }
    else {
	int path_info_start = find_path_info(r->uri, r->path_info);

	table_set(e, "SCRIPT_NAME", pstrndup(r->pool, r->uri,
					     path_info_start));

	table_set(e, "PATH_INFO", r->path_info);
    }

    if (r->path_info && r->path_info[0]) {
	/*
	 * To get PATH_TRANSLATED, treat PATH_INFO as a URI path.
	 * Need to re-escape it for this, since the entire URI was
	 * un-escaped before we determined where the PATH_INFO began.
	 */
	request_rec *pa_req = sub_req_lookup_uri(escape_uri(r->pool, r->path_info),
						 r);

	/* Don't bother destroying pa_req --- it's only created in
	 * child processes which are about to jettison their address
	 * space anyway.  BTW, we concatenate filename and path_info
	 * from the sub_request to be compatible in case the PATH_INFO
	 * is pointing to an object which doesn't exist.
	 */

	if (pa_req->filename) {
#ifdef WIN32
	    char buffer[HUGE_STRING_LEN];
#endif
	    char *pt = pstrcat(r->pool, pa_req->filename, pa_req->path_info,
			       NULL);
#ifdef WIN32
	    /* We need to make this a real Windows path name */
	    GetFullPathName(pt, HUGE_STRING_LEN, buffer, NULL);
	    table_set(e, "PATH_TRANSLATED", pstrdup(r->pool, buffer));
#else
	    table_set(e, "PATH_TRANSLATED", pt);
#endif
	}
    }
}


static int scan_script_header_err_core(request_rec *r, char *buffer,
		 int (*getsfunc) (char *, int, void *), void *getsfunc_data)
{
    char x[MAX_STRING_LEN];
    char *w, *l;
    int p;
    int cgi_status = HTTP_OK;

    if (buffer)
	*buffer = '\0';
    w = buffer ? buffer : x;

    hard_timeout("read script header", r);

    while (1) {

	if ((*getsfunc) (w, MAX_STRING_LEN - 1, getsfunc_data) == 0) {
	    kill_timeout(r);
	    aplog_error(APLOG_MARK, APLOG_ERR, r->server,
			"Premature end of script headers: %s", r->filename);
	    return SERVER_ERROR;
	}

	/* Delete terminal (CR?)LF */

	p = strlen(w);
	if (p > 0 && w[p - 1] == '\n') {
	    if (p > 1 && w[p - 2] == '\015')
		w[p - 2] = '\0';
	    else
		w[p - 1] = '\0';
	}

	/*
	 * If we've finished reading the headers, check to make sure any
	 * HTTP/1.1 conditions are met.  If so, we're done; normal processing
	 * will handle the script's output.  If not, just return the error.
	 * The appropriate thing to do would be to send the script process a
	 * SIGPIPE to let it know we're ignoring it, close the channel to the
	 * script process, and *then* return the failed-to-meet-condition
	 * error.  Otherwise we'd be waiting for the script to finish
	 * blithering before telling the client the output was no good.
	 * However, we don't have the information to do that, so we have to
	 * leave it to an upper layer.
	 */
	if (w[0] == '\0') {
	    int cond_status = OK;

	    kill_timeout(r);
	    if ((cgi_status == HTTP_OK) && (r->method_number == M_GET)) {
		cond_status = meets_conditions(r);
	    }
	    return cond_status;
	}

	/* if we see a bogus header don't ignore it. Shout and scream */

	if (!(l = strchr(w, ':'))) {
	    char malformed[(sizeof MALFORMED_MESSAGE) + 1 + MALFORMED_HEADER_LENGTH_TO_SHOW];
	    strcpy(malformed, MALFORMED_MESSAGE);
	    strncat(malformed, w, MALFORMED_HEADER_LENGTH_TO_SHOW);

	    if (!buffer)
		/* Soak up all the script output --- may save an outright kill */
		while ((*getsfunc) (w, MAX_STRING_LEN - 1, getsfunc_data))
		    continue;

	    kill_timeout(r);
	    aplog_error(APLOG_MARK, APLOG_ERR, r->server,
			"%s: %s", malformed, r->filename);
	    return SERVER_ERROR;
	}

	*l++ = '\0';
	while (*l && isspace(*l))
	    ++l;

	if (!strcasecmp(w, "Content-type")) {

	    /* Nuke trailing whitespace */

	    char *endp = l + strlen(l) - 1;
	    while (endp > l && isspace(*endp))
		*endp-- = '\0';

	    r->content_type = pstrdup(r->pool, l);
	}
	else if (!strcasecmp(w, "Status")) {
	    sscanf(l, "%d", &r->status);
	    r->status_line = pstrdup(r->pool, l);
	}
	else if (!strcasecmp(w, "Location")) {
	    table_set(r->headers_out, w, l);
	}
	else if (!strcasecmp(w, "Content-Length")) {
	    table_set(r->headers_out, w, l);
	}
	else if (!strcasecmp(w, "Transfer-Encoding")) {
	    table_set(r->headers_out, w, l);
	}
	/*
	 * If the script gave us a Last-Modified header, we can't just
	 * pass it on blindly because of restrictions on future values.
	 */
	else if (!strcasecmp(w, "Last-Modified")) {
	    time_t mtime = parseHTTPdate(l);

	    update_mtime(r, mtime);
	    set_last_modified(r);
	}
	/*
	 * If the script returned a specific status, that's what
	 * we'll use - otherwise we assume 200 OK.
	 */
	else if (!strcasecmp(w, "Status")) {
	    table_set(r->headers_out, w, l);
	    cgi_status = atoi(l);
	}

	/* The HTTP specification says that it is legal to merge duplicate
	 * headers into one.  Some browsers that support Cookies don't like
	 * merged headers and prefer that each Set-Cookie header is sent
	 * separately.  Lets humour those browsers.
	 */
	else if (!strcasecmp(w, "Set-Cookie")) {
	    table_add(r->err_headers_out, w, l);
	}
	else {
	    table_merge(r->err_headers_out, w, l);
	}
    }
}

static int getsfunc_FILE(char *buf, int len, void *f)
{
    return fgets(buf, len, (FILE *) f) != NULL;
}

API_EXPORT(int) scan_script_header_err(request_rec *r, FILE *f, char *buffer)
{
    return scan_script_header_err_core(r, buffer, getsfunc_FILE, f);
}

static int getsfunc_BUFF(char *w, int len, void *fb)
{
    return bgets(w, len, (BUFF *) fb) > 0;
}

API_EXPORT(int) scan_script_header_err_buff(request_rec *r, BUFF *fb,
					    char *buffer)
{
    return scan_script_header_err_core(r, buffer, getsfunc_BUFF, fb);
}


API_EXPORT(void) send_size(size_t size, request_rec *r)
{
    char ss[20];

    if (size == -1)
	strcpy(ss, "    -");
    else if (!size)
	strcpy(ss, "   0k");
    else if (size < 1024)
	strcpy(ss, "   1k");
    else if (size < 1048576)
	ap_snprintf(ss, sizeof(ss), "%4dk", (size + 512) / 1024);
    else if (size < 103809024)
	ap_snprintf(ss, sizeof(ss), "%4.1fM", size / 1048576.0);
    else
	ap_snprintf(ss, sizeof(ss), "%4dM", (size + 524288) / 1048576);
    rputs(ss, r);
}

#if defined(__EMX__) || defined(WIN32)
static char **create_argv_cmd(pool *p, char *av0, const char *args, char *path)
{
    register int x, n;
    char **av;
    char *w;

    for (x = 0, n = 2; args[x]; x++)
	if (args[x] == '+')
	    ++n;

    /* Add extra strings to array. */
    n = n + 2;

    av = (char **) palloc(p, (n + 1) * sizeof(char *));
    av[0] = av0;

    /* Now insert the extra strings we made room for above. */
    av[1] = strdup("/C");
    av[2] = strdup(path);

    for (x = (1 + 2); x < n; x++) {
	w = getword(p, &args, '+');
	unescape_url(w);
	av[x] = escape_shell_cmd(p, w);
    }
    av[n] = NULL;
    return av;
}
#endif


API_EXPORT(int) call_exec(request_rec *r, char *argv0, char **env, int shellcmd)
{
    int pid = 0;
#if defined(RLIMIT_CPU)  || defined(RLIMIT_NPROC) || \
    defined(RLIMIT_DATA) || defined(RLIMIT_VMEM)

    core_dir_config *conf =
    (core_dir_config *) get_module_config(r->per_dir_config, &core_module);

#endif

    /* the fd on r->server->error_log is closed, but we need somewhere to
     * put the error messages from the log_* functions. So, we use stderr,
     * since that is better than allowing errors to go unnoticed.
     */
    r->server->error_log = stderr;

#ifdef RLIMIT_CPU
    if (conf->limit_cpu != NULL)
	if ((setrlimit(RLIMIT_CPU, conf->limit_cpu)) != 0)
	    aplog_error(APLOG_MARK, APLOG_ERR, r->server,
			"setrlimit: failed to set CPU usage limit");
#endif
#ifdef RLIMIT_NPROC
    if (conf->limit_nproc != NULL)
	if ((setrlimit(RLIMIT_NPROC, conf->limit_nproc)) != 0)
	    aplog_error(APLOG_MARK, APLOG_ERR, r->server,
			"setrlimit: failed to set process limit");
#endif
#ifdef RLIMIT_DATA
    if (conf->limit_mem != NULL)
	if ((setrlimit(RLIMIT_DATA, conf->limit_mem)) != 0)
	    aplog_error(APLOG_MARK, APLOG_ERR, r->server,
			"setrlimit: failed to set memory usage limit");
#endif
#ifdef RLIMIT_VMEM
    if (conf->limit_mem != NULL)
	if ((setrlimit(RLIMIT_VMEM, conf->limit_mem)) != 0)
	    aplog_error(APLOG_MARK, APLOG_ERR, r->server,
			"setrlimit: failed to set memory usage limit");
#endif

#ifdef __EMX__
    {
	/* Additions by Alec Kloss, to allow exec'ing of scripts under OS/2 */
	int is_script;
	char interpreter[2048];	/* hope this is large enough for the interpreter path */
	FILE *program;
	program = fopen(r->filename, "r");
	if (!program) {
	    char err_string[HUGE_STRING_LEN];
	    ap_snprintf(err_string, sizeof(err_string), "open of %s failed", r->filename);

	    /* write(2, err_string, strlen(err_string)); */
	    /* exit(0); */
	    aplog_error(APLOG_MARK, APLOG_ERR, r->server, "fopen: %s", err_string);
	    return (pid);
	}
	fgets(interpreter, sizeof(interpreter), program);
	fclose(program);
	if (!strncmp(interpreter, "#!", 2)) {
	    is_script = 1;
	    interpreter[strlen(interpreter) - 1] = '\0';
	}
	else {
	    is_script = 0;
	}

	if ((!r->args) || (!r->args[0]) || (ind(r->args, '=') >= 0)) {
	    int emxloop;
	    char *emxtemp;

	    /* For OS/2 place the variables in the current
	     * enviornment then it will be inherited. This way
	     * the program will also get all of OS/2's other SETs.
	     */
	    for (emxloop = 0; ((emxtemp = env[emxloop]) != NULL); emxloop++)
		putenv(emxtemp);

	    /* Additions by Alec Kloss, to allow exec'ing of scripts under OS/2 */
	    if (is_script) {
		/* here's the stuff to run the interpreter */
		execl(interpreter + 2, interpreter + 2, r->filename, NULL);
	    }
	    else if (strstr(strupr(r->filename), ".CMD") > 0) {
		/* Special case to allow use of REXX commands as scripts. */
		os2pathname(r->filename);
		execl("CMD.EXE", "CMD.EXE", "/C", r->filename, NULL);
	    }
	    else {
		execl(r->filename, argv0, NULL);
	    }
	}
	else {
	    int emxloop;
	    char *emxtemp;

	    /* For OS/2 place the variables in the current
	     * environment so that they will be inherited. This way
	     * the program will also get all of OS/2's other SETs.
	     */
	    for (emxloop = 0; ((emxtemp = env[emxloop]) != NULL); emxloop++)
		putenv(emxtemp);

	    if (strstr(strupr(r->filename), ".CMD") > 0) {
		/* Special case to allow use of REXX commands as scripts. */
		os2pathname(r->filename);
		execv("CMD.EXE", create_argv_cmd(r->pool, argv0, r->args, r->filename));
	    }
	    else
		execv(r->filename,
		    create_argv(r->pool, NULL, NULL, NULL, argv0, r->args));
	}
	return (pid);
    }
#elif defined(WIN32)
    {
	/* Adapted from work by Alec Kloss, to allow exec'ing of scripts under OS/2 */
	int is_script = 0;
	int is_binary = 0;
	char interpreter[2048];	/* hope this is large enough for the interpreter path */
	FILE *program;
	int i, sz;
	char *dot;
	char *exename;
	int is_exe = 0;

	interpreter[0] = 0;

	exename = strrchr(r->filename, '/');
	if (!exename)
	    exename = strrchr(r->filename, '\\');
	if (!exename)
	    exename = r->filename;
	else
	    exename++;
	dot = strrchr(exename, '.');
	if (dot) {
	    if (!strcasecmp(dot, ".BAT") ||
		!strcasecmp(dot, ".EXE") ||
		!strcasecmp(dot, ".COM"))
		is_exe = 1;
	}

	if (!is_exe) {
	    program = fopen(r->filename, "rb");
	    if (!program) {
		char err_string[HUGE_STRING_LEN];
		ap_snprintf(err_string, sizeof(err_string),
			    "open of %s failed", r->filename);
		/* write(2, err_string, strlen(err_string)); */
		/* exit(0); */
		aplog_error(APLOG_MARK, APLOG_ERR, r->server, "fopen: %s", err_string);
		return (pid);
	    }
	    sz = fread(interpreter, 1, sizeof(interpreter) - 1, program);
	    if (sz < 0) {
		char err_string[HUGE_STRING_LEN];
		ap_snprintf(err_string, sizeof(err_string),
			    "open of %s failed", r->filename);
		aplog_error(APLOG_MARK, APLOG_ERR, r->server, "fread: %s", err_string);
		fclose(program);
		return (pid);
	    }
	    interpreter[sz] = 0;
	    fclose(program);
	    if (!strncmp(interpreter, "#!", 2)) {
		is_script = 1;
		for (i = 2; i < sizeof(interpreter); i++) {
		    if ((interpreter[i] == '\r') ||
			(interpreter[i] == '\n'))
			break;
		}
		interpreter[i] = 0;
	    }
	    else {
		/*
		 * check and see how many control chars. On
		 * that basis, I will classify it as a text
		 * or binary file
		 */
		int ctrl = 0;

		for (i = 0; i < sz; i++) {
		    static char *spec = "\r\n\t";
		    if (iscntrl(interpreter[i]) && !strchr(spec, interpreter[i]))
			ctrl++;
		}
		if (ctrl > sz / 10)
		    is_binary = 1;
		else
		    is_binary = 0;

	    }
	}

	if ((!r->args) || (!r->args[0]) || (ind(r->args, '=') >= 0)) {
	    if (is_exe || is_binary) {
		pid = spawnle(_P_NOWAIT, r->filename, r->filename, NULL, env);
	    }
	    else if (is_script) {
		pid = spawnle(_P_NOWAIT, interpreter + 2, interpreter + 2,
			      r->filename, NULL, env);
	    }
	    else {
		pid = spawnle(_P_NOWAIT, "CMD.EXE", "CMD.EXE", "/C",
			      r->filename, NULL, env);
	    }
	}
	else {
	    if (is_exe || is_binary) {
		pid = spawnve(_P_NOWAIT, r->filename,
			      create_argv(r->pool, argv0, NULL, NULL, r->args,
					  (void *) NULL), env);
	    }
	    else if (is_script) {
		ap_assert(0);
		pid = spawnve(_P_NOWAIT, interpreter + 2,
			      create_argv(r->pool, interpreter + 2, NULL, NULL,
					  r->filename, r->args), env);
	    }
	    else {
		pid = spawnve(_P_NOWAIT, "CMD.EXE",
			      create_argv_cmd(r->pool, argv0, r->args,
					      r->filename), env);
	    }
	}
	return (pid);
    }
#else
    if (suexec_enabled &&
	((r->server->server_uid != user_id) ||
	 (r->server->server_gid != group_id) ||
	 (!strncmp("/~", r->uri, 2)))) {

	char *execuser, *grpname;
	struct passwd *pw;
	struct group *gr;

	if (!strncmp("/~", r->uri, 2)) {
	    gid_t user_gid;
	    char *username = pstrdup(r->pool, r->uri + 2);
	    int pos = ind(username, '/');

	    if (pos >= 0)
		username[pos] = '\0';

	    if ((pw = getpwnam(username)) == NULL) {
		aplog_error(APLOG_MARK, APLOG_ERR, r->server,
			    "getpwnam: invalid username %s", username);
		return (pid);
	    }
	    execuser = pstrcat(r->pool, "~", pw->pw_name, NULL);
	    user_gid = pw->pw_gid;

	    if ((gr = getgrgid(user_gid)) == NULL) {
		if ((grpname = palloc(r->pool, 16)) == NULL)
		         return (pid);
		else
		    ap_snprintf(grpname, 16, "%d", user_gid);
	    }
	    else
		grpname = gr->gr_name;
	}
	else {
	    if ((pw = getpwuid(r->server->server_uid)) == NULL) {
		aplog_error(APLOG_MARK, APLOG_ERR, r->server,
		      "getpwuid: invalid userid %d", r->server->server_uid);
		return (pid);
	    }
	    execuser = pstrdup(r->pool, pw->pw_name);

	    if ((gr = getgrgid(r->server->server_gid)) == NULL) {
		aplog_error(APLOG_MARK, APLOG_ERR, r->server,
		     "getgrgid: invalid groupid %d", r->server->server_gid);
		return (pid);
	    }
	    grpname = gr->gr_name;
	}

	if (shellcmd)
	    execle(SUEXEC_BIN, SUEXEC_BIN, execuser, grpname, argv0, NULL, env);

	else if ((!r->args) || (!r->args[0]) || (ind(r->args, '=') >= 0))
	    execle(SUEXEC_BIN, SUEXEC_BIN, execuser, grpname, argv0, NULL, env);

	else {
	    execve(SUEXEC_BIN,
		   create_argv(r->pool, SUEXEC_BIN, execuser, grpname,
			       argv0, r->args),
		   env);
	}
    }
    else {
	if (shellcmd)
	    execle(SHELL_PATH, SHELL_PATH, "-c", argv0, NULL, env);

	else if ((!r->args) || (!r->args[0]) || (ind(r->args, '=') >= 0))
	    execle(r->filename, argv0, NULL, env);

	else
	    execve(r->filename,
		   create_argv(r->pool, NULL, NULL, NULL, argv0, r->args),
		   env);
    }
    return (pid);
#endif
}
