/* ====================================================================
 * Copyright (c) 1995-2000 The Apache Software Foundation.  All rights reserved.
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
 *    "This product includes software developed by the Apache Software Foundation
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Software Foundation" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Software Foundation.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Software Foundation
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE Apache Software Foundation ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE Apache Software Foundation OR
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
 * individuals on behalf of the Apache Software Foundation and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Software Foundation and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_main.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"	/* for sub_req_lookup_uri() */
#include "util_script.h"
#include "util_date.h"		/* For parseHTTPdate() */
#include <stdlib.h>
#include <string.h>

#ifdef OS2
#define INCL_DOS
#include <os2.h>
#endif

/*
 * Various utility functions which are common to a whole lot of
 * script-type extensions mechanisms, and might as well be gathered
 * in one place (if only to avoid creating inter-module dependancies
 * where there don't have to be).
 */

#define MALFORMED_MESSAGE "malformed header from script. Bad header="
#define MALFORMED_HEADER_LENGTH_TO_SHOW 30

#if defined(OS2) || defined(WIN32)
/* If a request includes query info in the URL (stuff after "?"), and
 * the query info does not contain "=" (indicative of a FORM submission),
 * then this routine is called to create the argument list to be passed
 * to the CGI script.  When suexec is enabled, the suexec path, user, and
 * group are the first three arguments to be passed; if not, all three
 * must be NULL.  The query info is split into separate arguments, where
 * "+" is the separator between keyword arguments.
 *
 * XXXX: note that the WIN32 code uses one of the suexec strings 
 * to pass an interpreter name.  Remember this if changing the way they
 * are handled in create_argv.
 *
 */
static char **create_argv(ap_context_t *p, char *path, char *user, char *group,
			  char *av0, const char *args)
{
    int x, numwords;
    char **av;
    char *w;
    int idx = 0;

    /* count the number of keywords */

    for (x = 0, numwords = 1; args[x]; x++) {
        if (args[x] == '+') {
	    ++numwords;
	}
    }

    if (numwords > APACHE_ARG_MAX - 5) {
	numwords = APACHE_ARG_MAX - 5;	/* Truncate args to prevent overrun */
    }
    av = (char **) ap_palloc(p, (numwords + 5) * sizeof(char *));

    if (path) {
	av[idx++] = path;
    }
    if (user) {
	av[idx++] = user;
    }
    if (group) {
	av[idx++] = group;
    }

    av[idx++] = av0;

    for (x = 1; x <= numwords; x++) {
	w = ap_getword_nulls(p, &args, '+');
	ap_unescape_url(w);
	av[idx++] = ap_escape_shell_cmd(p, w);
    }
    av[idx] = NULL;
    return av;
}
#endif /* defined(OS2) || defined(WIN32) */

static char *http2env(ap_context_t *a, char *w)
{
    char *res = ap_pstrcat(a, "HTTP_", w, NULL);
    char *cp = res;

    while (*++cp) {
	if (!ap_isalnum(*cp) && *cp != '_') {
	    *cp = '_';
	}
	else {
	    *cp = ap_toupper(*cp);
	}
    }

    return res;
}

API_EXPORT(char **) ap_create_environment(ap_context_t *p, ap_table_t *t)
{
    ap_array_header_t *env_arr = ap_table_elts(t);
    ap_table_entry_t *elts = (ap_table_entry_t *) env_arr->elts;
    char **env = (char **) ap_palloc(p, (env_arr->nelts + 2) * sizeof(char *));
    int i, j;
    char *tz;
    char *whack;

    j = 0;
    if (!ap_table_get(t, "TZ")) {
	tz = getenv("TZ");
	if (tz != NULL) {
	    env[j++] = ap_pstrcat(p, "TZ=", tz, NULL);
	}
    }
    for (i = 0; i < env_arr->nelts; ++i) {
        if (!elts[i].key) {
	    continue;
	}
	env[j] = ap_pstrcat(p, elts[i].key, "=", elts[i].val, NULL);
	whack = env[j];
	if (ap_isdigit(*whack)) {
	    *whack++ = '_';
	}
	while (*whack != '=') {
	    if (!ap_isalnum(*whack) && *whack != '_') {
		*whack = '_';
	    }
	    ++whack;
	}
	++j;
    }

    env[j] = NULL;
    return env;
}

API_EXPORT(void) ap_add_common_vars(request_rec *r)
{
    ap_table_t *e;
    server_rec *s = r->server;
    conn_rec *c = r->connection;
    const char *rem_logname;
    char *env_path;
#ifdef WIN32
    char *env_temp;
#endif
    const char *host;
    ap_array_header_t *hdrs_arr = ap_table_elts(r->headers_in);
    ap_table_entry_t *hdrs = (ap_table_entry_t *) hdrs_arr->elts;
    int i;

    /* use a temporary ap_table_t which we'll overlap onto
     * r->subprocess_env later
     */
    e = ap_make_table(r->pool, 25 + hdrs_arr->nelts);

    /* First, add environment vars from headers... this is as per
     * CGI specs, though other sorts of scripting interfaces see
     * the same vars...
     */

    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key) {
	    continue;
	}

	/* A few headers are special cased --- Authorization to prevent
	 * rogue scripts from capturing passwords; content-type and -length
	 * for no particular reason.
	 */

	if (!strcasecmp(hdrs[i].key, "Content-type")) {
	    ap_table_addn(e, "CONTENT_TYPE", hdrs[i].val);
	}
	else if (!strcasecmp(hdrs[i].key, "Content-length")) {
	    ap_table_addn(e, "CONTENT_LENGTH", hdrs[i].val);
	}
	/*
	 * You really don't want to disable this check, since it leaves you
	 * wide open to CGIs stealing passwords and people viewing them
	 * in the environment with "ps -e".  But, if you must...
	 */
#ifndef SECURITY_HOLE_PASS_AUTHORIZATION
	else if (!strcasecmp(hdrs[i].key, "Authorization") 
		 || !strcasecmp(hdrs[i].key, "Proxy-Authorization")) {
	    continue;
	}
#endif
	else {
	    ap_table_addn(e, http2env(r->pool, hdrs[i].key), hdrs[i].val);
	}
    }

    if (!(env_path = getenv("PATH"))) {
	env_path = DEFAULT_PATH;
    }

#ifdef WIN32
    if (env_temp = getenv("SystemRoot")) {
        ap_table_addn(e, "SystemRoot", env_temp);         
    }
    if (env_temp = getenv("COMSPEC")) {
        ap_table_addn(e, "COMSPEC", env_temp);            
    }
    if (env_temp = getenv("WINDIR")) {
        ap_table_addn(e, "WINDIR", env_temp);
    }
#endif

    ap_table_addn(e, "PATH", env_path);
    ap_table_addn(e, "SERVER_SIGNATURE", ap_psignature("", r));
    ap_table_addn(e, "SERVER_SOFTWARE", ap_get_server_version());
    ap_table_addn(e, "SERVER_NAME", ap_get_server_name(r));
    ap_table_addn(e, "SERVER_ADDR", r->connection->local_ip);	/* Apache */
    ap_table_addn(e, "SERVER_PORT",
		  ap_psprintf(r->pool, "%u", ap_get_server_port(r)));
    host = ap_get_remote_host(c, r->per_dir_config, REMOTE_HOST);
    if (host) {
	ap_table_addn(e, "REMOTE_HOST", host);
    }
    ap_table_addn(e, "REMOTE_ADDR", c->remote_ip);
    ap_table_addn(e, "DOCUMENT_ROOT", ap_document_root(r));	/* Apache */
    ap_table_addn(e, "SERVER_ADMIN", s->server_admin);	/* Apache */
    ap_table_addn(e, "SCRIPT_FILENAME", r->filename);	/* Apache */

    ap_table_addn(e, "REMOTE_PORT",
		  ap_psprintf(r->pool, "%d", ntohs(c->remote_addr.sin_port)));

    if (r->user) {
	ap_table_addn(e, "REMOTE_USER", r->user);
    }
    if (r->ap_auth_type) {
	ap_table_addn(e, "AUTH_TYPE", r->ap_auth_type);
    }
    rem_logname = ap_get_remote_logname(r);
    if (rem_logname) {
	ap_table_addn(e, "REMOTE_IDENT", ap_pstrdup(r->pool, rem_logname));
    }

    /* Apache custom error responses. If we have redirected set two new vars */

    if (r->prev) {
        if (r->prev->args) {
	    ap_table_addn(e, "REDIRECT_QUERY_STRING", r->prev->args);
	}
	if (r->prev->uri) {
	    ap_table_addn(e, "REDIRECT_URL", r->prev->uri);
	}
    }

    ap_overlap_tables(r->subprocess_env, e, AP_OVERLAP_TABLES_SET);
}

/* This "cute" little function comes about because the path info on
 * filenames and URLs aren't always the same. So we take the two,
 * and find as much of the two that match as possible.
 */

API_EXPORT(int) ap_find_path_info(const char *uri, const char *path_info)
{
    int lu = strlen(uri);
    int lp = strlen(path_info);

    while (lu-- && lp-- && uri[lu] == path_info[lp]);

    if (lu == -1) {
	lu = 0;
    }

    while (uri[lu] != '\0' && uri[lu] != '/') {
        lu++;
    }
    return lu;
}

/* Obtain the Request-URI from the original request-line, returning
 * a new string from the request pool containing the URI or "".
 */
static char *original_uri(request_rec *r)
{
    char *first, *last;

    if (r->the_request == NULL) {
	return (char *) ap_pcalloc(r->pool, 1);
    }

    first = r->the_request;	/* use the request-line */

    while (*first && !ap_isspace(*first)) {
	++first;		/* skip over the method */
    }
    while (ap_isspace(*first)) {
	++first;		/*   and the space(s)   */
    }

    last = first;
    while (*last && !ap_isspace(*last)) {
	++last;			/* end at next whitespace */
    }

    return ap_pstrndup(r->pool, first, last - first);
}

API_EXPORT(void) ap_add_cgi_vars(request_rec *r)
{
    ap_table_t *e = r->subprocess_env;

    ap_table_setn(e, "GATEWAY_INTERFACE", "CGI/1.1");
    ap_table_setn(e, "SERVER_PROTOCOL", r->protocol);
    ap_table_setn(e, "REQUEST_METHOD", r->method);
    ap_table_setn(e, "QUERY_STRING", r->args ? r->args : "");
    ap_table_setn(e, "REQUEST_URI", original_uri(r));

    /* Note that the code below special-cases scripts run from includes,
     * because it "knows" that the sub_request has been hacked to have the
     * args and path_info of the original request, and not any that may have
     * come with the script URI in the include command.  Ugh.
     */

    if (!strcmp(r->protocol, "INCLUDED")) {
	ap_table_setn(e, "SCRIPT_NAME", r->uri);
	if (r->path_info && *r->path_info) {
	    ap_table_setn(e, "PATH_INFO", r->path_info);
	}
    }
    else if (!r->path_info || !*r->path_info) {
	ap_table_setn(e, "SCRIPT_NAME", r->uri);
    }
    else {
	int path_info_start = ap_find_path_info(r->uri, r->path_info);

	ap_table_setn(e, "SCRIPT_NAME",
		      ap_pstrndup(r->pool, r->uri, path_info_start));

	ap_table_setn(e, "PATH_INFO", r->path_info);
    }

    if (r->path_info && r->path_info[0]) {
	/*
	 * To get PATH_TRANSLATED, treat PATH_INFO as a URI path.
	 * Need to re-escape it for this, since the entire URI was
	 * un-escaped before we determined where the PATH_INFO began.
	 */
	request_rec *pa_req;

	pa_req = ap_sub_req_lookup_uri(ap_escape_uri(r->pool, r->path_info), r);

	if (pa_req->filename) {
#ifdef WIN32
	    char buffer[HUGE_STRING_LEN];
#endif
	    char *pt = ap_pstrcat(r->pool, pa_req->filename, pa_req->path_info,
				  NULL);
#ifdef WIN32
	    /* We need to make this a real Windows path name */
	    GetFullPathName(pt, HUGE_STRING_LEN, buffer, NULL);
	    ap_table_setn(e, "PATH_TRANSLATED", ap_pstrdup(r->pool, buffer));
#else
	    ap_table_setn(e, "PATH_TRANSLATED", pt);
#endif
	}
	ap_destroy_sub_req(pa_req);
    }
}


static int set_cookie_doo_doo(void *v, const char *key, const char *val)
{
    ap_table_addn(v, key, val);
    return 1;
}

API_EXPORT(int) ap_scan_script_header_err_core(request_rec *r, char *buffer,
				       int (*getsfunc) (char *, int, void *),
				       void *getsfunc_data)
{
    char x[MAX_STRING_LEN];
    char *w, *l;
    int p;
    int cgi_status = HTTP_OK;
    ap_table_t *merge;
    ap_table_t *cookie_table;

    if (buffer) {
	*buffer = '\0';
    }
    w = buffer ? buffer : x;

    /* temporary place to hold headers to merge in later */
    merge = ap_make_table(r->pool, 10);

    /* The HTTP specification says that it is legal to merge duplicate
     * headers into one.  Some browsers that support Cookies don't like
     * merged headers and prefer that each Set-Cookie header is sent
     * separately.  Lets humour those browsers by not merging.
     * Oh what a pain it is.
     */
    cookie_table = ap_make_table(r->pool, 2);
    ap_table_do(set_cookie_doo_doo, cookie_table, r->err_headers_out, "Set-Cookie", NULL);

    while (1) {

	if ((*getsfunc) (w, MAX_STRING_LEN - 1, getsfunc_data) == 0) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "Premature end of script headers: %s", r->filename);
	    return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Delete terminal (CR?)LF */

	p = strlen(w);
	if (p > 0 && w[p - 1] == '\n') {
	    if (p > 1 && w[p - 2] == '\015') {
		w[p - 2] = '\0';
	    }
	    else {
		w[p - 1] = '\0';
	    }
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

	    if ((cgi_status == HTTP_OK) && (r->method_number == M_GET)) {
		cond_status = ap_meets_conditions(r);
	    }
	    ap_overlap_tables(r->err_headers_out, merge,
		AP_OVERLAP_TABLES_MERGE);
	    if (!ap_is_empty_table(cookie_table)) {
		/* the cookies have already been copied to the cookie_table */
		ap_table_unset(r->err_headers_out, "Set-Cookie");
		r->err_headers_out = ap_overlay_tables(r->pool,
		    r->err_headers_out, cookie_table);
	    }
	    return cond_status;
	}

	/* if we see a bogus header don't ignore it. Shout and scream */

#ifdef CHARSET_EBCDIC
	    /* Chances are that we received an ASCII header text instead of
	     * the expected EBCDIC header lines. Try to auto-detect:
	     */
	if (!(l = strchr(w, ':'))) {
	    int maybeASCII = 0, maybeEBCDIC = 0;
	    char *cp;

	    for (cp = w; *cp != '\0'; ++cp) {
		if (isprint(*cp) && !isprint(os_toebcdic[*cp]))
		    ++maybeEBCDIC;
		if (!isprint(*cp) && isprint(os_toebcdic[*cp]))
		    ++maybeASCII;
		}
	    if (maybeASCII > maybeEBCDIC) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
			 "CGI Interface Error: Script headers apparently ASCII: (CGI = %s)", r->filename);
		ascii2ebcdic(w, w, cp - w);
	    }
	}
#endif
	if (!(l = strchr(w, ':'))) {
	    char malformed[(sizeof MALFORMED_MESSAGE) + 1
			   + MALFORMED_HEADER_LENGTH_TO_SHOW];

	    strcpy(malformed, MALFORMED_MESSAGE);
	    strncat(malformed, w, MALFORMED_HEADER_LENGTH_TO_SHOW);

	    if (!buffer) {
		/* Soak up all the script output - may save an outright kill */
	        while ((*getsfunc) (w, MAX_STRING_LEN - 1, getsfunc_data)) {
		    continue;
		}
	    }

	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "%s: %s", malformed, r->filename);
	    return HTTP_INTERNAL_SERVER_ERROR;
	}

	*l++ = '\0';
	while (*l && ap_isspace(*l)) {
	    ++l;
	}

	if (!strcasecmp(w, "Content-type")) {
	    char *tmp;

	    /* Nuke trailing whitespace */

	    char *endp = l + strlen(l) - 1;
	    while (endp > l && ap_isspace(*endp)) {
		*endp-- = '\0';
	    }

	    tmp = ap_pstrdup(r->pool, l);
	    ap_content_type_tolower(tmp);
	    r->content_type = tmp;
	}
	/*
	 * If the script returned a specific status, that's what
	 * we'll use - otherwise we assume 200 OK.
	 */
	else if (!strcasecmp(w, "Status")) {
	    r->status = cgi_status = atoi(l);
	    r->status_line = ap_pstrdup(r->pool, l);
	}
	else if (!strcasecmp(w, "Location")) {
	    ap_table_set(r->headers_out, w, l);
	}
	else if (!strcasecmp(w, "Content-Length")) {
	    ap_table_set(r->headers_out, w, l);
	}
	else if (!strcasecmp(w, "Transfer-Encoding")) {
	    ap_table_set(r->headers_out, w, l);
	}
	/*
	 * If the script gave us a Last-Modified header, we can't just
	 * pass it on blindly because of restrictions on future values.
	 */
	else if (!strcasecmp(w, "Last-Modified")) {
	    ap_update_mtime(r, ap_parseHTTPdate(l));
	    ap_set_last_modified(r);
	}
	else if (!strcasecmp(w, "Set-Cookie")) {
	    ap_table_add(cookie_table, w, l);
	}
	else {
	    ap_table_add(merge, w, l);
	}
    }
}

static int getsfunc_FILE(char *buf, int len, void *f)
{
    return ap_fgets(buf, len, (ap_file_t *) f) == APR_SUCCESS;
}

API_EXPORT(int) ap_scan_script_header_err(request_rec *r, ap_file_t *f,
					  char *buffer)
{
    return ap_scan_script_header_err_core(r, buffer, getsfunc_FILE, f);
}

static int getsfunc_BUFF(char *w, int len, void *fb)
{
    return ap_bgets(w, len, (BUFF *) fb) > 0;
}

API_EXPORT(int) ap_scan_script_header_err_buff(request_rec *r, BUFF *fb,
					       char *buffer)
{
    return ap_scan_script_header_err_core(r, buffer, getsfunc_BUFF, fb);
}


API_EXPORT(void) ap_send_size(ap_ssize_t size, request_rec *r)
{
    /* XXX: this -1 thing is a gross hack */
    if (size == (ap_ssize_t)-1) {
	ap_rputs("    -", r);
    }
    else if (!size) {
	ap_rputs("   0k", r);
    }
    else if (size < 1024) {
	ap_rputs("   1k", r);
    }
    else if (size < 1048576) {
	ap_rprintf(r, "%4" APR_SSIZE_T_FMT "k", (size + 512) / 1024);
    }
    else if (size < 103809024) {
	ap_rprintf(r, "%4.1fM", size / 1048576.0);
    }
    else {
	ap_rprintf(r, "%4" APR_SSIZE_T_FMT "M", (size + 524288) / 1048576);
    }
}

#if defined(OS2) || defined(WIN32)
static char **create_argv_cmd(ap_context_t *p, char *av0, const char *args, char *path)
{
    register int x, n;
    char **av;
    char *w;

    for (x = 0, n = 2; args[x]; x++) {
        if (args[x] == '+') {
	    ++n;
	}
    }

    /* Add extra strings to array. */
    n = n + 2;

    av = (char **) ap_palloc(p, (n + 1) * sizeof(char *));
    av[0] = av0;

    /* Now insert the extra strings we made room for above. */
    av[1] = strdup("/C");
    av[2] = strdup(path);

    for (x = (1 + 2); x < n; x++) {
	w = ap_getword(p, &args, '+');
	ap_unescape_url(w);
	av[x] = ap_escape_shell_cmd(p, w);
    }
    av[n] = NULL;
    return av;
}
#endif

