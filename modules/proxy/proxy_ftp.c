/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

/* FTP routines for Apache proxy */

#include "mod_proxy.h"

#define AUTODETECT_PWD


/*
 * Decodes a '%' escaped string, and returns the number of characters
 */
static int decodeenc(char *x)
{
    int i, j, ch;

    if (x[0] == '\0')
	return 0;		/* special case for no characters */
    for (i = 0, j = 0; x[i] != '\0'; i++, j++) {
/* decode it if not already done */
	ch = x[i];
	if (ch == '%' && ap_isxdigit(x[i + 1]) && ap_isxdigit(x[i + 2])) {
	    ch = ap_proxy_hex2c(&x[i + 1]);
	    i += 2;
	}
	x[j] = ch;
    }
    x[j] = '\0';
    return j;
}

/*
 * checks an encoded ftp string for bad characters, namely, CR, LF or
 * non-ascii character
 */
static int ftp_check_string(const char *x)
{
    int i, ch = 0;

    for (i = 0; x[i] != '\0'; i++) {
	ch = x[i];
	if (ch == '%' && ap_isxdigit(x[i + 1]) && ap_isxdigit(x[i + 2])) {
	    ch = ap_proxy_hex2c(&x[i + 1]);
	    i += 2;
	}
#if !APR_CHARSET_EBCDIC
        if (ch == '\015' || ch == '\012' || (ch & 0x80))
#else /*APR_CHARSET_EBCDIC*/
        if (ch == '\r' || ch == '\n' || (os_toascii[ch] & 0x80))
#endif /*APR_CHARSET_EBCDIC*/
        return 0;
    }
    return 1;
}

/*
 * Canonicalise ftp URLs.
 */
int ap_proxy_ftp_canon(request_rec *r, char *url)
{
    char *user, *password, *host, *path, *parms, *strp, sport[7];
    apr_pool_t *p = r->pool;
    const char *err;
    int port;

    port = DEFAULT_FTP_PORT;
    err = ap_proxy_canon_netloc(p, &url, &user, &password, &host, &port);
    if (err)
	return HTTP_BAD_REQUEST;
    if (user != NULL && !ftp_check_string(user))
	return HTTP_BAD_REQUEST;
    if (password != NULL && !ftp_check_string(password))
	return HTTP_BAD_REQUEST;

/* now parse path/parameters args, according to rfc1738 */
/* N.B. if this isn't a true proxy request, then the URL path
 * (but not query args) has already been decoded.
 * This gives rise to the problem of a ; being decoded into the
 * path.
 */
    strp = strchr(url, ';');
    if (strp != NULL) {
	*(strp++) = '\0';
	parms = ap_proxy_canonenc(p, strp, strlen(strp), enc_parm,
				  r->proxyreq);
	if (parms == NULL)
	    return HTTP_BAD_REQUEST;
    }
    else
	parms = "";

    path = ap_proxy_canonenc(p, url, strlen(url), enc_path, r->proxyreq);
    if (path == NULL)
	return HTTP_BAD_REQUEST;
    if (!ftp_check_string(path))
	return HTTP_BAD_REQUEST;

    if (r->proxyreq && r->args != NULL) {
	if (strp != NULL) {
	    strp = ap_proxy_canonenc(p, r->args, strlen(r->args), enc_parm, 1);
	    if (strp == NULL)
		return HTTP_BAD_REQUEST;
	    parms = apr_pstrcat(p, parms, "?", strp, NULL);
	}
	else {
	    strp = ap_proxy_canonenc(p, r->args, strlen(r->args), enc_fpath, 1);
	    if (strp == NULL)
		return HTTP_BAD_REQUEST;
	    path = apr_pstrcat(p, path, "?", strp, NULL);
	}
	r->args = NULL;
    }

/* now, rebuild URL */

    if (port != DEFAULT_FTP_PORT)
	apr_snprintf(sport, sizeof(sport), ":%d", port);
    else
	sport[0] = '\0';

    r->filename = apr_pstrcat(p, "proxy:ftp://", (user != NULL) ? user : "",
			       (password != NULL) ? ":" : "",
			       (password != NULL) ? password : "",
		          (user != NULL) ? "@" : "", host, sport, "/", path,
			       (parms[0] != '\0') ? ";" : "", parms, NULL);

    return OK;
}


/*
 * Like ftp_getrc but returns both the ftp status code and 
 * remembers the response message in the supplied buffer
 */
static int ftp_getrc_msg(conn_rec *c, char *msgbuf, int msglen)
{
    int len, status;
    char *response;
    char buff[5];
    char *mb = msgbuf,
	 *me = &msgbuf[msglen];
    apr_bucket *e;
    apr_bucket_brigade *bb = apr_brigade_create(c->pool);

    bb = apr_brigade_create(c->pool);

    /* Tell http_filter to grab the data one line at a time. */
    c->remain = 0;

    ap_get_brigade(c->input_filters, bb, AP_MODE_BLOCKING);
    e = APR_BRIGADE_FIRST(bb);
    apr_bucket_read(e, (const char **)&response, &len, APR_BLOCK_READ);
    if (len == -1) {
	return -1;
    }
    if (len < 5 || !apr_isdigit(response[0]) || !apr_isdigit(response[1]) ||
	!apr_isdigit(response[2]) || (response[3] != ' ' && response[3] != '-'))
	status = 0;
    else
	status = 100 * response[0] + 10 * response[1] + response[2] - 111 * '0';

    mb = apr_cpystrn(mb, response+4, me - mb);

/* FIXME: If the line was too long, read till LF */

    if (response[3] == '-') {
	memcpy(buff, response, 3);
	buff[3] = ' ';
	do {
	    apr_bucket_read(e, (const char **)&response, &len, APR_BLOCK_READ);
	    if (len == -1)
		return -1;

/* FIXME: If the line was too long, read till LF */

	    mb = apr_cpystrn(mb, response+4, me - mb);
	} while (memcmp(response, buff, 4) != 0);
    }

    APR_BUCKET_REMOVE(e);
    apr_bucket_destroy(e);

    return status;
}

/* this is a filter that turns a raw ASCII directory listing into pretty HTML */

/* ideally, mod_proxy should simply send the raw directory list up the filter
 * stack to mod_autoindex, which in theory should turn the raw ascii into
 * pretty html along with all the bells and whistles it provides...
 *
 * all in good time...! :)
 */

apr_status_t ap_proxy_send_dir_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode)
{
    conn_rec *c = f->r->connection;
    apr_pool_t *p = f->r->pool;
    apr_bucket *e;
    char buf[MAX_STRING_LEN];
    char buf2[MAX_STRING_LEN];

    char *filename;
    int searchidx = 0;
    char *searchptr = NULL;
    int firstfile = 1;
    register int n;
    char *dir, *path, *reldir, *site;

    char *cwd = NULL;


    /* Save "scheme://site" prefix without password */
    site = ap_unparse_uri_components(p, &f->r->parsed_uri, UNP_OMITPASSWORD|UNP_OMITPATHINFO);
    /* ... and path without query args */
    path = ap_unparse_uri_components(p, &f->r->parsed_uri, UNP_OMITSITEPART|UNP_OMITQUERY);
    (void)decodeenc(path);

    /* Copy path, strip (all except the last) trailing slashes */
    path = dir = apr_pstrcat(p, path, "/", NULL);
    while ((n = strlen(path)) > 1 && path[n-1] == '/' && path[n-2] == '/')
	path[n-1] = '\0';

    /* print "ftp://host/" */
    n = apr_snprintf(buf, sizeof(buf), DOCTYPE_HTML_3_2
		"<HTML><HEAD><TITLE>%s%s</TITLE>\n"
		"<BASE HREF=\"%s%s\"></HEAD>\n"
		"<BODY><H2>Directory of "
		"<A HREF=\"/\">%s</A>/",
		site, path, site, path, site);

    e = apr_bucket_pool_create(buf, n, p);
    APR_BRIGADE_INSERT_TAIL(bb, e);

    while ((dir = strchr(dir+1, '/')) != NULL)
    {
	*dir = '\0';
	if ((reldir = strrchr(path+1, '/'))==NULL)
	    reldir = path+1;
	else
	    ++reldir;
	/* print "path/" component */
	n = apr_snprintf(buf, sizeof(buf), "<A HREF=\"/%s/\">%s</A>/", path+1, reldir);
	e = apr_bucket_pool_create(buf, n, p);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	*dir = '/';
    }
    /* If the caller has determined the current directory, and it differs */
    /* from what the client requested, then show the real name */
    if (cwd == NULL || strncmp (cwd, path, strlen(cwd)) == 0) {
	n = apr_snprintf(buf, sizeof(buf), "</H2>\n<HR><PRE>");
    } else {
	n = apr_snprintf(buf, sizeof(buf), "</H2>\n(%s)\n<HR><PRE>", cwd);
    }
    e = apr_bucket_pool_create(buf, n, p);
    APR_BRIGADE_INSERT_TAIL(bb, e);

    e = apr_bucket_flush_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);

    while (!c->aborted) {
	n = ap_getline(buf, sizeof(buf), f->r, 0);
	if (n == -1) {		/* input error */
	    break;
	}
	if (n == 0) {
	    break;		/* EOF */
	}
	if (buf[0] == 'l' && (filename=strstr(buf, " -> ")) != NULL) {
	    char *link_ptr = filename;

	    do {
		filename--;
	    } while (filename[0] != ' ');
	    *(filename++) = '\0';
	    *(link_ptr++) = '\0';
	    if ((n = strlen(link_ptr)) > 1 && link_ptr[n - 1] == '\n')
	      link_ptr[n - 1] = '\0';
	    apr_snprintf(buf2, sizeof(buf2), "%s <A HREF=\"%s\">%s %s</A>\n", buf, filename, filename, link_ptr);
	    apr_cpystrn(buf, buf2, sizeof(buf));
	    n = strlen(buf);
	}
	else if (buf[0] == 'd' || buf[0] == '-' || buf[0] == 'l' || apr_isdigit(buf[0])) {
	    if (apr_isdigit(buf[0])) {	/* handle DOS dir */
		searchptr = strchr(buf, '<');
		if (searchptr != NULL)
		    *searchptr = '[';
		searchptr = strchr(buf, '>');
		if (searchptr != NULL)
		    *searchptr = ']';
	    }

	    filename = strrchr(buf, ' ');
	    *(filename++) = 0;
	    filename[strlen(filename) - 1] = 0;

	    /* handle filenames with spaces in 'em */
	    if (!strcmp(filename, ".") || !strcmp(filename, "..") || firstfile) {
		firstfile = 0;
		searchidx = filename - buf;
	    }
	    else if (searchidx != 0 && buf[searchidx] != 0) {
		*(--filename) = ' ';
		buf[searchidx - 1] = 0;
		filename = &buf[searchidx];
	    }

	    /* Special handling for '.' and '..' */
	    if (!strcmp(filename, ".") || !strcmp(filename, "..") || buf[0] == 'd') {
		apr_snprintf(buf2, sizeof(buf2), "%s <A HREF=\"%s/\">%s</A>\n",
		    buf, filename, filename);
	    }
	    else {
		apr_snprintf(buf2, sizeof(buf2), "%s <A HREF=\"%s\">%s</A>\n", buf, filename, filename);
	    }
	    apr_cpystrn(buf, buf2, sizeof(buf));
	    n = strlen(buf);
	}

	e = apr_bucket_pool_create(buf, n, p);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	e = apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(bb, e);

    }

    n = apr_snprintf(buf, sizeof(buf), "</PRE><HR>\n%s</BODY></HTML>\n", ap_psignature("", f->r));
    e = apr_bucket_pool_create(buf, n, p);
    APR_BRIGADE_INSERT_TAIL(bb, e);

    e = apr_bucket_eos_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);

/* probably not necessary */
/*    e = apr_bucket_flush_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);
*/

    return APR_SUCCESS;
}

/* Common routine for failed authorization (i.e., missing or wrong password)
 * to an ftp service. This causes most browsers to retry the request
 * with username and password (which was presumably queried from the user)
 * supplied in the Authorization: header.
 * Note that we "invent" a realm name which consists of the
 * ftp://user@host part of the reqest (sans password -if supplied but invalid-)
 */
static int ftp_unauthorized (request_rec *r, int log_it)
{
    r->proxyreq = PROXYREQ_NONE;
    /* Log failed requests if they supplied a password
     * (log username/password guessing attempts)
     */
    if (log_it)
	ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r,
		      "proxy: missing or failed auth to %s",
		      ap_unparse_uri_components(r->pool,
		      &r->parsed_uri, UNP_OMITPATHINFO));

    apr_table_setn(r->err_headers_out, "WWW-Authenticate",
                  apr_pstrcat(r->pool, "Basic realm=\"",
		  ap_unparse_uri_components(r->pool, &r->parsed_uri,
		    UNP_OMITPASSWORD|UNP_OMITPATHINFO),
		    "\"", NULL));

    return HTTP_UNAUTHORIZED;
}

/*
 * Handles direct access of ftp:// URLs
 * Original (Non-PASV) version from
 * Troy Morrison <spiffnet@zoom.com>
 * PASV added by Chuck
 * Filters by [Graham Leggett <minfrin@sharp.fm>]
 */
int ap_proxy_ftp_handler(request_rec *r, char *url)
{
    apr_pool_t *p = r->pool;
    apr_socket_t *sock, *local_sock, *remote_sock;
    apr_sockaddr_t *uri_addr, *connect_addr;
    conn_rec *origin, *remote;
    int err;
    apr_bucket *e;
    apr_bucket_brigade *bb = apr_brigade_create(p);
    char *buf, *pasv, *connectname;
    apr_port_t connectport;
    char buffer[MAX_STRING_LEN];

    char *path, *strp, *parms;
    char *cwd = NULL;
    char *user = NULL;
/*    char *account = NULL; how to supply an account in a URL? */
    const char *password = NULL;
    int i, j, len, rc;
    int one = 1;
    char *size = NULL;

    /* stuff for PASV mode */
    int pasvmode = 0;
    char dates[AP_RFC822_DATE_LEN];

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);


    /*
     * I: Who Do I Connect To?
     * -----------------------
     *
     * Break up the URL to determine the host to connect to
     */

    /* we only support GET and HEAD */
    if (r->method_number != M_GET)
	return HTTP_NOT_IMPLEMENTED;


    /* We break the URL into host, port, path-search */
    connectname = r->parsed_uri.hostname;
    connectport = (r->parsed_uri.port != 0)
	           ? r->parsed_uri.port
	           : ap_default_port_for_request(r);
    path = apr_pstrdup(p, r->parsed_uri.path);
    path = (path != NULL && path[0] != '\0') ? &path[1] : "";

    parms = strchr(path, ';');
    if (parms != NULL)
	*(parms++) = '\0';

    /* The "Authorization:" header must be checked first.
     * We allow the user to "override" the URL-coded user [ & password ]
     * in the Browsers' User&Password Dialog.
     * NOTE that this is only marginally more secure than having the
     * password travel in plain as part of the URL, because Basic Auth
     * simply uuencodes the plain text password. 
     * But chances are still smaller that the URL is logged regularly.
     */
    if ((password = apr_table_get(r->headers_in, "Authorization")) != NULL
	&& strcasecmp(ap_getword(r->pool, &password, ' '), "Basic") == 0
	&& (password = ap_pbase64decode(r->pool, password))[0] != ':') {
	/* Note that this allocation has to be made from r->connection->pool
	 * because it has the lifetime of the connection.  The other allocations
	 * are temporary and can be tossed away any time.
	 */
	user = ap_getword_nulls (r->pool, &password, ':');
	r->ap_auth_type = "Basic";
	r->user = r->parsed_uri.user = user;
    }
    else if ((user = r->parsed_uri.user) != NULL) {
	user = apr_pstrdup(p, user);
	decodeenc(user);
	if ((password = r->parsed_uri.password) != NULL) {
	    char *tmp = apr_pstrdup(p, password);
	    decodeenc(tmp);
	    password = tmp;
	}
    }
    else {
		user = "anonymous";
		password = "apache_proxy@";
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		 "proxy: FTP connecting %s to %s:%d", url, connectname, connectport);

    /* do a DNS lookup for the destination host */
    err = apr_sockaddr_info_get(&uri_addr, connectname, APR_UNSPEC, connectport, 0, p);

    /* check if ProxyBlock directive on this host */
    if (OK != ap_proxy_checkproxyblock(r, conf, uri_addr)) {
	return ap_proxyerror(r, HTTP_FORBIDDEN,
			     "Connect to remote machine blocked");
    }

//return HTTP_NOT_IMPLEMENTED;

    /*
     * II: Make the Connection
     * -----------------------
     *
     * We have determined who to connect to. Now make the connection.
     */

    /* get all the possible IP addresses for the destname and loop through them
     * until we get a successful connection
     */
    if (APR_SUCCESS != err) {
	return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_pstrcat(p,
                             "DNS lookup failure for: ",
                             connectname, NULL));
    }

    if ((apr_socket_create(&sock, APR_INET, SOCK_STREAM, r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "proxy: error creating socket");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

#if !defined(TPF) && !defined(BEOS)
    if (conf->recv_buffer_size > 0
	&& apr_setsocketopt(sock, APR_SO_RCVBUF,
	    conf->recv_buffer_size)) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			 "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
    }
#endif

    if (apr_setsocketopt(sock, APR_SO_REUSEADDR, one)) {
#ifndef _OSD_POSIX /* BS2000 has this option "always on" */
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		     "proxy: error setting reuseaddr option: setsockopt(SO_REUSEADDR)");
	apr_socket_close(sock);
	return HTTP_INTERNAL_SERVER_ERROR;
#endif /*_OSD_POSIX*/
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		 "proxy: socket has been created");


    /*
     * At this point we have a list of one or more IP addresses of
     * the machine to connect to. If configured, reorder this
     * list so that the "best candidate" is first try. "best
     * candidate" could mean the least loaded server, the fastest
     * responding server, whatever.
     *
     * For now we do nothing, ie we get DNS round robin.
     * XXX FIXME
     */


    /* try each IP address until we connect successfully */
    {
	int failed = 1;
	while (connect_addr) {

	    /* make the connection out of the socket */
	    err = apr_connect(sock, connect_addr);

	    /* if an error occurred, loop round and try again */
            if (err != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, err, r->server,
			     "proxy: attempt to connect to %pI (%s) failed", connect_addr, connectname);
		connect_addr = connect_addr->next;
		continue;
            }

	    /* if we get here, all is well */
	    failed = 0;
	    break;
	}

	/* handle a permanent error from the above loop */
	if (failed) {
	    apr_socket_close(sock);
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_pstrcat(r->pool,
				 "Could not connect to remote machine: ",
				 r->parsed_uri.hostname, NULL));
	}
    }

    /* the socket is now open, create a new connection */
    origin = ap_new_connection(p, r->server, sock, r->connection->id);
    if (!origin) {
	/* the peer reset the connection already; ap_new_connection() 
	 * closed the socket */
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: an error occurred creating a new connection to %pI (%s)", connect_addr, connectname);
	apr_socket_close(sock);
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    conf->id = r->connection->id;
    /* allocate this out of the connection pool - the check on r->connection->id makes
     * sure that this string does not live past the connection lifetime */
    conf->connectname = apr_pstrdup(r->connection->pool, connectname);
    conf->connectport = connectport;

    /* if a keepalive connection is floating around, close it first! */
    if (conf->client_socket) {
	apr_socket_close(conf->client_socket);
    }
    conf->client_socket = sock;

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		 "proxy: connection complete");


    /*
     * III: Send Control Request
     * -------------------------
     *
     * Log into the ftp server, send the username & password, change to the correct
     * directory...
     */

    /* set up the connection filters */
    ap_proxy_pre_http_connection(origin);

    /* possible results: */
    /*   120 Service ready in nnn minutes. */
    /*   220 Service ready for new user. */
    /*   421 Service not available, closing control connection. */
    i = ftp_getrc_msg(origin, buffer, sizeof(buffer));
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "FTP: initial connect returned status %d", i);
    if (i == -1) {
	return ap_proxyerror(r, HTTP_BAD_GATEWAY,
			     "Error reading from remote server");
    }
#if 0
    if (i == 120) {
	/* RFC2068 states:
	 * 14.38 Retry-After
	 * 
	 *  The Retry-After response-header field can be used with a 503 (Service
	 *  Unavailable) response to indicate how long the service is expected to
	 *  be unavailable to the requesting client. The value of this field can
	 *  be either an HTTP-date or an integer number of seconds (in decimal)
	 *  after the time of the response.
	 *     Retry-After  = "Retry-After" ":" ( HTTP-date | delta-seconds )
	 */
	ap_set_header("Retry-After", apr_psprintf(p, "%u", 60*wait_mins);
	return ap_proxyerror(r, HTTP_SERVICE_UNAVAILABLE, resp);
    }
#endif
    if (i != 220) {
	return ap_proxyerror(r, HTTP_BAD_GATEWAY, buffer);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                 "FTP: connected.");

    buf = apr_pstrcat(p, "USER ", user, CRLF, NULL);
    bb = apr_brigade_create(p);
    e = apr_bucket_pool_create(buf, strlen(buf), p);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    e = apr_bucket_flush_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);
    ap_pass_brigade(origin->output_filters, bb);
    apr_brigade_destroy(bb);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                 "FTP: USER %s", user);

    /* possible results; 230, 331, 332, 421, 500, 501, 530 */
    /* states: 1 - error, 2 - success; 3 - send password, 4,5 fail */
    /*   230 User logged in, proceed. */
    /*   331 User name okay, need password. */
    /*   332 Need account for login. */
    /*   421 Service not available, closing control connection. */
    /*   500 Syntax error, command unrecognized. */
    /*       (This may include errors such as command line too long.) */
    /*   501 Syntax error in parameters or arguments. */
    /*   530 Not logged in. */
    i = ftp_getrc_msg(origin, buffer, sizeof(buffer));
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                 "FTP: returned status %d", i);
    if (i == -1) {
	return ap_proxyerror(r, HTTP_BAD_GATEWAY, buffer);
    }
    if (i == 530) {
/* FIXME: Insert clean disconnect */
	return ftp_unauthorized (r, 1);	/* log it: user name guessing attempt? */
    }
    if (i != 230 && i != 331) {
	return HTTP_BAD_GATEWAY;
    }

    if (i == 331) {		/* send password */
	if (password == NULL) {
/* FIXME: Insert clean disconnect */
	    return ftp_unauthorized (r, 0);
	}
	buf = apr_pstrcat(p, "PASS ", password, CRLF, NULL);
	bb = apr_brigade_create(p);
	e = apr_bucket_pool_create(buf, strlen(buf), p);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	e = apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(bb, e);
	ap_pass_brigade(origin->output_filters, bb);
	apr_brigade_destroy(bb);
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "FTP: PASS %s", password);

	/* possible results 202, 230, 332, 421, 500, 501, 503, 530 */
	/*   230 User logged in, proceed. */
	/*   332 Need account for login. */
	/*   421 Service not available, closing control connection. */
	/*   500 Syntax error, command unrecognized. */
	/*   501 Syntax error in parameters or arguments. */
	/*   503 Bad sequence of commands. */
	/*   530 Not logged in. */
	i = ftp_getrc_msg(origin, buffer, sizeof(buffer));
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "FTP: returned status %d", i);
	if (i == -1) {
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY,
				 "Error reading from remote server");
	}
	if (i == 332) {
	    return ap_proxyerror(r, HTTP_UNAUTHORIZED,
				 apr_pstrcat(p, "Need account for login: ", buffer, NULL));
	}
	/* @@@ questionable -- we might as well return a 403 Forbidden here */
	if (i == 530) {
/* FIXME: Insert clean disconnect */
	    return ftp_unauthorized (r, 1); /* log it: passwd guessing attempt? */
	}
	if (i != 230 && i != 202) {
	    return HTTP_BAD_GATEWAY;
	}
    }

    /* set the directory (walk directory component by component):
     * this is what we must do if we don't know the OS type of the remote
     * machine
     */
    for (;;) {
	strp = strchr(path, '/');
	if (strp == NULL)
	    break;
	*strp = '\0';

	len = decodeenc(path);
	buf = apr_pstrcat(p, "CWD ", path, CRLF, NULL);
	bb = apr_brigade_create(p);
	e = apr_bucket_pool_create(buf, strlen(buf), p);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	e = apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(bb, e);
	ap_pass_brigade(origin->output_filters, bb);
	apr_brigade_destroy(bb);
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "FTP: CWD %s", path);
	*strp = '/';
	/* responses: 250, 421, 500, 501, 502, 530, 550 */
	/*   250 Requested file action okay, completed. */
	/*   421 Service not available, closing control connection. */
	/*   500 Syntax error, command unrecognized. */
	/*   501 Syntax error in parameters or arguments. */
	/*   502 Command not implemented. */
	/*   530 Not logged in. */
	/*   550 Requested action not taken. */
	i = ftp_getrc_msg(origin, buffer, sizeof(buffer));
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "FTP: returned status %d", i);
	if (i == -1) {
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY,
				 "Error reading from remote server");
	}
	if (i == 550) {
	    return ap_proxyerror(r, HTTP_NOT_FOUND, buffer);
	}
	if (i != 250) {
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY, buffer);
	}

	path = strp + 1;
    }

    if (parms != NULL && strncmp(parms, "type=", 5) == 0) {
	parms += 5;
	if ((parms[0] != 'd' && parms[0] != 'a' && parms[0] != 'i') ||
	    parms[1] != '\0')
	    parms = "";
    }
    else
	parms = "";

    /* changed to make binary transfers the default */

    if (parms[0] != 'a') {
	/* set type to image */
	buf = apr_pstrcat(p, "TYPE I", CRLF, NULL);
	bb = apr_brigade_create(p);
	e = apr_bucket_pool_create(buf, strlen(buf), p);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	e = apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(bb, e);
	ap_pass_brigade(origin->output_filters, bb);
	apr_brigade_destroy(bb);
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "FTP: TYPE I");
	/* responses: 200, 421, 500, 501, 504, 530 */
	/*   200 Command okay. */
	/*   421 Service not available, closing control connection. */
	/*   500 Syntax error, command unrecognized. */
	/*   501 Syntax error in parameters or arguments. */
	/*   504 Command not implemented for that parameter. */
	/*   530 Not logged in. */
	i = ftp_getrc_msg(origin, buffer, sizeof(buffer));
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "FTP: returned status %d", i);
	if (i == -1) {
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY,
				 "Error reading from remote server");
	}
	if (i != 200 && i != 504) {
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY, buffer);
	}
	/* Allow not implemented */
	if (i == 504)
	    parms[0] = '\0';
    }


    /*
     * IV: Make Data Connection?
     * -------------------------
     *
     * Try PASV, if that fails try normally.
     */

    /* try to set up PASV data connection first */
    if ((apr_socket_create(&remote_sock, APR_INET, SOCK_STREAM, r->pool)) != APR_SUCCESS) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		     "proxy: error creating PASV socket");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

#if !defined (TPF) && !defined(BEOS)
    if (conf->recv_buffer_size > 0 && apr_setsocketopt(remote_sock, APR_SO_RCVBUF,
	conf->recv_buffer_size)) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			 "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
    }
#endif

    bb = apr_brigade_create(p);
    buf = apr_pstrcat(p, "PASV", CRLF, NULL);
    e = apr_bucket_pool_create(buf, strlen(buf), p);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    e = apr_bucket_flush_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);
    ap_pass_brigade(origin->output_filters, bb);
    apr_brigade_destroy(bb);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                 "FTP: PASV command issued");
    /* possible results: 227, 421, 500, 501, 502, 530 */
    /*   227 Entering Passive Mode (h1,h2,h3,h4,p1,p2). */
    /*   421 Service not available, closing control connection. */
    /*   500 Syntax error, command unrecognized. */
    /*   501 Syntax error in parameters or arguments. */
    /*   502 Command not implemented. */
    /*   530 Not logged in. */
    bb = apr_brigade_create(p);
    origin->remain = 0;
    ap_get_brigade(origin->input_filters, bb, AP_MODE_BLOCKING);
    e = APR_BRIGADE_FIRST(bb);
    apr_bucket_read(e, (const char **)&buf, &len, APR_BLOCK_READ);
    if (len < 5) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
		     "PASV: control connection is toast");
	apr_socket_close(remote_sock);
	return HTTP_BAD_GATEWAY;
    }
    else {
	unsigned int presult, h0, h1, h2, h3, p0, p1;
	char *pstr;

	pasv = apr_pstrdup(p, buf);
	pasv[len - 1] = '\0';
	pstr = strtok(pasv, " ");	/* separate result code */
	if (pstr != NULL) {
	    presult = atoi(pstr);
	    if (*(pstr + strlen(pstr) + 1) == '=')
	        pstr += strlen(pstr) + 2;
	    else
	    {
	        pstr = strtok(NULL, "(");  /* separate address & port params */
		if (pstr != NULL)
		    pstr = strtok(NULL, ")");
	    }
	}
	else
	    presult = atoi(pasv);

        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "FTP: PASV returned status %d", presult);

/* FIXME: Only supports IPV4 */

	if (presult == 227 && pstr != NULL && (sscanf(pstr,
		 "%d,%d,%d,%d,%d,%d", &h3, &h2, &h1, &h0, &p1, &p0) == 6)) {

	    apr_sockaddr_t *pasv_addr;
	    int pasvport = (p1 << 8) + p0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                         "FTP: PASV contacting host %d.%d.%d.%d:%d",
                         h3, h2, h1, h0, pasvport);

	    /* make the connection */
	    apr_sockaddr_info_get(&pasv_addr, apr_psprintf(p, "%d.%d.%d.%d", h3, h2, h1, h0), APR_UNSPEC, pasvport, 0, p);
	    err = apr_connect(sock, pasv_addr);
            if (err != APR_SUCCESS) {
		return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_psprintf(r->pool,
				     "PASV attempt to connect to %pI failed - firewall/NAT?", pasv_addr));
            }
	    else {
		pasvmode = 1;
	    }
	}
	else
	    /* and try the regular way */
	    apr_socket_close(remote_sock);
    }
    APR_BUCKET_REMOVE(e);
    apr_bucket_destroy(e);

    /* set up data connection */
    if (!pasvmode) {
	apr_sockaddr_t *local_addr;
	char *local_ip;
	apr_port_t local_port;

	if ((apr_socket_create(&local_sock, APR_INET, SOCK_STREAM, r->pool)) != APR_SUCCESS) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			 "proxy: error creating socket");
	    return HTTP_INTERNAL_SERVER_ERROR;
	}
        apr_socket_addr_get(&local_addr, APR_LOCAL, sock);
        apr_sockaddr_port_get(&local_port, local_addr);
        apr_sockaddr_ip_get(&local_ip, local_addr);

	if (apr_setsocketopt(local_sock, APR_SO_REUSEADDR, one) != APR_SUCCESS) {
#ifndef _OSD_POSIX /* BS2000 has this option "always on" */
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			 "proxy: error setting reuseaddr option");
	    apr_socket_close(local_sock);
	    return HTTP_INTERNAL_SERVER_ERROR;
#endif /*_OSD_POSIX*/
	}

        if (apr_sockaddr_info_get(&local_addr, local_ip, APR_INET,
				  local_port, 0, r->pool) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "proxy: error creating local socket address");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

	if (apr_bind(local_sock, local_addr) != APR_SUCCESS) {
	    char buff[22];

	    apr_snprintf(buff, sizeof(buff), "%s:%d", local_ip, local_port);
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			 "proxy: error binding to ftp data socket %s", buff);
	    apr_socket_close(remote_sock);
	    return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* only need a short queue */
	apr_listen(local_sock, 2);
    }


    /*
     * V: Set The Headers
     * -------------------
     *
     * Get the size of the request, set up the environment for HTTP.
     */

    /* set request; "path" holds last path component */
    len = decodeenc(path);

    /* TM - if len == 0 then it must be a directory (you can't RETR nothing) */

    if (len == 0) {
	parms = "d";
    }
    else {
	bb = apr_brigade_create(p);
	buf = apr_pstrcat(p, "SIZE ", path, CRLF, NULL);
	e = apr_bucket_pool_create(buf, strlen(buf), p);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	e = apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(bb, e);
	ap_pass_brigade(origin->output_filters, bb);
	apr_brigade_destroy(bb);
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "FTP: SIZE %s", path);
	i = ftp_getrc_msg(origin, buffer, sizeof buffer);
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "FTP: returned status %d with response %s", i, buffer);
	if (i != 500) {		/* Size command not recognized */
	    if (i == 550) {	/* Not a regular file */
                ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                             "FTP: SIZE shows this is a directory");
		parms = "d";
		bb = apr_brigade_create(p);
		buf = apr_pstrcat(p, "CWD ", path, CRLF, NULL);
		e = apr_bucket_pool_create(buf, strlen(buf), p);
		APR_BRIGADE_INSERT_TAIL(bb, e);
		e = apr_bucket_flush_create();
		APR_BRIGADE_INSERT_TAIL(bb, e);
		ap_pass_brigade(origin->output_filters, bb);
		apr_brigade_destroy(bb);
                ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                             "FTP: CWD %s", path);
		i = ftp_getrc_msg(origin, buffer, sizeof(buffer));
		/* possible results: 250, 421, 500, 501, 502, 530, 550 */
		/* 250 Requested file action okay, completed. */
		/* 421 Service not available, closing control connection. */
		/* 500 Syntax error, command unrecognized. */
		/* 501 Syntax error in parameters or arguments. */
		/* 502 Command not implemented. */
		/* 530 Not logged in. */
		/* 550 Requested action not taken. */
                ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                             "FTP: returned status %d", i);
		if (i == -1) {
		    return ap_proxyerror(r, HTTP_BAD_GATEWAY,
					 "Error reading from remote server");
		}
		if (i == 550) {
		    return ap_proxyerror(r, HTTP_NOT_FOUND, buffer);
		}
		if (i != 250) {
		    return ap_proxyerror(r, HTTP_BAD_GATEWAY, buffer);
		}
		path = "";
		len = 0;
	    }
	    else if (i == 213) { /* Size command ok */
		for (j = 0; j < sizeof(buffer) && apr_isdigit(buffer[j]); j++);
		buffer[j] = '\0';
		if (buffer[0] != '\0')
		    size = apr_pstrdup(p, buffer);
	    }
	}
    }

#ifdef AUTODETECT_PWD
    bb = apr_brigade_create(p);
    buf = apr_pstrcat(p, "PWD", CRLF, NULL);
    e = apr_bucket_pool_create(buf, strlen(buf), p);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    e = apr_bucket_flush_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);
    ap_pass_brigade(origin->output_filters, bb);
    apr_brigade_destroy(bb);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                 "FTP: PWD");
    /* responses: 257, 500, 501, 502, 421, 550 */
    /*   257 "<directory-name>" <commentary> */
    /*   421 Service not available, closing control connection. */
    /*   500 Syntax error, command unrecognized. */
    /*   501 Syntax error in parameters or arguments. */
    /*   502 Command not implemented. */
    /*   550 Requested action not taken. */
    i = ftp_getrc_msg(origin, buffer, sizeof(buffer));
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "FTP: PWD returned status %d", i);
    if (i == -1 || i == 421) {
	return ap_proxyerror(r, HTTP_BAD_GATEWAY,
			     "Error reading from remote server");
    }
    if (i == 550) {
	return ap_proxyerror(r, HTTP_NOT_FOUND, buffer);
    }
    if (i == 257) {
	const char *dirp = buffer;
	cwd = ap_getword_conf(r->pool, &dirp);
    }
#endif /*AUTODETECT_PWD*/

    if (parms[0] == 'd') {
		if (len != 0)
		    buf = apr_pstrcat(p, "LIST ", path, CRLF, NULL);
		else
		    buf = apr_pstrcat(p, "LIST -lag", CRLF, NULL);
		ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
					 "FTP: LIST %s", (len == 0 ? "-lag" : path));
    }
    else {
		buf = apr_pstrcat(p, "RETR ", path, CRLF, NULL);
		ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
					 "FTP: RETR %s", path);
    }
    bb = apr_brigade_create(p);
    e = apr_bucket_pool_create(buf, strlen(buf), p);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    e = apr_bucket_flush_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);
    ap_pass_brigade(origin->output_filters, bb);
    apr_brigade_destroy(bb);
    /* RETR: 110, 125, 150, 226, 250, 421, 425, 426, 450, 451, 500, 501, 530, 550
     * NLST: 125, 150, 226, 250, 421, 425, 426, 450, 451, 500, 501, 502, 530 */
    /*   110 Restart marker reply. */
    /*   125 Data connection already open; transfer starting. */
    /*   150 File status okay; about to open data connection. */
    /*   226 Closing data connection. */
    /*   250 Requested file action okay, completed. */
    /*   421 Service not available, closing control connection. */
    /*   425 Can't open data connection. */
    /*   426 Connection closed; transfer aborted. */
    /*   450 Requested file action not taken. */
    /*   451 Requested action aborted. Local error in processing. */
    /*   500 Syntax error, command unrecognized. */
    /*   501 Syntax error in parameters or arguments. */
    /*   530 Not logged in. */
    /*   550 Requested action not taken. */
    rc = ftp_getrc_msg(origin, buffer, sizeof(buffer));
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                 "FTP: returned status %d", rc);
    if (rc == -1) {
	return ap_proxyerror(r, HTTP_BAD_GATEWAY,
			     "Error reading from remote server");
    }
    if (rc == 550) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "FTP: RETR failed, trying LIST instead");
	parms = "d";
	bb = apr_brigade_create(p);
	buf = apr_pstrcat(p, "CWD ", path, CRLF, NULL);
	e = apr_bucket_pool_create(buf, strlen(buf), p);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	e = apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(bb, e);
	ap_pass_brigade(origin->output_filters, bb);
	apr_brigade_destroy(bb);
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                 "FTP: CWD %s", path);
	/* possible results: 250, 421, 500, 501, 502, 530, 550 */
	/* 250 Requested file action okay, completed. */
	/* 421 Service not available, closing control connection. */
	/* 500 Syntax error, command unrecognized. */
	/* 501 Syntax error in parameters or arguments. */
	/* 502 Command not implemented. */
	/* 530 Not logged in. */
	/* 550 Requested action not taken. */
	rc = ftp_getrc_msg(origin, buffer, sizeof(buffer));
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "FTP: returned status %d", rc);
	if (rc == -1) {
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY,
				 "Error reading from remote server");
	}
	if (rc == 550) {
	    return ap_proxyerror(r, HTTP_NOT_FOUND, buffer);
	}
	if (rc != 250) {
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY, buffer);
	}

#ifdef AUTODETECT_PWD
	bb = apr_brigade_create(p);
	buf = apr_pstrcat(p, "PWD ", CRLF, NULL);
	e = apr_bucket_pool_create(buf, strlen(buf), p);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	e = apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(bb, e);
	ap_pass_brigade(origin->output_filters, bb);
	apr_brigade_destroy(bb);
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "FTP: PWD");
/* responses: 257, 500, 501, 502, 421, 550 */
	/* 257 "<directory-name>" <commentary> */
	/* 421 Service not available, closing control connection. */
	/* 500 Syntax error, command unrecognized. */
	/* 501 Syntax error in parameters or arguments. */
	/* 502 Command not implemented. */
	/* 550 Requested action not taken. */
	i = ftp_getrc_msg(origin, buffer, sizeof(buffer));
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "FTP: PWD returned status %d", i);
	if (i == -1 || i == 421) {
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY,
				 "Error reading from remote server");
	}
	if (i == 550) {
	    return ap_proxyerror(r, HTTP_NOT_FOUND, buffer);
	}
	if (i == 257) {
	    const char *dirp = buffer;
	    cwd = ap_getword_conf(r->pool, &dirp);
	}
#endif /*AUTODETECT_PWD*/

	bb = apr_brigade_create(p);
	buf = apr_pstrcat(p, "LIST -lag", CRLF, NULL);
	e = apr_bucket_pool_create(buf, strlen(buf), p);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	e = apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(bb, e);
	ap_pass_brigade(origin->output_filters, bb);
	apr_brigade_destroy(bb);
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "FTP: LIST -lag");
	rc = ftp_getrc_msg(origin, buffer, sizeof(buffer));
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "FTP: returned status %d", rc);
	if (rc == -1)
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY,
				 "Error reading from remote server");
    }
    if (rc != 125 && rc != 150 && rc != 226 && rc != 250) {
	return ap_proxyerror(r, HTTP_BAD_GATEWAY, buffer);
    }

    r->status = HTTP_OK;
    r->status_line = "200 OK";

    apr_rfc822_date(dates, r->request_time);
    apr_table_setn(r->headers_out, "Date", dates);
    apr_table_setn(r->headers_out, "Server", ap_get_server_version());

    if (parms[0] == 'd')
		apr_table_setn(r->headers_out, "Content-Type", "text/html");
    else {
	if (r->content_type != NULL) {
	    apr_table_setn(r->headers_out, "Content-Type", r->content_type);
	    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
			 "FTP: Content-Type set to %s", r->content_type);
	}
	else {
	    apr_table_setn(r->headers_out, "Content-Type", ap_default_type(r));
	}
	if (parms[0] != 'a' && size != NULL) {
	    /* We "trust" the ftp server to really serve (size) bytes... */
	    apr_table_setn(r->headers_out, "Content-Length", size);
		ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
		 "FTP: Content-Length set to %s", size);
	}
    }
    if (r->content_encoding != NULL && r->content_encoding[0] != '\0') {
		ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
		 "FTP: Content-Encoding set to %s", r->content_encoding);
	apr_table_setn(r->headers_out, "Content-Encoding", r->content_encoding);
    }

    /* wait for connection */
    if (!pasvmode) {
        for(;;)
        {
            switch(apr_accept(&remote_sock, local_sock, r->pool))
            {
            case APR_EINTR:
                continue;
            case APR_SUCCESS:
                break;
            default:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "proxy: failed to accept data connection");
                apr_socket_close(local_sock);
                return HTTP_BAD_GATEWAY;
            }
        }
    }

    /* the transfer socket is now open, create a new connection */
    remote = ap_new_connection(p, r->server, remote_sock, r->connection->id);
    if (!remote) {
	/* the peer reset the connection already; ap_new_connection() 
	 * closed the socket */
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: an error occurred creating a new connection");
	apr_socket_close(remote_sock);
	apr_socket_close(local_sock);
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* set up the connection filters */
    ap_proxy_pre_http_connection(remote);


    /*
     * VI: Receive the Response
     * ------------------------
     *
     * Get response from the remote ftp socket, and pass it up the
     * filter chain.
     */

    /* send response */
    r->sent_bodyct = 1;

   if (parms[0] == 'd') {
	/* insert directory filter */
	ap_add_output_filter("PROXY_SEND_DIR", NULL, r, r->connection);
   }

    /* send body */
    if (!r->header_only) {

	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: FTP start body send");

	/* read the body, pass it to the output filters */
	bb = apr_brigade_create(p);
	while (ap_get_brigade(remote->input_filters, bb, AP_MODE_BLOCKING) == APR_SUCCESS) {
	    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
		ap_pass_brigade(r->output_filters, bb);
		break;
	    }
	    ap_pass_brigade(r->output_filters, bb);
	    apr_brigade_destroy(bb);
	    bb = apr_brigade_create(p);
	}
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: FTP end body send");


    }
    else {

	/* abort the transfer */
	bb = apr_brigade_create(p);
	buf = apr_pstrcat(p, "ABOR", CRLF, NULL);
	e = apr_bucket_pool_create(buf, strlen(buf), p);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	e = apr_bucket_flush_create();
	APR_BRIGADE_INSERT_TAIL(bb, e);
	ap_pass_brigade(origin->output_filters, bb);
	apr_brigade_destroy(bb);
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "FTP: ABOR");
	/* responses: 225, 226, 421, 500, 501, 502 */
	/*   225 Data connection open; no transfer in progress. */
	/*   226 Closing data connection. */
	/*   421 Service not available, closing control connection. */
	/*   500 Syntax error, command unrecognized. */
	/*   501 Syntax error in parameters or arguments. */
	/*   502 Command not implemented. */
	i = ftp_getrc_msg(origin, buffer, sizeof(buffer));
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
		     "FTP: returned status %d", i);
    }


    /*
     * VII: Clean Up
     * -------------
     *
     * If there are no KeepAlives, or if the connection has been signalled
     * to close, close the socket and clean up
     */

    /* finish */
    bb = apr_brigade_create(p);
    buf = apr_pstrcat(p, "QUIT", CRLF, NULL);
    e = apr_bucket_pool_create(buf, strlen(buf), p);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    e = apr_bucket_flush_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);
    ap_pass_brigade(origin->output_filters, bb);
    apr_brigade_destroy(bb);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                 "FTP: QUIT");
    /* responses: 221, 500 */
    /*   221 Service closing control connection. */
    /*   500 Syntax error, command unrecognized. */
    i = ftp_getrc_msg(origin, buffer, sizeof(buffer));
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                 "FTP: QUIT: status %d", i);

    return OK;
}
