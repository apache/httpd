/* ====================================================================
 * Copyright (c) 1996-1998 The Apache Group.  All rights reserved.
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

/* FTP routines for Apache proxy */

#include "mod_proxy.h"
#include "http_main.h"
#include "http_log.h"

DEF_Explain

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
	if (ch == '%' && isxdigit(x[i + 1]) && isxdigit(x[i + 2])) {
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
    int i, ch;

    for (i = 0; x[i] != '\0'; i++) {
	ch = x[i];
	if (ch == '%' && isxdigit(x[i + 1]) && isxdigit(x[i + 2])) {
	    ch = ap_proxy_hex2c(&x[i + 1]);
	    i += 2;
	}
#ifndef CHARSET_EBCDIC
	if (ch == '\015' || ch == '\012' || (ch & 0x80))
#else /*CHARSET_EBCDIC*/
	if (ch == '\r' || ch == '\n' || (os_toascii[ch] & 0x80))
#endif /*CHARSET_EBCDIC*/
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
    pool *p = r->pool;
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
	parms = ap_proxy_canonenc(p, strp, strlen(strp), enc_parm, r->proxyreq);
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

    if (!r->proxyreq && r->args != NULL) {
	if (strp != NULL) {
	    strp = ap_proxy_canonenc(p, r->args, strlen(r->args), enc_parm, 1);
	    if (strp == NULL)
		return HTTP_BAD_REQUEST;
	    parms = ap_pstrcat(p, parms, "?", strp, NULL);
	}
	else {
	    strp = ap_proxy_canonenc(p, r->args, strlen(r->args), enc_fpath, 1);
	    if (strp == NULL)
		return HTTP_BAD_REQUEST;
	    path = ap_pstrcat(p, path, "?", strp, NULL);
	}
	r->args = NULL;
    }

/* now, rebuild URL */

    if (port != DEFAULT_FTP_PORT)
	ap_snprintf(sport, sizeof(sport), ":%d", port);
    else
	sport[0] = '\0';

    r->filename = ap_pstrcat(p, "proxy:ftp://", (user != NULL) ? user : "",
			       (password != NULL) ? ":" : "",
			       (password != NULL) ? password : "",
		          (user != NULL) ? "@" : "", host, sport, "/", path,
			       (parms[0] != '\0') ? ";" : "", parms, NULL);

    return OK;
}

/*
 * Returns the ftp status code;
 *  or -1 on I/O error, 0 on data error
 */
static int ftp_getrc(BUFF *f)
{
    int len, status;
    char linebuff[100], buff[5];

    len = ap_bgets(linebuff, sizeof linebuff, f);
    if (len == -1)
	return -1;
/* check format */
    if (len < 5 || !ap_isdigit(linebuff[0]) || !ap_isdigit(linebuff[1]) ||
	!ap_isdigit(linebuff[2]) || (linebuff[3] != ' ' && linebuff[3] != '-'))
	status = 0;
    else
	status = 100 * linebuff[0] + 10 * linebuff[1] + linebuff[2] - 111 * '0';

    if (linebuff[len - 1] != '\n') {
	(void)ap_bskiplf(f);
    }

/* skip continuation lines */
    if (linebuff[3] == '-') {
	memcpy(buff, linebuff, 3);
	buff[3] = ' ';
	do {
	    len = ap_bgets(linebuff, sizeof linebuff, f);
	    if (len == -1)
		return -1;
	    if (linebuff[len - 1] != '\n') {
		(void)ap_bskiplf(f);
	    }
	} while (memcmp(linebuff, buff, 4) != 0);
    }

    return status;
}

/*
 * Like ftp_getrc but returns both the ftp status code and 
 * remembers the response message in the supplied buffer
 */
static int ftp_getrc_msg(BUFF *f, char *msgbuf, int msglen)
{
    int len, status;
    char linebuff[100], buff[5];
    char *mb = msgbuf,
	 *me = &msgbuf[msglen];

    len = ap_bgets(linebuff, sizeof linebuff, f);
    if (len == -1)
	return -1;
    if (len < 5 || !ap_isdigit(linebuff[0]) || !ap_isdigit(linebuff[1]) ||
	!ap_isdigit(linebuff[2]) || (linebuff[3] != ' ' && linebuff[3] != '-'))
	status = 0;
    else
	status = 100 * linebuff[0] + 10 * linebuff[1] + linebuff[2] - 111 * '0';

    mb = ap_cpystrn(mb, linebuff+4, me - mb);

    if (linebuff[len - 1] != '\n')
	(void)ap_bskiplf(f);

    if (linebuff[3] == '-') {
	memcpy(buff, linebuff, 3);
	buff[3] = ' ';
	do {
	    len = ap_bgets(linebuff, sizeof linebuff, f);
	    if (len == -1)
		return -1;
	    if (linebuff[len - 1] != '\n') {
		(void)ap_bskiplf(f);
	    }
	    mb = ap_cpystrn(mb, linebuff+4, me - mb);
	} while (memcmp(linebuff, buff, 4) != 0);
    }
    return status;
}

static long int send_dir(BUFF *f, request_rec *r, cache_req *c, char *url)
{
    char buf[IOBUFSIZE];
    char buf2[IOBUFSIZE];
    char *filename;
    char *tempurl;
    int searchidx = 0;
    char *searchptr = NULL;
    int firstfile = 1;
    char urlptr[HUGE_STRING_LEN];
    unsigned long total_bytes_sent = 0;
    register int n, o, w;
    int hostlen;
    conn_rec *con = r->connection;
    char *dir, *path, *reldir, *site, *psite;

    tempurl = ap_pstrdup(r->pool, url);

    (void)decodeenc(tempurl);

    /* Determine length of "scheme://site" prefix */
    for (hostlen=0; tempurl[hostlen]!='/'; ++hostlen)
	continue;
    if (tempurl[hostlen] == '/' && tempurl[hostlen+1] == '/') {
	for (hostlen+=2; tempurl[hostlen]!='/' && tempurl[hostlen]!='?'; ++hostlen)
	    continue;
    } else {
	hostlen = 0;
    }

    /* Save "scheme://site" prefix */
    site = psite = ap_pstrndup(r->pool, tempurl, hostlen);

    if ((n = strcspn(tempurl, "@")) != strlen(tempurl) && n < hostlen) {    /* hide user/passwd */
	memmove(tempurl + (n - 5), tempurl, 6);
	tempurl += n - 5;	/* leave room for ftp:// */
	hostlen -= (n-5);

	/* Save "scheme://site" prefix without user/password */
	site = ap_pstrndup(r->pool, tempurl, hostlen);
    }

    /* Copy path, strip (all except the last) trailing slashes */
    path = dir = ap_pstrcat(r->pool, tempurl+hostlen, "/", NULL);
    while ((n = strlen(path)) > 1 && path[n-1] == '/' && path[n-2] == '/')
	path[n-1] = '\0';

    /* print "ftp://host/" */
    ap_snprintf(buf, sizeof(buf), "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
		"<HTML><HEAD><TITLE>%s</TITLE>\n"
		"<BASE HREF=\"%s%s\"></HEAD>\n"
		"<BODY><H2>Directory of "
		"<A HREF=\"/\">%s</A>/",
		tempurl, psite, path, site);
    total_bytes_sent += ap_proxy_bputs2(buf, con->client, c);

    while ((dir = strchr(dir+1, '/')) != NULL)
    {
	*dir = '\0';
	if ((reldir = strrchr(path+1, '/'))==NULL)
	    reldir = path+1;
	else
	    ++reldir;
	/* print "path/" component */
	ap_snprintf(buf, sizeof(buf), "<A HREF=\"/%s/\">%s</A>/", path+1, reldir);
	total_bytes_sent += ap_proxy_bputs2(buf, con->client, c);
	total_bytes_sent += strlen(buf);
	*dir = '/';
    }
    ap_snprintf(buf, sizeof(buf), "</H2>\n<HR><PRE>");
    total_bytes_sent += ap_proxy_bputs2(buf, con->client, c);

    for (hostlen=0; url[hostlen]!='/'; ++hostlen)
	continue;
    if (url[hostlen] == '/' && url[hostlen+1] == '/') {
	for (hostlen+=2; url[hostlen]!='/' && url[hostlen]!='?'; ++hostlen)
	    continue;
    } else
	hostlen = 0;

    while (!con->aborted) {
	n = ap_bgets(buf, sizeof buf, f);
	if (n == -1) {		/* input error */
	    if (c != NULL)
		c = ap_proxy_cache_error(c);
	    break;
	}
	if (n == 0)
	    break;		/* EOF */
	if (buf[0] == 'l' && (filename=strstr(buf, " -> ")) != NULL) {
	    char *link_ptr = filename;

	    do
		filename--;
	    while (filename[0] != ' ');
	    *(filename++) = 0;
	    *(link_ptr++) = 0;
	    if ((n = strlen(link_ptr)) > 1 && link_ptr[n - 1] == '\n')
	      link_ptr[n - 1] = '\0';
	    ap_snprintf(urlptr, sizeof(urlptr), "%s%s%s", url+hostlen, (url[strlen(url) - 1] == '/' ? "" : "/"), filename);
	    ap_snprintf(buf2, sizeof(buf2), "%s <A HREF=\"%s\">%s %s</A>\n", buf, filename, filename, link_ptr);
	    ap_cpystrn(buf, buf2, sizeof(buf));
	    n = strlen(buf);
	}
	else if (buf[0] == 'd' || buf[0] == '-' || buf[0] == 'l' || ap_isdigit(buf[0])) {
	    if (ap_isdigit(buf[0])) {	/* handle DOS dir */
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
		ap_snprintf(buf2, sizeof(buf2), "%s <A HREF=\"%s/\">%s</A>\n",
		    buf, filename, filename);
	    }
	    else {
		ap_snprintf(buf2, sizeof(buf2), "%s <A HREF=\"%s\">%s</A>\n", buf, filename, filename);
	    }
	    ap_cpystrn(buf, buf2, sizeof(buf));
	    n = strlen(buf);
	}

	o = 0;
	total_bytes_sent += n;

	if (c != NULL && c->fp && ap_bwrite(c->fp, buf, n) != n)
	    c = ap_proxy_cache_error(c);

	while (n && !r->connection->aborted) {
	    w = ap_bwrite(con->client, &buf[o], n);
	    if (w <= 0)
		break;
	    ap_reset_timeout(r);	/* reset timeout after successfule write */
	    n -= w;
	    o += w;
	}
    }

    total_bytes_sent += ap_proxy_bputs2("</PRE><HR>\n", con->client, c);
    total_bytes_sent += ap_proxy_bputs2(ap_psignature("", r), con->client, c);
    total_bytes_sent += ap_proxy_bputs2("</BODY></HTML>\n", con->client, c);

    ap_bflush(con->client);

    return total_bytes_sent;
}

/*
 * Handles direct access of ftp:// URLs
 * Original (Non-PASV) version from
 * Troy Morrison <spiffnet@zoom.com>
 * PASV added by Chuck
 */
int ap_proxy_ftp_handler(request_rec *r, cache_req *c, char *url)
{
    char *host, *path, *strp, *user, *password, *parms;
    const char *err;
    int port, userlen, i, j, len, sock, dsock, rc, nocache;
    int passlen = 0;
    int csd = 0;
    struct sockaddr_in server;
    struct hostent server_hp;
    struct in_addr destaddr;
    table *resp_hdrs;
    BUFF *f;
    BUFF *data = NULL;
    pool *p = r->pool;
    int one = 1;
    const long int zero = 0L;
    NET_SIZE_T clen;
    struct tbl_do_args tdo;

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    struct noproxy_entry *npent = (struct noproxy_entry *) conf->noproxies->elts;
    struct nocache_entry *ncent = (struct nocache_entry *) conf->nocaches->elts;

/* stuff for PASV mode */
    unsigned int presult, h0, h1, h2, h3, p0, p1;
    unsigned int paddr;
    unsigned short pport;
    struct sockaddr_in data_addr;
    int pasvmode = 0;
    char pasv[64];
    char *pstr;

/* stuff for responses */
    char *resp;
    int resplen;
    char *size = NULL;

/* we only support GET and HEAD */

    if (r->method_number != M_GET)
	return HTTP_NOT_IMPLEMENTED;

/* allocate a buffer for the response message */
	resplen = MAX_STRING_LEN;
	resp = (char *)ap_palloc(r->pool, resplen);

/* We break the URL into host, port, path-search */

    host = ap_pstrdup(p, url + 6);
    port = DEFAULT_FTP_PORT;
    path = strchr(host, '/');
    if (path == NULL)
	path = "";
    else
	*(path++) = '\0';

    user = password = NULL;
    nocache = 0;
    strp = strchr(host, '@');
    if (strp != NULL) {
	(*strp++) = '\0';
	user = host;
	host = strp;
/* find password */
	strp = strchr(user, ':');
	if (strp != NULL) {
	    *(strp++) = '\0';
	    password = strp;
	    passlen = decodeenc(password);
	}
	userlen = decodeenc(user);
	nocache = 1;		/* don't cache when a username is supplied */
    }
    else {
	user = "anonymous";
	userlen = 9;

	password = "apache_proxy@";
	passlen = strlen(password);
    }

    strp = strchr(host, ':');
    if (strp != NULL) {
	*(strp++) = '\0';
	if (ap_isdigit(*strp))
	    port = atoi(strp);
    }

/* check if ProxyBlock directive on this host */
    destaddr.s_addr = ap_inet_addr(host);
    for (i = 0; i < conf->noproxies->nelts; i++) {
	if ((npent[i].name != NULL && strstr(host, npent[i].name) != NULL)
	    || destaddr.s_addr == npent[i].addr.s_addr || npent[i].name[0] == '*')
	    return ap_proxyerror(r, "Connect to remote machine blocked");
    }

    Explain2("FTP: connect to %s:%d", host, port);

    parms = strchr(path, ';');
    if (parms != NULL)
	*(parms++) = '\0';

    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    err = ap_proxy_host2addr(host, &server_hp);
    if (err != NULL)
	return ap_proxyerror(r, err);	/* give up */

    sock = ap_psocket(p, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		     "proxy: error creating socket");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (conf->recv_buffer_size) {
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
		       (const char *) &conf->recv_buffer_size, sizeof(int))
	    == -1) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			 "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
	}
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &one,
		   sizeof(one)) == -1) {
#ifndef _OSD_POSIX /* BS2000 has this option "always on" */
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		     "proxy: error setting reuseaddr option: setsockopt(SO_REUSEADDR)");
	ap_pclosesocket(p, sock);
	return HTTP_INTERNAL_SERVER_ERROR;
#endif /*_OSD_POSIX*/
    }

#ifdef SINIX_D_RESOLVER_BUG
    {
	struct in_addr *ip_addr = (struct in_addr *) *server_hp.h_addr_list;

	for (; ip_addr->s_addr != 0; ++ip_addr) {
	    memcpy(&server.sin_addr, ip_addr, sizeof(struct in_addr));
	    i = ap_proxy_doconnect(sock, &server, r);
	    if (i == 0)
		break;
	}
    }
#else
    j = 0;
    while (server_hp.h_addr_list[j] != NULL) {
	memcpy(&server.sin_addr, server_hp.h_addr_list[j],
	       sizeof(struct in_addr));
	i = ap_proxy_doconnect(sock, &server, r);
	if (i == 0)
	    break;
	j++;
    }
#endif
    if (i == -1) {
	ap_pclosesocket(p, sock);
	return ap_proxyerror(r, /*HTTP_BAD_GATEWAY*/ ap_pstrcat(r->pool,
				"Could not connect to remote machine: ",
				strerror(errno), NULL));
    }

    f = ap_bcreate(p, B_RDWR | B_SOCKET);
    ap_bpushfd(f, sock, sock);
/* shouldn't we implement telnet control options here? */

#ifdef CHARSET_EBCDIC
    ap_bsetflag(f, B_ASCII2EBCDIC|B_EBCDIC2ASCII, 1);
#endif /*CHARSET_EBCDIC*/

/* possible results: 120, 220, 421 */
    ap_hard_timeout("proxy ftp", r);
    i = ftp_getrc(f);
    Explain1("FTP: returned status %d", i);
    if (i == -1) {
	ap_kill_timeout(r);
	return ap_proxyerror(r, "Error reading from remote server");
    }
    if (i != 220) {
	ap_kill_timeout(r);
	return HTTP_BAD_GATEWAY;
    }

    Explain0("FTP: connected.");

    ap_bputs("USER ", f);
    ap_bwrite(f, user, userlen);
    ap_bputs(CRLF, f);
    ap_bflush(f);			/* capture any errors */
    Explain1("FTP: USER %s", user);

/* possible results; 230, 331, 332, 421, 500, 501, 530 */
/* states: 1 - error, 2 - success; 3 - send password, 4,5 fail */
    i = ftp_getrc(f);
    Explain1("FTP: returned status %d", i);
    if (i == -1) {
	ap_kill_timeout(r);
	return ap_proxyerror(r, "Error sending to remote server");
    }
    if (i == 530) {
	ap_kill_timeout(r);
	return ap_proxyerror(r, "Not logged in");
    }
    if (i != 230 && i != 331) {
	ap_kill_timeout(r);
	return HTTP_BAD_GATEWAY;
    }

    if (i == 331) {		/* send password */
	if (password == NULL)
	    return HTTP_FORBIDDEN;
	ap_bputs("PASS ", f);
	ap_bwrite(f, password, passlen);
	ap_bputs(CRLF, f);
	ap_bflush(f);
	Explain1("FTP: PASS %s", password);
/* possible results 202, 230, 332, 421, 500, 501, 503, 530 */
	i = ftp_getrc(f);
	Explain1("FTP: returned status %d", i);
	if (i == -1) {
	    ap_kill_timeout(r);
	    return ap_proxyerror(r, "Error sending to remote server");
	}
	if (i == 332) {
	    ap_kill_timeout(r);
	    return ap_proxyerror(r, "Need account for login");
	}
	if (i == 530) {
	    ap_kill_timeout(r);
	    return ap_proxyerror(r, "Not logged in");
	}
	if (i != 230 && i != 202) {
	    ap_kill_timeout(r);
	    return HTTP_BAD_GATEWAY;
	}
    }

/* set the directory */
/* this is what we must do if we don't know the OS type of the remote
 * machine
 */
    for (;;) {
	strp = strchr(path, '/');
	if (strp == NULL)
	    break;
	*strp = '\0';

	len = decodeenc(path);
	ap_bputs("CWD ", f);
	ap_bwrite(f, path, len);
	ap_bputs(CRLF, f);
	ap_bflush(f);
	Explain1("FTP: CWD %s", path);
/* responses: 250, 421, 500, 501, 502, 530, 550 */
/* 1,3 error, 2 success, 4,5 failure */
	i = ftp_getrc(f);
	Explain1("FTP: returned status %d", i);
	if (i == -1) {
	    ap_kill_timeout(r);
	    return ap_proxyerror(r, "Error sending to remote server");
	}
	if (i == 550) {
	    ap_kill_timeout(r);
	    return HTTP_NOT_FOUND;
	}
	if (i != 250) {
	    ap_kill_timeout(r);
	    return HTTP_BAD_GATEWAY;
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
	/* TM - Added \015\012 to the end of TYPE I, otherwise it hangs the
	   connection */
	ap_bputs("TYPE I" CRLF, f);
	ap_bflush(f);
	Explain0("FTP: TYPE I");
/* responses: 200, 421, 500, 501, 504, 530 */
	i = ftp_getrc(f);
	Explain1("FTP: returned status %d", i);
	if (i == -1) {
	    ap_kill_timeout(r);
	    return ap_proxyerror(r, "Error sending to remote server");
	}
	if (i != 200 && i != 504) {
	    ap_kill_timeout(r);
	    return HTTP_BAD_GATEWAY;
	}
/* Allow not implemented */
	if (i == 504)
	    parms[0] = '\0';
    }

/* try to set up PASV data connection first */
    dsock = ap_psocket(p, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (dsock == -1) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		     "proxy: error creating PASV socket");
	ap_bclose(f);
	ap_kill_timeout(r);
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (conf->recv_buffer_size) {
	if (setsockopt(dsock, SOL_SOCKET, SO_RCVBUF,
	       (const char *) &conf->recv_buffer_size, sizeof(int)) == -1) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			 "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
	}
    }

    ap_bputs("PASV" CRLF, f);
    ap_bflush(f);
    Explain0("FTP: PASV command issued");
/* possible results: 227, 421, 500, 501, 502, 530 */
    i = ap_bgets(pasv, sizeof(pasv), f);

    if (i == -1) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, r,
		     "PASV: control connection is toast");
	ap_pclosesocket(p, dsock);
	ap_bclose(f);
	ap_kill_timeout(r);
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
	pasv[i - 1] = '\0';
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

	Explain1("FTP: returned status %d", presult);

	if (presult == 227 && pstr != NULL && (sscanf(pstr,
		 "%d,%d,%d,%d,%d,%d", &h3, &h2, &h1, &h0, &p1, &p0) == 6)) {
	    /* pardon the parens, but it makes gcc happy */
	    paddr = (((((h3 << 8) + h2) << 8) + h1) << 8) + h0;
	    pport = (p1 << 8) + p0;
	    Explain5("FTP: contacting host %d.%d.%d.%d:%d",
		     h3, h2, h1, h0, pport);
	    data_addr.sin_family = AF_INET;
	    data_addr.sin_addr.s_addr = htonl(paddr);
	    data_addr.sin_port = htons(pport);
	    i = ap_proxy_doconnect(dsock, &data_addr, r);

	    if (i == -1) {
		ap_kill_timeout(r);
		return ap_proxyerror(r, /*HTTP_BAD_GATEWAY*/ ap_pstrcat(r->pool,
				"Could not connect to remote machine: ",
				strerror(errno), NULL));
	    }
	    else {
		pasvmode = 1;
	    }
	}
	else
	    ap_pclosesocket(p, dsock);	/* and try the regular way */
    }

    if (!pasvmode) {		/* set up data connection */
	clen = sizeof(struct sockaddr_in);
	if (getsockname(sock, (struct sockaddr *) &server, &clen) < 0) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			 "proxy: error getting socket address");
	    ap_bclose(f);
	    ap_kill_timeout(r);
	    return HTTP_INTERNAL_SERVER_ERROR;
	}

	dsock = ap_psocket(p, PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (dsock == -1) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			 "proxy: error creating socket");
	    ap_bclose(f);
	    ap_kill_timeout(r);
	    return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (setsockopt(dsock, SOL_SOCKET, SO_REUSEADDR, (void *) &one,
		       sizeof(one)) == -1) {
#ifndef _OSD_POSIX /* BS2000 has this option "always on" */
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			 "proxy: error setting reuseaddr option");
	    ap_pclosesocket(p, dsock);
	    ap_bclose(f);
	    ap_kill_timeout(r);
	    return HTTP_INTERNAL_SERVER_ERROR;
#endif /*_OSD_POSIX*/
	}

	if (bind(dsock, (struct sockaddr *) &server,
		 sizeof(struct sockaddr_in)) == -1) {
	    char buff[22];

	    ap_snprintf(buff, sizeof(buff), "%s:%d", inet_ntoa(server.sin_addr), server.sin_port);
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			 "proxy: error binding to ftp data socket %s", buff);
	    ap_bclose(f);
	    ap_pclosesocket(p, dsock);
	    return HTTP_INTERNAL_SERVER_ERROR;
	}
	listen(dsock, 2);	/* only need a short queue */
    }

/* set request */
    len = decodeenc(path);

    /* TM - if len == 0 then it must be a directory (you can't RETR nothing) */

    if (len == 0) {
	parms = "d";
    }
    else {
	ap_bputs("SIZE ", f);
	ap_bwrite(f, path, len);
	ap_bputs(CRLF, f);
	ap_bflush(f);
	Explain1("FTP: SIZE %s", path);
	i = ftp_getrc_msg(f, resp, resplen);
	Explain2("FTP: returned status %d with response %s", i, resp);
	if (i != 500) {		/* Size command not recognized */
	    if (i == 550) {	/* Not a regular file */
		Explain0("FTP: SIZE shows this is a directory");
		parms = "d";
		ap_bputs("CWD ", f);
		ap_bwrite(f, path, len);
		ap_bputs(CRLF, f);
		ap_bflush(f);
		Explain1("FTP: CWD %s", path);
		i = ftp_getrc(f);
		Explain1("FTP: returned status %d", i);
		if (i == -1) {
		    ap_kill_timeout(r);
		    return ap_proxyerror(r, "Error sending to remote server");
		}
		if (i == 550) {
		    ap_kill_timeout(r);
		    return HTTP_NOT_FOUND;
		}
		if (i != 250) {
		    ap_kill_timeout(r);
		    return HTTP_BAD_GATEWAY;
		}
		path = "";
		len = 0;
	    }
	    else if (i == 213) { /* Size command ok */
		for (j = 0; j < resplen && ap_isdigit(resp[j]); j++)
			;
		resp[j] = '\0';
		if (resp[0] != '\0')
		    size = ap_pstrdup(p, resp);
	    }
	}
    }

    if (parms[0] == 'd') {
	if (len != 0)
	    ap_bputs("LIST ", f);
	else
	    ap_bputs("LIST -lag", f);
	Explain1("FTP: LIST %s", (len == 0 ? "" : path));
    }
    else {
	ap_bputs("RETR ", f);
	Explain1("FTP: RETR %s", path);
    }
    ap_bwrite(f, path, len);
    ap_bputs(CRLF, f);
    ap_bflush(f);
/* RETR: 110, 125, 150, 226, 250, 421, 425, 426, 450, 451, 500, 501, 530, 550
   NLST: 125, 150, 226, 250, 421, 425, 426, 450, 451, 500, 501, 502, 530 */
    rc = ftp_getrc(f);
    Explain1("FTP: returned status %d", rc);
    if (rc == -1) {
	ap_kill_timeout(r);
	return ap_proxyerror(r, "Error sending to remote server");
    }
    if (rc == 550) {
	Explain0("FTP: RETR failed, trying LIST instead");
	parms = "d";
	ap_bputs("CWD ", f);
	ap_bwrite(f, path, len);
	ap_bputs(CRLF, f);
	ap_bflush(f);
	Explain1("FTP: CWD %s", path);
	rc = ftp_getrc(f);
	Explain1("FTP: returned status %d", rc);
	if (rc == -1) {
	    ap_kill_timeout(r);
	    return ap_proxyerror(r, "Error sending to remote server");
	}
	if (rc == 550) {
	    ap_kill_timeout(r);
	    return HTTP_NOT_FOUND;
	}
	if (rc != 250) {
	    ap_kill_timeout(r);
	    return HTTP_BAD_GATEWAY;
	}

	ap_bputs("LIST -lag" CRLF, f);
	ap_bflush(f);
	Explain0("FTP: LIST -lag");
	rc = ftp_getrc(f);
	Explain1("FTP: returned status %d", rc);
	if (rc == -1)
	    return ap_proxyerror(r, "Error sending to remote server");
    }
    ap_kill_timeout(r);
    if (rc != 125 && rc != 150 && rc != 226 && rc != 250)
	return HTTP_BAD_GATEWAY;

    r->status = HTTP_OK;
    r->status_line = "200 OK";

    resp_hdrs = ap_make_table(p, 2);
    c->hdrs = resp_hdrs;

    if (parms[0] == 'd')
	ap_table_set(resp_hdrs, "Content-Type", "text/html");
    else {
	if (r->content_type != NULL) {
	    ap_table_set(resp_hdrs, "Content-Type", r->content_type);
	    Explain1("FTP: Content-Type set to %s", r->content_type);
	}
	else {
	    ap_table_set(resp_hdrs, "Content-Type", "text/plain");
	}
	if (parms[0] != 'a' && size != NULL) {
	    ap_table_set(resp_hdrs, "Content-Length", size);
	    Explain1("FTP: Content-Length set to %s", size);
	}
    }

/* check if NoCache directive on this host */
    for (i = 0; i < conf->nocaches->nelts; i++) {
	if ((ncent[i].name != NULL && strstr(host, ncent[i].name) != NULL)
	    || destaddr.s_addr == ncent[i].addr.s_addr || ncent[i].name[0] == '*')
	    nocache = 1;
    }

    i = ap_proxy_cache_update(c, resp_hdrs, 0, nocache);

    if (i != DECLINED) {
	ap_pclosesocket(p, dsock);
	ap_bclose(f);
	return i;
    }

    if (!pasvmode) {		/* wait for connection */
	ap_hard_timeout("proxy ftp data connect", r);
	clen = sizeof(struct sockaddr_in);
	do
	    csd = accept(dsock, (struct sockaddr *) &server, &clen);
	while (csd == -1 && errno == EINTR);
	if (csd == -1) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			 "proxy: failed to accept data connection");
	    ap_pclosesocket(p, dsock);
	    ap_bclose(f);
	    ap_kill_timeout(r);
	    if (c != NULL)
		c = ap_proxy_cache_error(c);
	    return HTTP_BAD_GATEWAY;
	}
	ap_note_cleanups_for_socket(p, csd);
	data = ap_bcreate(p, B_RDWR | B_SOCKET);
	ap_bpushfd(data, csd, -1);
	ap_kill_timeout(r);
    }
    else {
	data = ap_bcreate(p, B_RDWR | B_SOCKET);
	ap_bpushfd(data, dsock, dsock);
    }

#ifdef CHARSET_EBCDIC
/*    bsetflag(data, B_ASCII2EBCDIC|B_EBCDIC2ASCII, 0);*/
#endif /*CHARSET_EBCDIC*/

    ap_hard_timeout("proxy receive", r);
/* send response */
/* write status line */
    if (!r->assbackwards)
	ap_rvputs(r, "HTTP/1.0 ", r->status_line, CRLF, NULL);
    if (c != NULL && c->fp != NULL &&
	ap_bvputs(c->fp, "HTTP/1.0 ", r->status_line, CRLF, NULL) == -1)
	c = ap_proxy_cache_error(c);

/* send headers */
    tdo.req = r;
    tdo.cache = c;
    ap_table_do(ap_proxy_send_hdr_line, &tdo, resp_hdrs, NULL);

    if (!r->assbackwards)
	ap_rputs(CRLF, r);
    if (c != NULL && c->fp != NULL && ap_bputs(CRLF, c->fp) == -1)
	c = ap_proxy_cache_error(c);

    ap_bsetopt(r->connection->client, BO_BYTECT, &zero);
    r->sent_bodyct = 1;
/* send body */
    if (!r->header_only) {
	if (parms[0] != 'd') {
/* we need to set this for ap_proxy_send_fb()... */
	    if (c != NULL)
		c->cache_completion = 0;
	    ap_proxy_send_fb(data, r, c);
	} else
	    send_dir(data, r, c, url);

	if (rc == 125 || rc == 150)
	    rc = ftp_getrc(f);
	if (rc != 226 && rc != 250)
	    c = ap_proxy_cache_error(c);
    }
    else {
/* abort the transfer */
	ap_bputs("ABOR" CRLF, f);
	ap_bflush(f);
	if (!pasvmode)
	    ap_bclose(data);
	Explain0("FTP: ABOR");
/* responses: 225, 226, 421, 500, 501, 502 */
	i = ftp_getrc(f);
	Explain1("FTP: returned status %d", i);
    }

    ap_kill_timeout(r);
    ap_proxy_cache_tidy(c);

/* finish */
    ap_bputs("QUIT" CRLF, f);
    ap_bflush(f);
    Explain0("FTP: QUIT");
/* responses: 221, 500 */

    if (pasvmode)
	ap_bclose(data);
    ap_bclose(f);

    ap_rflush(r);	/* flush before garbage collection */

    ap_proxy_garbage_coll(r);

    return OK;
}
