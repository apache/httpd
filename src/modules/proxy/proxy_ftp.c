/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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
#include "http_main.h"
#include "http_log.h"
#include "http_core.h"

#define AUTODETECT_PWD

/*
 * Decodes a '%' escaped string, and returns the number of characters
 */
static int decodeenc(char *x)
{
    int i, j, ch;

    if (x[0] == '\0')
        return 0;               /* special case for no characters */
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
    int i, ch;

    for (i = 0; x[i] != '\0'; i++) {
        ch = x[i];
        if (ch == '%' && ap_isxdigit(x[i + 1]) && ap_isxdigit(x[i + 2])) {
            ch = ap_proxy_hex2c(&x[i + 1]);
            i += 2;
        }
        if (ch == CR || ch == LF || (OS_ASC(ch) & 0x80))
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

    if (r->proxyreq == NOT_PROXY && r->args != NULL) {
        if (strp != NULL) {
            strp = ap_proxy_canonenc(p, r->args, strlen(r->args), enc_parm, STD_PROXY);
            if (strp == NULL)
                return HTTP_BAD_REQUEST;
            parms = ap_pstrcat(p, parms, "?", strp, NULL);
        }
        else {
            strp = ap_proxy_canonenc(p, r->args, strlen(r->args), enc_fpath, STD_PROXY);
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
static int ftp_getrc(BUFF *ctrl)
{
    int len, status;
    char linebuff[100], buff[5];

    len = ap_bgets(linebuff, sizeof linebuff, ctrl);
    if (len == -1)
        return -1;
/* check format */
    if (len < 5 || !ap_isdigit(linebuff[0]) || !ap_isdigit(linebuff[1]) ||
     !ap_isdigit(linebuff[2]) || (linebuff[3] != ' ' && linebuff[3] != '-'))
        status = 0;
    else
        status = 100 * linebuff[0] + 10 * linebuff[1] + linebuff[2] - 111 * '0';

    if (linebuff[len - 1] != '\n') {
        (void)ap_bskiplf(ctrl);
    }

/* skip continuation lines */
    if (linebuff[3] == '-') {
        memcpy(buff, linebuff, 3);
        buff[3] = ' ';
        do {
            len = ap_bgets(linebuff, sizeof linebuff, ctrl);
            if (len == -1)
                return -1;
            if (linebuff[len - 1] != '\n') {
                (void)ap_bskiplf(ctrl);
            }
        } while (memcmp(linebuff, buff, 4) != 0);
    }

    return status;
}

/*
 * Like ftp_getrc but returns both the ftp status code and
 * remembers the response message in the supplied buffer
 */
static int ftp_getrc_msg(BUFF *ctrl, char *msgbuf, int msglen)
{
    int len, status;
    char linebuff[100], buff[5];
    char *mb = msgbuf, *me = &msgbuf[msglen];

    len = ap_bgets(linebuff, sizeof linebuff, ctrl);
    if (len == -1)
        return -1;
    if (len < 5 || !ap_isdigit(linebuff[0]) || !ap_isdigit(linebuff[1]) ||
     !ap_isdigit(linebuff[2]) || (linebuff[3] != ' ' && linebuff[3] != '-'))
        status = 0;
    else
        status = 100 * linebuff[0] + 10 * linebuff[1] + linebuff[2] - 111 * '0';

    mb = ap_cpystrn(mb, linebuff + 4, me - mb);

    if (linebuff[len - 1] != '\n')
        (void)ap_bskiplf(ctrl);

    if (linebuff[3] == '-') {
        memcpy(buff, linebuff, 3);
        buff[3] = ' ';
        do {
            len = ap_bgets(linebuff, sizeof linebuff, ctrl);
            if (len == -1)
                return -1;
            if (linebuff[len - 1] != '\n') {
                (void)ap_bskiplf(ctrl);
            }
            mb = ap_cpystrn(mb, linebuff + 4, me - mb);
        } while (memcmp(linebuff, buff, 4) != 0);
    }
    return status;
}

static long int send_dir(BUFF *data, request_rec *r, cache_req *c, char *cwd)
{
    char *buf, *buf2;
    size_t buf_size;
    char *filename;
    int searchidx = 0;
    char *searchptr = NULL;
    int firstfile = 1;
    unsigned long total_bytes_sent = 0;
    register int n;
    conn_rec *con = r->connection;
    pool *p = r->pool;
    char *dir, *path, *reldir, *site, *type = NULL;
    char *basedir = "";         /* By default, path is relative to the $HOME
                                 * dir */

    /* create default sized buffers for the stuff below */
    buf_size = IOBUFSIZE;
    buf = ap_palloc(r->pool, buf_size);
    buf2 = ap_palloc(r->pool, buf_size);

    /* Save "scheme://site" prefix without password */
    site = ap_unparse_uri_components(p, &r->parsed_uri, UNP_OMITPASSWORD | UNP_OMITPATHINFO);
    /* ... and path without query args */
    path = ap_unparse_uri_components(p, &r->parsed_uri, UNP_OMITSITEPART | UNP_OMITQUERY);

    /* If path began with /%2f, change the basedir */
    if (strncasecmp(path, "/%2f", 4) == 0) {
        basedir = "/%2f";
    }

    /* Strip off a type qualifier. It is ignored for dir listings */
    if ((type = strstr(path, ";type=")) != NULL)
        *type++ = '\0';

    (void)decodeenc(path);

    while (path[1] == '/')      /* collapse multiple leading slashes to one */
        ++path;

    /* Copy path, strip (all except the last) trailing slashes */
    /* (the trailing slash is needed for the dir component loop below) */
    path = dir = ap_pstrcat(r->pool, path, "/", NULL);
    for (n = strlen(path); n > 1 && path[n - 1] == '/' && path[n - 2] == '/'; --n)
        path[n - 1] = '\0';

    /* print "ftp://host/" */
    n = ap_snprintf(buf, buf_size, DOCTYPE_HTML_3_2
                    "<html><head><title>%s%s%s</title>\n"
                    "<base href=\"%s%s%s\"></head>\n"
                    "<body><h2>Directory of "
                    "<a href=\"/\">%s</a>/",
                    site, basedir, ap_escape_html(p, path),
                    site, basedir, ap_escape_uri(p, path),
                    site);
    total_bytes_sent += ap_proxy_bputs2(buf, con->client, c);

    /* Add a link to the root directory (if %2f hack was used) */
    if (basedir[0] != '\0') {
        total_bytes_sent += ap_proxy_bputs2("<a href=\"/%2f/\">%2f</a>/", con->client, c);
    }

    for (dir = path + 1; (dir = strchr(dir, '/')) != NULL;) {
        *dir = '\0';
        if ((reldir = strrchr(path + 1, '/')) == NULL) {
            reldir = path + 1;
        }
        else
            ++reldir;
        /* print "path/" component */
        ap_snprintf(buf, buf_size, "<a href=\"%s%s/\">%s</a>/",
                    basedir,
                    ap_escape_uri(p, path),
                    ap_escape_html(p, reldir));
        total_bytes_sent += ap_proxy_bputs2(buf, con->client, c);
        *dir = '/';
        while (*dir == '/')
            ++dir;
    }

    /* If the caller has determined the current directory, and it differs */
    /* from what the client requested, then show the real name */
    if (cwd == NULL || strncmp(cwd, path, strlen(cwd)) == 0) {
        ap_snprintf(buf, buf_size, "</h2>\n<hr /><pre>");
    }
    else {
        ap_snprintf(buf, buf_size, "</h2>\n(%s)\n<hr /><pre>",
                    ap_escape_html(p, cwd));
    }
    total_bytes_sent += ap_proxy_bputs2(buf, con->client, c);

    while (!con->aborted) {
        n = ap_bgets(buf, buf_size, data);
        if (n == -1) {          /* input error */
            if (c != NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, c->req,
                              "proxy: error reading from %s", c->url);
                c = ap_proxy_cache_error(c);
            }
            break;
        }
        if (n == 0)
            break;              /* EOF */

        if (buf[n - 1] == '\n') /* strip trailing '\n' */
            buf[--n] = '\0';
        if (buf[n - 1] == '\r') /* strip trailing '\r' if present */
            buf[--n] = '\0';

        /* Handle unix-style symbolic link */
        if (buf[0] == 'l' && (filename = strstr(buf, " -> ")) != NULL) {
            char *link_ptr = filename;

            do {
                filename--;
            } while (filename[0] != ' ' && filename > buf);
            if (filename != buf)
                *(filename++) = '\0';
            *(link_ptr++) = '\0';
            ap_snprintf(buf2, buf_size, "%s <a href=\"%s\">%s %s</a>\n",
                        ap_escape_html(p, buf),
                        ap_escape_uri(p, filename),
                        ap_escape_html(p, filename),
                        ap_escape_html(p, link_ptr));
            ap_cpystrn(buf, buf2, buf_size);
            n = strlen(buf);
        }
        /* Handle unix style or DOS style directory  */
        else if (buf[0] == 'd' || buf[0] == '-' || buf[0] == 'l' || ap_isdigit(buf[0])) {
            if (ap_isdigit(buf[0])) {   /* handle DOS dir */
                searchptr = strchr(buf, '<');
                if (searchptr != NULL)
                    *searchptr = '[';
                searchptr = strchr(buf, '>');
                if (searchptr != NULL)
                    *searchptr = ']';
            }

            filename = strrchr(buf, ' ');
            *(filename++) = 0;

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

            /* Special handling for '.' and '..': append slash to link */
            if (!strcmp(filename, ".") || !strcmp(filename, "..") || buf[0] == 'd') {
                ap_snprintf(buf2, buf_size, "%s <a href=\"%s/\">%s</a>\n",
                         ap_escape_html(p, buf), ap_escape_uri(p, filename),
                            ap_escape_html(p, filename));
            }
            else {
                ap_snprintf(buf2, buf_size, "%s <a href=\"%s\">%s</a>\n",
                            ap_escape_html(p, buf),
                            ap_escape_uri(p, filename),
                            ap_escape_html(p, filename));
            }
            ap_cpystrn(buf, buf2, buf_size);
            n = strlen(buf);
        }
        /* else??? What about other OS's output formats? */
        else {
            strcat(buf, "\n");  /* re-append the newline char */
            ap_cpystrn(buf, ap_escape_html(p, buf), buf_size);
        }

        total_bytes_sent += ap_proxy_bputs2(buf, con->client, c);

        ap_reset_timeout(r);    /* reset timeout after successfule write */
    }

    total_bytes_sent += ap_proxy_bputs2("</pre><hr />\n", con->client, c);
    total_bytes_sent += ap_proxy_bputs2(ap_psignature("", r), con->client, c);
    total_bytes_sent += ap_proxy_bputs2("</body></html>\n", con->client, c);

    ap_bclose(data);

    ap_bflush(con->client);

    return total_bytes_sent;
}

/* Common routine for failed authorization (i.e., missing or wrong password)
 * to an ftp service. This causes most browsers to retry the request
 * with username and password (which was presumably queried from the user)
 * supplied in the Authorization: header.
 * Note that we "invent" a realm name which consists of the
 * ftp://user@host part of the reqest (sans password -if supplied but invalid-)
 */
static int ftp_unauthorized(request_rec *r, int log_it)
{
    r->proxyreq = NOT_PROXY;
    /*
     * Log failed requests if they supplied a password (log username/password
     * guessing attempts)
     */
    if (log_it)
        ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, r,
                      "proxy: missing or failed auth to %s",
                      ap_unparse_uri_components(r->pool,
                                         &r->parsed_uri, UNP_OMITPATHINFO));

    ap_table_setn(r->err_headers_out, "WWW-Authenticate",
                  ap_pstrcat(r->pool, "Basic realm=\"",
                          ap_unparse_uri_components(r->pool, &r->parsed_uri,
                                       UNP_OMITPASSWORD | UNP_OMITPATHINFO),
                             "\"", NULL));

    return HTTP_UNAUTHORIZED;
}

/* Set ftp server to TYPE {A,I,E} before transfer of a directory or file */
static int ftp_set_TYPE(request_rec *r, BUFF *ctrl, char xfer_type)
{
    static char old_type[2] = {'A', '\0'};      /* After logon, mode is ASCII */
    int ret = HTTP_OK;
    int rc;

    if (xfer_type == old_type[0])
        return ret;

    /* set desired type */
    old_type[0] = xfer_type;
    ap_bvputs(ctrl, "TYPE ", old_type, CRLF, NULL);
    ap_bflush(ctrl);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: TYPE %s", old_type);

/* responses: 200, 421, 500, 501, 504, 530 */
    /* 200 Command okay. */
    /* 421 Service not available, closing control connection. */
    /* 500 Syntax error, command unrecognized. */
    /* 501 Syntax error in parameters or arguments. */
    /* 504 Command not implemented for that parameter. */
    /* 530 Not logged in. */
    rc = ftp_getrc(ctrl);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", rc);
    if (rc == -1 || rc == 421) {
        ap_kill_timeout(r);
        ret = ap_proxyerror(r, HTTP_BAD_GATEWAY,
                            "Error reading from remote server");
    }
    else if (rc != 200 && rc != 504) {
        ap_kill_timeout(r);
        ret = ap_proxyerror(r, HTTP_BAD_GATEWAY,
                            "Unable to set transfer type");
    }
/* Allow not implemented */
    else if (rc == 504)
         /* ignore it silently */ ;

    return ret;
}

/* Common cleanup routine: close open BUFFers or sockets, and return an error */
static int ftp_cleanup_and_return(request_rec *r, BUFF *ctrl, BUFF *data, int csock, int dsock, int rc)
{
    if (ctrl != NULL)
        ap_bclose(ctrl);
    else if (csock != -1)
        ap_pclosesocket(r->pool, csock);

    if (data != NULL)
        ap_bclose(data);
    else if (dsock != -1)
        ap_pclosesocket(r->pool, dsock);

    ap_kill_timeout(r);

    return rc;
}

/*
 * Handles direct access of ftp:// URLs
 * Original (Non-PASV) version from
 * Troy Morrison <spiffnet@zoom.com>
 * PASV added by Chuck
 */
int ap_proxy_ftp_handler(request_rec *r, cache_req *c, char *url)
{
    char *host, *path, *strp, *parms;
    char *cwd = NULL;
    char *user = NULL;
/*    char *account = NULL; how to supply an account in a URL? */
    const char *password = NULL;
    const char *err;
    int port, i, j, len, rc, nocache = 0;
    int csd = 0, sock = -1, dsock = -1;
    struct sockaddr_in server;
    struct hostent server_hp;
    struct in_addr destaddr;
    table *resp_hdrs;
    BUFF *ctrl = NULL;
    BUFF *data = NULL;
    pool *p = r->pool;
    int one = 1;
    NET_SIZE_T clen;
    char xfer_type = 'A';       /* after ftp login, the default is ASCII */
    int get_dirlisting = 0;

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
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
    char resp[MAX_STRING_LEN];
    char *size = NULL;

/* we only support GET and HEAD */

    if (r->method_number != M_GET)
        return HTTP_NOT_IMPLEMENTED;

/* We break the URL into host, port, path-search */

    host = r->parsed_uri.hostname;
    port = (r->parsed_uri.port != 0)
        ? r->parsed_uri.port
        : ap_default_port_for_request(r);
    path = ap_pstrdup(p, r->parsed_uri.path);
    if (path == NULL)
        path = "";
    else
        while (*path == '/')
            ++path;

    /*
     * The "Authorization:" header must be checked first. We allow the user
     * to "override" the URL-coded user [ & password ] in the Browsers'
     * User&Password Dialog. NOTE that this is only marginally more secure
     * than having the password travel in plain as part of the URL, because
     * Basic Auth simply uuencodes the plain text password. But chances are
     * still smaller that the URL is logged regularly.
     */
    if ((password = ap_table_get(r->headers_in, "Authorization")) != NULL
        && strcasecmp(ap_getword(r->pool, &password, ' '), "Basic") == 0
        && (password = ap_pbase64decode(r->pool, password))[0] != ':') {
        /*
         * Note that this allocation has to be made from r->connection->pool
         * because it has the lifetime of the connection.  The other
         * allocations are temporary and can be tossed away any time.
         */
        user = ap_getword_nulls(r->connection->pool, &password, ':');
        r->connection->ap_auth_type = "Basic";
        r->connection->user = r->parsed_uri.user = user;
        nocache = 1;            /* This resource only accessible with
                                 * username/password */
    }
    else if ((user = r->parsed_uri.user) != NULL) {
        user = ap_pstrdup(p, user);
        decodeenc(user);
        if ((password = r->parsed_uri.password) != NULL) {
            char *tmp = ap_pstrdup(p, password);
            decodeenc(tmp);
            password = tmp;
        }
        nocache = 1;            /* This resource only accessible with
                                 * username/password */
    }
    else {
        user = "anonymous";
        password = "apache_proxy@";
    }

    /* check if ProxyBlock directive on this host */
    destaddr.s_addr = ap_inet_addr(host);
    for (i = 0; i < conf->noproxies->nelts; i++) {
        if (destaddr.s_addr == npent[i].addr.s_addr ||
            (npent[i].name != NULL &&
          (npent[i].name[0] == '*' || strstr(host, npent[i].name) != NULL)))
            return ap_proxyerror(r, HTTP_FORBIDDEN,
                                 "Connect to remote machine blocked");
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: connect to %s:%d", host, port);

    parms = strchr(path, ';');
    if (parms != NULL)
        *(parms++) = '\0';

    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons((unsigned short)port);
    err = ap_proxy_host2addr(host, &server_hp);
    if (err != NULL)
        return ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR, err);

    sock = ap_psocket_ex(p, PF_INET, SOCK_STREAM, IPPROTO_TCP, 1);
    if (sock == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                      "proxy: error creating socket");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

#if !defined(TPF) && !defined(BEOS)
    if (conf->recv_buffer_size > 0
        && setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                      (const char *)&conf->recv_buffer_size, sizeof(int))
        == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                      "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
    }
#endif

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&one,
                   sizeof(one)) == -1) {
#ifndef _OSD_POSIX              /* BS2000 has this option "always on" */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
         "proxy: error setting reuseaddr option: setsockopt(SO_REUSEADDR)");
        ap_pclosesocket(p, sock);
        return HTTP_INTERNAL_SERVER_ERROR;
#endif                          /* _OSD_POSIX */
    }

#ifdef SINIX_D_RESOLVER_BUG
    {
        struct in_addr *ip_addr = (struct in_addr *)*server_hp.h_addr_list;

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
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                      ap_proxyerror(r, HTTP_BAD_GATEWAY, ap_pstrcat(r->pool,
                                    "Could not connect to remote machine: ",
                                                   strerror(errno), NULL)));
    }

    /* record request_time for HTTP/1.1 age calculation */
    c->req_time = time(NULL);

    ctrl = ap_bcreate(p, B_RDWR | B_SOCKET);
    ap_bpushfd(ctrl, sock, sock);
/* shouldn't we implement telnet control options here? */

#ifdef CHARSET_EBCDIC
    ap_bsetflag(ctrl, B_ASCII2EBCDIC | B_EBCDIC2ASCII, 1);
#endif                          /* CHARSET_EBCDIC */

    /* possible results: */
    /* 120 Service ready in nnn minutes. */
    /* 220 Service ready for new user. */
    /* 421 Service not available, closing control connection. */
    ap_hard_timeout("proxy ftp", r);
    i = ftp_getrc_msg(ctrl, resp, sizeof resp);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", i);
    if (i == -1 || i == 421) {
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                      ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
    }
#if 0
    if (i == 120) {
        /*
         * RFC2068 states: 14.38 Retry-After
         * 
         * The Retry-After response-header field can be used with a 503 (Service
         * Unavailable) response to indicate how long the service is expected
         * to be unavailable to the requesting client. The value of this
         * field can be either an HTTP-date or an integer number of seconds
         * (in decimal) after the time of the response. Retry-After  =
         * "Retry-After" ":" ( HTTP-date | delta-seconds )
         */
/**INDENT** Error@756: Unbalanced parens */
        ap_set_header("Retry-After", ap_psprintf(p, "%u", 60 * wait_mins);
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                          ap_proxyerror(r, HTTP_SERVICE_UNAVAILABLE, resp));
    }
#endif
    if (i != 220) {
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                  ap_proxyerror(r, HTTP_BAD_GATEWAY, resp));
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: connected.");

    ap_bvputs(ctrl, "USER ", user, CRLF, NULL);
    ap_bflush(ctrl);            /* capture any errors */
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: USER %s", user);

    /* possible results; 230, 331, 332, 421, 500, 501, 530 */
    /* states: 1 - error, 2 - success; 3 - send password, 4,5 fail */
    /* 230 User logged in, proceed. */
    /* 331 User name okay, need password. */
    /* 332 Need account for login. */
    /* 421 Service not available, closing control connection. */
    /* 500 Syntax error, command unrecognized. */
    /* (This may include errors such as command line too long.) */
    /* 501 Syntax error in parameters or arguments. */
    /* 530 Not logged in. */
    i = ftp_getrc(ctrl);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", i);
    if (i == -1 || i == 421) {
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                      ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
    }
    if (i == 530) {
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                      ftp_unauthorized(r, 1));
    }
    if (i != 230 && i != 331) {
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                      HTTP_BAD_GATEWAY);
    }

    if (i == 331) {             /* send password */
        if (password == NULL) {
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ftp_unauthorized(r, 0));
        }
        ap_bvputs(ctrl, "PASS ", password, CRLF, NULL);
        ap_bflush(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: PASS %s", password);
        /* possible results 202, 230, 332, 421, 500, 501, 503, 530 */
        /* 230 User logged in, proceed. */
        /* 332 Need account for login. */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 503 Bad sequence of commands. */
        /* 530 Not logged in. */
        i = ftp_getrc(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", i);
        if (i == -1 || i == 421) {
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
        }
        if (i == 332) {
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_UNAUTHORIZED,
                                                 "Need account for login"));
        }
        /* @@@ questionable -- we might as well return a 403 Forbidden here */
        if (i == 530)           /* log it: passwd guessing attempt? */
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ftp_unauthorized(r, 1));
        if (i != 230 && i != 202)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          HTTP_BAD_GATEWAY);
    }

    /*
     * Special handling for leading "%2f": this enforces a "cwd /" out of the
     * $HOME directory which was the starting point after login
     */
    if (strncasecmp(path, "%2f", 3) == 0) {
        path += 3;
        while (*path == '/')    /* skip leading '/' (after root %2f) */
            ++path;
        ap_bputs("CWD /" CRLF, ctrl);
        ap_bflush(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: CWD /");

        /* possible results: 250, 421, 500, 501, 502, 530, 550 */
        /* 250 Requested file action okay, completed. */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 502 Command not implemented. */
        /* 530 Not logged in. */
        /* 550 Requested action not taken. */
        i = ftp_getrc(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", i);
        if (i == -1 || i == 421)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
        else if (i == 550)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          HTTP_NOT_FOUND);
        else if (i != 250)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          HTTP_BAD_GATEWAY);
    }

/* set the directory (walk directory component by component):
 * this is what we must do if we don't know the OS type of the remote
 * machine
 */
    for (; (strp = strchr(path, '/')) != NULL; path = strp + 1) {
        char *slash = strp;

        *slash = '\0';

        /* Skip multiple '/' (or trailing '/') to avoid 500 errors */
        while (strp[1] == '/')
            ++strp;
        if (strp[1] == '\0')
            break;

        len = decodeenc(path);  /* Note! This decodes a %2f -> "/" */
        if (strchr(path, '/'))  /* were there any '/' characters? */
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_BAD_REQUEST,
                       "Use of %2F is only allowed at the base directory"));

        ap_bvputs(ctrl, "CWD ", path, CRLF, NULL);
        ap_bflush(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: CWD %s", path);
        *slash = '/';

/* responses: 250, 421, 500, 501, 502, 530, 550 */
        /* 250 Requested file action okay, completed. */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 502 Command not implemented. */
        /* 530 Not logged in. */
        /* 550 Requested action not taken. */
        i = ftp_getrc(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", i);
        if (i == -1 || i == 421)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
        if (i == 550)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          HTTP_NOT_FOUND);
        if (i == 500 || i == 501)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_BAD_REQUEST,
                      "Syntax error in filename (reported by ftp server)"));
        if (i != 250)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          HTTP_BAD_GATEWAY);
    }

    if (parms != NULL && strncmp(parms, "type=", 5) == 0
        && ap_isalpha(parms[5])) {
        /*
         * "type=d" forces a dir listing. The other types (i|a|e) are
         * directly used for the ftp TYPE command
         */
        if (!(get_dirlisting = (parms[5] == 'd')))
            xfer_type = ap_toupper(parms[5]);

        /* Check valid types, rather than ignoring invalid types silently: */
        if (strchr("AEI", xfer_type) == NULL)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                      ap_proxyerror(r, HTTP_BAD_REQUEST, ap_pstrcat(r->pool,
                       "ftp proxy supports only types 'a', 'i', or 'e': \"",
                                           parms, "\" is invalid.", NULL)));
    }
    else {
        /* make binary transfers the default */
        xfer_type = 'I';
    }

/* try to set up PASV data connection first */
    dsock = ap_psocket_ex(p, PF_INET, SOCK_STREAM, IPPROTO_TCP, 1);
    if (dsock == -1) {
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                                      "proxy: error creating PASV socket"));
    }

#if !defined (TPF) && !defined(BEOS)
    if (conf->recv_buffer_size) {
        if (setsockopt(dsock, SOL_SOCKET, SO_RCVBUF,
                (const char *)&conf->recv_buffer_size, sizeof(int)) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                          "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
        }
    }
#endif

    ap_bputs("PASV" CRLF, ctrl);
    ap_bflush(ctrl);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: PASV command issued");
/* possible results: 227, 421, 500, 501, 502, 530 */
    /* 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2). */
    /* 421 Service not available, closing control connection. */
    /* 500 Syntax error, command unrecognized. */
    /* 501 Syntax error in parameters or arguments. */
    /* 502 Command not implemented. */
    /* 530 Not logged in. */

    i = ap_bgets(pasv, sizeof(pasv), ctrl);
    if (i == -1 || i == 421) {
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                               "proxy: PASV: control connection is toast"));
    }
    else {
        pasv[i - 1] = '\0';
        pstr = strtok(pasv, " ");       /* separate result code */
        if (pstr != NULL) {
            presult = atoi(pstr);
            if (*(pstr + strlen(pstr) + 1) == '=')
                pstr += strlen(pstr) + 2;
            else {
                pstr = strtok(NULL, "(");       /* separate address & port
                                                 * params */
                if (pstr != NULL)
                    pstr = strtok(NULL, ")");
            }
        }
        else
            presult = atoi(pasv);

        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", presult);

        if (presult == 227 && pstr != NULL && (sscanf(pstr,
                 "%d,%d,%d,%d,%d,%d", &h3, &h2, &h1, &h0, &p1, &p0) == 6)) {
            /* pardon the parens, but it makes gcc happy */
            paddr = (((((h3 << 8) + h2) << 8) + h1) << 8) + h0;
            pport = (p1 << 8) + p0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: contacting host %d.%d.%d.%d:%d",
                         h3, h2, h1, h0, pport);
            data_addr.sin_family = AF_INET;
            data_addr.sin_addr.s_addr = htonl(paddr);
            data_addr.sin_port = htons(pport);
            i = ap_proxy_doconnect(dsock, &data_addr, r);

            if (i == -1) {
                return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                                        ap_pstrcat(r->pool,
                                    "Could not connect to remote machine: ",
                                                   strerror(errno), NULL)));
            }
            pasvmode = 1;
        }
        else {
            ap_pclosesocket(p, dsock);  /* and try the regular way */
            dsock = -1;
        }
    }

    if (!pasvmode) {            /* set up data connection */
        clen = sizeof(struct sockaddr_in);
        if (getsockname(sock, (struct sockaddr *)&server, &clen) < 0) {
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                                    "proxy: error getting socket address"));
        }

        dsock = ap_psocket_ex(p, PF_INET, SOCK_STREAM, IPPROTO_TCP, 1);
        if (dsock == -1) {
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                                           "proxy: error creating socket"));
        }

        if (setsockopt(dsock, SOL_SOCKET, SO_REUSEADDR, (void *)&one,
                       sizeof(one)) == -1) {
#ifndef _OSD_POSIX              /* BS2000 has this option "always on" */
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                                  "proxy: error setting reuseaddr option"));
#endif                          /* _OSD_POSIX */
        }

        if (bind(dsock, (struct sockaddr *)&server,
                 sizeof(struct sockaddr_in)) == -1) {

            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
             ap_psprintf(p, "proxy: error binding to ftp data socket %s:%d",
                         inet_ntoa(server.sin_addr), server.sin_port)));
        }
        listen(dsock, 2);       /* only need a short queue */
    }

/* set request; "path" holds last path component */
    len = decodeenc(path);
    if (strchr(path, '/'))      /* were there any '/' characters? */
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                      ap_proxyerror(r, HTTP_BAD_REQUEST,
                       "Use of %2F is only allowed at the base directory"));

    /* TM - if len == 0 then it must be a directory (you can't RETR nothing) */

    if (len == 0) {
        get_dirlisting = 1;
    }
    else {
        ap_bvputs(ctrl, "SIZE ", path, CRLF, NULL);
        ap_bflush(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: SIZE %s", path);
        i = ftp_getrc_msg(ctrl, resp, sizeof resp);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d with response %s", i, resp);
        if (i != 500) {         /* Size command not recognized */
            if (i == 550) {     /* Not a regular file */
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: SIZE shows this is a directory");
                get_dirlisting = 1;
                ap_bvputs(ctrl, "CWD ", path, CRLF, NULL);
                ap_bflush(ctrl);
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: CWD %s", path);

                /* possible results: 250, 421, 500, 501, 502, 530, 550 */
                /* 250 Requested file action okay, completed. */
                /* 421 Service not available, closing control connection. */
                /* 500 Syntax error, command unrecognized. */
                /* 501 Syntax error in parameters or arguments. */
                /* 502 Command not implemented. */
                /* 530 Not logged in. */
                /* 550 Requested action not taken. */
                i = ftp_getrc(ctrl);
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", i);
                if (i == -1 || i == 421)
                    return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
                if (i == 550)
                    return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                                  HTTP_NOT_FOUND);
                if (i != 250)
                    return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                                  HTTP_BAD_GATEWAY);
                path = "";
                len = 0;
            }
            else if (i == 213) {/* Size command ok */
                for (j = 0; j < sizeof resp && ap_isdigit(resp[j]); j++);
                resp[j] = '\0';
                if (resp[0] != '\0')
                    size = ap_pstrdup(p, resp);
            }
        }
    }

#ifdef AUTODETECT_PWD
    ap_bvputs(ctrl, "PWD", CRLF, NULL);
    ap_bflush(ctrl);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: PWD");
/* responses: 257, 500, 501, 502, 421, 550 */
    /* 257 "<directory-name>" <commentary> */
    /* 421 Service not available, closing control connection. */
    /* 500 Syntax error, command unrecognized. */
    /* 501 Syntax error in parameters or arguments. */
    /* 502 Command not implemented. */
    /* 550 Requested action not taken. */
    i = ftp_getrc_msg(ctrl, resp, sizeof resp);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: PWD returned status %d", i);
    if (i == -1 || i == 421)
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                      ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
    if (i == 550)
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                      HTTP_NOT_FOUND);
    if (i == 257) {
        const char *dirp = resp;
        cwd = ap_getword_conf(r->pool, &dirp);
    }
#endif                          /* AUTODETECT_PWD */

    if (get_dirlisting) {
        if (len != 0)
            ap_bvputs(ctrl, "LIST ", path, CRLF, NULL);
        else
            ap_bputs("LIST -lag" CRLF, ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: LIST %s", (len == 0 ? "" : path));
    }
    else {
        ftp_set_TYPE(r, ctrl, xfer_type);
        ap_bvputs(ctrl, "RETR ", path, CRLF, NULL);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: RETR %s", path);
    }
    ap_bflush(ctrl);
/* RETR: 110, 125, 150, 226, 250, 421, 425, 426, 450, 451, 500, 501, 530, 550
   NLST: 125, 150, 226, 250, 421, 425, 426, 450, 451, 500, 501, 502, 530 */
    /* 110 Restart marker reply. */
    /* 125 Data connection already open; transfer starting. */
    /* 150 File status okay; about to open data connection. */
    /* 226 Closing data connection. */
    /* 250 Requested file action okay, completed. */
    /* 421 Service not available, closing control connection. */
    /* 425 Can't open data connection. */
    /* 426 Connection closed; transfer aborted. */
    /* 450 Requested file action not taken. */
    /* 451 Requested action aborted. Local error in processing. */
    /* 500 Syntax error, command unrecognized. */
    /* 501 Syntax error in parameters or arguments. */
    /* 530 Not logged in. */
    /* 550 Requested action not taken. */
    rc = ftp_getrc(ctrl);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", rc);
    if (rc == -1 || rc == 421)
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                      ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
    if (rc == 550) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: RETR failed, trying LIST instead");
        get_dirlisting = 1;
        ftp_set_TYPE(r, ctrl, 'A');     /* directories must be transferred in
                                         * ASCII */

        ap_bvputs(ctrl, "CWD ", path, CRLF, NULL);
        ap_bflush(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: CWD %s", path);
        /* possible results: 250, 421, 500, 501, 502, 530, 550 */
        /* 250 Requested file action okay, completed. */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 502 Command not implemented. */
        /* 530 Not logged in. */
        /* 550 Requested action not taken. */
        rc = ftp_getrc(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", rc);
        if (rc == -1 || rc == 421)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
        if (rc == 550)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          HTTP_NOT_FOUND);
        if (rc != 250)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          HTTP_BAD_GATEWAY);

#ifdef AUTODETECT_PWD
        ap_bvputs(ctrl, "PWD", CRLF, NULL);
        ap_bflush(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: PWD");
/* responses: 257, 500, 501, 502, 421, 550 */
        /* 257 "<directory-name>" <commentary> */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 502 Command not implemented. */
        /* 550 Requested action not taken. */
        i = ftp_getrc_msg(ctrl, resp, sizeof resp);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: PWD returned status %d", i);
        if (i == -1 || i == 421)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
        if (i == 550)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          HTTP_NOT_FOUND);
        if (i == 257) {
            const char *dirp = resp;
            cwd = ap_getword_conf(r->pool, &dirp);
        }
#endif                          /* AUTODETECT_PWD */

        ap_bputs("LIST -lag" CRLF, ctrl);
        ap_bflush(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: LIST -lag");
        rc = ftp_getrc(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", rc);
        if (rc == -1 || rc == 421)
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                       "Error reading from remote server"));
    }
    ap_kill_timeout(r);
    if (rc != 125 && rc != 150 && rc != 226 && rc != 250)
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                      HTTP_BAD_GATEWAY);

    r->status = HTTP_OK;
    r->status_line = "200 OK";

    resp_hdrs = ap_make_table(p, 2);
    c->hdrs = resp_hdrs;

    ap_table_setn(resp_hdrs, "Date", ap_gm_timestr_822(r->pool, r->request_time));
    ap_table_setn(resp_hdrs, "Server", ap_get_server_version());

    if (get_dirlisting) {
        ap_table_setn(resp_hdrs, "Content-Type", "text/html");
#ifdef CHARSET_EBCDIC
        r->ebcdic.conv_out = 1; /* server-generated */
#endif
    }
    else {
#ifdef CHARSET_EBCDIC
        r->ebcdic.conv_out = 0; /* do not convert what we read from the ftp
                                 * server */
#endif
        if (r->content_type != NULL) {
            ap_table_setn(resp_hdrs, "Content-Type", r->content_type);
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: Content-Type set to %s", r->content_type);
        }
        else {
            ap_table_setn(resp_hdrs, "Content-Type", ap_default_type(r));
        }
        if (xfer_type != 'A' && size != NULL) {
            /* We "trust" the ftp server to really serve (size) bytes... */
            ap_table_set(resp_hdrs, "Content-Length", size);
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: Content-Length set to %s", size);
        }
    }
    if (r->content_encoding != NULL && r->content_encoding[0] != '\0') {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: Content-Encoding set to %s", r->content_encoding);
        ap_table_setn(resp_hdrs, "Content-Encoding", r->content_encoding);
    }

/* check if NoCache directive on this host */
    if (nocache == 0) {
        for (i = 0; i < conf->nocaches->nelts; i++) {
            if (destaddr.s_addr == ncent[i].addr.s_addr ||
                (ncent[i].name != NULL &&
                 (ncent[i].name[0] == '*' ||
                  strstr(host, ncent[i].name) != NULL))) {
                nocache = 1;
                break;
            }
        }
    }

    i = ap_proxy_cache_update(c, resp_hdrs, 0, nocache);

    if (i != DECLINED) {
        return ftp_cleanup_and_return(r, ctrl, data, sock, dsock, i);
    }

    if (!pasvmode) {            /* wait for connection */
        ap_hard_timeout("proxy ftp data connect", r);
        clen = sizeof(struct sockaddr_in);
        do
            csd = accept(dsock, (struct sockaddr *)&server, &clen);
        while (csd == -1 && errno == EINTR);
        if (csd == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                          "proxy: failed to accept data connection");
            if (c != NULL)
                c = ap_proxy_cache_error(c);
            return ftp_cleanup_and_return(r, ctrl, data, sock, dsock,
                                          HTTP_BAD_GATEWAY);
        }
        data = ap_bcreate(p, B_RDWR | B_SOCKET);
        ap_bpushfd(data, csd, -1);
        ap_kill_timeout(r);
    }
    else {
        data = ap_bcreate(p, B_RDWR | B_SOCKET);
        ap_bpushfd(data, dsock, dsock);
    }

    ap_hard_timeout("proxy receive", r);

    /* send response */
    /* write status line and headers to the cache file */
    ap_proxy_write_headers(c, ap_pstrcat(p, "HTTP/1.1 ", r->status_line, NULL), resp_hdrs);

    /* Setup the headers for our client from upstreams response-headers */
    ap_overlap_tables(r->headers_out, resp_hdrs, AP_OVERLAP_TABLES_SET);
    /* Add X-Cache header */
    ap_table_setn(r->headers_out, "X-Cache",
                  ap_pstrcat(r->pool, "MISS from ",
                             ap_get_server_name(r), NULL));
    /* The Content-Type of this response is the upstream one. */
    r->content_type = ap_table_get(r->headers_out, "Content-Type");
    /* finally output the headers to the client */
    ap_send_http_header(r);

#ifdef CHARSET_EBCDIC
    ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, r->ebcdic.conv_out);
#endif
/* send body */
    if (!r->header_only) {
        if (!get_dirlisting) {
/* we need to set this for ap_proxy_send_fb()... */
            if (c != NULL)
                c->cache_completion = 0;
            ap_proxy_send_fb(data, r, c, -1, 0, 0, conf->io_buffer_size);
        }
        else {
            send_dir(data, r, c, cwd);
        }
        /* ap_proxy_send_fb() closes the socket */
        data = NULL;
        dsock = -1;

        /*
         * We checked for 125||150||226||250 above. See if another rc is
         * pending, and fetch it:
         */
        if (rc == 125 || rc == 150)
            rc = ftp_getrc(ctrl);
    }
    else {
/* abort the transfer: we send the header only */
        ap_bputs("ABOR" CRLF, ctrl);
        ap_bflush(ctrl);
        if (data != NULL) {
            ap_bclose(data);
            data = NULL;
            dsock = -1;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: ABOR");
/* responses: 225, 226, 421, 500, 501, 502 */
        /* 225 Data connection open; no transfer in progress. */
        /* 226 Closing data connection. */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 502 Command not implemented. */
        i = ftp_getrc(ctrl);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: returned status %d", i);
    }

    ap_kill_timeout(r);
    ap_proxy_cache_tidy(c);

/* finish */
    ap_bputs("QUIT" CRLF, ctrl);
    ap_bflush(ctrl);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: QUIT");
/* responses: 221, 500 */
    /* 221 Service closing control connection. */
    /* 500 Syntax error, command unrecognized. */
    i = ftp_getrc(ctrl);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "FTP: QUIT: status %d", i);

    ap_bclose(ctrl);

    ap_rflush(r);               /* flush before garbage collection */

    ap_proxy_garbage_coll(r);

    return OK;
}
