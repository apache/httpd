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

module AP_MODULE_DECLARE_DATA proxy_ftp_module;

int ap_proxy_ftp_canon(request_rec *r, char *url);
int ap_proxy_ftp_handler(request_rec *r, proxy_server_conf *conf,
                             char *url, const char *proxyhost,
                             apr_port_t proxyport);
apr_status_t ap_proxy_send_dir_filter(ap_filter_t * f,
                                                   apr_bucket_brigade *bb);


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
    int i, ch = 0;

    for (i = 0; x[i] != '\0'; i++) {
        ch = x[i];
        if (ch == '%' && ap_isxdigit(x[i + 1]) && ap_isxdigit(x[i + 2])) {
            ch = ap_proxy_hex2c(&x[i + 1]);
            i += 2;
        }
#if !APR_CHARSET_EBCDIC
        if (ch == '\015' || ch == '\012' || (ch & 0x80))
#else                           /* APR_CHARSET_EBCDIC */
        if (ch == '\r' || ch == '\n' || (os_toascii[ch] & 0x80))
#endif                          /* APR_CHARSET_EBCDIC */
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
    apr_port_t port, def_port;

    /* */
    if (strncasecmp(url, "ftp:", 4) == 0) {
        url += 4;
    }
    else {
        return DECLINED;
    }
    def_port = apr_uri_default_port_for_scheme("ftp");

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "proxy: FTP: canonicalising URL %s", url);

    port = def_port;
    err = ap_proxy_canon_netloc(p, &url, &user, &password, &host, &port);
    if (err)
        return HTTP_BAD_REQUEST;
    if (user != NULL && !ftp_check_string(user))
        return HTTP_BAD_REQUEST;
    if (password != NULL && !ftp_check_string(password))
        return HTTP_BAD_REQUEST;

    /* now parse path/parameters args, according to rfc1738 */
    /*
     * N.B. if this isn't a true proxy request, then the URL path (but not
     * query args) has already been decoded. This gives rise to the problem
     * of a ; being decoded into the path.
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

    if (port != def_port)
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

/* we chop lines longer than 80 characters */
#define MAX_LINE_LEN 80

/*
 * Reads response lines, returns both the ftp status code and
 * remembers the response message in the supplied buffer
 */
static int ftp_getrc_msg(conn_rec *ftp_ctrl, apr_bucket_brigade *bb, char *msgbuf, int msglen)
{
    int status;
    char response[MAX_LINE_LEN];
    char buff[5];
    char *mb = msgbuf, *me = &msgbuf[msglen];
    apr_status_t rv;
    int eos;

    if (APR_SUCCESS != (rv = ap_proxy_string_read(ftp_ctrl, bb, response, sizeof(response), &eos))) {
        return -1;
    }
/*
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, NULL,
                 "proxy: <FTP: %s", response);
*/
    if (!apr_isdigit(response[0]) || !apr_isdigit(response[1]) ||
    !apr_isdigit(response[2]) || (response[3] != ' ' && response[3] != '-'))
        status = 0;
    else
        status = 100 * response[0] + 10 * response[1] + response[2] - 111 * '0';

    mb = apr_cpystrn(mb, response + 4, me - mb);

    if (response[3] == '-') {
        memcpy(buff, response, 3);
        buff[3] = ' ';
        do {
            if (APR_SUCCESS != (rv = ap_proxy_string_read(ftp_ctrl, bb, response, sizeof(response), &eos))) {
                return -1;
            }
            mb = apr_cpystrn(mb, response + (' ' == response[0] ? 1 : 4), me - mb);
        } while (memcmp(response, buff, 4) != 0);
    }

    return status;
}

/* this is a filter that turns a raw ASCII directory listing into pretty HTML */

/* ideally, mod_proxy should simply send the raw directory list up the filter
 * stack to mod_autoindex, which in theory should turn the raw ascii into
 * pretty html along with all the bells and whistles it provides...
 *
 * all in good time...! :)
 */

typedef struct {
    apr_bucket_brigade *in;
    char buffer[MAX_STRING_LEN];
    enum {
        HEADER, BODY, FOOTER
    }    state;
}      proxy_dir_ctx_t;

apr_status_t ap_proxy_send_dir_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    apr_pool_t *p = r->pool;
    apr_bucket *e;
    apr_bucket_brigade *out = apr_brigade_create(p);
    apr_status_t rv;
    regex_t *re = NULL; /* @@@ put this in the context */
    regmatch_t re_result[3];

    register int n;
    char *dir, *path, *reldir, *site, *str, *type;

    const char *pwd = apr_table_get(r->notes, "Directory-PWD");
    const char *readme = apr_table_get(r->notes, "Directory-README");

    proxy_dir_ctx_t *ctx = f->ctx;

    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(p, sizeof(*ctx));
        ctx->in = apr_brigade_create(p);
        ctx->buffer[0] = 0;
        ctx->state = HEADER;
    }

    /* Compile the output format of "ls -s1" as a fallback for non-unix ftp listings */
    re = ap_pregcomp(p, "^ *([0-9]+) +([^ ]+)$", REG_EXTENDED);

    /* combine the stored and the new */
    APR_BRIGADE_CONCAT(ctx->in, in);

    if (HEADER == ctx->state) {

        /* basedir is either "", or "/%2f" for the "squid %2f hack" */
        const char *basedir = "";  /* By default, path is relative to the $HOME dir */
        char *wildcard = NULL;

        /* Save "scheme://site" prefix without password */
        site = apr_uri_unparse(p, &f->r->parsed_uri, APR_URI_UNP_OMITPASSWORD | APR_URI_UNP_OMITPATHINFO);
        /* ... and path without query args */
        path = apr_uri_unparse(p, &f->r->parsed_uri, APR_URI_UNP_OMITSITEPART | APR_URI_UNP_OMITQUERY);

        /* If path began with /%2f, change the basedir */
        if (strncasecmp(path, "/%2f", 4) == 0) {
            basedir = "/%2f";
        }

        /* Strip off a type qualifier. It is ignored for dir listings */
        if ((type = strstr(path, ";type=")) != NULL)
            *type++ = '\0';

        (void)decodeenc(path);

        while (path[1] == '/') /* collapse multiple leading slashes to one */
            ++path;

        reldir = strrchr(path, '/');
        if (reldir != NULL) {
            for (n=0; reldir[n] != '\0'; ++n) {
                if (reldir[n] == '\\' && reldir[n+1] != '\0')
                    ++n; /* escaped character */
                else if (reldir[n] == '*' || reldir[n] == '?') {
                    wildcard = &reldir[1];
                    reldir[0] = '\0'; /* strip off the wildcard suffix */
                    break;
                }
            }
        }

        /* Copy path, strip (all except the last) trailing slashes */
        /* (the trailing slash is needed for the dir component loop below) */
        path = dir = ap_pstrcat(p, path, "/", NULL);
        for (n = strlen(path); n > 1 && path[n - 1] == '/' && path[n - 2] == '/'; --n)
            path[n - 1] = '\0';

        /* Add a link to the root directory (if %2f hack was used) */
        str = (basedir[0] != '\0') ? "<a href=\"/%2f/\">%2f</a>/" : "";

        /* print "ftp://host/" */
        str = apr_psprintf(p, DOCTYPE_HTML_3_2
                "<html>\n <head>\n  <title>%s%s%s</title>\n"
                "  <base href=\"%s%s%s\">\n </head>\n"
                " <body>\n  <h2>Directory of "
                "<a href=\"/\">%s</a>/%s",
                site, basedir, ap_escape_html(p, path),
                site, basedir, ap_escape_uri(p, path),
                site, str);

        e = apr_bucket_pool_create(str, strlen(str), p);
        APR_BRIGADE_INSERT_TAIL(out, e);

        for (dir = path+1; (dir = strchr(dir, '/')) != NULL; )
        {
            *dir = '\0';
            if ((reldir = strrchr(path+1, '/'))==NULL) {
                reldir = path+1;
            }
            else
                ++reldir;
            /* print "path/" component */
            str = apr_psprintf(p, "<a href=\"%s%s/\">%s</a>/", basedir,
                        ap_escape_uri(p, path),
                        ap_escape_html(p, reldir));
            *dir = '/';
            while (*dir == '/')
              ++dir;
            APR_BRIGADE_INSERT_TAIL(out, apr_bucket_pool_create(str, strlen(str), p));
        }
        if (wildcard != NULL) {
            APR_BRIGADE_INSERT_TAIL(out, apr_bucket_pool_create(wildcard, strlen(wildcard), p));
        }

        /* If the caller has determined the current directory, and it differs */
        /* from what the client requested, then show the real name */
        if (pwd == NULL || strncmp(pwd, path, strlen(pwd)) == 0) {
            str = apr_psprintf(p, "</h2>\n\n  <hr />\n\n<pre>");
        }
        else {
            str = apr_psprintf(p, "</h2>\n\n(%s)\n\n  <hr />\n\n<pre>",
                               ap_escape_html(p, pwd));
        }
        e = apr_bucket_pool_create(str, strlen(str), p);
        APR_BRIGADE_INSERT_TAIL(out, e);

        /* print README */
        if (readme) {
            str = apr_psprintf(p, "%s\n</pre>\n\n<hr />\n\n<pre>\n",
                               ap_escape_html(p, readme));

            e = apr_bucket_pool_create(str, strlen(str), p);
            APR_BRIGADE_INSERT_TAIL(out, e);
        }

        /* make sure page intro gets sent out */
        e = apr_bucket_flush_create();
        APR_BRIGADE_INSERT_TAIL(out, e);
        if (APR_SUCCESS != (rv = ap_pass_brigade(f->next, out))) {
            return rv;
        }
        apr_brigade_cleanup(out);

        ctx->state = BODY;
    }

    /* loop through each line of directory */
    while (BODY == ctx->state) {
        char *filename;
        int found = 0;
        int eos = 0;

        /* get a complete line */
        /* if the buffer overruns - throw data away */
        while (!found && !APR_BRIGADE_EMPTY(ctx->in)) {
            char *pos, *response;
            apr_size_t len, max;
            e = APR_BRIGADE_FIRST(ctx->in);
            if (APR_BUCKET_IS_EOS(e)) {
                eos = 1;
                break;
            }
            if (APR_SUCCESS != (rv = apr_bucket_read(e, (const char **)&response, &len, APR_BLOCK_READ))) {
                return rv;
            }
            pos = memchr(response, APR_ASCII_LF, len);
            if (pos != NULL) {
                if ((response + len) != (pos + 1)) {
                    len = pos - response + 1;
                    apr_bucket_split(e, pos - response + 1);
                }
                found = 1;
            }
            max = sizeof(ctx->buffer) - strlen(ctx->buffer) - 1;
            if (len > max) {
                len = max;
            }

            /* len+1 to leave spave for the trailing nil char */
            apr_cpystrn(ctx->buffer+strlen(ctx->buffer), response, len+1);

            APR_BUCKET_REMOVE(e);
            apr_bucket_destroy(e);
        }

        /* EOS? jump to footer */
        if (eos) {
            ctx->state = FOOTER;
            break;
        }

        /* not complete? leave and try get some more */
        if (!found) {
            return APR_SUCCESS;
        }

        {
            size_t n = strlen(ctx->buffer);
            if (ctx->buffer[n-1] == CRLF[1])  /* strip trailing '\n' */
                ctx->buffer[--n] = '\0';
            if (ctx->buffer[n-1] == CRLF[0])  /* strip trailing '\r' if present */
                ctx->buffer[--n] = '\0';
        }

        /* a symlink? */
        if (ctx->buffer[0] == 'l' && (filename = strstr(ctx->buffer, " -> ")) != NULL) {
            char *link_ptr = filename;

            do {
                filename--;
            } while (filename[0] != ' ' && filename > ctx->buffer);
            if (filename > ctx->buffer)
                *(filename++) = '\0';
            *(link_ptr++) = '\0';
            str = apr_psprintf(p, "%s <a href=\"%s\">%s %s</a>\n",
                               ap_escape_html(p, ctx->buffer),
                               ap_escape_uri(p, filename),
                               ap_escape_html(p, filename),
                               ap_escape_html(p, link_ptr));
        }

        /* a directory/file? */
        else if (ctx->buffer[0] == 'd' || ctx->buffer[0] == '-' || ctx->buffer[0] == 'l' || apr_isdigit(ctx->buffer[0])) {
            int searchidx = 0;
            char *searchptr = NULL;
            int firstfile = 1;
            if (apr_isdigit(ctx->buffer[0])) {  /* handle DOS dir */
                searchptr = strchr(ctx->buffer, '<');
                if (searchptr != NULL)
                    *searchptr = '[';
                searchptr = strchr(ctx->buffer, '>');
                if (searchptr != NULL)
                    *searchptr = ']';
            }

            filename = strrchr(ctx->buffer, ' ');
            *(filename++) = '\0';

            /* handle filenames with spaces in 'em */
            if (!strcmp(filename, ".") || !strcmp(filename, "..") || firstfile) {
                firstfile = 0;
                searchidx = filename - ctx->buffer;
            }
            else if (searchidx != 0 && ctx->buffer[searchidx] != 0) {
                *(--filename) = ' ';
                ctx->buffer[searchidx - 1] = '\0';
                filename = &ctx->buffer[searchidx];
            }

            /* Append a slash to the HREF link for directories */
            if (!strcmp(filename, ".") || !strcmp(filename, "..") || ctx->buffer[0] == 'd') {
                str = apr_psprintf(p, "%s <a href=\"%s/\">%s</a>\n",
                                   ap_escape_html(p, ctx->buffer),
                                   ap_escape_uri(p, filename),
                                   ap_escape_html(p, filename));
            }
            else {
                str = apr_psprintf(p, "%s <a href=\"%s\">%s</a>\n",
                                   ap_escape_html(p, ctx->buffer),
                                   ap_escape_uri(p, filename),
                                   ap_escape_html(p, filename));
            }
        }
        /* Try a fallback for listings in the format of "ls -s1" */
        else if (0 == ap_regexec(re, ctx->buffer, 3, re_result, 0)) {

            filename = apr_pstrndup(p, &ctx->buffer[re_result[2].rm_so], re_result[2].rm_eo - re_result[2].rm_so);

            str = ap_pstrcat(p, ap_escape_html(p, apr_pstrndup(p, ctx->buffer, re_result[2].rm_so)),
                             "<a href=\"", ap_escape_uri(p, filename), "\">",
                             ap_escape_html(p, filename), "</a>\n", NULL);
        }
        else {
            strcat(ctx->buffer, "\n"); /* re-append the newline */
            str = ap_escape_html(p, ctx->buffer);
        }

        /* erase buffer for next time around */
        ctx->buffer[0] = 0;

        e = apr_bucket_pool_create(str, strlen(str), p);
        APR_BRIGADE_INSERT_TAIL(out, e);
        e = apr_bucket_flush_create();
        APR_BRIGADE_INSERT_TAIL(out, e);
        if (APR_SUCCESS != (rv = ap_pass_brigade(f->next, out))) {
            return rv;
        }
        apr_brigade_cleanup(out);

    }

    if (FOOTER == ctx->state) {
        str = apr_psprintf(p, "</pre>\n\n  <hr />\n\n  %s\n\n </body>\n</html>\n", ap_psignature("", r));
        e = apr_bucket_pool_create(str, strlen(str), p);
        APR_BRIGADE_INSERT_TAIL(out, e);

        e = apr_bucket_flush_create();
        APR_BRIGADE_INSERT_TAIL(out, e);

        e = apr_bucket_eos_create();
        APR_BRIGADE_INSERT_TAIL(out, e);

        if (APR_SUCCESS != (rv = ap_pass_brigade(f->next, out))) {
            return rv;
        }
        apr_brigade_destroy(out);
    }

    return APR_SUCCESS;
}

/*
 * Generic "send FTP command to server" routine, using the control socket.
 * Returns the FTP returncode (3 digit code)
 * Allows for tracing the FTP protocol (in LogLevel debug)
 */
static int
proxy_ftp_command(const char *cmd, request_rec *r, conn_rec *ftp_ctrl,
                  apr_bucket_brigade *bb, char **pmessage)
{
    char *crlf;
    int rc;
    char message[HUGE_STRING_LEN];

    /* If cmd == NULL, we retrieve the next ftp response line */
    if (cmd != NULL) {

        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(cmd, strlen(cmd), r->pool));
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_flush_create());
        ap_pass_brigade(ftp_ctrl->output_filters, bb);

        /* strip off the CRLF for logging */
        ap_cpystrn(message, cmd, sizeof message);
        if ((crlf = strchr(message, '\r')) != NULL ||
            (crlf = strchr(message, '\n')) != NULL)
            *crlf = '\0';
        if (strncmp(message,"PASS ", 5) == 0)
            strcpy(&message[5], "****");
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "proxy:>FTP: %s", message);
    }

    rc = ftp_getrc_msg(ftp_ctrl, bb, message, sizeof message);
    if (rc == -1 || rc == 421)
        strcpy(message,"<unable to read result>");
    if ((crlf = strchr(message, '\r')) != NULL ||
        (crlf = strchr(message, '\n')) != NULL)
        *crlf = '\0';
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "proxy:<FTP: %3.3u %s", rc, message);

    if (pmessage != NULL)
        *pmessage = ap_pstrdup(r->pool, message);

    return rc;
}

/* Set ftp server to TYPE {A,I,E} before transfer of a directory or file */
static int ftp_set_TYPE(char xfer_type, request_rec *r, conn_rec *ftp_ctrl,
                  apr_bucket_brigade *bb, char **pmessage)
{
    static char old_type[2] = { 'A', '\0' }; /* After logon, mode is ASCII */
    int ret = HTTP_OK;
    int rc;

    if (xfer_type == old_type[0])
        return ret;

    /* set desired type */
    old_type[0] = xfer_type;

    rc = proxy_ftp_command(apr_pstrcat(r->pool, "TYPE ", old_type, CRLF, NULL),
                           r, ftp_ctrl, bb, pmessage);
/* responses: 200, 421, 500, 501, 504, 530 */
    /* 200 Command okay. */
    /* 421 Service not available, closing control connection. */
    /* 500 Syntax error, command unrecognized. */
    /* 501 Syntax error in parameters or arguments. */
    /* 504 Command not implemented for that parameter. */
    /* 530 Not logged in. */
    if (rc == -1 || rc == 421) {
        ret = ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             "Error reading from remote server");
    }
    else if (rc != 200 && rc != 504) {
        ret = ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             "Unable to set transfer type");
    }
/* Allow not implemented */
    else if (rc == 504)
        /* ignore it silently */;

    return ret;
}


/* Return the current directory which we have selected on the FTP server, or NULL */
static char *ftp_get_PWD(request_rec *r, conn_rec *ftp_ctrl, apr_bucket_brigade *bb)
{
    char *cwd = NULL;
    char *ftpmessage = NULL;

    /* responses: 257, 500, 501, 502, 421, 550 */
    /* 257 "<directory-name>" <commentary> */
    /* 421 Service not available, closing control connection. */
    /* 500 Syntax error, command unrecognized. */
    /* 501 Syntax error in parameters or arguments. */
    /* 502 Command not implemented. */
    /* 550 Requested action not taken. */
    switch (proxy_ftp_command("PWD" CRLF, r, ftp_ctrl, bb, &ftpmessage)) {
        case -1:
        case 421:
        case 550:
            ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             "Failed to read PWD on ftp server");
            break;

        case 257: {
            const char *dirp = ftpmessage;
            cwd = ap_getword_conf(r->pool, &dirp);
        }
    }
    return cwd;
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
    r->proxyreq = PROXYREQ_NONE;
    /*
     * Log failed requests if they supplied a password (log username/password
     * guessing attempts)
     */
    if (log_it)
        ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, r,
                      "proxy: missing or failed auth to %s",
                      apr_uri_unparse(r->pool,
                                 &r->parsed_uri, APR_URI_UNP_OMITPATHINFO));

    apr_table_setn(r->err_headers_out, "WWW-Authenticate",
                   apr_pstrcat(r->pool, "Basic realm=\"",
                               apr_uri_unparse(r->pool, &r->parsed_uri,
                       APR_URI_UNP_OMITPASSWORD | APR_URI_UNP_OMITPATHINFO),
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
int ap_proxy_ftp_handler(request_rec *r, proxy_server_conf *conf,
                             char *url, const char *proxyhost,
                             apr_port_t proxyport)
{
    apr_pool_t *p = r->pool;
    conn_rec *c = r->connection;
    proxy_conn_rec *backend;
    apr_socket_t *sock, *local_sock, *data_sock = NULL;
    apr_sockaddr_t *connect_addr;
    apr_status_t rv;
    conn_rec *origin, *data = NULL;
    int err;
    apr_bucket_brigade *bb = apr_brigade_create(p);
    char *buf, *connectname;
    apr_port_t connectport;
    char buffer[MAX_STRING_LEN];
    char *ftpmessage = NULL;
    char *path, *strp, *type_suffix, *cwd = NULL;
    char *user = NULL;
/*    char *account = NULL; how to supply an account in a URL? */
    const char *password = NULL;
    int len, rc;
    int one = 1;
    char *size = NULL;
    apr_socket_t *origin_sock = NULL;
    char xfer_type = 'A'; /* after ftp login, the default is ASCII */
    int  dirlisting = 0;

    /* stuff for PASV mode */
    int connect = 0, use_port = 0;
    char dates[AP_RFC822_DATE_LEN];

    /* is this for us? */
    if (proxyhost) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "proxy: FTP: declining URL %s - proxyhost %s specified:", url, proxyhost);
        return DECLINED;        /* proxy connections are via HTTP */
    }
    if (strncasecmp(url, "ftp:", 4)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "proxy: FTP: declining URL %s - not ftp:", url);
        return DECLINED;        /* only interested in FTP */
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "proxy: FTP: serving URL %s", url);

    /* create space for state information */
    backend = (proxy_conn_rec *) ap_get_module_config(c->conn_config, &proxy_ftp_module);
    if (!backend) {
        backend = ap_pcalloc(c->pool, sizeof(proxy_conn_rec));
        backend->connection = NULL;
        backend->hostname = NULL;
        backend->port = 0;
        ap_set_module_config(c->conn_config, &proxy_ftp_module, backend);
    }
    if (backend->connection)
        origin_sock = ap_get_module_config(backend->connection->conn_config, &core_module);


    /*
     * I: Who Do I Connect To? -----------------------
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
        : apr_uri_default_port_for_scheme("ftp");
    path = apr_pstrdup(p, r->parsed_uri.path);
    path = (path != NULL && path[0] != '\0') ? &path[1] : "";

    type_suffix = strchr(path, ';');
    if (type_suffix != NULL)
        *(type_suffix++) = '\0';

    /*
     * The "Authorization:" header must be checked first. We allow the user
     * to "override" the URL-coded user [ & password ] in the Browsers'
     * User&Password Dialog. NOTE that this is only marginally more secure
     * than having the password travel in plain as part of the URL, because
     * Basic Auth simply uuencodes the plain text password. But chances are
     * still smaller that the URL is logged regularly.
     */
    if ((password = apr_table_get(r->headers_in, "Authorization")) != NULL
        && strcasecmp(ap_getword(r->pool, &password, ' '), "Basic") == 0
        && (password = ap_pbase64decode(r->pool, password))[0] != ':') {
        /*
         * Note that this allocation has to be made from r->connection->pool
         * because it has the lifetime of the connection.  The other
         * allocations are temporary and can be tossed away any time.
         */
        user = ap_getword_nulls(r->connection->pool, &password, ':');
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
        password = "apache-proxy@";
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
       "proxy: FTP: connecting %s to %s:%d", url, connectname, connectport);

    /* do a DNS lookup for the destination host */
    err = apr_sockaddr_info_get(&connect_addr, connectname, APR_UNSPEC, connectport, 0, p);

    /* check if ProxyBlock directive on this host */
    if (OK != ap_proxy_checkproxyblock(r, conf, connect_addr)) {
        return ap_proxyerror(r, HTTP_FORBIDDEN,
                             "Connect to remote machine blocked");
    }


    /*
     * II: Make the Connection -----------------------
     *
     * We have determined who to connect to. Now make the connection.
     */

    /*
     * get all the possible IP addresses for the destname and loop through
     * them until we get a successful connection
     */
    if (APR_SUCCESS != err) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_pstrcat(p,
                                                 "DNS lookup failure for: ",
                                                        connectname, NULL));
    }


    if ((rv = apr_socket_create(&sock, APR_INET, SOCK_STREAM, r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "proxy: FTP: error creating socket");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

#if !defined(TPF) && !defined(BEOS)
    if (conf->recv_buffer_size > 0
        && (rv = apr_setsocketopt(sock, APR_SO_RCVBUF,
                                  conf->recv_buffer_size))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
    }
#endif

    if (APR_SUCCESS != (rv = apr_setsocketopt(sock, APR_SO_REUSEADDR, one))) {
#ifndef _OSD_POSIX              /* BS2000 has this option "always on" */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "proxy: FTP: error setting reuseaddr option: setsockopt(SO_REUSEADDR)");
        return HTTP_INTERNAL_SERVER_ERROR;
#endif                          /* _OSD_POSIX */
    }

    /* Set a timeout on the socket */
    apr_setsocketopt(sock, APR_SO_TIMEOUT, (int)(r->server->timeout * APR_USEC_PER_SEC));

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "proxy: FTP: socket has been created");


    /*
     * At this point we have a list of one or more IP addresses of the
     * machine to connect to. If configured, reorder this list so that the
     * "best candidate" is first try. "best candidate" could mean the least
     * loaded server, the fastest responding server, whatever.
     *
     * For now we do nothing, ie we get DNS round robin. XXX FIXME
     */


    /* try each IP address until we connect successfully */
    {
        int failed = 1;
        while (connect_addr) {

            /* FIXME: @@@: We created an APR_INET socket. Now there may be
             * IPv6 (AF_INET6) DNS addresses in the list... IMO the socket
             * should be created with the correct family in the first place.
             * (either do it in this loop, or make at least two attempts
             * with the AF_INET and AF_INET6 elements in the list)
             */
            ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
                         "proxy: FTP: trying to connect to %pI (%s)...", connect_addr, connectname);

            /* make the connection out of the socket */
            rv = apr_connect(sock, connect_addr);

            /* if an error occurred, loop round and try again */
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                             "proxy: FTP: attempt to connect to %pI (%s) failed", connect_addr, connectname);
                connect_addr = connect_addr->next;
                continue;
            }

            /* if we get here, all is well */
            failed = 0;
            break;
        }

        /* handle a permanent error from the above loop */
        if (failed) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_psprintf(r->pool,
                          "Could not connect to remote machine: %s port %d",
                                                 connectname, connectport));
        }
    }

    /* the socket is now open, create a new connection */
    origin = ap_new_connection(p, r->server, sock, r->connection->id, r->connection->sbh);
    if (!origin) {
        /*
         * the peer reset the connection already; ap_new_connection() closed
         * the socket
         */
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "proxy: FTP: an error occurred creating a new connection to %pI (%s)", connect_addr, connectname);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* if a keepalive connection is floating around, close it first! */
    /* we might support ftp keepalives later, but not now... */
    if (backend->connection) {
        apr_socket_close(origin_sock);
        backend->connection = NULL;
        origin_sock = NULL;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "proxy: FTP: control connection complete");


    /*
     * III: Send Control Request -------------------------
     *
     * Log into the ftp server, send the username & password, change to the
     * correct directory...
     */

    /* set up the connection filters */
    ap_run_install_transport_filters(origin, sock);

    /* possible results: */
    /* 120 Service ready in nnn minutes. */
    /* 220 Service ready for new user. */
    /* 421 Service not available, closing control connection. */
    rc = proxy_ftp_command(NULL, r, origin, bb, &ftpmessage);
    if (rc == -1 || rc == 421) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY, "Error reading from remote server");
    }
    if (rc == 120) {
        /*
         * RFC2616 states: 14.37 Retry-After
         *
         * The Retry-After response-header field can be used with a 503 (Service
         * Unavailable) response to indicate how long the service is expected
         * to be unavailable to the requesting client. [...] The value of
         * this field can be either an HTTP-date or an integer number of
         * seconds (in decimal) after the time of the response. Retry-After
         * = "Retry-After" ":" ( HTTP-date | delta-seconds )
         */
        char *secs_str = ftpmessage;
        time_t secs;

        /* Look for a number, preceded by whitespace */
        while (*secs_str)
            if (apr_isspace(secs_str[-1]) && apr_isdigit(secs_str[0]))
                break;
        if (*secs_str != '\0') {
            secs = atol(secs_str);
            ap_table_add(r->headers_out, "Retry-After",
                         apr_psprintf(p, "%lu", (unsigned long)(60 * secs)));
        }
        return ap_proxyerror(r, HTTP_SERVICE_UNAVAILABLE, ftpmessage);
    }
    if (rc != 220) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY, ftpmessage);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "proxy: FTP: connected.");

    rc = proxy_ftp_command(apr_pstrcat(p, "USER ", user, CRLF, NULL),
                           r, origin, bb, &ftpmessage);
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
    if (rc == -1 || rc == 421) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY, "Error reading from remote server");
    }
    if (rc == 530) {
        return ftp_unauthorized(r, 1);  /* log it: user name guessing
                                         * attempt? */
    }
    if (rc != 230 && rc != 331) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY, ftpmessage);
    }

    if (rc == 331) {            /* send password */
        if (password == NULL) {
            return ftp_unauthorized(r, 0);
        }

        rc = proxy_ftp_command(apr_pstrcat(p, "PASS ", password, CRLF, NULL),
                           r, origin, bb, &ftpmessage);
        /* possible results 202, 230, 332, 421, 500, 501, 503, 530 */
        /* 230 User logged in, proceed. */
        /* 332 Need account for login. */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 503 Bad sequence of commands. */
        /* 530 Not logged in. */
        if (rc == -1 || rc == 421) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                 "Error reading from remote server");
        }
        if (rc == 332) {
            return ap_proxyerror(r, HTTP_UNAUTHORIZED,
                  apr_pstrcat(p, "Need account for login: ", ftpmessage, NULL));
        }
        /* @@@ questionable -- we might as well return a 403 Forbidden here */
        if (rc == 530) {
            return ftp_unauthorized(r, 1);      /* log it: passwd guessing
                                                 * attempt? */
        }
        if (rc != 230 && rc != 202) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY, ftpmessage);
        }
    }
    apr_table_set(r->notes, "Directory-README", ftpmessage);

    /*
     * set the directory (walk directory component by component): this is
     * what we must do if we don't know the OS type of the remote machine
     */
    for (;;) {
        strp = strchr(path, '/');
        if (strp == NULL)
            break;
        *strp = '\0';

        len = decodeenc(path);

        /* NOTE: FTP servers do globbing on the path.
         * So we need to escape the URI metacharacters.
         * In the current implementation, we use shell escaping, because
         * it masks all characters which are also dangerous for FTP.
         * We could also have extended gen_test_char.c with a special T_ESCAPE_FTP_PATH
         */
        rc = proxy_ftp_command(apr_pstrcat(p, "CWD ",
                           ap_escape_shell_cmd(p, path), CRLF, NULL),
                           r, origin, bb, &ftpmessage);
        *strp = '/';
        /* responses: 250, 421, 500, 501, 502, 530, 550 */
        /* 250 Requested file action okay, completed. */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 502 Command not implemented. */
        /* 530 Not logged in. */
        /* 550 Requested action not taken. */
        if (rc == -1 || rc == 421) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                 "Error reading from remote server");
        }
        if (rc == 550) {
            return ap_proxyerror(r, HTTP_NOT_FOUND, ftpmessage);
        }
        if (rc != 250) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY, ftpmessage);
        }

        path = strp + 1;
    }

    if (type_suffix != NULL && strncmp(type_suffix, "type=", 5) == 0
        && ap_isalpha(type_suffix[5])) {
        /* "type=d" forces a dir listing.
         * The other types (i|a|e) are directly used for the ftp TYPE command
         */
        if ( ! (dirlisting = (ap_tolower(type_suffix[5]) == 'd')))
            xfer_type = ap_toupper(type_suffix[5]);

        /* Check valid types, rather than ignoring invalid types silently: */
        if (strchr("AEI", xfer_type) == NULL)
            return ap_proxyerror(r, HTTP_BAD_REQUEST, ap_pstrcat(r->pool,
                                    "ftp proxy supports only types 'a', 'i', or 'e': \"",
                                    type_suffix, "\" is invalid.", NULL));
    }
    else {
        /* make binary transfers the default */
        xfer_type = 'I';
    }


    /*
     * IV: Make Data Connection? -------------------------
     *
     * Try EPSV, if that fails... try PASV, if that fails... try PORT.
     */
/* this temporarily switches off EPSV/PASV */
/*goto bypass;*/

    /* set up data connection - EPSV */
    {
        apr_sockaddr_t *data_addr;
        char *data_ip;
        apr_port_t data_port;

        /*
         * The EPSV command replaces PASV where both IPV4 and IPV6 is
         * supported. Only the port is returned, the IP address is always the
         * same as that on the control connection. Example: Entering Extended
         * Passive Mode (|||6446|)
         */
        rc = proxy_ftp_command("EPSV" CRLF,
                           r, origin, bb, &ftpmessage);
        /* possible results: 227, 421, 500, 501, 502, 530 */
        /* 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2). */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 502 Command not implemented. */
        /* 530 Not logged in. */
        if (rc == -1 || rc == 421) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                 "Error reading from remote server");
        }
        if (rc != 229 && rc != 500 && rc != 501 && rc != 502) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY, ftpmessage);
        }
        else if (rc == 229) {
            char *pstr;
            char *tok_cntx;

            pstr = ftpmessage;
            pstr = apr_strtok(pstr, " ", &tok_cntx);    /* separate result code */
            if (pstr != NULL) {
                if (*(pstr + strlen(pstr) + 1) == '=') {
                    pstr += strlen(pstr) + 2;
                }
                else {
                    pstr = apr_strtok(NULL, "(", &tok_cntx);    /* separate address &
                                                                 * port params */
                    if (pstr != NULL)
                        pstr = apr_strtok(NULL, ")", &tok_cntx);
                }
            }

            if (pstr) {
                apr_sockaddr_t *epsv_addr;
                data_port = atoi(pstr + 3);

                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                       "proxy: FTP: EPSV contacting remote host on port %d",
                             data_port);

                if ((rv = apr_socket_create(&data_sock, APR_INET, SOCK_STREAM, r->pool)) != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                  "proxy: FTP: error creating EPSV socket");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

#if !defined (TPF) && !defined(BEOS)
                if (conf->recv_buffer_size > 0 && (rv = apr_setsocketopt(data_sock, APR_SO_RCVBUF,
                                                 conf->recv_buffer_size))) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                  "proxy: FTP: setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
                }
#endif

                /* make the connection */
                apr_socket_addr_get(&data_addr, APR_REMOTE, sock);
                apr_sockaddr_ip_get(&data_ip, data_addr);
                apr_sockaddr_info_get(&epsv_addr, data_ip, APR_INET, data_port, 0, p);
                rv = apr_connect(data_sock, epsv_addr);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                                 "proxy: FTP: EPSV attempt to connect to %pI failed - Firewall/NAT?", epsv_addr);
                    return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_psprintf(r->pool,
                                                                           "EPSV attempt to connect to %pI failed - firewall/NAT?", epsv_addr));
                }
                else {
                    connect = 1;
                }
            }
            else {
                /* and try the regular way */
                apr_socket_close(data_sock);
            }
        }
    }

    /* set up data connection - PASV */
    if (!connect) {
        rc = proxy_ftp_command("PASV" CRLF,
                           r, origin, bb, &ftpmessage);
        /* possible results: 227, 421, 500, 501, 502, 530 */
        /* 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2). */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 502 Command not implemented. */
        /* 530 Not logged in. */
        if (rc == -1 || rc == 421) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                 "Error reading from remote server");
        }
        if (rc != 227 && rc != 502) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY, ftpmessage);
        }
        else if (rc == 227) {
            unsigned int h0, h1, h2, h3, p0, p1;
            char *pstr;
            char *tok_cntx;

/* FIXME: Check PASV against RFC1123 */

            pstr = ftpmessage;
            pstr = apr_strtok(pstr, " ", &tok_cntx);    /* separate result code */
            if (pstr != NULL) {
                if (*(pstr + strlen(pstr) + 1) == '=') {
                    pstr += strlen(pstr) + 2;
                }
                else {
                    pstr = apr_strtok(NULL, "(", &tok_cntx);    /* separate address &
                                                                 * port params */
                    if (pstr != NULL)
                        pstr = apr_strtok(NULL, ")", &tok_cntx);
                }
            }

/* FIXME: Only supports IPV4 - fix in RFC2428 */

            if (pstr != NULL && (sscanf(pstr,
                 "%d,%d,%d,%d,%d,%d", &h3, &h2, &h1, &h0, &p1, &p0) == 6)) {

                apr_sockaddr_t *pasv_addr;
                apr_port_t pasvport = (p1 << 8) + p0;
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                          "proxy: FTP: PASV contacting host %d.%d.%d.%d:%d",
                             h3, h2, h1, h0, pasvport);

                if ((rv = apr_socket_create(&data_sock, APR_INET, SOCK_STREAM, r->pool)) != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                  "proxy: error creating PASV socket");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

#if !defined (TPF) && !defined(BEOS)
                if (conf->recv_buffer_size > 0 && (rv = apr_setsocketopt(data_sock, APR_SO_RCVBUF,
                                                 conf->recv_buffer_size))) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                  "proxy: FTP: setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
                }
#endif

                /* make the connection */
                apr_sockaddr_info_get(&pasv_addr, apr_psprintf(p, "%d.%d.%d.%d", h3, h2, h1, h0), APR_INET, pasvport, 0, p);
                rv = apr_connect(data_sock, pasv_addr);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                                 "proxy: FTP: PASV attempt to connect to %pI failed - Firewall/NAT?", pasv_addr);
                    return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_psprintf(r->pool,
                                                                           "PASV attempt to connect to %pI failed - firewall/NAT?", pasv_addr));
                }
                else {
                    connect = 1;
                }
            }
            else {
                /* and try the regular way */
                apr_socket_close(data_sock);
            }
        }
    }
/*bypass:*/

    /* set up data connection - PORT */
    if (!connect) {
        apr_sockaddr_t *local_addr;
        char *local_ip;
        apr_port_t local_port;
        unsigned int h0, h1, h2, h3, p0, p1;

        if ((rv = apr_socket_create(&local_sock, APR_INET, SOCK_STREAM, r->pool)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "proxy: FTP: error creating local socket");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_socket_addr_get(&local_addr, APR_LOCAL, sock);
        apr_sockaddr_port_get(&local_port, local_addr);
        apr_sockaddr_ip_get(&local_ip, local_addr);

        if ((rv = apr_setsocketopt(local_sock, APR_SO_REUSEADDR, one)) != APR_SUCCESS) {
#ifndef _OSD_POSIX              /* BS2000 has this option "always on" */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "proxy: FTP: error setting reuseaddr option");
            return HTTP_INTERNAL_SERVER_ERROR;
#endif                          /* _OSD_POSIX */
        }

        apr_sockaddr_info_get(&local_addr, local_ip, APR_UNSPEC, local_port, 0, r->pool);

        if ((rv = apr_bind(local_sock, local_addr)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
            "proxy: FTP: error binding to ftp data socket %pI", local_addr);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* only need a short queue */
        if ((rv = apr_listen(local_sock, 2)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "proxy: FTP: error listening to ftp data socket %pI", local_addr);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

/* FIXME: Sent PORT here */

        if (local_ip && (sscanf(local_ip,
                                "%d.%d.%d.%d", &h3, &h2, &h1, &h0) == 4)) {
            p1 = (local_port >> 8);
            p0 = (local_port & 0xFF);

            rc = proxy_ftp_command(apr_psprintf(p, "PORT %d,%d,%d,%d,%d,%d" CRLF, h3, h2, h1, h0, p1, p0),
                           r, origin, bb, &ftpmessage);
            /* possible results: 200, 421, 500, 501, 502, 530 */
            /* 200 Command okay. */
            /* 421 Service not available, closing control connection. */
            /* 500 Syntax error, command unrecognized. */
            /* 501 Syntax error in parameters or arguments. */
            /* 502 Command not implemented. */
            /* 530 Not logged in. */
            if (rc == -1 || rc == 421) {
                return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                     "Error reading from remote server");
            }
            if (rc != 200) {
                return ap_proxyerror(r, HTTP_BAD_GATEWAY, buffer);
            }

            /* signal that we must use the EPRT/PORT loop */
            use_port = 1;
        }
        else {
/* IPV6 FIXME:
 * The EPRT command replaces PORT where both IPV4 and IPV6 is supported. The first
 * number (1,2) indicates the protocol type. Examples:
 *   EPRT |1|132.235.1.2|6275|
 *   EPRT |2|1080::8:800:200C:417A|5282|
 */
            return ap_proxyerror(r, HTTP_NOT_IMPLEMENTED, "Connect to IPV6 ftp server using EPRT not supported. Enable EPSV.");
        }
    }


    /*
     * V: Set The Headers -------------------
     *
     * Get the size of the request, set up the environment for HTTP.
     */

    /* set request; "path" holds last path component */
    len = decodeenc(path);

    /* If len == 0 then it must be a directory (you can't RETR nothing)
     * Also, don't allow to RETR by wildcard. Instead, create a dirlisting
     */
    if (len == 0 || strpbrk(path, "*?") != NULL) {
        dirlisting = 1;
    }
    else {
        rc = proxy_ftp_command(apr_pstrcat(p, "SIZE ", path, CRLF, NULL),
                           r, origin, bb, &ftpmessage);
        if (rc == -1 || rc == 421) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                 "Error reading from remote server");
        }
        else if (rc == 213) {/* Size command ok */
            int j;
            for (j = 0; apr_isdigit(ftpmessage[j]); j++)
                ;
            ftpmessage[j] = '\0';
            if (ftpmessage[0] != '\0')
                 size = ftpmessage; /* already pstrdup'ed: no copy necessary */
        }
        else if (rc == 550) {    /* Not a regular file */
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                             "proxy: FTP: SIZE shows this is a directory");
            dirlisting = 1;
            rc = proxy_ftp_command(apr_pstrcat(p, "CWD ", 
                           ap_escape_shell_cmd(p, path), CRLF, NULL),
                           r, origin, bb, &ftpmessage);
            /* possible results: 250, 421, 500, 501, 502, 530, 550 */
            /* 250 Requested file action okay, completed. */
            /* 421 Service not available, closing control connection. */
            /* 500 Syntax error, command unrecognized. */
            /* 501 Syntax error in parameters or arguments. */
            /* 502 Command not implemented. */
            /* 530 Not logged in. */
            /* 550 Requested action not taken. */
            if (rc == -1 || rc == 421) {
                return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                     "Error reading from remote server");
            }
            if (rc == 550) {
                return ap_proxyerror(r, HTTP_NOT_FOUND, ftpmessage);
            }
            if (rc != 250) {
                return ap_proxyerror(r, HTTP_BAD_GATEWAY, ftpmessage);
            }
            path = "";
            len = 0;
        }
    }

    cwd = ftp_get_PWD(r, origin, bb);
    if (cwd != NULL) {
        apr_table_set(r->notes, "Directory-PWD", cwd);
    }

    if (dirlisting) {
        /* If the current directory contains no slash, we are talking to
         * a non-unix ftp system. Try LIST instead of "LIST -lag", it
         * should return a long listing anyway (unlike NLST).
         * Some exotic FTP servers might choke on the "-lag" switch.
         */
        /* Note that we do not escape the path here, to allow for
         * queries like: ftp://user@host/apache/src/server/http_*.c
         */
        if (len != 0)
            buf = apr_pstrcat(p, "LIST ", path, CRLF, NULL);
        else if (cwd == NULL || strchr(cwd, '/') != NULL)
            buf = apr_pstrcat(p, "LIST -lag", CRLF, NULL);
        else
            buf = "LIST" CRLF;
    }
    else {
        /* switch to binary if the user did not specify ";type=a" */
        ftp_set_TYPE(xfer_type, r, origin, bb, &ftpmessage);
/* FIXME: Handle range requests - send REST */
        buf = apr_pstrcat(p, "RETR ", ap_escape_shell_cmd(p, path), CRLF, NULL);
    }
    rc = proxy_ftp_command(buf, r, origin, bb, &ftpmessage);
    /* rc is an intermediate response for the LIST or RETR commands */

    /*
     * RETR: 110, 125, 150, 226, 250, 421, 425, 426, 450, 451, 500, 501, 530,
     * 550 NLST: 125, 150, 226, 250, 421, 425, 426, 450, 451, 500, 501, 502,
     * 530
     */
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
    if (rc == -1 || rc == 421) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             "Error reading from remote server");
    }
    if (rc == 550) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "proxy: FTP: RETR failed, trying LIST instead");

        /* Directory Listings should always be fetched in ASCII mode */
        dirlisting = 1;
        ftp_set_TYPE('A', r, origin, bb, NULL);

        rc = proxy_ftp_command(apr_pstrcat(p, "CWD ",
                               ap_escape_shell_cmd(p, path), CRLF, NULL),
                               r, origin, bb, &ftpmessage);
        /* possible results: 250, 421, 500, 501, 502, 530, 550 */
        /* 250 Requested file action okay, completed. */
        /* 421 Service not available, closing control connection. */
        /* 500 Syntax error, command unrecognized. */
        /* 501 Syntax error in parameters or arguments. */
        /* 502 Command not implemented. */
        /* 530 Not logged in. */
        /* 550 Requested action not taken. */
        if (rc == -1 || rc == 421) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                 "Error reading from remote server");
        }
        if (rc == 550) {
            return ap_proxyerror(r, HTTP_NOT_FOUND, ftpmessage);
        }
        if (rc != 250) {
            return ap_proxyerror(r, HTTP_BAD_GATEWAY, ftpmessage);
        }

        /* Update current directory after CWD */
        cwd = ftp_get_PWD(r, origin, bb);
        if (cwd != NULL) {
            apr_table_set(r->notes, "Directory-PWD", cwd);
        }

        /* See above for the "LIST" vs. "LIST -lag" discussion. */
        rc = proxy_ftp_command((cwd == NULL || strchr(cwd, '/') != NULL)
                               ? "LIST -lag" CRLF : "LIST" CRLF,
                               r, origin, bb, &ftpmessage);

        /* rc is an intermediate response for the LIST command (125 transfer starting, 150 opening data connection) */
        if (rc == -1 || rc == 421)
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                 "Error reading from remote server");
    }
    if (rc != 125 && rc != 150 && rc != 226 && rc != 250) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY, ftpmessage);
    }

    r->status = HTTP_OK;
    r->status_line = "200 OK";

    apr_rfc822_date(dates, r->request_time);
    apr_table_setn(r->headers_out, "Date", dates);
    apr_table_setn(r->headers_out, "Server", ap_get_server_version());

    /* set content-type */
    if (dirlisting) {
        r->content_type = "text/html";
    }
    else {
        if (r->content_type) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "proxy: FTP: Content-Type set to %s", r->content_type);
        }
        else {
            r->content_type = ap_default_type(r);
        }
        if (xfer_type != 'A' && size != NULL) {
            /* We "trust" the ftp server to really serve (size) bytes... */
            apr_table_setn(r->headers_out, "Content-Length", size);
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                         "proxy: FTP: Content-Length set to %s", size);
        }
    }
    apr_table_setn(r->headers_out, "Content-Type", r->content_type);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "proxy: FTP: Content-Type set to %s", r->content_type);

    /* If an encoding has been set by mistake, delete it.
     * @@@ FIXME (e.g., for ftp://user@host/file*.tar.gz,
     * @@@        the encoding is currently set to x-gzip)
     */
    if (dirlisting && r->content_encoding != NULL)
        r->content_encoding = NULL;

    /* set content-encoding (not for dir listings, they are uncompressed)*/
    if (r->content_encoding != NULL && r->content_encoding[0] != '\0') {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
             "proxy: FTP: Content-Encoding set to %s", r->content_encoding);
        apr_table_setn(r->headers_out, "Content-Encoding", r->content_encoding);
    }

    /* wait for connection */
    if (use_port) {
        for (;;) {
            rv = apr_accept(&data_sock, local_sock, r->pool);
            if (rv == APR_EINTR) {
                continue;
            }
            else if (rv == APR_SUCCESS) {
                break;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                            "proxy: FTP: failed to accept data connection");
                return HTTP_BAD_GATEWAY;
            }
        }
    }

    /* the transfer socket is now open, create a new connection */
    data = ap_new_connection(p, r->server, data_sock, r->connection->id, r->connection->sbh);
    if (!data) {
        /*
         * the peer reset the connection already; ap_new_connection() closed
         * the socket
         */
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
          "proxy: FTP: an error occurred creating the transfer connection");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* set up the connection filters */
    ap_run_install_transport_filters(data, data_sock);

    /*
     * VI: Receive the Response ------------------------
     *
     * Get response from the remote ftp socket, and pass it up the filter chain.
     */

    /* send response */
    r->sent_bodyct = 1;

    if (dirlisting) {
        /* insert directory filter */
        ap_add_output_filter("PROXY_SEND_DIR", NULL, r, r->connection);
    }

    /* send body */
    if (!r->header_only) {

        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "proxy: FTP: start body send");

        /* read the body, pass it to the output filters */
        while (ap_get_brigade(data->input_filters, bb, AP_MODE_EXHAUSTIVE,
                              APR_BLOCK_READ, 0) == APR_SUCCESS) {
            if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
                ap_pass_brigade(r->output_filters, bb);
                break;
            }
            if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS) {
                /* Ack! Phbtt! Die! User aborted! */
                break;
            }
            apr_brigade_cleanup(bb);
        }
    }
    ap_flush_conn(data);
    apr_socket_close(data_sock);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "proxy: FTP: Closing Data connection.");

    /* Retrieve the final response for the RETR or LIST commands */
    rc = proxy_ftp_command(NULL, r, origin, bb, &ftpmessage);
    apr_brigade_cleanup(bb);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "proxy: FTP: end body send");

    /*
     * VII: Clean Up -------------
     *
     * If there are no KeepAlives, or if the connection has been signalled to
     * close, close the socket and clean up
     */

    /* finish */
    rc = proxy_ftp_command("QUIT" CRLF,
                           r, origin, bb, &ftpmessage);
    /* responses: 221, 500 */
    /* 221 Service closing control connection. */
    /* 500 Syntax error, command unrecognized. */
    ap_flush_conn(origin);
    if (origin_sock) {
        apr_socket_close(origin_sock);
        origin_sock = NULL;
    }
    apr_brigade_destroy(bb);
    return OK;
}

static void ap_proxy_ftp_register_hook(apr_pool_t *p)
{
    /* hooks */
    proxy_hook_scheme_handler(ap_proxy_ftp_handler, NULL, NULL, APR_HOOK_MIDDLE);
    proxy_hook_canon_handler(ap_proxy_ftp_canon, NULL, NULL, APR_HOOK_MIDDLE);
    /* filters */
    ap_register_output_filter("PROXY_SEND_DIR", ap_proxy_send_dir_filter, AP_FTYPE_CONTENT);
}

module AP_MODULE_DECLARE_DATA proxy_ftp_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    ap_proxy_ftp_register_hook  /* register hooks */
};
