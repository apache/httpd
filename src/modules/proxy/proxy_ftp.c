/* ====================================================================
 * Copyright (c) 1996,1997 The Apache Group.  All rights reserved.
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

/* FTP routines for Apache proxy */

#include "mod_proxy.h"
#include "http_main.h"

extern int find_ct(request_rec *r);

/*
 * Decodes a '%' escaped string, and returns the number of characters
 */
static int
decodeenc(char *x)
{
    int i, j, ch;

    if (x[0] == '\0') return 0; /* special case for no characters */
    for (i=0, j=0; x[i] != '\0'; i++, j++)
    {
/* decode it if not already done */
	ch = x[i];
	if ( ch == '%' && isxdigit(x[i+1]) && isxdigit(x[i+2]))
	{
	    ch = proxy_hex2c(&x[i+1]);
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
static int
ftp_check_string(const char *x)
{
    int i, ch;

    for (i=0; x[i] != '\0'; i++)
    {
	ch = x[i];
	if ( ch == '%' && isxdigit(x[i+1]) && isxdigit(x[i+2]))
	{
	    ch = proxy_hex2c(&x[i+1]);
	    i += 2;
	}
	if (ch == '\015' || ch == '\012' || (ch & 0x80)) return 0;
    }
    return 1;
}

/*
 * Canonicalise ftp URLs.
 */
int
proxy_ftp_canon(request_rec *r, char *url)
{
    char *user, *password, *host, *path, *parms, *p, sport[7];
    pool *pool=r->pool;
    const char *err;
    int port;

    port = DEFAULT_FTP_PORT;
    err = proxy_canon_netloc(pool, &url, &user, &password, &host, &port);
    if (err) return BAD_REQUEST;
    if (user != NULL && !ftp_check_string(user)) return BAD_REQUEST;
    if (password != NULL && !ftp_check_string(password)) return BAD_REQUEST;

/* now parse path/parameters args, according to rfc1738 */
/* N.B. if this isn't a true proxy request, then the URL path
 * (but not query args) has already been decoded.
 * This gives rise to the problem of a ; being decoded into the
 * path.
 */
    p = strchr(url, ';');
    if (p != NULL)
    {
	*(p++) = '\0';
	parms = proxy_canonenc(pool, p, strlen(p), enc_parm, r->proxyreq);
	if (parms == NULL) return BAD_REQUEST;
    } else
	parms = "";

    path = proxy_canonenc(pool, url, strlen(url), enc_path, r->proxyreq);
    if (path == NULL) return BAD_REQUEST;
    if (!ftp_check_string(path)) return BAD_REQUEST;

    if (!r->proxyreq && r->args != NULL)
    {
	if (p != NULL)
	{
	    p = proxy_canonenc(pool, r->args, strlen(r->args), enc_parm, 1);
	    if (p == NULL) return BAD_REQUEST;
	    parms = pstrcat(pool, parms, "?", p, NULL);
	}
	else
	{
	    p = proxy_canonenc(pool, r->args, strlen(r->args), enc_path, 1);
	    if (p == NULL) return BAD_REQUEST;
	    path = pstrcat(pool, path, "?", p, NULL);
	}
	r->args = NULL;
    }

/* now, rebuild URL */

    if (port != DEFAULT_FTP_PORT) ap_snprintf(sport, sizeof(sport), ":%d", port);
    else sport[0] = '\0';

    r->filename = pstrcat(pool, "proxy:ftp://", (user != NULL) ? user : "",
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
static int
ftp_getrc(BUFF *f)
{
    int i, len, status;
    char linebuff[100], buff[5];

    len = bgets(linebuff, 100, f);
    if (len == -1) return -1;
/* check format */
    if (len < 5 || !isdigit(linebuff[0]) || !isdigit(linebuff[1]) ||
	!isdigit(linebuff[2]) || (linebuff[3] != ' ' && linebuff[3] != '-'))
	status = 0;
    else
	status = 100 * linebuff[0] + 10 * linebuff[1] + linebuff[2] - 111 * '0';

    Explain1("FTP: ftp_getrc() status = %d", status);
    
    if (linebuff[len-1] != '\n')
    {
	i = bskiplf(f);
    }

/* skip continuation lines */    
    if (linebuff[3] == '-')
    {
	memcpy(buff, linebuff, 3);
	buff[3] = ' ';
	do
	{
	    len = bgets(linebuff, 100, f);
	    if (len == -1) return -1;
	    if (linebuff[len-1] != '\n')
	    {
		i = bskiplf(f);
	    }
	} while (memcmp(linebuff, buff, 4) != 0);
    }

    return status;
}

static long int
send_dir(BUFF *f, request_rec *r, BUFF *f2, struct cache_req *c, char *url)
{
    char buf[IOBUFSIZE];
    char buf2[IOBUFSIZE];
    char *filename;
    char urlptr[HUGE_STRING_LEN];
    long total_bytes_sent;
    register int n, o, w;
    conn_rec *con = r->connection;

    ap_snprintf(buf, sizeof(buf), "<HTML><HEAD><TITLE>%s</TITLE></HEAD><BODY><H1>Directory %s</H1><HR><PRE>", url, url);
    bwrite(con->client, buf, strlen(buf));
    if (f2 != NULL) bwrite(f2, buf, strlen(buf));
    total_bytes_sent=strlen(buf);
    while(!con->aborted)
    {
        n = bgets(buf, IOBUFSIZE, f);
        if (n == -1) /* input error */
        {
            if (f2 != NULL) f2 = proxy_cache_error(c);
            break;
        }
        if (n == 0) break; /* EOF */
        if(buf[0]=='l')
        {
            char *link;

            link=strstr(buf, " -> ");
            filename=link;
            do filename--; while (filename[0]!=' ');
            *(filename++)=0;
            *(link++)=0;
            ap_snprintf(urlptr, sizeof(urlptr), "%s%s%s",url,(url[strlen(url)-1]=='/' ? "" : "/"), filename);
            ap_snprintf(buf2, sizeof(urlptr), "%s <A HREF=\"%s\">%s %s</A>\015\012", buf, urlptr, filename, link);
            strncpy(buf, buf2, sizeof(buf)-1);
	    buf[sizeof(buf)-1] = '\0';
            n=strlen(buf);
        }
        else if(buf[0]=='d' || buf[0]=='-' || buf[0]=='l')
        {
            filename=strrchr(buf, ' ');
            *(filename++)=0;
            filename[strlen(filename)-1]=0;
            /* Special handling for '.' and '..' */
            if (!strcmp(filename, "."))
            {
                ap_snprintf(urlptr, sizeof(urlptr), "%s",url);
                ap_snprintf(buf2, sizeof(buf2), "%s <A HREF=\"%s\">%s</A>\015\012", buf, urlptr, filename);
            }
            else if (!strcmp(filename, ".."))
            {
                char temp[200];
                char newpath[200];
                char *method, *host, *path, *newfile;
   
                strncpy(temp, url, sizeof(temp)-1);
		temp[sizeof(temp)-1] = '\0';
                method=temp;

                host=strchr(method,':');
                if (host == NULL) host="";
                else *(host++)=0;
                host++; host++;
                
                path=strchr(host,'/');
                if (path == NULL) path="";
                else *(path++)=0;
                
                strncpy(newpath, path, sizeof(newpath)-1);
		newpath[sizeof(newpath)-1] = '\0';
                newfile=strrchr(newpath,'/');
                if (newfile) *(newfile)=0;
                else newpath[0]=0;

                ap_snprintf(urlptr, sizeof(urlptr), "%s://%s/%s",method,host,newpath);
                ap_snprintf(buf2, sizeof(buf2), "%s <A HREF=\"%s\">%s</A>\015\012", buf, urlptr, filename);
            }
            else 
            {
                ap_snprintf(urlptr, sizeof(urlptr), "%s%s%s",url,(url[strlen(url)-1]=='/' ? "" : "/"), filename);
                ap_snprintf(buf2, sizeof(buf2), "%s <A HREF=\"%s\">%s</A>\015\012", buf, urlptr, filename);
            }
            strncpy(buf, buf2, sizeof(buf));
	    buf[sizeof(buf)-1] = '\0';
            n=strlen(buf);
        }      

        o=0;
	total_bytes_sent += n;

	if (f2 != NULL)
	    if (bwrite(f2, buf, n) != n) f2 = proxy_cache_error(c);
	
        while(n && !r->connection->aborted) {
            w = bwrite(con->client, &buf[o], n);
	    if (w <= 0)
		break;
	    reset_timeout(r); /* reset timeout after successfule write */
            n-=w;
            o+=w;
        }
    }
    ap_snprintf(buf, sizeof(buf), "</PRE><HR><I><A HREF=\"http://www.apache.org\">%s</A></I></BODY></HTML>", SERVER_VERSION);
    bwrite(con->client, buf, strlen(buf));
    if (f2 != NULL) bwrite(f2, buf, strlen(buf));
    total_bytes_sent+=strlen(buf);
    bflush(con->client);
    
    return total_bytes_sent;
}

/*
 * Handles direct access of ftp:// URLs
 * Original (Non-PASV) version from
 * Troy Morrison <spiffnet@zoom.com>
 * PASV added by Chuck
 */
int
proxy_ftp_handler(request_rec *r, struct cache_req *c, char *url)
{
    char *host, *path, *p, *user, *password, *parms;
    const char *err;
    int port, userlen, i, len, sock, dsock, rc, nocache;
    int passlen = 0;
    int csd = 0;
    struct sockaddr_in server;
    struct hdr_entry *hdr;
    struct in_addr destaddr;
    array_header *resp_hdrs;
    BUFF *f, *cache;
    BUFF *data = NULL;
    pool *pool=r->pool;
    const int one=1;
    const long int zero=0L;

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
        (proxy_server_conf *)get_module_config(sconf, &proxy_module);
    struct noproxy_entry *npent=(struct noproxy_entry *)conf->noproxies->elts;
    struct nocache_entry *ncent=(struct nocache_entry *)conf->nocaches->elts;

/* stuff for PASV mode */
    unsigned int presult, h0, h1, h2, h3, p0, p1;
    unsigned int paddr;
    unsigned short pport;
    struct sockaddr_in data_addr;
    int pasvmode = 0;
    char pasv[64];
    char *pstr;
 
/* we only support GET and HEAD */

    if (r->method_number != M_GET) return NOT_IMPLEMENTED;

/* We break the URL into host, port, path-search */

    host = pstrdup(pool, url + 6);
    port = DEFAULT_FTP_PORT;
    path = strchr(host, '/');
    if (path == NULL)
	path = "";
    else
	*(path++) = '\0';

    user = password = NULL;
    nocache = 0;
    p = strchr(host, '@');
    if (p != NULL)
    {
	(*p++) = '\0';
	user = host;
	host = p;
/* find password */
	p = strchr(user, ':');
	if (p != NULL)
	{
	    *(p++) = '\0';
	    password = p;
	    passlen = decodeenc(password);
	}
	userlen = decodeenc(user);
	nocache = 1; /* don't cache when a username is supplied */
    } else
    {
	user = "anonymous";
	userlen = 9;

	password = "proxy_user@apache_host.org";
	passlen = strlen(password);
    }

    p = strchr(host, ':');
    if (p != NULL)
    {
	*(p++) = '\0';
	if (isdigit(*p))
	    port = atoi(p);
    }

/* check if ProxyBlock directive on this host */
    destaddr.s_addr = inet_addr(host);
    for (i=0; i < conf->noproxies->nelts; i++)
    {
        if ((npent[i].name != NULL && strstr(host, npent[i].name) != NULL)
          || destaddr.s_addr == npent[i].addr.s_addr || npent[i].name[0] == '*')
            return proxyerror(r, "Connect to remote machine blocked");
    }

    Explain2("FTP: connect to %s:%d",host,port);

    parms = strchr(path, ';');
    if (parms != NULL) *(parms++) = '\0';

    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    err = proxy_host2addr(host, &server.sin_addr);
    if (err != NULL) return proxyerror(r, err); /* give up */

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1)
    {
	proxy_log_uerror("socket", NULL, "proxy: error creating socket",
	    r->server);
	return SERVER_ERROR;
    }
    note_cleanups_for_fd(pool, sock);

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one,
		   sizeof(int)) == -1)
    {
	proxy_log_uerror("setsockopt", NULL,
	    "proxy: error setting reuseaddr option", r->server);
	pclosef(pool, sock);
	return SERVER_ERROR;
    }

    i = proxy_doconnect(sock, &server, r);
    if (i == -1) return proxyerror(r, "Could not connect to remote machine");

    f = bcreate(pool, B_RDWR);
    bpushfd(f, sock, sock);
/* shouldn't we implement telnet control options here? */

/* possible results: 120, 220, 421 */
    hard_timeout ("proxy ftp", r);
    i = ftp_getrc(f);
    Explain1("FTP: returned status %d", i);
    if (i == -1) return proxyerror(r, "Error reading from remote server");
    if (i != 220) return BAD_GATEWAY;

    Explain0("FTP: connected.");

    bputs("USER ", f);
    bwrite(f, user, userlen);
    bputs("\015\012", f);
    bflush(f); /* capture any errors */
    Explain1("FTP: USER %s",user);
    
/* possible results; 230, 331, 332, 421, 500, 501, 530 */
/* states: 1 - error, 2 - success; 3 - send password, 4,5 fail */
    i = ftp_getrc(f);
    Explain1("FTP: returned status %d",i);
    if (i == -1) return proxyerror(r, "Error sending to remote server");
    if (i == 530) return FORBIDDEN;
    else if (i != 230 && i != 331) return BAD_GATEWAY;
	
    if (i == 331) /* send password */
    {
	if (password == NULL) return FORBIDDEN;
	bputs("PASS ", f);
	bwrite(f, password, passlen);
	bputs("\015\012", f);
	bflush(f);
        Explain1("FTP: PASS %s",password);
/* possible results 202, 230, 332, 421, 500, 501, 503, 530 */
	i = ftp_getrc(f);
        Explain1("FTP: returned status %d",i);
	if (i == -1) return proxyerror(r, "Error sending to remote server");
	if (i == 332 || i == 530) return FORBIDDEN;
	else if (i != 230 && i != 202) return BAD_GATEWAY;
    }  

/* set the directory */
/* this is what we must do if we don't know the OS type of the remote
 * machine
 */
    for (;;)
    {
	p = strchr(path, '/');
	if (p == NULL) break;
	*p = '\0';

	len = decodeenc(path);
	bputs("CWD ", f);
	bwrite(f, path, len);
	bputs("\015\012", f);
        bflush(f);
        Explain1("FTP: CWD %s",path);
/* responses: 250, 421, 500, 501, 502, 530, 550 */
/* 1,3 error, 2 success, 4,5 failure */
	i = ftp_getrc(f);
        Explain1("FTP: returned status %d",i);
	if (i == -1) return proxyerror(r, "Error sending to remote server");
	else if (i == 550) return NOT_FOUND;
	else if (i != 250) return BAD_GATEWAY;

	path = p + 1;
    }

    if (parms != NULL && strncmp(parms, "type=", 5) == 0)
    {
	parms += 5;
	if ((parms[0] != 'd' && parms[0] != 'a' && parms[0] != 'i') ||
	    parms[1] != '\0') parms = "";
    }
    else parms = "";

    /* changed to make binary transfers the default */

    if (parms[0] != 'a')
    {
	/* set type to image */
        /* TM - Added \015\012 to the end of TYPE I, otherwise it hangs the
           connection */
	bputs("TYPE I\015\012", f);
	bflush(f);
        Explain0("FTP: TYPE I");
/* responses: 200, 421, 500, 501, 504, 530 */
	i = ftp_getrc(f);
        Explain1("FTP: returned status %d",i);
	if (i == -1) return proxyerror(r, "Error sending to remote server");
	else if (i != 200 && i != 504) return BAD_GATEWAY;
/* Allow not implemented */
	else if (i == 504) parms[0] = '\0';
    }

/* try to set up PASV data connection first */
    dsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (dsock == -1)
    { 
	proxy_log_uerror("socket", NULL, "proxy: error creating PASV socket",
	    r->server);
	pclosef(pool, sock);
        return SERVER_ERROR;
    }
    note_cleanups_for_fd(pool, dsock);

    bputs("PASV\015\012", f);
    bflush(f);
    Explain0("FTP: PASV command issued");
/* possible results: 227, 421, 500, 501, 502, 530 */
    i = bgets(pasv, sizeof(pasv), f); 

    if (i == -1)
    {
	proxy_log_uerror("command", NULL, "PASV: control connection is toast",
	    r->server);
	pclosef(pool, dsock);
	pclosef(pool, sock);
	return SERVER_ERROR;
    } else
    {
	pasv[i-1] = '\0';
	pstr = strtok(pasv, " ");	/* separate result code */
	if (pstr != NULL)
	{
	    presult = atoi(pstr);
	    pstr = strtok(NULL, "(");	/* separate address & port params */
	    if (pstr != NULL)
		pstr = strtok(NULL, ")");
	}
	else
	    presult = atoi(pasv);

	Explain1("FTP: returned status %d", presult);

	if (presult == 227 && pstr != NULL && (sscanf(pstr,
	    "%d,%d,%d,%d,%d,%d", &h3, &h2, &h1, &h0, &p1, &p0) == 6))
	{
	    /* pardon the parens, but it makes gcc happy */
            paddr = (((((h3 << 8) + h2) << 8) + h1) << 8) + h0;
            pport = (p1 << 8) + p0;
	    Explain5("FTP: contacting host %d.%d.%d.%d:%d",
		h3, h2, h1, h0, pport);
            data_addr.sin_family = AF_INET;
            data_addr.sin_addr.s_addr = htonl(paddr);
            data_addr.sin_port = htons(pport);
	    i = proxy_doconnect(dsock, &data_addr, r);

	    if (i == -1)
		return proxyerror(r, "Could not connect to remote machine");
	    else
	    {
	        data = bcreate(pool, B_RDWR); 
	        bpushfd(data, dsock, dsock);
	        pasvmode = 1;
	    }
	} else
	    pclosef(pool, dsock);	/* and try the regular way */
    }

    if (!pasvmode)	/* set up data connection */
    {
        len = sizeof(struct sockaddr_in);
        if (getsockname(sock, (struct sockaddr *)&server, &len) < 0)
        {
	    proxy_log_uerror("getsockname", NULL,
	        "proxy: error getting socket address", r->server);
	    pclosef(pool, sock);
	    return SERVER_ERROR;
        }

        dsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (dsock == -1)
        {
	    proxy_log_uerror("socket", NULL, "proxy: error creating socket",
	        r->server);
	    pclosef(pool, sock);
	    return SERVER_ERROR;
        }
        note_cleanups_for_fd(pool, dsock);

        if (setsockopt(dsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one,
		   sizeof(int)) == -1)
        {
	    proxy_log_uerror("setsockopt", NULL,
	        "proxy: error setting reuseaddr option", r->server);
	    pclosef(pool, dsock);
	    pclosef(pool, sock);
	    return SERVER_ERROR;
        }

        if (bind(dsock, (struct sockaddr *)&server,
            sizeof(struct sockaddr_in)) == -1)
        {
	    char buff[22];

	    ap_snprintf(buff, sizeof(buff), "%s:%d", inet_ntoa(server.sin_addr), server.sin_port);
	    proxy_log_uerror("bind", buff,
	        "proxy: error binding to ftp data socket", r->server);
    	    pclosef(pool, sock);
    	    pclosef(pool, dsock);
        }
        listen(dsock, 2); /* only need a short queue */
    }

/* set request */
    len = decodeenc(path);

    /* TM - if len == 0 then it must be a directory (you can't RETR nothing) */

    if(len==0)
    {
	parms="d";
    } else
    {
        bputs("SIZE ", f);
        bwrite(f, path, len);
        bputs("\015\012", f);
        bflush(f);
        Explain1("FTP: SIZE %s",path);
        i = ftp_getrc(f);
        Explain1("FTP: returned status %d", i);
        if (i != 500) /* Size command not recognized */
        {
            if (i==550) /* Not a regular file */
            {
                Explain0("FTP: SIZE shows this is a directory");
                parms="d";
                bputs("CWD ", f);
                bwrite(f, path, len);
                bputs("\015\012", f);
                bflush(f);
                Explain1("FTP: CWD %s",path);
                i = ftp_getrc(f);
                Explain1("FTP: returned status %d", i);
                if (i == -1) return proxyerror(r, "Error sending to remote server");
                else if (i == 550) return NOT_FOUND;
                else if (i != 250) return BAD_GATEWAY;
                path=""; len=0;
            }
        }
    }
            
    if (parms[0] == 'd')
    {
	if (len != 0) bputs("LIST ", f);
	else bputs("LIST -lag", f);
        Explain1("FTP: LIST %s",(len==0 ? "" : path));
    }
    else
    {
        bputs("RETR ", f);
        Explain1("FTP: RETR %s",path);
    }
    bwrite(f, path, len);
    bputs("\015\012", f);
    bflush(f);
/* RETR: 110, 125, 150, 226, 250, 421, 425, 426, 450, 451, 500, 501, 530, 550
   NLST: 125, 150, 226, 250, 421, 425, 426, 450, 451, 500, 501, 502, 530 */
    rc = ftp_getrc(f);
    Explain1("FTP: returned status %d",rc);
    if (rc == -1) return proxyerror(r, "Error sending to remote server");
    if (rc == 550)
    {
       Explain0("FTP: RETR failed, trying LIST instead");
       parms="d";
       bputs("CWD ", f);
       bwrite(f, path, len);
       bputs("\015\012", f);
       bflush(f);
       Explain1("FTP: CWD %s", path);
       rc = ftp_getrc(f);
       Explain1("FTP: returned status %d", rc);
       if (rc == -1) return proxyerror(r, "Error sending to remote server");
       if (rc == 550) return NOT_FOUND;
       if (rc != 250) return BAD_GATEWAY;

       bputs("LIST -lag\015\012", f);
       bflush(f);
       Explain0("FTP: LIST -lag");
       rc = ftp_getrc(f);
       Explain1("FTP: returned status %d", rc);
       if (rc == -1) return proxyerror(r, "Error sending to remote server");
    }   
    if (rc != 125 && rc != 150 && rc != 226 && rc != 250) return BAD_GATEWAY;
    kill_timeout(r);

    r->status = 200;
    r->status_line = "200 OK";

    resp_hdrs = make_array(pool, 2, sizeof(struct hdr_entry));
    if (parms[0] == 'd')
	proxy_add_header(resp_hdrs, "Content-Type", "text/html", HDR_REP);
    else
    {
        find_ct(r);
        if(r->content_type != NULL)
        {
            proxy_add_header(resp_hdrs, "Content-Type", r->content_type,
		HDR_REP);
            Explain1("FTP: Content-Type set to %s",r->content_type);
        } else
	{
	    proxy_add_header(resp_hdrs, "Content-Type", "text/plain", HDR_REP);
	}
    }

/* check if NoCache directive on this host */ 
    for (i=0; i < conf->nocaches->nelts; i++)
    {
        if ((ncent[i].name != NULL && strstr(host, ncent[i].name) != NULL)
          || destaddr.s_addr == ncent[i].addr.s_addr || ncent[i].name[0] == '*')
            nocache = 1;
    }

    i = proxy_cache_update(c, resp_hdrs, "FTP", nocache);

    if (i != DECLINED)
    {
	pclosef(pool, dsock);
	pclosef(pool, sock);
	return i;
    }
    cache = c->fp;

    if (!pasvmode)	/* wait for connection */
    {
        hard_timeout ("proxy ftp data connect", r);
        len = sizeof(struct sockaddr_in);
        do csd = accept(dsock, (struct sockaddr *)&server, &len);
        while (csd == -1 && errno == EINTR);
        if (csd == -1)
        {
	    proxy_log_uerror("accept", NULL,
	        "proxy: failed to accept data connection", r->server);
	    pclosef(pool, dsock);
	    pclosef(pool, sock);
	    proxy_cache_error(c);
	    return BAD_GATEWAY;
        }
        note_cleanups_for_fd(pool, csd);
        data = bcreate(pool, B_RDWR);
        bpushfd(data, csd, -1);
	kill_timeout(r);
    }

    hard_timeout ("proxy receive", r);
/* send response */
/* write status line */
    if (!r->assbackwards)
	rvputs(r, SERVER_PROTOCOL, " ", r->status_line, "\015\012", NULL);
    if (cache != NULL)
	if (bvputs(cache, SERVER_PROTOCOL, " ", r->status_line, "\015\012",
		   NULL) == -1)
	    cache = proxy_cache_error(c);

/* send headers */
    len = resp_hdrs->nelts;
    hdr = (struct hdr_entry *)resp_hdrs->elts;
    for (i=0; i < len; i++)
    {
	if (hdr[i].field == NULL || hdr[i].value == NULL ||
	    hdr[i].value[0] == '\0') continue;
	if (!r->assbackwards)
	    rvputs(r, hdr[i].field, ": ", hdr[i].value, "\015\012", NULL);
	if (cache != NULL)
	    if (bvputs(cache, hdr[i].field, ": ", hdr[i].value, "\015\012",
		       NULL) == -1)
		cache = proxy_cache_error(c);
    }

    if (!r->assbackwards) rputs("\015\012", r);
    if (cache != NULL)
	if (bputs("\015\012", cache) == -1) cache = proxy_cache_error(c);

    bsetopt(r->connection->client, BO_BYTECT, &zero);
    r->sent_bodyct = 1;
/* send body */
    if (!r->header_only)
    {
	if (parms[0] != 'd') proxy_send_fb(data, r, cache, c);
        else send_dir(data, r, cache, c, url);

	if (rc == 125 || rc == 150) rc = ftp_getrc(f);
	if (rc != 226 && rc != 250) proxy_cache_error(c);
    }
    else
    {
/* abort the transfer */
	bputs("ABOR\015\012", f);
	bflush(f);
	if (!pasvmode)
            pclosef(pool, csd);
        Explain0("FTP: ABOR");
/* responses: 225, 226, 421, 500, 501, 502 */
	i = ftp_getrc(f);
        Explain1("FTP: returned status %d",i);
    }

    kill_timeout(r);
    proxy_cache_tidy(c);

/* finish */
    bputs("QUIT\015\012", f);
    bflush(f);
    Explain0("FTP: QUIT");
/* responses: 221, 500 */    

    if (!pasvmode)
        pclosef(pool, csd);
    pclosef(pool, dsock);
    pclosef(pool, sock);

    return OK;
}

