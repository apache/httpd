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

/* Utility routines for Apache proxy */

#include "mod_proxy.h"
#include "http_main.h"
#include "md5.h"

/* already called in the knowledge that the characters are hex digits */
int
proxy_hex2c(const char *x)
{
    int i, ch;

    ch = x[0];
    if (isdigit(ch)) i = ch - '0';
    else if (isupper(ch)) i = ch - ('A' - 10);
    else i = ch - ('a' - 10);
    i <<= 4;

    ch = x[1];
    if (isdigit(ch)) i += ch - '0';
    else if (isupper(ch)) i += ch - ('A' - 10);
    else i += ch - ('a' - 10);
    return i;
}

void
proxy_c2hex(int ch, char *x)
{
    int i;

    x[0] = '%';
    i = (ch & 0xF0) >> 4;
    if (i >= 10) x[1] = ('A' - 10) + i;
    else x[1] = '0' + i;

    i = ch & 0x0F;
    if (i >= 10) x[2] = ('A' - 10) + i;
    else x[2] = '0' + i;
}

/*
 * canonicalise a URL-encoded string
 */

/*
 * Convert a URL-encoded string to canonical form.
 * It decodes characters which need not be encoded,
 * and encodes those which must be encoded, and does not touch
 * those which must not be touched.
 */
char *
proxy_canonenc(pool *p, const char *x, int len, enum enctype t, int isenc)
{
    int i, j, ispath, ch;
    char *y;
    const char *allowed;  /* characters which should not be encoded */
    const char *reserved;  /* characters which much not be en/de-coded */

/* N.B. in addition to :@&=, this allows ';' in an http path
 * and '?' in an ftp path -- this may be revised
 * 
 * Also, it makes a '+' character in a search string reserved, as
 * it may be form-encoded. (Although RFC 1738 doesn't allow this -
 * it only permits ; / ? : @ = & as reserved chars.)
 */
    if (t == enc_path) allowed = "$-_.+!*'(),;:@&=";
    else if (t == enc_search) allowed = "$-_.!*'(),;:@&=";
    else if (t == enc_user) allowed = "$-_.+!*'(),;@&=";
    else if (t == enc_fpath) allowed = "$-_.+!*'(),?:@&=";
    else /* if (t == enc_parm) */ allowed = "$-_.+!*'(),?/:@&=";

    if (t == enc_path) reserved = "/";
    else if (t == enc_search) reserved = "+";
    else reserved = "";

    y = palloc(p, 3*len+1);
    ispath = (t == enc_path);

    for (i=0, j=0; i < len; i++, j++)
    {
/* always handle '/' first */
	ch = x[i];
	if (ind(reserved, ch) != -1)
	{
	    y[j] = ch;
	    continue;
	}
/* decode it if not already done */
	if (isenc && ch == '%')
	{
	    if (!isxdigit(x[i+1]) || !isxdigit(x[i+2]))
		return NULL;
	    ch = proxy_hex2c(&x[i+1]);
	    i += 2;
	    if (ch != 0 && ind(reserved, ch) != -1)
	    {  /* keep it encoded */
		proxy_c2hex(ch, &y[j]);
		j += 2;
		continue;
	    }
	}
/* recode it, if necessary */
	if (!isalnum(ch) && ind(allowed, ch) == -1)
	{
	    proxy_c2hex(ch, &y[j]);
	    j += 2;
	} else y[j] = ch;
    }
    y[j] = '\0';
    return y;
}

/*
 * Parses network-location.
 *    urlp           on input the URL; on output the path, after the leading /
 *    user           NULL if no user/password permitted
 *    password       holder for password
 *    host           holder for host
 *    port           port number; only set if one is supplied.
 *
 * Returns an error string.
 */
char *
proxy_canon_netloc(pool *pool, char **const urlp, char **userp,
    char **passwordp, char **hostp, int *port)
{
    int i;
    char *p, *host, *url=*urlp;

    if (url[0] != '/' || url[1] != '/') return "Malformed URL";
    host = url + 2;
    url = strchr(host, '/');
    if (url == NULL)
	url = "";
    else
	*(url++) = '\0';  /* skip seperating '/' */

    if (userp != NULL)
    {
	char *user=NULL, *password = NULL;
	p = strchr(host, '@');

	if (p != NULL)
	{
	    *p = '\0';
	    user = host;
	    host = p + 1;

/* find password */
	    p = strchr(user, ':');
	    if (p != NULL)
	    {
		*p = '\0';
		password = proxy_canonenc(pool, p+1, strlen(p+1), enc_user, 1);
		if (password == NULL)
		    return "Bad %-escape in URL (password)";
	    }

	    user = proxy_canonenc(pool, user, strlen(user), enc_user, 1);
	    if (user == NULL) return "Bad %-escape in URL (username)";
	}
	*userp = user;
	*passwordp = password;
    }

    p = strchr(host, ':');
    if (p != NULL)
    {
	*(p++) = '\0';
	
	for (i=0; p[i] != '\0'; i++)
	    if (!isdigit(p[i])) break;

	if (i == 0 || p[i] != '\0')
	    return "Bad port number in URL";
	*port = atoi(p);
	if (*port > 65535) return "Port number in URL > 65535";
    }
    str_tolower(host); /* DNS names are case-insensitive */
    if (*host == '\0') return "Missing host in URL";
/* check hostname syntax */
    for (i=0; host[i] != '\0'; i++)
	if (!isdigit(host[i]) && host[i] != '.')
	    break;
 /* must be an IP address */
    if (host[i] == '\0' && (inet_addr(host) == -1 || inet_network(host) == -1))
	    return "Bad IP address in URL";

    *urlp = url;
    *hostp = host;

    return NULL;
}

static const char *lwday[7]=
{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
static const char *wday[7]=
{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char *months[12]=
{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
 "Dec"};

/*
 * If the date is a valid RFC 850 date or asctime() date, then it
 * is converted to the RFC 1123 format, otherwise it is not modified.
 * This routine is not very fast at doing conversions, as it uses
 * sscanf and sprintf. However, if the date is already correctly
 * formatted, then it exits very quickly.
 */
char *
proxy_date_canon(pool *p, char *x)
{
    int wk, mday, year, hour, min, sec, mon;
    char *q, month[4], zone[4], week[4];
    
    q = strchr(x, ',');
    /* check for RFC 850 date */
    if (q != NULL && q - x > 3 && q[1] == ' ')
    {
	*q = '\0';
	for (wk=0; wk < 7; wk++)
	    if (strcmp(x, lwday[wk]) == 0) break;
	*q = ',';
	if (wk == 7) return x;  /* not a valid date */
	if (q[4] != '-' || q[8] != '-' || q[11] != ' ' || q[14] != ':' ||
	    q[17] != ':' || strcmp(&q[20], " GMT") != 0) return x;
	if (sscanf(q+2, "%u-%3s-%u %u:%u:%u %3s", &mday, month, &year,
		   &hour, &min, &sec, zone) != 7) return x;
	if (year < 70) year += 2000;
	else year += 1900;
    } else
    {
/* check for acstime() date */
	if (x[3] != ' ' || x[7] != ' ' || x[10] != ' ' || x[13] != ':' ||
	    x[16] != ':' || x[19] != ' ' || x[24] != '\0') return x;
	if (sscanf(x, "%3s %3s %u %u:%u:%u %u", week, month, &mday, &hour,
		   &min, &sec, &year) != 7) return x;
	for (wk=0; wk < 7; wk++)
	    if (strcmp(week, wday[wk]) == 0) break;
	if (wk == 7) return x;
    }

/* check date */
    for (mon=0; mon < 12; mon++) if (strcmp(month, months[mon]) == 0) break;
    if (mon == 12) return x;

    if (strlen(x) < 31) x = palloc(p, 31);
    ap_snprintf(x, strlen(x)+1, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT", wday[wk], mday,
	    months[mon], year, hour, min, sec);
    return x;
}

/*
 * Reads headers from a buffer and returns an array of headers.
 * Returns NULL on file error
 */
array_header *
proxy_read_headers(pool *pool, char *buffer, int size, BUFF *f)
{
    int gotcr, len, i, j;
    array_header *resp_hdrs;
    struct hdr_entry *hdr;
    char *p;

    resp_hdrs = make_array(pool, 10, sizeof(struct hdr_entry));
    hdr = NULL;

    gotcr = 1;
    for (;;)
    {
	len = bgets(buffer, size, f);
	if (len == -1) return NULL;
	if (len == 0) break;
	if (buffer[len-1] == '\n')
	{
	    buffer[--len] = '\0';
	    i = 1;
	} else
	    i = 0;

	if (!gotcr || buffer[0] == ' ' || buffer[0] == '\t')
	{
	    /* a continuation header */
	    if (hdr == NULL)
	    {
		/* error!! */
		if (!i)
		{
		    i = bskiplf(f);
		    if (i == -1) return NULL;
		}
		gotcr = 1;
		continue;
	    }
	    hdr->value = pstrcat(pool, hdr->value, buffer, NULL);
	}
	else if (gotcr && len == 0) break;
	else
	{
	    p = strchr(buffer, ':');
	    if (p == NULL)
	    {
		/* error!! */
		if (!gotcr)
		{
		    i = bskiplf(f);
		    if (i == -1) return NULL;
		}
		gotcr = 1;
		hdr = NULL;
		continue;
	    }
	    hdr = push_array(resp_hdrs);
	    *(p++) = '\0';
	    hdr->field = pstrdup(pool, buffer);
	    while (*p == ' ' || *p == '\t') p++;
	    hdr->value = pstrdup(pool, p);
	    gotcr = i;
	}
    }

    hdr = (struct hdr_entry *)resp_hdrs->elts;
    for (i=0; i < resp_hdrs->nelts; i++)
    {
	p = hdr[i].value;
	j = strlen(p);
	while (j > 0 && (p[j-1] == ' ' || p[j-1] == '\t')) j--;
	p[j] = '\0';
    }

    return resp_hdrs;
}

long int
proxy_send_fb(BUFF *f, request_rec *r, BUFF *f2, struct cache_req *c)
{
    char buf[IOBUFSIZE];
    long total_bytes_sent;
    register int n,o,w;
    conn_rec *con = r->connection;
    
    total_bytes_sent = 0;

    /* Since we are reading from one buffer and writing to another,
     * it is unsafe to do a soft_timeout here, at least until the proxy
     * has its own timeout handler which can set both buffers to EOUT.
     */
    hard_timeout("proxy send body", r);

    while (!con->aborted) {
	n = bread(f, buf, IOBUFSIZE);
	if (n == -1) /* input error */
	{
	    if (f2 != NULL) f2 = proxy_cache_error(c);
	    break;
	}
	if (n == 0) break; /* EOF */
        o=0;
	total_bytes_sent += n;

	if (f2 != NULL)
	    if (bwrite(f2, buf, n) != n) f2 = proxy_cache_error(c);
	
        while(n && !con->aborted) {
            w = bwrite(con->client, &buf[o], n);
            if (w <= 0) {
                if (f2 != NULL) {
                    pclosef(c->req->pool, c->fp->fd);
                    c->fp = NULL; 
                    unlink(c->tempfile);
                }
                break;
            }
	    reset_timeout(r); /* reset timeout after successful write */
            n-=w;
            o+=w;
        }
    }
    if (!con->aborted)
        bflush(con->client);
    
    kill_timeout(r);
    return total_bytes_sent;
}

/*
 * Read a header from the array, returning the first entry
 */
struct hdr_entry *
proxy_get_header(array_header *hdrs_arr, const char *name)
{
    struct hdr_entry *hdrs;
    int i;

    hdrs = (struct hdr_entry *)hdrs_arr->elts;
    for (i = 0; i < hdrs_arr->nelts; i++)
        if (hdrs[i].field != NULL && strcasecmp(name, hdrs[i].field) == 0)
	    return &hdrs[i];

    return NULL;
}

/*
 * Add to the header reply, either concatenating, or replacing existin
 * headers. It stores the pointers provided, so make sure the data
 * is not subsequently overwritten
 */
struct hdr_entry *
proxy_add_header(array_header *hdrs_arr, char *field, char *value,
	   int rep)
{
    int i;
    struct hdr_entry *hdrs;

    hdrs = (struct hdr_entry *)hdrs_arr->elts;
    if (rep)
	for (i = 0; i < hdrs_arr->nelts; i++)
	    if (hdrs[i].field != NULL && strcasecmp(field, hdrs[i].field) == 0)
	    {
		hdrs[i].value = value;
		return hdrs;
	    }
	
    hdrs = push_array(hdrs_arr);
    hdrs->field = field;
    hdrs->value = value;

    return hdrs;
}

void
proxy_del_header(array_header *hdrs_arr, const char *field)
{
    int i;
    struct hdr_entry *hdrs;

    hdrs = (struct hdr_entry *)hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; i++)
	if (hdrs[i].field != NULL && strcasecmp(field, hdrs[i].field) == 0)
	    hdrs[i].value = NULL;
}

/*
 * Sends response line and headers
 * A timeout should be set before calling this routine.
 */
void
proxy_send_headers(BUFF *fp, const char *respline, array_header *hdrs_arr)
{
    struct hdr_entry *hdrs;
    int i;

    hdrs = (struct hdr_entry *)hdrs_arr->elts;

    bputs(respline, fp);
    bputs("\015\012", fp);
    for (i = 0; i < hdrs_arr->nelts; i++)
    {
        if (hdrs[i].field == NULL) continue;
	bvputs(fp, hdrs[i].field, ": ", hdrs[i].value, "\015\012", NULL);
    }

    bputs("\015\012", fp);
}


/*
 * list is a comma-separated list of case-insensitive tokens, with
 * optional whitespace around the tokens.
 * The return returns 1 if the token val is found in the list, or 0
 * otherwise.
 */
int
proxy_liststr(const char *list, const char *val)
{
    int len, i;
    const char *p;

    len = strlen(val);

    while (list != NULL)
    {
	p = strchr(list, ',');
	if (p != NULL)
	{
	    i = p - list;
	    do p++; while (isspace(*p));
	} 
	else
	    i = strlen(list);

	while (i > 0 && isspace(list[i-1])) i--;
	if (i == len && strncasecmp(list, val, len) == 0) return 1;
	list = p;
    }
    return 0;
}

void
proxy_hash(const char *it, char *val,int ndepth,int nlength)
{
    MD5_CTX context;
    unsigned char digest[16];
    char tmp[22];
    int i, k, d;
    unsigned int x;
    static const char table[64]=
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@";

    MD5Init(&context);
    MD5Update(&context, (const unsigned char *)it, strlen(it));
    MD5Final(digest, &context);

/* encode 128 bits as 22 characters, using a modified uuencoding */
/* the encoding is 3 bytes -> 4 characters
 * i.e. 128 bits is 5 x 3 bytes + 1 byte -> 5 * 4 characters + 2 characters
 */
    for (i=0, k=0; i < 15; i += 3)
    {
	x = (digest[i] << 16) | (digest[i+1] << 8) | digest[i+2];
	tmp[k++] = table[x >> 18];
	tmp[k++] = table[(x >> 12) & 0x3f];
	tmp[k++] = table[(x >> 6) & 0x3f];
	tmp[k++] = table[x & 0x3f];
    }
/* one byte left */
    x = digest[15];
    tmp[k++] = table[x >> 2];  /* use up 6 bits */
    tmp[k++] = table[(x << 4) & 0x3f];
    /* now split into directory levels */

    for(i=k=d=0 ; d < ndepth ; ++d)
	{
	strncpy(&val[i],&tmp[k],nlength);
	k+=nlength;
	val[i+nlength]='/';
	i+=nlength+1;
	}
    memcpy(&val[i],&tmp[k],22-k);
    val[i+22-k]='\0';
}

/*
 * Converts 8 hex digits to a time integer
 */
int
proxy_hex2sec(const char *x)
{
    int i, ch;
    unsigned int j;

    for (i=0, j=0; i < 8; i++)
    {
	ch = x[i];
	j <<= 4;
	if (isdigit(ch)) j |= ch - '0';
	else if (isupper(ch)) j |= ch - ('A' - 10);
	else j |= ch - ('a' - 10);
    }
    if (j == 0xffffffff) return -1;  /* so that it works with 8-byte ints */
    else return j;
}

/*
 * Converts a time integer to 8 hex digits
 */
void
proxy_sec2hex(int t, char *y)
{
    int i, ch;
    unsigned int j=t;

    for (i=7; i >= 0; i--)
    {
	ch = j & 0xF;
	j >>= 4;
	if (ch >= 10) y[i] = ch + ('A' - 10);
	else y[i] = ch + '0';
    }
    y[8] = '\0';
}

void
proxy_log_uerror(const char *routine, const char *file, const char *err,
	   server_rec *s)
{
    char *p, *q;

    q = get_time();
    p = strerror(errno);

    if (err != NULL)
    {
	fprintf(s->error_log, "[%s] %s\n", q, err);
	if (file != NULL)
	    fprintf(s->error_log, "- %s: %s: %s\n", routine, file, p);
	else
	    fprintf(s->error_log, "- %s: %s\n", routine, p);
    } else
    {
	if (file != NULL)
	    fprintf(s->error_log, "[%s] %s: %s: %s\n", q, routine, file, p);
	else
	    fprintf(s->error_log, "[%s] %s: %s\n", q, routine, p);
    }

    fflush(s->error_log);
}

BUFF *
proxy_cache_error(struct cache_req *c)
{
    proxy_log_uerror("write", c->tempfile, "proxy: error writing to cache file",
        c->req->server);
    pclosef(c->req->pool, c->fp->fd);
    c->fp = NULL; 
    unlink(c->tempfile);
    return NULL;
}

int
proxyerror(request_rec *r, const char *message)
{
    r->status = SERVER_ERROR;
    r->status_line = "500 Proxy Error";
    r->content_type = "text/html";

    send_http_header(r);
    soft_timeout("proxy error", r);

    rvputs(r, "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\015\012\
<html><head><title>Proxy Error</title><head>\015\012<body><h1>Proxy Error\
</h1>\015\012The proxy server could not handle this request.\
\015\012<p>\015\012Reason: <b>", message, "</b>\015\012</body><html>\015\012",
	   NULL);

    kill_timeout(r);
    return OK;
}

/*
 * This routine returns its own error message
 */
const char *
proxy_host2addr(const char *host, struct hostent *reqhp)
{
    int i;
    struct hostent *hp;
    static struct hostent hpbuf;
    static u_long ipaddr;

    for (i=0; host[i] != '\0'; i++)
	if (!isdigit(host[i]) && host[i] != '.')
	    break;

    if (host[i] != '\0')
    {
	hp = gethostbyname(host);
	if (hp == NULL)
	    return "Host not found";
    } else
    {
	ipaddr = inet_addr(host);
	hp = gethostbyaddr((char *)&ipaddr, sizeof(u_long), AF_INET);
	if (hp == NULL) {
	    memchr(&hpbuf, 0, sizeof(hpbuf));
	    hpbuf.h_name = 0;
	    hpbuf.h_addrtype = AF_INET;
	    hpbuf.h_length = sizeof(u_long);
	    hpbuf.h_addr_list = malloc(2 * sizeof(char*));
	    hpbuf.h_addr_list[0] = (char*)&ipaddr;
	    hpbuf.h_addr_list[1] = 0;
	    hp = &hpbuf;
	}
    }
    memcpy(reqhp, hp, sizeof(struct hostent));
    if (hpbuf.h_addr_list != NULL)
	free(hpbuf.h_addr_list);
    return NULL;
}

int
proxy_doconnect(int sock, struct sockaddr_in *addr, request_rec *r)
{
    int i;

    hard_timeout("proxy connect", r);
    do	i = connect(sock, (struct sockaddr *)addr, sizeof(struct sockaddr_in));
    while (i == -1 && errno == EINTR);
    if (i == -1) proxy_log_uerror("connect", NULL, NULL, r->server);
    kill_timeout(r);

    return i;
}

