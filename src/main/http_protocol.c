    
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
  
/*
 * http_protocol.c --- routines which directly communicate with the
 * client.
 *
 * Code originally by Rob McCool; much redone by rst.
 */

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"		/* For errors detected in basic auth
				 * common support code...
				 */

#include <stdarg.h>

#define SET_BYTES_SENT(r) \
  do { if (r->sent_bodyct) \
	  bgetopt (r->connection->client, BO_BYTECT, &r->bytes_sent); \
  } while (0)

/* Handling of conditional gets (if-modified-since); Roy owes Rob beer. 
 * This would be considerably easier if strptime or timegm were portable...
 */

const char month_snames[12][4] = {
    "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"
};

int find_month(char *mon) {
    register int x;

    for(x=0;x<12;x++)
        if(!strcmp(month_snames[x],mon))
            return x;
    return -1;
}

int later_than(struct tm *lms, char *ims) {
    char *ip;
    char mname[MAX_STRING_LEN];
    int year = 0, month = 0, day = 0, hour = 0, min = 0, sec = 0, x;

    /* Whatever format we're looking at, it will start with weekday. */
    /* Skip to first space. */
    if(!(ip = strchr(ims,' ')))
        return 0;
    else
        while(isspace(*ip))
            ++ip;

    if(isalpha(*ip)) {
        /* ctime */
        sscanf(ip,"%s %d %d:%d:%d %d",mname,&day,&hour,&min,&sec,&year);
    }
    else if(ip[2] == '-') {
        /* RFC 850 (normal HTTP) */
        char t[MAX_STRING_LEN];
        sscanf(ip,"%s %d:%d:%d",t,&hour,&min,&sec);
        t[2] = '\0';
        day = atoi(t);
        t[6] = '\0';
        strcpy(mname,&t[3]);
        x = atoi(&t[7]);
        /* Prevent wraparound from ambiguity */
        if(x < 70)
            x += 100;
        year = 1900 + x;
    }
    else {
        /* RFC 822 */
        sscanf(ip,"%d %s %d %d:%d:%d",&day,mname,&year,&hour,&min,&sec);
    }
    month = find_month(mname);

    if((x = (1900+lms->tm_year) - year))
        return x < 0;
    if((x = lms->tm_mon - month))
        return x < 0;
    if((x = lms->tm_mday - day))
        return x < 0;
    if((x = lms->tm_hour - hour))
        return x < 0;
    if((x = lms->tm_min - min))
        return x < 0;
    if((x = lms->tm_sec - sec))
        return x < 0;

    return 1;
}

static int parse_byterange (char *range, long clength, long *start, long *end)
{
    char *dash = strchr(range, '-');

    if (!dash)
	return 0;

    if ((dash == range)) {
	/* In the form "-5" */
	*start = clength - atol(dash + 1);
	*end = clength - 1;
    }
    else {
	*dash = '\0';
	dash++;
	*start = atol(range);
	if (*dash)
	    *end = atol(dash);
	else	/* "5-" */
	    *end = clength -1;
    }

    if (*start > *end)
	return 0;

    if (*end >= clength)
	*end = clength - 1;

    return 1;
}

/* This is a string I made up. Pounded on the keyboard a couple of times.
 * It's a good a way as any, I suppose, if you can't parse the document
 * beforehand (which we can't).
 */

#define BYTERANGE_BOUNDARY "13962mx38v144c9999AQdk39d2Klmx79"

int set_byterange (request_rec *r)
{
    char *range = table_get (r->headers_in, "Range");
    char *if_range = table_get (r->headers_in, "If-Range");
    char ts[MAX_STRING_LEN], *match;
    long range_start, range_end;

    /* Reasons we won't do ranges... */

    if (!r->clength || r->assbackwards) return 0;
    if (!range || strncmp(range, "bytes=", 6)) {
	table_set (r->headers_out, "Accept-Ranges", "bytes");
	return 0;
    }

    /* Check the If-Range header. Golly, this is a long if statement */

    if (if_range
	&& !((if_range[0] == '"') /* an entity tag */
	     && (match = table_get(r->headers_out, "Etag"))
	     && (match[0] == '"') && !strcasecmp(if_range, match))
	&& !((if_range[0] != '"') /* a date */
	     && (match = table_get(r->headers_out, "Last-Modified"))
	     && (!strcasecmp(if_range, match))))
	return 0;
    
    if (!strchr(range, ',')) {
	/* A single range */
	if (!parse_byterange(pstrdup(r->pool, range + 6), r->clength,
			     &range_start, &range_end))
	    return 0;

	r->byterange = 1;

	sprintf(ts, "bytes %ld-%ld/%ld", range_start, range_end,
		r->clength);
	table_set(r->headers_out, "Content-Range",
		  pstrdup(r->pool, ts));
	sprintf(ts, "%ld", range_end - range_start + 1);
	table_set(r->headers_out, "Content-Length", ts);
    }
    else {
	/* a multiple range */
	r->byterange = 2;
	table_unset(r->headers_out, "Content-Length");
    }
    
    r->status = PARTIAL_CONTENT;
    r->range = range + 6;

    return 1;
}

int each_byterange (request_rec *r, long *offset, long *length) {
    long range_start, range_end;
    char *range;

    if (!*r->range) {
	if (r->byterange > 1)
	    rvputs(r, "\015\012--", BYTERANGE_BOUNDARY, "--\015\012", NULL);
	return 0;
    }

    range = getword(r->pool, &r->range, ',');
    if (!parse_byterange(range, r->clength, &range_start, &range_end))
	return each_byterange(r, offset, length);	/* Skip this one */

    if (r->byterange > 1) {
	char *ct = r->content_type ? r->content_type : default_type(r);
	char ts[MAX_STRING_LEN];

	sprintf(ts, "%ld-%ld/%ld", range_start, range_end, r->clength);
	rvputs(r, "\015\012--", BYTERANGE_BOUNDARY, "\015\012Content-type: ",
	       ct, "\015\012Content-range: bytes ", ts, "\015\012\015\012",
	       NULL);
    }

    *offset = range_start;
    *length = range_end - range_start + 1;
    return 1;
}

int set_content_length (request_rec *r, long clength)
{
    char ts[MAX_STRING_LEN];

    r->clength = clength;

    sprintf (ts, "%ld", clength);
    table_set (r->headers_out, "Content-Length", pstrdup (r->pool, ts));

    return 0;
}

int set_keepalive(request_rec *r)
{
    char *conn = table_get (r->headers_in, "Connection");
    char *length = table_get (r->headers_out, "Content-length");

#ifdef FORHTTP11
    if ((((r->proto_num >= 1001) && (!find_token(r->pool, conn, "close")))
	 || (find_token(r->pool, conn, "keep-alive")))
#else
    if ((find_token(r->pool, conn, "keep-alive"))
#endif
	&& (r->header_only || length ||
	    ((r->proto_num >= 1001) && (r->byterange > 1 || (r->chunked = 1))))
	&& (r->server->keep_alive_timeout &&
	    (r->server->keep_alive > r->connection->keepalives))) {
	char header[26];
	int left = r->server->keep_alive - r->connection->keepalives;
	
	r->connection->keepalive = 1;
	r->connection->keepalives++;
	
#ifdef FORHTTP11
	if (r->proto_num < 1001) {
#endif
	    sprintf(header, "timeout=%d, max=%d",
		    r->server->keep_alive_timeout, left);
	    table_set (r->headers_out, "Connection", "Keep-Alive");
	    table_set (r->headers_out, "Keep-Alive", pstrdup(r->pool, header));
#ifdef FORHTTP11
	}
#endif	

	return 1;
    }

    /* We only really need to send this to HTTP/1.1 clients, but we
     * always send it anyway, because a broken proxy may identify itself
     * as HTTP/1.0, but pass our request along with our HTTP/1.1 tag
     * to a HTTP/1.1 client. Better safe than sorry.
     */
    table_set (r->headers_out, "Connection", "close");

    return 0;
}

int set_last_modified(request_rec *r, time_t mtime)
{
    char *ts, etag[MAX_STRING_LEN];
    char *if_modified_since = table_get (r->headers_in, "If-Modified-Since");
    char *if_unmodified = table_get (r->headers_in, "If-Unmodified-Since");
    char *if_nonematch = table_get (r->headers_in, "If-None-Match");
    char *if_match = table_get (r->headers_in, "If-Match");

    /* Invalid, future time... just ignore it */
    if (mtime > r->request_time) return OK;

    ts = gm_timestr_822(r->pool, mtime);
    table_set (r->headers_out, "Last-Modified", ts);

    /* Make an ETag header out of various peices of information. We use
     * the last-modified date and, if we have a real file, the
     * length and inode number - note that this doesn't have to match
     * the content-length (i.e. includes), it just has to be unique
     * for the file.
     */

    if (r->finfo.st_mode != 0)
        sprintf(etag, "\"%lx-%lx-%lx\"", r->finfo.st_ino, r->finfo.st_size,
		mtime);
    else
        sprintf(etag, "\"%lx\"", mtime);
    table_set (r->headers_out, "ETag", etag);

    /* We now do the no_cache stuff using an Expires: header (we used to
     * withhold Last-modified). However, we still want to enforce this by
     * not allowing conditional GETs.
     */

    if (r->no_cache) return OK;

    /* Check for conditional GETs --- note that we only want this check
     * to succeed if the GET was successful; ErrorDocuments *always* get sent.
     */
    
    if ((r->status < 200) || (r->status >= 300))
        return OK;

    if (if_modified_since && later_than(gmtime(&mtime), if_modified_since))
        return USE_LOCAL_COPY;
    else if (if_unmodified && !later_than(gmtime(&mtime), if_unmodified))
        return PRECONDITION_FAILED;
    else if (if_nonematch && ((if_nonematch[0] == '*') ||
			      find_token(r->pool, if_nonematch, etag)))
        return (r->method_number == M_GET) ?
	    USE_LOCAL_COPY : PRECONDITION_FAILED;
    else if (if_match && !((if_match[0] == '*') ||
			   find_token(r->pool, if_match, etag)))
        return PRECONDITION_FAILED;
    else
        return OK;
}

/*
 * Finally, real protocol stuff.
 */

static char *
getline(char *s, int n, BUFF *in)
{
    int retval = bgets (s, n, in);

    if (retval == -1) return NULL;

    if (retval > 0 && s[retval-1] == '\n') s[retval-1] = '\0';

    return s;
}

void parse_uri (request_rec *r, char *uri)
{
    const char *s;

#ifdef __EMX__
    /* Variable for OS/2 fix below. */
    int loop;
#endif

/* A proxy request contains a ':' early on, but not as first character */
    for (s=uri; s != '\0'; s++)
	if (!isalnum(*s) && *s != '+' && *s != '-' && *s != '.') break;

    if (*s == ':' && s != uri)
    {
	r->proxyreq = 1;
	r->uri = uri;
	r->args = NULL;
    }
    else if (r->method && !strcmp(r->method, "TRACE")) {
	r->proxyreq = 0;
	r->uri = uri;
	r->args = NULL;
    }
    else {
	r->proxyreq = 0;
	r->uri = getword (r->pool, &uri, '?');

#ifdef __EMX__
    /* Handle path translations for OS/2 and plug security hole. */
    /* This will prevent "http://www.wherever.com/..\..\/" from
       returning a directory for the root drive. */
    for (loop = 0; loop <= strlen(r->uri); ++loop) {
        if (r->uri[loop] == '\\')
            r->uri[loop] = '/';
};
#endif

	if (*uri) r->args= uri;
	else r->args = NULL;
    }
}

char *check_fulluri (request_rec *r, char *uri) {
  char *name, *host;
  int i, port;

  /* This routine parses full URLs, if they match the server */
  if (strncmp(uri, "http://", 7)) return uri;
  name = pstrdup(r->pool, uri + 7);
  
  /* Find the hostname, assuming a valid request */
  i = ind(name, '/');
  name[i] = '\0';

  /* Find the port */
  host = getword(r->pool, &name, ':');
  if (*name) port = atoi(name);
  else port = 80;

  /* Make sure ports patch */
  if (port != r->server->port) return uri;

  /* Save it for later use */
  r->hostname = pstrdup(r->pool, host);
  r->hostlen = 7 + i;

  /* The easy cases first */
  if (!strcasecmp(host, r->server->server_hostname)) {
    return (uri + r->hostlen);
  }
  else if (!strcmp(host, inet_ntoa(r->connection->local_addr.sin_addr))) {
    return (uri + r->hostlen);
  }

  /* Now things get a bit trickier - check the IP address(es) of the host */
  /* they gave, see if it matches ours.                                   */
  else {
    struct hostent *hp;
    int n;

    if ((hp = gethostbyname(host))) {
      for (n = 0; hp->h_addr_list[n] != NULL; n++) {
	if (r->connection->local_addr.sin_addr.s_addr ==
	    (((struct in_addr *)(hp->h_addr_list[n]))->s_addr)) {
	  return (uri + r->hostlen);
	}
      }
    }
  }
  
  return uri;
}

int read_request_line (request_rec *r)
{
    char l[HUGE_STRING_LEN];
    char *ll = l, *uri;
    conn_rec *conn = r->connection;
    int major = 1, minor = 0;	/* Assume HTTP/1.0 if non-"HTTP" protocol*/
    
    l[0] = '\0';
    if(!getline(l, HUGE_STRING_LEN, conn->client))
        return 0;
    if(!l[0]) 
        return 0;

    r->the_request = pstrdup (r->pool, l);
    r->method = getword(r->pool, &ll,' ');
    uri = getword(r->pool, &ll,' ');
    uri = check_fulluri(r, uri);
    parse_uri (r, uri);
    
    r->assbackwards = (ll[0] == '\0');
    r->protocol = pstrdup (r->pool, ll[0] ? ll : "HTTP/0.9");
    sscanf(r->protocol, "HTTP/%d.%d", &major, &minor);
    r->proto_num = 1000*major + minor;

    return 1;
}

void get_mime_headers(request_rec *r)
{
    char w[MAX_STRING_LEN];
    char *t;
    conn_rec *c = r->connection;

    while(getline(w, MAX_STRING_LEN-1, c->client)) {
        if(!w[0]) 
            return;
        if(!(t = strchr(w,':')))
            continue;
        *t++ = '\0';
        while(isspace(*t)) ++t;

	table_merge (r->headers_in, w, t);
    }
}

void check_hostalias (request_rec *r) {
  char *host = getword(r->pool, &r->hostname, ':');	/* Get rid of port */
  int port = (*r->hostname) ? atoi(r->hostname) : 80;
  server_rec *s;

  if (port && (port != r->server->port))
    return;

  if ((host[strlen(host)-1]) == '.') {
    host[strlen(host)-1] = '\0';
  }

  r->hostname = host;

  for (s = r->server->next; s; s = s->next) {
    char *names = s->names;
    
    if ((!strcasecmp(host, s->server_hostname)) && (port == s->port)) {
      r->server = r->connection->server = s;
      if (r->hostlen && !strncmp(r->uri, "http://", 7)) {
	r->uri += r->hostlen;
	parse_uri(r, r->uri);
      }
    }

    if (!names) continue;

    while (*names) {
      char *name = getword_conf (r->pool, &names);

      if ((is_matchexp(name) && !strcasecmp_match(host, name)) ||
	  (!strcasecmp(host, name))) {
	r->server = r->connection->server = s;
	if (r->hostlen && !strncmp(r->uri, "http://", 7)) {
	  r->uri += r->hostlen;
	  r->proxyreq = 0;
	}
      }
    }
  }
}

void check_serverpath (request_rec *r) {
  server_rec *s;

  /* This is in conjunction with the ServerPath code in
   * http_core, so we get the right host attached to a non-
   * Host-sending request.
   */

  for (s = r->server->next; s; s = s->next) {
    if (s->path && !strncmp(r->uri, s->path, s->pathlen))
      r->server = r->connection->server = s;
  }
}

request_rec *read_request (conn_rec *conn)
{
    request_rec *r = (request_rec *)pcalloc (conn->pool, sizeof(request_rec));

    r->request_time = time(NULL);
  
    r->connection = conn;
    r->server = conn->server;
    r->pool = make_sub_pool(conn->pool);

    conn->keptalive = conn->keepalive;
    conn->keepalive = 0;

    conn->user = NULL;
    conn->auth_type = NULL;

    r->headers_in = make_table (r->pool, 50);
    r->subprocess_env = make_table (r->pool, 50);
    r->headers_out = make_table (r->pool, 5);
    r->err_headers_out = make_table (r->pool, 5);
    r->notes = make_table (r->pool, 5);

    r->request_config = create_request_config (r->pool);
    r->per_dir_config = r->server->lookup_defaults; /* For now. */

    r->sent_bodyct = 0; /* bytect isn't for body */
    
    r->status = 200;		/* Until further notice.
				 * Only changed by die(), or (bletch!)
				 * scan_script_header...
				 */

    /* Get the request... */
    
    hard_timeout ("read", r);
    if (!read_request_line (r)) return NULL;
    if (!r->assbackwards) get_mime_headers (r);

/* handle Host header here, to get virtual server */

    if (r->hostname || (r->hostname = table_get(r->headers_in, "Host")))
      check_hostalias(r);
    else
      check_serverpath(r);

    kill_timeout (r);
    conn->keptalive = 0;   /* We now have a request - so no more short timeouts */
    
    if(!strcmp(r->method, "HEAD")) {
        r->header_only=1;
	r->method_number = M_GET;
    }
    else if(!strcmp(r->method, "GET")) 
	r->method_number = M_GET;
    else if(!strcmp(r->method,"POST")) 
        r->method_number = M_POST;
    else if(!strcmp(r->method,"PUT")) 
        r->method_number = M_PUT;
    else if(!strcmp(r->method,"DELETE")) 
        r->method_number = M_DELETE;
    else if(!strcmp(r->method,"CONNECT"))
        r->method_number = M_CONNECT;
    else if(!strcmp(r->method,"OPTIONS"))
        r->method_number = M_OPTIONS;
    else if(!strcmp(r->method,"TRACE"))
        r->method_number = M_TRACE;
    else 
        r->method_number = M_INVALID; /* Will eventually croak. */

    return r;
}

/*
 * A couple of other functions which initialize some of the fields of
 * a request structure, as appropriate for adjuncts of one kind or another
 * to a request in progress.  Best here, rather than elsewhere, since
 * *someone* has to set the protocol-specific fields...
 */

void set_sub_req_protocol (request_rec *rnew, request_rec *r)
{
    rnew->assbackwards = 1;	/* Don't send headers from this. */
    rnew->no_cache = 1;		/* Don't try to send USE_LOCAL_COPY for a
				 * fragment.
				 */
    rnew->method = "GET"; rnew->method_number = M_GET;
    rnew->protocol = "INCLUDED";

    rnew->status = 200;

    rnew->headers_in = r->headers_in;
    rnew->subprocess_env = copy_table (rnew->pool, r->subprocess_env);
    rnew->headers_out = make_table (rnew->pool, 5);
    rnew->err_headers_out = make_table (rnew->pool, 5);
    rnew->notes = make_table (rnew->pool, 5);
    
    rnew->main = r;
}

void finalize_sub_req_protocol (request_rec *sub)
{
    SET_BYTES_SENT (sub->main);
} 

/* Support for the Basic authentication protocol, and a bit for Digest.
 */

void note_auth_failure(request_rec *r)
{
    if (!strcasecmp(auth_type(r), "Basic"))
      note_basic_auth_failure(r);
    else if(!strcasecmp(auth_type(r), "Digest"))
      note_digest_auth_failure(r);
}

void note_basic_auth_failure(request_rec *r)
{
    if (strcasecmp(auth_type(r), "Basic"))
      note_auth_failure(r);
    else
      table_set (r->err_headers_out, "WWW-Authenticate",
		 pstrcat(r->pool, "Basic realm=\"", auth_name(r), "\"", NULL));
}

void note_digest_auth_failure(request_rec *r)
{
    char nonce[10];

    sprintf(nonce, "%lu", r->request_time);
    table_set (r->err_headers_out, "WWW-Authenticate",
               pstrcat(r->pool, "Digest realm=\"", auth_name(r),
                       "\", nonce=\"", nonce, "\"", NULL));
}

int get_basic_auth_pw (request_rec *r, char **pw)
{
    char *auth_line = table_get (r->headers_in, "Authorization");
    char *t;
    
    if(!(t = auth_type(r)) || strcasecmp(t, "Basic"))
        return DECLINED;

    if (!auth_name (r)) {
        log_reason ("need AuthName", r->uri, r);
	return SERVER_ERROR;
    }
    
    if(!auth_line) {
        note_basic_auth_failure (r);
	return AUTH_REQUIRED;
    }

    if (strcmp(getword (r->pool, &auth_line, ' '), "Basic")) {
        /* Client tried to authenticate using wrong auth scheme */
        log_reason ("client used wrong authentication scheme", r->uri, r);
        note_basic_auth_failure (r);
	return AUTH_REQUIRED;
    }

    t = uudecode (r->pool, auth_line);
    r->connection->user = getword_nulls (r->pool, &t, ':');
    r->connection->auth_type = "Basic";

    *pw = t;

    return OK;
}

#define RESPONSE_CODE_LIST " 200 206 301 302 304 400 401 403 404 405 411 412 500 503 501 502 "

/* New Apache routine to map error responses into array indicies 
 *  e.g.  400 -> 0,  500 -> 1,  502 -> 2 ...                     
 * the indicies have no significance
 */

char *status_lines[] = {
   "200 OK",
   "206 Partial Content",
   "301 Moved Permanently",
   "302 Found",
   "304 Not Modified",
   "400 Bad Request",
   "401 Unauthorized",
   "403 Forbidden",
   "404 Not found",
   "405 Method Not Allowed",
   "411 Length Required",
   "412 Precondition Failed",
   "500 Server error",
   "503 Out of resources",
   "501 Not Implemented",
   "502 Bad Gateway"
}; 

char *response_titles[] = {
   "200 OK",			/* Never actually sent, barring die(200,...) */
   "206 Partial Content",	/* Never sent as an error (we hope) */
   "Document moved",		/* 301 Redirect */
   "Document moved",		/* 302 Redirect */
   "304 Not Modified",		/* Never sent... 304 MUST be header only */
   "Bad Request",
   "Authorization Required",
   "Forbidden",
   "File Not found",
   "Method Not Allowed",
   "Length Required",
   "Precondition Failed",
   "Server Error",
   "Out of resources",
   "Method not implemented",
   "Bad Gateway"
};

int index_of_response(int err_no) {
   char *cptr, err_string[10];
   static char *response_codes = RESPONSE_CODE_LIST;
   int index_number;
   
   sprintf(err_string,"%3d",err_no);
   
   cptr = response_codes;
   cptr++;
   index_number = 0;
   while (*cptr && strncmp(cptr, err_string, 3)) { 
      cptr += 4;
      index_number++;
   }
   if (!*cptr) return -1;
   return index_number;
}


void basic_http_header (request_rec *r)
{
    BUFF *fd = r->connection->client;
    
    if (r->assbackwards) return;
    
    if (!r->status_line)
        r->status_line = status_lines[index_of_response(r->status)];
    
    bvputs(fd, SERVER_PROTOCOL, " ", r->status_line, "\015\012", NULL);
    bvputs(fd,"Date: ",gm_timestr_822 (r->pool, r->request_time),
	   "\015\012", NULL);
    bvputs(fd,"Server: ", SERVER_VERSION, "\015\012", NULL);
}

char *nuke_mime_parms (pool *p, char *content_type)
{
    /* How marvelous.  Arena doesn't *accept* "text/html; level=3"
     * as a MIME type, so we have to strip off the parms.
     */

#ifndef ARENA_BUG_WORKAROUND
    return content_type;
#else

    char *cp = strchr(content_type, ';');

    if (cp) {
        content_type = pstrdup (p, content_type);
	cp = strchr (content_type, ';');
	
        while (cp > content_type && isspace (cp[-1]))
	    --cp;
	*cp = '\0';
    }

    return content_type;
#endif
}

char *make_allow(request_rec *r)
{
    int allowed = r->allowed;

    return 2 + pstrcat(r->pool, (allowed & (1 << M_GET)) ? ", GET" : "",
		       (allowed & (1 << M_POST)) ? ", POST" : "",
		       (allowed & (1 << M_PUT)) ? ", PUT" : "",
		       (allowed & (1 << M_DELETE)) ? ", DELETE" : "",
		       (allowed & (1 << M_OPTIONS)) ? ", OPTIONS" : "",
		       (allowed & (1 << M_TRACE)) ? ", TRACE" : "",
		       NULL);
    
}

int send_http_trace (request_rec *r)
{
    array_header *hdrs_arr = table_elts(r->headers_in);
    table_entry *hdrs = (table_entry *)hdrs_arr->elts;
    int i;

    /* Get the original request */
    while (r->prev) r = r->prev;

    soft_timeout ("send", r);

    r->content_type = "message/http";
    send_http_header(r);
    
    /* Now we recreate the request, and echo it back */

    rvputs(r, r->method, " ", r->uri, " ", r->protocol, "\015\012", NULL);

    for (i = 0; i < hdrs_arr->nelts; ++i) {
      if (!hdrs[i].key) continue;
      rvputs(r, hdrs[i].key, ": ", hdrs[i].val, "\015\012", NULL);
    }

    kill_timeout(r);
    return OK;
}

int send_http_options(request_rec *r)
{
    BUFF *fd = r->connection->client;
    const long int zero=0L;

    if (r->assbackwards) return DECLINED;

    soft_timeout ("send", r);

    basic_http_header(r);
    bputs("Connection: close\015\012", fd);
    bvputs(fd, "Allow: ", make_allow(r), "\015\012", NULL);
    bputs("\015\012", fd);

    bsetopt(fd, BO_BYTECT, &zero);
    kill_timeout (r);

    return OK;
}

void send_http_header(request_rec *r)
{
    conn_rec *c = r->connection;
    BUFF *fd = c->client;
    const long int zero=0L;
    array_header *hdrs_arr;
    table_entry *hdrs;
    int i;
    
    core_dir_config *dir_conf =
      (core_dir_config *)get_module_config(r->per_dir_config, &core_module);
    char *default_type = dir_conf->default_type;
  
    if (r->assbackwards) {
	bsetopt(fd, BO_BYTECT, &zero);
	r->sent_bodyct = 1;
	return;
    }
    
    basic_http_header (r);

    set_keepalive (r);

    if (r->chunked)
	bputs("Transfer-Encoding: chunked\015\012", fd);

    if (r->byterange > 1)
        bvputs(fd, "Content-Type: multipart/byteranges; boundary=",
	       BYTERANGE_BOUNDARY, "\015\012", NULL);
    else if (r->content_type)
        bvputs(fd, "Content-Type: ", 
		 nuke_mime_parms (r->pool, r->content_type), "\015\012", NULL);
    else if (default_type)
        bvputs(fd, "Content-Type: ", default_type, "\015\012", NULL);
    
    if (r->content_encoding)
        bvputs(fd,"Content-Encoding: ", r->content_encoding, "\015\012", NULL);
    
    if (r->content_language)
        bvputs(fd,"Content-Language: ", r->content_language, "\015\012", NULL);

    /* If it's a TRACE, or if they sent us Via:, send one back */
    if ((r->method_number == M_TRACE) || table_get(r->headers_in, "Via"))
        bvputs(fd, "Via: ",
	SERVER_PROTOCOL + (!strncmp(SERVER_PROTOCOL, "HTTP/", 5) ? 5 : 0), " ",
	construct_server(r->pool, r->server->server_hostname, r->server->port),
	       " (", SERVER_VERSION, ")\015\012", NULL);
    
    /* We now worry about this here */

    if (r->no_cache && (r->proto_num >= 1001))
        bputs ("Cache-Control: private\015\012", fd);
    else if (r->no_cache)
        bvputs(fd,"Expires: ", gm_timestr_822(r->pool, r->request_time),
	       "\015\012", NULL);

    hdrs_arr = table_elts(r->headers_out);
    hdrs = (table_entry *)hdrs_arr->elts;
    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key) continue;
	if (r->no_cache && !strcasecmp(hdrs[i].key, "Expires")) continue;
	bvputs(fd, hdrs[i].key, ": ", hdrs[i].val, "\015\012", NULL);
    }

    hdrs_arr = table_elts(r->err_headers_out);
    hdrs = (table_entry *)hdrs_arr->elts;
    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key) continue;
	if (r->no_cache && !strcasecmp(hdrs[i].key, "Expires")) continue;
	bvputs(fd, hdrs[i].key, ": ", hdrs[i].val, "\015\012", NULL);
    }

    bputs("\015\012",fd);

    if (c->keepalive)
	bflush(fd);  /* This is to work around a Netscape bug */

    bsetopt(fd, BO_BYTECT, &zero);
    r->sent_bodyct = 1;		/* Whatever follows is real body stuff... */

    /* Set buffer flags for the body */
    if (r->chunked) bsetflag(fd, B_CHUNK, 1);
}

void finalize_request_protocol (request_rec *r) {
    BUFF *fd = r->connection->client;

    /* Turn off chunked encoding */

    if (r->chunked) {
        bsetflag(fd, B_CHUNK, 0);
	bputs("0\015\012", fd);
	/* If we had footer "headers", we'd send them now */
	bputs("\015\012", fd);
    }

}

int setup_client_block (request_rec *r)
{
    char *tenc = table_get (r->headers_in, "Transfer-Encoding");
    char *lenp = table_get (r->headers_in, "Content-length");

    if ((r->method_number != M_POST) && (r->method_number != M_PUT))
	return OK;

    if (tenc) {
	if (strcasecmp(tenc, "chunked")) {
	    log_printf(r->server, "Unknown Transfer-Encoding %s", tenc);
	    return BAD_REQUEST;
	}
	r->read_chunked = 1;
    }
    else {
	if (!lenp) {
	    log_reason("POST or PUT without Content-length:", r->filename, r);
	    return LENGTH_REQUIRED;
	}
	r->remaining = atol(lenp);
    }

    return OK;
}

int should_client_block (request_rec *r) {
    return (r->method_number == M_POST || r->method_number == M_PUT);
}

static int rd_chunk_size (BUFF *b) {
    int chunksize = 0;
    int c;

    while ((c = bgetc (b)) != EOF && isxdigit (c)) {
        int xvalue = 0;

        if (c >= '0' && c <= '9') xvalue = c - '0';
        else if (c >= 'A' && c <= 'F') xvalue = c - 'A' + 0xa;
        else if (c >= 'a' && c <= 'f') xvalue = c - 'a' + 0xa;

        chunksize = (chunksize << 4) | xvalue;
    }

    /* Skip to end of line, bypassing chunk options, if present */

    while (c != '\n' && c != EOF)
        c = bgetc (b);

    return (c == EOF) ? -1 : chunksize;
}

long read_client_block (request_rec *r, char *buffer, int bufsiz)
{
    long c, len_read, len_to_read = r->remaining;

    if (!r->read_chunked) {	/* Content-length read */
	if (len_to_read >= bufsiz)
	    len_to_read = bufsiz - 1;
	len_read = bread(r->connection->client, buffer, len_to_read);
	r->remaining -= len_read;
	return len_read;
    }

    /* Handle chunked reading */
    if (len_to_read == 0) {
	len_to_read = rd_chunk_size(r->connection->client);
	if (len_to_read == 0) {
	    /* Skip over any "footers" */
	    do c = bgets(buffer, bufsiz, r->connection->client);
	    while ((c > 0) && (*buffer != '\015') && (*buffer != '\012'));
	    return 0;
	}
    }
    if (len_to_read >= bufsiz) {
	r->remaining = len_to_read - bufsiz - 1;
	len_to_read = bufsiz - 1;
    }
    else
	r->remaining = 0;
    
    len_read = bread(r->connection->client, buffer, len_to_read);
    if (r->remaining == 0) {
	do c = bgetc (r->connection->client);
	while (c != '\n' && c != EOF);
    }

    return len_read;
}

long send_fd(FILE *f, request_rec *r) { return send_fd_length(f, r, -1); }

long send_fd_length(FILE *f, request_rec *r, long length)
{
    char buf[IOBUFSIZE];
    long total_bytes_sent;
    register int n, w, o, len;
    conn_rec *c = r->connection;
    
    if (length == 0) return 0;

    total_bytes_sent = 0;
    while (!r->connection->aborted) {
	if ((length > 0) && (total_bytes_sent + IOBUFSIZE) > length)
	    len = length - total_bytes_sent;
	else len = IOBUFSIZE;

        while ((n= fread(buf, sizeof(char), len, f)) < 1
	       && ferror(f) && errno == EINTR)
	    continue;
	
	if (n < 1) {
            break;
        }
        o=0;
	total_bytes_sent += n;
	
        while(n && !r->connection->aborted) {
            w=bwrite(c->client, &buf[o], n);
	    if(w <= 0)
		break;
	    reset_timeout(r); /* reset timeout after successfule write */
            n-=w;
	    o+=w;
        }
    }

    if (length > 0) bflush(c->client);
    
    SET_BYTES_SENT(r);
    return total_bytes_sent;
}

int rputc (int c, request_rec *r)
{
    if (r->connection->aborted) return EOF;
    bputc(c, r->connection->client);
    SET_BYTES_SENT(r);
    return c;
}

int
rputs(const char *str, request_rec *r)
{
    if (r->connection->aborted) return EOF;
    SET_BYTES_SENT(r);
    return bputs(str, r->connection->client);
}

int rprintf(request_rec *r,const char *fmt,...)
    {
    va_list vlist;
    int n;

    if(r->connection->aborted) return EOF;
    va_start(vlist,fmt);
    n=vbprintf(r->connection->client,fmt,vlist);
    va_end(vlist);
    SET_BYTES_SENT(r);
    return n;
    }

int
rvputs(request_rec *r, ...)
{
    va_list args;
    int i, j, k;
    const char *x;
    BUFF *fb=r->connection->client;
    
    if (r->connection->aborted) return EOF;
    
    va_start (args, r);
    for (k=0;;)
    {
	x = va_arg(args, const char *);
	if (x == NULL) break;
	j = strlen(x);
	i = bwrite(fb, x, j);
	if (i != j)
	{
	    va_end(args);
	    return -1;
	}
	k += i;
    }
    va_end(args);

    SET_BYTES_SENT(r);
    return k;
}

void send_error_response (request_rec *r, int recursive_error)
{
    conn_rec *c = r->connection;
    char *custom_response;
    int status = r->status;
    int idx = index_of_response (status);
    char *location = table_get (r->headers_out, "Location");

    if (!r->assbackwards) {
	int i;
	table *err_hdrs_arr = r->err_headers_out;
	table_entry *err_hdrs = (table_entry *)err_hdrs_arr->elts;
  
        basic_http_header (r);
	
	/* For conditional get's which didn't send anything, *don't*
	 * send a bogus content-type, or any body --- but must still
	 * terminate header.
	 */
	
	if (status == USE_LOCAL_COPY) {
	    char *etag = table_get(r->headers_out, "ETag");
	    char *cloc = table_get(r->headers_out, "Content-Location");
	    if (etag) bvputs(c->client, "ETag: ", etag, "\015\012", NULL);
	    if (cloc) bvputs(c->client, "Content-Location: ", cloc,
			     "\015\012", NULL);
	    if (set_keepalive(r)) {
#ifdef FORHTTP11
		if (r->proto_num < 1001)
#endif
		    bputs("Connection: Keep-Alive\015\012", c->client);
	    }
	    else bputs("Connection: close", c->client);
	    bputs("\015\012", c->client);
	    return;
	}

	/* We don't want persistent connections here, for several reasons.
	 * Most importantly, if there's been an error, we don't want
	 * it screwing up the next request.
	 */
	bputs("Connection: close\015\012", c->client);
	
	if ((status == REDIRECT) || (status == MOVED))
	    bvputs(c->client, "Location: ", location, "\015\012", NULL);

	if ((status == METHOD_NOT_ALLOWED) || (status == NOT_IMPLEMENTED))
	    bvputs(c->client, "Allow: ", make_allow(r), "\015\012", NULL);
	
	for (i = 0; i < err_hdrs_arr->nelts; ++i) {
	    if (!err_hdrs[i].key) continue;
	    bvputs(c->client, err_hdrs[i].key, ": ", err_hdrs[i].val,
		   "\015\012", NULL);
	}

	bputs("Content-type: text/html\015\012\015\012", c->client);
    }

    if (r->header_only) return;
    
    if ((custom_response = response_code_string (r, idx))) {
        /*
	 * We have a custom response output. This should only be
	 * a text-string to write back. But if the ErrorDocument
	 * was a local redirect and the requested resource failed
	 * for any reason, the custom_response will still hold the
	 * redirect URL. We don't really want to output this URL
	 * as a text message, so first check the custom response 
	 * string to ensure that it is a text-string (using the
	 * same test used in die(), i.e. does it start with a
	 * "). If it doesn't, we've got a recursive error, so find
	 * the original error and output that as well.
	 */
        if (custom_response[0] == '\"') { 
            bputs(custom_response+1, c->client);
	      return;
	}
	/* Redirect failed, so get back the original error
	 */
	while (r->prev && r->prev->status != 200)
          r = r->prev;
    }
    {
	char *title = response_titles[idx];
	BUFF *fd = c->client;
	
        bvputs(fd,"<HEAD><TITLE>", title, "</TITLE></HEAD>\n<BODY><H1>", title,
	       "</H1>\n", NULL);
	
        switch (r->status) {
	case REDIRECT:
	case MOVED:
	    bvputs(fd, "The document has moved <A HREF=\"",
		    escape_html(r->pool, location), "\">here</A>.<P>\n", NULL);
	    break;
	case AUTH_REQUIRED:
	    bputs("This server could not verify that you\n", fd);
	    bputs("are authorized to access the document you\n", fd);
	    bputs("requested.  Either you supplied the wrong\n", fd);
	    bputs("credentials (e.g., bad password), or your\n", fd);
	    bputs("browser doesn't understand how to supply\n", fd);
	    bputs("the credentials required.<P>\n", fd);
	    break;
	case BAD_REQUEST:
	    bputs("Your browser sent a query that\n", fd);
	    bputs("this server could not understand.<P>\n", fd);
	    break;
	case FORBIDDEN:
	    bvputs(fd, "You don't have permission to access ",
		     escape_html(r->pool, r->uri), "\non this server.<P>\n",
		   NULL);
	    break;
	case NOT_FOUND:
	    bvputs(fd, "The requested URL ", escape_html(r->pool, r->uri),
		    " was not found on this server.<P>\n", NULL);
	    break;
	case METHOD_NOT_ALLOWED:
	    bvputs(fd, "The requested method ", r->method, " is not allowed "
		   "for the URL ", escape_html(r->pool, r->uri),
		   ".<P>\n", NULL);
	    break;
	case LENGTH_REQUIRED:
	    bvputs(fd, "A request of the requested method ", r->method,
		   " requires a valid Content-length.<P>\n", NULL);
	    break;
	case PRECONDITION_FAILED:
	    bvputs(fd, "The requested precondition for serving the URL ",
		   escape_html(r->pool, r->uri), " evaluated to false.<P>\n",
		   NULL);
	    break;
	case SERVER_ERROR:
	    bputs("The server encountered an internal error or\n", fd);
	    bputs("misconfiguration and was unable to complete\n", fd);
	    bputs("your request.<P>\n", fd);
	    bputs("Please contact the server administrator,\n ", fd);
	    bputs(escape_html(r->pool, r->server->server_admin), fd);
	    bputs(" and inform them of the time the error occurred,\n", fd);
	    bputs("and anything you might have done that may have\n", fd);
	    bputs("caused the error.<P>\n", fd);
	    break;
	case NOT_IMPLEMENTED:
	    bvputs(fd, escape_html(r->pool, r->method), " to ",
		   escape_html(r->pool, r->uri), " not supported.<P>\n", NULL);
	    break;
	case BAD_GATEWAY:
	    bputs("The proxy server received an invalid\015\012", fd);
	    bputs("response from an upstream server.<P>\015\012", fd);
	    break;
	}

        if (recursive_error) {
	    char x[80];
	    sprintf (x, "Additionally, an error of type %d was encountered\n",
		     recursive_error);
	    bputs(x, fd);
	    bputs("while trying to use an ErrorDocument to\n", fd);
	    bputs("handle the request.\n", fd);
	}
	bputs("</BODY>\n", fd);
    }
        
}

/* Finally, this... it's here to support nph- scripts
 * Now what ever are we going to do about them when HTTP-NG packetization
 * comes along?
 */

void client_to_stdout (conn_rec *c)
{
    bflush(c->client);
    dup2(c->client->fd, STDOUT_FILENO);
}
