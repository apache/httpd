/* ====================================================================
 * Copyright (c) 1998-1999 The Apache Group.  All rights reserved.
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

/*
 * util_uri.c: URI related utility things
 * 
 */

#include "httpd.h"
#include "http_log.h"
#include "http_conf_globals.h"	/* for user_id & group_id */
#include "util_uri.h"

/* Some WWW schemes and their default ports; this is basically /etc/services */
/* This will become global when the protocol abstraction comes */
/* As the schemes are searched by a linear search, */
/* they are sorted by their expected frequency */
static schemes_t schemes[] =
{
    {"http",   DEFAULT_HTTP_PORT},
    {"ftp",    DEFAULT_FTP_PORT},
    {"https",  DEFAULT_HTTPS_PORT},
    {"gopher", DEFAULT_GOPHER_PORT},
    {"wais",   DEFAULT_WAIS_PORT},
    {"nntp",   DEFAULT_NNTP_PORT},
    {"snews",  DEFAULT_SNEWS_PORT},
    {"prospero", DEFAULT_PROSPERO_PORT},
    { NULL, 0xFFFF }			/* unknown port */
};


API_EXPORT(unsigned short) ap_default_port_for_scheme(const char *scheme_str)
{
    schemes_t *scheme;

    for (scheme = schemes; scheme->name != NULL; ++scheme)
	if (strcasecmp(scheme_str, scheme->name) == 0)
	    return scheme->default_port;

    return 0;
}

API_EXPORT(unsigned short) ap_default_port_for_request(const request_rec *r)
{
    return (r->parsed_uri.scheme)
	? ap_default_port_for_scheme(r->parsed_uri.scheme)
	: 0;
}

/* Create a copy of a "struct hostent" record; it was presumably returned
 * from a call to gethostbyname() and lives in static storage.
 * By creating a copy we can tuck it away for later use.
 */
API_EXPORT(struct hostent *) ap_pduphostent(pool *p, const struct hostent *hp)
{
    struct hostent *newent;
    char	  **ptrs;
    char	  **aliases;
    struct in_addr *addrs;
    int		   i = 0, j = 0;

    if (hp == NULL)
	return NULL;

    /* Count number of alias entries */
    if (hp->h_aliases != NULL)
	for (; hp->h_aliases[j] != NULL; ++j)
	    continue;

    /* Count number of in_addr entries */
    if (hp->h_addr_list != NULL)
	for (; hp->h_addr_list[i] != NULL; ++i)
	    continue;

    /* Allocate hostent structure, alias ptrs, addr ptrs, addrs */
    newent = (struct hostent *) ap_palloc(p, sizeof(*hp));
    aliases = (char **) ap_palloc(p, (j+1) * sizeof(char*));
    ptrs = (char **) ap_palloc(p, (i+1) * sizeof(char*));
    addrs  = (struct in_addr *) ap_palloc(p, (i+1) * sizeof(struct in_addr));

    *newent = *hp;
    newent->h_name = ap_pstrdup(p, hp->h_name);
    newent->h_aliases = aliases;
    newent->h_addr_list = (char**) ptrs;

    /* Copy Alias Names: */
    for (j = 0; hp->h_aliases[j] != NULL; ++j) {
       aliases[j] = ap_pstrdup(p, hp->h_aliases[j]);
    }
    aliases[j] = NULL;

    /* Copy address entries */
    for (i = 0; hp->h_addr_list[i] != NULL; ++i) {
	ptrs[i] = (char*) &addrs[i];
	addrs[i] = *(struct in_addr *) hp->h_addr_list[i];
    }
    ptrs[i] = NULL;

    return newent;
}


/* pgethostbyname(): resolve hostname, if successful return an ALLOCATED
 * COPY OF the hostent structure, intended to be stored and used later.
 * (gethostbyname() uses static storage that would be overwritten on each call)
 */
API_EXPORT(struct hostent *) ap_pgethostbyname(pool *p, const char *hostname)
{
    struct hostent *hp = gethostbyname(hostname);
    return (hp == NULL) ? NULL : ap_pduphostent(p, hp);
}


/* Unparse a uri_components structure to an URI string.
 * Optionally suppress the password for security reasons.
 */
API_EXPORT(char *) ap_unparse_uri_components(pool *p, const uri_components *uptr, unsigned flags)
{
    char *ret = "";

    /* If suppressing the site part, omit both user name & scheme://hostname */
    if (!(flags & UNP_OMITSITEPART)) {

	/* Construct a "user:password@" string, honoring the passed UNP_ flags: */
	if (uptr->user||uptr->password)
	    ret = ap_pstrcat (p,
			(uptr->user     && !(flags & UNP_OMITUSER)) ? uptr->user : "",
			(uptr->password && !(flags & UNP_OMITPASSWORD)) ? ":" : "",
			(uptr->password && !(flags & UNP_OMITPASSWORD))
			   ? ((flags & UNP_REVEALPASSWORD) ? uptr->password : "XXXXXXXX")
			   : "",
			"@", NULL);

	/* Construct scheme://site string */
	if (uptr->hostname) {
	    ret = ap_pstrcat (p,
			uptr->scheme, "://", ret, 
			uptr->hostname ? uptr->hostname : "",
			uptr->port_str ? ":" : "",
			uptr->port_str ? uptr->port_str : "",
			NULL);
	}
    }

    /* Should we suppress all path info? */
    if (!(flags & UNP_OMITPATHINFO)) {
	/* Append path, query and fragment strings: */
	ret = ap_pstrcat (p,
		ret,
		uptr->path ? uptr->path : "",
		(uptr->query    && !(flags & UNP_OMITQUERY)) ? "?" : "",
		(uptr->query    && !(flags & UNP_OMITQUERY)) ? uptr->query : "",
		(uptr->fragment && !(flags & UNP_OMITQUERY)) ? "#" : NULL,
		(uptr->fragment && !(flags & UNP_OMITQUERY)) ? uptr->fragment : NULL,
		NULL);
    }
    return ret;
}

/* The regex version of parse_uri_components has the advantage that it is
 * relatively easy to understand and extend.  But it has the disadvantage
 * that the regexes are complex enough that regex libraries really
 * don't do a great job with them performancewise.
 *
 * The default is a hand coded scanner that is two orders of magnitude
 * faster.
 */
#ifdef UTIL_URI_REGEX

static regex_t re_uri;
static regex_t re_hostpart;

void ap_util_uri_init(void)
{
    int ret;
    const char *re_str;

    /* This is a modified version of the regex that appeared in
     * draft-fielding-uri-syntax-01.  It doesnt allow the uri to contain a
     * scheme but no hostinfo or vice versa. 
     *
     * draft-fielding-uri-syntax-01.txt, section 4.4 tells us:
     *
     *	    Although the BNF defines what is allowed in each component, it is
     *	    ambiguous in terms of differentiating between a site component and
     *	    a path component that begins with two slash characters.
     *  
     * RFC2068 disambiguates this for the Request-URI, which may only ever be
     * the "abs_path" portion of the URI.  So a request "GET //foo/bar
     * HTTP/1.1" is really referring to the path //foo/bar, not the host foo,
     * path /bar.  Nowhere in RFC2068 is it possible to have a scheme but no
     * hostinfo or a hostinfo but no scheme.  (Unless you're proxying a
     * protocol other than HTTP, but this parsing engine probably won't work
     * for other protocols.)
     *
     *         12            3          4       5   6        7 8 */
    re_str = "^(([^:/?#]+)://([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?$";
    /*          ^scheme--^   ^site---^  ^path--^   ^query^    ^frag */
    if ((ret = regcomp(&re_uri, re_str, REG_EXTENDED)) != 0) {
	char line[1024];

	/* Make a readable error message */
	ret = regerror(ret, &re_uri, line, sizeof line);
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL,
		"Internal error: regcomp(\"%s\") returned non-zero (%s) - "
		"possibly due to broken regex lib! "
		"Did you define WANTHSREGEX=yes?",
		re_str, line);

	exit(1);
    }

    /* This is a sub-RE which will break down the hostinfo part,
     * i.e., user, password, hostname and port.
     * $          12      3 4        5       6 7    */
    re_str    = "^(([^:]*)(:(.*))?@)?([^@:]*)(:(.*))?$";
    /*             ^^user^ :pw      ^host^   port */
    if ((ret = regcomp(&re_hostpart, re_str, REG_EXTENDED)) != 0) {
	char line[1024];

	/* Make a readable error message */
	ret = regerror(ret, &re_hostpart, line, sizeof line);
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL,
		"Internal error: regcomp(\"%s\") returned non-zero (%s) - "
		"possibly due to broken regex lib! "
		"Did you define WANTHSREGEX=yes?",
		re_str, line);

	exit(1);
    }
}


/* parse_uri_components():
 * Parse a given URI, fill in all supplied fields of a uri_components
 * structure. This eliminates the necessity of extracting host, port,
 * path, query info repeatedly in the modules.
 * Side effects:
 *  - fills in fields of uri_components *uptr
 *  - none on any of the r->* fields
 */
API_EXPORT(int) ap_parse_uri_components(pool *p, const char *uri, uri_components *uptr)
{
    int ret;
    regmatch_t match[10];	/* This must have at least as much elements
				* as there are braces in the re_strings */

    ap_assert (uptr != NULL);

    /* Initialize the structure. parse_uri() and parse_uri_components()
     * can be called more than once per request.
     */
    memset (uptr, '\0', sizeof(*uptr));
    uptr->is_initialized = 1;

    ret = regexec(&re_uri, uri, re_uri.re_nsub + 1, match, 0);

    if (ret != 0) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL,
                    "regexec() could not parse uri (\"%s\")",
		    uri);

	return HTTP_BAD_REQUEST;
    }

    if (match[2].rm_so != match[2].rm_eo)
	uptr->scheme = ap_pstrndup (p, uri+match[2].rm_so, match[2].rm_eo - match[2].rm_so);

    /* empty hostinfo is valid, that's why we test $1 but use $3 */
    if (match[1].rm_so != match[1].rm_eo)
	uptr->hostinfo = ap_pstrndup (p, uri+match[3].rm_so, match[3].rm_eo - match[3].rm_so);

    if (match[4].rm_so != match[4].rm_eo)
	uptr->path = ap_pstrndup (p, uri+match[4].rm_so, match[4].rm_eo - match[4].rm_so);

    /* empty query string is valid, that's why we test $5 but use $6 */
    if (match[5].rm_so != match[5].rm_eo)
	uptr->query = ap_pstrndup (p, uri+match[6].rm_so, match[6].rm_eo - match[6].rm_so);

    /* empty fragment is valid, test $7 use $8 */
    if (match[7].rm_so != match[7].rm_eo)
	uptr->fragment = ap_pstrndup (p, uri+match[8].rm_so, match[8].rm_eo - match[8].rm_so);

    if (uptr->hostinfo) {
	/* Parse the hostinfo part to extract user, password, host, and port */
	ret = regexec(&re_hostpart, uptr->hostinfo, re_hostpart.re_nsub + 1, match, 0);
	if (ret != 0) {
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL,
                    "regexec() could not parse (\"%s\") as host part",
		    uptr->hostinfo);

	    return HTTP_BAD_REQUEST;
	}

	/* $          12      3 4        5       6 7    */
	/*        = "^(([^:]*)(:(.*))?@)?([^@:]*)(:(.*))?$" */
	/*             ^^user^ :pw      ^host^   port */

	/* empty user is valid, that's why we test $1 but use $2 */
	if (match[1].rm_so != match[1].rm_eo)
	    uptr->user = ap_pstrndup (p, uptr->hostinfo+match[2].rm_so, match[2].rm_eo - match[2].rm_so);

	/* empty password is valid, test $3 but use $4 */
	if (match[3].rm_so != match[3].rm_eo)
	    uptr->password = ap_pstrndup (p, uptr->hostinfo+match[4].rm_so, match[4].rm_eo - match[4].rm_so);

	/* empty hostname is valid, and implied by the existence of hostinfo */
	uptr->hostname = ap_pstrndup (p, uptr->hostinfo+match[5].rm_so, match[5].rm_eo - match[5].rm_so);

	if (match[6].rm_so != match[6].rm_eo) {
	    /* Note that the port string can be empty.
	     * If it is, we use the default port associated with the scheme
	     */
	    uptr->port_str = ap_pstrndup (p, uptr->hostinfo+match[7].rm_so, match[7].rm_eo - match[7].rm_so);
	    if (uptr->port_str[0] != '\0') {
		char *endstr;
		int port;

		port = strtol(uptr->port_str, &endstr, 10);
		uptr->port = port;
		if (*endstr != '\0' || uptr->port != port) {
		    /* Invalid characters after ':' found */
		    return HTTP_BAD_REQUEST;
		}
	    }
	    else {
		uptr->port = uptr->scheme ? ap_default_port_for_scheme(uptr->scheme) : DEFAULT_HTTP_PORT;
	    }
	}
    }

    if (ret == 0)
	ret = HTTP_OK;
    return ret;
}
#else

/* Here is the hand-optimized parse_uri_components().  There are some wild
 * tricks we could pull in assembly language that we don't pull here... like we
 * can do word-at-time scans for delimiter characters using the same technique
 * that fast memchr()s use.  But that would be way non-portable. -djg
 */

/* We have a table that we can index by character and it tells us if the
 * character is one of the interesting delimiters.  Note that we even get
 * compares for NUL for free -- it's just another delimiter.
 */

#define T_COLON		0x01	/* ':' */
#define T_SLASH		0x02	/* '/' */
#define T_QUESTION	0x04	/* '?' */
#define T_HASH		0x08	/* '#' */
#define T_NUL		0x80	/* '\0' */

/* the uri_delims.h file is autogenerated by gen_uri_delims.c */
#include "uri_delims.h"

/* it works like this:
    if (uri_delims[ch] & NOTEND_foobar) {
	then we're not at a delimiter for foobar
    }
*/

/* Note that we optimize the scheme scanning here, we cheat and let the
 * compiler know that it doesn't have to do the & masking.
 */
#define NOTEND_SCHEME	(0xff)
#define NOTEND_HOSTINFO	(T_SLASH | T_QUESTION | T_HASH | T_NUL)
#define NOTEND_PATH	(T_QUESTION | T_HASH | T_NUL)

void ap_util_uri_init(void)
{
    /* nothing to do */
}

/* parse_uri_components():
 * Parse a given URI, fill in all supplied fields of a uri_components
 * structure. This eliminates the necessity of extracting host, port,
 * path, query info repeatedly in the modules.
 * Side effects:
 *  - fills in fields of uri_components *uptr
 *  - none on any of the r->* fields
 */
API_EXPORT(int) ap_parse_uri_components(pool *p, const char *uri, uri_components *uptr)
{
    const char *s;
    const char *s1;
    const char *hostinfo;
    char *endstr;
    int port;

    /* Initialize the structure. parse_uri() and parse_uri_components()
     * can be called more than once per request.
     */
    memset (uptr, '\0', sizeof(*uptr));
    uptr->is_initialized = 1;

    /* We assume the processor has a branch predictor like most --
     * it assumes forward branches are untaken and backwards are taken.  That's
     * the reason for the gotos.  -djg
     */
    if (uri[0] == '/') {
deal_with_path:
	/* we expect uri to point to first character of path ... remember
	 * that the path could be empty -- http://foobar?query for example
	 */
	s = uri;
	while ((uri_delims[*(unsigned char *)s] & NOTEND_PATH) == 0) {
	    ++s;
	}
	if (s != uri) {
	    uptr->path = ap_pstrndup(p, uri, s - uri);
	}
	if (*s == 0) {
	    return HTTP_OK;
	}
	if (*s == '?') {
	    ++s;
	    s1 = strchr(s, '#');
	    if (s1) {
		uptr->fragment = ap_pstrdup(p, s1 + 1);
		uptr->query = ap_pstrndup(p, s, s1 - s);
	    }
	    else {
		uptr->query = ap_pstrdup(p, s);
	    }
	    return HTTP_OK;
	}
	/* otherwise it's a fragment */
	uptr->fragment = ap_pstrdup(p, s + 1);
	return HTTP_OK;
    }

    /* find the scheme: */
    s = uri;
    while ((uri_delims[*(unsigned char *)s] & NOTEND_SCHEME) == 0) {
	++s;
    }
    /* scheme must be non-empty and followed by :// */
    if (s == uri || s[0] != ':' || s[1] != '/' || s[2] != '/') {
	goto deal_with_path;	/* backwards predicted taken! */
    }

    uptr->scheme = ap_pstrndup(p, uri, s - uri);
    s += 3;
    hostinfo = s;
    while ((uri_delims[*(unsigned char *)s] & NOTEND_HOSTINFO) == 0) {
	++s;
    }
    uri = s;	/* whatever follows hostinfo is start of uri */
    uptr->hostinfo = ap_pstrndup(p, hostinfo, uri - hostinfo);

    /* If there's a username:password@host:port, the @ we want is the last @...
     * too bad there's no memrchr()... For the C purists, note that hostinfo
     * is definately not the first character of the original uri so therefore
     * &hostinfo[-1] < &hostinfo[0] ... and this loop is valid C.
     */
    do {
	--s;
    } while (s >= hostinfo && *s != '@');
    if (s < hostinfo) {
	/* again we want the common case to be fall through */
deal_with_host:
	/* We expect hostinfo to point to the first character of
	 * the hostname.  If there's a port it is the first colon.
	 */
	s = memchr(hostinfo, ':', uri - hostinfo);
	if (s == NULL) {
	    /* we expect the common case to have no port */
	    uptr->hostname = ap_pstrndup(p, hostinfo, uri - hostinfo);
	    goto deal_with_path;
	}
	uptr->hostname = ap_pstrndup(p, hostinfo, s - hostinfo);
	++s;
	uptr->port_str = ap_pstrndup(p, s, uri - s);
	if (uri != s) {
	    port = strtol(uptr->port_str, &endstr, 10);
	    uptr->port = port;
	    if (*endstr == '\0') {
		goto deal_with_path;
	    }
	    /* Invalid characters after ':' found */
	    return HTTP_BAD_REQUEST;
	}
	uptr->port = ap_default_port_for_scheme(uptr->scheme);
	goto deal_with_path;
    }

    /* first colon delimits username:password */
    s1 = memchr(hostinfo, ':', s - hostinfo);
    if (s1) {
	uptr->user = ap_pstrndup(p, hostinfo, s1 - hostinfo);
	++s1;
	uptr->password = ap_pstrndup(p, s1, s - s1);
    }
    else {
	uptr->user = ap_pstrndup(p, hostinfo, s - hostinfo);
    }
    hostinfo = s + 1;
    goto deal_with_host;
}

/* Special case for CONNECT parsing: it comes with the hostinfo part only */
/* See the INTERNET-DRAFT document "Tunneling SSL Through a WWW Proxy"
 * currently at http://www.mcom.com/newsref/std/tunneling_ssl.html
 * for the format of the "CONNECT host:port HTTP/1.0" request
 */
API_EXPORT(int) ap_parse_hostinfo_components(pool *p, const char *hostinfo, uri_components *uptr)
{
    const char *s;
    char *endstr;

    /* Initialize the structure. parse_uri() and parse_uri_components()
     * can be called more than once per request.
     */
    memset (uptr, '\0', sizeof(*uptr));
    uptr->is_initialized = 1;
    uptr->hostinfo = ap_pstrdup(p, hostinfo);

    /* We expect hostinfo to point to the first character of
     * the hostname.  There must be a port, separated by a colon
     */
    s = strchr(hostinfo, ':');
    if (s == NULL) {
	return HTTP_BAD_REQUEST;
    }
    uptr->hostname = ap_pstrndup(p, hostinfo, s - hostinfo);
    ++s;
    uptr->port_str = ap_pstrdup(p, s);
    if (*s != '\0') {
	uptr->port = strtol(uptr->port_str, &endstr, 10);
	if (*endstr == '\0') {
	    return HTTP_OK;
	}
	/* Invalid characters after ':' found */
    }
    return HTTP_BAD_REQUEST;
}
#endif
