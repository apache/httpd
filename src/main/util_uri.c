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
static schemes_t schemes[] =
{
    {"ftp",    DEFAULT_FTP_PORT},
    {"gopher", DEFAULT_GOPHER_PORT},
    {"http",   DEFAULT_HTTP_PORT},
    {"nntp",   DEFAULT_NNTP_PORT},
    {"wais",   DEFAULT_WAIS_PORT},
    {"https",  DEFAULT_HTTPS_PORT},
    {"snews",  DEFAULT_SNEWS_PORT},
    {"prospero", DEFAULT_PROSPERO_PORT},
    { NULL, 0xFFFF }			/* unknown port */
};


unsigned short default_port_for_scheme(const char *scheme_str)
{
    schemes_t *scheme;

    for (scheme = schemes; scheme->name != NULL; ++scheme)
	if (strcasecmp(scheme_str, scheme->name) == 0)
	    return scheme->default_port;

    return 0;
}

#ifdef WITH_UTIL_URI
unsigned short default_port_for_request(const request_rec *r)
{
    return (r->parsed_uri.has_scheme)
	? default_port_for_scheme(r->parsed_uri.scheme)
	: 0;
}
#endif /*WITH_UTIL_URI*/

static unsigned short default_port_for_uri_components(const uri_components *uri_p)
{
    return (uri_p->has_scheme)
	? default_port_for_scheme(uri_p->scheme)
	: 0;
}

/* Create a copy of a "struct hostent" record; it was presumably returned
 * from a call to gethostbyname() and lives in static storage.
 * By creating a copy we can tuck it away for later use.
 */
struct hostent *pduphostent(pool *p, struct hostent *hp)
{
    struct hostent *newent;
    char	  **ptrs;
    char	  **aliases;
    struct in_addr *addrs;
    int		   i = 0, j = 0;

    if (hp == NULL)
	return hp;

    /* Count number of alias entries */
    if (hp->h_aliases != NULL)
	for (; hp->h_aliases[j] != NULL; ++j)
	    continue;

    /* Count number of in_addr entries */
    if (hp->h_addr_list != NULL)
	for (; hp->h_addr_list[i] != NULL; ++i)
	    continue;

    /* Allocate hostent structure, alias ptrs, addr ptrs, addrs */
    newent = (struct hostent *) palloc(p, sizeof(*hp));
    aliases = (char **) palloc(p, (j+1) * sizeof(char*));
    ptrs = (char **) palloc(p, (i+1) * sizeof(char*));
    addrs  = (struct in_addr *) palloc(p, (i+1) * sizeof(struct in_addr));

    *newent = *hp;
    newent->h_name = pstrdup(p, hp->h_name);
    newent->h_aliases = aliases;
    newent->h_addr_list = (char**) ptrs;

    /* Copy Alias Names: */
    for (j = 0; hp->h_aliases[j] != NULL; ++j) {
       aliases[j] = pstrdup(p, hp->h_aliases[j]);
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
struct hostent *pgethostbyname(pool *p, const char *hostname)
{
    struct hostent *hp = gethostbyname(hostname);
    return (hp == NULL) ? NULL : pduphostent(p, hp);
}


/* Unparse a uri_components structure to an URI string.
 * Optionally suppress the password for security reasons.
 */
char *unparse_uri_components(pool *p, const uri_components *uptr, int *pHostlen, unsigned flags)
{
    char *ret = "";

    /* Construct a "user:password@" string, honoring the passed UNP_ flags: */
    if (uptr->has_user||uptr->has_password)
	ret = pstrcat (p,
		(uptr->has_user     && !(flags & UNP_OMITUSER)) ? uptr->user : "",
		(uptr->has_password && !(flags & UNP_OMITPASSWORD)) ? ":" : "",
		(uptr->has_password && !(flags & UNP_OMITPASSWORD))
		   ? ((flags & UNP_REVEALPASSWORD) ? uptr->password : "XXXXXXXX")
		   : "",
		"@", NULL);

    /* Construct scheme://site string */
    if (uptr->has_hostname && !(flags & UNP_OMITSITEPART)) {
	ret = pstrcat (p,
		uptr->scheme, "://", ret, 
		uptr->has_hostname ? uptr->hostname : "",
		       uptr->has_port ? ":" : "",
		       uptr->has_port ? uptr->port_str : "",
		       NULL);
    }
    /* Return length constructed so far (the famous "hostlen") */
    if (pHostlen != NULL)
	*pHostlen = strlen(ret);

    /* Append path, query and fragment strings: */
    ret = pstrcat (p,
		   ret,
		   uptr->path,
		   uptr->has_query ? "?" : "",
		   uptr->has_query ? uptr->query : "",
		   uptr->has_fragment ? "#" : NULL,
		   uptr->has_fragment ? uptr->fragment : NULL,
		   NULL);
    return ret;
}


/* parse_uri_components():
 * Parse a given URI, fill in all supplied fields of a uri_components
 * structure. This eliminates the necessity of extracting host, port,
 * path, query info repeatedly in the modules.
 * Side effects:
 *  - fills in fields of uri_components *uptr
 *  - none on any of the r->* fields
 */
int parse_uri_components(pool *p, const char *uri, uri_components *uptr, int *pHostlen)
{
    const char *s;
    int ret = HTTP_OK;
    int hostlen = 0;

    /* Initialize the structure. parse_uri() and parse_uri_components()
     * can be called more than once per request.
     */
    memset (uptr, '\0', sizeof(*uptr));
    uptr->is_initialized = 1;

    /* A proxy request contains a ':' early on (after the scheme),
     * but not as first character. RFC1738 allows [a-zA-Z0-9-+.]:
     */
    for (s = uri; s != '\0'; s++)
	if (!isalnum(*s) && *s != '+' && *s != '-' && *s != '.')
	    break;

    if (s == uri || s[0] != ':' || s[1] == '\0') {
	/* not a full URL (not: scheme://host/path), so no proxy request: */

	/* Store path, without the optional "?query" argument: */
	uptr->has_path = 1;
	uptr->path = getword (p, &uri, '?');

	uptr->has_query = (uri[0] != '\0');
	uptr->query = (uptr->has_query) ? pstrdup(p, uri) : NULL;

#if defined(__EMX__) || defined(WIN32)
	/* Handle path translations for OS/2 and plug security hole.
	 * This will prevent "http://www.wherever.com/..\..\/" from
	 * returning a directory for the root drive.
	 */
	for (s = uptr->path; (s = strchr(s, '\\')) != NULL; )
		*s = '/';
#ifndef WIN32   /* for OS/2 only: */
	/* Fix OS/2 HPFS filename case problem. */
	uptr->path = strlwr(uptr->path);
#endif
#endif  /* __EMX__ || WIN32 */
    }
    else {
	/* Yes, it is a proxy request. We've detected the scheme, now
	 * we split the URI's components and mark what we've found:
	 * - scheme
	 *   followed by "://", then:
	 * - [ username [ ":" password ] "@" ]
	 * - hostname
	 * [ ":" port ]
	 * [ "/" path ... [ "?" query ] ]
	 */

	/* As per RFC1738:
	 * The generic form of a URL is:
	 *   genericurl     = scheme ":" schemepart
	 *
	 * the scheme is in lower case; interpreters should use case-ignore
	 *   scheme         = 1*[ lowalpha | digit | "+" | "-" | "." ]
	 *
	 * Extract the scheme:
	 */
	s = uri;
	uptr->scheme = getword(p, &s, ':');
	uptr->has_scheme = 1;

	/*  URL schemeparts for ip based protocols:
	 *
	 * ip-schemepart  = "//" login [ "/" urlpath ]
	 *
	 * login          = [ user [ ":" password ] "@" ] hostport
	 * hostport       = host [ ":" port ]
	 * host           = hostname | hostnumber
	 * hostname       = *[ domainlabel "." ] toplabel
	 * domainlabel    = alphadigit | alphadigit *[ alphadigit | "-" ] alphadigit
	 * toplabel       = alpha | alpha *[ alphadigit | "-" ] alphadigit
	 * alphadigit     = alpha | digit
	 * hostnumber     = digits "." digits "." digits "." digits
	 * port           = digits
	 * user           = *[ uchar | ";" | "?" | "&" | "=" ]
	 * password       = *[ uchar | ";" | "?" | "&" | "=" ]
	 * urlpath        = *xchar
	 */
	/* if IP-schemepart follows, extract host, port etc. */
	if (s[0] == '/' && s[1] == '/') {
	    char *tmp;

	    s += 2;
	    if ((tmp = strchr(s, '/')) != NULL) {
		hostlen = (tmp - uri);

		/* In the request_rec structure, the uri is not
		 * separated into path & query for proxy requests.
		 * But here, we want maximum knowledge about the request,
		 * so we still split them. */
		uptr->has_path = 1;
		uptr->path = getword_nc(p, &tmp, '?');

		uptr->has_query = (tmp[0] != '\0');
		uptr->query = (uptr->has_query) ? pstrdup(p, tmp) : NULL;
	    }
	    else {
		/* the request is just http://hostname - no trailing slash.
		 * Provide one:
		 */
		uptr->path = "/";
		uptr->has_path = 1;

		uptr->has_query = 0;
		hostlen = strlen(uri);
	    }

	    uptr->hostname = getword (p, &s, '/');
	    uptr->has_hostname = uptr->hostname[0] != '\0';

	    /* disintegrate "user@host" */
	    /* NOTE: using reverse search here because user:password might
	     * contain a '@' as well (ftp login: user=ftp : password=user@host)
	     */
	    if ((tmp = strrchr(uptr->hostname, '@')) != NULL) {
		uptr->user = uptr->hostname;
		uptr->has_user = 1;
		*tmp++ = '\0';
		uptr->hostname = tmp;

		/* disintegrate "user:password" */
		if ((tmp = strchr(uptr->user, ':')) != NULL) {
		    *tmp++ = '\0';
		    uptr->password = tmp;
		    uptr->has_password = 1;
		}
	    }

	    /* disintegrate "host:port" */
	    if ((tmp = strchr(uptr->hostname, ':')) != NULL) {
		*tmp++ = '\0';
		uptr->port_str = tmp;
		uptr->port = (unsigned short) strtol(tmp, &tmp, 10);
		uptr->has_port = 1;
		/* Catch possible problem: http://www.apache.org:80@@@/dist/ */
		if (*tmp != '\0')
		    ret = HTTP_BAD_REQUEST;
	    }

	    /* Strip any trailing dots in hostname */
	    tmp = &uptr->hostname[strlen(uptr->hostname)-1];
	    for (; *tmp == '.' && tmp > uptr->hostname; --tmp)
		*tmp = '\0';

	    /* This name hasn't been looked up yet */
	    uptr->dns_looked_up = 0;
	}
	/* If the ip-schemepart doesn't start with "//", deny: */
	else
	    ret = HTTP_BAD_REQUEST;

    }

    /* If caller is interested in the length of the scheme://...host:port prefix: */
    if (pHostlen != NULL)
	*pHostlen = hostlen;

    return ret;
}

/* parse_uri_components_regex():
 * Parse a given URI, fill in all supplied fields of a uri_components
 * structure. This eliminates the necessity of extracting host, port,
 * path, query info repeatedly in the modules.
 * Side effects:
 *  - fills in fields of uri_components *uptr
 *  - none on any of the r->* fields
 */
int parse_uri_components_regex(pool *p, const char *uri, uri_components *uptr)
{
    int ret = HTTP_OK;
    static struct {
	regex_t uri;
	regex_t hostpart;
	regmatch_t match[10];	/* This must have at least as much elements
				 * as there are braces in the re_strings */
	unsigned is_initialized:1;
    } re = { 0, 0, 0 };

    ap_assert (uptr != NULL);

    /* Initialize the structure. parse_uri() and parse_uri_components()
     * can be called more than once per request.
     */
    memset (uptr, '\0', sizeof(*uptr));
    uptr->is_initialized = 1;

    if (!re.is_initialized) {
	const char *re_str;

	re.is_initialized = 1;

	/* This is a modified version of the regex that appeared in
	 * http://www.ics.uci.edu/~fielding/url/url.txt
	 * It doesnt allow the uri to contain a scheme but no hostinfo
	 * or vice versa. 
	 * $       12            3          4       5   6        7 8     */
	re_str = "^(([^:/?#]+)://([^/?#]+))?([^?#]*)(\\?([^#]*))?(#(.*))?";
	/*          ^^scheme^^://^^site^^^  ^^path^^   ?^query^   #frag  */
	if ((ret = regcomp(&re.uri, re_str, REG_EXTENDED)) != 0)
	{
	    char line[1024];

	    /* Make a readable error message */
	    ret = regerror(ret, &re.uri, line, sizeof line);
	    aplog_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL,
                    "Internal error: regcomp(\"%s\") returned non-zero (%s) - "
		    "possibly due to broken regex lib! "
		    "Did you define WANTHSREGEX=yes?",
		    re_str, line);

	    return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* This is a sub-RE which will break down the hostinfo part,
	 * i.e., user, password, hostname and port.
	 * $          12       3       4       5 6    */
	re_str    = "^(([^:]*):(.*)?@)?([^@:]*)(:(.*))?$";
	/*             ^^user^ :pw      ^host^   port */
	if ((ret = regcomp(&re.hostpart, re_str, REG_EXTENDED|REG_ICASE)) != 0)
	{
	    char line[1024];

	    /* Make a readable error message */
	    ret = regerror(ret, &re.hostpart, line, sizeof line);
	    aplog_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL,
                    "Internal error: regcomp(\"%s\") returned non-zero (%s) - "
		    "possibly due to broken regex lib! "
		    "Did you define WANTHSREGEX=yes?",
		    re_str, line);

	    return HTTP_INTERNAL_SERVER_ERROR;
	}
    }

    ret = regexec(&re.uri, uri, re.uri.re_nsub, re.match, 0);

    if (ret != 0) {
	aplog_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL,
                    "regexec() could not parse uri (\"%s\")",
		    uri);

	return HTTP_BAD_REQUEST;
    }

    /* if hostlen is 0, it's not a proxy request */
    uptr->hostlen = (re.match[1].rm_eo - re.match[1].rm_so);

    uptr->has_scheme = (re.match[2].rm_so != re.match[2].rm_eo);
    uptr->has_hostinfo = (re.match[3].rm_so != re.match[3].rm_eo);
    uptr->has_path = (re.match[4].rm_so != re.match[4].rm_eo);
    uptr->has_query = (re.match[5].rm_so != re.match[5].rm_eo);
    uptr->has_fragment = (re.match[7].rm_so != re.match[7].rm_eo);

    if (uptr->has_scheme)
	uptr->scheme = pstrndup (p, uri+re.match[2].rm_so, re.match[2].rm_eo - re.match[2].rm_so);
    if (uptr->has_hostinfo)
	uptr->hostinfo = pstrndup (p, uri+re.match[3].rm_so, re.match[3].rm_eo - re.match[3].rm_so);
    if (uptr->has_path)
	uptr->path = pstrndup (p, uri+re.match[4].rm_so, re.match[4].rm_eo - re.match[4].rm_so);
    if (uptr->has_query)
	uptr->query = pstrndup (p, uri+re.match[6].rm_so, re.match[6].rm_eo - re.match[6].rm_so);
    if (uptr->has_fragment)
	uptr->fragment = pstrndup (p, uri+re.match[7].rm_so, re.match[7].rm_eo - re.match[7].rm_so);


    if (uptr->has_hostinfo) {

	/* Parse the hostinfo part to extract user, password, host, and port */
	ret = regexec(&re.hostpart, uptr->hostinfo, re.hostpart.re_nsub, re.match, 0);
	if (ret != 0) {
	    aplog_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL,
                    "regexec() could not parse (\"%s\") as host part",
		    uptr->hostinfo);

	    return HTTP_BAD_REQUEST;
	}

	/* $      12       3       4       5 6    */
	/*    = "^(([^:]*):(.*)?@)?([^@:]*)(:([0-9]*))?$" */
	/*         ^^user^ :pw      ^host^   port */
	if (uptr->has_user = (re.match[2].rm_so != re.match[2].rm_eo))
	    uptr->user = pstrndup (p, uptr->hostinfo+re.match[2].rm_so, re.match[2].rm_eo - re.match[2].rm_so);
	if (uptr->has_password = (re.match[3].rm_so != re.match[3].rm_eo))
	    uptr->password = pstrndup (p, uptr->hostinfo+re.match[3].rm_so, re.match[3].rm_eo - re.match[3].rm_so);
	if (uptr->has_hostname = (re.match[4].rm_so != re.match[4].rm_eo))
	    uptr->hostname = pstrndup (p, uptr->hostinfo+re.match[4].rm_so, re.match[4].rm_eo - re.match[4].rm_so);
	if (uptr->has_port = (re.match[5].rm_so != re.match[5].rm_eo)) {
	    uptr->port_str = pstrndup (p, uptr->hostinfo+re.match[5].rm_so+1, re.match[5].rm_eo - re.match[5].rm_so-1);
	    /* Note that the port string can be empty.
	     * If it is, we use the default port associated with the scheme
	     */
	    if (uptr->port_str[0] != '\0') {
		char *endstr;

		uptr->port = strtoul(uptr->port_str, &endstr, 10);
		if (*endstr != '\0')
		    /* Invalid characters after ':' found */
		    return HTTP_BAD_REQUEST;
	    } else
		uptr->port = default_port_for_scheme(uptr->scheme);
	}
    }

#if defined(__EMX__) || defined(WIN32)
    /* Handle path translations for OS/2 and plug security hole.
     * This will prevent "http://www.wherever.com/..\..\/" from
     * returning a directory for the root drive.
     */
    {
	char *s;

	for (s = uptr->path; (s = strchr(s, '\\')) != NULL; )
	    *s = '/';
    }
#ifndef WIN32   /* for OS/2 only: */
    /* Fix OS/2 HPFS filename case problem. */
    str_tolower(uptr->path);
#endif
#endif  /* __EMX__ || WIN32 */

    if (ret == 0)
	ret = HTTP_OK;
    return ret;
}
