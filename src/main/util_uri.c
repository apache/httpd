/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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

/*
 * util_uri.c: URI related utility things
 * 
 */

#include "httpd.h"
#include "http_log.h"
#include "http_conf_globals.h"  /* for user_id & group_id */
#include "util_uri.h"

/* Some WWW schemes and their default ports; this is basically /etc/services */
/* This will become global when the protocol abstraction comes */
/* As the schemes are searched by a linear search, */
/* they are sorted by their expected frequency */
static schemes_t schemes[] = {
    {"http", DEFAULT_HTTP_PORT},
    {"ftp", DEFAULT_FTP_PORT},
    {"https", DEFAULT_HTTPS_PORT},
    {"gopher", DEFAULT_GOPHER_PORT},
    {"wais", DEFAULT_WAIS_PORT},
    {"nntp", DEFAULT_NNTP_PORT},
    {"snews", DEFAULT_SNEWS_PORT},
    {"prospero", DEFAULT_PROSPERO_PORT},
    {NULL, 0xFFFF}              /* unknown port */
};


API_EXPORT(unsigned short) ap_default_port_for_scheme(const char *scheme_str)
{
    schemes_t *scheme;

    if (scheme_str == NULL)
        return 0;

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
    char **ptrs;
    char **aliases;
    struct in_addr *addrs;
    int i = 0, j = 0;

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
    aliases = (char **) ap_palloc(p, (j + 1) * sizeof(char *));
    ptrs = (char **) ap_palloc(p, (i + 1) * sizeof(char *));
    addrs = (struct in_addr *) ap_palloc(p, (i + 1) * sizeof(struct in_addr));

    *newent = *hp;
    newent->h_name = ap_pstrdup(p, hp->h_name);
    newent->h_aliases = aliases;
    newent->h_addr_list = (char **) ptrs;

    /* Copy Alias Names: */
    for (j = 0; hp->h_aliases[j] != NULL; ++j) {
        aliases[j] = ap_pstrdup(p, hp->h_aliases[j]);
    }
    aliases[j] = NULL;

    /* Copy address entries */
    for (i = 0; hp->h_addr_list[i] != NULL; ++i) {
        ptrs[i] = (char *) &addrs[i];
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
#ifdef TPF
    /* get rid of compilation warning on TPF */
    struct hostent *hp = gethostbyname((char *)hostname);
#else
    struct hostent *hp = gethostbyname(hostname);
#endif
    return (hp == NULL) ? NULL : ap_pduphostent(p, hp);
}


/* Unparse a uri_components structure to an URI string.
 * Optionally suppress the password for security reasons.
 * See also RFC 2396.
 */
API_EXPORT(char *) ap_unparse_uri_components(pool *p,
                                             const uri_components * uptr,
                                             unsigned flags)
{
    char *parts[16];     /* 16 distinct parts of a URI */
    char *scheme = NULL; /* to hold the scheme without modifying const args */
    int j = 0;           /* an index into parts */
    
    memset(parts, 0, sizeof(parts));
        
    /* If suppressing the site part, omit all of scheme://user:pass@host:port */
    if (!(flags & UNP_OMITSITEPART)) {

        /* if the user passes in a scheme, we'll assume an absoluteURI */
        if (uptr->scheme) {
            scheme = uptr->scheme;
            
            parts[j++] = uptr->scheme;
            parts[j++] = ":";
        }
        
        /* handle the hier_part */
        if (uptr->user || uptr->password || uptr->hostname) {
            
            /* this stuff requires absoluteURI, so we have to add the scheme */
            if (!uptr->scheme) {
                scheme = DEFAULT_URI_SCHEME;
                
                parts[j++] = DEFAULT_URI_SCHEME;
                parts[j++] = ":";
            }
            
            parts[j++] = "//";
            
            /* userinfo requires hostport */
            if (uptr->hostname && (uptr->user || uptr->password)) {
                if (uptr->user && !(flags & UNP_OMITUSER))
                    parts[j++] = uptr->user;
                
                if (uptr->password && !(flags & UNP_OMITPASSWORD)) {
                    parts[j++] = ":";

                    if (flags & UNP_REVEALPASSWORD)
                        parts[j++] = uptr->password;
                    else
                        parts[j++] = "XXXXXXXX";
                }    

                parts[j++] = "@";
            }                
            
            /* If we get here, there must be a hostname. */
            parts[j++] = uptr->hostname;
            
            /* Emit the port.  A small beautification
             * prevents http://host:80/ and similar visual blight.
             */
            if (uptr->port_str &&
                !(uptr->port   &&
                  scheme       &&
                  uptr->port == ap_default_port_for_scheme(scheme))) {

                parts[j++] = ":";
                parts[j++] = uptr->port_str;
            }
        }
    }
        
    if (!(flags & UNP_OMITPATHINFO)) {
        
        
        /* We must ensure we don't put out a hier_part and a rel_path */
        if (j && uptr->path && *uptr->path != '/')
            parts[j++] = "/";
        
        if (uptr->path != NULL)
            parts[j++] = uptr->path;

        if (!(flags & UNP_OMITQUERY)) {
            if (uptr->query) {
                parts[j++] = "?";
                parts[j++] = uptr->query;
            }
            
            if (uptr->fragment) {
                parts[j++] = "#";
                parts[j++] = uptr->fragment;
            }
        }
    }

    /* Ugly, but correct and probably faster than ap_vsnprintf. */
    return ap_pstrcat(p,
        parts[0],
        parts[1],
        parts[2],
        parts[3],
        parts[4],
        parts[5],
        parts[6],
        parts[7],
        parts[8],
        parts[9],
        parts[10],
        parts[11],
        parts[12],
        parts[13],
        parts[14],
        parts[15],
        NULL
    );
}

/* Here is the hand-optimized parse_uri_components().  There are some wild
 * tricks we could pull in assembly language that we don't pull here... like we
 * can do word-at-time scans for delimiter characters using the same technique
 * that fast memchr()s use.  But that would be way non-portable. -djg
 */

/* We have a table that we can index by character and it tells us if the
 * character is one of the interesting delimiters.  Note that we even get
 * compares for NUL for free -- it's just another delimiter.
 */

#define T_COLON         0x01    /* ':' */
#define T_SLASH         0x02    /* '/' */
#define T_QUESTION      0x04    /* '?' */
#define T_HASH          0x08    /* '#' */
#define T_NUL           0x80    /* '\0' */

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
#define NOTEND_SCHEME   (0xff)
#define NOTEND_HOSTINFO (T_SLASH | T_QUESTION | T_HASH | T_NUL)
#define NOTEND_PATH     (T_QUESTION | T_HASH | T_NUL)

void ap_util_uri_init(void)
{
    /* Nothing to do - except....
       UTIL_URI_REGEX was removed, but third parties may depend on this symbol
       being present. So, we'll leave it in.... - vjo
     */
}

/* parse_uri_components():
 * Parse a given URI, fill in all supplied fields of a uri_components
 * structure. This eliminates the necessity of extracting host, port,
 * path, query info repeatedly in the modules.
 * Side effects:
 *  - fills in fields of uri_components *uptr
 *  - none on any of the r->* fields
 */
API_EXPORT(int) ap_parse_uri_components(pool *p, const char *uri,
                                        uri_components * uptr)
{
    const char *s;
    const char *s1;
    const char *hostinfo;
    char *endstr;
    int port;

    /* Initialize the structure. parse_uri() and parse_uri_components()
     * can be called more than once per request.
     */
    memset(uptr, '\0', sizeof(*uptr));
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
        while ((uri_delims[*(unsigned char *) s] & NOTEND_PATH) == 0) {
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
    while ((uri_delims[*(unsigned char *) s] & NOTEND_SCHEME) == 0) {
        ++s;
    }
    /* scheme must be non-empty and followed by :// */
    if (s == uri || s[0] != ':' || s[1] != '/' || s[2] != '/') {
        goto deal_with_path;    /* backwards predicted taken! */
    }

    uptr->scheme = ap_pstrndup(p, uri, s - uri);
    s += 3;
    hostinfo = s;
    while ((uri_delims[*(unsigned char *) s] & NOTEND_HOSTINFO) == 0) {
        ++s;
    }
    uri = s;                    /* whatever follows hostinfo is start of uri */
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
            port = ap_strtol(uptr->port_str, &endstr, 10);
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
API_EXPORT(int) ap_parse_hostinfo_components(pool *p, const char *hostinfo,
                                             uri_components * uptr)
{
    const char *s;
    char *endstr;

    /* Initialize the structure. parse_uri() and parse_uri_components()
     * can be called more than once per request.
     */
    memset(uptr, '\0', sizeof(*uptr));
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
        uptr->port = (unsigned short)ap_strtol(uptr->port_str, &endstr, 10);
        if (*endstr == '\0') {
            return HTTP_OK;
        }
        /* Invalid characters after ':' found */
    }
    return HTTP_BAD_REQUEST;
}
