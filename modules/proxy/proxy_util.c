/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Utility routines for Apache proxy */
#include "mod_proxy.h"
#include "ap_mpm.h"
#include "scoreboard.h"
#include "apr_version.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_atomic.h"
#include "http_core.h"
#include "proxy_util.h"
#include "ajp.h"
#include "scgi.h"

#include "mpm_common.h" /* for ap_max_mem_free */

#include "mod_http2.h" /* for http2_get_num_workers() */

#if APR_HAVE_UNISTD_H
#include <unistd.h>         /* for getpid() */
#endif

#if APR_HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#if (APR_MAJOR_VERSION < 2)
#include "apr_support.h"        /* for apr_wait_for_io_or_timeout() */
#endif

APLOG_USE_MODULE(proxy);

/*
 * Opaque structure containing target server info when
 * using a forward proxy.
 * Up to now only used in combination with HTTP CONNECT to ProxyRemote
 */
typedef struct {
    int          use_http_connect; /* Use SSL Tunneling via HTTP CONNECT */
    const char   *target_host;     /* Target hostname */
    apr_port_t   target_port;      /* Target port */
    const char   *proxy_auth;      /* Proxy authorization */
} forward_info;

/*
 * Opaque structure containing a refcounted and TTL'ed address.
 */
typedef struct proxy_address {
    apr_sockaddr_t *addr;       /* Remote address info */
    const char *hostname;       /* Remote host name */
    apr_port_t hostport;        /* Remote host port */
    apr_uint32_t refcount;      /* Number of conns and/or worker using it */
    apr_uint32_t expiry;        /* Expiry timestamp (seconds to proxy_start_time) */
} proxy_address;

/* Global balancer counter */
int PROXY_DECLARE_DATA proxy_lb_workers = 0;
static int lb_workers_limit = 0;
const apr_strmatch_pattern PROXY_DECLARE_DATA *ap_proxy_strmatch_path;
const apr_strmatch_pattern PROXY_DECLARE_DATA *ap_proxy_strmatch_domain;

extern apr_global_mutex_t *proxy_mutex;

static const apr_time_t *proxy_start_time; /* epoch for expiring addresses */

static int proxy_match_ipaddr(struct dirconn_entry *This, request_rec *r);
static int proxy_match_domainname(struct dirconn_entry *This, request_rec *r);
static int proxy_match_hostname(struct dirconn_entry *This, request_rec *r);
static int proxy_match_word(struct dirconn_entry *This, request_rec *r);
static int ap_proxy_retry_worker(const char *proxy_function, proxy_worker *worker, server_rec *s);
static proxy_worker *proxy_balancer_get_best_worker(proxy_balancer *balancer,
                                                    request_rec *r,
                                                    proxy_is_best_callback_fn_t *is_best,
                                                    void *baton);

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(proxy, PROXY, int, create_req,
                                   (request_rec *r, request_rec *pr), (r, pr),
                                   OK, DECLINED)

PROXY_DECLARE(apr_status_t) ap_proxy_strncpy(char *dst, const char *src,
                                             apr_size_t dlen)
{
    char *thenil;
    apr_size_t thelen;

    /* special case handling */
    if (!dlen) {
        /* XXX: APR_ENOSPACE would be better */
        return APR_EGENERAL;
    }
    if (!src) {
        *dst = '\0';
        return APR_SUCCESS;
    }
    thenil = apr_cpystrn(dst, src, dlen);
    thelen = thenil - dst;
    if (src[thelen] == '\0') {
        return APR_SUCCESS;
    }
    return APR_EGENERAL;
}

/* already called in the knowledge that the characters are hex digits */
PROXY_DECLARE(int) ap_proxy_hex2c(const char *x)
{
    int i;

#if !APR_CHARSET_EBCDIC
    int ch = x[0];

    if (apr_isdigit(ch)) {
        i = ch - '0';
    }
    else if (apr_isupper(ch)) {
        i = ch - ('A' - 10);
    }
    else {
        i = ch - ('a' - 10);
    }
    i <<= 4;

    ch = x[1];
    if (apr_isdigit(ch)) {
        i += ch - '0';
    }
    else if (apr_isupper(ch)) {
        i += ch - ('A' - 10);
    }
    else {
        i += ch - ('a' - 10);
    }
    return i;
#else /*APR_CHARSET_EBCDIC*/
    /*
     * we assume that the hex value refers to an ASCII character
     * so convert to EBCDIC so that it makes sense locally;
     *
     * example:
     *
     * client specifies %20 in URL to refer to a space char;
     * at this point we're called with EBCDIC "20"; after turning
     * EBCDIC "20" into binary 0x20, we then need to assume that 0x20
     * represents an ASCII char and convert 0x20 to EBCDIC, yielding
     * 0x40
     */
    char buf[1];

    if (1 == sscanf(x, "%2x", &i)) {
        buf[0] = i & 0xFF;
        ap_xlate_proto_from_ascii(buf, 1);
        return buf[0];
    }
    else {
        return 0;
    }
#endif /*APR_CHARSET_EBCDIC*/
}

PROXY_DECLARE(void) ap_proxy_c2hex(int ch, char *x)
{
#if !APR_CHARSET_EBCDIC
    int i;

    x[0] = '%';
    i = (ch & 0xF0) >> 4;
    if (i >= 10) {
        x[1] = ('A' - 10) + i;
    }
    else {
        x[1] = '0' + i;
    }

    i = ch & 0x0F;
    if (i >= 10) {
        x[2] = ('A' - 10) + i;
    }
    else {
        x[2] = '0' + i;
    }
#else /*APR_CHARSET_EBCDIC*/
    static const char ntoa[] = { "0123456789ABCDEF" };
    char buf[1];

    ch &= 0xFF;

    buf[0] = ch;
    ap_xlate_proto_to_ascii(buf, 1);

    x[0] = '%';
    x[1] = ntoa[(buf[0] >> 4) & 0x0F];
    x[2] = ntoa[buf[0] & 0x0F];
    x[3] = '\0';
#endif /*APR_CHARSET_EBCDIC*/
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
PROXY_DECLARE(char *)ap_proxy_canonenc_ex(apr_pool_t *p, const char *x, int len,
                                          enum enctype t, int flags,
                                          int proxyreq)
{
    int i, j, ch;
    char *y;
    char *allowed;  /* characters which should not be encoded */
    char *reserved; /* characters which much not be en/de-coded */
    int forcedec = flags & PROXY_CANONENC_FORCEDEC;
    int noencslashesenc = flags & PROXY_CANONENC_NOENCODEDSLASHENCODING;

/*
 * N.B. in addition to :@&=, this allows ';' in an http path
 * and '?' in an ftp path -- this may be revised
 *
 * Also, it makes a '+' character in a search string reserved, as
 * it may be form-encoded. (Although RFC 1738 doesn't allow this -
 * it only permits ; / ? : @ = & as reserved chars.)
 */
    if (t == enc_path) {
        allowed = "~$-_.+!*'(),;:@&=";
    }
    else if (t == enc_search) {
        allowed = "$-_.!*'(),;:@&=";
    }
    else if (t == enc_user) {
        allowed = "$-_.+!*'(),;@&=";
    }
    else if (t == enc_fpath) {
        allowed = "$-_.+!*'(),?:@&=";
    }
    else {            /* if (t == enc_parm) */
        allowed = "$-_.+!*'(),?/:@&=";
    }

    if (t == enc_path) {
        reserved = "/";
    }
    else if (t == enc_search) {
        reserved = "+";
    }
    else {
        reserved = "";
    }

    y = apr_palloc(p, 3 * len + 1);

    for (i = 0, j = 0; i < len; i++, j++) {
/* always handle '/' first */
        ch = x[i];
        if (strchr(reserved, ch)) {
            y[j] = ch;
            continue;
        }
/*
 * decode it if not already done. do not decode reverse proxied URLs
 * unless specifically forced
 */
        if ((forcedec || noencslashesenc
            || (proxyreq && proxyreq != PROXYREQ_REVERSE)) && ch == '%') {
            if (apr_isxdigit(x[i + 1]) && apr_isxdigit(x[i + 2])) {
                ch = ap_proxy_hex2c(&x[i + 1]);
                if (ch != 0 && strchr(reserved, ch)) {  /* keep it encoded */
                    y[j++] = x[i++];
                    y[j++] = x[i++];
                    y[j] = x[i];
                    continue;
                }
                if (noencslashesenc && !forcedec && (proxyreq == PROXYREQ_REVERSE)) {
                    /*
                     * In the reverse proxy case when we only want to keep encoded
                     * slashes untouched revert back to '%' which will cause
                     * '%' to be encoded in the following.
                     */
                    ch = '%';
                }
                else {
                    i += 2;
                }
            }
            /*
             * In the reverse proxy case when we only want to keep encoded
             * slashes untouched we can have decoded '%''s in the URI that got
             * sent to us in the original URL as %25.
             * Don't error out in this case but just fall through and have them
             * encoded to %25 when forwarding to the backend.
             */
            else if (!noencslashesenc || forcedec
                     || (proxyreq && proxyreq != PROXYREQ_REVERSE)) {
                return NULL;
            }
        }
/* recode it, if necessary */
        if (!apr_isalnum(ch) && !strchr(allowed, ch)) {
            ap_proxy_c2hex(ch, &y[j]);
            j += 2;
        }
        else {
            y[j] = ch;
        }
    }
    y[j] = '\0';
    return y;
}

/*
 * Convert a URL-encoded string to canonical form.
 * It decodes characters which need not be encoded,
 * and encodes those which must be encoded, and does not touch
 * those which must not be touched.
 */
PROXY_DECLARE(char *)ap_proxy_canonenc(apr_pool_t *p, const char *x, int len,
                                       enum enctype t, int forcedec,
                                       int proxyreq)
{
    int flags;

    flags = forcedec ? PROXY_CANONENC_FORCEDEC : 0;
    return ap_proxy_canonenc_ex(p, x, len, t, flags, proxyreq);
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
PROXY_DECLARE(char *)
     ap_proxy_canon_netloc(apr_pool_t *p, char **const urlp, char **userp,
            char **passwordp, char **hostp, apr_port_t *port)
{
    char *addr, *scope_id, *strp, *host, *url = *urlp;
    char *user = NULL, *password = NULL;
    apr_port_t tmp_port;
    apr_status_t rv;

    if (url[0] != '/' || url[1] != '/') {
        return "Malformed URL";
    }
    host = url + 2;
    url = strchr(host, '/');
    if (url == NULL) {
        url = "";
    }
    else {
        *(url++) = '\0';    /* skip separating '/' */
    }

    /* find _last_ '@' since it might occur in user/password part */
    strp = strrchr(host, '@');

    if (strp != NULL) {
        *strp = '\0';
        user = host;
        host = strp + 1;

/* find password */
        strp = strchr(user, ':');
        if (strp != NULL) {
            *strp = '\0';
            password = ap_proxy_canonenc(p, strp + 1, strlen(strp + 1), enc_user, 1, 0);
            if (password == NULL) {
                return "Bad %-escape in URL (password)";
            }
        }

        user = ap_proxy_canonenc(p, user, strlen(user), enc_user, 1, 0);
        if (user == NULL) {
            return "Bad %-escape in URL (username)";
        }
    }
    if (userp != NULL) {
        *userp = user;
    }
    if (passwordp != NULL) {
        *passwordp = password;
    }

    /*
     * Parse the host string to separate host portion from optional port.
     * Perform range checking on port.
     */
    rv = apr_parse_addr_port(&addr, &scope_id, &tmp_port, host, p);
    if (rv != APR_SUCCESS || addr == NULL || scope_id != NULL) {
        return "Invalid host/port";
    }
    if (tmp_port != 0) { /* only update caller's port if port was specified */
        *port = tmp_port;
    }

    ap_str_tolower(addr); /* DNS names are case-insensitive */

    *urlp = url;
    *hostp = addr;

    return NULL;
}

static int proxyerror_core(request_rec *r, int statuscode, const char *message,
                           apr_status_t rv)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00898)
                  "%s returned by %s", message, r->uri);

    apr_table_setn(r->notes, "error-notes",
        apr_pstrcat(r->pool,
            "The proxy server could not handle the request<p>"
            "Reason: <strong>", ap_escape_html(r->pool, message),
            "</strong></p>",
            NULL));

    /* Allow "error-notes" string to be printed by ap_send_error_response() */
    apr_table_setn(r->notes, "verbose-error-to", "*");

    r->status_line = apr_psprintf(r->pool, "%3.3u Proxy Error", statuscode);
    return statuscode;
}

PROXY_DECLARE(int) ap_proxyerror(request_rec *r, int statuscode, const char *message)
{
    return proxyerror_core(r, statuscode, message, 0);
}

static const char *
     proxy_get_host_of_request(request_rec *r)
{
    char *url, *user = NULL, *password = NULL, *err, *host = NULL;
    apr_port_t port;

    if (r->hostname != NULL) {
        return r->hostname;
    }

    /* Set url to the first char after "scheme://" */
    if ((url = strchr(r->uri, ':')) == NULL || url[1] != '/' || url[2] != '/') {
        return NULL;
    }

    url = apr_pstrdup(r->pool, &url[1]);    /* make it point to "//", which is what proxy_canon_netloc expects */

    err = ap_proxy_canon_netloc(r->pool, &url, &user, &password, &host, &port);

    if (err != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00899) "%s", err);
    }

    r->hostname = host;

    return host;        /* ought to return the port, too */
}

/* Return TRUE if addr represents an IP address (or an IP network address) */
PROXY_DECLARE(int) ap_proxy_is_ipaddr(struct dirconn_entry *This, apr_pool_t *p)
{
    const char *addr = This->name;
    long ip_addr[4];
    int i, quads;
    long bits;

    /*
     * if the address is given with an explicit netmask, use that
     * Due to a deficiency in apr_inet_addr(), it is impossible to parse
     * "partial" addresses (with less than 4 quads) correctly, i.e.
     * 192.168.123 is parsed as 192.168.0.123, which is not what I want.
     * I therefore have to parse the IP address manually:
     * if (proxy_readmask(This->name, &This->addr.s_addr, &This->mask.s_addr) == 0)
     * addr and mask were set by proxy_readmask()
     * return 1;
     */

    /*
     * Parse IP addr manually, optionally allowing
     * abbreviated net addresses like 192.168.
     */

    /* Iterate over up to 4 (dotted) quads. */
    for (quads = 0; quads < 4 && *addr != '\0'; ++quads) {
        char *tmp;

        if (*addr == '/' && quads > 0) {  /* netmask starts here. */
            break;
        }

        if (!apr_isdigit(*addr)) {
            return 0;       /* no digit at start of quad */
        }

        ip_addr[quads] = strtol(addr, &tmp, 0);

        if (tmp == addr) {  /* expected a digit, found something else */
            return 0;
        }

        if (ip_addr[quads] < 0 || ip_addr[quads] > 255) {
            /* invalid octet */
            return 0;
        }

        addr = tmp;

        if (*addr == '.' && quads != 3) {
            ++addr;     /* after the 4th quad, a dot would be illegal */
        }
    }

    for (This->addr.s_addr = 0, i = 0; i < quads; ++i) {
        This->addr.s_addr |= htonl(ip_addr[i] << (24 - 8 * i));
    }

    if (addr[0] == '/' && apr_isdigit(addr[1])) {   /* net mask follows: */
        char *tmp;

        ++addr;

        bits = strtol(addr, &tmp, 0);

        if (tmp == addr) {   /* expected a digit, found something else */
            return 0;
        }

        addr = tmp;

        if (bits < 0 || bits > 32) { /* netmask must be between 0 and 32 */
            return 0;
        }

    }
    else {
        /*
         * Determine (i.e., "guess") netmask by counting the
         * number of trailing .0's; reduce #quads appropriately
         * (so that 192.168.0.0 is equivalent to 192.168.)
         */
        while (quads > 0 && ip_addr[quads - 1] == 0) {
            --quads;
        }

        /* "IP Address should be given in dotted-quad form, optionally followed by a netmask (e.g., 192.168.111.0/24)"; */
        if (quads < 1) {
            return 0;
        }

        /* every zero-byte counts as 8 zero-bits */
        bits = 8 * quads;

        if (bits != 32) {     /* no warning for fully qualified IP address */
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00900)
                         "Warning: NetMask not supplied with IP-Addr; guessing: %s/%ld",
                         inet_ntoa(This->addr), bits);
        }
    }

    This->mask.s_addr = htonl(APR_INADDR_NONE << (32 - bits));

    if (*addr == '\0' && (This->addr.s_addr & ~This->mask.s_addr) != 0) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00901)
                     "Warning: NetMask and IP-Addr disagree in %s/%ld",
                     inet_ntoa(This->addr), bits);
        This->addr.s_addr &= This->mask.s_addr;
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00902)
                     "         Set to %s/%ld", inet_ntoa(This->addr), bits);
    }

    if (*addr == '\0') {
        This->matcher = proxy_match_ipaddr;
        return 1;
    }
    else {
        return (*addr == '\0'); /* okay iff we've parsed the whole string */
    }
}

/* Return TRUE if addr represents an IP address (or an IP network address) */
static int proxy_match_ipaddr(struct dirconn_entry *This, request_rec *r)
{
    int i, ip_addr[4];
    struct in_addr addr, *ip;
    const char *host = proxy_get_host_of_request(r);

    if (host == NULL) {   /* oops! */
       return 0;
    }

    memset(&addr, '\0', sizeof addr);
    memset(ip_addr, '\0', sizeof ip_addr);

    if (4 == sscanf(host, "%d.%d.%d.%d", &ip_addr[0], &ip_addr[1], &ip_addr[2], &ip_addr[3])) {
        for (addr.s_addr = 0, i = 0; i < 4; ++i) {
            /* ap_proxy_is_ipaddr() already confirmed that we have
             * a valid octet in ip_addr[i]
             */
            addr.s_addr |= htonl(ip_addr[i] << (24 - 8 * i));
        }

        if (This->addr.s_addr == (addr.s_addr & This->mask.s_addr)) {
#if DEBUGGING
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00903)
                         "1)IP-Match: %s[%s] <-> ", host, inet_ntoa(addr));
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00904)
                         "%s/", inet_ntoa(This->addr));
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00905)
                         "%s", inet_ntoa(This->mask));
#endif
            return 1;
        }
#if DEBUGGING
        else {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00906)
                         "1)IP-NoMatch: %s[%s] <-> ", host, inet_ntoa(addr));
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00907)
                         "%s/", inet_ntoa(This->addr));
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00908)
                         "%s", inet_ntoa(This->mask));
        }
#endif
    }
    else {
        struct apr_sockaddr_t *reqaddr;

        if (apr_sockaddr_info_get(&reqaddr, host, APR_UNSPEC, 0, 0, r->pool)
            != APR_SUCCESS) {
#if DEBUGGING
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00909)
             "2)IP-NoMatch: hostname=%s msg=Host not found", host);
#endif
            return 0;
        }

        /* Try to deal with multiple IP addr's for a host */
        /* FIXME: This needs to be able to deal with IPv6 */
        while (reqaddr) {
            ip = (struct in_addr *) reqaddr->ipaddr_ptr;
            if (This->addr.s_addr == (ip->s_addr & This->mask.s_addr)) {
#if DEBUGGING
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00910)
                             "3)IP-Match: %s[%s] <-> ", host, inet_ntoa(*ip));
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00911)
                             "%s/", inet_ntoa(This->addr));
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00912)
                             "%s", inet_ntoa(This->mask));
#endif
                return 1;
            }
#if DEBUGGING
            else {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00913)
                             "3)IP-NoMatch: %s[%s] <-> ", host, inet_ntoa(*ip));
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00914)
                             "%s/", inet_ntoa(This->addr));
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00915)
                             "%s", inet_ntoa(This->mask));
            }
#endif
            reqaddr = reqaddr->next;
        }
    }

    return 0;
}

/* Return TRUE if addr represents a domain name */
PROXY_DECLARE(int) ap_proxy_is_domainname(struct dirconn_entry *This, apr_pool_t *p)
{
    char *addr = This->name;
    int i;

    /* Domain name must start with a '.' */
    if (addr[0] != '.') {
        return 0;
    }

    /* rfc1035 says DNS names must consist of "[-a-zA-Z0-9]" and '.' */
    for (i = 0; apr_isalnum(addr[i]) || addr[i] == '-' || addr[i] == '.'; ++i) {
        continue;
    }

#if 0
    if (addr[i] == ':') {
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(03234)
                     "@@@@ handle optional port in proxy_is_domainname()");
    /* @@@@ handle optional port */
    }
#endif

    if (addr[i] != '\0') {
        return 0;
    }

    /* Strip trailing dots */
    for (i = strlen(addr) - 1; i > 0 && addr[i] == '.'; --i) {
        addr[i] = '\0';
    }

    This->matcher = proxy_match_domainname;
    return 1;
}

/* Return TRUE if host "host" is in domain "domain" */
static int proxy_match_domainname(struct dirconn_entry *This, request_rec *r)
{
    const char *host = proxy_get_host_of_request(r);
    int d_len = strlen(This->name), h_len;

    if (host == NULL) {      /* some error was logged already */
        return 0;
    }

    h_len = strlen(host);

    /* @@@ do this within the setup? */
    /* Ignore trailing dots in domain comparison: */
    while (d_len > 0 && This->name[d_len - 1] == '.') {
        --d_len;
    }
    while (h_len > 0 && host[h_len - 1] == '.') {
        --h_len;
    }
    return h_len > d_len
        && strncasecmp(&host[h_len - d_len], This->name, d_len) == 0;
}

/* Return TRUE if host represents a host name */
PROXY_DECLARE(int) ap_proxy_is_hostname(struct dirconn_entry *This, apr_pool_t *p)
{
    struct apr_sockaddr_t *addr;
    char *host = This->name;
    int i;

    /* Host names must not start with a '.' */
    if (host[0] == '.') {
        return 0;
    }
    /* rfc1035 says DNS names must consist of "[-a-zA-Z0-9]" and '.' */
    for (i = 0; apr_isalnum(host[i]) || host[i] == '-' || host[i] == '.'; ++i);

    if (host[i] != '\0' || apr_sockaddr_info_get(&addr, host, APR_UNSPEC, 0, 0, p) != APR_SUCCESS) {
        return 0;
    }

    This->hostaddr = addr;

    /* Strip trailing dots */
    for (i = strlen(host) - 1; i > 0 && host[i] == '.'; --i) {
        host[i] = '\0';
    }

    This->matcher = proxy_match_hostname;
    return 1;
}

/* Return TRUE if host "host" is equal to host2 "host2" */
static int proxy_match_hostname(struct dirconn_entry *This, request_rec *r)
{
    char *host = This->name;
    const char *host2 = proxy_get_host_of_request(r);
    int h2_len;
    int h1_len;

    if (host == NULL || host2 == NULL) {
        return 0; /* oops! */
    }

    h2_len = strlen(host2);
    h1_len = strlen(host);

#if 0
    struct apr_sockaddr_t *addr = *This->hostaddr;

    /* Try to deal with multiple IP addr's for a host */
    while (addr) {
        if (addr->ipaddr_ptr == ? ? ? ? ? ? ? ? ? ? ? ? ?)
            return 1;
        addr = addr->next;
    }
#endif

    /* Ignore trailing dots in host2 comparison: */
    while (h2_len > 0 && host2[h2_len - 1] == '.') {
        --h2_len;
    }
    while (h1_len > 0 && host[h1_len - 1] == '.') {
        --h1_len;
    }
    return h1_len == h2_len
        && strncasecmp(host, host2, h1_len) == 0;
}

/* Return TRUE if addr is to be matched as a word */
PROXY_DECLARE(int) ap_proxy_is_word(struct dirconn_entry *This, apr_pool_t *p)
{
    This->matcher = proxy_match_word;
    return 1;
}

/* Return TRUE if string "str2" occurs literally in "str1" */
static int proxy_match_word(struct dirconn_entry *This, request_rec *r)
{
    const char *host = proxy_get_host_of_request(r);
    return host != NULL && ap_strstr_c(host, This->name) != NULL;
}

#define MAX_IP_STR_LEN (46)

PROXY_DECLARE(int) ap_proxy_checkproxyblock(request_rec *r, proxy_server_conf *conf,
                                            const char *hostname, apr_sockaddr_t *addr)
{
    int j;

    /* XXX FIXME: conf->noproxies->elts is part of an opaque structure */
    for (j = 0; j < conf->noproxies->nelts; j++) {
        struct noproxy_entry *npent = (struct noproxy_entry *) conf->noproxies->elts;
        struct apr_sockaddr_t *conf_addr;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "checking remote machine [%s] against [%s]",
                      hostname, npent[j].name);
        if (ap_strstr_c(hostname, npent[j].name) || npent[j].name[0] == '*') {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(00916)
                          "connect to remote machine %s blocked: name %s "
                          "matched", hostname, npent[j].name);
            return HTTP_FORBIDDEN;
        }

        /* No IP address checks if no IP address was passed in,
         * i.e. the forward address proxy case, where this server does
         * not resolve the hostname.  */
        if (!addr)
            continue;

        for (conf_addr = npent[j].addr; conf_addr; conf_addr = conf_addr->next) {
            char caddr[MAX_IP_STR_LEN], uaddr[MAX_IP_STR_LEN];
            apr_sockaddr_t *uri_addr;

            if (apr_sockaddr_ip_getbuf(caddr, sizeof caddr, conf_addr))
                continue;

            for (uri_addr = addr; uri_addr; uri_addr = uri_addr->next) {
                if (apr_sockaddr_ip_getbuf(uaddr, sizeof uaddr, uri_addr))
                    continue;
                ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                              "ProxyBlock comparing %s and %s", caddr, uaddr);
                if (!strcmp(caddr, uaddr)) {
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(00917)
                                  "connect to remote machine %s blocked: "
                                  "IP %s matched", hostname, caddr);
                    return HTTP_FORBIDDEN;
                }
            }
        }
    }

    return OK;
}

/* set up the minimal filter set */
PROXY_DECLARE(int) ap_proxy_pre_http_request(conn_rec *c, request_rec *r)
{
    ap_add_input_filter("HTTP_IN", NULL, r, c);
    ap_add_input_filter("HTTP1_BODY_IN", NULL, r, c);
    return OK;
}

PROXY_DECLARE(const char *) ap_proxy_location_reverse_map(request_rec *r,
                              proxy_dir_conf *conf, const char *url)
{
    proxy_req_conf *rconf;
    struct proxy_alias *ent;
    int i, l1, l1_orig, l2;
    char *u;

    /*
     * XXX FIXME: Make sure this handled the ambiguous case of the :<PORT>
     * after the hostname
     * XXX FIXME: Ensure the /uri component is a case sensitive match
     */
    if (r->proxyreq != PROXYREQ_REVERSE) {
        return url;
    }

    l1_orig = strlen(url);
    if (conf->interpolate_env == 1) {
        rconf = ap_get_module_config(r->request_config, &proxy_module);
        ent = (struct proxy_alias *)rconf->raliases->elts;
    }
    else {
        ent = (struct proxy_alias *)conf->raliases->elts;
    }
    for (i = 0; i < conf->raliases->nelts; i++) {
        proxy_server_conf *sconf = (proxy_server_conf *)
            ap_get_module_config(r->server->module_config, &proxy_module);
        proxy_balancer *balancer;
        const char *real = ent[i].real;

        /* Restore the url length, if it had been changed by the code below */
        l1 = l1_orig;

        /*
         * First check if mapping against a balancer and see
         * if we have such a entity. If so, then we need to
         * find the particulars of the actual worker which may
         * or may not be the right one... basically, we need
         * to find which member actually handled this request.
         */
        if (ap_proxy_valid_balancer_name((char *)real, 0) &&
            (balancer = ap_proxy_get_balancer(r->pool, sconf, real, 1))) {
            int n, l3 = 0;
            proxy_worker **worker = (proxy_worker **)balancer->workers->elts;
            const char *urlpart = ap_strchr_c(real + sizeof(BALANCER_PREFIX) - 1, '/');
            if (urlpart) {
                if (!urlpart[1])
                    urlpart = NULL;
                else
                    l3 = strlen(urlpart);
            }
            /* The balancer comparison is a bit trickier.  Given the context
             *   BalancerMember balancer://alias http://example.com/foo
             *   ProxyPassReverse /bash balancer://alias/bar
             * translate url http://example.com/foo/bar/that to /bash/that
             */
            for (n = 0; n < balancer->workers->nelts; n++) {
                l2 = strlen((*worker)->s->name);
                if (urlpart) {
                    /* urlpart (l3) assuredly starts with its own '/' */
                    if ((*worker)->s->name[l2 - 1] == '/')
                        --l2;
                    if (l1 >= l2 + l3
                            && strncasecmp((*worker)->s->name, url, l2) == 0
                            && strncmp(urlpart, url + l2, l3) == 0) {
                        u = apr_pstrcat(r->pool, ent[i].fake, &url[l2 + l3],
                                        NULL);
                        return ap_is_url(u) ? u : ap_construct_url(r->pool, u, r);
                    }
                }
                else if (l1 >= l2 && strncasecmp((*worker)->s->name, url, l2) == 0) {
                    /* edge case where fake is just "/"... avoid double slash */
                    if ((ent[i].fake[0] == '/') && (ent[i].fake[1] == 0) && (url[l2] == '/')) {
                        u = apr_pstrdup(r->pool, &url[l2]);
                    } else {
                        u = apr_pstrcat(r->pool, ent[i].fake, &url[l2], NULL);
                    }
                    return ap_is_url(u) ? u : ap_construct_url(r->pool, u, r);
                }
                worker++;
            }
        }
        else {
            const char *part = url;
            l2 = strlen(real);
            if (real[0] == '/') {
                part = ap_strstr_c(url, "://");
                if (part) {
                    part = ap_strchr_c(part+3, '/');
                    if (part) {
                        l1 = strlen(part);
                    }
                    else {
                        part = url;
                    }
                }
                else {
                    part = url;
                }
            }
            if (l2 > 0 && l1 >= l2 && strncasecmp(real, part, l2) == 0) {
                u = apr_pstrcat(r->pool, ent[i].fake, &part[l2], NULL);
                return ap_is_url(u) ? u : ap_construct_url(r->pool, u, r);
            }
        }
    }

    return url;
}

/*
 * Cookies are a bit trickier to match: we've got two substrings to worry
 * about, and we can't just find them with strstr 'cos of case.  Regexp
 * matching would be an easy fix, but for better consistency with all the
 * other matches we'll refrain and use apr_strmatch to find path=/domain=
 * and stick to plain strings for the config values.
 */
PROXY_DECLARE(const char *) ap_proxy_cookie_reverse_map(request_rec *r,
                              proxy_dir_conf *conf, const char *str)
{
    proxy_req_conf *rconf = ap_get_module_config(r->request_config,
                                                 &proxy_module);
    struct proxy_alias *ent;
    apr_size_t len = strlen(str);
    const char *newpath = NULL;
    const char *newdomain = NULL;
    const char *pathp;
    const char *domainp;
    const char *pathe = NULL;
    const char *domaine = NULL;
    apr_size_t l1, l2, poffs = 0, doffs = 0;
    int i;
    int ddiff = 0;
    int pdiff = 0;
    char *tmpstr, *tmpstr_orig, *token, *last, *ret;

    if (r->proxyreq != PROXYREQ_REVERSE) {
        return str;
    }

   /*
    * Find the match and replacement, but save replacing until we've done
    * both path and domain so we know the new strlen
    */
    tmpstr_orig = tmpstr = apr_pstrdup(r->pool, str);
    while ((token = apr_strtok(tmpstr, ";", &last))) {
        /* skip leading spaces */
        while (apr_isspace(*token)) {
            ++token;
        }

        if (ap_cstr_casecmpn("path=", token, 5) == 0) {
            pathp = token + 5;
            poffs = pathp - tmpstr_orig;
            l1 = strlen(pathp);
            pathe = str + poffs + l1;
            if (conf->interpolate_env == 1) {
                ent = (struct proxy_alias *)rconf->cookie_paths->elts;
            }
            else {
                ent = (struct proxy_alias *)conf->cookie_paths->elts;
            }
            for (i = 0; i < conf->cookie_paths->nelts; i++) {
                l2 = strlen(ent[i].fake);
                if (l1 >= l2 && strncmp(ent[i].fake, pathp, l2) == 0) {
                    newpath = ent[i].real;
                    pdiff = strlen(newpath) - l1;
                    break;
                }
            }
        }
        else if (ap_cstr_casecmpn("domain=", token, 7) == 0) {
            domainp = token + 7;
            doffs = domainp - tmpstr_orig;
            l1 = strlen(domainp);
            domaine = str + doffs + l1;
            if (conf->interpolate_env == 1) {
                ent = (struct proxy_alias *)rconf->cookie_domains->elts;
            }
            else {
                ent = (struct proxy_alias *)conf->cookie_domains->elts;
            }
            for (i = 0; i < conf->cookie_domains->nelts; i++) {
                l2 = strlen(ent[i].fake);
                if (l1 >= l2 && strncasecmp(ent[i].fake, domainp, l2) == 0) {
                    newdomain = ent[i].real;
                    ddiff = strlen(newdomain) - l1;
                    break;
                }
            }
        }

        /* Iterate the remaining tokens using apr_strtok(NULL, ...) */
        tmpstr = NULL;
    }

    if (newpath) {
        ret = apr_palloc(r->pool, len + pdiff + ddiff + 1);
        l1 = strlen(newpath);
        if (newdomain) {
            l2 = strlen(newdomain);
            if (doffs > poffs) {
                memcpy(ret, str, poffs);
                memcpy(ret + poffs, newpath, l1);
                memcpy(ret + poffs + l1, pathe, str + doffs - pathe);
                memcpy(ret + doffs + pdiff, newdomain, l2);
                strcpy(ret + doffs + pdiff + l2, domaine);
            }
            else {
                memcpy(ret, str, doffs) ;
                memcpy(ret + doffs, newdomain, l2);
                memcpy(ret + doffs + l2, domaine, str + poffs - domaine);
                memcpy(ret + poffs + ddiff, newpath, l1);
                strcpy(ret + poffs + ddiff + l1, pathe);
            }
        }
        else {
            memcpy(ret, str, poffs);
            memcpy(ret + poffs, newpath, l1);
            strcpy(ret + poffs + l1, pathe);
        }
    }
    else if (newdomain) {
            ret = apr_palloc(r->pool, len + ddiff + 1);
            l2 = strlen(newdomain);
            memcpy(ret, str, doffs);
            memcpy(ret + doffs, newdomain, l2);
            strcpy(ret + doffs + l2, domaine);
    }
    else {
        ret = (char *)str; /* no change */
    }

    return ret;
}

/*
 * BALANCER related...
 */

/*
 * verifies that the balancer name conforms to standards.
 */
PROXY_DECLARE(int) ap_proxy_valid_balancer_name(char *name, int i)
{
    if (!i)
        i = sizeof(BALANCER_PREFIX)-1;
    return (!ap_cstr_casecmpn(name, BALANCER_PREFIX, i));
}


PROXY_DECLARE(proxy_balancer *) ap_proxy_get_balancer(apr_pool_t *p,
                                                      proxy_server_conf *conf,
                                                      const char *url,
                                                      int care)
{
    proxy_balancer *balancer;
    char *c, *uri = apr_pstrdup(p, url);
    int i;
    proxy_hashes hash;

    c = strchr(uri, ':');
    if (c == NULL || c[1] != '/' || c[2] != '/' || c[3] == '\0') {
        return NULL;
    }
    /* remove path from uri */
    if ((c = strchr(c + 3, '/'))) {
        *c = '\0';
    }
    ap_str_tolower(uri);
    hash.def = ap_proxy_hashfunc(uri, PROXY_HASHFUNC_DEFAULT);
    hash.fnv = ap_proxy_hashfunc(uri, PROXY_HASHFUNC_FNV);
    balancer = (proxy_balancer *)conf->balancers->elts;
    for (i = 0; i < conf->balancers->nelts; i++) {
        if (balancer->hash.def == hash.def && balancer->hash.fnv == hash.fnv) {
            if (!care || !balancer->s->inactive) {
                return balancer;
            }
        }
        balancer++;
    }
    return NULL;
}


PROXY_DECLARE(char *) ap_proxy_update_balancer(apr_pool_t *p,
                                                proxy_balancer *balancer,
                                                const char *url)
{
    apr_uri_t puri;
    if (!url) {
        return NULL;
    }
    if (apr_uri_parse(p, url, &puri) != APR_SUCCESS) {
        return apr_psprintf(p, "unable to parse: %s", url);
    }
    if (puri.path && PROXY_STRNCPY(balancer->s->vpath, puri.path) != APR_SUCCESS) {
        return apr_psprintf(p, "balancer %s front-end virtual-path (%s) too long",
                            balancer->s->name, puri.path);
    }
    if (puri.hostname && PROXY_STRNCPY(balancer->s->vhost, puri.hostname) != APR_SUCCESS) {
        return apr_psprintf(p, "balancer %s front-end vhost name (%s) too long",
                            balancer->s->name, puri.hostname);
    }
    return NULL;
}

#define PROXY_UNSET_NONCE '\n'

PROXY_DECLARE(char *) ap_proxy_define_balancer(apr_pool_t *p,
                                               proxy_balancer **balancer,
                                               proxy_server_conf *conf,
                                               const char *url,
                                               const char *alias,
                                               int do_malloc)
{
    proxy_balancer_method *lbmethod;
    proxy_balancer_shared *bshared;
    char *c, *q, *uri = apr_pstrdup(p, url);
    const char *sname;

    /* We should never get here without a valid BALANCER_PREFIX... */

    c = strchr(uri, ':');
    if (c == NULL || c[1] != '/' || c[2] != '/' || c[3] == '\0')
        return apr_psprintf(p, "Bad syntax for a balancer name (%s)", uri);
    /* remove path from uri */
    if ((q = strchr(c + 3, '/')))
        *q = '\0';

    ap_str_tolower(uri);
    *balancer = apr_array_push(conf->balancers);
    memset(*balancer, 0, sizeof(proxy_balancer));

    /*
     * NOTE: The default method is byrequests - if it doesn't
     * exist, that's OK at this time. We check when we share and sync
     */
    lbmethod = ap_lookup_provider(PROXY_LBMETHOD, "byrequests", "0");
    (*balancer)->lbmethod = lbmethod;
    
    (*balancer)->workers = apr_array_make(p, 5, sizeof(proxy_worker *));
#if APR_HAS_THREADS
    (*balancer)->gmutex = NULL;
    (*balancer)->tmutex = NULL;
#endif

    if (do_malloc)
        bshared = ap_malloc(sizeof(proxy_balancer_shared));
    else
        bshared = apr_palloc(p, sizeof(proxy_balancer_shared));

    memset(bshared, 0, sizeof(proxy_balancer_shared));

    bshared->was_malloced = (do_malloc != 0);
    PROXY_STRNCPY(bshared->lbpname, "byrequests");
    if (PROXY_STRNCPY(bshared->name, uri) != APR_SUCCESS) {
        if (do_malloc) free(bshared);
        return apr_psprintf(p, "balancer name (%s) too long", uri);
    }
    (*balancer)->lbmethod_set = 1;

    /*
     * We do the below for verification. The real sname will be
     * done post_config
     */
    ap_pstr2_alnum(p, bshared->name + sizeof(BALANCER_PREFIX) - 1,
                   &sname);
    sname = apr_pstrcat(p, conf->id, "_", sname, NULL);
    if (PROXY_STRNCPY(bshared->sname, sname) != APR_SUCCESS) {
        if (do_malloc) free(bshared);
        return apr_psprintf(p, "balancer safe-name (%s) too long", sname);
    }
    bshared->hash.def = ap_proxy_hashfunc(bshared->name, PROXY_HASHFUNC_DEFAULT);
    bshared->hash.fnv = ap_proxy_hashfunc(bshared->name, PROXY_HASHFUNC_FNV);
    (*balancer)->hash = bshared->hash;

    bshared->forcerecovery = 1;
    bshared->sticky_separator = '.';
    *bshared->nonce = PROXY_UNSET_NONCE;  /* impossible valid input */

    (*balancer)->s = bshared;
    (*balancer)->sconf = conf;

    return ap_proxy_update_balancer(p, *balancer, alias);
}

/*
 * Create an already defined balancer and free up memory.
 */
PROXY_DECLARE(apr_status_t) ap_proxy_share_balancer(proxy_balancer *balancer,
                                                    proxy_balancer_shared *shm,
                                                    int i)
{
    apr_status_t rv = APR_SUCCESS;
    proxy_balancer_method *lbmethod;
    char *action = "copying";
    if (!shm || !balancer->s)
        return APR_EINVAL;

    if ((balancer->s->hash.def != shm->hash.def) ||
        (balancer->s->hash.fnv != shm->hash.fnv)) {
        memcpy(shm, balancer->s, sizeof(proxy_balancer_shared));
        if (balancer->s->was_malloced)
            free(balancer->s);
    } else {
        action = "re-using";
    }
    balancer->s = shm;
    balancer->s->index = i;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(02337)
                 "%s shm[%d] (0x%pp) for %s", action, i, (void *)shm,
                 balancer->s->name);
    /* the below should always succeed */
    lbmethod = ap_lookup_provider(PROXY_LBMETHOD, balancer->s->lbpname, "0");
    if (lbmethod) {
        balancer->lbmethod = lbmethod;
        balancer->lbmethod_set = 1;
    } else {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, ap_server_conf, APLOGNO(02432)
                     "Cannot find LB Method: %s", balancer->s->lbpname);
        return APR_EINVAL;
    }
    if (*balancer->s->nonce == PROXY_UNSET_NONCE) {
        char nonce[APR_UUID_FORMATTED_LENGTH + 1];
        apr_uuid_t uuid;

        /* Generate a pseudo-UUID from the PRNG to use as a nonce for
         * the lifetime of the process. uuid.data is a char array so
         * this is an adequate substitute for apr_uuid_get(). */
        ap_random_insecure_bytes(uuid.data, sizeof uuid.data);
        apr_uuid_format(nonce, &uuid);
        rv = PROXY_STRNCPY(balancer->s->nonce, nonce);
    }
    return rv;
}

PROXY_DECLARE(apr_status_t) ap_proxy_initialize_balancer(proxy_balancer *balancer, server_rec *s, apr_pool_t *p)
{
#if APR_HAS_THREADS
    apr_status_t rv = APR_SUCCESS;
#endif
    ap_slotmem_provider_t *storage = balancer->storage;
    apr_size_t size;
    unsigned int num;

    if (!storage) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(00918)
                     "no provider for %s", balancer->s->name);
        return APR_EGENERAL;
    }
    /*
     * for each balancer we need to init the global
     * mutex and then attach to the shared worker shm
     */
    if (!balancer->gmutex) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(00919)
                     "no mutex %s", balancer->s->name);
        return APR_EGENERAL;
    }

    /* Re-open the mutex for the child. */
    rv = apr_global_mutex_child_init(&(balancer->gmutex),
                                     apr_global_mutex_lockfile(balancer->gmutex),
                                     p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00920)
                     "Failed to reopen mutex %s in child",
                     balancer->s->name);
        return rv;
    }

    /* now attach */
    storage->attach(&(balancer->wslot), balancer->s->sname, &size, &num, p);
    if (!balancer->wslot) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(00921) "slotmem_attach failed");
        return APR_EGENERAL;
    }

#if APR_HAS_THREADS
    if (balancer->tmutex == NULL) {
        rv = apr_thread_mutex_create(&(balancer->tmutex), APR_THREAD_MUTEX_DEFAULT, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(00922)
                         "can not create balancer thread mutex");
            return rv;
        }
    }
#endif
    return APR_SUCCESS;
}

static proxy_worker *proxy_balancer_get_best_worker(proxy_balancer *balancer,
                                                    request_rec *r,
                                                    proxy_is_best_callback_fn_t *is_best,
                                                    void *baton)
{
    int i = 0;
    int cur_lbset = 0;
    int max_lbset = 0;
    int unusable_workers = 0;
    apr_pool_t *tpool = NULL;
    apr_array_header_t *spares = NULL;
    apr_array_header_t *standbys = NULL;
    proxy_worker *worker = NULL;
    proxy_worker *best_worker = NULL;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, APLOGNO(10122)
                 "proxy: Entering %s for BALANCER (%s)",
                 balancer->lbmethod->name, balancer->s->name);

    apr_pool_create(&tpool, r->pool);
    apr_pool_tag(tpool, "proxy_lb_best");

    spares = apr_array_make(tpool, 1, sizeof(proxy_worker*));
    standbys = apr_array_make(tpool, 1, sizeof(proxy_worker*));

    /* Process lbsets in order, only replacing unusable workers in a given lbset
     * with available spares from the same lbset. Hot standbys will be used as a
     * last resort when all other workers and spares are unavailable.
     */
    for (cur_lbset = 0; !best_worker && (cur_lbset <= max_lbset); cur_lbset++) {
        unusable_workers = 0;
        apr_array_clear(spares);
        apr_array_clear(standbys);

        for (i = 0; i < balancer->workers->nelts; i++) {
            worker = APR_ARRAY_IDX(balancer->workers, i, proxy_worker *);

            if (worker->s->lbset > max_lbset) {
                max_lbset = worker->s->lbset;
            }

            if (worker->s->lbset != cur_lbset) {
                continue;
            }

            /* A draining worker that is neither a spare nor a standby should be
             * considered unusable to be replaced by spares.
             */
            if (PROXY_WORKER_IS_DRAINING(worker)) {
                if (!PROXY_WORKER_IS_SPARE(worker) && !PROXY_WORKER_IS_STANDBY(worker)) {
                    unusable_workers++;
                }

                continue;
            }

            /* If the worker is in error state run retry on that worker. It will
             * be marked as operational if the retry timeout is elapsed.  The
             * worker might still be unusable, but we try anyway.
             */
            if (!PROXY_WORKER_IS_USABLE(worker)) {
                ap_proxy_retry_worker("BALANCER", worker, r->server);
            }

            if (PROXY_WORKER_IS_SPARE(worker)) {
                if (PROXY_WORKER_IS_USABLE(worker)) {
                    APR_ARRAY_PUSH(spares, proxy_worker *) = worker;
                }
            }
            else if (PROXY_WORKER_IS_STANDBY(worker)) {
                if (PROXY_WORKER_IS_USABLE(worker)) {
                    APR_ARRAY_PUSH(standbys, proxy_worker *) = worker;
                }
            }
            else if (PROXY_WORKER_IS_USABLE(worker)) {
              if (is_best(worker, best_worker, baton)) {
                best_worker = worker;
              }
            }
            else {
                unusable_workers++;
            }
        }

        /* Check if any spares are best. */
        for (i = 0; (i < spares->nelts) && (i < unusable_workers); i++) {
          worker = APR_ARRAY_IDX(spares, i, proxy_worker *);

          if (is_best(worker, best_worker, baton)) {
            best_worker = worker;
          }
        }

        /* If no workers are available, use the standbys. */
        if (!best_worker) {
            for (i = 0; i < standbys->nelts; i++) {
              worker = APR_ARRAY_IDX(standbys, i, proxy_worker *);

              if (is_best(worker, best_worker, baton)) {
                best_worker = worker;
              }
            }
        }
    }

    apr_pool_destroy(tpool);

    if (best_worker) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, APLOGNO(10123)
                     "proxy: %s selected worker \"%s\" : busy %" APR_SIZE_T_FMT " : lbstatus %d",
                     balancer->lbmethod->name, best_worker->s->name, best_worker->s->busy, best_worker->s->lbstatus);
    }

    return best_worker;
}

PROXY_DECLARE(proxy_worker *) ap_proxy_balancer_get_best_worker(proxy_balancer *balancer,
                                                                request_rec *r,
                                                                proxy_is_best_callback_fn_t *is_best,
                                                                void *baton)
{
    return proxy_balancer_get_best_worker(balancer, r, is_best, baton);
}

/*
 * CONNECTION related...
 */

static void socket_cleanup(proxy_conn_rec *conn)
{
    conn->sock = NULL;
    conn->tmp_bb = NULL;
    conn->connection = NULL;
    conn->ssl_hostname = NULL;
    apr_pool_clear(conn->scpool);
    conn->close = 0;
}

static void conn_cleanup(proxy_conn_rec *conn)
{
    socket_cleanup(conn);
    conn->address = NULL;
    conn->addr = NULL;
    conn->hostname = NULL;
    conn->port = 0;
    conn->uds_path = NULL;
    if (conn->uds_pool) {
        apr_pool_clear(conn->uds_pool);
    }
}

static apr_status_t conn_pool_cleanup(void *theworker)
{
    /* Signal that the child is exiting */
    ((proxy_worker *)theworker)->cp = NULL;
    return APR_SUCCESS;
}

static apr_pool_t *make_conn_subpool(apr_pool_t *p, const char *tag,
                                     server_rec *s)
{
    apr_pool_t *sp = NULL;
    apr_allocator_t *alloc;
    apr_thread_mutex_t *mutex;
    apr_status_t rv;

    rv = apr_allocator_create(&alloc);
    if (rv == APR_SUCCESS) {
        rv = apr_thread_mutex_create(&mutex, APR_THREAD_MUTEX_DEFAULT, p);
        if (rv == APR_SUCCESS) {
            apr_allocator_mutex_set(alloc, mutex);
            apr_allocator_max_free_set(alloc, ap_max_mem_free);
            rv = apr_pool_create_ex(&sp, p, NULL, alloc);
        }
        else {
            apr_allocator_destroy(alloc);
        }
    }
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(10474)
                     "failed to create %s pool", tag);
        ap_abort_on_oom();
        return NULL; /* not reached */
    }
    apr_allocator_owner_set(alloc, sp);
    apr_pool_tag(sp, tag);

    return sp;
}

static void init_conn_pool(apr_pool_t *p, proxy_worker *worker, server_rec *s)
{
    proxy_conn_pool *cp;

    /*
     * Alloc from the same pool as worker.
     * proxy_conn_pool is permanently attached to the worker.
     */
    cp = (proxy_conn_pool *)apr_pcalloc(p, sizeof(proxy_conn_pool));
    worker->cp = cp;

    /*
     * We need a first pool (cp->pool) to maintain the connections attached to
     * the worker and a second one (cp->dns_pool) to maintain the DNS addresses
     * in use (TTL'ed, refcounted). New connections are created as/on a subpool
     * of cp->pool and new addresses as/on a subpool of cp->dns_pool, such that
     * both leaks (the subpools can be destroyed when the connections and/or
     * addresses are over) and race conditions (the creation/destruction of
     * subpools is protected by the parent pool's mutex) can be avoided.
     *
     * cp->dns_pool is created before cp->pool because when a connection on the
     * latter is destroyed it might destroy an address on the former, so when
     * the base pools are destroyed (e.g. child exit) we thusly make sure that
     * cp->dns_pool and its subpools are still alive when cp->pool gets killed.
     *
     * Both cp->dns_pool and cp->pool have their own allocator/mutex too since
     * acquiring connections and addresses don't need to contend.
     */
    cp->dns_pool = make_conn_subpool(p, "proxy_worker_dns", s);
    cp->pool = make_conn_subpool(p, "proxy_worker_cp", s);

    /* When p is cleaning up the child is exiting, signal that to e.g. avoid
     * destroying the subpools explicitely in connection_destructor() when
     * they have been destroyed already by the reslist cleanup.
     */
    apr_pool_pre_cleanup_register(p, worker, conn_pool_cleanup);
}

PROXY_DECLARE(int) ap_proxy_connection_reusable(proxy_conn_rec *conn)
{
    proxy_worker *worker = conn->worker;

    return !(conn->close
             || conn->forward
             || worker->s->disablereuse);
}

static proxy_conn_rec *connection_make(apr_pool_t *p, proxy_worker *worker)
{
    proxy_conn_rec *conn;

    conn = apr_pcalloc(p, sizeof(proxy_conn_rec));
    conn->pool = p;
    conn->worker = worker;

    /*
     * Create another subpool that manages the data for the
     * socket and the connection member of the proxy_conn_rec struct as we
     * destroy this data more frequently than other data in the proxy_conn_rec
     * struct like hostname and addr (at least in the case where we have
     * keepalive connections that timed out).
     *
     * XXX: this is really needed only when worker->s->is_address_reusable,
     *      otherwise conn->scpool = conn->pool would be fine. For now we
     *      can't change it since it's (kind of) part of the API.
     */
    apr_pool_create(&conn->scpool, p);
    apr_pool_tag(conn->scpool, "proxy_conn_scpool");

    return conn;
}

static void connection_cleanup(void *theconn)
{
    proxy_conn_rec *conn = (proxy_conn_rec *)theconn;
    proxy_worker *worker = conn->worker;

    /* Sanity check: Did we already return the pooled connection? */
    if (conn->inreslist) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, conn->pool, APLOGNO(00923)
                      "Pooled connection 0x%pp for worker %s has been"
                      " already returned to the connection pool.", conn,
                      ap_proxy_worker_get_name(worker));
        return;
    }

    if (conn->r) {
        apr_pool_destroy(conn->r->pool);
        conn->r = NULL;
    }

    /* determine if the connection should be cleared, closed or reused */
    if (!worker->s->is_address_reusable) {
        apr_pool_t *p = conn->pool;
        apr_pool_clear(p);
        conn = connection_make(p, worker);
    }
    else if (!conn->sock
             || (conn->connection
                 && conn->connection->keepalive == AP_CONN_CLOSE)
             || !ap_proxy_connection_reusable(conn)) {
        socket_cleanup(conn);
    }
    else if (conn->is_ssl) {
        /* The current ssl section/dir config of the conn is not necessarily
         * the one it will be reused for, so while the conn is in the reslist
         * reset its ssl config to the worker's, until a new user sets its own
         * ssl config eventually in proxy_connection_create() and so on.
         */
        ap_proxy_ssl_engine(conn->connection, worker->section_config, 1);
    }

    if (worker->s->hmax && worker->cp->res) {
        conn->inreslist = 1;
        apr_reslist_release(worker->cp->res, (void *)conn);
    }
    else {
        worker->cp->conn = conn;
    }
}

/* DEPRECATED */
PROXY_DECLARE(apr_status_t) ap_proxy_ssl_connection_cleanup(proxy_conn_rec *conn,
                                                            request_rec *r)
{
    apr_status_t rv;

    /*
     * If we have an existing SSL connection it might be possible that the
     * server sent some SSL message we have not read so far (e.g. an SSL
     * shutdown message if the server closed the keepalive connection while
     * the connection was held unused in our pool).
     * So ensure that if present (=> APR_NONBLOCK_READ) it is read and
     * processed. We don't expect any data to be in the returned brigade.
     */
    if (conn->sock && conn->connection) {
        rv = ap_get_brigade(conn->connection->input_filters, conn->tmp_bb,
                            AP_MODE_READBYTES, APR_NONBLOCK_READ,
                            HUGE_STRING_LEN);
        if (!APR_BRIGADE_EMPTY(conn->tmp_bb)) {
            apr_off_t len;

            rv = apr_brigade_length(conn->tmp_bb, 0, &len);
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, rv, r,
                          "SSL cleanup brigade contained %"
                          APR_OFF_T_FMT " bytes of data.", len);
            apr_brigade_cleanup(conn->tmp_bb);
        }
        if ((rv != APR_SUCCESS) && !APR_STATUS_IS_EAGAIN(rv)) {
            socket_cleanup(conn);
        }
    }
    return APR_SUCCESS;
}

/* reslist constructor */
static apr_status_t connection_constructor(void **resource, void *params,
                                           apr_pool_t *pool)
{
    apr_pool_t *p;
    proxy_conn_rec *conn;
    proxy_worker *worker = (proxy_worker *)params;

    /*
     * Create a subpool for each connection
     * This keeps the memory consumption constant
     * when it's recycled or destroyed.
     */
    apr_pool_create(&p, pool);
    apr_pool_tag(p, "proxy_conn_pool");
    conn = connection_make(p, worker);
    conn->inreslist = 1;

    *resource = conn;
    return APR_SUCCESS;
}

/* reslist destructor */
static apr_status_t connection_destructor(void *resource, void *params,
                                          apr_pool_t *pool)
{
    proxy_worker *worker = params;

    /* Destroy the pool only if not called from reslist_destroy */
    if (worker->cp) {
        proxy_conn_rec *conn = resource;
        apr_pool_destroy(conn->pool);
    }

    return APR_SUCCESS;
}

/*
 * WORKER related...
 */

PROXY_DECLARE(const char *) ap_proxy_worker_get_name(const proxy_worker *worker)
{
    return worker->uds_name ? worker->uds_name : worker->s->name;
}

/* Deprecated/legacy */
PROXY_DECLARE(char *) ap_proxy_worker_name(apr_pool_t *unused,
                                           proxy_worker *worker)
{
    (void)unused;
    return (char *)ap_proxy_worker_get_name(worker);
}

PROXY_DECLARE(int) ap_proxy_worker_can_upgrade(apr_pool_t *p,
                                               const proxy_worker *worker,
                                               const char *upgrade,
                                               const char *dflt)
{
    /* Find in worker->s->upgrade list (if any) */
    const char *worker_upgrade = worker->s->upgrade;
    if (*worker_upgrade) {
        return (strcmp(worker_upgrade, "*") == 0
                || ap_cstr_casecmp(worker_upgrade, upgrade) == 0
                || ap_find_token(p, worker_upgrade, upgrade));
    }

    /* Compare to the provided default (if any) */
    return (dflt && ap_cstr_casecmp(dflt, upgrade) == 0);
}

/*
 * Taken from ap_strcmp_match() :
 * Match = 0, NoMatch = 1, Abort = -1, Inval = -2
 * Based loosely on sections of wildmat.c by Rich Salz
 * Hmmm... shouldn't this really go component by component?
 *
 * Adds handling of the "\<any>" => "<any>" unescaping.
 */
static int ap_proxy_strcmp_ematch(const char *str, const char *expected)
{
    apr_size_t x, y;

    for (x = 0, y = 0; expected[y]; ++y, ++x) {
        if (expected[y] == '$' && apr_isdigit(expected[y + 1])) {
            do {
                y += 2;
            } while (expected[y] == '$' && apr_isdigit(expected[y + 1]));
            if (!expected[y])
                return 0;
            while (str[x]) {
                int ret;
                if ((ret = ap_proxy_strcmp_ematch(&str[x++], &expected[y])) != 1)
                    return ret;
            }
            return -1;
        }
        else if (!str[x]) {
            return -1;
        }
        else if (expected[y] == '\\' && !expected[++y]) {
            /* NUL is an invalid char! */
            return -2;
        }
        if (str[x] != expected[y])
            return 1;
    }
    /* We got all the way through the worker path without a difference */
    return 0;
}

static int worker_matches(proxy_worker *worker,
                          const char *url, apr_size_t url_len,
                          apr_size_t min_match, apr_size_t *max_match,
                          unsigned int mask)
{
    apr_size_t name_len = strlen(worker->s->name);
    if (name_len <= url_len
        && name_len > *max_match
        /* min_match is the length of the scheme://host part only of url,
         * so it's used as a fast path to avoid the match when url is too
         * small, but it's irrelevant when the worker host contains globs
         * (i.e. ->is_host_matchable).
         */
        && (worker->s->is_name_matchable
            ? ((mask & AP_PROXY_WORKER_IS_MATCH)
               && (worker->s->is_host_matchable || name_len >= min_match)
               && !ap_proxy_strcmp_ematch(url, worker->s->name))
            : ((mask & AP_PROXY_WORKER_IS_PREFIX)
               && (name_len >= min_match)
               && !strncmp(url, worker->s->name, name_len)))) {
        *max_match = name_len;
        return 1;
    }
    return 0;
}

PROXY_DECLARE(proxy_worker *) ap_proxy_get_worker_ex(apr_pool_t *p,
                                                     proxy_balancer *balancer,
                                                     proxy_server_conf *conf,
                                                     const char *url,
                                                     unsigned int mask)
{
    proxy_worker *max_worker = NULL;
    apr_size_t min_match, max_match = 0;
    apr_size_t url_len;
    const char *c;
    char *url_copy;
    int i;

    if (!url) {
        return NULL;
    }

    if (!(mask & AP_PROXY_WORKER_NO_UDS)) {
        url = ap_proxy_de_socketfy(p, url);
        if (!url) {
            return NULL;
        }
    }

    c = ap_strchr_c(url, ':');
    if (c == NULL || c[1] != '/' || c[2] != '/' || c[3] == '\0') {
        return NULL;
    }

    url_len = strlen(url);
    url_copy = apr_pstrmemdup(p, url, url_len);

    /* Default to lookup for both _PREFIX and _MATCH workers */
    if (!(mask & (AP_PROXY_WORKER_IS_PREFIX | AP_PROXY_WORKER_IS_MATCH))) {
        mask |= AP_PROXY_WORKER_IS_PREFIX | AP_PROXY_WORKER_IS_MATCH;
    }

    /*
     * We need to find the start of the path and
     * therefore we know the length of the scheme://hostname/
     * part to we can force-lowercase everything up to
     * the start of the path.
     */
    c = ap_strchr_c(c+3, '/');
    if (c) {
        char *pathstart;
        pathstart = url_copy + (c - url);
        *pathstart = '\0';
        ap_str_tolower(url_copy);
        min_match = strlen(url_copy);
        *pathstart = '/';
    }
    else {
        ap_str_tolower(url_copy);
        min_match = strlen(url_copy);
    }

    /*
     * Do a "longest match" on the worker name to find the worker that
     * fits best to the URL, but keep in mind that we must have at least
     * a minimum matching of length min_match such that
     * scheme://hostname[:port] matches between worker and url.
     */
    if (balancer) {
        proxy_worker **worker = (proxy_worker **)balancer->workers->elts;
        for (i = 0; i < balancer->workers->nelts; i++, worker++) {
            if (worker_matches(*worker, url_copy, url_len,
                               min_match, &max_match, mask)) {
                max_worker = *worker;
            }
        }
    }
    else {
        proxy_worker *worker = (proxy_worker *)conf->workers->elts;
        for (i = 0; i < conf->workers->nelts; i++, worker++) {
            if (worker_matches(worker, url_copy, url_len,
                               min_match, &max_match, mask)) {
                max_worker = worker;
            }
        }
    }

    return max_worker;
}

PROXY_DECLARE(proxy_worker *) ap_proxy_get_worker(apr_pool_t *p,
                                                  proxy_balancer *balancer,
                                                  proxy_server_conf *conf,
                                                  const char *url)
{
    return ap_proxy_get_worker_ex(p, balancer, conf, url, 0);
}

/*
 * To create a worker from scratch first we define the
 * specifics of the worker; this is all local data.
 * We then allocate space for it if data needs to be
 * shared. This allows for dynamic addition during
 * config and runtime.
 */
PROXY_DECLARE(char *) ap_proxy_define_worker_ex(apr_pool_t *p,
                                             proxy_worker **worker,
                                             proxy_balancer *balancer,
                                             proxy_server_conf *conf,
                                             const char *url,
                                             unsigned int mask)
{
    apr_status_t rv;
    proxy_worker_shared *wshared;
    const char *ptr = NULL, *sockpath = NULL, *pdollars = NULL;
    apr_port_t port_of_scheme;
    int address_not_reusable = 0;
    apr_uri_t uri;

    /*
     * Look to see if we are using UDS:
     * require format: unix:/path/foo/bar.sock|http://ignored/path2/
     * This results in talking http to the socket at /path/foo/bar.sock
     */
    if (!ap_cstr_casecmpn(url, "unix:", 5)
            && (ptr = ap_strchr_c(url + 5, '|'))) {
        rv = apr_uri_parse(p, apr_pstrmemdup(p, url, ptr - url), &uri);
        if (rv == APR_SUCCESS) {
            sockpath = ap_runtime_dir_relative(p, uri.path);
            ptr++;    /* so we get the scheme for the uds */
        }
        else {
            ptr = url;
        }
    }
    else {
        ptr = url;
    }

    if (mask & AP_PROXY_WORKER_IS_MATCH) {
        /* apr_uri_parse() will accept the '$' sign anywhere in the URL but
         * in the :port part, and we don't want scheme://host:port$1$2/path
         * to fail (e.g. "ProxyPassMatch ^/(a|b)(/.*)? http://host:port$2").
         * So we trim all the $n from the :port and prepend them in uri.path
         * afterward for apr_uri_unparse() to restore the original URL below.
         * If a dollar substitution is found in the hostname[:port] part of
         * the URL, reusing address and connections in the same worker is not
         * possible (the current implementation of active connections cache
         * handles/assumes a single origin server:port per worker only), so
         * we set address_not_reusable here during parsing to take that into
         * account in the worker settings below.
         */
#define IS_REF(x) (x[0] == '$' && apr_isdigit(x[1]))
        const char *pos = ap_strstr_c(ptr, "://");
        if (pos) {
            pos += 3;
            while (*pos && *pos != ':' && *pos != '/') {
                if (*pos == '$') {
                    address_not_reusable = 1;
                }
                pos++;
            }
            if (*pos == ':') {
                pos++;
                while (*pos && !IS_REF(pos) && *pos != '/') {
                    pos++;
                }
                if (IS_REF(pos)) {
                    struct iovec vec[2];
                    const char *path = pos + 2;
                    while (*path && *path != '/') {
                        path++;
                    }
                    pdollars = apr_pstrmemdup(p, pos, path - pos);
                    vec[0].iov_base = (void *)ptr;
                    vec[0].iov_len = pos - ptr;
                    vec[1].iov_base = (void *)path;
                    vec[1].iov_len = strlen(path);
                    ptr = apr_pstrcatv(p, vec, 2, NULL);
                    address_not_reusable = 1;
                }
            }
        }
#undef IS_REF
    }

    /* Normalize the url (worker name) */
    rv = apr_uri_parse(p, ptr, &uri);
    if (rv != APR_SUCCESS) {
        return apr_pstrcat(p, "Unable to parse URL: ", url, NULL);
    }
    if (!uri.scheme) {
        return apr_pstrcat(p, "URL must be absolute!: ", url, NULL);
    }
    if (!uri.hostname || !*uri.hostname) {
        if (sockpath) {
            /* allow for unix:/path|http: */
            uri.hostname = "localhost";
        }
        else {
            return apr_pstrcat(p, "URL must be absolute!: ", url, NULL);
        }
    }
    else {
        ap_str_tolower(uri.hostname);
    }
    ap_str_tolower(uri.scheme);
    port_of_scheme = ap_proxy_port_of_scheme(uri.scheme);
    if (uri.port && uri.port == port_of_scheme) {
        uri.port = 0;
    }
    if (pdollars) {
        /* Restore/prepend pdollars into the path. */
        uri.path = apr_pstrcat(p, pdollars, uri.path, NULL);
    }
    ptr = apr_uri_unparse(p, &uri, APR_URI_UNP_REVEALPASSWORD);

    /*
     * Workers can be associated w/ balancers or on their
     * own; ie: the generic reverse-proxy or a worker
     * in a simple ProxyPass statement. eg:
     *
     *      ProxyPass / http://www.example.com
     *
     * in which case the worker goes in the conf slot.
     */
    if (balancer) {
        proxy_worker **runtime;
        /* recall that we get a ptr to the ptr here */
        runtime = apr_array_push(balancer->workers);
        *worker = *runtime = apr_palloc(p, sizeof(proxy_worker));   /* right to left baby */
        /* we've updated the list of workers associated with
         * this balancer *locally* */
        balancer->wupdated = apr_time_now();
    } else if (conf) {
        *worker = apr_array_push(conf->workers);
    } else {
        /* we need to allocate space here */
        *worker = apr_palloc(p, sizeof(proxy_worker));
    }
    memset(*worker, 0, sizeof(proxy_worker));
    
    /* right here we just want to tuck away the worker info.
     * if called during config, we don't have shm setup yet,
     * so just note the info for later. */
    if (mask & AP_PROXY_WORKER_IS_MALLOCED)
        wshared = ap_malloc(sizeof(proxy_worker_shared));  /* will be freed ap_proxy_share_worker */
    else
        wshared = apr_palloc(p, sizeof(proxy_worker_shared));
    memset(wshared, 0, sizeof(proxy_worker_shared));

    if (PROXY_STRNCPY(wshared->name, ptr) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(02808)
        "Alert! worker name (%s) too long; truncated to: %s", ptr, wshared->name);
    }
    if (PROXY_STRNCPY(wshared->scheme, uri.scheme) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(010117)
        "Alert! worker scheme (%s) too long; truncated to: %s", uri.scheme, wshared->scheme);
    }
    if (PROXY_STRNCPY(wshared->hostname_ex, uri.hostname) != APR_SUCCESS) {
        return apr_psprintf(p, "worker hostname (%s) too long", uri.hostname);
    }
    if (PROXY_STRNCPY(wshared->hostname, uri.hostname) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(010118)
        "worker hostname (%s) too long; truncated for legacy modules that do not use "
        "proxy_worker_shared->hostname_ex: %s", uri.hostname, wshared->hostname);
    }
    if (sockpath) {
        if (PROXY_STRNCPY(wshared->uds_path, sockpath) != APR_SUCCESS) {
            return apr_psprintf(p, "worker uds path (%s) too long", sockpath);
        }
        (*worker)->uds_name = apr_pstrcat(p, "unix:", sockpath, "|", ptr, NULL);
    }
    wshared->port = (uri.port) ? uri.port : port_of_scheme;
    wshared->flush_packets = flush_off;
    wshared->flush_wait = PROXY_FLUSH_WAIT;
    wshared->address_ttl = (address_not_reusable) ? 0 : -1;
    wshared->is_address_reusable = (address_not_reusable == 0);
    wshared->disablereuse = (address_not_reusable != 0);
    wshared->lbfactor = 100;
    wshared->passes = 1;
    wshared->fails = 1;
    wshared->interval = apr_time_from_sec(HCHECK_WATHCHDOG_DEFAULT_INTERVAL);
    wshared->smax = -1;
    wshared->hash.def = ap_proxy_hashfunc(wshared->name, PROXY_HASHFUNC_DEFAULT);
    wshared->hash.fnv = ap_proxy_hashfunc(wshared->name, PROXY_HASHFUNC_FNV);
    wshared->was_malloced = (mask & AP_PROXY_WORKER_IS_MALLOCED) != 0;
    if (mask & AP_PROXY_WORKER_IS_MATCH) {
        wshared->is_name_matchable = 1;
        wshared->is_host_matchable = (address_not_reusable != 0);

        /* Before AP_PROXY_WORKER_IS_MATCH (< 2.4.47), a regex worker with
         * dollar substitution was never matched against any actual URL, thus
         * the requests fell through the generic worker. Now if a ProyPassMatch
         * matches, a worker (and its parameters) is always used to determine
         * the properties of the connection with the origin server. So for
         * instance the same "timeout=" will be enforced for all the requests
         * matched by the same ProyPassMatch worker, which is an improvement
         * compared to the global/vhost [Proxy]Timeout applied by the generic
         * worker. Likewise, address and connection reuse is the default for
         * a ProyPassMatch worker with no dollar substitution, just like a
         * "normal" worker. However to avoid DNS and connection reuse compat
         * issues, connection reuse is disabled by default if there is any
         * substitution in the uri-path (an explicit enablereuse=on can still
         * opt-in), and reuse is even disabled definitively for substitutions
         * happening in the hostname[:port] (is_address_reusable was unset
         * above so it will prevent enablereuse=on to apply anyway).
         */
        if (ap_strchr_c(wshared->name, '$')) {
            wshared->disablereuse = 1;
        }
    }
    if (!balancer) {
        wshared->status |= PROXY_WORKER_IGNORE_ERRORS;
    }

    (*worker)->hash = wshared->hash;
    (*worker)->context = NULL;
    (*worker)->cp = NULL;
    (*worker)->balancer = balancer;
    (*worker)->s = wshared;

    return NULL;
}

PROXY_DECLARE(char *) ap_proxy_define_worker(apr_pool_t *p,
                                             proxy_worker **worker,
                                             proxy_balancer *balancer,
                                             proxy_server_conf *conf,
                                             const char *url,
                                             int do_malloc)
{
    return ap_proxy_define_worker_ex(p, worker, balancer, conf, url,
                                     AP_PROXY_WORKER_IS_PREFIX |
                                     (do_malloc ? AP_PROXY_WORKER_IS_MALLOCED
                                                : 0));
}

/* DEPRECATED */
PROXY_DECLARE(char *) ap_proxy_define_match_worker(apr_pool_t *p,
                                             proxy_worker **worker,
                                             proxy_balancer *balancer,
                                             proxy_server_conf *conf,
                                             const char *url,
                                             int do_malloc)
{
    return ap_proxy_define_worker_ex(p, worker, balancer, conf, url,
                                     AP_PROXY_WORKER_IS_MATCH |
                                     (do_malloc ? AP_PROXY_WORKER_IS_MALLOCED
                                                : 0));
}

/*
 * Create an already defined worker and free up memory
 */
PROXY_DECLARE(apr_status_t) ap_proxy_share_worker(proxy_worker *worker, proxy_worker_shared *shm,
                                                  int i)
{
    char *action = "copying";
    if (!shm || !worker->s)
        return APR_EINVAL;

    if ((worker->s->hash.def != shm->hash.def) ||
        (worker->s->hash.fnv != shm->hash.fnv)) {
        memcpy(shm, worker->s, sizeof(proxy_worker_shared));
        if (worker->s->was_malloced)
            free(worker->s); /* was malloced in ap_proxy_define_worker */
    } else {
        action = "re-using";
    }
    worker->s = shm;
    worker->s->index = i;

    if (APLOGdebug(ap_server_conf)) {
        apr_pool_t *pool;
        apr_pool_create(&pool, ap_server_conf->process->pool);
        apr_pool_tag(pool, "proxy_worker_name");
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(02338)
                     "%s shm[%d] (0x%pp) for worker: %s", action, i, (void *)shm,
                     ap_proxy_worker_get_name(worker));
        if (pool) {
            apr_pool_destroy(pool);
        }
    }
    return APR_SUCCESS;
}

PROXY_DECLARE(apr_status_t) ap_proxy_initialize_worker(proxy_worker *worker, server_rec *s, apr_pool_t *p)
{
    APR_OPTIONAL_FN_TYPE(http2_get_num_workers) *get_h2_num_workers;
    apr_status_t rv = APR_SUCCESS;
    int max_threads, minw, maxw;

    if (worker->s->status & PROXY_WORKER_INITIALIZED) {
        /* The worker is already initialized */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00924)
                     "worker %s shared already initialized",
                     ap_proxy_worker_get_name(worker));
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00925)
                     "initializing worker %s shared",
                     ap_proxy_worker_get_name(worker));
        /* Set default parameters */
        if (!worker->s->retry_set) {
            worker->s->retry = apr_time_from_sec(PROXY_WORKER_DEFAULT_RETRY);
        }
        /* Consistently set address and connection reusabilty: when reuse
         * is disabled by configuration, or when the address is known already
         * to not be reusable for this worker (in any case, thus ignore/force
         * DisableReuse).
         */
        if (!worker->s->address_ttl || (!worker->s->address_ttl_set
                                        && worker->s->disablereuse)) {
            worker->s->is_address_reusable = 0;
        }
        if (!worker->s->is_address_reusable && !worker->s->disablereuse) {
            /* Explicit enablereuse=on can't work in this case, warn user. */
            if (worker->s->disablereuse_set) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10400)
                             "enablereuse/disablereuse ignored for worker %s",
                             ap_proxy_worker_get_name(worker));
            }
            worker->s->disablereuse = 1;
        }

        /*
         * When mod_http2 is loaded we might have more threads since it has
         * its own pool of processing threads.
         */
        ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads);
        get_h2_num_workers = APR_RETRIEVE_OPTIONAL_FN(http2_get_num_workers);
        if (get_h2_num_workers) {
            get_h2_num_workers(s, &minw, &maxw);
            /* So now the max is:
             *   max_threads-1 threads for HTTP/1 each requiring one connection
             *   + one thread for HTTP/2 requiring maxw connections
             */
            max_threads = max_threads - 1 + maxw;
        }
        if (max_threads > 1) {
            /* Default hmax is max_threads to scale with the load and never
             * wait for an idle connection to proceed.
             */
            if (worker->s->hmax == 0) {
                worker->s->hmax = max_threads;
            }
            if (worker->s->smax == -1 || worker->s->smax > worker->s->hmax) {
                worker->s->smax = worker->s->hmax;
            }
            /* Set min to be lower than smax */
            if (worker->s->min > worker->s->smax) {
                worker->s->min = worker->s->smax;
            }
        }
        else {
            /* This will suppress the apr_reslist creation */
            worker->s->min = worker->s->smax = worker->s->hmax = 0;
        }
    }

    /* What if local is init'ed and shm isn't?? Even possible? */
    if (worker->local_status & PROXY_WORKER_INITIALIZED) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00926)
                     "worker %s local already initialized",
                     ap_proxy_worker_get_name(worker));
    }
    else {
        apr_global_mutex_lock(proxy_mutex);
        /* Check again after we got the lock if we are still uninitialized */
        if (!(AP_VOLATILIZE_T(unsigned int, worker->local_status) & PROXY_WORKER_INITIALIZED)) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00927)
                         "initializing worker %s local",
                         ap_proxy_worker_get_name(worker));
            /* Now init local worker data */
#if APR_HAS_THREADS
            if (worker->tmutex == NULL) {
                rv = apr_thread_mutex_create(&(worker->tmutex), APR_THREAD_MUTEX_DEFAULT, p);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00928)
                                 "can not create worker thread mutex");
                    apr_global_mutex_unlock(proxy_mutex);
                    return rv;
                }
            }
#endif
            if (worker->cp == NULL)
                init_conn_pool(p, worker, s);
            if (worker->cp == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00929)
                             "can not create connection pool");
                apr_global_mutex_unlock(proxy_mutex);
                return APR_EGENERAL;
            }

            if (worker->s->hmax) {
                rv = apr_reslist_create(&(worker->cp->res),
                                        worker->s->min, worker->s->smax,
                                        worker->s->hmax, worker->s->ttl,
                                        connection_constructor, connection_destructor,
                                        worker, worker->cp->pool);

                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00930)
                    "initialized pool in child %" APR_PID_T_FMT " for (%s:%d) min=%d max=%d smax=%d",
                     getpid(), worker->s->hostname_ex, (int)worker->s->port,
                     worker->s->min, worker->s->hmax, worker->s->smax);

                /* Set the acquire timeout */
                if (rv == APR_SUCCESS && worker->s->acquire_set) {
                    apr_reslist_timeout_set(worker->cp->res, worker->s->acquire);
                }

            }
            else {
                void *conn;

                rv = connection_constructor(&conn, worker, worker->cp->pool);
                worker->cp->conn = conn;

                ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(00931)
                     "initialized single connection worker in child %" APR_PID_T_FMT " for (%s:%d)",
                     getpid(), worker->s->hostname_ex,
                     (int)worker->s->port);
            }
            if (rv == APR_SUCCESS) {
                worker->local_status |= (PROXY_WORKER_INITIALIZED);
            }
        }
        apr_global_mutex_unlock(proxy_mutex);

    }
    if (rv == APR_SUCCESS) {
        worker->s->status |= (PROXY_WORKER_INITIALIZED);
    }
    return rv;
}

static int ap_proxy_retry_worker(const char *proxy_function, proxy_worker *worker,
        server_rec *s)
{
    if (worker->s->status & PROXY_WORKER_IN_ERROR) {
        if (PROXY_WORKER_IS(worker, PROXY_WORKER_STOPPED)) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(3305)
                         "%s: Won't retry worker (%s:%d): stopped",
                         proxy_function, worker->s->hostname_ex,
                         (int)worker->s->port);
            return DECLINED;
        }
        if ((worker->s->status & PROXY_WORKER_IGNORE_ERRORS)
            || apr_time_now() > worker->s->error_time + worker->s->retry) {
            ++worker->s->retries;
            worker->s->status &= ~PROXY_WORKER_IN_ERROR;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00932)
                         "%s: worker for (%s:%d) has been marked for retry",
                         proxy_function, worker->s->hostname_ex,
                         (int)worker->s->port);
            return OK;
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00933)
                         "%s: too soon to retry worker for (%s:%d)",
                         proxy_function, worker->s->hostname_ex,
                         (int)worker->s->port);
            return DECLINED;
        }
    }
    else {
        return OK;
    }
}

/*
 * In the case of the reverse proxy, we need to see if we
 * were passed a UDS url (eg: from mod_proxy) and adjust uds_path
 * as required.  
 */
static int fixup_uds_filename(request_rec *r) 
{
    char *uds_url = r->filename + 6, *origin_url;

    if (!strncmp(r->filename, "proxy:", 6) &&
            !ap_cstr_casecmpn(uds_url, "unix:", 5) &&
            (origin_url = ap_strchr(uds_url + 5, '|'))) {
        char *uds_path = NULL, *col;
        apr_uri_t urisock;
        apr_status_t rv;

        *origin_url = '\0';
        rv = apr_uri_parse(r->pool, uds_url, &urisock);
        *origin_url++ = '|';

        if (rv == APR_SUCCESS && urisock.path && (!urisock.hostname
                                                  || !urisock.hostname[0])) {
            uds_path = ap_runtime_dir_relative(r->pool, urisock.path);
        }
        if (!uds_path || !(col = ap_strchr(origin_url, ':'))) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10292)
                    "Invalid proxy UDS filename (%s)", r->filename);
            apr_table_unset(r->notes, "uds_path");
            return HTTP_BAD_REQUEST;
        }
        apr_table_setn(r->notes, "uds_path", uds_path);

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                "*: fixup UDS from %s: %s (%s)",
                r->filename, origin_url, uds_path);

        /* The hostname part of the URL is not mandated for UDS though
         * the canon_handler hooks will require it. ProxyPass URLs are
         * fixed at load time by adding "localhost" automatically in the
         * worker URL, but SetHandler "proxy:unix:/udspath|scheme:[//]"
         * URLs are not so we have to fix it here the same way.
         */
        if (!col[1]) {
            /* origin_url is "scheme:" */
            r->filename = apr_pstrcat(r->pool, "proxy:",
                                      origin_url, "//localhost",
                                      NULL);
        }
        /* For a SetHandler "proxy:..." in a <Location "/path">, the "/path"
         * is appended to r->filename, hence the below origin_url cases too:
         */
        else if (col[1] == '/' && (col[2] != '/'    /* "scheme:/path" */
                                   || col[3] == '/' /* "scheme:///path" */
                                   || !col[3])) {   /* "scheme://" */
            char *scheme = origin_url;
            *col = '\0'; /* nul terminate scheme */
            if (col[2] != '/') {
                origin_url = col + 1;
            }
            else {
                origin_url = col + 3;
            }
            r->filename = apr_pstrcat(r->pool, "proxy:",
                                      scheme, "://localhost",
                                      origin_url, NULL);
        }
        else {
            /* origin_url is normal "scheme://host/path", can overwrite
             * the UDS part of r->filename in place.
             */
            memmove(uds_url, origin_url, strlen(origin_url) + 1);
        }
        return OK;
    }

    apr_table_unset(r->notes, "uds_path");
    return DECLINED;
}

/* Deprecated (unused upstream) */
PROXY_DECLARE(int) ap_proxy_fixup_uds_filename(request_rec *r)
{
    return fixup_uds_filename(r);
}

PROXY_DECLARE(const char *) ap_proxy_interpolate(request_rec *r,
                                                 const char *str)
{
    /* Interpolate an env str in a configuration string
     * Syntax ${var} --> value_of(var)
     * Method: replace one var, and recurse on remainder of string
     * Nothing clever here, and crap like nested vars may do silly things
     * but we'll at least avoid sending the unwary into a loop
     */
    const char *start;
    const char *end;
    const char *var;
    const char *val;
    const char *firstpart;

    start = ap_strstr_c(str, "${");
    if (start == NULL) {
        return str;
    }
    end = ap_strchr_c(start+2, '}');
    if (end == NULL) {
        return str;
    }
    /* OK, this is syntax we want to interpolate.  Is there such a var ? */
    var = apr_pstrmemdup(r->pool, start+2, end-(start+2));
    val = apr_table_get(r->subprocess_env, var);
    firstpart = apr_pstrmemdup(r->pool, str, (start-str));

    if (val == NULL) {
        return apr_pstrcat(r->pool, firstpart,
                           ap_proxy_interpolate(r, end+1), NULL);
    }
    else {
        return apr_pstrcat(r->pool, firstpart, val,
                           ap_proxy_interpolate(r, end+1), NULL);
    }
}

static apr_array_header_t *proxy_vars(request_rec *r, apr_array_header_t *hdr)
{
    int i;
    apr_array_header_t *ret = apr_array_make(r->pool, hdr->nelts,
                                             sizeof (struct proxy_alias));
    struct proxy_alias *old = (struct proxy_alias *) hdr->elts;

    for (i = 0; i < hdr->nelts; ++i) {
        struct proxy_alias *newcopy = apr_array_push(ret);
        newcopy->fake = (old[i].flags & PROXYPASS_INTERPOLATE)
                        ? ap_proxy_interpolate(r, old[i].fake) : old[i].fake;
        newcopy->real = (old[i].flags & PROXYPASS_INTERPOLATE)
                        ? ap_proxy_interpolate(r, old[i].real) : old[i].real;
    }
    return ret;
}

PROXY_DECLARE(int) ap_proxy_canon_url(request_rec *r)
{
    char *url, *p;
    int access_status;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                 &proxy_module);

    if (!r->proxyreq || !r->filename || strncmp(r->filename, "proxy:", 6) != 0)
        return DECLINED;

    /* Put the UDS path appart if any (and not already stripped) */
    if (r->proxyreq == PROXYREQ_REVERSE) {
        access_status = fixup_uds_filename(r);
        if (ap_is_HTTP_ERROR(access_status)) {
            return access_status;
        }
    }

    /* Keep this after fixup_uds_filename() */
    url = apr_pstrdup(r->pool, r->filename + 6);

    if ((dconf->interpolate_env == 1) && (r->proxyreq == PROXYREQ_REVERSE)) {
        /* create per-request copy of reverse proxy conf,
         * and interpolate vars in it
         */
        proxy_req_conf *rconf = apr_palloc(r->pool, sizeof(proxy_req_conf));
        ap_set_module_config(r->request_config, &proxy_module, rconf);
        rconf->raliases = proxy_vars(r, dconf->raliases);
        rconf->cookie_paths = proxy_vars(r, dconf->cookie_paths);
        rconf->cookie_domains = proxy_vars(r, dconf->cookie_domains);
    }

    /* canonicalise each specific scheme */
    if ((access_status = proxy_run_canon_handler(r, url))) {
        return access_status;
    }

    p = strchr(url, ':');
    if (p == NULL || p == url)
        return HTTP_BAD_REQUEST;

    return OK;      /* otherwise; we've done the best we can */
}

PROXY_DECLARE(int) ap_proxy_pre_request(proxy_worker **worker,
                                        proxy_balancer **balancer,
                                        request_rec *r,
                                        proxy_server_conf *conf, char **url)
{
    int access_status;

    access_status = proxy_run_pre_request(worker, balancer, r, conf, url);
    if (access_status == DECLINED && *balancer == NULL) {
        /* UDS path stripped from *url by proxy_fixup() already */
        *worker = ap_proxy_get_worker_ex(r->pool, NULL, conf, *url,
                                         AP_PROXY_WORKER_NO_UDS);
        if (*worker) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                          "%s: found worker %s for %s",
                          (*worker)->s->scheme, (*worker)->s->name, *url);
            access_status = OK;
        }
        else if (r->proxyreq == PROXYREQ_PROXY) {
            if (conf->forward) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                              "*: found forward proxy worker for %s", *url);
                *worker = conf->forward;
                access_status = OK;
                /*
                 * The forward worker does not keep connections alive, so
                 * ensure that mod_proxy_http does the correct thing
                 * regarding the Connection header in the request.
                 */
                apr_table_setn(r->subprocess_env, "proxy-nokeepalive", "1");
            }
        }
        else if (r->proxyreq == PROXYREQ_REVERSE) {
            if (conf->reverse) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                              "*: using default reverse proxy worker for %s "
                              "(no keepalive)", *url);
                *worker = conf->reverse;
                access_status = OK;
                /*
                 * The reverse worker does not keep connections alive, so
                 * ensure that mod_proxy_http does the correct thing
                 * regarding the Connection header in the request.
                 */
                apr_table_setn(r->subprocess_env, "proxy-nokeepalive", "1");
            }
        }
    }
    else if (access_status == DECLINED && *balancer != NULL) {
        /* All the workers are busy */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00934)
                      "all workers are busy.  Unable to serve %s", *url);
        access_status = HTTP_SERVICE_UNAVAILABLE;
    }

    return access_status;
}

PROXY_DECLARE(int) ap_proxy_post_request(proxy_worker *worker,
                                         proxy_balancer *balancer,
                                         request_rec *r,
                                         proxy_server_conf *conf)
{
    int access_status = OK;
    if (balancer) {
        access_status = proxy_run_post_request(worker, balancer, r, conf);
        if (access_status == DECLINED) {
            access_status = OK; /* no post_request handler available */
            /* TODO: recycle direct worker */
        }
    }

    return access_status;
}

/* DEPRECATED */
PROXY_DECLARE(int) ap_proxy_connect_to_backend(apr_socket_t **newsock,
                                               const char *proxy_function,
                                               apr_sockaddr_t *backend_addr,
                                               const char *backend_name,
                                               proxy_server_conf *conf,
                                               request_rec *r)
{
    apr_status_t rv;
    int connected = 0;
    int loglevel;

    while (backend_addr && !connected) {
        if ((rv = apr_socket_create(newsock, backend_addr->family,
                                    SOCK_STREAM, 0, r->pool)) != APR_SUCCESS) {
            loglevel = backend_addr->next ? APLOG_DEBUG : APLOG_ERR;
            ap_log_rerror(APLOG_MARK, loglevel, rv, r, APLOGNO(00935)
                          "%s: error creating fam %d socket for target %s",
                          proxy_function, backend_addr->family, backend_name);
            /*
             * this could be an IPv6 address from the DNS but the
             * local machine won't give us an IPv6 socket; hopefully the
             * DNS returned an additional address to try
             */
            backend_addr = backend_addr->next;
            continue;
        }

        if (conf->recv_buffer_size > 0 &&
            (rv = apr_socket_opt_set(*newsock, APR_SO_RCVBUF,
                                     conf->recv_buffer_size))) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00936)
                          "apr_socket_opt_set(SO_RCVBUF): Failed to set "
                          "ProxyReceiveBufferSize, using default");
        }

        rv = apr_socket_opt_set(*newsock, APR_TCP_NODELAY, 1);
        if (rv != APR_SUCCESS && rv != APR_ENOTIMPL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00937)
                          "apr_socket_opt_set(APR_TCP_NODELAY): "
                          "Failed to set");
        }

        /* Set a timeout on the socket */
        if (conf->timeout_set) {
            apr_socket_timeout_set(*newsock, conf->timeout);
        }
        else {
            apr_socket_timeout_set(*newsock, r->server->timeout);
        }

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: fam %d socket created to connect to %s",
                      proxy_function, backend_addr->family, backend_name);

        if (conf->source_address) {
            apr_sockaddr_t *local_addr;
            /* Make a copy since apr_socket_bind() could change
             * conf->source_address, which we don't want.
             */
            local_addr = apr_pmemdup(r->pool, conf->source_address,
                                     sizeof(apr_sockaddr_t));
            local_addr->pool = r->pool;
            rv = apr_socket_bind(*newsock, local_addr);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00938)
                              "%s: failed to bind socket to local address",
                              proxy_function);
            }
        }

        /* make the connection out of the socket */
        rv = apr_socket_connect(*newsock, backend_addr);

        /* if an error occurred, loop round and try again */
        if (rv != APR_SUCCESS) {
            apr_socket_close(*newsock);
            loglevel = backend_addr->next ? APLOG_DEBUG : APLOG_ERR;
            ap_log_rerror(APLOG_MARK, loglevel, rv, r, APLOGNO(00939)
                          "%s: attempt to connect to %pI (%s) failed",
                          proxy_function, backend_addr, backend_name);
            backend_addr = backend_addr->next;
            continue;
        }
        connected = 1;
    }
    return connected ? 0 : 1;
}

PROXY_DECLARE(int) ap_proxy_acquire_connection(const char *proxy_function,
                                               proxy_conn_rec **conn,
                                               proxy_worker *worker,
                                               server_rec *s)
{
    apr_status_t rv;

    if (!PROXY_WORKER_IS_USABLE(worker)) {
        /* Retry the worker */
        ap_proxy_retry_worker(proxy_function, worker, s);

        if (!PROXY_WORKER_IS_USABLE(worker)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00940)
                         "%s: disabled connection for (%s:%d)",
                         proxy_function, worker->s->hostname_ex,
                         (int)worker->s->port);
            return HTTP_SERVICE_UNAVAILABLE;
        }
    }

    if (worker->s->hmax && worker->cp->res) {
        rv = apr_reslist_acquire(worker->cp->res, (void **)conn);
    }
    else {
        /* create the new connection if the previous was destroyed */
        if (!worker->cp->conn) {
            rv = connection_constructor((void **)conn, worker, worker->cp->pool);
        }
        else {
            *conn = worker->cp->conn;
            worker->cp->conn = NULL;
            rv = APR_SUCCESS;
        }
    }

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00941)
                     "%s: failed to acquire connection for (%s:%d)",
                     proxy_function, worker->s->hostname_ex,
                     (int)worker->s->port);
        return HTTP_SERVICE_UNAVAILABLE;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00942)
                 "%s: has acquired connection for (%s:%d)",
                 proxy_function, worker->s->hostname_ex,
                 (int)worker->s->port);

    (*conn)->worker = worker;
    (*conn)->inreslist = 0;

    return OK;
}

PROXY_DECLARE(int) ap_proxy_release_connection(const char *proxy_function,
                                               proxy_conn_rec *conn,
                                               server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00943)
                "%s: has released connection for (%s:%d)",
                proxy_function, conn->worker->s->hostname_ex,
                (int)conn->worker->s->port);
    connection_cleanup(conn);

    return OK;
}

static APR_INLINE void proxy_address_inc(proxy_address *address)
{
    apr_uint32_t old = apr_atomic_inc32(&address->refcount);
    ap_assert(old > 0 && old < APR_UINT32_MAX);
}

static APR_INLINE void proxy_address_dec(proxy_address *address)
{
    /* Use _add32(, -1) since _dec32()'s returned value does not help */
    apr_uint32_t old = apr_atomic_add32(&address->refcount, -1);
    ap_assert(old > 0);
    if (old == 1) {
        apr_pool_destroy(address->addr->pool);
    }
}

static apr_status_t proxy_address_cleanup(void *address)
{
    proxy_address_dec(address);
    return APR_SUCCESS;
}

static APR_INLINE proxy_address *worker_address_get(proxy_worker *worker)
{
    /* No _readptr() so let's _casptr(, NULL, NULL) instead */
    return apr_atomic_casptr((void *)&worker->address, NULL, NULL);
}

/* XXX: Call when PROXY_THREAD_LOCK()ed only! */
static APR_INLINE void worker_address_set(proxy_worker *worker,
                                          proxy_address *to)
{
    proxy_address *old = apr_atomic_xchgptr((void *)&worker->address, to);
    if (old && old != to) {
        proxy_address_dec(old);
    }
}

static apr_status_t worker_address_resolve(proxy_worker *worker,
                                           apr_sockaddr_t **paddr,
                                           const char *hostname,
                                           apr_port_t hostport,
                                           const char *proxy_function,
                                           request_rec *r, server_rec *s)
{
    apr_status_t rv;
    apr_pool_t *pool = NULL;

    apr_pool_create(&pool, worker->cp->dns_pool);
    rv = apr_sockaddr_info_get(paddr, hostname, APR_UNSPEC,
                               hostport, 0, pool);
    if (rv != APR_SUCCESS) {
        if (r && !s) {
            proxyerror_core(r, HTTP_INTERNAL_SERVER_ERROR,
                            apr_pstrcat(pool,
                                        "DNS lookup failure for: ",
                                        hostname, NULL),
                            rv);
        }
        else if (r) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(10477)
                          "%s: resolving worker %s address",
                          proxy_function, hostname);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(10478)
                         "%s: resolving worker %s address",
                         proxy_function, hostname);
        }
        apr_pool_destroy(pool);
        return rv;
    }

    if (r ? APLOGrdebug(r) : APLOGdebug(s)) {
        char *addrs = NULL;
        apr_sockaddr_t *addr = *paddr;
        for (; addr; addr = addr->next) {
            addrs = apr_psprintf(pool, "%s%s%pI",
                                 addrs ? addrs : "",
                                 addrs ? ", " : "",
                                 addr);
        }
        if (r) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10479)
                          "%s: %s resolved to %s",
                          proxy_function, hostname, addrs);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10480)
                         "%s: %s resolved to %s",
                         proxy_function, hostname, addrs);
        }
    }

    return APR_SUCCESS;
}

static int proxy_addrs_equal(const apr_sockaddr_t *addr1,
                             const apr_sockaddr_t *addr2)
{
    const apr_sockaddr_t *base2 = addr2, *pos2;
    while (addr1 && addr2) {
        for (pos2 = base2; pos2; pos2 = pos2->next) {
            if (apr_sockaddr_equal(pos2, addr1)) {
                break;
            }
        }
        if (!pos2) {
            return 0;
        }
        addr1 = addr1->next;
        addr2 = addr2->next;
    }
    if (addr1 || addr2) {
        return 0;
    }
    return 1;
}

PROXY_DECLARE(apr_status_t) ap_proxy_determine_address(const char *proxy_function,
                                                       proxy_conn_rec *conn,
                                                       const char *hostname,
                                                       apr_port_t hostport,
                                                       unsigned int flags,
                                                       request_rec *r,
                                                       server_rec *s)
{
    proxy_worker *worker = conn->worker;
    apr_status_t rv;

    /*
     * Worker can have the single constant backend adress.
     * The single DNS lookup is used once per worker.
     * If dynamic change is needed then set the addr to NULL
     * inside dynamic config to force the lookup.
     * The worker's addressTTL parameter may also be configured
     * to perform the DNS lookups only when the TTL expires,
     * or each time if that TTL is zero.
     */
    if (!worker->s->is_address_reusable) {
        conn->hostname = apr_pstrdup(conn->pool, hostname);
        conn->port = hostport;

        rv = apr_sockaddr_info_get(&conn->addr, hostname, APR_UNSPEC,
                                   hostport, 0, conn->pool);
        if (rv != APR_SUCCESS) {
            if (r && !s) {
                proxyerror_core(r, HTTP_INTERNAL_SERVER_ERROR,
                                apr_pstrcat(r->pool, "DNS lookup failure for: ",
                                            hostname, NULL), rv);
            }
            else if (r) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(10475)
                              "%s: resolving backend %s address",
                              proxy_function, hostname);
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(10476)
                              "%s: resolving backend %s address",
                              proxy_function, hostname);
            }
            return rv;
        }
    }
    else {
        apr_sockaddr_t *addr = NULL;
        proxy_address *address = NULL;
        apr_int32_t ttl = worker->s->address_ttl;
        apr_uint32_t now = 0;

        if (flags & PROXY_DETERMINE_ADDRESS_CHECK) {
            /* The caller wants to check if the address changed, return
             * APR_EEXIST if not, otherwise fall through to update the
             * worker's for everyone to switch.
             */
            if (!conn->addr) {
                /* Need something to compare with */
                return APR_EINVAL;
            }
            rv = worker_address_resolve(worker, &addr,
                                        hostname, hostport,
                                        proxy_function, r, s);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            if (proxy_addrs_equal(conn->addr, addr)) {
                apr_pool_destroy(addr->pool);
                return APR_EEXIST;
            }
        }

        AP_DEBUG_ASSERT(ttl != 0);
        if (ttl > 0) {
            /* TODO: use a monotonic clock here */
            now = apr_time_sec(apr_time_now() - *proxy_start_time);
        }

        /* Addresses are refcounted, destroyed when their refcount reaches 0.
         *
         * One ref is taken by worker->address as the worker's current/latest
         * address, it's dropped when that address expires/changes (see below).
         * The other refs are taken by the connections when using/switching to
         * the current worker address (also below), they are dropped when the
         * conns are destroyed (by the reslist though it should never happen
         * if hmax is greater than the number of threads) OR for an expired
         * conn->address when it's replaced by the new worker->address below.
         *
         * Dereferencing worker->address requires holding the worker mutex or
         * some concurrent connection processing might change/destroy it at any
         * time. So only conn->address is safe to dereference anywhere (unless
         * NULL..) since it has at least the lifetime of the connection.
         */
        if (!addr) {
            address = worker_address_get(worker);
        }
        if (!address
            || conn->address != address
            || apr_atomic_read32(&address->expiry) <= now) {
            PROXY_THREAD_LOCK(worker);

            /* Re-check while locked, might be a new address already */
            if (!addr) {
                address = worker_address_get(worker);
            }
            if (!address || apr_atomic_read32(&address->expiry) <= now) {
                if (!addr) {
                    rv = worker_address_resolve(worker, &addr,
                                                hostname, hostport,
                                                proxy_function, r, s);
                    if (rv != APR_SUCCESS) {
                        PROXY_THREAD_UNLOCK(worker);
                        return rv;
                    }

                    /* Recompute "now" should the DNS be slow
                     * TODO: use a monotonic clock here
                     */
                    now = apr_time_sec(apr_time_now() - *proxy_start_time);
                }

                address = apr_pcalloc(addr->pool, sizeof(*address));
                address->hostname = apr_pstrdup(addr->pool, hostname);
                address->hostport = hostport;
                address->addr = addr;

                if (ttl > 0) {
                    /* We keep each worker's expiry date shared accross all the
                     * children so that they update their address at the same
                     * time, regardless of whether a specific child forced an
                     * address to expire at some point (for connect() issues).
                     */
                    address->expiry = apr_atomic_read32(&worker->s->address_expiry);
                    if (address->expiry <= now) {
                        apr_uint32_t prev, next = (now + ttl) - (now % ttl);
                        do {
                            prev = apr_atomic_cas32(&worker->s->address_expiry,
                                                    next, address->expiry);
                            if (prev == address->expiry) {
                                address->expiry = next;
                                break;
                            }
                            address->expiry = prev;
                        } while (prev <= now);
                    }
                }
                else {
                    /* Never expires */
                    address->expiry = APR_UINT32_MAX;
                }

                /* One ref is for worker->address in any case */
                if (worker->address || worker->cp->addr) {
                    apr_atomic_set32(&address->refcount, 1);
                }
                else {
                    /* Set worker->cp->addr once for compat with third-party
                     * modules. This addr never changed before and can't change
                     * underneath users now because of some TTL configuration.
                     * So we take one more ref for worker->cp->addr to remain
                     * allocated forever (though it might not be up to date..).
                     * Modules should use conn->addr instead of worker->cp-addr
                     * to get the actual address used by each conn, determined
                     * at connect() time.
                     */
                    apr_atomic_set32(&address->refcount, 2);
                    worker->cp->addr = address->addr;
                }

                /* Publish the changes. The old worker address (if any) is no
                 * longer used by this worker, it will be destroyed now if the
                 * worker is the last user (refcount == 1) or by the last conn
                 * using it (refcount > 1).
                 */
                worker_address_set(worker, address);
            }

            /* Take the ref for conn->address (before dropping the mutex so to
             * let no chance for this address be killed before it's used!)
             */
            proxy_address_inc(address);

            PROXY_THREAD_UNLOCK(worker);

            /* Release the old conn address */
            if (conn->address) {
                /* On Windows and OS/2, apr_socket_connect() called from
                 * ap_proxy_connect_backend() does a simple pointer copy of
                 * its given conn->addr[->next] into conn->sock->remote_addr.
                 * Thus conn->addr cannot be freed if the conn->sock should be
                 * kept alive (same new and old addresses) and the old address
                 * is still in conn->sock->remote_addr. In this case we rather
                 * delay the release of the old address by moving the cleanup
                 * to conn->scpool such that it runs when the socket is closed.
                 * In any other case, including other platforms, just release
                 * the old address now since conn->sock->remote_addr is either
                 * obsolete (socket forcibly closed) or a copy on conn->scpool
                 * already (not a dangling pointer).
                 */
                int keep_addr_alive = 0,
                    keep_conn_alive = (conn->sock && conn->addr &&
                                       proxy_addrs_equal(conn->addr,
                                                         address->addr));
                if (keep_conn_alive) {
#if defined(WIN32) || defined(OS2)
                    apr_sockaddr_t *remote_addr = NULL;
                    apr_socket_addr_get(&remote_addr, APR_REMOTE, conn->sock);
                    for (addr = conn->addr; addr; addr = addr->next) {
                        if (addr == remote_addr) {
                            keep_addr_alive = 1;
                            break;
                        }
                    }
#else
                    /* Nothing to do, keep_addr_alive = 0 */
#endif
                }
                else if (conn->sock && (r ? APLOGrdebug(r) : APLOGdebug(s))) {
                    apr_sockaddr_t *local_addr = NULL;
                    apr_sockaddr_t *remote_addr = NULL;
                    apr_socket_addr_get(&local_addr, APR_LOCAL, conn->sock);
                    apr_socket_addr_get(&remote_addr, APR_REMOTE, conn->sock);
                    if (r) {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10481)
                                      "%s: closing connection to %s (%pI<>%pI) on "
                                      "address change", proxy_function, hostname,
                                      local_addr, remote_addr);
                    }
                    else {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10482)
                                     "%s: closing connection to %s (%pI<>%pI) on "
                                     "address change", proxy_function, hostname,
                                     local_addr, remote_addr);
                    }
                }
                if (keep_addr_alive) {
                    apr_pool_cleanup_kill(conn->pool, conn->address,
                                          proxy_address_cleanup);
                    apr_pool_cleanup_register(conn->scpool, conn->address,
                                              proxy_address_cleanup,
                                              apr_pool_cleanup_null);
                }
                else {
                    apr_pool_cleanup_run(conn->pool, conn->address,
                                         proxy_address_cleanup);
                    if (!keep_conn_alive) {
                        conn_cleanup(conn);
                    }
                }
            }

            /* Use the new address */
            apr_pool_cleanup_register(conn->pool, address,
                                      proxy_address_cleanup,
                                      apr_pool_cleanup_null);
            conn->address = address;
            conn->hostname = address->hostname;
            conn->port = address->hostport;
            conn->addr = address->addr;
        }
    }

    return APR_SUCCESS;
}

PROXY_DECLARE(int)
ap_proxy_determine_connection(apr_pool_t *p, request_rec *r,
                              proxy_server_conf *conf,
                              proxy_worker *worker,
                              proxy_conn_rec *conn,
                              apr_uri_t *uri,
                              char **url,
                              const char *proxyname,
                              apr_port_t proxyport,
                              char *server_portstr,
                              int server_portstr_size)
{
    int server_port;
    const char *uds_path;

    /*
     * Break up the URL to determine the host to connect to
     */

    /* we break the URL into host, port, uri */
    if (APR_SUCCESS != apr_uri_parse(p, *url, uri)) {
        return ap_proxyerror(r, HTTP_BAD_REQUEST,
                             apr_pstrcat(p,"URI cannot be parsed: ", *url,
                                         NULL));
    }

    if (!uri->hostname) {
        return ap_proxyerror(r, HTTP_BAD_REQUEST,
                             apr_pstrcat(p,"URI has no hostname: ", *url,
                                         NULL));
    }

    if (!uri->port) {
        uri->port = ap_proxy_port_of_scheme(uri->scheme);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00944)
                 "connecting %s to %s:%d", *url, uri->hostname, uri->port);

    /* Close a possible existing socket if we are told to do so */
    if (conn->close) {
        socket_cleanup(conn);
    }

    /*
     * allocate these out of the specified connection pool
     * The scheme handler decides if this is permanent or
     * short living pool.
     */
    /* Unless we are connecting the backend via a (forward Proxy)Remote, we
     * have to use the original form of the URI (non absolute), but this is
     * also the case via a remote proxy using the CONNECT method since the
     * original request (and URI) is to be embedded in the body.
     */
    if (!proxyname || conn->is_ssl) {
        *url = apr_pstrcat(p, uri->path, uri->query ? "?" : "",
                           uri->query ? uri->query : "",
                           uri->fragment ? "#" : "",
                           uri->fragment ? uri->fragment : "", NULL);
    }
    /*
     * Figure out if our passed in proxy_conn_rec has a usable
     * address cached.
     *
     * TODO: Handle this much better... 
     *
     * XXX: If generic workers are ever address-reusable, we need 
     *      to check host and port on the conn and be careful about
     *      spilling the cached addr from the worker.
     */
    uds_path = (*worker->s->uds_path
                ? worker->s->uds_path
                : apr_table_get(r->notes, "uds_path"));
    if (uds_path) {
        if (!conn->uds_path || strcmp(conn->uds_path, uds_path) != 0) {
            apr_pool_t *pool = conn->pool;
            if (conn->uds_path) {
                conn_cleanup(conn);
                if (!conn->uds_pool) {
                    apr_pool_create(&conn->uds_pool, worker->cp->dns_pool);
                }
                pool = conn->uds_pool;
            }
            /*
             * In UDS cases, some structs are NULL. Protect from de-refs
             * and provide info for logging at the same time.
             */
#if APR_HAVE_SOCKADDR_UN
            apr_sockaddr_info_get(&conn->addr, uds_path, APR_UNIX, 0, 0, pool);
            if (conn->addr && conn->addr->hostname) {
                conn->uds_path = conn->addr->hostname;
            }
            else {
                conn->uds_path = apr_pstrdup(pool, uds_path);
            }
#else
            apr_sockaddr_info_get(&conn->addr, NULL, APR_UNSPEC, 0, 0, pool);
            conn->uds_path = apr_pstrdup(pool, uds_path);
#endif
            conn->hostname = apr_pstrdup(pool, uri->hostname);
            conn->port = uri->port;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02545)
                     "%s: has determined UDS as %s (for %s:%hu)",
                     uri->scheme, conn->uds_path, conn->hostname, conn->port);
    }
    else {
        const char *hostname = uri->hostname;
        apr_port_t hostport = uri->port;

        /* Not a remote CONNECT until further notice */
        conn->forward = NULL;

        if (proxyname) {
            hostname = proxyname;
            hostport = proxyport;

            /*
             * If we have a remote proxy and the protocol is HTTPS,
             * then we need to prepend a HTTP CONNECT request before
             * sending our actual HTTPS requests.
             */
            if (conn->is_ssl) {
                forward_info *forward;
                const char *proxy_auth;

                /* Do we want to pass Proxy-Authorization along?
                 * If we haven't used it, then YES
                 * If we have used it then MAYBE: RFC2616 says we MAY propagate it.
                 * So let's make it configurable by env.
                 * The logic here is the same used in mod_proxy_http.
                 */
                proxy_auth = apr_table_get(r->notes, "proxy-basic-creds");
                if (proxy_auth == NULL
                    && (r->user == NULL /* we haven't yet authenticated */
                        || apr_table_get(r->subprocess_env, "Proxy-Chain-Auth"))) {
                    proxy_auth = apr_table_get(r->headers_in, "Proxy-Authorization");
                }
                if (proxy_auth != NULL && proxy_auth[0] == '\0') {
                    proxy_auth = NULL;
                }

                /* Reset forward info if they changed */
                if (!(forward = conn->forward)
                    || forward->target_port != uri->port
                    || ap_cstr_casecmp(forward->target_host, uri->hostname) != 0
                    || (forward->proxy_auth != NULL) != (proxy_auth != NULL)
                    || (forward->proxy_auth != NULL && proxy_auth != NULL &&
                        strcmp(forward->proxy_auth, proxy_auth) != 0)) {
                    apr_pool_t *fwd_pool = conn->pool;
                    if (worker->s->is_address_reusable) {
                        if (conn->fwd_pool) {
                            apr_pool_clear(conn->fwd_pool);
                        }
                        else {
                            apr_pool_create(&conn->fwd_pool, conn->pool);
                        }
                        fwd_pool = conn->fwd_pool;
                    }
                    forward = apr_pcalloc(fwd_pool, sizeof(forward_info));
                    conn->forward = forward;

                    /*
                     * Save our real backend data for using it later during HTTP CONNECT.
                     */
                    forward->use_http_connect = 1;
                    forward->target_host = apr_pstrdup(fwd_pool, uri->hostname);
                    forward->target_port = uri->port;
                    if (proxy_auth) {
                        forward->proxy_auth = apr_pstrdup(fwd_pool, proxy_auth);
                    }
                }
            }
        }

        if (conn->hostname
            && (conn->port != hostport
                || ap_cstr_casecmp(conn->hostname, hostname) != 0)) {
            conn_cleanup(conn);
        }

        /* Resolve the connection address with the determined hostname/port */
        if (ap_proxy_determine_address(uri->scheme, conn, hostname, hostport,
                                       0, r, NULL)) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Get the server port for the Via headers */
    server_port = ap_get_server_port(r);
    AP_DEBUG_ASSERT(server_portstr_size > 0);
    if (ap_is_default_port(server_port, r)) {
        server_portstr[0] = '\0';
    }
    else {
        apr_snprintf(server_portstr, server_portstr_size, ":%d",
                     server_port);
    }

    /* check if ProxyBlock directive on this host */
    if (OK != ap_proxy_checkproxyblock(r, conf, uri->hostname, 
                                       proxyname ? NULL : conn->addr)) {
        return ap_proxyerror(r, HTTP_FORBIDDEN,
                             "Connect to remote machine blocked");
    }
    /*
     * When SSL is configured, determine the hostname (SNI) for the request
     * and save it in conn->ssl_hostname. Close any reused connection whose
     * SNI differs.
     */
    if (conn->is_ssl) {
        proxy_dir_conf *dconf;
        const char *ssl_hostname;
        /*
         * In the case of ProxyPreserveHost on use the hostname of
         * the request if present otherwise use the one from the
         * backend request URI.
         */
        dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
        if (worker->s->override_ssl_sni_set) {
            ssl_hostname = worker->s->override_ssl_sni;
        }
        else if (dconf->preserve_host) {
            ssl_hostname = r->hostname;
        }
        else if (conn->forward
                 && ((forward_info *)(conn->forward))->use_http_connect) {
            ssl_hostname = ((forward_info *)conn->forward)->target_host;
        }
        else {
            ssl_hostname = conn->hostname;
        }
        /*
         * Close if a SNI is in use but this request requires no or
         * a different one, or no SNI is in use but one is required.
         */
        if ((conn->ssl_hostname && (!ssl_hostname ||
                                    strcasecmp(conn->ssl_hostname,
                                               ssl_hostname) != 0)) ||
                (!conn->ssl_hostname && ssl_hostname && conn->sock)) {
            socket_cleanup(conn);
        }
        if (conn->ssl_hostname == NULL) {
            conn->ssl_hostname = apr_pstrdup(conn->scpool, ssl_hostname);
        }
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00947)
                 "connecting %s to %pI (%s:%hu)", *url,
                 conn->addr, conn->hostname, conn->port);
    return OK;
}

#define USE_ALTERNATE_IS_CONNECTED 1

#if !defined(APR_MSG_PEEK) && defined(MSG_PEEK)
#define APR_MSG_PEEK MSG_PEEK
#endif

#if USE_ALTERNATE_IS_CONNECTED && defined(APR_MSG_PEEK)
PROXY_DECLARE(int) ap_proxy_is_socket_connected(apr_socket_t *socket)
{
    apr_pollfd_t pfds[1];
    apr_status_t status;
    apr_int32_t  nfds;

    pfds[0].reqevents = APR_POLLIN;
    pfds[0].desc_type = APR_POLL_SOCKET;
    pfds[0].desc.s = socket;

    do {
        status = apr_poll(&pfds[0], 1, &nfds, 0);
    } while (APR_STATUS_IS_EINTR(status));

    if (status == APR_SUCCESS && nfds == 1 &&
        pfds[0].rtnevents == APR_POLLIN) {
        apr_sockaddr_t unused;
        apr_size_t len = 1;
        char buf[1];
        /* The socket might be closed in which case
         * the poll will return POLLIN.
         * If there is no data available the socket
         * is closed.
         */
        status = apr_socket_recvfrom(&unused, socket, APR_MSG_PEEK,
                                     &buf[0], &len);
        if (status == APR_SUCCESS && len)
            return 1;
        else
            return 0;
    }
    else if (APR_STATUS_IS_EAGAIN(status) || APR_STATUS_IS_TIMEUP(status)) {
        return 1;
    }
    return 0;

}
#else
PROXY_DECLARE(int) ap_proxy_is_socket_connected(apr_socket_t *sock)

{
    apr_size_t buffer_len = 1;
    char test_buffer[1];
    apr_status_t socket_status;
    apr_interval_time_t current_timeout;

    /* save timeout */
    apr_socket_timeout_get(sock, &current_timeout);
    /* set no timeout */
    apr_socket_timeout_set(sock, 0);
    socket_status = apr_socket_recv(sock, test_buffer, &buffer_len);
    /* put back old timeout */
    apr_socket_timeout_set(sock, current_timeout);
    if (APR_STATUS_IS_EOF(socket_status)
        || APR_STATUS_IS_ECONNRESET(socket_status)) {
        return 0;
    }
    else {
        return 1;
    }
}
#endif /* USE_ALTERNATE_IS_CONNECTED */


/*
 * Send a HTTP CONNECT request to a forward proxy.
 * The proxy is given by "backend", the target server
 * is contained in the "forward" member of "backend".
 */
static apr_status_t send_http_connect(proxy_conn_rec *backend,
                                      server_rec *s)
{
    int status;
    apr_size_t nbytes;
    apr_size_t left;
    int complete = 0;
    char buffer[HUGE_STRING_LEN];
    char drain_buffer[HUGE_STRING_LEN];
    forward_info *forward = (forward_info *)backend->forward;
    int len = 0;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00948)
                 "CONNECT: sending the CONNECT request for %s:%d "
                 "to the remote proxy %pI (%s)",
                 forward->target_host, forward->target_port,
                 backend->addr, backend->hostname);
    /* Create the CONNECT request */
    nbytes = apr_snprintf(buffer, sizeof(buffer),
                          "CONNECT %s:%d HTTP/1.0" CRLF,
                          forward->target_host, forward->target_port);
    /* Add proxy authorization from the configuration, or initial
     * request if necessary */
    if (forward->proxy_auth != NULL) {
        nbytes += apr_snprintf(buffer + nbytes, sizeof(buffer) - nbytes,
                               "Proxy-Authorization: %s" CRLF,
                               forward->proxy_auth);
    }
    /* Set a reasonable agent and send everything */
    nbytes += apr_snprintf(buffer + nbytes, sizeof(buffer) - nbytes,
                           "Proxy-agent: %s" CRLF CRLF,
                           ap_get_server_banner());
    ap_xlate_proto_to_ascii(buffer, nbytes);
    apr_socket_send(backend->sock, buffer, &nbytes);

    /* Receive the whole CONNECT response */
    left = sizeof(buffer) - 1;
    /* Read until we find the end of the headers or run out of buffer */
    do {
        nbytes = left;
        status = apr_socket_recv(backend->sock, buffer + len, &nbytes);
        len += nbytes;
        left -= nbytes;
        buffer[len] = '\0';
        if (strstr(buffer + len - nbytes, CRLF_ASCII CRLF_ASCII) != NULL) {
            ap_xlate_proto_from_ascii(buffer, len);
            complete = 1;
            break;
        }
    } while (status == APR_SUCCESS && left > 0);
    /* Drain what's left */
    if (!complete) {
        nbytes = sizeof(drain_buffer) - 1;
        while (status == APR_SUCCESS && nbytes) {
            status = apr_socket_recv(backend->sock, drain_buffer, &nbytes);
            drain_buffer[nbytes] = '\0';
            nbytes = sizeof(drain_buffer) - 1;
            if (strstr(drain_buffer, CRLF_ASCII CRLF_ASCII) != NULL) {
                break;
            }
        }
    }

    /* Check for HTTP_OK response status */
    if (status == APR_SUCCESS) {
        unsigned int major, minor;
        /* Only scan for three character status code */
        char code_str[4];

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00949)
                     "send_http_connect: response from the forward proxy: %s",
                     buffer);

        /* Extract the returned code */
        if (sscanf(buffer, "HTTP/%u.%u %3s", &major, &minor, code_str) == 3) {
            status = atoi(code_str);
            if (status == HTTP_OK) {
                status = APR_SUCCESS;
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00950)
                             "send_http_connect: the forward proxy returned code is '%s'",
                             code_str);
                status = APR_INCOMPLETE;
            }
        }
    }

    return(status);
}


/* TODO: In APR 2.x: Extend apr_sockaddr_t to possibly be a path !!! */
PROXY_DECLARE(apr_status_t) ap_proxy_connect_uds(apr_socket_t *sock,
                                                 const char *uds_path,
                                                 apr_pool_t *p)
{
#if APR_HAVE_SYS_UN_H
    apr_status_t rv;
    apr_os_sock_t rawsock;
    apr_interval_time_t t;
    struct sockaddr_un *sa;
    apr_socklen_t addrlen, pathlen;

    rv = apr_os_sock_get(&rawsock, sock);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_socket_timeout_get(sock, &t);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    pathlen = strlen(uds_path);
    /* copy the UDS path (including NUL) to the sockaddr_un */
    addrlen = APR_OFFSETOF(struct sockaddr_un, sun_path) + pathlen;
    sa = (struct sockaddr_un *)apr_palloc(p, addrlen + 1);
    memcpy(sa->sun_path, uds_path, pathlen + 1);
    sa->sun_family = AF_UNIX;

    do {
        rv = connect(rawsock, (struct sockaddr*)sa, addrlen);
    } while (rv == -1 && (rv = errno) == EINTR);

    if (rv && rv != EISCONN) {
        if ((rv == EINPROGRESS || rv == EALREADY) && (t > 0))  {
#if APR_MAJOR_VERSION < 2
            rv = apr_wait_for_io_or_timeout(NULL, sock, 0);
#else
            rv = apr_socket_wait(sock, APR_WAIT_WRITE);
#endif
        }
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    return APR_SUCCESS;
#else
    return APR_ENOTIMPL;
#endif
}

PROXY_DECLARE(apr_status_t) ap_proxy_check_connection(const char *scheme,
                                                      proxy_conn_rec *conn,
                                                      server_rec *server,
                                                      unsigned max_blank_lines,
                                                      int flags)
{
    apr_status_t rv = APR_SUCCESS;
    proxy_worker *worker = conn->worker;

    if (!PROXY_WORKER_IS_USABLE(worker)) {
        /*
         * The worker is in error likely done by a different thread / process
         * e.g. for a timeout or bad status. We should respect this and should
         * not continue with a connection via this worker even if we got one.
         */
        rv = APR_EINVAL;
    }
    else if (conn->connection) {
        /* We have a conn_rec, check the full filter stack for things like
         * SSL alert/shutdown, filters aside data...
         */
        rv = ap_check_pipeline(conn->connection, conn->tmp_bb,
                               max_blank_lines);
        apr_brigade_cleanup(conn->tmp_bb);
        if (rv == APR_SUCCESS) {
            /* Some data available, the caller might not want them. */
            if (flags & PROXY_CHECK_CONN_EMPTY) {
                rv = APR_ENOTEMPTY;
            }
        }
        else if (APR_STATUS_IS_EAGAIN(rv)) {
            /* Filter chain is OK and empty, yet we can't determine from
             * ap_check_pipeline (actually ap_core_input_filter) whether
             * an empty non-blocking read is EAGAIN or EOF on the socket
             * side (it's always SUCCESS), so check it explicitly here.
             */
            if (ap_proxy_is_socket_connected(conn->sock)) {
                rv = APR_SUCCESS;
            }
            else {
                rv = APR_EPIPE;
            }
        }
    }
    else if (conn->sock) {
        /* For modules working with sockets directly, check it. */
        if (!ap_proxy_is_socket_connected(conn->sock)) {
            rv = APR_EPIPE;
        }
    }
    else {
        rv = APR_ENOSOCKET;
    }

    if (rv == APR_SUCCESS) {
        if (APLOGtrace2(server)) {
            apr_sockaddr_t *local_addr = NULL;
            apr_socket_addr_get(&local_addr, APR_LOCAL, conn->sock);
            ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, server,
                         "%s: reusing backend connection %pI<>%pI",
                         scheme, local_addr, conn->addr);
        }
    }
    else if (conn->sock) {
        /* This clears conn->scpool (and associated data), so backup and
         * restore any ssl_hostname for this connection set earlier by
         * ap_proxy_determine_connection().
         */
        char ssl_hostname[PROXY_WORKER_RFC1035_NAME_SIZE];
        if (rv == APR_EINVAL
                || !conn->ssl_hostname
                || PROXY_STRNCPY(ssl_hostname, conn->ssl_hostname)) {
            ssl_hostname[0] = '\0';
        }

        socket_cleanup(conn);
        if (rv != APR_ENOTEMPTY) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, APLOGNO(00951)
                         "%s: backend socket is disconnected.", scheme);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, server, APLOGNO(03408)
                         "%s: reusable backend connection is not empty: "
                         "forcibly closed", scheme);
        }

        if (ssl_hostname[0]) {
            conn->ssl_hostname = apr_pstrdup(conn->scpool, ssl_hostname);
        }
    }

    return rv;
}

PROXY_DECLARE(int) ap_proxy_connect_backend(const char *proxy_function,
                                            proxy_conn_rec *conn,
                                            proxy_worker *worker,
                                            server_rec *s)
{
    apr_status_t rv;
    int loglevel;
    forward_info *forward = conn->forward;
    apr_sockaddr_t *backend_addr;
    /* the local address to use for the outgoing connection */
    apr_sockaddr_t *local_addr;
    apr_socket_t *newsock;
    void *sconf = s->module_config;
    int address_reusable = worker->s->is_address_reusable;
    int did_dns_lookup = 0;
    proxy_server_conf *conf =
        (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    rv = ap_proxy_check_connection(proxy_function, conn, s, 0, 0);
    if (rv == APR_EINVAL) {
        return DECLINED;
    }

    /* We'll set conn->addr to the address actually connect()ed, so if the
     * network connection is not reused (per ap_proxy_check_connection()
     * above) we need to reset conn->addr to the first resolved address
     * and try to connect it first.
     */
    if (conn->address && rv != APR_SUCCESS) {
        conn->addr = conn->address->addr;
    }
    backend_addr = conn->addr;

    while (rv != APR_SUCCESS && (backend_addr || conn->uds_path)) {
#if APR_HAVE_SYS_UN_H
        if (conn->uds_path)
        {
            rv = apr_socket_create(&newsock, AF_UNIX, SOCK_STREAM, 0,
                                   conn->scpool);
            if (rv != APR_SUCCESS) {
                loglevel = APLOG_ERR;
                ap_log_error(APLOG_MARK, loglevel, rv, s, APLOGNO(02453)
                             "%s: error creating Unix domain socket "
                             "%s (%s:%hu)",
                             proxy_function,
                             conn->uds_path,
                             conn->hostname, conn->port);
                break;
            }
            conn->connection = NULL;

            rv = ap_proxy_connect_uds(newsock, conn->uds_path, conn->scpool);
            if (rv != APR_SUCCESS) {
                apr_socket_close(newsock);
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(02454)
                             "%s: attempt to connect to Unix domain socket "
                             "%s (%s:%hu) failed",
                             proxy_function, conn->uds_path,
                             conn->hostname, conn->port);
                break;
            }

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02823)
                         "%s: connection established with Unix domain socket "
                         "%s (%s:%hu)",
                         proxy_function,
                         conn->uds_path,
                         conn->hostname, conn->port);
        }
        else
#endif
        {
            if ((rv = apr_socket_create(&newsock, backend_addr->family,
                                        SOCK_STREAM, worker->s->sock_proto,
                                        conn->scpool)) != APR_SUCCESS) {
                loglevel = backend_addr->next ? APLOG_DEBUG : APLOG_ERR;
                ap_log_error(APLOG_MARK, loglevel, rv, s, APLOGNO(00952)
                             "%s: error creating fam %d socket to %pI for "
                             "(%s:%hu)",
                             proxy_function,
                             backend_addr->family, backend_addr,
                             conn->hostname, conn->port);
                /*
                 * this could be an IPv6 address from the DNS but the
                 * local machine won't give us an IPv6 socket; hopefully the
                 * DNS returned an additional address to try
                 */
                backend_addr = backend_addr->next;
                continue;
            }
            conn->connection = NULL;

            if (worker->s->recv_buffer_size > 0 &&
                (rv = apr_socket_opt_set(newsock, APR_SO_RCVBUF,
                                         worker->s->recv_buffer_size))) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00953)
                             "apr_socket_opt_set(SO_RCVBUF): Failed to set "
                             "ProxyReceiveBufferSize, using default");
            }

            rv = apr_socket_opt_set(newsock, APR_TCP_NODELAY, 1);
            if (rv != APR_SUCCESS && rv != APR_ENOTIMPL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00954)
                             "apr_socket_opt_set(APR_TCP_NODELAY): "
                             "Failed to set");
            }

            /* Set a timeout for connecting to the backend on the socket */
            if (worker->s->conn_timeout_set) {
                apr_socket_timeout_set(newsock, worker->s->conn_timeout);
            }
            else if (worker->s->timeout_set) {
                apr_socket_timeout_set(newsock, worker->s->timeout);
            }
            else if (conf->timeout_set) {
                apr_socket_timeout_set(newsock, conf->timeout);
            }
            else {
                apr_socket_timeout_set(newsock, s->timeout);
            }
            /* Set a keepalive option */
            if (worker->s->keepalive) {
                if ((rv = apr_socket_opt_set(newsock,
                                             APR_SO_KEEPALIVE, 1)) != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00955)
                                 "apr_socket_opt_set(SO_KEEPALIVE): Failed to set"
                                 " Keepalive");
                }
            }
            ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, s,
                         "%s: fam %d socket created for %pI (%s:%hu)",
                         proxy_function, backend_addr->family, backend_addr,
                         conn->hostname, conn->port);

            if (conf->source_address_set) {
                local_addr = apr_pmemdup(conn->scpool, conf->source_address,
                                         sizeof(apr_sockaddr_t));
                local_addr->pool = conn->scpool;
                rv = apr_socket_bind(newsock, local_addr);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00956)
                                 "%s: failed to bind socket to local address",
                                 proxy_function);
                }
            }

            /* make the connection out of the socket */
            rv = apr_socket_connect(newsock, backend_addr);

            /* if an error occurred, loop round and try again */
            if (rv != APR_SUCCESS) {
                apr_socket_close(newsock);
                loglevel = backend_addr->next ? APLOG_DEBUG : APLOG_ERR;
                ap_log_error(APLOG_MARK, loglevel, rv, s, APLOGNO(00957)
                             "%s: attempt to connect to %pI (%s:%hu) failed",
                             proxy_function, backend_addr,
                             conn->hostname, conn->port);
                backend_addr = backend_addr->next;
                /*
                 * If we run out of resolved IP's when connecting and if
                 * we cache the resolution in the worker the resolution
                 * might have changed. Hence try a DNS lookup to see if this
                 * helps.
                 */
                if (!backend_addr && address_reusable && !did_dns_lookup) {
                    /* Issue a new DNS lookup to check if the address changed,
                     * in which case (SUCCESS) restart the loop with the new
                     * one(s), otherwise leave (nothing we can do about it).
                     */
                    if (ap_proxy_determine_address(proxy_function, conn,
                                                   conn->hostname, conn->port,
                                                   PROXY_DETERMINE_ADDRESS_CHECK,
                                                   NULL, s) == APR_SUCCESS) {
                        backend_addr = conn->addr;
                    }

                    /*
                     * In case of an error backend_addr will be NULL which
                     * is enough to leave the loop. If successful we'll retry
                     * the new addresses only once.
                     */
                    did_dns_lookup = 1;
                }
                continue;
            }

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02824)
                         "%s: connection established with %pI (%s:%hu)",
                         proxy_function, backend_addr,
                         conn->hostname, conn->port);

            /* Set the actual sockaddr we are connected to */
            conn->addr = backend_addr;
        }

        /* Set a timeout on the socket */
        if (worker->s->timeout_set) {
            apr_socket_timeout_set(newsock, worker->s->timeout);
        }
        else if (conf->timeout_set) {
            apr_socket_timeout_set(newsock, conf->timeout);
        }
        else {
             apr_socket_timeout_set(newsock, s->timeout);
        }

        conn->sock = newsock;

        if (forward && forward->use_http_connect) {
            /*
             * For HTTP CONNECT we need to prepend CONNECT request before
             * sending our actual HTTPS requests.
             */
            {
                rv = send_http_connect(conn, s);
                /* If an error occurred, loop round and try again */
                if (rv != APR_SUCCESS) {
                    conn->sock = NULL;
                    apr_socket_close(newsock);
                    loglevel = backend_addr->next ? APLOG_DEBUG : APLOG_ERR;
                    ap_log_error(APLOG_MARK, loglevel, rv, s, APLOGNO(00958)
                                 "%s: attempt to connect to %s:%hu "
                                 "via http CONNECT through %pI (%s:%hu) failed",
                                 proxy_function,
                                 forward->target_host, forward->target_port,
                                 backend_addr, conn->hostname, conn->port);
                    backend_addr = backend_addr->next;
                    continue;
                }
            }
        }
    }

    if (PROXY_WORKER_IS_USABLE(worker)) {
        /*
         * Put the entire worker to error state if
         * the PROXY_WORKER_IGNORE_ERRORS flag is not set.
         * Although some connections may be alive
         * no further connections to the worker could be made
         */
        if (rv != APR_SUCCESS) {
            if (!(worker->s->status & PROXY_WORKER_IGNORE_ERRORS)) {
                worker->s->error_time = apr_time_now();
                worker->s->status |= PROXY_WORKER_IN_ERROR;
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00959)
                    "ap_proxy_connect_backend disabling worker for (%s:%d) "
                    "for %" APR_TIME_T_FMT "s",
                    worker->s->hostname_ex, (int)worker->s->port,
                    apr_time_sec(worker->s->retry));
            }
        }
        else {
            if (worker->s->retries) {
                /*
                 * A worker came back. So here is where we need to
                 * either reset all params to initial conditions or
                 * apply some sort of aging
                 */
            }
            worker->s->error_time = 0;
            worker->s->retries = 0;
        }
    }
    else {
        /*
         * The worker is in error likely done by a different thread / process
         * e.g. for a timeout or bad status. We should respect this and should
         * not continue with a connection via this worker even if we got one.
         */
        rv = APR_EINVAL;
    }
    if (rv != APR_SUCCESS) {
        socket_cleanup(conn);
        return DECLINED;
    }
    return OK;
}

static apr_status_t connection_shutdown(void *theconn)
{
    proxy_conn_rec *conn = (proxy_conn_rec *)theconn;
    conn_rec *c = conn->connection;
    if (c) {
        if (!c->aborted) {
            apr_interval_time_t saved_timeout = 0;
            apr_socket_timeout_get(conn->sock, &saved_timeout);
            if (saved_timeout) {
                apr_socket_timeout_set(conn->sock, 0);
            }

            (void)ap_shutdown_conn(c, 0);
            c->aborted = 1;

            if (saved_timeout) {
                apr_socket_timeout_set(conn->sock, saved_timeout);
            }
        }

        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(02642)
                      "proxy: connection shutdown");
    }
    return APR_SUCCESS;
}


static int proxy_connection_create(const char *proxy_function,
                                   proxy_conn_rec *conn,
                                   request_rec *r, server_rec *s)
{
    ap_conf_vector_t *per_dir_config = (r) ? r->per_dir_config
                                           : conn->worker->section_config;
    apr_sockaddr_t *backend_addr = conn->addr;
    apr_interval_time_t current_timeout;
    apr_bucket_alloc_t *bucket_alloc;
    int rc = OK;

    if (conn->connection) {
        if (conn->is_ssl) {
            /* on reuse, reinit the SSL connection dir config with the current
             * r->per_dir_config, the previous one was reset on release.
             */
            ap_proxy_ssl_engine(conn->connection, per_dir_config, 1);
        }
        return OK;
    }

    if (conn->sock) {
        bucket_alloc = apr_bucket_alloc_create(conn->scpool);
        conn->tmp_bb = apr_brigade_create(conn->scpool, bucket_alloc);
        /*
         * The socket is now open, create a new backend server connection
         */
        conn->connection = ap_create_connection(conn->scpool, s, conn->sock,
                                                0, NULL, bucket_alloc, 1);
    }
    if (!conn->connection) {
        /*
         * the peer reset the connection already; ap_create_connection()
         * closed the socket
         */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                     s, APLOGNO(00960) "%s: an error occurred creating a "
                     "new connection to %pI (%s)%s",
                     proxy_function, backend_addr, conn->hostname,
                     conn->sock ? "" : " (not connected)");
        rc = HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    /* For ssl connection to backend */
    if (conn->is_ssl) {
        if (!ap_proxy_ssl_engine(conn->connection, per_dir_config, 1)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                         s, APLOGNO(00961) "%s: failed to enable ssl support "
                         "for %pI (%s)", proxy_function,
                         backend_addr, conn->hostname);
            rc = HTTP_INTERNAL_SERVER_ERROR;
            goto cleanup;
        }
        if (conn->ssl_hostname) {
            /* Set a note on the connection about what CN is requested,
             * such that mod_ssl can check if it is requested to do so.
             */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, conn->connection, 
                          "%s: set SNI to %s for (%s)", proxy_function,
                          conn->ssl_hostname, conn->hostname);
            apr_table_setn(conn->connection->notes, "proxy-request-hostname",
                           conn->ssl_hostname);
        }
    }
    else {
        /* TODO: See if this will break FTP */
        ap_proxy_ssl_engine(conn->connection, per_dir_config, 0);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00962)
                 "%s: connection complete to %pI (%s)",
                 proxy_function, backend_addr, conn->hostname);

    /*
     * save the timeout of the socket because core_pre_connection
     * will set it to base_server->timeout
     * (core TimeOut directive).
     */
    apr_socket_timeout_get(conn->sock, &current_timeout);
    /* set up the connection filters */
    rc = ap_run_pre_connection(conn->connection, conn->sock);
    if (rc != OK && rc != DONE) {
        conn->connection->aborted = 1;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00963)
                     "%s: pre_connection setup failed (%d)",
                     proxy_function, rc);
        goto cleanup;
    }
    apr_socket_timeout_set(conn->sock, current_timeout);

    /* Shutdown the connection before closing it (eg. SSL connections
     * need to be close-notify-ed).
     */
    apr_pool_pre_cleanup_register(conn->scpool, conn, connection_shutdown);

    return OK;

cleanup:
    socket_cleanup(conn);
    return rc;
}

PROXY_DECLARE(int) ap_proxy_connection_create_ex(const char *proxy_function,
                                                 proxy_conn_rec *conn,
                                                 request_rec *r)
{
    return proxy_connection_create(proxy_function, conn, r, r->server);
}

PROXY_DECLARE(int) ap_proxy_connection_create(const char *proxy_function,
                                              proxy_conn_rec *conn,
                                              conn_rec *c, server_rec *s)
{
    (void) c; /* unused */
    return proxy_connection_create(proxy_function, conn, NULL, s);
}

int ap_proxy_lb_workers(void)
{
    /*
     * Since we can't resize the scoreboard when reconfiguring, we
     * have to impose a limit on the number of workers, we are
     * able to reconfigure to.
     */
    if (!lb_workers_limit)
        lb_workers_limit = proxy_lb_workers + PROXY_DYNAMIC_BALANCER_LIMIT;
    return lb_workers_limit;
}

static APR_INLINE int error_code_overridden(const int *elts, int nelts,
                                            int code)
{
    int min = 0;
    int max = nelts - 1;
    AP_DEBUG_ASSERT(max >= 0);

    while (min < max) {
        int mid = (min + max) / 2;
        int val = elts[mid];

        if (val < code) {
            min = mid + 1;
        }
        else if (val > code) {
            max = mid - 1;
        }
        else {
            return 1;
        }
    }

    return elts[min] == code;
}

PROXY_DECLARE(int) ap_proxy_should_override(proxy_dir_conf *conf, int code)
{
    if (!conf->error_override) 
        return 0;

    if (apr_is_empty_array(conf->error_override_codes))
        return ap_is_HTTP_ERROR(code);

    /* Since error_override_codes is sorted, apply binary search. */
    return error_code_overridden((int *)conf->error_override_codes->elts,
                                 conf->error_override_codes->nelts,
                                 code);
}

PROXY_DECLARE(void) ap_proxy_fill_error_brigade(request_rec *r, int status,
                                                apr_bucket_brigade *bb,
                                                int eoc)
{
    apr_bucket *e, *eos;
    conn_rec *c = r->connection;

    /*
     * Add an error and (eventually) EOC buckets to signal the http filter
     * that it should get out of our way, BUT ensure that they are inserted
     * BEFORE an EOS bucket in bb as some resource filters like mod_deflate
     * pass everything up to the EOS down the chain immediately and sent the
     * remainder of the brigade later (or even never). But in this case the
     * ap_http_header_filter does not get out of our way soon enough.
     */

    eos = APR_BRIGADE_LAST(bb);
    while (eos != APR_BRIGADE_SENTINEL(bb) && !APR_BUCKET_IS_EOS(eos)) {
        eos = APR_BUCKET_PREV(eos);
    }

    e = ap_bucket_error_create(status, NULL, c->pool, c->bucket_alloc);
    if (eos == APR_BRIGADE_SENTINEL(bb)) {
        APR_BRIGADE_INSERT_TAIL(bb, e);
        eos = APR_BRIGADE_SENTINEL(bb);
    }
    else {
        APR_BUCKET_INSERT_BEFORE(eos, e);
    }

    /* If asked to (eoc > 0) or if heuristically (eoc < 0) the header was
     * sent already we need to terminate the connection.
     */
    if (eoc > 0 || (eoc < 0 && r->sent_bodyct)) {
        e = ap_bucket_eoc_create(c->bucket_alloc);
        if (eos == APR_BRIGADE_SENTINEL(bb)) {
            APR_BRIGADE_INSERT_TAIL(bb, e);
        }
        else {
            APR_BUCKET_INSERT_BEFORE(eos, e);
        }
    }
}

/* deprecated - to be removed in v2.6 */
PROXY_DECLARE(void) ap_proxy_backend_broke(request_rec *r,
                                           apr_bucket_brigade *brigade)
{
    conn_rec *c = r->connection;

    r->no_cache = 1;
    /*
     * If this is a subrequest, then prevent also caching of the main
     * request.
     */
    if (r->main)
        r->main->no_cache = 1;

    APR_BRIGADE_INSERT_TAIL(brigade, apr_bucket_eos_create(c->bucket_alloc));
    ap_proxy_fill_error_brigade(r, HTTP_BAD_GATEWAY, brigade, 0);
}

/*
 * Provide a string hashing function for the proxy.
 * We offer 2 methods: one is the APR model but we
 * also provide our own, based on either FNV or SDBM.
 * The reason is in case we want to use both to ensure no
 * collisions.
 */
PROXY_DECLARE(unsigned int)
ap_proxy_hashfunc(const char *str, proxy_hash_t method)
{
    if (method == PROXY_HASHFUNC_APR) {
        apr_ssize_t slen = strlen(str);
        return apr_hashfunc_default(str, &slen);
    }
    else if (method == PROXY_HASHFUNC_FNV) {
        /* FNV model */
        unsigned int hash;
        const unsigned int fnv_prime = 0x811C9DC5;
        for (hash = 0; *str; str++) {
            hash *= fnv_prime;
            hash ^= (*str);
        }
        return hash;
    }
    else { /* method == PROXY_HASHFUNC_DEFAULT */
        /* SDBM model */
        unsigned int hash;
        for (hash = 0; *str; str++) {
            hash = (*str) + (hash << 6) + (hash << 16) - hash;
        }
        return hash;
    }
}

PROXY_DECLARE(apr_status_t) ap_proxy_set_wstatus(char c, int set, proxy_worker *w)
{
    unsigned int *status = &w->s->status;
    char flag = toupper(c);
    proxy_wstat_t *pwt = proxy_wstat_tbl;
    while (pwt->bit) {
        if (flag == pwt->flag) {
            if (set)
                *status |= pwt->bit;
            else
                *status &= ~(pwt->bit);
            return APR_SUCCESS;
        }
        pwt++;
    }
    return APR_EINVAL;
}

PROXY_DECLARE(char *) ap_proxy_parse_wstatus(apr_pool_t *p, proxy_worker *w)
{
    char *ret = "";
    unsigned int status = w->s->status;
    proxy_wstat_t *pwt = proxy_wstat_tbl;
    while (pwt->bit) {
        if (status & pwt->bit)
            ret = apr_pstrcat(p, ret, pwt->name, NULL);
        pwt++;
    }
    if (!*ret) {
        ret = "??? ";
    }
    if (PROXY_WORKER_IS_USABLE(w))
        ret = apr_pstrcat(p, ret, "Ok ", NULL);
    return ret;
}

PROXY_DECLARE(apr_status_t) ap_proxy_sync_balancer(proxy_balancer *b, server_rec *s,
                                                    proxy_server_conf *conf)
{
    proxy_worker **workers;
    int i;
    int index;
    proxy_worker_shared *shm;
    proxy_balancer_method *lbmethod;
    ap_slotmem_provider_t *storage = b->storage;

    if (b->s->wupdated <= b->wupdated)
        return APR_SUCCESS;
    /* balancer sync */
    lbmethod = ap_lookup_provider(PROXY_LBMETHOD, b->s->lbpname, "0");
    if (lbmethod) {
        b->lbmethod = lbmethod;
    } else {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(02433)
                     "Cannot find LB Method: %s", b->s->lbpname);
        return APR_EINVAL;
    }

    /* worker sync */

    /*
     * Look thru the list of workers in shm
     * and see which one(s) we are lacking...
     * again, the cast to unsigned int is safe
     * since our upper limit is always max_workers
     * which is int.
     */
    for (index = 0; index < b->max_workers; index++) {
        int found;
        apr_status_t rv;
        if ((rv = storage->dptr(b->wslot, (unsigned int)index, (void *)&shm)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(00965) "worker slotmem_dptr failed");
            return APR_EGENERAL;
        }
        /* account for possible "holes" in the slotmem
         * (eg: slots 0-2 are used, but 3 isn't, but 4-5 is)
         */
        if (!shm->hash.def || !shm->hash.fnv)
            continue;
        found = 0;
        workers = (proxy_worker **)b->workers->elts;
        for (i = 0; i < b->workers->nelts; i++, workers++) {
            proxy_worker *worker = *workers;
            if (worker->hash.def == shm->hash.def && worker->hash.fnv == shm->hash.fnv) {
                found = 1;
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02402)
                             "re-grabbing shm[%d] (0x%pp) for worker: %s", i, (void *)shm,
                             ap_proxy_worker_get_name(worker));
                break;
            }
        }
        if (!found) {
            proxy_worker **runtime;
            /* XXX: a thread mutex is maybe enough here */
            apr_global_mutex_lock(proxy_mutex);
            runtime = apr_array_push(b->workers);
            *runtime = apr_pcalloc(conf->pool, sizeof(proxy_worker));
            apr_global_mutex_unlock(proxy_mutex);
            (*runtime)->hash = shm->hash;
            (*runtime)->balancer = b;
            (*runtime)->s = shm;

            rv = ap_proxy_initialize_worker(*runtime, s, conf->pool);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(00966) "Cannot init worker");
                return rv;
            }
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02403)
                         "grabbing shm[%d] (0x%pp) for worker: %s", i, (void *)shm,
                         (*runtime)->s->name);
        }
    }
    if (b->s->need_reset) {
        if (b->lbmethod && b->lbmethod->reset)
            b->lbmethod->reset(b, s);
        b->s->need_reset = 0;
    }
    b->wupdated = b->s->wupdated;
    return APR_SUCCESS;
}

PROXY_DECLARE(proxy_worker_shared *) ap_proxy_find_workershm(ap_slotmem_provider_t *storage,
                                                               ap_slotmem_instance_t *slot,
                                                               proxy_worker *worker,
                                                               unsigned int *index)
{
    proxy_worker_shared *shm;
    unsigned int i, limit;
    limit = storage->num_slots(slot);
    for (i = 0; i < limit; i++) {
        if (storage->dptr(slot, i, (void *)&shm) != APR_SUCCESS) {
            return NULL;
        }
        if ((worker->s->hash.def == shm->hash.def) &&
            (worker->s->hash.fnv == shm->hash.fnv)) {
            *index = i;
            return shm;
        }
    }
    return NULL;
}

PROXY_DECLARE(proxy_balancer_shared *) ap_proxy_find_balancershm(ap_slotmem_provider_t *storage,
                                                                 ap_slotmem_instance_t *slot,
                                                                 proxy_balancer *balancer,
                                                                 unsigned int *index)
{
    proxy_balancer_shared *shm;
    unsigned int i, limit;
    limit = storage->num_slots(slot);
    for (i = 0; i < limit; i++) {
        if (storage->dptr(slot, i, (void *)&shm) != APR_SUCCESS) {
            return NULL;
        }
        if ((balancer->s->hash.def == shm->hash.def) &&
            (balancer->s->hash.fnv == shm->hash.fnv)) {
            *index = i;
            return shm;
        }
    }
    return NULL;
}

typedef struct header_connection {
    apr_pool_t *pool;
    apr_array_header_t *array;
    const char *error;
    int is_req;
} header_connection;

static int find_conn_headers(void *data, const char *key, const char *val)
{
    header_connection *x = data;
    x->error = ap_parse_token_list_strict(x->pool, val, &x->array, !x->is_req);
    return !x->error;
}

/**
 * Remove all headers referred to by the Connection header.
 * Returns -1 on error. Otherwise, returns 1 if 'Close' was seen in
 * the Connection header tokens, and 0 if not.
 */
static int ap_proxy_clear_connection(request_rec *r, apr_table_t *headers)
{
    int closed = 0;
    header_connection x;

    x.pool = r->pool;
    x.array = NULL;
    x.error = NULL;
    x.is_req = (headers == r->headers_in);

    apr_table_unset(headers, "Proxy-Connection");

    apr_table_do(find_conn_headers, &x, headers, "Connection", NULL);
    apr_table_unset(headers, "Connection");

    if (x.error) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO(02806)
                "Error parsing Connection header: %s", x.error);
        return -1;
    }

    if (x.array) {
        int i;
        for (i = 0; i < x.array->nelts; i++) {
            const char *name = APR_ARRAY_IDX(x.array, i, const char *);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02807)
                          "Removing header '%s' listed in Connection header",
                          name);
            if (!ap_cstr_casecmp(name, "close")) {
                closed = 1;
            }
            apr_table_unset(headers, name);
        }
    }

    return closed;
}

PROXY_DECLARE(int) ap_proxy_create_hdrbrgd(apr_pool_t *p,
                                            apr_bucket_brigade *header_brigade,
                                            request_rec *r,
                                            proxy_conn_rec *p_conn,
                                            proxy_worker *worker,
                                            proxy_server_conf *conf,
                                            apr_uri_t *uri,
                                            char *url, char *server_portstr,
                                            char **old_cl_val,
                                            char **old_te_val)
{
    int rc = OK;
    conn_rec *c = r->connection;
    char *buf;
    apr_table_t *saved_headers_in = r->headers_in;
    const char *saved_host = apr_table_get(saved_headers_in, "Host");
    apr_bucket *e;
    int force10 = 0, do_100_continue = 0;
    conn_rec *origin = p_conn->connection;
    const char *host, *creds, *val;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config, &proxy_module);

    /*
     * HTTP "Ping" test? Easiest is 100-Continue. However:
     * To be compliant, we only use 100-Continue for requests with bodies.
     * We also make sure we won't be talking HTTP/1.0 as well.
     */
    if (apr_table_get(r->subprocess_env, "force-proxy-request-1.0")) {
        force10 = 1;
    }
    else if (apr_table_get(r->notes, "proxy-100-continue")
             || PROXY_SHOULD_PING_100_CONTINUE(worker, r)) {
        do_100_continue = 1;
    }
    if (force10 || apr_table_get(r->subprocess_env, "proxy-nokeepalive")) {
        if (origin) {
            origin->keepalive = AP_CONN_CLOSE;
        }
        p_conn->close = 1;
    }

    if (force10) {
        buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.0" CRLF, NULL);
    }
    else {
        buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.1" CRLF, NULL);
    }
    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);

    /*
     * Make a copy on r->headers_in for the request we make to the backend,
     * modify the copy in place according to our configuration and connection
     * handling, use it to fill in the forwarded headers' brigade, and finally
     * restore the saved/original ones in r->headers_in.
     *
     * Note: We need to take r->pool for apr_table_copy as the key / value
     * pairs in r->headers_in have been created out of r->pool and
     * p might be (and actually is) a longer living pool.
     * This would trigger the bad pool ancestry abort in apr_table_copy if
     * apr is compiled with APR_POOL_DEBUG.
     *
     * icing: if p indeed lives longer than r->pool, we should allocate
     * all new header values from r->pool as well and avoid leakage.
     */
    r->headers_in = apr_table_copy(r->pool, saved_headers_in);

    /* Return the original Transfer-Encoding and/or Content-Length values
     * then drop the headers, they must be set by the proxy handler based
     * on the actual body being forwarded.
     */
    if ((*old_te_val = (char *)apr_table_get(r->headers_in,
                                             "Transfer-Encoding"))) {
        apr_table_unset(r->headers_in, "Transfer-Encoding");
    }
    if ((*old_cl_val = (char *)apr_table_get(r->headers_in,
                                             "Content-Length"))) {
        apr_table_unset(r->headers_in, "Content-Length");
    }

    /* Clear out hop-by-hop request headers not to forward */
    if (ap_proxy_clear_connection(r, r->headers_in) < 0) {
        rc = HTTP_BAD_REQUEST;
        goto cleanup;
    }

    /* RFC2616 13.5.1 says we should strip these */
    apr_table_unset(r->headers_in, "Keep-Alive");
    apr_table_unset(r->headers_in, "Upgrade");
    apr_table_unset(r->headers_in, "TE");

    /* FIXME: since we now handle r->trailers_in on forwarding
     * request bodies, it seems unwise to clear any Trailer
     * header present. Is this the correct thing now?
     */
    if (force10)
        apr_table_unset(r->headers_in, "Trailer");

    /* Compute Host header */
    if (worker->s->override_http_host_set) {
        host = worker->s->override_http_host;
        apr_table_setn(r->headers_in, "Host", host);
    }
    else if (dconf->preserve_host == 0) {
        if (!uri->hostname) {
            rc = HTTP_BAD_REQUEST;
            goto cleanup;
        }
        if (ap_strchr_c(uri->hostname, ':')) { /* if literal IPv6 address */
            if (uri->port_str && uri->port != DEFAULT_HTTP_PORT) {
                host = apr_pstrcat(r->pool, "[", uri->hostname, "]:",
                                   uri->port_str, NULL);
            } else {
                host = apr_pstrcat(r->pool, "[", uri->hostname, "]", NULL);
            }
        } else {
            if (uri->port_str && uri->port != DEFAULT_HTTP_PORT) {
                host = apr_pstrcat(r->pool, uri->hostname, ":",
                                   uri->port_str, NULL);
            } else {
                host = uri->hostname;
            }
        }
        apr_table_setn(r->headers_in, "Host", host);
    }
    else {
        /* don't want to use r->hostname as the incoming header might have a
         * port attached, let's use the original header.
         */
        host = saved_host;
        if (!host) {
            host =  r->server->server_hostname;
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01092)
                          "no HTTP 0.9 request (with no host line) "
                          "on incoming request and preserve host set "
                          "forcing hostname to be %s for uri %s",
                          host, r->uri);
            apr_table_setn(r->headers_in, "Host", host);
        }
    }

    /* handle Via */
    if (conf->viaopt == via_block) {
        /* Block all outgoing Via: headers */
        apr_table_unset(r->headers_in, "Via");
    } else if (conf->viaopt != via_off) {
        const char *server_name = ap_get_server_name(r);
        /* If USE_CANONICAL_NAME_OFF was configured for the proxy virtual host,
         * then the server name returned by ap_get_server_name() is the
         * origin server name (which does make too much sense with Via: headers)
         * so we use the proxy vhost's name instead.
         */
        if (server_name == r->hostname)
            server_name = r->server->server_hostname;
        /* Create a "Via:" request header entry and merge it */
        /* Generate outgoing Via: header with/without server comment: */
        apr_table_mergen(r->headers_in, "Via",
                         (conf->viaopt == via_full)
                         ? apr_psprintf(r->pool, "%d.%d %s%s (%s)",
                                        HTTP_VERSION_MAJOR(r->proto_num),
                                        HTTP_VERSION_MINOR(r->proto_num),
                                        server_name, server_portstr,
                                        AP_SERVER_BASEVERSION)
                         : apr_psprintf(r->pool, "%d.%d %s%s",
                                        HTTP_VERSION_MAJOR(r->proto_num),
                                        HTTP_VERSION_MINOR(r->proto_num),
                                        server_name, server_portstr)
                         );
    }

    /* Use HTTP/1.1 100-Continue as quick "HTTP ping" test
     * to backend
     */
    if (do_100_continue) {
        /* Add the Expect header if not already there. */
        if (!(val = apr_table_get(r->headers_in, "Expect"))
            || (ap_cstr_casecmp(val, "100-Continue") != 0 /* fast path */
                && !ap_find_token(r->pool, val, "100-Continue"))) {
            apr_table_mergen(r->headers_in, "Expect", "100-Continue");
        }
    }
    else {
        /* XXX: we should strip the 100-continue token only from the
         * Expect header, but are there others actually used anywhere?
         */
        apr_table_unset(r->headers_in, "Expect");
    }

    /* X-Forwarded-*: handling
     *
     * XXX Privacy Note:
     * -----------------
     *
     * These request headers are only really useful when the mod_proxy
     * is used in a reverse proxy configuration, so that useful info
     * about the client can be passed through the reverse proxy and on
     * to the backend server, which may require the information to
     * function properly.
     *
     * In a forward proxy situation, these options are a potential
     * privacy violation, as information about clients behind the proxy
     * are revealed to arbitrary servers out there on the internet.
     *
     * The HTTP/1.1 Via: header is designed for passing client
     * information through proxies to a server, and should be used in
     * a forward proxy configuration instead of X-Forwarded-*. See the
     * ProxyVia option for details.
     */
    if (dconf->add_forwarded_headers) {
        if (PROXYREQ_REVERSE == r->proxyreq) {
            /* Add X-Forwarded-For: so that the upstream has a chance to
             * determine, where the original request came from.
             */
            apr_table_mergen(r->headers_in, "X-Forwarded-For",
                             r->useragent_ip);

            /* Add X-Forwarded-Host: so that upstream knows what the
             * original request hostname was.
             */
            if (saved_host) {
                apr_table_mergen(r->headers_in, "X-Forwarded-Host",
                                 saved_host);
            }

            /* Add X-Forwarded-Server: so that upstream knows what the
             * name of this proxy server is (if there are more than one)
             * XXX: This duplicates Via: - do we strictly need it?
             */
            apr_table_mergen(r->headers_in, "X-Forwarded-Server",
                             r->server->server_hostname);
        }
    }

    /* Do we want to strip Proxy-Authorization ?
     * If we haven't used it, then NO
     * If we have used it then MAYBE: RFC2616 says we MAY propagate it.
     * So let's make it configurable by env.
     */
    if (r->user != NULL /* we've authenticated */
        && !apr_table_get(r->subprocess_env, "Proxy-Chain-Auth")) {
        apr_table_unset(r->headers_in, "Proxy-Authorization");
    }

    /* for sub-requests, ignore freshness/expiry headers */
    if (r->main) {
        apr_table_unset(r->headers_in, "If-Match");
        apr_table_unset(r->headers_in, "If-Modified-Since");
        apr_table_unset(r->headers_in, "If-Range");
        apr_table_unset(r->headers_in, "If-Unmodified-Since");
        apr_table_unset(r->headers_in, "If-None-Match");
    }

    /* Add credentials (per worker) if any */
    creds = apr_table_get(r->notes, "proxy-basic-creds");
    if (creds) {
        apr_table_mergen(r->headers_in, "Proxy-Authorization", creds);
    }

    /* run hook to fixup the request we are about to send */
    proxy_run_fixups(r);

    /* We used to send `Host: ` always first, so let's keep it that
     * way. No telling which legacy backend is relying on this.
     * If proxy_run_fixups() changed the value, use it (though removal
     * is ignored).
     */
    val = apr_table_get(r->headers_in, "Host");
    if (val) {
        apr_table_unset(r->headers_in, "Host");
        host = val;
    }
    ap_h1_append_header(header_brigade, r->pool, "Host", host);

    /* Append the (remaining) headers to the brigade */
    ap_h1_append_headers(header_brigade, r, r->headers_in);

cleanup:
    r->headers_in = saved_headers_in;
    return rc;
}

PROXY_DECLARE(int) ap_proxy_prefetch_input(request_rec *r,
                                           proxy_conn_rec *backend,
                                           apr_bucket_brigade *input_brigade,
                                           apr_read_type_e block,
                                           apr_off_t *bytes_read,
                                           apr_off_t max_read)
{
    apr_pool_t *p = r->pool;
    conn_rec *c = r->connection;
    apr_bucket_brigade *temp_brigade;
    apr_status_t status;
    apr_off_t bytes;

    *bytes_read = 0;
    if (max_read < APR_BUCKET_BUFF_SIZE) {
        max_read = APR_BUCKET_BUFF_SIZE;
    }

    /* Prefetch max_read bytes
     *
     * This helps us avoid any election of C-L v.s. T-E
     * request bodies, since we are willing to keep in
     * memory this much data, in any case.  This gives
     * us an instant C-L election if the body is of some
     * reasonable size.
     */
    temp_brigade = apr_brigade_create(p, input_brigade->bucket_alloc);

    /* Account for saved input, if any. */
    apr_brigade_length(input_brigade, 0, bytes_read);

    /* Ensure we don't hit a wall where we have a buffer too small for
     * ap_get_brigade's filters to fetch us another bucket, surrender
     * once we hit 80 bytes (an arbitrary value) less than max_read.
     */
    while (*bytes_read < max_read - 80
           && (APR_BRIGADE_EMPTY(input_brigade)
               || !APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade)))) {
        status = ap_get_brigade(r->input_filters, temp_brigade,
                                AP_MODE_READBYTES, block,
                                max_read - *bytes_read);
        /* ap_get_brigade may return success with an empty brigade
         * for a non-blocking read which would block
         */
        if (block == APR_NONBLOCK_READ
                && ((status == APR_SUCCESS && APR_BRIGADE_EMPTY(temp_brigade))
                    || APR_STATUS_IS_EAGAIN(status))) {
            break;
        }
        if (status != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01095)
                          "prefetch request body failed to %pI (%s)"
                          " from %s (%s)", backend->addr,
                          backend->hostname ? backend->hostname : "",
                          c->client_ip, c->remote_host ? c->remote_host : "");
            return ap_map_http_request_error(status, HTTP_BAD_REQUEST);
        }

        apr_brigade_length(temp_brigade, 1, &bytes);
        *bytes_read += bytes;

        /*
         * Save temp_brigade in input_brigade. (At least) in the SSL case
         * temp_brigade contains transient buckets whose data would get
         * overwritten during the next call of ap_get_brigade in the loop.
         * ap_save_brigade ensures these buckets to be set aside.
         * Calling ap_save_brigade with NULL as filter is OK, because
         * input_brigade already has been created and does not need to get
         * created by ap_save_brigade.
         */
        status = ap_save_brigade(NULL, &input_brigade, &temp_brigade, p);
        if (status != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01096)
                          "processing prefetched request body failed"
                          " to %pI (%s) from %s (%s)", backend->addr,
                          backend->hostname ? backend->hostname : "",
                          c->client_ip, c->remote_host ? c->remote_host : "");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

PROXY_DECLARE(int) ap_proxy_read_input(request_rec *r,
                                       proxy_conn_rec *backend,
                                       apr_bucket_brigade *bb,
                                       apr_off_t max_read)
{
    apr_bucket_alloc_t *bucket_alloc = bb->bucket_alloc;
    apr_read_type_e block = (backend->connection) ? APR_NONBLOCK_READ
                                                  : APR_BLOCK_READ;
    apr_status_t status;
    int rv;

    for (;;) {
        apr_brigade_cleanup(bb);
        status = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                                block, max_read);
        if (block == APR_BLOCK_READ
                || (!(status == APR_SUCCESS && APR_BRIGADE_EMPTY(bb))
                    && !APR_STATUS_IS_EAGAIN(status))) {
            break;
        }

        /* Flush and retry (blocking) */
        apr_brigade_cleanup(bb);
        rv = ap_proxy_pass_brigade(bucket_alloc, r, backend,
                                   backend->connection, bb, 1);
        if (rv != OK) {
            return rv;
        }
        block = APR_BLOCK_READ;
    }

    if (status != APR_SUCCESS) {
        conn_rec *c = r->connection;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(02608)
                      "read request body failed to %pI (%s)"
                      " from %s (%s)", backend->addr,
                      backend->hostname ? backend->hostname : "",
                      c->client_ip, c->remote_host ? c->remote_host : "");
        return ap_map_http_request_error(status, HTTP_BAD_REQUEST);
    }

    return OK;
}

PROXY_DECLARE(int) ap_proxy_spool_input(request_rec *r,
                                        proxy_conn_rec *backend,
                                        apr_bucket_brigade *input_brigade,
                                        apr_off_t *bytes_spooled,
                                        apr_off_t max_mem_spool)
{
    apr_pool_t *p = r->pool;
    int seen_eos = 0, rv = OK;
    apr_status_t status = APR_SUCCESS;
    apr_bucket_alloc_t *bucket_alloc = input_brigade->bucket_alloc;
    apr_bucket_brigade *body_brigade;
    apr_bucket *e;
    apr_off_t bytes, fsize = 0;
    apr_file_t *tmpfile = NULL;

    *bytes_spooled = 0;
    body_brigade = apr_brigade_create(p, bucket_alloc);

    do {
        if (APR_BRIGADE_EMPTY(input_brigade)) {
            rv = ap_proxy_read_input(r, backend, input_brigade,
                                     HUGE_STRING_LEN);
            if (rv != OK) {
                return rv;
            }
        }

        /* If this brigade contains EOS, either stop or remove it. */
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
            seen_eos = 1;
        }

        apr_brigade_length(input_brigade, 1, &bytes);

        if (*bytes_spooled + bytes > max_mem_spool) {
            /* can't spool any more in memory; write latest brigade to disk */
            if (tmpfile == NULL) {
                const char *temp_dir;
                char *template;

                status = apr_temp_dir_get(&temp_dir, p);
                if (status != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01089)
                                  "search for temporary directory failed");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                apr_filepath_merge(&template, temp_dir,
                                   "modproxy.tmp.XXXXXX",
                                   APR_FILEPATH_NATIVE, p);
                status = apr_file_mktemp(&tmpfile, template, 0, p);
                if (status != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01090)
                                  "creation of temporary file in directory "
                                  "%s failed", temp_dir);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            for (e = APR_BRIGADE_FIRST(input_brigade);
                 e != APR_BRIGADE_SENTINEL(input_brigade);
                 e = APR_BUCKET_NEXT(e)) {
                const char *data;
                apr_size_t bytes_read, bytes_written;

                apr_bucket_read(e, &data, &bytes_read, APR_BLOCK_READ);
                status = apr_file_write_full(tmpfile, data, bytes_read, &bytes_written);
                if (status != APR_SUCCESS) {
                    const char *tmpfile_name;

                    if (apr_file_name_get(&tmpfile_name, tmpfile) != APR_SUCCESS) {
                        tmpfile_name = "(unknown)";
                    }
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01091)
                                  "write to temporary file %s failed",
                                  tmpfile_name);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                AP_DEBUG_ASSERT(bytes_read == bytes_written);
                fsize += bytes_written;
            }
            apr_brigade_cleanup(input_brigade);
        }
        else {

            /*
             * Save input_brigade in body_brigade. (At least) in the SSL case
             * input_brigade contains transient buckets whose data would get
             * overwritten during the next call of ap_get_brigade in the loop.
             * ap_save_brigade ensures these buckets to be set aside.
             * Calling ap_save_brigade with NULL as filter is OK, because
             * body_brigade already has been created and does not need to get
             * created by ap_save_brigade.
             */
            status = ap_save_brigade(NULL, &body_brigade, &input_brigade, p);
            if (status != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }

        }

        *bytes_spooled += bytes;
    } while (!seen_eos);

    APR_BRIGADE_CONCAT(input_brigade, body_brigade);
    if (tmpfile) {
        apr_brigade_insert_file(input_brigade, tmpfile, 0, fsize, p);
    }
    if (apr_table_get(r->subprocess_env, "proxy-sendextracrlf")) {
        e = apr_bucket_immortal_create(CRLF_ASCII, 2, bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(input_brigade, e);
    }
    if (tmpfile) {
        /* We dropped metadata buckets when spooling to tmpfile,
         * terminate with EOS to allow for flushing in a one go.
         */
        e = apr_bucket_eos_create(bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(input_brigade, e);
    }
    return OK;
}

PROXY_DECLARE(int) ap_proxy_pass_brigade(apr_bucket_alloc_t *bucket_alloc,
                                         request_rec *r, proxy_conn_rec *p_conn,
                                         conn_rec *origin, apr_bucket_brigade *bb,
                                         int flush)
{
    apr_status_t status;
    apr_off_t transferred;

    if (flush) {
        apr_bucket *e = apr_bucket_flush_create(bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }
    apr_brigade_length(bb, 0, &transferred);
    if (transferred != -1)
        p_conn->worker->s->transferred += transferred;
    status = ap_pass_brigade(origin->output_filters, bb);
    /* Cleanup the brigade now to avoid buckets lifetime
     * issues in case of error returned below. */
    apr_brigade_cleanup(bb);
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01084)
                      "pass request body failed to %pI (%s)",
                      p_conn->addr, p_conn->hostname);
        if (origin->aborted) {
            const char *ssl_note;

            if (((ssl_note = apr_table_get(origin->notes, "SSL_connect_rv"))
                 != NULL) && (strcmp(ssl_note, "err") == 0)) {
                return ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                                     "Error during SSL Handshake with"
                                     " remote server");
            }
            return APR_STATUS_IS_TIMEUP(status) ? HTTP_GATEWAY_TIME_OUT
                                                : HTTP_BAD_GATEWAY;
        }
        else {
            return HTTP_BAD_REQUEST;
        }
    }
    return OK;
}

/* Fill in unknown schemes from apr_uri_port_of_scheme() */

typedef struct proxy_schemes_t {
    const char *name;
    apr_port_t default_port;
} proxy_schemes_t ;

static proxy_schemes_t pschemes[] =
{
    {"fcgi",     8000},
    {"ajp",      AJP13_DEF_PORT},
    {"scgi",     SCGI_DEF_PORT},
    {"h2c",      DEFAULT_HTTP_PORT},
    {"h2",       DEFAULT_HTTPS_PORT},
    {"ws",       DEFAULT_HTTP_PORT},
    {"wss",      DEFAULT_HTTPS_PORT},
    { NULL, 0xFFFF }     /* unknown port */
};

PROXY_DECLARE(apr_port_t) ap_proxy_port_of_scheme(const char *scheme)
{
    if (scheme) {
        apr_port_t port;
        if ((port = apr_uri_port_of_scheme(scheme)) != 0) {
            return port;
        } else {
            proxy_schemes_t *pscheme;
            for (pscheme = pschemes; pscheme->name != NULL; ++pscheme) {
                if (ap_cstr_casecmp(scheme, pscheme->name) == 0) {
                    return pscheme->default_port;
                }
            }
        }
    }
    return 0;
}

PROXY_DECLARE(apr_status_t) ap_proxy_buckets_lifetime_transform(request_rec *r,
                                                      apr_bucket_brigade *from,
                                                      apr_bucket_brigade *to)
{
    apr_bucket *e;
    apr_bucket *new;
    const char *data;
    apr_size_t bytes;
    apr_status_t rv = APR_SUCCESS;
    apr_bucket_alloc_t *bucket_alloc = to->bucket_alloc;

    apr_brigade_cleanup(to);
    for (e = APR_BRIGADE_FIRST(from);
         e != APR_BRIGADE_SENTINEL(from);
         e = APR_BUCKET_NEXT(e)) {
        if (!APR_BUCKET_IS_METADATA(e)) {
            apr_bucket_read(e, &data, &bytes, APR_BLOCK_READ);
            new = apr_bucket_transient_create(data, bytes, bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else if (APR_BUCKET_IS_FLUSH(e)) {
            new = apr_bucket_flush_create(bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else if (APR_BUCKET_IS_EOS(e)) {
            new = apr_bucket_eos_create(bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(03304)
                          "Unhandled bucket type of type %s in"
                          " ap_proxy_buckets_lifetime_transform", e->type->name);
            rv = APR_EGENERAL;
        }
    }
    return rv;
}

/* An arbitrary large value to address pathological case where we keep
 * reading from one side only, without scheduling the other direction for
 * too long. This can happen with large MTU and small read buffers, like
 * micro-benchmarking huge files bidirectional transfer with client, proxy
 * and backend on localhost for instance. Though we could just ignore the
 * case and let the sender stop by itself at some point when/if it needs to
 * receive data, or the receiver stop when/if it needs to send...
 */
#define PROXY_TRANSFER_MAX_READS 10000

static apr_status_t proxy_transfer(request_rec *r,
                                   conn_rec *c_i,
                                   conn_rec *c_o,
                                   apr_bucket_brigade *bb_i,
                                   apr_bucket_brigade *bb_o,
                                   const char *name,
                                   apr_off_t bsize,
                                   int flags,
                                   apr_off_t *bytes_in,
                                   apr_off_t *bytes_out,
                                   proxy_tunnel_rec *tunnel)
{
    apr_status_t rv;
    int flush_each = 0;
    unsigned int num_reads = 0;
    apr_off_t len;
    apr_bucket *b;

    /*
     * Compat: since FLUSH_EACH is default (and zero) for legacy reasons, we
     * pretend it's no FLUSH_AFTER nor YIELD_PENDING flags, the latter because
     * flushing would defeat the purpose of checking for pending data (hence
     * determine whether or not the output chain/stack is full for stopping).
     */
    if (!(flags & (AP_PROXY_TRANSFER_FLUSH_AFTER |
                   AP_PROXY_TRANSFER_YIELD_PENDING))) {
        flush_each = 1;
    }

    for (;;) {
        apr_brigade_cleanup(bb_i);
        rv = ap_get_brigade(c_i->input_filters, bb_i, AP_MODE_READBYTES,
                            APR_NONBLOCK_READ, bsize);
        if (rv != APR_SUCCESS) {
            if (!APR_STATUS_IS_EAGAIN(rv) && !APR_STATUS_IS_EOF(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(03308)
                              "proxy_transfer: can't get data from %s", name);
                if (rv == APR_INCOMPLETE) {
                    /* Don't return APR_INCOMPLETE, it'd mean "should yield"
                     * for the caller, while it means "incomplete body" here
                     * from ap_http_filter(), which is an error.
                     */
                    rv = APR_EGENERAL;
                }
            }
            break;
        }
        if (c_o->aborted) {
            rv = APR_EPIPE;
            break;
        }
        if (APR_BRIGADE_EMPTY(bb_i)) {
            break;
        }

        len = -1;
        apr_brigade_length(bb_i, 0, &len);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "proxy_transfer: got %" APR_OFF_T_FMT " bytes "
                      "from %s", len, name);
        if (bytes_in && len > 0) {
            *bytes_in += len;
        }

        rv = ap_proxy_buckets_lifetime_transform(r, bb_i, bb_o);
        if (rv != APR_SUCCESS) {
            break;
        }

        if (tunnel) {
            int rc = proxy_run_tunnel_forward(tunnel, c_i, c_o, bb_o);
            if (rc != OK && rc != DONE) {
                if (!ap_is_HTTP_ERROR(rc)) {
                    /* SUSPENDED is not allowed for now */
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10295)
                                  "proxy: %s: invalid status %d returned by "
                                  "tunnel forward hooks", tunnel->scheme, rc);
                }
                rv = APR_EGENERAL;
                break;
            }
            if (APR_BRIGADE_EMPTY(bb_o)) {
                /* Buckets retained by the hooks, next. */
                continue;
            }
            if (rc == DONE) {
                /* DONE with data is invalid because it'd mean that the next
                 * hooks wouldn't have a chance to see the data, hence no hook
                 * would be able to retain data.
                 */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10296)
                              "proxy: %s: invalid return value from tunnel "
                              " forward hook", tunnel->scheme);
                rv = APR_EGENERAL;
                break;
            }

            len = -1;
            apr_brigade_length(bb_o, 0, &len);
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                          "proxy_transfer: forward %" APR_OFF_T_FMT " bytes "
                          "from %s", len, name);
        }
        if (bytes_out && len > 0) {
            *bytes_out += len;
        }

        if (flush_each) {
            /*
             * Do not use ap_fflush here since this would cause the flush
             * bucket to be sent in a separate brigade afterwards which
             * causes some filters to set aside the buckets from the first
             * brigade and process them when FLUSH arrives in the second
             * brigade. As set asides of our transformed buckets involve
             * memory copying we try to avoid this. If we have the flush
             * bucket in the first brigade they directly process the
             * buckets without setting them aside.
             */
            b = apr_bucket_flush_create(bb_o->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb_o, b);
        }
        else {
            /* Prevent setaside/coalescing by intermediate filters. */
            b = ap_bucket_wc_create(bb_o->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb_o, b);
        }
        rv = ap_pass_brigade(c_o->output_filters, bb_o);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(03307)
                          "proxy_transfer: can't pass %" APR_OFF_T_FMT
                          " bytes from %s", len, name);
            flags &= ~AP_PROXY_TRANSFER_FLUSH_AFTER;
            break;
        }
        apr_brigade_cleanup(bb_o);

        /* Yield if the output filters stack is full? This is to avoid
         * blocking and give the caller a chance to POLLOUT async.
         */
        if ((flags & AP_PROXY_TRANSFER_YIELD_PENDING)
                && ap_filter_should_yield(c_o->output_filters)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                          "proxy_transfer: yield (output pending)");
            rv = APR_INCOMPLETE;
            break;
        }

        /* Yield if we keep hold of the thread for too long? This gives
         * the caller a chance to schedule the other direction too.
         */
        if ((flags & AP_PROXY_TRANSFER_YIELD_MAX_READS)
                && ++num_reads > PROXY_TRANSFER_MAX_READS) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                          "proxy_transfer: yield (max reads)");
            rv = APR_SUCCESS;
            break;
        }
    }

    /* bb_o first to avoid protential dangling buckets (transient) */
    apr_brigade_cleanup(bb_o);
    apr_brigade_cleanup(bb_i);

    if ((flags & AP_PROXY_TRANSFER_FLUSH_AFTER) && !c_o->aborted) {
        ap_fflush(c_o->output_filters, bb_o);
        apr_brigade_cleanup(bb_o);
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, rv, r,
                  "proxy_transfer complete (%s %pI)",
                  (c_i == r->connection) ? "to" : "from",
                  (c_i == r->connection) ? c_o->client_addr
                                         : c_i->client_addr);

    if (APR_STATUS_IS_EAGAIN(rv)) {
        rv = APR_SUCCESS;
    }
    return rv;
}

PROXY_DECLARE(apr_status_t) ap_proxy_transfer_between_connections(
                                                       request_rec *r,
                                                       conn_rec *c_i,
                                                       conn_rec *c_o,
                                                       apr_bucket_brigade *bb_i,
                                                       apr_bucket_brigade *bb_o,
                                                       const char *name,
                                                       int *sent,
                                                       apr_off_t bsize,
                                                       int flags)
{
    apr_off_t bytes_out = 0;
    apr_status_t rv = proxy_transfer(r, c_i, c_o, bb_i, bb_o, name, bsize,
                                     flags, NULL, &bytes_out, NULL);
    if (sent && bytes_out > 0) {
        *sent = 1;
    }
    return rv;
}

struct proxy_tunnel_conn {
    /* the other side of the tunnel */
    struct proxy_tunnel_conn *other;

    conn_rec *c;
    const char *name;

    apr_pollfd_t *pfd;
    apr_bucket_brigade *bb;

    apr_off_t bytes_in,
              bytes_out;

    unsigned int down_in:1,
                 down_out:1;
};

PROXY_DECLARE(apr_off_t) ap_proxy_tunnel_conn_bytes_in(
                                const proxy_tunnel_conn_t *tc)
{
    return tc->bytes_in;
}
PROXY_DECLARE(apr_off_t) ap_proxy_tunnel_conn_bytes_out(
                                const proxy_tunnel_conn_t *tc)
{
    return tc->bytes_out;
}

PROXY_DECLARE(apr_status_t) ap_proxy_tunnel_create(proxy_tunnel_rec **ptunnel,
                                                   request_rec *r, conn_rec *c_o,
                                                   const char *scheme)
{
    apr_status_t rv;
    conn_rec *c_i = r->connection;
    apr_interval_time_t client_timeout = -1, origin_timeout = -1;
    proxy_tunnel_rec *tunnel;

    *ptunnel = NULL;

    tunnel = apr_pcalloc(r->pool, sizeof(*tunnel));

    rv = apr_pollset_create(&tunnel->pollset, 2, r->pool, APR_POLLSET_NOCOPY);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    tunnel->r = r;
    tunnel->scheme = apr_pstrdup(r->pool, scheme);
    tunnel->client = apr_pcalloc(r->pool, sizeof(proxy_tunnel_conn_t));
    tunnel->origin = apr_pcalloc(r->pool, sizeof(proxy_tunnel_conn_t));
    tunnel->pfds = apr_array_make(r->pool, 2, sizeof(apr_pollfd_t));
    tunnel->read_buf_size = ap_get_read_buf_size(r);
    tunnel->client->other = tunnel->origin;
    tunnel->origin->other = tunnel->client;
    tunnel->timeout = -1;

    tunnel->client->c = c_i;
    tunnel->client->name = "client";
    tunnel->client->bb = apr_brigade_create(c_i->pool, c_i->bucket_alloc);
    tunnel->client->pfd = &APR_ARRAY_PUSH(tunnel->pfds, apr_pollfd_t);
    tunnel->client->pfd->p = r->pool;
    tunnel->client->pfd->desc_type = APR_NO_DESC;
    rv = ap_get_pollfd_from_conn(tunnel->client->c,
                                 tunnel->client->pfd, &client_timeout);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    tunnel->client->pfd->client_data = tunnel->client;
    if (tunnel->client->pfd->desc_type == APR_POLL_SOCKET) {
        apr_socket_opt_set(tunnel->client->pfd->desc.s, APR_SO_NONBLOCK, 1);
    }

    tunnel->origin->c = c_o;
    tunnel->origin->name = "origin";
    tunnel->origin->bb = apr_brigade_create(c_o->pool, c_o->bucket_alloc);
    tunnel->origin->pfd = &APR_ARRAY_PUSH(tunnel->pfds, apr_pollfd_t);
    tunnel->origin->pfd->p = r->pool;
    tunnel->origin->pfd->desc_type = APR_POLL_SOCKET;
    tunnel->origin->pfd->desc.s = ap_get_conn_socket(c_o);
    tunnel->origin->pfd->client_data = tunnel->origin;
    apr_socket_timeout_get(tunnel->origin->pfd->desc.s, &origin_timeout);
    apr_socket_opt_set(tunnel->origin->pfd->desc.s, APR_SO_NONBLOCK, 1);

    /* Defaults to the largest timeout of both connections */
    tunnel->timeout = (client_timeout >= 0 && client_timeout > origin_timeout ?
                       client_timeout : origin_timeout);

    /* Bidirectional non-HTTP stream will confuse mod_reqtimeoout */
    ap_remove_input_filter_byhandle(c_i->input_filters, "reqtimeout");

    /* The input/output filter stacks should contain connection filters only */
    r->input_filters = r->proto_input_filters = c_i->input_filters;
    r->output_filters = r->proto_output_filters = c_i->output_filters;

    /* Won't be reused after tunneling */
    c_i->keepalive = AP_CONN_CLOSE;
    c_o->keepalive = AP_CONN_CLOSE;

    /* Disable half-close forwarding for this request? */
    if (apr_table_get(r->subprocess_env, "proxy-nohalfclose")) {
        tunnel->nohalfclose = 1;
    }

    if (tunnel->client->pfd->desc_type == APR_POLL_SOCKET) {
        /* Both ends are sockets, the poll strategy is:
         * - poll both sides POLLOUT
         * - when one side is writable, remove the POLLOUT
         *   and add POLLIN to the other side.
         * - tunnel arriving data, remove POLLIN from the source
         *   again and add POLLOUT to the receiving side
         * - on EOF on read, remove the POLLIN from that side
         * Repeat until both sides are down */
        tunnel->client->pfd->reqevents = APR_POLLOUT | APR_POLLERR;
        tunnel->origin->pfd->reqevents = APR_POLLOUT | APR_POLLERR;
        if ((rv = apr_pollset_add(tunnel->pollset, tunnel->origin->pfd)) ||
            (rv = apr_pollset_add(tunnel->pollset, tunnel->client->pfd))) {
            return rv;
        }
    }
    else if (tunnel->client->pfd->desc_type == APR_POLL_FILE) {
        /* Input is a PIPE fd, the poll strategy is:
         * - always POLLIN on origin
         * - use socket strategy described above for client only
         * otherwise the same
         */
        tunnel->client->pfd->reqevents = 0;
        tunnel->origin->pfd->reqevents = APR_POLLIN | APR_POLLHUP |
                                         APR_POLLOUT | APR_POLLERR;
        if ((rv = apr_pollset_add(tunnel->pollset, tunnel->origin->pfd))) {
            return rv;
        }
    }
    else {
        /* input is already closed, unsual, but we know nothing about
         * the tunneled protocol. */
        tunnel->client->down_in = 1;
        tunnel->origin->pfd->reqevents = APR_POLLIN | APR_POLLHUP;
        if ((rv = apr_pollset_add(tunnel->pollset, tunnel->origin->pfd))) {
            return rv;
        }
    }

    *ptunnel = tunnel;
    return APR_SUCCESS;
}

PROXY_DECLARE(apr_status_t) ap_proxy_decrement_busy_count(void *worker_)
{
    apr_size_t val;
    proxy_worker *worker = worker_;

#if APR_SIZEOF_VOIDP == 4
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(apr_uint32_t));
    val = apr_atomic_read32(&worker->s->busy);
    while (val > 0) {
        apr_size_t old = val;
        val = apr_atomic_cas32(&worker->s->busy, val - 1, old);
        if (val == old) {
            break;
        }
    }
#elif APR_VERSION_AT_LEAST(1,7,4) /* APR 64bit atomics not safe before 1.7.4 */
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(apr_uint64_t));
    val = apr_atomic_read64(&worker->s->busy);
    while (val > 0) {
        apr_size_t old = val;
        val = apr_atomic_cas64(&worker->s->busy, val - 1, old);
        if (val == old) {
            break;
        }
    }
#else /* Use atomics for (64bit) pointers */
    void *volatile *busy_p = (void *)&worker->s->busy;
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(void*));
    AP_DEBUG_ASSERT((apr_uintptr_t)busy_p % sizeof(void*) == 0);
    val = (apr_uintptr_t)apr_atomic_casptr((void *)busy_p, NULL, NULL);
    while (val > 0) {
        apr_size_t old = val;
        val = (apr_uintptr_t)apr_atomic_casptr((void *)busy_p,
                                               (void *)(apr_uintptr_t)(val - 1),
                                               (void *)(apr_uintptr_t)old);
        if (val == old) {
            break;
        }
    }
#endif
    return APR_SUCCESS;
}

PROXY_DECLARE(void) ap_proxy_increment_busy_count(proxy_worker *worker)
{
    apr_size_t val;
#if APR_SIZEOF_VOIDP == 4
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(apr_uint32_t));
    val = apr_atomic_read32(&worker->s->busy);
    while (val < APR_INT32_MAX) {
        apr_size_t old = val;
        val = apr_atomic_cas32(&worker->s->busy, val + 1, old);
        if (val == old) {
            break;
        }
    }
#elif APR_VERSION_AT_LEAST(1,7,4) /* APR 64bit atomics not safe before 1.7.4 */
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(apr_uint64_t));
    val = apr_atomic_read64(&worker->s->busy);
    while (val < APR_INT64_MAX) {
        apr_size_t old = val;
        val = apr_atomic_cas64(&worker->s->busy, val + 1, old);
        if (val == old) {
            break;
        }
    }
#else /* Use atomics for (64bit) pointers */
    void *volatile *busy_p = (void *)&worker->s->busy;
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(void*));
    AP_DEBUG_ASSERT((apr_uintptr_t)busy_p % sizeof(void*) == 0);
    val = (apr_uintptr_t)apr_atomic_casptr((void *)busy_p, NULL, NULL);
    while (val < APR_INT64_MAX) {
        apr_size_t old = val;
        val = (apr_uintptr_t)apr_atomic_casptr((void *)busy_p,
                                               (void *)(apr_uintptr_t)(val + 1),
                                               (void *)(apr_uintptr_t)old);
        if (val == old) {
            break;
        }
    }
#endif
}

PROXY_DECLARE(apr_size_t) ap_proxy_get_busy_count(proxy_worker *worker)
{
    apr_size_t val;
#if APR_SIZEOF_VOIDP == 4
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(apr_uint32_t));
    val = apr_atomic_read32(&worker->s->busy);
#elif APR_VERSION_AT_LEAST(1,7,4) /* APR 64bit atomics not safe before 1.7.4 */
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(apr_uint64_t));
    val = apr_atomic_read64(&worker->s->busy);
#else /* Use atomics for (64bit) pointers */
    void *volatile *busy_p = (void *)&worker->s->busy;
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(void*));
    AP_DEBUG_ASSERT((apr_uintptr_t)busy_p % sizeof(void*) == 0);
    val = (apr_uintptr_t)apr_atomic_casptr((void *)busy_p, NULL, NULL);
#endif

    return val;
}

PROXY_DECLARE(void) ap_proxy_set_busy_count(proxy_worker *worker, apr_size_t to)
{
#if APR_SIZEOF_VOIDP == 4
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(apr_uint32_t));
    apr_atomic_set32(&worker->s->busy, to);
#elif APR_VERSION_AT_LEAST(1,7,4) /* APR 64bit atomics not safe before 1.7.4 */
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(apr_uint64_t));
    apr_atomic_set64(&worker->s->busy, to);
#else /* Use atomics for (64bit) pointers */
    void *volatile *busy_p = (void *)&worker->s->busy;
    AP_DEBUG_ASSERT(sizeof(apr_size_t) == sizeof(void*));
    AP_DEBUG_ASSERT((apr_uintptr_t)busy_p % sizeof(void*) == 0);
    apr_atomic_xchgptr((void *)busy_p, (void *)(apr_uintptr_t)to);
#endif
}

static void add_pollset(apr_pollset_t *pollset, apr_pollfd_t *pfd,
                        apr_int16_t events)
{
    apr_status_t rv;

    AP_DEBUG_ASSERT((pfd->reqevents & events) == 0);

    if (pfd->reqevents) {
        rv = apr_pollset_remove(pollset, pfd);
        if (rv != APR_SUCCESS) {
            AP_DEBUG_ASSERT(1);
        }
    }

    if (events & APR_POLLIN) {
        events |= APR_POLLHUP;
    }
    pfd->reqevents |= events | APR_POLLERR;
    rv = apr_pollset_add(pollset, pfd);
    if (rv != APR_SUCCESS) {
        AP_DEBUG_ASSERT(1);
    }
}

static void del_pollset(apr_pollset_t *pollset, apr_pollfd_t *pfd,
                        apr_int16_t events)
{
    apr_status_t rv;

    AP_DEBUG_ASSERT((pfd->reqevents & events) != 0);

    rv = apr_pollset_remove(pollset, pfd);
    if (rv != APR_SUCCESS) {
        AP_DEBUG_ASSERT(0);
        return;
    }

    if (events & APR_POLLIN) {
        events |= APR_POLLHUP;
    }
    if (pfd->reqevents & ~(events | APR_POLLERR)) {
        pfd->reqevents &= ~events;
        rv = apr_pollset_add(pollset, pfd);
        if (rv != APR_SUCCESS) {
            AP_DEBUG_ASSERT(0);
            return;
        }
    }
    else {
        pfd->reqevents = 0;
    }
}

static int proxy_tunnel_transfer(proxy_tunnel_rec *tunnel,
                                 proxy_tunnel_conn_t *in)
{
    proxy_tunnel_conn_t *out = in->other;
    apr_status_t rv;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, tunnel->r,
                  "proxy: %s: %s input ready",
                  tunnel->scheme, in->name);

    rv = proxy_transfer(tunnel->r,
                        in->c, out->c,
                        in->bb, out->bb,
                        in->name, tunnel->read_buf_size,
                        AP_PROXY_TRANSFER_YIELD_PENDING |
                        AP_PROXY_TRANSFER_YIELD_MAX_READS,
                        &in->bytes_in, &out->bytes_out,
                        tunnel);
    if (rv != APR_SUCCESS) {
        if (APR_STATUS_IS_INCOMPLETE(rv)) {
            /* Pause POLLIN while waiting for POLLOUT on the other
             * side, hence avoid filling the output filters even
             * more to avoid blocking there.
             */
            ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, tunnel->r,
                          "proxy: %s: %s wait writable",
                          tunnel->scheme, out->name);
        }
        else if (APR_STATUS_IS_EOF(rv)) {
            /* Stop POLLIN and wait for POLLOUT (flush) on the
             * other side to shut it down.
             */
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, tunnel->r,
                          "proxy: %s: %s read shutdown",
                          tunnel->scheme, in->name);
            if (tunnel->nohalfclose) {
                /* No half-close forwarding, we are done both ways as
                 * soon as one side shuts down.
                 */
                return DONE;
            }
            in->down_in = 1;
        }
        else {
            /* Real failure, bail out */
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        del_pollset(tunnel->pollset, in->pfd, APR_POLLIN);
        if (out->pfd->desc_type == APR_POLL_SOCKET) {
            /* if the output is a SOCKET, we can stop polling the input
             * until the output signals POLLOUT again. */
            add_pollset(tunnel->pollset, out->pfd, APR_POLLOUT);
        }
        else {
            /* We can't use POLLOUT in this direction for the only
             * APR_POLL_FILE case we have so far (mod_h2's "signal" pipe),
             * we assume that the client's ouput filters chain will block/flush
             * if necessary (i.e. no pending data), hence that the origin
             * is EOF when reaching here. This direction is over. */
            ap_assert(in->down_in && APR_STATUS_IS_EOF(rv));
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, tunnel->r,
                          "proxy: %s: %s write shutdown",
                          tunnel->scheme, out->name);
            out->down_out = 1;
        }
    }

    return OK;
}

PROXY_DECLARE(int) ap_proxy_tunnel_run(proxy_tunnel_rec *tunnel)
{
    int status = OK, rc;
    request_rec *r = tunnel->r;
    apr_pollset_t *pollset = tunnel->pollset;
    proxy_tunnel_conn_t *client = tunnel->client,
                        *origin = tunnel->origin;
    apr_interval_time_t timeout = tunnel->timeout >= 0 ? tunnel->timeout : -1;
    const char *scheme = tunnel->scheme;
    apr_status_t rv;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(10212)
                  "proxy: %s: tunnel running (timeout %lf)",
                  scheme, timeout >= 0 ? (double)timeout / APR_USEC_PER_SEC
                                       : (double)-1.0);

    /* Loop until both directions of the connection are closed,
     * or a failure occurs.
     */
    do {
        const apr_pollfd_t *results;
        apr_int32_t nresults, i;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r,
                      "proxy: %s: polling (client=%hx, origin=%hx)",
                      scheme, client->pfd->reqevents, origin->pfd->reqevents);
        do {
            rv = apr_pollset_poll(pollset, timeout, &nresults, &results);
        } while (APR_STATUS_IS_EINTR(rv));

        if (rv != APR_SUCCESS) {
            if (APR_STATUS_IS_TIMEUP(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, APLOGNO(10213)
                              "proxy: %s: polling timed out "
                              "(client=%hx, origin=%hx)",
                              scheme, client->pfd->reqevents,
                              origin->pfd->reqevents);
                status = HTTP_GATEWAY_TIME_OUT;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10214)
                              "proxy: %s: polling failed", scheme);
                status = HTTP_INTERNAL_SERVER_ERROR;
            }
            goto done;
        }

        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, APLOGNO(10215)
                      "proxy: %s: woken up, %i result(s)", scheme, nresults);

        for (i = 0; i < nresults; i++) {
            const apr_pollfd_t *pfd = &results[i];
            proxy_tunnel_conn_t *tc = pfd->client_data;

            ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r,
                          "proxy: %s: #%i: %s: %hx/%hx", scheme, i,
                          tc->name, pfd->rtnevents, tc->pfd->reqevents);

            /* sanity check */
            if (pfd->desc.s != client->pfd->desc.s
                    && pfd->desc.s != origin->pfd->desc.s) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10222)
                              "proxy: %s: unknown socket in pollset", scheme);
                status = HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            if (!(pfd->rtnevents & (APR_POLLIN  | APR_POLLOUT |
                                    APR_POLLHUP | APR_POLLERR))) {
                /* this catches POLLNVAL etc.. */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10220)
                              "proxy: %s: polling events error (%x)",
                              scheme, pfd->rtnevents);
                status = HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            /* We want to write if we asked for POLLOUT and got:
             * - POLLOUT: the socket is ready for write;
             * - !POLLIN: the socket is in error state (POLLERR) so we let
             *   the user know by failing the write and log, OR the socket
             *   is shutdown for read already (POLLHUP) so we have to
             *   shutdown for write.
             */
            if ((tc->pfd->reqevents & APR_POLLOUT)
                    && ((pfd->rtnevents & APR_POLLOUT)
                        || !(tc->pfd->reqevents & APR_POLLIN)
                        || !(pfd->rtnevents & (APR_POLLIN | APR_POLLHUP)))) {
                proxy_tunnel_conn_t *out = tc, *in = tc->other;

                ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r,
                              "proxy: %s: %s output ready",
                              scheme, out->name);

                rc = ap_filter_output_pending(out->c);
                if (rc == OK) {
                    /* Keep polling out (only) */
                    continue;
                }
                if (rc != DECLINED) {
                    /* Real failure, bail out */
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10221)
                                  "proxy: %s: %s flushing failed (%i)",
                                  scheme, out->name, rc);
                    status = rc;
                    goto done;
                }

                /* No more pending data. If the other side is not readable
                 * anymore it's time to shutdown for write (this direction
                 * is over). Otherwise back to normal business.
                 */
                del_pollset(pollset, out->pfd, APR_POLLOUT);
                if (in->down_in) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                                  "proxy: %s: %s write shutdown",
                                  scheme, out->name);
                    apr_socket_shutdown(out->pfd->desc.s, 1);
                    out->down_out = 1;
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r,
                                  "proxy: %s: %s resume writable",
                                  scheme, out->name);
                    add_pollset(pollset, in->pfd, APR_POLLIN);

                    /* Flush any pending input data now, we don't know when
                     * the next POLLIN will trigger and retaining data might
                     * deadlock the underlying protocol. We don't check for
                     * pending data first with ap_filter_input_pending() since
                     * the read from proxy_tunnel_transfer() is nonblocking
                     * anyway and returning OK if there's no data.
                     */
                    rc = proxy_tunnel_transfer(tunnel, in);
                    if (rc != OK) {
                        status = rc;
                        goto done;
                    }
                }
            }

            /* We want to read if we asked for POLLIN|HUP and got:
             * - POLLIN|HUP: the socket is ready for read or EOF (POLLHUP);
             * - !POLLOUT: the socket is in error state (POLLERR) so we let
             *   the user know by failing the read and log.
             */
            if ((tc->pfd->reqevents & APR_POLLIN)
                    && ((pfd->rtnevents & (APR_POLLIN | APR_POLLHUP))
                        || !(pfd->rtnevents & APR_POLLOUT))) {
                rc = proxy_tunnel_transfer(tunnel, tc);
                if (rc != OK) {
                    status = rc;
                    goto done;
                }
            }
        }
    } while (!client->down_out || !origin->down_out);

done:
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(10223)
                  "proxy: %s: tunneling returns (%i)", scheme, status);
    if (client->bytes_out > 0) {
        tunnel->replied = 1;
    }
    if (status == DONE) {
        status = OK;
    }
    return status;
}

PROXY_DECLARE (const char *) ap_proxy_show_hcmethod(hcmethod_t method)
{
    proxy_hcmethods_t *m = proxy_hcmethods;
    for (; m->name; m++) {
        if (m->method == method) {
            return m->name;
        }
    }
    return "???";
}

void proxy_util_register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(ap_proxy_retry_worker);
    APR_REGISTER_OPTIONAL_FN(ap_proxy_clear_connection);
    APR_REGISTER_OPTIONAL_FN(proxy_balancer_get_best_worker);

    {
        apr_time_t *start_time = ap_retained_data_get("proxy_start_time");
        if (start_time == NULL) {
            start_time = ap_retained_data_create("proxy_start_time",
                                                 sizeof(*start_time));
            *start_time = apr_time_now();
        }
        proxy_start_time = start_time;
    }
}
