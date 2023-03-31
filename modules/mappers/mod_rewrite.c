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

/*                       _                            _ _
 *   _ __ ___   ___   __| |    _ __ _____      ___ __(_) |_ ___
 *  | '_ ` _ \ / _ \ / _` |   | '__/ _ \ \ /\ / / '__| | __/ _ \
 *  | | | | | | (_) | (_| |   | | |  __/\ V  V /| |  | | ||  __/
 *  |_| |_| |_|\___/ \__,_|___|_|  \___| \_/\_/ |_|  |_|\__\___|
 *                       |_____|
 *
 *  URL Rewriting Module
 *
 *  This module uses a rule-based rewriting engine (based on a
 *  regular-expression parser) to rewrite requested URLs on the fly.
 *
 *  It supports an unlimited number of additional rule conditions (which can
 *  operate on a lot of variables, even on HTTP headers) for granular
 *  matching and even external database lookups (either via plain text
 *  tables, DBM hash files or even external processes) for advanced URL
 *  substitution.
 *
 *  It operates on the full URLs (including the PATH_INFO part) both in
 *  per-server context (httpd.conf) and per-dir context (.htaccess) and even
 *  can generate QUERY_STRING parts on result.   The rewriting result finally
 *  can lead to internal subprocessing, external request redirection or even
 *  to internal proxy throughput.
 *
 *  This module was originally written in April 1996 and
 *  gifted exclusively to the The Apache Software Foundation in July 1997 by
 *
 *      Ralf S. Engelschall
 *      rse engelschall.com
 *      www.engelschall.com
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_user.h"
#include "apr_lib.h"
#include "apr_signal.h"
#include "apr_global_mutex.h"
#include "apr_dbm.h"
#include "apr_dbd.h"

#include "apr_version.h"
#if !APR_VERSION_AT_LEAST(2,0,0)
#include "apu_version.h"
#endif

#include "mod_dbd.h"

#if APR_HAS_THREADS
#include "apr_thread_mutex.h"
#endif

#define APR_WANT_MEMFUNC
#define APR_WANT_STRFUNC
#define APR_WANT_IOVEC
#include "apr_want.h"

/* XXX: Do we really need these headers? */
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_CTYPE_H
#include <ctype.h>
#endif
#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_ssl.h"
#include "http_vhost.h"
#include "util_mutex.h"

#include "mod_rewrite.h"
#include "ap_expr.h"

#include "test_char.h"

static ap_dbd_t *(*dbd_acquire)(request_rec*) = NULL;
static void (*dbd_prepare)(server_rec*, const char*, const char*) = NULL;
static const char* really_last_key = "rewrite_really_last";

/*
 * in order to improve performance on running production systems, you
 * may strip all rewritelog code entirely from mod_rewrite by using the
 * -DREWRITELOG_DISABLED compiler option.
 *
 * DO NOT USE THIS OPTION FOR PUBLIC BINARY RELEASES. Otherwise YOU are
 * responsible for answering all the mod_rewrite questions out there.
 */
/* If logging is limited to APLOG_DEBUG or lower, disable rewrite log, too */
#ifdef  APLOG_MAX_LOGLEVEL
#if     APLOG_MAX_LOGLEVEL < APLOG_TRACE1
#ifndef REWRITELOG_DISABLED
#define REWRITELOG_DISABLED
#endif
#endif
#endif

#ifndef REWRITELOG_DISABLED

#define rewritelog(x) do_rewritelog x
#define REWRITELOG_MODE  ( APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD )
#define REWRITELOG_FLAGS ( APR_WRITE | APR_APPEND | APR_CREATE )

#else /* !REWRITELOG_DISABLED */

#define rewritelog(x)

#endif /* REWRITELOG_DISABLED */

/* remembered mime-type for [T=...] */
#define REWRITE_FORCED_MIMETYPE_NOTEVAR "rewrite-forced-mimetype"
#define REWRITE_FORCED_HANDLER_NOTEVAR  "rewrite-forced-handler"

#define ENVVAR_SCRIPT_URL "SCRIPT_URL"
#define REDIRECT_ENVVAR_SCRIPT_URL "REDIRECT_" ENVVAR_SCRIPT_URL
#define ENVVAR_SCRIPT_URI "SCRIPT_URI"

#define CONDFLAG_NONE               (1<<0)
#define CONDFLAG_NOCASE             (1<<1)
#define CONDFLAG_NOTMATCH           (1<<2)
#define CONDFLAG_ORNEXT             (1<<3)
#define CONDFLAG_NOVARY             (1<<4)

#define RULEFLAG_NONE               (1<<0)
#define RULEFLAG_FORCEREDIRECT      (1<<1)
#define RULEFLAG_LASTRULE           (1<<2)
#define RULEFLAG_NEWROUND           (1<<3)
#define RULEFLAG_CHAIN              (1<<4)
#define RULEFLAG_IGNOREONSUBREQ     (1<<5)
#define RULEFLAG_NOTMATCH           (1<<6)
#define RULEFLAG_PROXY              (1<<7)
#define RULEFLAG_PASSTHROUGH        (1<<8)
#define RULEFLAG_QSAPPEND           (1<<9)
#define RULEFLAG_NOCASE             (1<<10)
#define RULEFLAG_NOESCAPE           (1<<11)
#define RULEFLAG_NOSUB              (1<<12)
#define RULEFLAG_STATUS             (1<<13)
#define RULEFLAG_ESCAPEBACKREF      (1<<14)
#define RULEFLAG_DISCARDPATHINFO    (1<<15)
#define RULEFLAG_QSDISCARD          (1<<16)
#define RULEFLAG_END                (1<<17)
#define RULEFLAG_ESCAPENOPLUS       (1<<18)
#define RULEFLAG_QSLAST             (1<<19)
#define RULEFLAG_QSNONE             (1<<20) /* programattic only */
#define RULEFLAG_ESCAPECTLS         (1<<21)

/* return code of the rewrite rule
 * the result may be escaped - or not
 */
#define ACTION_NORMAL               (1<<0)
#define ACTION_NOESCAPE             (1<<1)
#define ACTION_STATUS               (1<<2)


#define MAPTYPE_TXT                 (1<<0)
#define MAPTYPE_DBM                 (1<<1)
#define MAPTYPE_PRG                 (1<<2)
#define MAPTYPE_INT                 (1<<3)
#define MAPTYPE_RND                 (1<<4)
#define MAPTYPE_DBD                 (1<<5)
#define MAPTYPE_DBD_CACHE           (1<<6)

#define ENGINE_DISABLED             (1<<0)
#define ENGINE_ENABLED              (1<<1)

#define OPTION_NONE                 (1<<0)
#define OPTION_INHERIT              (1<<1)
#define OPTION_INHERIT_BEFORE       (1<<2)
#define OPTION_NOSLASH              (1<<3)
#define OPTION_ANYURI               (1<<4)
#define OPTION_MERGEBASE            (1<<5)
#define OPTION_INHERIT_DOWN         (1<<6)
#define OPTION_INHERIT_DOWN_BEFORE  (1<<7)
#define OPTION_IGNORE_INHERIT       (1<<8)
#define OPTION_IGNORE_CONTEXT_INFO  (1<<9)
#define OPTION_LEGACY_PREFIX_DOCROOT (1<<10)

#ifndef RAND_MAX
#define RAND_MAX 32767
#endif

/* max cookie size in rfc 2109 */
/* XXX: not used at all. We should do a check somewhere and/or cut the cookie */
#define MAX_COOKIE_LEN 4096

/* max line length (incl.\n) in text rewrite maps */
#ifndef REWRITE_MAX_TXT_MAP_LINE
#define REWRITE_MAX_TXT_MAP_LINE 1024
#endif

/* buffer length for prg rewrite maps */
#ifndef REWRITE_PRG_MAP_BUF
#define REWRITE_PRG_MAP_BUF 1024
#endif

/* for better readbility */
#define LEFT_CURLY  '{'
#define RIGHT_CURLY '}'

/*
 * expansion result items on the stack to save some cycles
 *
 * (5 == about 2 variables like "foo%{var}bar%{var}baz")
 */
#define SMALL_EXPANSION 5

/*
 * check that a subrequest won't cause infinite recursion
 *
 * either not in a subrequest, or in a subrequest
 * and URIs aren't NULL and sub/main URIs differ
 */
#define subreq_ok(r) (!r->main || \
    (r->main->uri && r->uri && strcmp(r->main->uri, r->uri)))

#ifndef REWRITE_MAX_ROUNDS
#define REWRITE_MAX_ROUNDS 32000
#endif

/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                 Types and Structures
 * |                                                       |
 * +-------------------------------------------------------+
 */

typedef struct {
    const char *datafile;          /* filename for map data files         */
    const char *dbmtype;           /* dbm type for dbm map data files     */
    const char *checkfile;         /* filename to check for map existence */
    const char *cachename;         /* for cached maps (txt/rnd/dbm)       */
    int   type;                    /* the type of the map                 */
    apr_file_t *fpin;              /* in  file pointer for program maps   */
    apr_file_t *fpout;             /* out file pointer for program maps   */
    apr_file_t *fperr;             /* err file pointer for program maps   */
    char *(*func)(request_rec *,   /* function pointer for internal maps  */
                  char *);
    char **argv;                   /* argv of the external rewrite map    */
    const char *dbdq;              /* SQL SELECT statement for rewritemap */
    const char *checkfile2;        /* filename to check for map existence
                                      NULL if only one file               */
    const char *user;              /* run RewriteMap program as this user */
    const char *group;             /* run RewriteMap program as this group */
} rewritemap_entry;

/* special pattern types for RewriteCond */
typedef enum {
    CONDPAT_REGEX = 0,
    CONDPAT_FILE_EXISTS,
    CONDPAT_FILE_SIZE,
    CONDPAT_FILE_LINK,
    CONDPAT_FILE_DIR,
    CONDPAT_FILE_XBIT,
    CONDPAT_LU_URL,
    CONDPAT_LU_FILE,
    CONDPAT_STR_LT,
    CONDPAT_STR_LE,
    CONDPAT_STR_EQ,
    CONDPAT_STR_GT,
    CONDPAT_STR_GE,
    CONDPAT_INT_LT,
    CONDPAT_INT_LE,
    CONDPAT_INT_EQ,
    CONDPAT_INT_GT,
    CONDPAT_INT_GE,
    CONDPAT_AP_EXPR
} pattern_type;

typedef struct {
    char           *input;   /* Input string of RewriteCond   */
    char           *pattern; /* the RegExp pattern string     */
    ap_regex_t     *regexp;  /* the precompiled regexp        */
    ap_expr_info_t *expr;    /* the compiled ap_expr          */
    int             flags;   /* Flags which control the match */
    pattern_type    ptype;   /* pattern type                  */
    int             pskip;   /* back-index to display pattern */
} rewritecond_entry;

/* single linked list for env vars and cookies */
typedef struct data_item {
    struct data_item *next;
    char *data;
} data_item;

typedef struct {
    apr_array_header_t *rewriteconds;/* the corresponding RewriteCond entries */
    char      *pattern;              /* the RegExp pattern string             */
    ap_regex_t *regexp;              /* the RegExp pattern compilation        */
    char      *output;               /* the Substitution string               */
    int        flags;                /* Flags which control the substitution  */
    char      *forced_mimetype;      /* forced MIME type of substitution      */
    char      *forced_handler;       /* forced content handler of subst.      */
    int        forced_responsecode;  /* forced HTTP response status           */
    data_item *env;                  /* added environment variables           */
    data_item *cookie;               /* added cookies                         */
    int        skip;                 /* number of next rules to skip          */
    int        maxrounds;            /* limit on number of loops with N flag  */
    const char *escapes;             /* specific backref escapes              */
    const char *noescapes;           /* specific backref chars not to escape  */
} rewriterule_entry;

typedef struct {
    int           state;              /* the RewriteEngine state            */
    int           options;            /* the RewriteOption state            */
    apr_hash_t         *rewritemaps;  /* the RewriteMap entries             */
    apr_array_header_t *rewriteconds; /* the RewriteCond entries (temp.)    */
    apr_array_header_t *rewriterules; /* the RewriteRule entries            */
    server_rec   *server;             /* the corresponding server indicator */
    unsigned int state_set:1;
    unsigned int options_set:1;
} rewrite_server_conf;

typedef struct {
    int           state;              /* the RewriteEngine state           */
    int           options;            /* the RewriteOption state           */
    apr_array_header_t *rewriteconds; /* the RewriteCond entries (temp.)   */
    apr_array_header_t *rewriterules; /* the RewriteRule entries           */
    char         *directory;          /* the directory where it applies    */
    const char   *baseurl;            /* the base-URL  where it applies    */
    unsigned int state_set:1;
    unsigned int options_set:1;
    unsigned int baseurl_set:1;
} rewrite_perdir_conf;

/* the (per-child) cache structures.
 */
typedef struct cache {
    apr_pool_t         *pool;
    apr_hash_t         *maps;
#if APR_HAS_THREADS
    apr_thread_mutex_t *lock;
#endif
} cache;

/* cached maps contain an mtime for the whole map and live in a subpool
 * of the cachep->pool. That makes it easy to forget them if necessary.
 */
typedef struct {
    apr_time_t mtime;
    apr_pool_t *pool;
    apr_hash_t *entries;
} cachedmap;

/* the regex structure for the
 * substitution of backreferences
 */
typedef struct backrefinfo {
    const char *source;
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
} backrefinfo;

/* single linked list used for
 * variable expansion
 */
typedef struct result_list {
    struct result_list *next;
    apr_size_t len;
    const char *string;
} result_list;

/* context structure for variable lookup and expansion
 */
typedef struct {
    request_rec *r;
    const char  *uri;
    const char  *vary_this;
    const char  *vary;
    char        *perdir;
    backrefinfo briRR;
    backrefinfo briRC;
} rewrite_ctx;

/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                 static module data
 * |                                                       |
 * +-------------------------------------------------------+
 */

/* the global module structure */
module AP_MODULE_DECLARE_DATA rewrite_module;

/* rewritemap int: handler function registry */
static apr_hash_t *mapfunc_hash;

/* the cache */
static cache *cachep;

/* whether proxy module is available or not */
static int proxy_available;

/* Locks/Mutexes */
static int rewrite_lock_needed = 0;
static apr_global_mutex_t *rewrite_mapr_lock_acquire = NULL;
static const char *rewritemap_mutex_type = "rewrite-map";

/* Optional functions imported from mod_ssl when loaded: */
static char *escape_backref(apr_pool_t *p, const char *path,
                            const char *escapeme, const char *noescapeme,
                            int flags);

/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |              rewriting logfile support
 * |                                                       |
 * +-------------------------------------------------------+
 */

#ifndef REWRITELOG_DISABLED
static void do_rewritelog(request_rec *r, int level, char *perdir,
                          const char *fmt, ...)
        __attribute__((format(printf,4,5)));

static void do_rewritelog(request_rec *r, int level, char *perdir,
                          const char *fmt, ...)
{
    char *logline, *text;
    const char *rhost, *rname;
    int redir;
    request_rec *req;
    va_list ap;

    if (!APLOG_R_IS_LEVEL(r, APLOG_DEBUG + level))
        return;

    rhost = ap_get_useragent_host(r, REMOTE_NOLOOKUP, NULL);
    rname = ap_get_remote_logname(r);

    for (redir=0, req=r; req->prev; req = req->prev) {
        ++redir;
    }

    va_start(ap, fmt);
    text = apr_pvsprintf(r->pool, fmt, ap);
    va_end(ap);

    logline = apr_psprintf(r->pool, "%s %s %s [%s/sid#%pp][rid#%pp/%s%s%s] "
                                    "%s%s%s%s",
                           rhost ? rhost : "UNKNOWN-HOST",
                           rname ? rname : "-",
                           r->user ? (*r->user ? r->user : "\"\"") : "-",
                           ap_get_server_name(r),
                           (void *)(r->server),
                           (void *)r,
                           r->main ? "subreq" : "initial",
                           redir ? "/redir#" : "",
                           redir ? apr_itoa(r->pool, redir) : "",
                           perdir ? "[perdir " : "",
                           perdir ? perdir : "",
                           perdir ? "] ": "",
                           text);

    AP_REWRITE_LOG((uintptr_t)r, level, r->main ? 0 : 1, (char *)ap_get_server_name(r), logline);

    /* Intentional no APLOGNO */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG + level, 0, r, "%s", logline);

    return;
}
#endif /* !REWRITELOG_DISABLED */


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                URI and path functions
 * |                                                       |
 * +-------------------------------------------------------+
 */

/* return number of chars of the scheme (incl. '://')
 * if the URI is absolute (includes a scheme etc.)
 * otherwise 0.
 * If supportqs is not NULL, we return a whether or not
 * the scheme supports a query string or not.
 *
 * NOTE: If you add new schemes here, please have a
 *       look at escape_absolute_uri and splitout_queryargs.
 *       Not every scheme takes query strings and some schemes
 *       may be handled in a special way.
 *
 * XXX: we may consider a scheme registry, perhaps with
 *      appropriate escape callbacks to allow other modules
 *      to extend mod_rewrite at runtime.
 */
static unsigned is_absolute_uri(char *uri, int *supportsqs)
{
    int dummy, *sqs;

    sqs = (supportsqs ? supportsqs : &dummy);
    *sqs = 0;
    /* fast exit */
    if (*uri == '/' || strlen(uri) <= 5) {
        return 0;
    }

    switch (*uri++) {
    case 'a':
    case 'A':
        if (!ap_cstr_casecmpn(uri, "jp://", 5)) {        /* ajp://    */
          *sqs = 1;
          return 6;
        }
        break;

    case 'b':
    case 'B':
        if (!ap_cstr_casecmpn(uri, "alancer://", 10)) {   /* balancer:// */
          *sqs = 1;
          return 11;
        }
        break;

    case 'f':
    case 'F':
        if (!ap_cstr_casecmpn(uri, "tp://", 5)) {        /* ftp://    */
            return 6;
        }
        if (!ap_cstr_casecmpn(uri, "cgi://", 6)) {       /* fcgi://   */
            *sqs = 1;
            return 7;
        }
        break;

    case 'g':
    case 'G':
        if (!ap_cstr_casecmpn(uri, "opher://", 8)) {     /* gopher:// */
            return 9;
        }
        break;

    case 'h':
    case 'H':
        if (!ap_cstr_casecmpn(uri, "ttp://", 6)) {       /* http://   */
            *sqs = 1;
            return 7;
        }
        else if (!ap_cstr_casecmpn(uri, "ttps://", 7)) { /* https://  */
            *sqs = 1;
            return 8;
        }
        else if (!ap_cstr_casecmpn(uri, "2://", 4)) {    /* h2://     */
            *sqs = 1;
            return 5;
        }
        else if (!ap_cstr_casecmpn(uri, "2c://", 5)) {   /* h2c://    */
            *sqs = 1;
            return 6;
        }
        break;

    case 'l':
    case 'L':
        if (!ap_cstr_casecmpn(uri, "dap://", 6)) {       /* ldap://   */
            return 7;
        }
        break;

    case 'm':
    case 'M':
        if (!ap_cstr_casecmpn(uri, "ailto:", 6)) {       /* mailto:   */
            *sqs = 1;
            return 7;
        }
        break;

    case 'n':
    case 'N':
        if (!ap_cstr_casecmpn(uri, "ews:", 4)) {         /* news:     */
            return 5;
        }
        else if (!ap_cstr_casecmpn(uri, "ntp://", 6)) {  /* nntp://   */
            return 7;
        }
        break;

    case 's':
    case 'S':
        if (!ap_cstr_casecmpn(uri, "cgi://", 6)) {       /* scgi://   */
            *sqs = 1;
            return 7;
        }
        break;

    case 'w':
    case 'W':
        if (!ap_cstr_casecmpn(uri, "s://", 4)) {        /* ws://     */
            *sqs = 1;
            return 5;
        }
        else if (!ap_cstr_casecmpn(uri, "ss://", 5)) {  /* wss://    */
            *sqs = 1;
            return 6;
        }
        break;

    case 'u':
    case 'U':
        if (!ap_cstr_casecmpn(uri, "nix:", 4)) {        /* unix:     */
            *sqs = 1;
            return (uri[4] == '/' && uri[5] == '/') ? 7 : 5;
        }
    }

    return 0;
}

static const char c2x_table[] = "0123456789abcdef";

static APR_INLINE unsigned char *c2x(unsigned what, unsigned char prefix,
                                     unsigned char *where)
{
#if APR_CHARSET_EBCDIC
    what = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)what);
#endif /*APR_CHARSET_EBCDIC*/
    *where++ = prefix;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0xf];
    return where;
}

/*
 * Escapes a backreference in a similar way as php's urlencode does.
 * Based on ap_os_escape_path in server/util.c
 */
static char *escape_backref(apr_pool_t *p, const char *path,
                            const char *escapeme, const char *noescapeme,
                            int flags)
{
    char *copy = apr_palloc(p, 3 * strlen(path) + 1);
    const unsigned char *s = (const unsigned char *)path;
    unsigned char *d = (unsigned char *)copy;
    int noplus = (flags & RULEFLAG_ESCAPENOPLUS) != 0;
    int ctls = (flags & RULEFLAG_ESCAPECTLS) != 0;
    unsigned char c;

    while ((c = *s)) {
        if (((ctls ? !TEST_CHAR(c, T_VCHAR_OBSTEXT) : !escapeme)
             || (escapeme && ap_strchr_c(escapeme, c)))
            && (!noescapeme || !ap_strchr_c(noescapeme, c))) {
            if (apr_isalnum(c) || c == '_') {
                *d++ = c;
            }
            else if (c == ' ' && !noplus) {
                *d++ = '+';
            }
            else {
                d = c2x(c, '%', d);
            }
        }
        else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}

/*
 * escape absolute uri, which may or may not be path oriented.
 * So let's handle them differently.
 */
static char *escape_absolute_uri(apr_pool_t *p, char *uri, unsigned scheme)
{
    char *cp;

    /* be safe.
     * NULL should indicate elsewhere, that something's wrong
     */
    if (!scheme || strlen(uri) < scheme) {
        return NULL;
    }

    cp = uri + scheme;

    /* scheme with authority part? */
    if (cp[-1] == '/') {
        /* skip host part */
        while (*cp && *cp != '/') {
            ++cp;
        }

        /* nothing after the hostpart. ready! */
        if (!*cp || !*++cp) {
            return apr_pstrdup(p, uri);
        }

        /* remember the hostname stuff */
        scheme = cp - uri;

        /* special thing for ldap.
         * The parts are separated by question marks. From RFC 2255:
         *     ldapurl = scheme "://" [hostport] ["/"
         *               [dn ["?" [attributes] ["?" [scope]
         *               ["?" [filter] ["?" extensions]]]]]]
         */
        if (!ap_cstr_casecmpn(uri, "ldap", 4)) {
            char *token[5];
            int c = 0;

            token[0] = cp = apr_pstrdup(p, cp);
            while (*cp && c < 4) {
                if (*cp == '?') {
                    token[++c] = cp + 1;
                    *cp = '\0';
                }
                ++cp;
            }

            return apr_pstrcat(p, apr_pstrndup(p, uri, scheme),
                                          ap_escape_uri(p, token[0]),
                               (c >= 1) ? "?" : NULL,
                               (c >= 1) ? ap_escape_uri(p, token[1]) : NULL,
                               (c >= 2) ? "?" : NULL,
                               (c >= 2) ? ap_escape_uri(p, token[2]) : NULL,
                               (c >= 3) ? "?" : NULL,
                               (c >= 3) ? ap_escape_uri(p, token[3]) : NULL,
                               (c >= 4) ? "?" : NULL,
                               (c >= 4) ? ap_escape_uri(p, token[4]) : NULL,
                               NULL);
        }
    }

    /* Nothing special here. Apply normal escaping. */
    return apr_pstrcat(p, apr_pstrndup(p, uri, scheme),
                       ap_escape_uri(p, cp), NULL);
}

/*
 * split out a QUERY_STRING part from
 * the current URI string
 */
static void splitout_queryargs(request_rec *r, int flags)
{
    char *q;
    int split, skip;
    int qsappend = flags & RULEFLAG_QSAPPEND;
    int qsdiscard = flags & RULEFLAG_QSDISCARD;
    int qslast = flags & RULEFLAG_QSLAST;

    if (flags & RULEFLAG_QSNONE) {
        rewritelog((r, 2, NULL, "discarding query string, no parse from substitution"));
        r->args = NULL;
        return;
    }

    /* don't touch, unless it's a scheme for which a query string makes sense.
     * See RFC 1738 and RFC 2368.
     */
    if ((skip = is_absolute_uri(r->filename, &split))
        && !split) {
        r->args = NULL; /* forget the query that's still flying around */
        return;
    }

    if (qsdiscard) {
        r->args = NULL; /* Discard query string */
        rewritelog((r, 2, NULL, "discarding query string"));
    }

    q = qslast ? ap_strrchr(r->filename + skip, '?') : ap_strchr(r->filename + skip, '?');

    if (q != NULL) {
        char *olduri;
        apr_size_t len;

        olduri = apr_pstrdup(r->pool, r->filename);
        *q++ = '\0';
        if (qsappend) {
            if (*q) {
                r->args = apr_pstrcat(r->pool, q, "&" , r->args, NULL);
            }
        }
        else {
            r->args = apr_pstrdup(r->pool, q);
        }

        if (r->args) {
           len = strlen(r->args);

           if (!len) {
               r->args = NULL;
           }
           else if (r->args[len-1] == '&') {
               r->args[len-1] = '\0';
           }
        }

        rewritelog((r, 3, NULL, "split uri=%s -> uri=%s, args=%s", olduri,
                    r->filename, r->args ? r->args : "<none>"));
    }
}

/*
 * strip 'http[s]://ourhost/' from URI
 */
static void reduce_uri(request_rec *r)
{
    char *cp;
    apr_size_t l;

    cp = (char *)ap_http_scheme(r);
    l  = strlen(cp);
    if (   strlen(r->filename) > l+3
        && ap_cstr_casecmpn(r->filename, cp, l) == 0
        && r->filename[l]   == ':'
        && r->filename[l+1] == '/'
        && r->filename[l+2] == '/' ) {

        unsigned short port;
        char *portp, *host, *url, *scratch;

        scratch = apr_pstrdup(r->pool, r->filename); /* our scratchpad */

        /* cut the hostname and port out of the URI */
        cp = host = scratch + l + 3;    /* 3 == strlen("://") */
        while (*cp && *cp != '/' && *cp != ':') {
            ++cp;
        }

        if (*cp == ':') {      /* additional port given */
            *cp++ = '\0';
            portp = cp;
            while (*cp && *cp != '/') {
                ++cp;
            }
            *cp = '\0';

            port = atoi(portp);
            url = r->filename + (cp - scratch);
            if (!*url) {
                url = "/";
            }
        }
        else if (*cp == '/') { /* default port */
            *cp = '\0';

            port = ap_default_port(r);
            url = r->filename + (cp - scratch);
        }
        else {
            port = ap_default_port(r);
            url = "/";
        }

        /* now check whether we could reduce it to a local path... */
        if (ap_matches_request_vhost(r, host, port)) {
            rewrite_server_conf *conf = 
                ap_get_module_config(r->server->module_config, &rewrite_module);
            rewritelog((r, 3, NULL, "reduce %s -> %s", r->filename, url));
            r->filename = apr_pstrdup(r->pool, url);

            /* remember that the uri was reduced */
            if(!(conf->options & OPTION_LEGACY_PREFIX_DOCROOT)) {
                apr_table_setn(r->notes, "mod_rewrite_uri_reduced", "true");
            }
        }
    }

    return;
}

/*
 * add 'http[s]://ourhost[:ourport]/' to URI
 * if URI is still not fully qualified
 */
static void fully_qualify_uri(request_rec *r)
{
    if (r->method_number == M_CONNECT) {
        return;
    }
    else if (!is_absolute_uri(r->filename, NULL)) {
        const char *thisserver;
        char *thisport;
        int port;

        thisserver = ap_get_server_name_for_url(r);
        port = ap_get_server_port(r);
        thisport = ap_is_default_port(port, r)
                   ? ""
                   : apr_psprintf(r->pool, ":%u", port);

        r->filename = apr_psprintf(r->pool, "%s://%s%s%s%s",
                                   ap_http_scheme(r), thisserver, thisport,
                                   (*r->filename == '/') ? "" : "/",
                                   r->filename);
    }

    return;
}

/*
 * stat() only the first segment of a path
 */
static int prefix_stat(const char *path, apr_pool_t *pool)
{
    const char *curpath = path;
    const char *root;
    const char *slash;
    char *statpath;
    apr_status_t rv;

    rv = apr_filepath_root(&root, &curpath, APR_FILEPATH_TRUENAME, pool);

    if (rv != APR_SUCCESS) {
        return 0;
    }

    /* let's recognize slashes only, the mod_rewrite semantics are opaque
     * enough.
     */
    if ((slash = ap_strchr_c(curpath, '/')) != NULL) {
        rv = apr_filepath_merge(&statpath, root,
                                apr_pstrndup(pool, curpath,
                                             (apr_size_t)(slash - curpath)),
                                APR_FILEPATH_NOTABOVEROOT |
                                APR_FILEPATH_NOTRELATIVE, pool);
    }
    else {
        rv = apr_filepath_merge(&statpath, root, curpath,
                                APR_FILEPATH_NOTABOVEROOT |
                                APR_FILEPATH_NOTRELATIVE, pool);
    }

    if (rv == APR_SUCCESS) {
        apr_finfo_t sb;

        if (apr_stat(&sb, statpath, APR_FINFO_MIN, pool) == APR_SUCCESS) {
            return 1;
        }
    }

    return 0;
}

/*
 * substitute the prefix path 'match' in 'input' with 'subst' (RewriteBase)
 */
static char *subst_prefix_path(request_rec *r, char *input, const char *match,
                               const char *subst)
{
    apr_size_t len = strlen(match);

    if (len && match[len - 1] == '/') {
        --len;
    }

    if (!strncmp(input, match, len) && input[len++] == '/') {
        apr_size_t slen, outlen;
        char *output;

        rewritelog((r, 5, NULL, "strip matching prefix: %s -> %s", input,
                    input+len));

        slen = strlen(subst);
        if (slen && subst[slen - 1] != '/') {
            ++slen;
        }

        outlen = strlen(input) + slen - len;
        output = apr_palloc(r->pool, outlen + 1); /* don't forget the \0 */

        memcpy(output, subst, slen);
        if (slen && !output[slen-1]) {
            output[slen-1] = '/';
        }
        memcpy(output+slen, input+len, outlen - slen);
        output[outlen] = '\0';

        rewritelog((r, 4, NULL, "add subst prefix: %s -> %s", input+len,
                    output));

        return output;
    }

    /* prefix didn't match */
    return input;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                    caching support
 * |                                                       |
 * +-------------------------------------------------------+
 */

static void set_cache_value(const char *name, apr_time_t t, char *key,
                            char *val)
{
    cachedmap *map;

    if (cachep) {
#if APR_HAS_THREADS
        apr_thread_mutex_lock(cachep->lock);
#endif
        map = apr_hash_get(cachep->maps, name, APR_HASH_KEY_STRING);

        if (!map) {
            apr_pool_t *p;

            if (apr_pool_create(&p, cachep->pool) != APR_SUCCESS) {
#if APR_HAS_THREADS
                apr_thread_mutex_unlock(cachep->lock);
#endif
                return;
            }
            apr_pool_tag(p, "rewrite_cachedmap");

            map = apr_palloc(cachep->pool, sizeof(cachedmap));
            map->pool = p;
            map->entries = apr_hash_make(map->pool);
            map->mtime = t;

            apr_hash_set(cachep->maps, name, APR_HASH_KEY_STRING, map);
        }
        else if (map->mtime != t) {
            apr_pool_clear(map->pool);
            map->entries = apr_hash_make(map->pool);
            map->mtime = t;
        }

        /* Now we should have a valid map->entries hash, where we
         * can store our value.
         *
         * We need to copy the key and the value into OUR pool,
         * so that we don't leave it during the r->pool cleanup.
         */
        apr_hash_set(map->entries,
                     apr_pstrdup(map->pool, key), APR_HASH_KEY_STRING,
                     apr_pstrdup(map->pool, val));

#if APR_HAS_THREADS
        apr_thread_mutex_unlock(cachep->lock);
#endif
    }

    return;
}

static char *get_cache_value(const char *name, apr_time_t t, char *key,
                             apr_pool_t *p)
{
    cachedmap *map;
    char *val = NULL;

    if (cachep) {
#if APR_HAS_THREADS
        apr_thread_mutex_lock(cachep->lock);
#endif
        map = apr_hash_get(cachep->maps, name, APR_HASH_KEY_STRING);

        if (map) {
            /* if this map is outdated, forget it. */
            if (map->mtime != t) {
                apr_pool_clear(map->pool);
                map->entries = apr_hash_make(map->pool);
                map->mtime = t;
            }
            else {
                val = apr_hash_get(map->entries, key, APR_HASH_KEY_STRING);
                if (val) {
                    /* copy the cached value into the supplied pool,
                     * where it belongs (r->pool usually)
                     */
                    val = apr_pstrdup(p, val);
                }
            }
        }

#if APR_HAS_THREADS
        apr_thread_mutex_unlock(cachep->lock);
#endif
    }

    return val;
}

static int init_cache(apr_pool_t *p)
{
    cachep = apr_palloc(p, sizeof(cache));
    if (apr_pool_create(&cachep->pool, p) != APR_SUCCESS) {
        cachep = NULL; /* turns off cache */
        return 0;
    }
    apr_pool_tag(cachep->pool, "rewrite_cachep");

    cachep->maps = apr_hash_make(cachep->pool);
#if APR_HAS_THREADS
    (void)apr_thread_mutex_create(&(cachep->lock), APR_THREAD_MUTEX_DEFAULT, p);
#endif

    return 1;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                    Map Functions
 * |                                                       |
 * +-------------------------------------------------------+
 */

/*
 * General Note: key is already a fresh string, created (expanded) just
 * for the purpose to be passed in here. So one can modify key itself.
 */

static char *rewrite_mapfunc_toupper(request_rec *r, char *key)
{
    ap_str_toupper(key);

    return key;
}

static char *rewrite_mapfunc_tolower(request_rec *r, char *key)
{
    ap_str_tolower(key);

    return key;
}

static char *rewrite_mapfunc_escape(request_rec *r, char *key)
{
    return ap_escape_uri(r->pool, key);
}

static char *rewrite_mapfunc_unescape(request_rec *r, char *key)
{
    ap_unescape_url(key);

    return key;
}

static char *select_random_value_part(request_rec *r, char *value)
{
    char *p = value;
    unsigned n = 1;

    /* count number of distinct values */
    while ((p = ap_strchr(p, '|')) != NULL) {
        ++n;
        ++p;
    }

    if (n > 1) {
        n = ap_random_pick(1, n);

        /* extract it from the whole string */
        while (--n && (value = ap_strchr(value, '|')) != NULL) {
            ++value;
        }

        if (value) { /* should not be NULL, but ... */
            p = ap_strchr(value, '|');
            if (p) {
                *p = '\0';
            }
        }
    }

    return value;
}

/* child process code */
static void rewrite_child_errfn(apr_pool_t *p, apr_status_t err,
                                const char *desc)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, err, NULL, APLOGNO(00653) "%s", desc);
}

static apr_status_t rewritemap_program_child(apr_pool_t *p,
                                             const char *progname, char **argv,
                                             const char *user, const char *group,
                                             apr_file_t **fpout,
                                             apr_file_t **fpin)
{
    apr_status_t rc;
    apr_procattr_t *procattr;
    apr_proc_t *procnew;

    if (   APR_SUCCESS == (rc=apr_procattr_create(&procattr, p))
        && APR_SUCCESS == (rc=apr_procattr_io_set(procattr, APR_FULL_BLOCK,
                                                  APR_FULL_BLOCK, APR_NO_PIPE))
        && APR_SUCCESS == (rc=apr_procattr_dir_set(procattr,
                                             ap_make_dirstr_parent(p, argv[0])))
        && (!user || APR_SUCCESS == (rc=apr_procattr_user_set(procattr, user, "")))
        && (!group || APR_SUCCESS == (rc=apr_procattr_group_set(procattr, group)))
        && APR_SUCCESS == (rc=apr_procattr_cmdtype_set(procattr, APR_PROGRAM))
        && APR_SUCCESS == (rc=apr_procattr_child_errfn_set(procattr,
                                                           rewrite_child_errfn))
        && APR_SUCCESS == (rc=apr_procattr_error_check_set(procattr, 1))) {

        procnew = apr_pcalloc(p, sizeof(*procnew));
        rc = apr_proc_create(procnew, argv[0], (const char **)argv, NULL,
                             procattr, p);

        if (rc == APR_SUCCESS) {
            apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);

            if (fpin) {
                (*fpin) = procnew->in;
            }

            if (fpout) {
                (*fpout) = procnew->out;
            }
        }
    }

    return (rc);
}

static apr_status_t run_rewritemap_programs(server_rec *s, apr_pool_t *p)
{
    rewrite_server_conf *conf;
    apr_hash_index_t *hi;
    apr_status_t rc;

    conf = ap_get_module_config(s->module_config, &rewrite_module);

    /*  If the engine isn't turned on,
     *  don't even try to do anything.
     */
    if (conf->state == ENGINE_DISABLED) {
        return APR_SUCCESS;
    }

    for (hi = apr_hash_first(p, conf->rewritemaps); hi; hi = apr_hash_next(hi)){
        apr_file_t *fpin = NULL;
        apr_file_t *fpout = NULL;
        rewritemap_entry *map;
        void *val;

        apr_hash_this(hi, NULL, NULL, &val);
        map = val;

        if (map->type != MAPTYPE_PRG) {
            continue;
        }
        if (!(map->argv[0]) || !*(map->argv[0]) || map->fpin || map->fpout) {
            continue;
        }

        rc = rewritemap_program_child(p, map->argv[0], map->argv,
                                      map->user, map->group,
                                      &fpout, &fpin);
        if (rc != APR_SUCCESS || fpin == NULL || fpout == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, APLOGNO(00654)
                         "mod_rewrite: could not start RewriteMap "
                         "program %s", map->checkfile);
            return rc;
        }
        map->fpin  = fpin;
        map->fpout = fpout;
    }

    return APR_SUCCESS;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                  Lookup functions
 * |                                                       |
 * +-------------------------------------------------------+
 */

static char *lookup_map_txtfile(request_rec *r, const char *file, char *key)
{
    apr_file_t *fp = NULL;
    char line[REWRITE_MAX_TXT_MAP_LINE + 1]; /* +1 for \0 */
    char *value, *keylast;
    apr_status_t rv;

    if ((rv = apr_file_open(&fp, file, APR_READ|APR_BUFFERED, APR_OS_DEFAULT,
                            r->pool)) != APR_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00655)
                      "mod_rewrite: can't open text RewriteMap file %s", file);
        return NULL;
    }

    keylast = key + strlen(key);
    value = NULL;
    while (apr_file_gets(line, sizeof(line), fp) == APR_SUCCESS) {
        char *p, *c;

        /* ignore comments and lines starting with whitespaces */
        if (*line == '#' || apr_isspace(*line)) {
            continue;
        }

        p = line;
        c = key;
        while (c < keylast && *p == *c && !apr_isspace(*p)) {
            ++p;
            ++c;
        }

        /* key doesn't match - ignore. */
        if (c != keylast || !apr_isspace(*p)) {
            continue;
        }

        /* jump to the value */
        while (apr_isspace(*p)) {
            ++p;
        }

        /* no value? ignore */
        if (!*p) {
            continue;
        }

        /* extract the value and return. */
        c = p;
        while (*p && !apr_isspace(*p)) {
            ++p;
        }
        value = apr_pstrmemdup(r->pool, c, p - c);
        break;
    }
    apr_file_close(fp);

    return value;
}

static char *lookup_map_dbmfile(request_rec *r, const char *file,
                                const char *dbmtype, char *key)
{
#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 7)
    const apr_dbm_driver_t *driver;
    const apu_err_t *err;
#endif
    apr_dbm_t *dbmfp = NULL;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    char *value;
    apr_status_t rv;

#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 7)
    if ((rv = apr_dbm_get_driver(&driver, dbmtype, &err,
            r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10287)
                "mod_rewrite: can't load DBM library '%s': %s",
                     err->reason, err->msg);
        return NULL;
    }
    if ((rv = apr_dbm_open2(&dbmfp, driver, file, APR_DBM_READONLY,
                              APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00656)
                      "mod_rewrite: can't open DBM RewriteMap %s", file);
        return NULL;
    }
#else
    if ((rv = apr_dbm_open_ex(&dbmfp, dbmtype, file, APR_DBM_READONLY,
                              APR_OS_DEFAULT, r->pool)) != APR_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00656)
                      "mod_rewrite: can't open DBM RewriteMap %s", file);
        return NULL;
    }
#endif

    dbmkey.dptr  = key;
    dbmkey.dsize = strlen(key);

    if (apr_dbm_fetch(dbmfp, dbmkey, &dbmval) == APR_SUCCESS && dbmval.dptr) {
        value = apr_pstrmemdup(r->pool, dbmval.dptr, dbmval.dsize);
    }
    else {
        value = NULL;
    }

    apr_dbm_close(dbmfp);

    return value;
}
static char *lookup_map_dbd(request_rec *r, char *key, const char *label)
{
    apr_status_t rv;
    apr_dbd_prepared_t *stmt;
    const char *errmsg;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;
    char *ret = NULL;
    int n = 0;
    ap_dbd_t *db = dbd_acquire(r);
    
    if (db == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02963)
                      "rewritemap: No db handle available! "
                      "Check your database access");
        return NULL;
   }

    stmt = apr_hash_get(db->prepared, label, APR_HASH_KEY_STRING);

    rv = apr_dbd_pvselect(db->driver, r->pool, db->handle, &res,
                          stmt, 0, key, NULL);
    if (rv != 0) {
        errmsg = apr_dbd_error(db->driver, db->handle, rv);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00657)
                      "rewritemap: error %s querying for %s", errmsg, key);
        return NULL;
    }
    while ((rv = apr_dbd_get_row(db->driver, r->pool, res, &row, -1)) == 0) {
        ++n;
        if (ret == NULL) {
            ret = apr_pstrdup(r->pool,
                              apr_dbd_get_entry(db->driver, row, 0));
        }
        else {
            /* randomise crudely amongst multiple results */
            if ((double)rand() < (double)RAND_MAX/(double)n) {
                ret = apr_pstrdup(r->pool,
                                  apr_dbd_get_entry(db->driver, row, 0));
            }
        }
    }
    if (rv != -1) {
        errmsg = apr_dbd_error(db->driver, db->handle, rv);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00658)
                      "rewritemap: error %s looking up %s", errmsg, key);
    }
    switch (n) {
    case 0:
        return NULL;
    case 1:
        return ret;
    default:
        /* what's a fair rewritelog level for this? */
        rewritelog((r, 3, NULL, "Multiple values found for %s", key));
        return ret;
    }
}

static char *lookup_map_program(request_rec *r, apr_file_t *fpin,
                                apr_file_t *fpout, char *key)
{
    char *buf;
    char c;
    apr_size_t i, nbytes, combined_len = 0;
    apr_status_t rv;
    const char *eol = APR_EOL_STR;
    apr_size_t eolc = 0;
    int found_nl = 0;
    result_list *buflist = NULL, *curbuf = NULL;

#ifndef NO_WRITEV
    struct iovec iova[2];
    apr_size_t niov;
#endif

    /* when `RewriteEngine off' was used in the per-server
     * context then the rewritemap-programs were not spawned.
     * In this case using such a map (usually in per-dir context)
     * is useless because it is not available.
     *
     * newlines in the key leave bytes in the pipe and cause
     * bad things to happen (next map lookup will use the chars
     * after the \n instead of the new key etc etc - in other words,
     * the Rewritemap falls out of sync with the requests).
     */
    if (fpin == NULL || fpout == NULL || ap_strchr(key, '\n')) {
        return NULL;
    }

    /* take the lock */
    if (rewrite_mapr_lock_acquire) {
        rv = apr_global_mutex_lock(rewrite_mapr_lock_acquire);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00659)
                          "apr_global_mutex_lock(rewrite_mapr_lock_acquire) "
                          "failed");
            return NULL; /* Maybe this should be fatal? */
        }
    }

    /* write out the request key */
#ifdef NO_WRITEV
    nbytes = strlen(key);
    /* XXX: error handling */
    apr_file_write_full(fpin, key, nbytes, NULL);
    nbytes = 1;
    apr_file_write_full(fpin, "\n", nbytes, NULL);
#else
    iova[0].iov_base = key;
    iova[0].iov_len = strlen(key);
    iova[1].iov_base = "\n";
    iova[1].iov_len = 1;

    niov = 2;
    /* XXX: error handling */
    apr_file_writev_full(fpin, iova, niov, &nbytes);
#endif

    buf = apr_palloc(r->pool, REWRITE_PRG_MAP_BUF + 1);

    /* read in the response value */
    nbytes = 1;
    apr_file_read(fpout, &c, &nbytes);
    do {
        i = 0;
        while (nbytes == 1 && (i < REWRITE_PRG_MAP_BUF)) {
            if (c == eol[eolc]) {
                if (!eol[++eolc]) {
                    /* remove eol from the buffer */
                    --eolc;
                    if (i < eolc) {
                        curbuf->len -= eolc-i;
                        i = 0;
                    }
                    else {
                        i -= eolc;
                    }
                    ++found_nl;
                    break;
                }
            }

            /* only partial (invalid) eol sequence -> reset the counter */
            else if (eolc) {
                eolc = 0;
            }

            /* catch binary mode, e.g. on Win32 */
            else if (c == '\n') {
                ++found_nl;
                break;
            }

            buf[i++] = c;
            apr_file_read(fpout, &c, &nbytes);
        }

        /* well, if there wasn't a newline yet, we need to read further */
        if (buflist || (nbytes == 1 && !found_nl)) {
            if (!buflist) {
                curbuf = buflist = apr_palloc(r->pool, sizeof(*buflist));
            }
            else if (i) {
                curbuf->next = apr_palloc(r->pool, sizeof(*buflist));
                curbuf = curbuf->next;

            }
            curbuf->next = NULL;

            if (i) {
                curbuf->string = buf;
                curbuf->len = i;
                combined_len += i;
                buf = apr_palloc(r->pool, REWRITE_PRG_MAP_BUF);
            }

            if (nbytes == 1 && !found_nl) {
                continue;
            }
        }

        break;
    } while (1);

    /* concat the stuff */
    if (buflist) {
        char *p;

        p = buf = apr_palloc(r->pool, combined_len + 1); /* \0 */
        while (buflist) {
            if (buflist->len) {
                memcpy(p, buflist->string, buflist->len);
                p += buflist->len;
            }
            buflist = buflist->next;
        }
        *p = '\0';
        i = combined_len;
    }
    else {
        buf[i] = '\0';
    }

    /* give the lock back */
    if (rewrite_mapr_lock_acquire) {
        rv = apr_global_mutex_unlock(rewrite_mapr_lock_acquire);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00660)
                          "apr_global_mutex_unlock(rewrite_mapr_lock_acquire) "
                          "failed");
            return NULL; /* Maybe this should be fatal? */
        }
    }

    /* catch the "failed" case */
    if (i == 4 && !strcasecmp(buf, "NULL")) {
        return NULL;
    }

    return buf;
}

/*
 * generic map lookup
 */
static char *lookup_map(request_rec *r, char *name, char *key)
{
    rewrite_server_conf *conf;
    rewritemap_entry *s;
    char *value;
    apr_finfo_t st;
    apr_status_t rv;

    /* get map configuration */
    conf = ap_get_module_config(r->server->module_config, &rewrite_module);
    s = apr_hash_get(conf->rewritemaps, name, APR_HASH_KEY_STRING);

    /* map doesn't exist */
    if (!s) {
        return NULL;
    }

    switch (s->type) {
    /*
     * Text file map (perhaps random)
     */
    case MAPTYPE_RND:
    case MAPTYPE_TXT:
        rv = apr_stat(&st, s->checkfile, APR_FINFO_MIN, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00661)
                          "mod_rewrite: can't access text RewriteMap file %s",
                          s->checkfile);
            return NULL;
        }

        value = get_cache_value(s->cachename, st.mtime, key, r->pool);
        if (!value) {
            rewritelog((r, 6, NULL,
                        "cache lookup FAILED, forcing new map lookup"));

            value = lookup_map_txtfile(r, s->datafile, key);
            if (!value) {
                rewritelog((r, 5, NULL, "map lookup FAILED: map=%s[txt] key=%s",
                            name, key));
                set_cache_value(s->cachename, st.mtime, key, "");
                return NULL;
            }

            rewritelog((r, 5, NULL,"map lookup OK: map=%s[txt] key=%s -> val=%s",
                        name, key, value));
            set_cache_value(s->cachename, st.mtime, key, value);
        }
        else {
            rewritelog((r,5,NULL,"cache lookup OK: map=%s[txt] key=%s -> val=%s",
                        name, key, value));
        }

        if (s->type == MAPTYPE_RND && *value) {
            value = select_random_value_part(r, value);
            rewritelog((r, 5, NULL, "randomly chosen the subvalue `%s'",value));
        }

        return *value ? value : NULL;

    /*
     * DBM file map
     */
    case MAPTYPE_DBM:
        rv = apr_stat(&st, s->checkfile, APR_FINFO_MIN, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00662)
                          "mod_rewrite: can't access DBM RewriteMap file %s",
                          s->checkfile);
        }
        else if(s->checkfile2 != NULL) {
            apr_finfo_t st2;

            rv = apr_stat(&st2, s->checkfile2, APR_FINFO_MIN, r->pool);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00663)
                              "mod_rewrite: can't access DBM RewriteMap "
                              "file %s", s->checkfile2);
            }
            else if(st2.mtime > st.mtime) {
                st.mtime = st2.mtime;
            }
        }
        if(rv != APR_SUCCESS) {
            return NULL;
        }

        value = get_cache_value(s->cachename, st.mtime, key, r->pool);
        if (!value) {
            rewritelog((r, 6, NULL,
                        "cache lookup FAILED, forcing new map lookup"));

            value = lookup_map_dbmfile(r, s->datafile, s->dbmtype, key);
            if (!value) {
                rewritelog((r, 5, NULL, "map lookup FAILED: map=%s[dbm] key=%s",
                            name, key));
                set_cache_value(s->cachename, st.mtime, key, "");
                return NULL;
            }

            rewritelog((r, 5, NULL, "map lookup OK: map=%s[dbm] key=%s -> "
                        "val=%s", name, key, value));

            set_cache_value(s->cachename, st.mtime, key, value);
            return value;
        }

        rewritelog((r, 5, NULL, "cache lookup OK: map=%s[dbm] key=%s -> val=%s",
                    name, key, value));
        return *value ? value : NULL;

    /*
     * SQL map without cache
     */
    case MAPTYPE_DBD:
        value = lookup_map_dbd(r, key, s->dbdq);
        if (!value) {
            rewritelog((r, 5, NULL, "SQL map lookup FAILED: map %s key=%s",
                        name, key));
            return NULL;
        }

        rewritelog((r, 5, NULL, "SQL map lookup OK: map %s key=%s, val=%s",
                   name, key, value));

        return value;

    /*
     * SQL map with cache
     */
    case MAPTYPE_DBD_CACHE:
        value = get_cache_value(s->cachename, 0, key, r->pool);
        if (!value) {
            rewritelog((r, 6, NULL,
                        "cache lookup FAILED, forcing new map lookup"));

            value = lookup_map_dbd(r, key, s->dbdq);
            if (!value) {
                rewritelog((r, 5, NULL, "SQL map lookup FAILED: map %s key=%s",
                            name, key));
                set_cache_value(s->cachename, 0, key, "");
                return NULL;
            }

            rewritelog((r, 5, NULL, "SQL map lookup OK: map %s key=%s, val=%s",
                        name, key, value));

            set_cache_value(s->cachename, 0, key, value);
            return value;
        }

        rewritelog((r, 5, NULL, "cache lookup OK: map=%s[SQL] key=%s, val=%s",
                    name, key, value));
        return *value ? value : NULL;

    /*
     * Program file map
     */
    case MAPTYPE_PRG:
        value = lookup_map_program(r, s->fpin, s->fpout, key);
        if (!value) {
            rewritelog((r, 5,NULL,"map lookup FAILED: map=%s key=%s", name,
                        key));
            return NULL;
        }

        rewritelog((r, 5, NULL, "map lookup OK: map=%s key=%s -> val=%s",
                    name, key, value));
        return value;

    /*
     * Internal Map
     */
    case MAPTYPE_INT:
        value = s->func(r, key);
        if (!value) {
            rewritelog((r, 5,NULL,"map lookup FAILED: map=%s key=%s", name,
                        key));
            return NULL;
        }

        rewritelog((r, 5, NULL, "map lookup OK: map=%s key=%s -> val=%s",
                    name, key, value));
        return value;
    }

    return NULL;
}

/*
 * lookup a HTTP header and set VARY note
 */
static const char *lookup_header(const char *name, rewrite_ctx *ctx)
{
    const char *val = apr_table_get(ctx->r->headers_in, name);

    /* Skip the 'Vary: Host' header combination
     * as indicated in rfc7231 section-7.1.4
     */
    if (val && strcasecmp(name, "Host") != 0) {
        ctx->vary_this = ctx->vary_this
                         ? apr_pstrcat(ctx->r->pool, ctx->vary_this, ", ",
                                       name, NULL)
                         : apr_pstrdup(ctx->r->pool, name);
    }

    return val;
}

/*
 * lookahead helper function
 * Determine the correct URI path in perdir context
 */
static APR_INLINE const char *la_u(rewrite_ctx *ctx)
{
    rewrite_perdir_conf *conf;

    if (*ctx->uri == '/') {
        return ctx->uri;
    }

    conf = ap_get_module_config(ctx->r->per_dir_config, &rewrite_module);

    return apr_pstrcat(ctx->r->pool, conf->baseurl
                                     ? conf->baseurl : conf->directory,
                       ctx->uri, NULL);
}

/*
 * generic variable lookup
 */
static char *lookup_variable(char *var, rewrite_ctx *ctx)
{
    const char *result;
    request_rec *r = ctx->r;
    apr_size_t varlen = strlen(var);

    /* fast exit */
    if (varlen < 4) {
        return "";
    }

    result = NULL;

    /* fast tests for variable length variables (sic) first */
    if (var[3] == ':') {
        if (var[4] && !strncasecmp(var, "ENV", 3)) {
            var += 4;
            result = apr_table_get(r->notes, var);

            if (!result) {
                result = apr_table_get(r->subprocess_env, var);
            }
            if (!result) {
                result = getenv(var);
            }
        }
        else if (var[4] && !strncasecmp(var, "SSL", 3)) {
            result = ap_ssl_var_lookup(r->pool, r->server, r->connection, r,
                                        var + 4);
        }
    }
    else if (var[4] == ':') {
        if (var[5]) {
            request_rec *rr;
            const char *path;

            if (!strncasecmp(var, "HTTP", 4)) {
                result = lookup_header(var+5, ctx);
            }
            else if (!strncasecmp(var, "LA-U", 4)) {
                if (ctx->uri && subreq_ok(r)) {
                    path = ctx->perdir ? la_u(ctx) : ctx->uri;
                    rr = ap_sub_req_lookup_uri(path, r, NULL);
                    ctx->r = rr;
                    result = apr_pstrdup(r->pool, lookup_variable(var+5, ctx));
                    ctx->r = r;
                    ap_destroy_sub_req(rr);

                    rewritelog((r, 5, ctx->perdir, "lookahead: path=%s var=%s "
                                "-> val=%s", path, var+5, result));

                    return (char *)result;
                }
            }
            else if (!strncasecmp(var, "LA-F", 4)) {
                if (ctx->uri && subreq_ok(r)) {
                    path = ctx->uri;
                    if (ctx->perdir && *path == '/') {
                        /* sigh, the user wants a file based subrequest, but
                         * we can't do one, since we don't know what the file
                         * path is! In this case behave like LA-U.
                         */
                        rr = ap_sub_req_lookup_uri(path, r, NULL);
                    }
                    else {
                        if (ctx->perdir) {
                            rewrite_perdir_conf *conf;

                            conf = ap_get_module_config(r->per_dir_config,
                                                        &rewrite_module);

                            path = apr_pstrcat(r->pool, conf->directory, path,
                                               NULL);
                        }

                        rr = ap_sub_req_lookup_file(path, r, NULL);
                    }

                    ctx->r = rr;
                    result = apr_pstrdup(r->pool, lookup_variable(var+5, ctx));
                    ctx->r = r;
                    ap_destroy_sub_req(rr);

                    rewritelog((r, 5, ctx->perdir, "lookahead: path=%s var=%s "
                                "-> val=%s", path, var+5, result));

                    return (char *)result;
                }
            }
        }
    }

    /* well, do it the hard way */
    else {
        apr_time_exp_t tm;

        /* can't do this above, because of the getenv call */
        ap_str_toupper(var);

        switch (varlen) {
        case  4:
            if (!strcmp(var, "TIME")) {
                apr_time_exp_lt(&tm, apr_time_now());
                result = apr_psprintf(r->pool, "%04d%02d%02d%02d%02d%02d",
                                      tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
                                      tm.tm_hour, tm.tm_min, tm.tm_sec);
                rewritelog((r, 1, ctx->perdir, "RESULT='%s'", result));
                return (char *)result;
            }
            else if (!strcmp(var, "IPV6")) {
                int flag = FALSE;
#if APR_HAVE_IPV6
                apr_sockaddr_t *addr = r->useragent_addr;
                flag = (addr->family == AF_INET6 &&
                        !IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addr->ipaddr_ptr));
                rewritelog((r, 1, ctx->perdir, "IPV6='%s'", flag ? "on" : "off"));
#else
                rewritelog((r, 1, ctx->perdir, "IPV6='off' (IPv6 is not enabled)"));
#endif
                result = (flag ? "on" : "off");
            }
            break;

        case  5:
            if (!strcmp(var, "HTTPS")) {
                int flag = ap_ssl_conn_is_ssl(r->connection);
                return apr_pstrdup(r->pool, flag ? "on" : "off");
            }
            break;

        case  8:
            switch (var[6]) {
            case 'A':
                if (!strcmp(var, "TIME_DAY")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_mday);
                }
                break;

            case 'E':
                if (!strcmp(var, "TIME_SEC")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_sec);
                }
                break;

            case 'I':
                if (!strcmp(var, "TIME_MIN")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_min);
                }
                break;

            case 'O':
                if (!strcmp(var, "TIME_MON")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_mon+1);
                }
                break;
            }
            break;

        case  9:
            switch (var[7]) {
            case 'A':
                if (var[8] == 'Y' && !strcmp(var, "TIME_WDAY")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%d", tm.tm_wday);
                }
                else if (!strcmp(var, "TIME_YEAR")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%04d", tm.tm_year+1900);
                }
                break;

            case 'E':
                if (!strcmp(var, "IS_SUBREQ")) {
                    result = (r->main ? "true" : "false");
                }
                break;

            case 'F':
                if (!strcmp(var, "PATH_INFO")) {
                    result = r->path_info;
                }
                break;

            case 'P':
                if (!strcmp(var, "AUTH_TYPE")) {
                    result = r->ap_auth_type;
                }
                break;

            case 'S':
                if (!strcmp(var, "HTTP_HOST")) {
                    result = lookup_header("Host", ctx);
                }
                break;

            case 'U':
                if (!strcmp(var, "TIME_HOUR")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_hour);
                }
                break;
            }
            break;

        case 11:
            switch (var[8]) {
            case 'A':
                if (!strcmp(var, "SERVER_NAME")) {
                    result = ap_get_server_name_for_url(r);
                }
                break;

            case 'D':
                if (*var == 'R' && !strcmp(var, "REMOTE_ADDR")) {
                    result = r->useragent_ip;
                }
                else if (!strcmp(var, "SERVER_ADDR")) {
                    result = r->connection->local_ip;
                }
                break;

            case 'E':
                if (*var == 'H' && !strcmp(var, "HTTP_ACCEPT")) {
                    result = lookup_header("Accept", ctx);
                }
                else if (!strcmp(var, "THE_REQUEST")) {
                    result = r->the_request;
                }
                break;

            case 'I':
                if (!strcmp(var, "API_VERSION")) {
                    return apr_psprintf(r->pool, "%d:%d",
                                        MODULE_MAGIC_NUMBER_MAJOR,
                                        MODULE_MAGIC_NUMBER_MINOR);
                }
                break;

            case 'K':
                if (!strcmp(var, "HTTP_COOKIE")) {
                    result = lookup_header("Cookie", ctx);
                }
                break;

            case 'O':
                if (*var == 'S' && !strcmp(var, "SERVER_PORT")) {
                    return apr_psprintf(r->pool, "%u", ap_get_server_port(r));
                }
                else if (var[7] == 'H' && !strcmp(var, "REMOTE_HOST")) {
                    result = ap_get_remote_host(r->connection,r->per_dir_config,
                                                REMOTE_NAME, NULL);
                }
                else if (!strcmp(var, "REMOTE_PORT")) {
                    return apr_itoa(r->pool, r->useragent_addr->port);
                }
                break;

            case 'S':
                if (*var == 'R' && !strcmp(var, "REMOTE_USER")) {
                    result = r->user;
                }
                else if (!strcmp(var, "SCRIPT_USER")) {
                    result = "<unknown>";
                    if (r->finfo.valid & APR_FINFO_USER) {
                        apr_uid_name_get((char **)&result, r->finfo.user,
                                         r->pool);
                    }
                }
                break;

            case 'U':
                if (!strcmp(var, "REQUEST_URI")) {
                    result = r->uri;
                }
                break;
            }
            break;

        case 12:
            switch (var[3]) {
            case 'I':
                if (!strcmp(var, "SCRIPT_GROUP")) {
                    result = "<unknown>";
                    if (r->finfo.valid & APR_FINFO_GROUP) {
                        apr_gid_name_get((char **)&result, r->finfo.group,
                                         r->pool);
                    }
                }
                break;

            case 'O':
                if (!strcmp(var, "REMOTE_IDENT")) {
                    result = ap_get_remote_logname(r);
                }
                break;

            case 'P':
                if (!strcmp(var, "HTTP_REFERER")) {
                    result = lookup_header("Referer", ctx);
                }
                break;

            case 'R':
                if (!strcmp(var, "QUERY_STRING")) {
                    result = r->args;
                }
                break;

            case 'V':
                if (!strcmp(var, "SERVER_ADMIN")) {
                    result = r->server->server_admin;
                }
                break;
            }
            break;

        case 13:
            if (!strcmp(var, "DOCUMENT_ROOT")) {
                result = ap_document_root(r);
            }
            break;

        case 14:
            if (*var == 'H' && !strcmp(var, "HTTP_FORWARDED")) {
                result = lookup_header("Forwarded", ctx);
            }
            else if (*var == 'C' && !strcmp(var, "CONTEXT_PREFIX")) {
                result = ap_context_prefix(r);
            }
            else if (var[8] == 'M' && !strcmp(var, "REQUEST_METHOD")) {
                result = r->method;
            }
            else if (!strcmp(var, "REQUEST_SCHEME")) {
                result = ap_http_scheme(r);
            }
            break;

        case 15:
            switch (var[7]) {
            case 'E':
                if (!strcmp(var, "HTTP_USER_AGENT")) {
                    result = lookup_header("User-Agent", ctx);
                }
                break;

            case 'F':
                if (!strcmp(var, "SCRIPT_FILENAME")) {
                    result = r->filename; /* same as request_filename (16) */
                }
                break;

            case 'P':
                if (!strcmp(var, "SERVER_PROTOCOL")) {
                    result = r->protocol;
                }
                break;

            case 'S':
                if (!strcmp(var, "SERVER_SOFTWARE")) {
                    result = ap_get_server_banner();
                }
                break;
            }
            break;

        case 16:
            if (*var == 'C' && !strcmp(var, "CONN_REMOTE_ADDR")) {
                result = r->connection->client_ip;
            }
            else if (!strcmp(var, "REQUEST_FILENAME")) {
                result = r->filename; /* same as script_filename (15) */
            }
            break;

        case 21:
            if (!strcmp(var, "HTTP_PROXY_CONNECTION")) {
                result = lookup_header("Proxy-Connection", ctx);
            }
            else if (!strcmp(var, "CONTEXT_DOCUMENT_ROOT")) {
                result = ap_context_document_root(r);
            }
            break;
        }
    }

    return apr_pstrdup(r->pool, result ? result : "");
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                 Expansion functions
 * |                                                       |
 * +-------------------------------------------------------+
 */

/*
 * Bracketed expression handling
 * s points after the opening bracket
 */
static APR_INLINE char *find_closing_curly(char *s)
{
    unsigned depth;

    for (depth = 1; *s; ++s) {
        if (*s == RIGHT_CURLY && --depth == 0) {
            return s;
        }
        else if (*s == LEFT_CURLY) {
            ++depth;
        }
    }

    return NULL;
}

static APR_INLINE char *find_char_in_curlies(char *s, int c)
{
    unsigned depth;

    for (depth = 1; *s; ++s) {
        if (*s == c && depth == 1) {
            return s;
        }
        else if (*s == RIGHT_CURLY && --depth == 0) {
            return NULL;
        }
        else if (*s == LEFT_CURLY) {
            ++depth;
        }
    }

    return NULL;
}

/* perform all the expansions on the input string
 * putting the result into a new string
 *
 * for security reasons this expansion must be performed in a
 * single pass, otherwise an attacker can arrange for the result
 * of an earlier expansion to include expansion specifiers that
 * are interpreted by a later expansion, producing results that
 * were not intended by the administrator.
 */
static char *do_expand(char *input, rewrite_ctx *ctx, rewriterule_entry *entry)
{
    result_list *result, *current;
    result_list sresult[SMALL_EXPANSION];
    unsigned spc = 0;
    apr_size_t span, inputlen, outlen;
    char *p, *c;
    apr_pool_t *pool = ctx->r->pool;

    span = strcspn(input, "\\$%");
    inputlen = strlen(input);

    /* fast exit */
    if (inputlen == span) {
        return apr_pstrmemdup(pool, input, inputlen);
    }

    /* well, actually something to do */
    result = current = &(sresult[spc++]);

    p = input + span;
    current->next = NULL;
    current->string = input;
    current->len = span;
    outlen = span;

    /* loop for specials */
    do {
        /* prepare next entry */
        if (current->len) {
            current->next = (spc < SMALL_EXPANSION)
                            ? &(sresult[spc++])
                            : (result_list *)apr_palloc(pool,
                                                        sizeof(result_list));
            current = current->next;
            current->next = NULL;
            current->len = 0;
        }

        /* escaped character */
        if (*p == '\\') {
            current->len = 1;
            ++outlen;
            if (!p[1]) {
                current->string = p;
                break;
            }
            else {
                current->string = ++p;
                ++p;
            }
        }

        /* variable or map lookup */
        else if (p[1] == '{') {
            char *endp;

            endp = find_closing_curly(p+2);
            if (!endp) {
                current->len = 2;
                current->string = p;
                outlen += 2;
                p += 2;
            }

            /* variable lookup */
            else if (*p == '%') {
                p = lookup_variable(apr_pstrmemdup(pool, p+2, endp-p-2), ctx);

                span = strlen(p);
                current->len = span;
                current->string = p;
                outlen += span;
                p = endp + 1;
            }

            /* map lookup */
            else {     /* *p == '$' */
                char *key;

                /*
                 * To make rewrite maps useful, the lookup key and
                 * default values must be expanded, so we make
                 * recursive calls to do the work. For security
                 * reasons we must never expand a string that includes
                 * verbatim data from the network. The recursion here
                 * isn't a problem because the result of expansion is
                 * only passed to lookup_map() so it cannot be
                 * re-expanded, only re-looked-up. Another way of
                 * looking at it is that the recursion is entirely
                 * driven by the syntax of the nested curly brackets.
                 */

                key = find_char_in_curlies(p+2, ':');
                if (!key) {
                    current->len = 2;
                    current->string = p;
                    outlen += 2;
                    p += 2;
                }
                else {
                    char *map, *dflt;

                    map = apr_pstrmemdup(pool, p+2, endp-p-2);
                    key = map + (key-p-2);
                    *key++ = '\0';
                    dflt = find_char_in_curlies(key, '|');
                    if (dflt) {
                        *dflt++ = '\0';
                    }

                    /* reuse of key variable as result */
                    key = lookup_map(ctx->r, map, do_expand(key, ctx, entry));

                    if (!key && dflt && *dflt) {
                        key = do_expand(dflt, ctx, entry);
                    }

                    if (key) {
                        span = strlen(key);
                        current->len = span;
                        current->string = key;
                        outlen += span;
                    }

                    p = endp + 1;
                }
            }
        }

        /* backreference */
        else if (apr_isdigit(p[1])) {
            int n = p[1] - '0';
            backrefinfo *bri = (*p == '$') ? &ctx->briRR : &ctx->briRC;

            /* see ap_pregsub() in server/util.c */
            if (bri->source && n < AP_MAX_REG_MATCH
                && bri->regmatch[n].rm_eo > bri->regmatch[n].rm_so) {
                span = bri->regmatch[n].rm_eo - bri->regmatch[n].rm_so;
                if (entry && (entry->flags & RULEFLAG_ESCAPEBACKREF)) {
                    /* escape the backreference */
                    char *tmp2, *tmp;
                    tmp = apr_pstrmemdup(pool, bri->source + bri->regmatch[n].rm_so, span);
                    tmp2 = escape_backref(pool, tmp, entry->escapes, entry->noescapes,
                                          entry->flags);
                    rewritelog((ctx->r, 5, ctx->perdir, "escaping backreference '%s' to '%s'",
                            tmp, tmp2));

                    current->len = span = strlen(tmp2);
                    current->string = tmp2;
                } else {
                    current->len = span;
                    current->string = bri->source + bri->regmatch[n].rm_so;
                }

                outlen += span;
            }

            p += 2;
        }

        /* not for us, just copy it */
        else {
            current->len = 1;
            current->string = p++;
            ++outlen;
        }

        /* check the remainder */
        if (*p && (span = strcspn(p, "\\$%")) > 0) {
            if (current->len) {
                current->next = (spc < SMALL_EXPANSION)
                                ? &(sresult[spc++])
                                : (result_list *)apr_palloc(pool,
                                                           sizeof(result_list));
                current = current->next;
                current->next = NULL;
            }

            current->len = span;
            current->string = p;
            p += span;
            outlen += span;
        }

    } while (p < input+inputlen);

    /* assemble result */
    c = p = apr_palloc(pool, outlen + 1); /* don't forget the \0 */
    do {
        if (result->len) {
            ap_assert(c+result->len <= p+outlen); /* XXX: can be removed after
                                                   * extensive testing and
                                                   * review
                                                   */
            memcpy(c, result->string, result->len);
            c += result->len;
        }
        result = result->next;
    } while (result);

    p[outlen] = '\0';

    return p;
}

/*
 * perform all the expansions on the environment variables
 */
static void do_expand_env(data_item *env, rewrite_ctx *ctx)
{
    char *name, *val;

    while (env) {
        name = do_expand(env->data, ctx, NULL);
        if (*name == '!') {
            name++;
            apr_table_unset(ctx->r->subprocess_env, name);
            rewritelog((ctx->r, 5, NULL, "unsetting env variable '%s'", name));
        }
        else {
            if ((val = ap_strchr(name, ':')) != NULL) {
                *val++ = '\0';
            } else {
                val = "";
            }

            apr_table_set(ctx->r->subprocess_env, name, val);
            rewritelog((ctx->r, 5, NULL, "setting env variable '%s' to '%s'",
                        name, val));
        }

        env = env->next;
    }

    return;
}

/*
 * perform all the expansions on the cookies
 *
 * TODO: use cached time similar to how logging does it
 */
static void add_cookie(request_rec *r, char *s)
{
    char *var;
    char *val;
    char *domain;
    char *expires;
    char *path;
    char *secure;
    char *httponly;
    char *samesite;

    char *tok_cntx;
    char *cookie;
    /* long-standing default, but can't use ':' in a cookie */
    const char *sep = ":"; 

    /* opt-in to ; separator if first character is a ; */
    if (s && *s == ';') { 
        sep = ";"; 
        s++;
    }

    var = apr_strtok(s, sep, &tok_cntx);
    val = apr_strtok(NULL, sep, &tok_cntx);
    domain = apr_strtok(NULL, sep, &tok_cntx);

    if (var && val && domain) {
        request_rec *rmain = r;
        char *notename;
        void *data;

        while (rmain->main) {
            rmain = rmain->main;
        }

        notename = apr_pstrcat(rmain->pool, var, "_rewrite", NULL);
        apr_pool_userdata_get(&data, notename, rmain->pool);
        if (!data) {
            char *exp_time = NULL;

            expires = apr_strtok(NULL, sep, &tok_cntx);
            path = expires ? apr_strtok(NULL, sep, &tok_cntx) : NULL;
            secure = path ? apr_strtok(NULL, sep, &tok_cntx) : NULL;
            httponly = secure ? apr_strtok(NULL, sep, &tok_cntx) : NULL;
            samesite = httponly ? apr_strtok(NULL, sep, &tok_cntx) : NULL;

            if (expires) {
                apr_time_exp_t tms;
                long exp_min;

                exp_min = atol(expires);
                if (exp_min) {
                    apr_time_exp_gmt(&tms, r->request_time
                                     + apr_time_from_sec((60 * exp_min)));
                    exp_time = apr_psprintf(r->pool, "%s, %.2d-%s-%.4d "
                                                     "%.2d:%.2d:%.2d GMT",
                                           apr_day_snames[tms.tm_wday],
                                           tms.tm_mday,
                                           apr_month_snames[tms.tm_mon],
                                           tms.tm_year+1900,
                                           tms.tm_hour, tms.tm_min, tms.tm_sec);
                }
            }

            cookie = apr_pstrcat(rmain->pool,
                                 var, "=", val,
                                 "; path=", path ? path : "/",
                                 "; domain=", domain,
                                 expires ? (exp_time ? "; expires=" : "")
                                 : NULL,
                                 expires ? (exp_time ? exp_time : "")
                                 : NULL,
                                 (secure && (!ap_cstr_casecmp(secure, "true")
                                             || !strcmp(secure, "1")
                                             || !ap_cstr_casecmp(secure,
                                                            "secure"))) ?
                                  "; secure" : NULL,
                                 (httponly && (!ap_cstr_casecmp(httponly, "true")
                                               || !strcmp(httponly, "1")
                                               || !ap_cstr_casecmp(httponly,
                                                              "HttpOnly"))) ?
                                  "; HttpOnly" : NULL,
                                 NULL);

            if (samesite && strcmp(samesite, "0") && ap_cstr_casecmp(samesite,"false")) { 
                cookie = apr_pstrcat(rmain->pool, cookie, "; SameSite=", 
                                     samesite, NULL);
            }

            apr_table_addn(rmain->err_headers_out, "Set-Cookie", cookie);
            apr_pool_userdata_set("set", notename, NULL, rmain->pool);
            rewritelog((rmain, 5, NULL, "setting cookie '%s'", cookie));
        }
        else {
            rewritelog((rmain, 5, NULL, "skipping already set cookie '%s'",
                        var));
        }
    }

    return;
}

static void do_expand_cookie(data_item *cookie, rewrite_ctx *ctx)
{
    while (cookie) {
        add_cookie(ctx->r, do_expand(cookie->data, ctx, NULL));
        cookie = cookie->next;
    }

    return;
}

#if APR_HAS_USER
/*
 * Expand tilde-paths (/~user) through Unix /etc/passwd
 * database information (or other OS-specific database)
 */
static char *expand_tildepaths(request_rec *r, char *uri)
{
    if (uri && *uri == '/' && uri[1] == '~') {
        char *p, *user;

        p = user = uri + 2;
        while (*p && *p != '/') {
            ++p;
        }

        if (p > user) {
            char *homedir;

            user = apr_pstrmemdup(r->pool, user, p-user);
            if (apr_uid_homepath_get(&homedir, user, r->pool) == APR_SUCCESS) {
                if (*p) {
                    /* reuse of user variable */
                    user = homedir + strlen(homedir) - 1;
                    if (user >= homedir && *user == '/') {
                        *user = '\0';
                    }

                    return apr_pstrcat(r->pool, homedir, p, NULL);
                }
                else {
                    return homedir;
                }
            }
        }
    }

    return uri;
}
#endif  /* if APR_HAS_USER */


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |              rewriting lockfile support
 * |                                                       |
 * +-------------------------------------------------------+
 */

static apr_status_t rewritelock_create(server_rec *s, apr_pool_t *p)
{
    apr_status_t rc;

    /* create the lockfile */
    rc = ap_global_mutex_create(&rewrite_mapr_lock_acquire, NULL,
                                rewritemap_mutex_type, NULL, s, p, 0);
    if (rc != APR_SUCCESS) {
        return rc;
    }

    return APR_SUCCESS;
}

static apr_status_t rewritelock_remove(void *data)
{
    /* destroy the rewritelock */
    if (rewrite_mapr_lock_acquire) {
        apr_global_mutex_destroy(rewrite_mapr_lock_acquire);
        rewrite_mapr_lock_acquire = NULL;
    }
    return APR_SUCCESS;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |           configuration directive handling
 * |                                                       |
 * +-------------------------------------------------------+
 */

/*
 * own command line parser for RewriteRule and RewriteCond,
 * which doesn't have the '\\' problem.
 * (returns true on error)
 *
 * XXX: what an inclined parser. Seems we have to leave it so
 *      for backwards compat. *sigh*
 */
static int parseargline(char *str, char **a1, char **a2, char **a2_end, char **a3)
{
    char quote;

    while (apr_isspace(*str)) {
        ++str;
    }

    /*
     * determine first argument
     */
    quote = (*str == '"' || *str == '\'') ? *str++ : '\0';
    *a1 = str;

    for (; *str; ++str) {
        if ((apr_isspace(*str) && !quote) || (*str == quote)) {
            break;
        }
        if (*str == '\\' && apr_isspace(str[1])) {
            ++str;
            continue;
        }
    }

    if (!*str) {
        return 1;
    }
    *str++ = '\0';

    while (apr_isspace(*str)) {
        ++str;
    }

    /*
     * determine second argument
     */
    quote = (*str == '"' || *str == '\'') ? *str++ : '\0';
    *a2 = str;

    for (; *str; ++str) {
        if ((apr_isspace(*str) && !quote) || (*str == quote)) {
            break;
        }
        if (*str == '\\' && apr_isspace(str[1])) {
            ++str;
            continue;
        }
    }

    if (!*str) {
        *a3 = NULL; /* 3rd argument is optional */
        *a2_end = str;
        return 0;
    }
    *a2_end = str;
    *str++ = '\0';

    while (apr_isspace(*str)) {
        ++str;
    }

    if (!*str) {
        *a3 = NULL; /* 3rd argument is still optional */
        return 0;
    }

    /*
     * determine third argument
     */
    quote = (*str == '"' || *str == '\'') ? *str++ : '\0';
    *a3 = str;
    for (; *str; ++str) {
        if ((apr_isspace(*str) && !quote) || (*str == quote)) {
            break;
        }
        if (*str == '\\' && apr_isspace(str[1])) {
            ++str;
            continue;
        }
    }
    *str = '\0';

    return 0;
}

static void *config_server_create(apr_pool_t *p, server_rec *s)
{
    rewrite_server_conf *a;

    a = (rewrite_server_conf *)apr_pcalloc(p, sizeof(rewrite_server_conf));

    a->state           = ENGINE_DISABLED;
    a->options         = OPTION_NONE;
    a->rewritemaps     = apr_hash_make(p);
    a->rewriteconds    = apr_array_make(p, 2, sizeof(rewritecond_entry));
    a->rewriterules    = apr_array_make(p, 2, sizeof(rewriterule_entry));
    a->server          = s;

    return (void *)a;
}

static void *config_server_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    rewrite_server_conf *a, *base, *overrides;

    a         = (rewrite_server_conf *)apr_pcalloc(p,
                                                   sizeof(rewrite_server_conf));
    base      = (rewrite_server_conf *)basev;
    overrides = (rewrite_server_conf *)overridesv;

    a->state = (overrides->state_set == 0) ? base->state : overrides->state;
    a->state_set = overrides->state_set || base->state_set;
    a->options = (overrides->options_set == 0) ? base->options : overrides->options;
    a->options_set = overrides->options_set || base->options_set;

    a->server  = overrides->server;

    if (a->options & OPTION_INHERIT ||
            (base->options & OPTION_INHERIT_DOWN &&
             !(a->options & OPTION_IGNORE_INHERIT))) {
        /*
         *  local directives override
         *  and anything else is inherited
         */
        a->rewritemaps     = apr_hash_overlay(p, overrides->rewritemaps,
                                              base->rewritemaps);
        a->rewriteconds    = apr_array_append(p, overrides->rewriteconds,
                                              base->rewriteconds);
        a->rewriterules    = apr_array_append(p, overrides->rewriterules,
                                              base->rewriterules);
    }
    else if (a->options & OPTION_INHERIT_BEFORE || 
            (base->options & OPTION_INHERIT_DOWN_BEFORE &&
             !(a->options & OPTION_IGNORE_INHERIT))) {
        /*
         *  local directives override
         *  and anything else is inherited (preserving order)
         */
        a->rewritemaps     = apr_hash_overlay(p, base->rewritemaps,
                                              overrides->rewritemaps);
        a->rewriteconds    = apr_array_append(p, base->rewriteconds,
                                              overrides->rewriteconds);
        a->rewriterules    = apr_array_append(p, base->rewriterules,
                                              overrides->rewriterules);
    }
    else {
        /*
         *  local directives override
         *  and anything else gets defaults
         */
        a->rewritemaps     = overrides->rewritemaps;
        a->rewriteconds    = overrides->rewriteconds;
        a->rewriterules    = overrides->rewriterules;
    }

    return (void *)a;
}

static void *config_perdir_create(apr_pool_t *p, char *path)
{
    rewrite_perdir_conf *a;

    a = (rewrite_perdir_conf *)apr_pcalloc(p, sizeof(rewrite_perdir_conf));

    a->state           = ENGINE_DISABLED;
    a->options         = OPTION_NONE;
    a->baseurl         = NULL;
    a->rewriteconds    = apr_array_make(p, 2, sizeof(rewritecond_entry));
    a->rewriterules    = apr_array_make(p, 2, sizeof(rewriterule_entry));

    if (path == NULL) {
        a->directory = NULL;
    }
    else {
        /* make sure it has a trailing slash */
        if (path[strlen(path)-1] == '/') {
            a->directory = apr_pstrdup(p, path);
        }
        else {
            a->directory = apr_pstrcat(p, path, "/", NULL);
        }
    }

    return (void *)a;
}

static void *config_perdir_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    rewrite_perdir_conf *a, *base, *overrides;

    a         = (rewrite_perdir_conf *)apr_pcalloc(p,
                                                  sizeof(rewrite_perdir_conf));
    base      = (rewrite_perdir_conf *)basev;
    overrides = (rewrite_perdir_conf *)overridesv;

    a->state = (overrides->state_set == 0) ? base->state : overrides->state;
    a->state_set = overrides->state_set || base->state_set;
    a->options = (overrides->options_set == 0) ? base->options : overrides->options;
    a->options_set = overrides->options_set || base->options_set;

    if (a->options & OPTION_MERGEBASE) { 
        a->baseurl = (overrides->baseurl_set == 0) ? base->baseurl : overrides->baseurl;
        a->baseurl_set = overrides->baseurl_set || base->baseurl_set;
    }
    else { 
        a->baseurl = overrides->baseurl;
    }

    a->directory  = overrides->directory;

    if (a->options & OPTION_INHERIT ||
            (base->options & OPTION_INHERIT_DOWN &&
             !(a->options & OPTION_IGNORE_INHERIT))) {
        a->rewriteconds = apr_array_append(p, overrides->rewriteconds,
                                           base->rewriteconds);
        a->rewriterules = apr_array_append(p, overrides->rewriterules,
                                           base->rewriterules);
    }
    else if (a->options & OPTION_INHERIT_BEFORE || 
            (base->options & OPTION_INHERIT_DOWN_BEFORE &&
             !(a->options & OPTION_IGNORE_INHERIT))) {
        a->rewriteconds    = apr_array_append(p, base->rewriteconds,
                                              overrides->rewriteconds);
        a->rewriterules    = apr_array_append(p, base->rewriterules,
                                              overrides->rewriterules);
    }
    else {
        a->rewriteconds = overrides->rewriteconds;
        a->rewriterules = overrides->rewriterules;
    }

    return (void *)a;
}

static const char *cmd_rewriteengine(cmd_parms *cmd,
                                     void *in_dconf, int flag)
{
    rewrite_perdir_conf *dconf = in_dconf;
    rewrite_server_conf *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    /* server command? set both global scope and base directory scope */
    if (cmd->path == NULL) {
        sconf->state = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
        sconf->state_set = 1;
        dconf->state = sconf->state;
        dconf->state_set = 1;
    }
    /* directory command? set directory scope only */
    else {
        dconf->state = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
        dconf->state_set = 1;
    }

    return NULL;
}

static const char *cmd_rewriteoptions(cmd_parms *cmd,
                                      void *in_dconf, const char *option)
{
    int options = 0;

    while (*option) {
        char *w = ap_getword_conf(cmd->temp_pool, &option);

        if (!strcasecmp(w, "inherit")) {
            options |= OPTION_INHERIT;
        }
        else if (!strcasecmp(w, "inheritbefore")) {
            options |= OPTION_INHERIT_BEFORE;
        }
        else if (!strcasecmp(w, "inheritdown")) {
            options |= OPTION_INHERIT_DOWN;
        }
        else if(!strcasecmp(w, "inheritdownbefore")) {
            options |= OPTION_INHERIT_DOWN_BEFORE;
        }
        else if (!strcasecmp(w, "ignoreinherit")) {
            options |= OPTION_IGNORE_INHERIT;
        }
        else if (!strcasecmp(w, "allownoslash")) {
            options |= OPTION_NOSLASH;
        }
        else if (!strncasecmp(w, "MaxRedirects=", 13)) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server, APLOGNO(00664)
                         "RewriteOptions: MaxRedirects option has been "
                         "removed in favor of the global "
                         "LimitInternalRecursion directive and will be "
                         "ignored.");
        }
        else if (!strcasecmp(w, "allowanyuri")) {
            options |= OPTION_ANYURI;
        }
        else if (!strcasecmp(w, "mergebase")) {
            options |= OPTION_MERGEBASE;
        }
        else if (!strcasecmp(w, "ignorecontextinfo")) {
            options |= OPTION_IGNORE_CONTEXT_INFO;
        }
        else if (!strcasecmp(w, "legacyprefixdocroot")) {
            options |= OPTION_LEGACY_PREFIX_DOCROOT;
        }
        else {
            return apr_pstrcat(cmd->pool, "RewriteOptions: unknown option '",
                               w, "'", NULL);
        }
    }

    /* server command? set both global scope and base directory scope */
    if (cmd->path == NULL) { /* is server command */
        rewrite_perdir_conf *dconf = in_dconf;
        rewrite_server_conf *sconf =
            ap_get_module_config(cmd->server->module_config,
                                 &rewrite_module);

        sconf->options |= options;
        sconf->options_set = 1;
        dconf->options |= options;
        dconf->options_set = 1;
    }
    /* directory command? set directory scope only */
    else {                  /* is per-directory command */
        rewrite_perdir_conf *dconf = in_dconf;

        dconf->options |= options;
        dconf->options_set = 1;
    }

    return NULL;
}

static const char *cmd_rewritemap(cmd_parms *cmd, void *dconf, const char *a1,
                                  const char *a2, const char *a3)
{
    rewrite_server_conf *sconf;
    rewritemap_entry *newmap;
    apr_finfo_t st;
    const char *fname;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    newmap = apr_pcalloc(cmd->pool, sizeof(rewritemap_entry));

    if (strncasecmp(a2, "txt:", 4) == 0) {
        if ((fname = ap_server_root_relative(cmd->pool, a2+4)) == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad path to txt map: ",
                               a2+4, NULL);
        }

        newmap->type      = MAPTYPE_TXT;
        newmap->datafile  = fname;
        newmap->checkfile = fname;
        newmap->cachename = apr_psprintf(cmd->pool, "%pp:%s",
                                         (void *)cmd->server, a1);
    }
    else if (strncasecmp(a2, "rnd:", 4) == 0) {
        if ((fname = ap_server_root_relative(cmd->pool, a2+4)) == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad path to rnd map: ",
                               a2+4, NULL);
        }

        newmap->type      = MAPTYPE_RND;
        newmap->datafile  = fname;
        newmap->checkfile = fname;
        newmap->cachename = apr_psprintf(cmd->pool, "%pp:%s",
                                         (void *)cmd->server, a1);
    }
    else if (strncasecmp(a2, "dbm", 3) == 0) {
        apr_status_t rv;

        newmap->type = MAPTYPE_DBM;
        fname = NULL;
        newmap->cachename = apr_psprintf(cmd->pool, "%pp:%s",
                                         (void *)cmd->server, a1);

        if (a2[3] == ':') {
            newmap->dbmtype = "default";
            fname = a2+4;
        }
        else if (a2[3] == '=') {
            const char *colon = ap_strchr_c(a2 + 4, ':');

            if (colon) {
                newmap->dbmtype = apr_pstrndup(cmd->pool, a2 + 4,
                                               colon - (a2 + 3) - 1);
                fname = colon + 1;
            }
        }

        if (!fname) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad map:",
                               a2, NULL);
        }

        if ((newmap->datafile = ap_server_root_relative(cmd->pool,
                                                        fname)) == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad path to dbm map: ",
                               fname, NULL);
        }

        rv = apr_dbm_get_usednames_ex(cmd->pool, newmap->dbmtype,
                                      newmap->datafile, &newmap->checkfile,
                                      &newmap->checkfile2);
        if (rv != APR_SUCCESS) {
            return apr_pstrcat(cmd->pool, "RewriteMap: dbm type ",
                               newmap->dbmtype, " is invalid", NULL);
        }
    }
    else if ((strncasecmp(a2, "dbd:", 4) == 0)
             || (strncasecmp(a2, "fastdbd:", 8) == 0)) {
        if (dbd_prepare == NULL) {
            return "RewriteMap types dbd and fastdbd require mod_dbd!";
        }
        if ((a2[0] == 'd') || (a2[0] == 'D')) {
            newmap->type = MAPTYPE_DBD;
            fname = a2+4;
        }
        else {
            newmap->type = MAPTYPE_DBD_CACHE;
            fname = a2+8;
            newmap->cachename = apr_psprintf(cmd->pool, "%pp:%s",
                                             (void *)cmd->server, a1);
        }
        newmap->dbdq = a1;
        dbd_prepare(cmd->server, fname, newmap->dbdq);
    }
    else if (strncasecmp(a2, "prg:", 4) == 0) {
        apr_tokenize_to_argv(a2 + 4, &newmap->argv, cmd->pool);

        fname = newmap->argv[0];
        if ((newmap->argv[0] = ap_server_root_relative(cmd->pool,
                                                       fname)) == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad path to prg map: ",
                               fname, NULL);
        }

        newmap->type      = MAPTYPE_PRG;
        newmap->checkfile = newmap->argv[0];
        rewrite_lock_needed = 1;

        if (a3) {
            char *tok_cntx;
            newmap->user = apr_strtok(apr_pstrdup(cmd->pool, a3), ":", &tok_cntx);
            newmap->group = apr_strtok(NULL, ":", &tok_cntx);
        }
    }
    else if (strncasecmp(a2, "int:", 4) == 0) {
        newmap->type      = MAPTYPE_INT;
        newmap->func      = (char *(*)(request_rec *,char *))
                            apr_hash_get(mapfunc_hash, a2+4, strlen(a2+4));
        if (newmap->func == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: internal map not found:",
                               a2+4, NULL);
        }
    }
    else {
        if ((fname = ap_server_root_relative(cmd->pool, a2)) == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad path to txt map: ",
                               a2, NULL);
        }

        newmap->type      = MAPTYPE_TXT;
        newmap->datafile  = fname;
        newmap->checkfile = fname;
        newmap->cachename = apr_psprintf(cmd->pool, "%pp:%s",
                                         (void *)cmd->server, a1);
    }

    if (newmap->checkfile
        && (apr_stat(&st, newmap->checkfile, APR_FINFO_MIN,
                     cmd->pool) != APR_SUCCESS)) {
        return apr_pstrcat(cmd->pool,
                           "RewriteMap: file for map ", a1,
                           " not found:", newmap->checkfile, NULL);
    }

    apr_hash_set(sconf->rewritemaps, a1, APR_HASH_KEY_STRING, newmap);

    return NULL;
}

static const char *cmd_rewritebase(cmd_parms *cmd, void *in_dconf,
                                   const char *a1)
{
    rewrite_perdir_conf *dconf = in_dconf;

    if (cmd->path == NULL || dconf == NULL) {
        return "RewriteBase: only valid in per-directory config files";
    }
    if (a1[0] == '\0') {
        return "RewriteBase: empty URL not allowed";
    }
    if (a1[0] != '/') {
        return "RewriteBase: argument is not a valid URL";
    }

    dconf->baseurl = a1;
    dconf->baseurl_set = 1;

    return NULL;
}

/*
 * generic lexer for RewriteRule and RewriteCond flags.
 * The parser will be passed in as a function pointer
 * and called if a flag was found
 */
static const char *cmd_parseflagfield(apr_pool_t *p, void *cfg, char *key,
                                      const char *(*parse)(apr_pool_t *,
                                                           void *,
                                                           char *, char *))
{
    char *val, *nextp, *endp;
    const char *err;

    endp = key + strlen(key) - 1;
    if (*key != '[' || *endp != ']') {
        return "bad flag delimiters";
    }

    *endp = ','; /* for simpler parsing */
    ++key;

    while (*key) {
        /* skip leading spaces */
        while (apr_isspace(*key)) {
            ++key;
        }

        if (!*key || (nextp = ap_strchr(key, ',')) == NULL) { /* NULL should not
                                                               * happen, but ...
                                                               */
            break;
        }

        /* strip trailing spaces */
        endp = nextp - 1;
        while (apr_isspace(*endp)) {
            --endp;
        }
        *++endp = '\0';

        /* split key and val */
        val = ap_strchr(key, '=');
        if (val) {
            *val++ = '\0';
        }
        else {
            val = endp;
        }

        err = parse(p, cfg, key, val);
        if (err) {
            return err;
        }

        key = nextp + 1;
    }

    return NULL;
}

static const char *cmd_rewritecond_setflag(apr_pool_t *p, void *_cfg,
                                           char *key, char *val)
{
    rewritecond_entry *cfg = _cfg;

    if (   strcasecmp(key, "nocase") == 0
        || strcasecmp(key, "NC") == 0    ) {
        cfg->flags |= CONDFLAG_NOCASE;
    }
    else if (   strcasecmp(key, "ornext") == 0
             || strcasecmp(key, "OR") == 0    ) {
        cfg->flags |= CONDFLAG_ORNEXT;
    }
    else if (   strcasecmp(key, "novary") == 0
             || strcasecmp(key, "NV") == 0    ) {
        cfg->flags |= CONDFLAG_NOVARY;
    }
    else {
        return apr_pstrcat(p, "unknown flag '", key, "'", NULL);
    }
    return NULL;
}

static const char *cmd_rewritecond(cmd_parms *cmd, void *in_dconf,
                                   const char *in_str)
{
    rewrite_perdir_conf *dconf = in_dconf;
    char *str = apr_pstrdup(cmd->pool, in_str);
    rewrite_server_conf *sconf;
    rewritecond_entry *newcond;
    ap_regex_t *regexp;
    char *a1 = NULL, *a2 = NULL, *a2_end, *a3 = NULL;
    const char *err;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    /*  make a new entry in the internal temporary rewrite rule list */
    if (cmd->path == NULL) {   /* is server command */
        newcond = apr_array_push(sconf->rewriteconds);
    }
    else {                     /* is per-directory command */
        newcond = apr_array_push(dconf->rewriteconds);
    }

    /* parse the argument line ourself
     * a1 .. a3 are substrings of str, which is a fresh copy
     * of the argument line. So we can use a1 .. a3 without
     * copying them again.
     */
    if (parseargline(str, &a1, &a2, &a2_end, &a3)) {
        return apr_pstrcat(cmd->pool, "RewriteCond: bad argument line '", str,
                           "'", NULL);
    }

    /* arg1: the input string */
    newcond->input = a1;

    /* arg3: optional flags field
     * (this has to be parsed first, because we need to
     *  know if the regex should be compiled with ICASE!)
     */
    newcond->flags = CONDFLAG_NONE;
    if (a3 != NULL) {
        if ((err = cmd_parseflagfield(cmd->pool, newcond, a3,
                                      cmd_rewritecond_setflag)) != NULL) {
            return apr_pstrcat(cmd->pool, "RewriteCond: ", err, NULL);
        }
    }

    /* arg2: the pattern */
    newcond->pattern = a2;
    if (*a2 == '!') {
        newcond->flags |= CONDFLAG_NOTMATCH;
        ++a2;
    }

    /* determine the pattern type */
    newcond->ptype = CONDPAT_REGEX;
    if (strcasecmp(a1, "expr") == 0) {
        newcond->ptype = CONDPAT_AP_EXPR;
    }
    else if (*a2 && a2[1]) {
        if (*a2 == '-') {
            if (!a2[2]) {
                switch (a2[1]) {
                case 'f': newcond->ptype = CONDPAT_FILE_EXISTS; break;
                case 's': newcond->ptype = CONDPAT_FILE_SIZE;   break;
                case 'd': newcond->ptype = CONDPAT_FILE_DIR;    break;
                case 'x': newcond->ptype = CONDPAT_FILE_XBIT;   break;
                case 'h': newcond->ptype = CONDPAT_FILE_LINK;   break;
                case 'L': newcond->ptype = CONDPAT_FILE_LINK;   break;
                case 'l': newcond->ptype = CONDPAT_FILE_LINK;   break;
                case 'U': newcond->ptype = CONDPAT_LU_URL;      break;
                case 'F': newcond->ptype = CONDPAT_LU_FILE;     break;
                }
            }
            else if (a2[3]) {
                switch (a2[1]) {
                case 'l':
                    if (a2[2] == 't') {
                        a2 += 3;
                        newcond->ptype = CONDPAT_INT_LT;
                    }
                    else if (a2[2] == 'e') {
                        a2 += 3;
                        newcond->ptype = CONDPAT_INT_LE;
                    }
                    break;

                case 'g':
                    if (a2[2] == 't') {
                        a2 += 3;
                        newcond->ptype = CONDPAT_INT_GT;
                    }
                    else if (a2[2] == 'e') {
                        a2 += 3;
                        newcond->ptype = CONDPAT_INT_GE;
                    }
                    break;

                case 'e':
                    if (a2[2] == 'q') {
                        a2 += 3;
                        newcond->ptype = CONDPAT_INT_EQ;
                    }
                    break;

                case 'n':
                    if (a2[2] == 'e') {
                        /* Inversion, ensure !-ne == -eq */
                        a2 += 3;
                        newcond->ptype = CONDPAT_INT_EQ;
                        newcond->flags ^= CONDFLAG_NOTMATCH;
                    }
                    break;
                }
            }
        }
        else {
            switch (*a2) {
            case '>': if (*++a2 == '=')
                          ++a2, newcond->ptype = CONDPAT_STR_GE;
                      else
                          newcond->ptype = CONDPAT_STR_GT;
                      break;

            case '<': if (*++a2 == '=')
                          ++a2, newcond->ptype = CONDPAT_STR_LE;
                      else
                          newcond->ptype = CONDPAT_STR_LT;
                      break;

            case '=': newcond->ptype = CONDPAT_STR_EQ;
                      /* "" represents an empty string */
                      if (*++a2 == '"' && a2[1] == '"' && !a2[2])
                          a2 += 2;
                      break;
            }
        }
    }

    if ((newcond->ptype != CONDPAT_REGEX) &&
        (newcond->ptype < CONDPAT_STR_LT || newcond->ptype > CONDPAT_STR_GE) &&
        (newcond->flags & CONDFLAG_NOCASE)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server, APLOGNO(00665)
                     "RewriteCond: NoCase option for non-regex pattern '%s' "
                     "is not supported and will be ignored. (%s:%d)", a2,
                     cmd->directive->filename, cmd->directive->line_num);
        newcond->flags &= ~CONDFLAG_NOCASE;
    }

    newcond->pskip = a2 - newcond->pattern;
    newcond->pattern += newcond->pskip;

    if (newcond->ptype == CONDPAT_REGEX) {
        regexp = ap_pregcomp(cmd->pool, a2,
                             AP_REG_EXTENDED | ((newcond->flags & CONDFLAG_NOCASE)
                                             ? AP_REG_ICASE : 0));
        if (!regexp) {
            return apr_pstrcat(cmd->pool, "RewriteCond: cannot compile regular "
                               "expression '", a2, "'", NULL);
        }

        newcond->regexp  = regexp;
    }
    else if (newcond->ptype == CONDPAT_AP_EXPR) {
        unsigned int flags = newcond->flags & CONDFLAG_NOVARY ?
                             AP_EXPR_FLAG_DONT_VARY : 0;
        newcond->expr = ap_expr_parse_cmd(cmd, a2, flags, &err, NULL);
        if (err)
            return apr_psprintf(cmd->pool, "RewriteCond: cannot compile "
                                "expression \"%s\": %s", a2, err);
    }

    return NULL;
}

static const char *cmd_rewriterule_setflag(apr_pool_t *p, void *_cfg,
                                           char *key, char *val)
{
    rewriterule_entry *cfg = _cfg;
    int error = 0;

    switch (*key++) {
    case 'b':
    case 'B':
        if (!*key || !strcasecmp(key, "ackrefescaping")) {
            cfg->flags |= RULEFLAG_ESCAPEBACKREF;
            if (val && *val) {
                cfg->escapes = val;
            }
        }
        else if (!strcasecmp(key, "NE")) {
            if (val && *val) {
                cfg->noescapes = val;
            }
            else {
                return "flag 'BNE' wants a list of characters (i.e. [BNE=...])";
            }
        }
        else if (!strcasecmp(key, "NP") || !strcasecmp(key, "ackrefernoplus")) { 
            cfg->flags |= RULEFLAG_ESCAPENOPLUS;
        }
        else if (!strcasecmp(key, "CTLS")) {
            cfg->flags |= RULEFLAG_ESCAPECTLS|RULEFLAG_ESCAPEBACKREF;
        }
        else {
            ++error;
        }
        break;
    case 'c':
    case 'C':
        if (!*key || !strcasecmp(key, "hain")) {           /* chain */
            cfg->flags |= RULEFLAG_CHAIN;
        }
        else if (((*key == 'O' || *key == 'o') && !key[1])
                 || !strcasecmp(key, "ookie")) {           /* cookie */
            data_item *cp = cfg->cookie;

            if (!cp) {
                cp = cfg->cookie = apr_palloc(p, sizeof(*cp));
            }
            else {
                while (cp->next) {
                    cp = cp->next;
                }
                cp->next = apr_palloc(p, sizeof(*cp));
                cp = cp->next;
            }

            cp->next = NULL;
            cp->data = val;
        }
        else {
            ++error;
        }
        break;
    case 'd':
    case 'D':
        if (!*key || !strcasecmp(key, "PI") || !strcasecmp(key,"iscardpath")) {
            cfg->flags |= (RULEFLAG_DISCARDPATHINFO);
        }
        break;
    case 'e':
    case 'E':
        if (!*key || !strcasecmp(key, "nv")) {             /* env */
            data_item *cp = cfg->env;

            if (!cp) {
                cp = cfg->env = apr_palloc(p, sizeof(*cp));
            }
            else {
                while (cp->next) {
                    cp = cp->next;
                }
                cp->next = apr_palloc(p, sizeof(*cp));
                cp = cp->next;
            }

            cp->next = NULL;
            cp->data = val;
        }
        else if (!strcasecmp(key, "nd")) {                /* end */
            cfg->flags |= RULEFLAG_END;
        }
        else {
            ++error;
        }
        break;

    case 'f':
    case 'F':
        if (!*key || !strcasecmp(key, "orbidden")) {       /* forbidden */
            cfg->flags |= (RULEFLAG_STATUS | RULEFLAG_NOSUB);
            cfg->forced_responsecode = HTTP_FORBIDDEN;
        }
        else {
            ++error;
        }
        break;

    case 'g':
    case 'G':
        if (!*key || !strcasecmp(key, "one")) {            /* gone */
            cfg->flags |= (RULEFLAG_STATUS | RULEFLAG_NOSUB);
            cfg->forced_responsecode = HTTP_GONE;
        }
        else {
            ++error;
        }
        break;

    case 'h':
    case 'H':
        if (!*key || !strcasecmp(key, "andler")) {         /* handler */
            cfg->forced_handler = val;
        }
        else {
            ++error;
        }
        break;
    case 'l':
    case 'L':
        if (!*key || !strcasecmp(key, "ast")) {            /* last */
            cfg->flags |= RULEFLAG_LASTRULE;
        }
        else {
            ++error;
        }
        break;

    case 'n':
    case 'N':
        if (((*key == 'E' || *key == 'e') && !key[1])
            || !strcasecmp(key, "oescape")) {              /* noescape */
            cfg->flags |= RULEFLAG_NOESCAPE;
        }
        else if (!*key || !strcasecmp(key, "ext")) {       /* next */
            cfg->flags |= RULEFLAG_NEWROUND;
            if (val && *val) { 
                cfg->maxrounds = atoi(val);
            }

        }
        else if (((*key == 'S' || *key == 's') && !key[1])
            || !strcasecmp(key, "osubreq")) {              /* nosubreq */
            cfg->flags |= RULEFLAG_IGNOREONSUBREQ;
        }
        else if (((*key == 'C' || *key == 'c') && !key[1])
            || !strcasecmp(key, "ocase")) {                /* nocase */
            cfg->flags |= RULEFLAG_NOCASE;
        }
        else {
            ++error;
        }
        break;

    case 'p':
    case 'P':
        if (!*key || !strcasecmp(key, "roxy")) {           /* proxy */
            cfg->flags |= RULEFLAG_PROXY;
        }
        else if (((*key == 'T' || *key == 't') && !key[1])
            || !strcasecmp(key, "assthrough")) {           /* passthrough */
            cfg->flags |= RULEFLAG_PASSTHROUGH;
        }
        else {
            ++error;
        }
        break;

    case 'q':
    case 'Q':
        if (   !strcasecmp(key, "SA")
            || !strcasecmp(key, "sappend")) {              /* qsappend */
            cfg->flags |= RULEFLAG_QSAPPEND;
        } else if ( !strcasecmp(key, "SD")
                || !strcasecmp(key, "sdiscard") ) {       /* qsdiscard */
            cfg->flags |= RULEFLAG_QSDISCARD;
        } else if ( !strcasecmp(key, "SL")
                || !strcasecmp(key, "slast") ) {          /* qslast */
            cfg->flags |= RULEFLAG_QSLAST;
        }
        else {
            ++error;
        }
        break;

    case 'r':
    case 'R':
        if (!*key || !strcasecmp(key, "edirect")) {        /* redirect */
            int status = 0;

            cfg->flags |= RULEFLAG_FORCEREDIRECT;
            if (*val) {
                if (strcasecmp(val, "permanent") == 0) {
                    status = HTTP_MOVED_PERMANENTLY;
                }
                else if (strcasecmp(val, "temp") == 0) {
                    status = HTTP_MOVED_TEMPORARILY;
                }
                else if (strcasecmp(val, "seeother") == 0) {
                    status = HTTP_SEE_OTHER;
                }
                else if (apr_isdigit(*val)) {
                    status = atoi(val);
                    if (status != HTTP_INTERNAL_SERVER_ERROR) {
                        int idx =
                            ap_index_of_response(HTTP_INTERNAL_SERVER_ERROR);

                        if (ap_index_of_response(status) == idx) {
                            return apr_psprintf(p, "invalid HTTP "
                                                   "response code '%s' for "
                                                   "flag 'R'",
                                                val);
                        }
                    }
                    if (!ap_is_HTTP_REDIRECT(status)) {
                        cfg->flags |= (RULEFLAG_STATUS | RULEFLAG_NOSUB);
                    }
                }
                cfg->forced_responsecode = status;
            }
        }
        else {
            ++error;
        }
        break;

    case 's':
    case 'S':
        if (!*key || !strcasecmp(key, "kip")) {            /* skip */
            cfg->skip = atoi(val);
        }
        else {
            ++error;
        }
        break;

    case 't':
    case 'T':
        if (!*key || !strcasecmp(key, "ype")) {            /* type */
            cfg->forced_mimetype = val;
        }
        else {
            ++error;
        }
        break;
    default:
        ++error;
        break;
    }

    if (error) {
        return apr_pstrcat(p, "unknown flag '", --key, "'", NULL);
    }

    return NULL;
}

static const char *cmd_rewriterule(cmd_parms *cmd, void *in_dconf,
                                   const char *in_str)
{
    rewrite_perdir_conf *dconf = in_dconf;
    char *str = apr_pstrdup(cmd->pool, in_str);
    rewrite_server_conf *sconf;
    rewriterule_entry *newrule;
    ap_regex_t *regexp;
    char *a1 = NULL, *a2 = NULL, *a2_end, *a3 = NULL;
    const char *err;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    /*  make a new entry in the internal rewrite rule list */
    if (cmd->path == NULL) {   /* is server command */
        newrule = apr_array_push(sconf->rewriterules);
    }
    else {                     /* is per-directory command */
        newrule = apr_array_push(dconf->rewriterules);
    }

    /*  parse the argument line ourself */
    if (parseargline(str, &a1, &a2, &a2_end, &a3)) {
        return apr_pstrcat(cmd->pool, "RewriteRule: bad argument line '", str,
                           "'", NULL);
    }

    newrule->forced_mimetype     = NULL;
    newrule->forced_handler      = NULL;
    newrule->forced_responsecode = HTTP_MOVED_TEMPORARILY;
    newrule->flags  = RULEFLAG_NONE;
    newrule->env = NULL;
    newrule->cookie = NULL;
    newrule->skip   = 0;
    newrule->maxrounds = REWRITE_MAX_ROUNDS;
    newrule->escapes = newrule->noescapes = NULL;

    /* arg3: optional flags field */
    if (a3 != NULL) {
        if ((err = cmd_parseflagfield(cmd->pool, newrule, a3,
                                      cmd_rewriterule_setflag)) != NULL) {
            return apr_pstrcat(cmd->pool, "RewriteRule: ", err, NULL);
        }
    }

    /* arg1: the pattern
     * try to compile the regexp to test if is ok
     */
    if (*a1 == '!') {
        newrule->flags |= RULEFLAG_NOTMATCH;
        ++a1;
    }

    regexp = ap_pregcomp(cmd->pool, a1, AP_REG_EXTENDED |
                                        ((newrule->flags & RULEFLAG_NOCASE)
                                         ? AP_REG_ICASE : 0));
    if (!regexp) {
        return apr_pstrcat(cmd->pool,
                           "RewriteRule: cannot compile regular expression '",
                           a1, "'", NULL);
    }

    newrule->pattern = a1;
    newrule->regexp  = regexp;

    /* arg2: the output string */
    newrule->output = a2;
    if (*a2 == '-' && !a2[1]) {
        newrule->flags |= RULEFLAG_NOSUB;
    }

    if (*(a2_end-1) == '?') {
        /* a literal ? at the end of the unsubstituted rewrite rule */
        newrule->flags |= RULEFLAG_QSNONE;
        *(a2_end-1) = '\0'; /* trailing ? has done its job */
    }
    else if (newrule->flags & RULEFLAG_QSDISCARD) {
        if (NULL == ap_strchr(newrule->output, '?')) {
            newrule->flags |= RULEFLAG_QSNONE;
        }
    }

    /* now, if the server or per-dir config holds an
     * array of RewriteCond entries, we take it for us
     * and clear the array
     */
    if (cmd->path == NULL) {  /* is server command */
        newrule->rewriteconds   = sconf->rewriteconds;
        sconf->rewriteconds = apr_array_make(cmd->pool, 2,
                                             sizeof(rewritecond_entry));
    }
    else {                    /* is per-directory command */
        newrule->rewriteconds   = dconf->rewriteconds;
        dconf->rewriteconds = apr_array_make(cmd->pool, 2,
                                             sizeof(rewritecond_entry));
    }

    return NULL;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                  the rewriting engine
 * |                                                       |
 * +-------------------------------------------------------+
 */

/* Lexicographic Compare */
static APR_INLINE int compare_lexicography(char *a, char *b)
{
    apr_size_t i, lena, lenb;

    lena = strlen(a);
    lenb = strlen(b);

    if (lena == lenb) {
        for (i = 0; i < lena; ++i) {
            if (a[i] != b[i]) {
                return ((unsigned char)a[i] > (unsigned char)b[i]) ? 1 : -1;
            }
        }

        return 0;
    }

    return ((lena > lenb) ? 1 : -1);
}

/*
 * Apply a single rewriteCond
 */
static int apply_rewrite_cond(rewritecond_entry *p, rewrite_ctx *ctx)
{
    char *input = NULL;
    apr_finfo_t sb;
    request_rec *rsub, *r = ctx->r;
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
    int rc = 0;
    int basis;

    if (p->ptype != CONDPAT_AP_EXPR)
        input = do_expand(p->input, ctx, NULL);

    switch (p->ptype) {
    case CONDPAT_FILE_EXISTS:
        if (   apr_stat(&sb, input, APR_FINFO_MIN, r->pool) == APR_SUCCESS
            && sb.filetype == APR_REG) {
            rc = 1;
        }
        break;

    case CONDPAT_FILE_SIZE:
        if (   apr_stat(&sb, input, APR_FINFO_MIN, r->pool) == APR_SUCCESS
            && sb.filetype == APR_REG && sb.size > 0) {
            rc = 1;
        }
        break;

    case CONDPAT_FILE_LINK:
#if !defined(OS2)
        if (   apr_stat(&sb, input, APR_FINFO_MIN | APR_FINFO_LINK,
                        r->pool) == APR_SUCCESS
            && sb.filetype == APR_LNK) {
            rc = 1;
        }
#endif
        break;

    case CONDPAT_FILE_DIR:
        if (   apr_stat(&sb, input, APR_FINFO_MIN, r->pool) == APR_SUCCESS
            && sb.filetype == APR_DIR) {
            rc = 1;
        }
        break;

    case CONDPAT_FILE_XBIT:
        if (   apr_stat(&sb, input, APR_FINFO_PROT, r->pool) == APR_SUCCESS
            && (sb.protection & (APR_UEXECUTE | APR_GEXECUTE | APR_WEXECUTE))) {
            rc = 1;
        }
        break;

    case CONDPAT_LU_URL:
        if (*input && subreq_ok(r)) {
            rsub = ap_sub_req_lookup_uri(input, r, NULL);
            if (rsub->status < 400) {
                rc = 1;
            }
            rewritelog((r, 5, NULL, "RewriteCond URI (-U) check: "
                        "path=%s -> status=%d", input, rsub->status));
            ap_destroy_sub_req(rsub);
        }
        break;

    case CONDPAT_LU_FILE:
        if (*input && subreq_ok(r)) {
            rsub = ap_sub_req_lookup_file(input, r, NULL);
            if (rsub->status < 300 &&
                /* double-check that file exists since default result is 200 */
                apr_stat(&sb, rsub->filename, APR_FINFO_MIN,
                         r->pool) == APR_SUCCESS) {
                rc = 1;
            }
            rewritelog((r, 5, NULL, "RewriteCond file (-F) check: path=%s "
                        "-> file=%s status=%d", input, rsub->filename,
                        rsub->status));
            ap_destroy_sub_req(rsub);
        }
        break;

    case CONDPAT_STR_GE:
        basis = 0;
        goto test_str_g;
    case CONDPAT_STR_GT:
        basis = 1;
test_str_g:
        if (p->flags & CONDFLAG_NOCASE) {
            rc = (strcasecmp(input, p->pattern) >= basis) ? 1 : 0;
        }
        else {
            rc = (compare_lexicography(input, p->pattern) >= basis) ? 1 : 0;
        }
        break;

    case CONDPAT_STR_LE:
        basis = 0;
        goto test_str_l;
    case CONDPAT_STR_LT:
        basis = -1;
test_str_l:
        if (p->flags & CONDFLAG_NOCASE) {
            rc = (strcasecmp(input, p->pattern) <= basis) ? 1 : 0;
        }
        else {
            rc = (compare_lexicography(input, p->pattern) <= basis) ? 1 : 0;
        }
        break;

    case CONDPAT_STR_EQ:
        /* Note: the only type where the operator is dropped from p->pattern */
        if (p->flags & CONDFLAG_NOCASE) {
            rc = !strcasecmp(input, p->pattern);
        }
        else {
            rc = !strcmp(input, p->pattern);
        }
        break;

    case CONDPAT_INT_GE: rc = (atoi(input) >= atoi(p->pattern)); break;
    case CONDPAT_INT_GT: rc = (atoi(input) > atoi(p->pattern));  break;

    case CONDPAT_INT_LE: rc = (atoi(input) <= atoi(p->pattern)); break;
    case CONDPAT_INT_LT: rc = (atoi(input) < atoi(p->pattern));  break;

    case CONDPAT_INT_EQ: rc = (atoi(input) == atoi(p->pattern)); break;

    case CONDPAT_AP_EXPR:
        {
            const char *err, *source;
            rc = ap_expr_exec_re(r, p->expr, AP_MAX_REG_MATCH, regmatch,
                                 &source, &err);
            if (rc < 0 || err) {
                rewritelog((r, 1, ctx->perdir,
                            "RewriteCond: expr='%s' evaluation failed: %s",
                            p->pattern - p->pskip, err));
                rc = 0;
            }
            /* update briRC backref info */
            if (rc && !(p->flags & CONDFLAG_NOTMATCH)) {
                ctx->briRC.source = source;
                memcpy(ctx->briRC.regmatch, regmatch, sizeof(regmatch));
            }
        }
        break;
    default:
        /* it is really a regexp pattern, so apply it */
        rc = !ap_regexec(p->regexp, input, AP_MAX_REG_MATCH, regmatch, 0);

        /* update briRC backref info */
        if (rc && !(p->flags & CONDFLAG_NOTMATCH)) {
            ctx->briRC.source = input;
            memcpy(ctx->briRC.regmatch, regmatch, sizeof(regmatch));
        }
        break;
    }

    if (p->flags & CONDFLAG_NOTMATCH) {
        rc = !rc;
    }

    rewritelog((r, 4, ctx->perdir, "RewriteCond: input='%s' pattern='%s'%s "
                "=> %s", input, p->pattern - p->pskip,
                (p->flags & CONDFLAG_NOCASE) ? " [NC]" : "",
                rc ? "matched" : "not-matched"));

    return rc;
}

/* check for forced type and handler */
static APR_INLINE void force_type_handler(rewriterule_entry *p,
                                          rewrite_ctx *ctx)
{
    char *expanded;

    if (p->forced_mimetype) {
        expanded = do_expand(p->forced_mimetype, ctx, p);

        if (*expanded) {
            ap_str_tolower(expanded);

            rewritelog((ctx->r, 2, ctx->perdir, "remember %s to have MIME-type "
                        "'%s'", ctx->r->filename, expanded));

            apr_table_setn(ctx->r->notes, REWRITE_FORCED_MIMETYPE_NOTEVAR,
                           expanded);
        }
    }

    if (p->forced_handler) {
        expanded = do_expand(p->forced_handler, ctx, p);

        if (*expanded) {
            ap_str_tolower(expanded);

            rewritelog((ctx->r, 2, ctx->perdir, "remember %s to have "
                        "Content-handler '%s'", ctx->r->filename, expanded));

            apr_table_setn(ctx->r->notes, REWRITE_FORCED_HANDLER_NOTEVAR,
                           expanded);
        }
    }
}

/*
 * Apply a single RewriteRule
 */
static int apply_rewrite_rule(rewriterule_entry *p, rewrite_ctx *ctx)
{
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
    apr_array_header_t *rewriteconds;
    rewritecond_entry *conds;
    int i, rc;
    char *newuri = NULL;
    request_rec *r = ctx->r;
    int is_proxyreq = 0;

    ctx->uri = r->filename;

    if (ctx->perdir) {
        apr_size_t dirlen = strlen(ctx->perdir);

        /*
         * Proxy request?
         */
        is_proxyreq = (   r->proxyreq && r->filename
                       && !strncmp(r->filename, "proxy:", 6));

        /* Since we want to match against the (so called) full URL, we have
         * to re-add the PATH_INFO postfix
         */
        if (r->path_info && *r->path_info) {
            rewritelog((r, 3, ctx->perdir, "add path info postfix: %s -> %s%s",
                        ctx->uri, ctx->uri, r->path_info));
            ctx->uri = apr_pstrcat(r->pool, ctx->uri, r->path_info, NULL);
        }

        /* Additionally we strip the physical path from the url to match
         * it independent from the underlying filesystem.
         */
        if (!is_proxyreq && strlen(ctx->uri) >= dirlen &&
            !strncmp(ctx->uri, ctx->perdir, dirlen)) {

            rewritelog((r, 3, ctx->perdir, "strip per-dir prefix: %s -> %s",
                        ctx->uri, ctx->uri + dirlen));
            ctx->uri = ctx->uri + dirlen;
        }
    }

    /* Try to match the URI against the RewriteRule pattern
     * and exit immediately if it didn't apply.
     */
    rewritelog((r, 3, ctx->perdir, "applying pattern '%s' to uri '%s'",
                p->pattern, ctx->uri));

    rc = !ap_regexec(p->regexp, ctx->uri, AP_MAX_REG_MATCH, regmatch, 0);
    if (! (( rc && !(p->flags & RULEFLAG_NOTMATCH)) ||
           (!rc &&  (p->flags & RULEFLAG_NOTMATCH))   ) ) {
        return 0;
    }

    /* It matched, wow! Now it's time to prepare the context structure for
     * further processing
     */
    ctx->vary_this = NULL;
    ctx->briRC.source = NULL;

    if (p->flags & RULEFLAG_NOTMATCH) {
        ctx->briRR.source = NULL;
    }
    else {
        ctx->briRR.source = apr_pstrdup(r->pool, ctx->uri);
        memcpy(ctx->briRR.regmatch, regmatch, sizeof(regmatch));
    }

    /* Ok, we already know the pattern has matched, but we now
     * additionally have to check for all existing preconditions
     * (RewriteCond) which have to be also true. We do this at
     * this very late stage to avoid unnecessary checks which
     * would slow down the rewriting engine.
     */
    rewriteconds = p->rewriteconds;
    conds = (rewritecond_entry *)rewriteconds->elts;

    for (i = 0; i < rewriteconds->nelts; ++i) {
        rewritecond_entry *c = &conds[i];

        rc = apply_rewrite_cond(c, ctx);
        /*
         * Reset vary_this if the novary flag is set for this condition.
         */
        if (c->flags & CONDFLAG_NOVARY) {
            ctx->vary_this = NULL;
        }
        if (c->flags & CONDFLAG_ORNEXT) {
            if (!rc) {
                /* One condition is false, but another can be still true. */
                ctx->vary_this = NULL;
                continue;
            }
            else {
                /* skip the rest of the chained OR conditions */
                while (   i < rewriteconds->nelts
                       && c->flags & CONDFLAG_ORNEXT) {
                    c = &conds[++i];
                }
            }
        }
        else if (!rc) {
            return 0;
        }

        /* If some HTTP header was involved in the condition, remember it
         * for later use
         */
        if (ctx->vary_this) {
            ctx->vary = ctx->vary
                        ? apr_pstrcat(r->pool, ctx->vary, ", ", ctx->vary_this,
                                      NULL)
                        : ctx->vary_this;
            ctx->vary_this = NULL;
        }
    }

    /* expand the result */
    if (!(p->flags & RULEFLAG_NOSUB)) {
        newuri = do_expand(p->output, ctx, p);
        rewritelog((r, 2, ctx->perdir, "rewrite '%s' -> '%s'", ctx->uri,
                    newuri));
    }

    /* expand [E=var:val] and [CO=<cookie>] */
    do_expand_env(p->env, ctx);
    do_expand_cookie(p->cookie, ctx);

    /* non-substitution rules ('RewriteRule <pat> -') end here. */
    if (p->flags & RULEFLAG_NOSUB) {
        force_type_handler(p, ctx);

        if (p->flags & RULEFLAG_STATUS) {
            rewritelog((r, 2, ctx->perdir, "forcing responsecode %d for %s",
                        p->forced_responsecode, r->filename));

            r->status = p->forced_responsecode;
        }

        return 2;
    }

    /* Now adjust API's knowledge about r->filename and r->args */
    r->filename = newuri;

    if (ctx->perdir && (p->flags & RULEFLAG_DISCARDPATHINFO)) {
        r->path_info = NULL;
    }

    splitout_queryargs(r, p->flags);

    /* Add the previously stripped per-directory location prefix, unless
     * (1) it's an absolute URL path and
     * (2) it's a full qualified URL
     */
    if (   ctx->perdir && !is_proxyreq && *r->filename != '/'
        && !is_absolute_uri(r->filename, NULL)) {
        rewritelog((r, 3, ctx->perdir, "add per-dir prefix: %s -> %s%s",
                    r->filename, ctx->perdir, r->filename));

        r->filename = apr_pstrcat(r->pool, ctx->perdir, r->filename, NULL);
    }

    /* If this rule is forced for proxy throughput
     * (`RewriteRule ... ... [P]') then emulate mod_proxy's
     * URL-to-filename handler to be sure mod_proxy is triggered
     * for this URL later in the Apache API. But make sure it is
     * a fully-qualified URL. (If not it is qualified with
     * ourself).
     */
    if (p->flags & RULEFLAG_PROXY) {
        /* For rules evaluated in server context, the mod_proxy fixup
         * hook can be relied upon to escape the URI as and when
         * necessary, since it occurs later.  If in directory context,
         * the ordering of the fixup hooks is forced such that
         * mod_proxy comes first, so the URI must be escaped here
         * instead.  See PR 39746, 46428, and other headaches. */
        if (ctx->perdir && (p->flags & RULEFLAG_NOESCAPE) == 0) {
            char *old_filename = r->filename;

            r->filename = ap_escape_uri(r->pool, r->filename);
            rewritelog((r, 2, ctx->perdir, "escaped URI in per-dir context "
                        "for proxy, %s -> %s", old_filename, r->filename));
        }

        fully_qualify_uri(r);

        rewritelog((r, 2, ctx->perdir, "forcing proxy-throughput with %s",
                    r->filename));

        r->filename = apr_pstrcat(r->pool, "proxy:", r->filename, NULL);
        return 1;
    }

    /* If this rule is explicitly forced for HTTP redirection
     * (`RewriteRule .. .. [R]') then force an external HTTP
     * redirect. But make sure it is a fully-qualified URL. (If
     * not it is qualified with ourself).
     */
    if (p->flags & RULEFLAG_FORCEREDIRECT) {
        fully_qualify_uri(r);

        rewritelog((r, 2, ctx->perdir, "explicitly forcing redirect with %s",
                    r->filename));

        r->status = p->forced_responsecode;
        return 1;
    }

    /* Special Rewriting Feature: Self-Reduction
     * We reduce the URL by stripping a possible
     * http[s]://<ourhost>[:<port>] prefix, i.e. a prefix which
     * corresponds to ourself. This is to simplify rewrite maps
     * and to avoid recursion, etc. When this prefix is not a
     * coincidence then the user has to use [R] explicitly (see
     * above).
     */
    reduce_uri(r);

    /* If this rule is still implicitly forced for HTTP
     * redirection (`RewriteRule .. <scheme>://...') then
     * directly force an external HTTP redirect.
     */
    if (is_absolute_uri(r->filename, NULL)) {
        rewritelog((r, 2, ctx->perdir, "implicitly forcing redirect (rc=%d) "
                    "with %s", p->forced_responsecode, r->filename));

        r->status = p->forced_responsecode;
        return 1;
    }

    /* Finally remember the forced mime-type */
    force_type_handler(p, ctx);

    /* Puuhhhhhhhh... WHAT COMPLICATED STUFF ;_)
     * But now we're done for this particular rule.
     */
    return 1;
}

/*
 * Apply a complete rule set,
 * i.e. a list of rewrite rules
 */
static int apply_rewrite_list(request_rec *r, apr_array_header_t *rewriterules,
                              char *perdir)
{
    rewriterule_entry *entries;
    rewriterule_entry *p;
    int i;
    int changed;
    int rc;
    int s;
    rewrite_ctx *ctx;
    int round = 1;

    ctx = apr_palloc(r->pool, sizeof(*ctx));
    ctx->perdir = perdir;
    ctx->r = r;

    /*
     *  Iterate over all existing rules
     */
    entries = (rewriterule_entry *)rewriterules->elts;
    changed = 0;
    loop:
    for (i = 0; i < rewriterules->nelts; i++) {
        p = &entries[i];

        /*
         *  Ignore this rule on subrequests if we are explicitly
         *  asked to do so or this is a proxy-throughput or a
         *  forced redirect rule.
         */
        if (r->main != NULL &&
            (p->flags & RULEFLAG_IGNOREONSUBREQ ||
             p->flags & RULEFLAG_FORCEREDIRECT    )) {
            continue;
        }

        /*
         *  Apply the current rule.
         */
        ctx->vary = NULL;
        rc = apply_rewrite_rule(p, ctx);

        if (rc) {

            /* Catch looping rules with pathinfo growing unbounded */
            if ( strlen( r->filename ) > 2*r->server->limit_req_line ) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "RewriteRule '%s' and URI '%s' "
                              "exceeded maximum length (%d)", 
                              p->pattern, r->uri, 2*r->server->limit_req_line );
                r->status = HTTP_INTERNAL_SERVER_ERROR;
                return ACTION_STATUS;
            }

            /* Regardless of what we do next, we've found a match. Check to see
             * if any of the request header fields were involved, and add them
             * to the Vary field of the response.
             */
            if (ctx->vary) {
                apr_table_merge(r->headers_out, "Vary", ctx->vary);
            }

            /*
             * The rule sets the response code (implies match-only)
             */
            if (p->flags & RULEFLAG_STATUS) {
                return ACTION_STATUS;
            }

            /*
             * Indicate a change if this was not a match-only rule.
             */
            if (rc != 2) {
                changed = ((p->flags & RULEFLAG_NOESCAPE)
                           ? ACTION_NOESCAPE : ACTION_NORMAL);
            }

            /*
             *  Pass-Through Feature (`RewriteRule .. .. [PT]'):
             *  Because the Apache 1.x API is very limited we
             *  need this hack to pass the rewritten URL to other
             *  modules like mod_alias, mod_userdir, etc.
             */
            if (p->flags & RULEFLAG_PASSTHROUGH) {
                rewritelog((r, 2, perdir, "forcing '%s' to get passed through "
                           "to next API URI-to-filename handler", r->filename));
                r->filename = apr_pstrcat(r->pool, "passthrough:",
                                         r->filename, NULL);
                changed = ACTION_NORMAL;
                break;
            }

            if (p->flags & RULEFLAG_END) {
                rewritelog((r, 8, perdir, "Rule has END flag, no further rewriting for this request"));
                apr_pool_userdata_set("1", really_last_key, apr_pool_cleanup_null, r->pool);
                break;
            }
            /*
             *  Stop processing also on proxy pass-through and
             *  last-rule and new-round flags.
             */
            if (p->flags & (RULEFLAG_PROXY | RULEFLAG_LASTRULE)) {
                break;
            }

            /*
             *  On "new-round" flag we just start from the top of
             *  the rewriting ruleset again.
             */
            if (p->flags & RULEFLAG_NEWROUND) {
                if (++round >= p->maxrounds) { 
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02596)
                                  "RewriteRule '%s' and URI '%s' exceeded "
                                  "maximum number of rounds (%d) via the [N] flag", 
                                  p->pattern, r->uri, p->maxrounds);

                    r->status = HTTP_INTERNAL_SERVER_ERROR;
                    return ACTION_STATUS; 
                }
                goto loop;
            }

            /*
             *  If we are forced to skip N next rules, do it now.
             */
            if (p->skip > 0) {
                s = p->skip;
                while (   i < rewriterules->nelts
                       && s > 0) {
                    i++;
                    s--;
                }
            }
        }
        else {
            /*
             *  If current rule is chained with next rule(s),
             *  skip all this next rule(s)
             */
            while (   i < rewriterules->nelts
                   && p->flags & RULEFLAG_CHAIN) {
                i++;
                p = &entries[i];
            }
        }
    }
    return changed;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |             Module Initialization Hooks
 * |                                                       |
 * +-------------------------------------------------------+
 */

static int pre_config(apr_pool_t *pconf,
                      apr_pool_t *plog,
                      apr_pool_t *ptemp)
{
    APR_OPTIONAL_FN_TYPE(ap_register_rewrite_mapfunc) *map_pfn_register;

    rewrite_lock_needed = 0; 
    ap_mutex_register(pconf, rewritemap_mutex_type, NULL, APR_LOCK_DEFAULT, 0);

    /* register int: rewritemap handlers */
    map_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_rewrite_mapfunc);
    if (map_pfn_register) {
        map_pfn_register("tolower", rewrite_mapfunc_tolower);
        map_pfn_register("toupper", rewrite_mapfunc_toupper);
        map_pfn_register("escape", rewrite_mapfunc_escape);
        map_pfn_register("unescape", rewrite_mapfunc_unescape);
    }
    dbd_acquire = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    dbd_prepare = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
    return OK;
}

static int post_config(apr_pool_t *p,
                       apr_pool_t *plog,
                       apr_pool_t *ptemp,
                       server_rec *s)
{
    apr_status_t rv;

    /* check if proxy module is available */
    proxy_available = (ap_find_linked_module("mod_proxy.c") != NULL);

    if (rewrite_lock_needed) {
        rv = rewritelock_create(s, p);
        if (rv != APR_SUCCESS) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        apr_pool_cleanup_register(p, (void *)s, rewritelock_remove,
                apr_pool_cleanup_null);
    }

    /* if we are not doing the initial config, step through the servers and
     * open the RewriteMap prg:xxx programs,
     */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_CONFIG) {
        for (; s; s = s->next) {
            if (run_rewritemap_programs(s, p) != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    return OK;
}

static void init_child(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv = 0; /* get a rid of gcc warning (REWRITELOG_DISABLED) */

    if (rewrite_mapr_lock_acquire) {
        rv = apr_global_mutex_child_init(&rewrite_mapr_lock_acquire,
                 apr_global_mutex_lockfile(rewrite_mapr_lock_acquire), p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00666)
                         "mod_rewrite: could not init rewrite_mapr_lock_acquire"
                         " in child");
        }
    }

    /* create the lookup cache */
    if (!init_cache(p)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00667)
                     "mod_rewrite: could not init map cache in child");
    }
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                     runtime hooks
 * |                                                       |
 * +-------------------------------------------------------+
 */

/*
 * URI-to-filename hook
 * [deals with RewriteRules in server context]
 */
static int hook_uri2file(request_rec *r)
{
    rewrite_perdir_conf *dconf;
    rewrite_server_conf *conf;
    const char *saved_rulestatus;
    const char *var;
    const char *thisserver;
    char *thisport;
    const char *thisurl;
    unsigned int port;
    int rulestatus;
    void *skipdata;
    const char *oargs;

    /*
     *  retrieve the config structures
     */
    conf = ap_get_module_config(r->server->module_config, &rewrite_module);

    dconf = (rewrite_perdir_conf *)ap_get_module_config(r->per_dir_config,
                                                        &rewrite_module);

    /*
     *  only do something under runtime if the engine is really enabled,
     *  else return immediately!
     */
    if (!dconf || dconf->state == ENGINE_DISABLED) {
        return DECLINED;
    }

    /*
     *  check for the ugly API case of a virtual host section where no
     *  mod_rewrite directives exists. In this situation we became no chance
     *  by the API to setup our default per-server config so we have to
     *  on-the-fly assume we have the default config. But because the default
     *  config has a disabled rewriting engine we are lucky because can
     *  just stop operating now.
     */
    if (conf->server != r->server) {
        return DECLINED;
    }

    /* END flag was used as a RewriteRule flag on this request */
    apr_pool_userdata_get(&skipdata, really_last_key, r->pool);
    if (skipdata != NULL) {
        rewritelog((r, 8, NULL, "Declining, no further rewriting due to END flag"));
        return DECLINED;
    }

    /* Unless the anyuri option is set, ensure that the input to the
     * first rule really is a URL-path, avoiding security issues with
     * poorly configured rules.  See CVE-2011-3368, CVE-2011-4317. */
    if ((dconf->options & OPTION_ANYURI) == 0
        && ((r->unparsed_uri[0] == '*' && r->unparsed_uri[1] == '\0')
            || !r->uri || r->uri[0] != '/')) {
        rewritelog((r, 8, NULL, "Declining, request-URI '%s' is not a URL-path. "
                    "Consult the manual entry for the RewriteOptions directive "
                    "for options and caveats about matching other strings.",
                    r->uri));
        return DECLINED;
    }

    /*
     *  remember the original query string for later check, since we don't
     *  want to apply URL-escaping when no substitution has changed it.
     */
    oargs = r->args;

    /*
     *  add the SCRIPT_URL variable to the env. this is a bit complicated
     *  due to the fact that apache uses subrequests and internal redirects
     */

    if (r->main == NULL) {
         var = apr_table_get(r->subprocess_env, REDIRECT_ENVVAR_SCRIPT_URL);
         if (var == NULL) {
             apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URL, r->uri);
         }
         else {
             apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URL, var);
         }
    }
    else {
         var = apr_table_get(r->main->subprocess_env, ENVVAR_SCRIPT_URL);
         apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URL, var);
    }

    /*
     *  create the SCRIPT_URI variable for the env
     */

    /* add the canonical URI of this URL */
    thisserver = ap_get_server_name_for_url(r);
    port = ap_get_server_port(r);
    if (ap_is_default_port(port, r)) {
        thisport = "";
    }
    else {
        thisport = apr_psprintf(r->pool, ":%u", port);
    }
    thisurl = apr_table_get(r->subprocess_env, ENVVAR_SCRIPT_URL);

    /* set the variable */
    var = apr_pstrcat(r->pool, ap_http_scheme(r), "://", thisserver, thisport,
                      thisurl, NULL);
    apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URI, var);

    if (!(saved_rulestatus = apr_table_get(r->notes,"mod_rewrite_rewritten"))) {
        /* if filename was not initially set,
         * we start with the requested URI
         */
        if (r->filename == NULL) {
            r->filename = apr_pstrdup(r->pool, r->uri);
            rewritelog((r, 2, NULL, "init rewrite engine with requested uri %s",
                        r->filename));
        }
        else {
            rewritelog((r, 2, NULL, "init rewrite engine with passed filename "
                        "%s. Original uri = %s", r->filename, r->uri));
        }

        /*
         *  now apply the rules ...
         */
        rulestatus = apply_rewrite_list(r, conf->rewriterules, NULL);
        apr_table_setn(r->notes, "mod_rewrite_rewritten",
                       apr_psprintf(r->pool,"%d",rulestatus));
    }
    else {
        rewritelog((r, 2, NULL, "uri already rewritten. Status %s, Uri %s, "
                    "r->filename %s", saved_rulestatus, r->uri, r->filename));

        rulestatus = atoi(saved_rulestatus);
    }

    if (rulestatus) {
        unsigned skip_absolute = is_absolute_uri(r->filename, NULL);
        apr_size_t flen =  r->filename ? strlen(r->filename) : 0;
        int to_proxyreq = (flen > 6 && strncmp(r->filename, "proxy:", 6) == 0);
        int will_escape = skip_absolute && (rulestatus != ACTION_NOESCAPE);

        if (r->args
                && !will_escape
                && *(ap_scan_vchar_obstext(r->args))) {
            /*
             * We have a raw control character or a ' ' in r->args.
             * Correct encoding was missed.
             * Correct encoding was missed and we're not going to escape
             * it before returning.
             */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10410)
                          "Rewritten query string contains control "
                          "characters or spaces");
            return HTTP_FORBIDDEN;
        }

        if (ACTION_STATUS == rulestatus) {
            int n = r->status;

            r->status = HTTP_OK;
            return n;
        }

        if (to_proxyreq) {
            /* it should be go on as an internal proxy request */

            /* check if the proxy module is enabled, so
             * we can actually use it!
             */
            if (!proxy_available) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00669)
                              "attempt to make remote request from mod_rewrite "
                              "without proxy enabled: %s", r->filename);
                return HTTP_FORBIDDEN;
            }

            if (rulestatus == ACTION_NOESCAPE) {
                apr_table_setn(r->notes, "proxy-nocanon", "1");
            }

            /* make sure the QUERY_STRING and
             * PATH_INFO parts get incorporated
             */
            if (r->path_info != NULL) {
                r->filename = apr_pstrcat(r->pool, r->filename,
                                          r->path_info, NULL);
            }
            if ((r->args != NULL)
                && ((r->proxyreq == PROXYREQ_PROXY)
                    || (rulestatus == ACTION_NOESCAPE))) {
                /* see proxy_http:proxy_http_canon() */
                r->filename = apr_pstrcat(r->pool, r->filename,
                                          "?", r->args, NULL);
            }

            /* now make sure the request gets handled by the proxy handler */
            if (PROXYREQ_NONE == r->proxyreq) {
                r->proxyreq = PROXYREQ_REVERSE;
            }
            r->handler  = "proxy-server";

            rewritelog((r, 1, NULL, "go-ahead with proxy request %s [OK]",
                        r->filename));
            return OK;
        }
        else if (skip_absolute > 0) {
            int n;

            /* it was finally rewritten to a remote URL */

            if (rulestatus != ACTION_NOESCAPE) {
                rewritelog((r, 1, NULL, "escaping %s for redirect",
                            r->filename));
                r->filename = escape_absolute_uri(r->pool, r->filename, skip_absolute);
            }

            /* append the QUERY_STRING part */
            if (r->args) {
                char *escaped_args = NULL;
                int noescape = (rulestatus == ACTION_NOESCAPE ||
                                (oargs && !strcmp(r->args, oargs)));

                r->filename = apr_pstrcat(r->pool, r->filename, "?",
                                          noescape
                                            ? r->args
                                            : (escaped_args =
                                               ap_escape_uri(r->pool, r->args)),
                                          NULL);

                rewritelog((r, 1, NULL, "%s %s to query string for redirect %s",
                            noescape ? "copying" : "escaping",
                            r->args ,
                            noescape ? "" : escaped_args));
            }

            /* determine HTTP redirect response code */
            if (ap_is_HTTP_REDIRECT(r->status)) {
                n = r->status;
                r->status = HTTP_OK; /* make Apache kernel happy */
            }
            else {
                n = HTTP_MOVED_TEMPORARILY;
            }

            /* now do the redirection */
            apr_table_setn(r->headers_out, "Location", r->filename);
            rewritelog((r, 1, NULL, "redirect to %s [REDIRECT/%d]", r->filename,
                        n));

            return n;
        }
        else if (flen > 12 && strncmp(r->filename, "passthrough:", 12) == 0) {
            /*
             * Hack because of underpowered API: passing the current
             * rewritten filename through to other URL-to-filename handlers
             * just as it were the requested URL. This is to enable
             * post-processing by mod_alias, etc.  which always act on
             * r->uri! The difference here is: We do not try to
             * add the document root
             */
            r->uri = apr_pstrdup(r->pool, r->filename+12);
            return DECLINED;
        }
        else {
            /* it was finally rewritten to a local path */
            const char *uri_reduced = NULL;

            /* expand "/~user" prefix */
#if APR_HAS_USER
            r->filename = expand_tildepaths(r, r->filename);
#endif
            rewritelog((r, 2, NULL, "local path result: %s", r->filename));

            /* the filename must be either an absolute local path or an
             * absolute local URL.
             */
            if (   *r->filename != '/'
                && !ap_os_is_path_absolute(r->pool, r->filename)) {
                return HTTP_BAD_REQUEST;
            }

            /* if there is no valid prefix, we call
             * the translator from the core and
             * prefix the filename with document_root
             *
             * NOTICE:
             * We cannot leave out the prefix_stat because
             * - when we always prefix with document_root
             *   then no absolute path can be created, e.g. via
             *   emulating a ScriptAlias directive, etc.
             * - when we always NOT prefix with document_root
             *   then the files under document_root have to
             *   be references directly and document_root
             *   gets never used and will be a dummy parameter -
             *   this is also bad
             *
             * BUT:
             * Under real Unix systems this is no problem,
             * because we only do stat() on the first directory
             * and this gets cached by the kernel for along time!
             */

            if(!(conf->options & OPTION_LEGACY_PREFIX_DOCROOT)) {
                uri_reduced = apr_table_get(r->notes, "mod_rewrite_uri_reduced");
            }

            if (!prefix_stat(r->filename, r->pool) || uri_reduced != NULL) {
                int res;
                char *tmp = r->uri;

                r->uri = r->filename;
                res = ap_core_translate(r);
                r->uri = tmp;

                if (res != OK) {
                    rewritelog((r, 1, NULL, "prefixing with document_root of %s"
                                " FAILED", r->filename));

                    return res;
                }

                rewritelog((r, 2, NULL, "prefixed with document_root to %s",
                            r->filename));
            }

            rewritelog((r, 1, NULL, "go-ahead with %s [OK]", r->filename));
            return OK;
        }
    }
    else {
        rewritelog((r, 1, NULL, "pass through %s", r->filename));
        return DECLINED;
    }
}

/*
 * Fixup hook
 * [RewriteRules in directory context]
 */
static int hook_fixup(request_rec *r)
{
    rewrite_perdir_conf *dconf;
    char *cp;
    char *cp2;
    const char *ccp;
    apr_size_t l;
    int rulestatus;
    int n;
    char *ofilename, *oargs;
    int is_proxyreq;
    void *skipdata;

    dconf = (rewrite_perdir_conf *)ap_get_module_config(r->per_dir_config,
                                                        &rewrite_module);

    /* if there is no per-dir config we return immediately */
    if (dconf == NULL) {
        return DECLINED;
    }

    /*
     * only do something under runtime if the engine is really enabled,
     * for this directory, else return immediately!
     */
    if (dconf->state == ENGINE_DISABLED) {
        return DECLINED;
    }

    /* if there are no real (i.e. no RewriteRule directives!)
       per-dir config of us, we return also immediately */
    if (dconf->directory == NULL) {
        return DECLINED;
    }

    /*
     * Proxy request?
     */
    is_proxyreq = (   r->proxyreq && r->filename
                   && !strncmp(r->filename, "proxy:", 6));

    /*
     *  .htaccess file is called before really entering the directory, i.e.:
     *  URL: http://localhost/foo  and .htaccess is located in foo directory
     *  Ignore such attempts, allowing mod_dir to direct the client to the
     *  canonical URL. This can be controlled with the AllowNoSlash option.
     */
    if (!is_proxyreq && !(dconf->options & OPTION_NOSLASH)) {
        l = strlen(dconf->directory) - 1;
        if (r->filename && strlen(r->filename) == l &&
            (dconf->directory)[l] == '/' &&
            !strncmp(r->filename, dconf->directory, l)) {
            return DECLINED;
        }
    }

    /* END flag was used as a RewriteRule flag on this request */
    apr_pool_userdata_get(&skipdata, really_last_key, r->pool);
    if (skipdata != NULL) {
        rewritelog((r, 8, dconf->directory, "Declining, no further rewriting due to END flag"));
        return DECLINED;
    }

    /*
     *  Do the Options check after engine check, so
     *  the user is able to explicitly turn RewriteEngine Off.
     */
    if (!(ap_allow_options(r) & (OPT_SYM_LINKS | OPT_SYM_OWNER))) {
        /* FollowSymLinks is mandatory! */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00670)
                     "Options FollowSymLinks and SymLinksIfOwnerMatch are both off, "
                     "so the RewriteRule directive is also forbidden "
                     "due to its similar ability to circumvent directory restrictions : "
                     "%s", r->filename);
        return HTTP_FORBIDDEN;
    }

    /*
     *  remember the current filename before rewriting for later check
     *  to prevent deadlooping because of internal redirects
     *  on final URL/filename which can be equal to the initial one.
     *  also, we'll restore original r->filename if we decline this
     *  request
     */
    ofilename = r->filename;
    oargs = r->args;

    if (r->filename == NULL) {
        r->filename = apr_pstrdup(r->pool, r->uri);
        rewritelog((r, 2, dconf->directory, "init rewrite engine with"
                   " requested uri %s", r->filename));
    }

    /*
     *  now apply the rules ...
     */
    rulestatus = apply_rewrite_list(r, dconf->rewriterules, dconf->directory);
    if (rulestatus) {
        unsigned skip_absolute = is_absolute_uri(r->filename, NULL);
        int to_proxyreq = 0;
        int will_escape = 0;

        l = strlen(r->filename);
        to_proxyreq = l > 6 && strncmp(r->filename, "proxy:", 6) == 0;
        will_escape = skip_absolute && (rulestatus != ACTION_NOESCAPE);

        if (r->args
               && !will_escape
               &&  *(ap_scan_vchar_obstext(r->args))) {
            /*
             * We have a raw control character or a ' ' in r->args.
             * Correct encoding was missed.
             */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10411)
                          "Rewritten query string contains control "
                          "characters or spaces");
            return HTTP_FORBIDDEN;
        }

        if (ACTION_STATUS == rulestatus) {
            int n = r->status;

            r->status = HTTP_OK;
            return n;
        }

        if (to_proxyreq) {
            /* it should go on as an internal proxy request */

            /* make sure the QUERY_STRING and
             * PATH_INFO parts get incorporated
             * (r->path_info was already appended by the
             * rewriting engine because of the per-dir context!)
             */
            if (r->args != NULL) {
                /* see proxy_http:proxy_http_canon() */
                r->filename = apr_pstrcat(r->pool, r->filename,
                                          "?", r->args, NULL);
            }

            /* now make sure the request gets handled by the proxy handler */
            if (PROXYREQ_NONE == r->proxyreq) {
                r->proxyreq = PROXYREQ_REVERSE;
            }
            r->handler  = "proxy-server";

            rewritelog((r, 1, dconf->directory, "go-ahead with proxy request "
                        "%s [OK]", r->filename));
            return OK;
        }
        else if (skip_absolute > 0) {
            /* it was finally rewritten to a remote URL */

            /* because we are in a per-dir context
             * first try to replace the directory with its base-URL
             * if there is a base-URL available
             */
            if (dconf->baseurl != NULL) {
                /* skip 'scheme://' */
                cp = r->filename + skip_absolute;

                if ((cp = ap_strchr(cp, '/')) != NULL && *(++cp)) {
                    rewritelog((r, 2, dconf->directory,
                                "trying to replace prefix %s with %s",
                                dconf->directory, dconf->baseurl));

                    /* I think, that hack needs an explanation:
                     * well, here is it:
                     * mod_rewrite was written for unix systems, were
                     * absolute file-system paths start with a slash.
                     * URL-paths _also_ start with slashes, so they
                     * can be easily compared with system paths.
                     *
                     * the following assumes, that the actual url-path
                     * may be prefixed by the current directory path and
                     * tries to replace the system path with the RewriteBase
                     * URL.
                     * That assumption is true if we use a RewriteRule like
                     *
                     * RewriteRule ^foo bar [R]
                     *
                     * (see apply_rewrite_rule function)
                     * However on systems that don't have a / as system
                     * root this will never match, so we skip the / after the
                     * hostname and compare/substitute only the stuff after it.
                     *
                     * (note that cp was already increased to the right value)
                     */
                    cp2 = subst_prefix_path(r, cp, (*dconf->directory == '/')
                                                   ? dconf->directory + 1
                                                   : dconf->directory,
                                            dconf->baseurl + 1);
                    if (strcmp(cp2, cp) != 0) {
                        *cp = '\0';
                        r->filename = apr_pstrcat(r->pool, r->filename,
                                                  cp2, NULL);
                    }
                }
            }

            /* now prepare the redirect... */
            if (rulestatus != ACTION_NOESCAPE) {
                rewritelog((r, 1, dconf->directory, "escaping %s for redirect",
                            r->filename));
                r->filename = escape_absolute_uri(r->pool, r->filename, skip_absolute);
            }

            /* append the QUERY_STRING part */
            if (r->args) {
                char *escaped_args = NULL;
                int noescape = (rulestatus == ACTION_NOESCAPE ||
                                (oargs && !strcmp(r->args, oargs)));

                r->filename = apr_pstrcat(r->pool, r->filename, "?",
                                          noescape
                                            ? r->args
                                            : (escaped_args = ap_escape_uri(r->pool, r->args)),
                                          NULL);

                rewritelog((r, 1, dconf->directory, "%s %s to query string for redirect %s",
                            noescape ? "copying" : "escaping",
                            r->args ,
                            noescape ? "" : escaped_args));
            }

            /* determine HTTP redirect response code */
            if (ap_is_HTTP_REDIRECT(r->status)) {
                n = r->status;
                r->status = HTTP_OK; /* make Apache kernel happy */
            }
            else {
                n = HTTP_MOVED_TEMPORARILY;
            }

            /* now do the redirection */
            apr_table_setn(r->headers_out, "Location", r->filename);
            rewritelog((r, 1, dconf->directory, "redirect to %s [REDIRECT/%d]",
                        r->filename, n));
            return n;
        }
        else {
            const char *tmpfilename = NULL;
            /* it was finally rewritten to a local path */

            /* if someone used the PASSTHROUGH flag in per-dir
             * context we just ignore it. It is only useful
             * in per-server context
             */
            if (l > 12 && strncmp(r->filename, "passthrough:", 12) == 0) {
                r->filename = apr_pstrdup(r->pool, r->filename+12);
            }

            /* the filename must be either an absolute local path or an
             * absolute local URL.
             */
            if (   *r->filename != '/'
                && !ap_os_is_path_absolute(r->pool, r->filename)) {
                return HTTP_BAD_REQUEST;
            }

            /* Check for deadlooping:
             * At this point we KNOW that at least one rewriting
             * rule was applied, but when the resulting URL is
             * the same as the initial URL, we are not allowed to
             * use the following internal redirection stuff because
             * this would lead to a deadloop.
             */
            if (ofilename != NULL && strcmp(r->filename, ofilename) == 0) {
                rewritelog((r, 1, dconf->directory, "initial URL equal rewritten"
                            " URL: %s [IGNORING REWRITE]", r->filename));
                return OK;
            }

            tmpfilename = r->filename;

            /* if there is a valid base-URL then substitute
             * the per-dir prefix with this base-URL if the
             * current filename still is inside this per-dir
             * context. If not then treat the result as a
             * plain URL
             */
            if (dconf->baseurl != NULL) {
                rewritelog((r, 2, dconf->directory, "trying to replace prefix "
                            "%s with %s", dconf->directory, dconf->baseurl));

                r->filename = subst_prefix_path(r, r->filename,
                                                dconf->directory,
                                                dconf->baseurl);
            }
            else {
                /* if no explicit base-URL exists we assume
                 * that the directory prefix is also a valid URL
                 * for this webserver and only try to remove the
                 * document_root if it is prefix
                 */
                if ((ccp = ap_document_root(r)) != NULL) {
                    /* strip trailing slash */
                    l = strlen(ccp);
                    if (ccp[l-1] == '/') {
                        --l;
                    }
                    if (!strncmp(r->filename, ccp, l) &&
                        r->filename[l] == '/') {
                        rewritelog((r, 2,dconf->directory, "strip document_root"
                                    " prefix: %s -> %s", r->filename,
                                    r->filename+l));

                        r->filename = apr_pstrdup(r->pool, r->filename+l);
                    }
                }
            }

            /* No base URL, or r->filename wasn't still under dconf->directory
             * or, r->filename wasn't still under the document root. 
             * If there's a context document root AND a context prefix, and 
             * the context document root is a prefix of r->filename, replace.
             * This allows a relative substitution on a path found by mod_userdir 
             * or mod_alias without baking in a RewriteBase.
             */
            if (tmpfilename == r->filename && 
                !(dconf->options & OPTION_IGNORE_CONTEXT_INFO)) { 
                if ((ccp = ap_context_document_root(r)) != NULL) { 
                    const char *prefix = ap_context_prefix(r);
                    if (prefix != NULL) { 
                        rewritelog((r, 2, dconf->directory, "trying to replace "
                                    "context docroot %s with context prefix %s",
                                    ccp, prefix));
                        r->filename = subst_prefix_path(r, r->filename,
                                ccp, prefix);
                    }
                }
            }

            apr_table_setn(r->notes, "redirect-keeps-vary", "");

            /* now initiate the internal redirect */
            rewritelog((r, 1, dconf->directory, "internal redirect with %s "
                        "[INTERNAL REDIRECT]", r->filename));
            r->filename = apr_pstrcat(r->pool, "redirect:", r->filename, NULL);
            r->handler = REWRITE_REDIRECT_HANDLER_NAME;
            return OK;
        }
    }
    else {
        rewritelog((r, 1, dconf->directory, "pass through %s", r->filename));
        r->filename = ofilename;
        return DECLINED;
    }
}

/*
 * MIME-type hook
 * [T=...,H=...] execution
 */
static int hook_mimetype(request_rec *r)
{
    const char *t;

    /* type */
    t = apr_table_get(r->notes, REWRITE_FORCED_MIMETYPE_NOTEVAR);
    if (t && *t) {
        rewritelog((r, 1, NULL, "force filename %s to have MIME-type '%s'",
                    r->filename, t));

        ap_set_content_type(r, t);
    }

    /* handler */
    t = apr_table_get(r->notes, REWRITE_FORCED_HANDLER_NOTEVAR);
    if (t && *t) {
        rewritelog((r, 1, NULL, "force filename %s to have the "
                    "Content-handler '%s'", r->filename, t));

        r->handler = t;
    }

    return OK;
}


/*
 * "content" handler for internal redirects
 */
static int handler_redirect(request_rec *r)
{
    if (strcmp(r->handler, REWRITE_REDIRECT_HANDLER_NAME)) {
        return DECLINED;
    }

    /* just make sure that we are really meant! */
    if (strncmp(r->filename, "redirect:", 9) != 0) {
        return DECLINED;
    }

    /* now do the internal redirect */
    ap_internal_redirect(apr_pstrcat(r->pool, r->filename+9,
                                     r->args ? "?" : NULL, r->args, NULL), r);

    /* and return gracefully */
    return OK;
}


/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |                Module paraphernalia
 * |                                                       |
 * +-------------------------------------------------------+
 */

static const command_rec command_table[] = {
    AP_INIT_FLAG(    "RewriteEngine",   cmd_rewriteengine,  NULL, OR_FILEINFO,
                     "On or Off to enable or disable (default) the whole "
                     "rewriting engine"),
    AP_INIT_ITERATE( "RewriteOptions",  cmd_rewriteoptions,  NULL, OR_FILEINFO,
                     "List of option strings to set"),
    AP_INIT_TAKE1(   "RewriteBase",     cmd_rewritebase,     NULL, OR_FILEINFO,
                     "the base URL of the per-directory context"),
    AP_INIT_RAW_ARGS("RewriteCond",     cmd_rewritecond,     NULL, OR_FILEINFO,
                     "an input string and a to be applied regexp-pattern"),
    AP_INIT_RAW_ARGS("RewriteRule",     cmd_rewriterule,     NULL, OR_FILEINFO,
                     "an URL-applied regexp-pattern and a substitution URL"),
    AP_INIT_TAKE23(   "RewriteMap",      cmd_rewritemap,      NULL, RSRC_CONF,
                     "a mapname and a filename and options"),
    { NULL }
};

static void ap_register_rewrite_mapfunc(char *name, rewrite_mapfunc_t *func)
{
    apr_hash_set(mapfunc_hash, name, strlen(name), (const void *)func);
}

static void register_hooks(apr_pool_t *p)
{
    /* fixup after mod_proxy, so that the proxied url will not
     * escaped accidentally by mod_proxy's fixup.
     */
    static const char * const aszPre[]={ "mod_proxy.c", NULL };

    /* make the hashtable before registering the function, so that
     * other modules are prevented from accessing uninitialized memory.
     */
    mapfunc_hash = apr_hash_make(p);
    APR_REGISTER_OPTIONAL_FN(ap_register_rewrite_mapfunc);

    ap_hook_handler(handler_redirect, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(init_child, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_fixups(hook_fixup, aszPre, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(hook_mimetype, NULL, NULL, APR_HOOK_LAST);
    ap_hook_translate_name(hook_uri2file, NULL, NULL, APR_HOOK_FIRST);
}

    /* the main config structure */
AP_DECLARE_MODULE(rewrite) = {
   STANDARD20_MODULE_STUFF,
   config_perdir_create,        /* create per-dir    config structures */
   config_perdir_merge,         /* merge  per-dir    config structures */
   config_server_create,        /* create per-server config structures */
   config_server_merge,         /* merge  per-server config structures */
   command_table,               /* table of config file commands       */
   register_hooks               /* register hooks                      */
};

/*EOF*/
