/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

#ifndef MOD_REWRITE_H
#define MOD_REWRITE_H 1

/*
**                       _                            _ _
**   _ __ ___   ___   __| |    _ __ _____      ___ __(_) |_ ___
**  | '_ ` _ \ / _ \ / _` |   | '__/ _ \ \ /\ / / '__| | __/ _ \
**  | | | | | | (_) | (_| |   | | |  __/\ V  V /| |  | | ||  __/
**  |_| |_| |_|\___/ \__,_|___|_|  \___| \_/\_/ |_|  |_|\__\___|
**                       |_____|
**
**  URL Rewriting Module
**
**  This module uses a rule-based rewriting engine (based on a
**  regular-expression parser) to rewrite requested URLs on the fly.
**
**  It supports an unlimited number of additional rule conditions (which can
**  operate on a lot of variables, even on HTTP headers) for granular
**  matching and even external database lookups (either via plain text
**  tables, DBM hash files or even external processes) for advanced URL
**  substitution.
**
**  It operates on the full URLs (including the PATH_INFO part) both in
**  per-server context (httpd.conf) and per-dir context (.htaccess) and even
**  can generate QUERY_STRING parts on result.   The rewriting result finally
**  can lead to internal subprocessing, external request redirection or even
**  to internal proxy throughput.
**
**  This module was originally written in April 1996 and
**  gifted exclusively to the The Apache Software Foundation in July 1997 by
**
**      Ralf S. Engelschall
**      rse@engelschall.com
**      www.engelschall.com
*/

#include "apr.h"

#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

    /* Include from the underlaying Unix system ... */
#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_CTYPE_H
#include <ctype.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if APR_HAS_THREADS
#include "apr_thread_mutex.h"
#endif
#include "apr_optional.h"
#include "apr_dbm.h"
#include "ap_config.h"

    /* Include from the Apache server ... */
#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_log.h"
#include "http_vhost.h"

    /*
     * The key in the r->notes apr_table_t wherein we store our accumulated
     * Vary values, and the one used for per-condition checks in a chain.
     */
#define VARY_KEY "rewrite-Vary"
#define VARY_KEY_THIS "rewrite-Vary-this"

/*
**
**  Some defines
**
*/

#define ENVVAR_SCRIPT_URL "SCRIPT_URL"
#define REDIRECT_ENVVAR_SCRIPT_URL "REDIRECT_SCRIPT_URL"
#define ENVVAR_SCRIPT_URI "SCRIPT_URI"

#define REWRITE_FORCED_MIMETYPE_NOTEVAR "rewrite-forced-mimetype"

#define CONDFLAG_NONE               1<<0
#define CONDFLAG_NOCASE             1<<1
#define CONDFLAG_NOTMATCH           1<<2
#define CONDFLAG_ORNEXT             1<<3

#define RULEFLAG_NONE               1<<0
#define RULEFLAG_FORCEREDIRECT      1<<1
#define RULEFLAG_LASTRULE           1<<2
#define RULEFLAG_NEWROUND           1<<3
#define RULEFLAG_CHAIN              1<<4
#define RULEFLAG_IGNOREONSUBREQ     1<<5
#define RULEFLAG_NOTMATCH           1<<6
#define RULEFLAG_PROXY              1<<7
#define RULEFLAG_PASSTHROUGH        1<<8
#define RULEFLAG_FORBIDDEN          1<<9
#define RULEFLAG_GONE               1<<10
#define RULEFLAG_QSAPPEND           1<<11
#define RULEFLAG_NOCASE             1<<12
#define RULEFLAG_NOESCAPE           1<<13

#define ACTION_NORMAL               1<<0
#define ACTION_NOESCAPE             1<<1

#define MAPTYPE_TXT                 1<<0
#define MAPTYPE_DBM                 1<<1
#define MAPTYPE_PRG                 1<<2
#define MAPTYPE_INT                 1<<3
#define MAPTYPE_RND                 1<<4

#define ENGINE_DISABLED             1<<0
#define ENGINE_ENABLED              1<<1

#define OPTION_NONE                 1<<0
#define OPTION_INHERIT              1<<1

#define CACHEMODE_TS                1<<0
#define CACHEMODE_TTL               1<<1

#define CACHE_TLB_ROWS 1024
#define CACHE_TLB_COLS 4

#ifndef FALSE
#define FALSE 0
#define TRUE  !FALSE
#endif

#ifndef NO
#define NO    FALSE
#define YES   TRUE
#endif

#ifndef RAND_MAX
#define RAND_MAX 32767
#endif

#ifndef LONG_STRING_LEN
#define LONG_STRING_LEN 2048
#endif

#define MAX_ENV_FLAGS 15
#define MAX_COOKIE_FLAGS 15
/*** max cookie size in rfc 2109 ***/
#define MAX_COOKIE_LEN 4096

#define MAX_NMATCH    10

/* default maximum number of internal redirects */
#define REWRITE_REDIRECT_LIMIT 10


/*
**
**  our private data structures we handle with
**
*/

    /* the list structures for holding the mapfile information
     * and the rewrite rules
     */
typedef struct {
    const char *name;              /* the name of the map */
    const char *datafile;          /* filename for map data files */
    const char *dbmtype;           /* dbm type for dbm map data files */
    const char *checkfile;         /* filename to check for map existence */
    int   type;                    /* the type of the map */
    apr_file_t *fpin;               /* in  file pointer for program maps */
    apr_file_t *fpout;              /* out file pointer for program maps */
    apr_file_t *fperr;              /* err file pointer for program maps */
    char *(*func)(request_rec *,   /* function pointer for internal maps */
                  char *);
    char **argv;
} rewritemap_entry;

typedef struct {
    char    *input;                /* Input string of RewriteCond */
    char    *pattern;              /* the RegExp pattern string */
    regex_t *regexp;
    int      flags;                /* Flags which control the match */
} rewritecond_entry;

typedef struct {
    apr_array_header_t *rewriteconds;    /* the corresponding RewriteCond entries */
    char    *pattern;              /* the RegExp pattern string */
    regex_t *regexp;               /* the RegExp pattern compilation */
    char    *output;               /* the Substitution string */
    int      flags;                /* Flags which control the substitution */
    char    *forced_mimetype;      /* forced MIME type of substitution */
    int      forced_responsecode;  /* forced HTTP redirect response status */
    char    *env[MAX_ENV_FLAGS+1]; /* added environment variables */
    char    *cookie[MAX_COOKIE_FLAGS+1]; /* added cookies */
    int      skip;                 /* number of next rules to skip */
} rewriterule_entry;


    /* the per-server or per-virtual-server configuration
     * statically generated once on startup for every server
     */
typedef struct {
    int           state;           /* the RewriteEngine state */
    int           options;         /* the RewriteOption state */
    const char   *rewritelogfile;  /* the RewriteLog filename */
    apr_file_t   *rewritelogfp;    /* the RewriteLog open filepointer */
    int           rewriteloglevel; /* the RewriteLog level of verbosity */
    apr_array_header_t *rewritemaps;     /* the RewriteMap entries */
    apr_array_header_t *rewriteconds;    /* the RewriteCond entries (temporary) */
    apr_array_header_t *rewriterules;    /* the RewriteRule entries */
    server_rec   *server;          /* the corresponding server indicator */
    int          redirect_limit;   /* maximum number of internal redirects */
} rewrite_server_conf;


    /* the per-directory configuration
     * generated on-the-fly by Apache server for current request
     */
typedef struct {
    int           state;           /* the RewriteEngine state */
    int           options;         /* the RewriteOption state */
    apr_array_header_t *rewriteconds;    /* the RewriteCond entries (temporary) */
    apr_array_header_t *rewriterules;    /* the RewriteRule entries */
    char         *directory;       /* the directory where it applies */
    const char   *baseurl;         /* the base-URL  where it applies */
    int          redirect_limit;   /* maximum number of internal redirects */
} rewrite_perdir_conf;


    /* the per-request configuration
     */
typedef struct {
    int           redirects;       /* current number of redirects */
    int           redirect_limit;  /* maximum number of redirects */
} rewrite_request_conf;


    /* the cache structures,
     * a 4-way hash apr_table_t with LRU functionality
     */
typedef struct cacheentry {
    apr_time_t time;
    char  *key;
    char  *value;
} cacheentry;

typedef struct tlbentry {
    int t[CACHE_TLB_COLS];
} cachetlbentry;

typedef struct cachelist {
    char         *resource;
    apr_array_header_t *entries;
    apr_array_header_t *tlb;
} cachelist;

typedef struct cache {
    apr_pool_t         *pool;
    apr_array_header_t *lists;
#if APR_HAS_THREADS
    apr_thread_mutex_t *lock;
#endif
} cache;


    /* the regex structure for the
     * substitution of backreferences
     */
typedef struct backrefinfo {
    char *source;
    int nsub;
    regmatch_t regmatch[10];
} backrefinfo;


/*
**
**  forward declarations
**
*/

    /* config structure handling */
static void *config_server_create(apr_pool_t *p, server_rec *s);
static void *config_server_merge (apr_pool_t *p, void *basev, void *overridesv);
static void *config_perdir_create(apr_pool_t *p, char *path);
static void *config_perdir_merge (apr_pool_t *p, void *basev, void *overridesv);

    /* config directive handling */
static const char *cmd_rewriteengine(cmd_parms *cmd,
                                     void *dconf, int flag);
static const char *cmd_rewriteoptions(cmd_parms *cmd,
                                      void *dconf,
                                      const char *option);
static const char *cmd_rewritelog     (cmd_parms *cmd, void *dconf, const char *a1);
static const char *cmd_rewriteloglevel(cmd_parms *cmd, void *dconf, const char *a1);
static const char *cmd_rewritemap     (cmd_parms *cmd, void *dconf, 
                                       const char *a1, const char *a2);
static const char *cmd_rewritelock(cmd_parms *cmd, void *dconf, const char *a1);
static const char *cmd_rewritebase(cmd_parms *cmd, void *dconf,
                                   const char *a1);
static const char *cmd_rewritecond(cmd_parms *cmd, void *dconf,
                                   const char *str);
static const char *cmd_rewritecond_parseflagfield(apr_pool_t *p,
                                                  rewritecond_entry *new,
                                                  char *str);
static const char *cmd_rewritecond_setflag(apr_pool_t *p, rewritecond_entry *cfg,
                                           char *key, char *val);
static const char *cmd_rewriterule(cmd_parms *cmd, void *dconf,
                                   const char *str);
static const char *cmd_rewriterule_parseflagfield(apr_pool_t *p,
                                                  rewriterule_entry *new,
                                                  char *str);
static const char *cmd_rewriterule_setflag(apr_pool_t *p, rewriterule_entry *cfg,
                                           char *key, char *val);

    /* initialisation */
static int pre_config(apr_pool_t *pconf,
                      apr_pool_t *plog,
                      apr_pool_t *ptemp);
static int post_config(apr_pool_t *pconf,
                       apr_pool_t *plog,
                       apr_pool_t *ptemp,
                       server_rec *s);
static void init_child(apr_pool_t *p, server_rec *s);

    /* runtime hooks */
static int hook_uri2file   (request_rec *r);
static int hook_mimetype   (request_rec *r);
static int hook_fixup      (request_rec *r);
static int handler_redirect(request_rec *r);

    /* rewriting engine */
static int apply_rewrite_list(request_rec *r, apr_array_header_t *rewriterules,
                              char *perdir);
static int apply_rewrite_rule(request_rec *r, rewriterule_entry *p,
                              char *perdir);
static int apply_rewrite_cond(request_rec *r, rewritecond_entry *p,
                              char *perdir, backrefinfo *briRR,
                              backrefinfo *briRC);

static void do_expand(request_rec *r, char *input, char *buffer, int nbuf,
		      backrefinfo *briRR, backrefinfo *briRC);
static void do_expand_env(request_rec *r, char *env[],
			  backrefinfo *briRR, backrefinfo *briRC);
static void do_expand_cookie(request_rec *r, char *cookie[],
			  backrefinfo *briRR, backrefinfo *briRC);

    /* URI transformation function */
static void  splitout_queryargs(request_rec *r, int qsappend);
static void  fully_qualify_uri(request_rec *r);
static void  reduce_uri(request_rec *r);
static unsigned is_absolute_uri(char *uri);
static char *escape_absolute_uri(apr_pool_t *p, char *uri, unsigned scheme);
static char *expand_tildepaths(request_rec *r, char *uri);

    /* rewrite map support functions */
static char *lookup_map(request_rec *r, char *name, char *key);
static char *lookup_map_txtfile(request_rec *r, const char *file, char *key);
static char *lookup_map_dbmfile(request_rec *r, const char *file, 
                                const char *dbmtype, char *key);
static char *lookup_map_program(request_rec *r, apr_file_t *fpin,
                                apr_file_t *fpout, char *key);

typedef char *(rewrite_mapfunc_t)(request_rec *r, char *key);
static void ap_register_rewrite_mapfunc(char *name, rewrite_mapfunc_t *func);
APR_DECLARE_OPTIONAL_FN(void, ap_register_rewrite_mapfunc,
                        (char *name, rewrite_mapfunc_t *func));

static char *rewrite_mapfunc_toupper(request_rec *r, char *key);
static char *rewrite_mapfunc_tolower(request_rec *r, char *key);
static char *rewrite_mapfunc_escape(request_rec *r, char *key);
static char *rewrite_mapfunc_unescape(request_rec *r, char *key);

static char *select_random_value_part(request_rec *r, char *value);
static void  rewrite_rand_init(void);
static int   rewrite_rand(int l, int h);

    /* rewriting logfile support */
static void  open_rewritelog(server_rec *s, apr_pool_t *p);
static void  rewritelog(request_rec *r, int level, const char *text, ...)
                        __attribute__((format(printf,3,4)));
static char *current_logtime(request_rec *r);

    /* rewriting lockfile support */
static apr_status_t rewritelock_create(server_rec *s, apr_pool_t *p);
static apr_status_t rewritelock_remove(void *data);

    /* program map support */
static apr_status_t run_rewritemap_programs(server_rec *s, apr_pool_t *p);
static apr_status_t rewritemap_program_child(apr_pool_t *p, 
                                             const char *progname, char **argv,
                                             apr_file_t **fpout,
                                             apr_file_t **fpin);

    /* env variable support */
static char *lookup_variable(request_rec *r, char *var);
static const char *lookup_header(request_rec *r, const char *name);

    /* caching functions */
static cache *init_cache(apr_pool_t *p);
static char  *get_cache_string(cache *c, const char *res, int mode, apr_time_t mtime,
                               char *key);
static void   set_cache_string(cache *c, const char *res, int mode, apr_time_t mtime,
                               char *key, char *value);
static cacheentry *retrieve_cache_string(cache *c, const char *res, char *key);
static void   store_cache_string(cache *c, const char *res, cacheentry *ce);

    /* misc functions */
static char  *subst_prefix_path(request_rec *r, char *input, char *match,
                                const char *subst);
static int    parseargline(char *str, char **a1, char **a2, char **a3);
static int    prefix_stat(const char *path, apr_pool_t *pool);
static void   add_env_variable(request_rec *r, char *s);
static void   add_cookie(request_rec *r, char *s);
static int    subreq_ok(request_rec *r);
static int    is_redirect_limit_exceeded(request_rec *r);

    /* Lexicographic Comparison */
static int compare_lexicography(char *cpNum1, char *cpNum2);

    /* Bracketed expression handling */
static char *find_closing_bracket(char *s, int left, int right);
static char *find_char_in_brackets(char *s, int c, int left, int right);

#endif /* MOD_REWRITE_H */
