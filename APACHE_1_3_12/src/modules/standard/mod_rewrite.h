/* ====================================================================
 * Copyright (c) 1996-1999 The Apache Group.  All rights reserved.
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
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
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


#ifndef _MOD_REWRITE_H
#define _MOD_REWRITE_H 1

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
**  gifted exclusively to the The Apache Group in July 1997 by
**
**      Ralf S. Engelschall
**      rse@engelschall.com
**      www.engelschall.com
*/


    /* Include from the underlaying Unix system ... */
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#ifndef NETWARE
#include <sys/types.h>
#endif
#include <sys/stat.h>

    /* Include from the Apache server ... */
#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_conf_globals.h"
#include "http_request.h"
#include "http_core.h"
#include "http_log.h"
#include "http_vhost.h"

    /*
     * The key in the r->notes table wherein we store our accumulated
     * Vary values, and the one used for per-condition checks in a chain.
     */
#define VARY_KEY "rewrite-Vary"
#define VARY_KEY_THIS "rewrite-Vary-this"

    /* The NDBM support:
     * We support only NDBM files.
     * But we have to stat the file for the mtime,
     * so we also need to know the file extension
     */
#ifndef NO_DBM_REWRITEMAP
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) \
    && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
#include <db1/ndbm.h>
#else
#include <ndbm.h>
#endif
#if defined(DBM_SUFFIX)
#define NDBM_FILE_SUFFIX DBM_SUFFIX
#elif defined(__FreeBSD__) || (defined(DB_LOCK) && defined(DB_SHMEM))
#define NDBM_FILE_SUFFIX ".db"
#else
#define NDBM_FILE_SUFFIX ".pag"
#endif
#endif


    /* The locking support:
     * Try to determine whether we should use fcntl() or flock().
     * Would be better ap_config.h could provide this... :-(
     */
#if defined(USE_FCNTL_SERIALIZED_ACCEPT)
#define USE_FCNTL 1
#include <fcntl.h>
#endif
#if defined(USE_FLOCK_SERIALIZED_ACCEPT)
#define USE_FLOCK 1
#include <sys/file.h>
#endif
#if !defined(USE_FCNTL) && !defined(USE_FLOCK)
#define USE_FLOCK 1
#if !defined(MPE) && !defined(WIN32) && !defined(__TANDEM) && !defined(NETWARE)
#include <sys/file.h>
#endif
#ifndef LOCK_UN
#undef USE_FLOCK
#define USE_FCNTL 1
#include <fcntl.h>
#endif
#endif
#ifdef AIX
#undef USE_FLOCK
#define USE_FCNTL 1
#include <fcntl.h>
#endif
#ifdef WIN32
#undef USE_FCNTL
#define USE_LOCKING
#include <sys/locking.h>
#endif


/*
**
**  Some defines
**
*/

#define ENVVAR_SCRIPT_URL "SCRIPT_URL"
#define ENVVAR_SCRIPT_URI "SCRIPT_URI"

#ifndef SUPPORT_DBM_REWRITEMAP
#define SUPPORT_DBM_REWRITEMAP 0
#endif

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

#define MAX_NMATCH    10

/*
**
**  our private data structures we handle with
**
*/

    /* the list structures for holding the mapfile information
     * and the rewrite rules
     */
typedef struct {
    char *name;                    /* the name of the map */
    char *datafile;                /* filename for map data files */
    char *checkfile;               /* filename to check for map existence */
    int   type;                    /* the type of the map */
    int   fpin;                    /* in  file pointer for program maps */
    int   fpout;                   /* out file pointer for program maps */
    int   fperr;                   /* err file pointer for program maps */
    char *(*func)(request_rec *,   /* function pointer for internal maps */
                  char *);
} rewritemap_entry;

typedef struct {
    char    *input;                /* Input string of RewriteCond */
    char    *pattern;              /* the RegExp pattern string */
    regex_t *regexp;
    int      flags;                /* Flags which control the match */
} rewritecond_entry;

typedef struct {
    array_header *rewriteconds;    /* the corresponding RewriteCond entries */
    char    *pattern;              /* the RegExp pattern string */
    regex_t *regexp;               /* the RegExp pattern compilation */
    char    *output;               /* the Substitution string */
    int      flags;                /* Flags which control the substitution */
    char    *forced_mimetype;      /* forced MIME type of substitution */
    int      forced_responsecode;  /* forced HTTP redirect response status */
    char    *env[MAX_ENV_FLAGS+1]; /* added environment variables */
    int      skip;                 /* number of next rules to skip */
} rewriterule_entry;


    /* the per-server or per-virtual-server configuration
     * statically generated once on startup for every server
     */
typedef struct {
    int           state;           /* the RewriteEngine state */
    int           options;         /* the RewriteOption state */
    char         *rewritelogfile;  /* the RewriteLog filename */
    int           rewritelogfp;    /* the RewriteLog open filepointer */
    int           rewriteloglevel; /* the RewriteLog level of verbosity */
    array_header *rewritemaps;     /* the RewriteMap entries */
    array_header *rewriteconds;    /* the RewriteCond entries (temporary) */
    array_header *rewriterules;    /* the RewriteRule entries */
    server_rec   *server;          /* the corresponding server indicator */
} rewrite_server_conf;


    /* the per-directory configuration
     * generated on-the-fly by Apache server for current request
     */
typedef struct {
    int           state;           /* the RewriteEngine state */
    int           options;         /* the RewriteOption state */
    array_header *rewriteconds;    /* the RewriteCond entries (temporary) */
    array_header *rewriterules;    /* the RewriteRule entries */
    char         *directory;       /* the directory where it applies */
    char         *baseurl;         /* the base-URL  where it applies */
} rewrite_perdir_conf;


    /* the cache structures,
     * a 4-way hash table with LRU functionality
     */
typedef struct cacheentry {
    time_t time;
    char  *key;
    char  *value;
} cacheentry;

typedef struct tlbentry {
    int t[CACHE_TLB_COLS];
} cachetlbentry;

typedef struct cachelist {
    char         *resource;
    array_header *entries;
    array_header *tlb;
} cachelist;

typedef struct cache {
    pool         *pool;
    array_header *lists;
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
static void *config_server_create(pool *p, server_rec *s);
static void *config_server_merge (pool *p, void *basev, void *overridesv);
static void *config_perdir_create(pool *p, char *path);
static void *config_perdir_merge (pool *p, void *basev, void *overridesv);

    /* config directive handling */
static const char *cmd_rewriteengine(cmd_parms *cmd,
                                     rewrite_perdir_conf *dconf, int flag);
static const char *cmd_rewriteoptions(cmd_parms *cmd,
                                      rewrite_perdir_conf *dconf,
                                      char *option);
static const char *cmd_rewriteoptions_setoption(pool *p, int *options,
                                                char *name);
static const char *cmd_rewritelog     (cmd_parms *cmd, void *dconf, char *a1);
static const char *cmd_rewriteloglevel(cmd_parms *cmd, void *dconf, char *a1);
static const char *cmd_rewritemap     (cmd_parms *cmd, void *dconf, char *a1,
                                       char *a2);
static const char *cmd_rewritelock(cmd_parms *cmd, void *dconf, char *a1);
static const char *cmd_rewritebase(cmd_parms *cmd, rewrite_perdir_conf *dconf,
                                   char *a1);
static const char *cmd_rewritecond(cmd_parms *cmd, rewrite_perdir_conf *dconf,
                                   char *str);
static const char *cmd_rewritecond_parseflagfield(pool *p,
                                                  rewritecond_entry *new,
                                                  char *str);
static const char *cmd_rewritecond_setflag(pool *p, rewritecond_entry *cfg,
                                           char *key, char *val);
static const char *cmd_rewriterule(cmd_parms *cmd, rewrite_perdir_conf *dconf,
                                   char *str);
static const char *cmd_rewriterule_parseflagfield(pool *p,
                                                  rewriterule_entry *new,
                                                  char *str);
static const char *cmd_rewriterule_setflag(pool *p, rewriterule_entry *cfg,
                                           char *key, char *val);

    /* initialisation */
static void init_module(server_rec *s, pool *p);
static void init_child(server_rec *s, pool *p);

    /* runtime hooks */
static int hook_uri2file   (request_rec *r);
static int hook_mimetype   (request_rec *r);
static int hook_fixup      (request_rec *r);
static int handler_redirect(request_rec *r);

    /* rewriting engine */
static int apply_rewrite_list(request_rec *r, array_header *rewriterules,
                              char *perdir);
static int apply_rewrite_rule(request_rec *r, rewriterule_entry *p,
                              char *perdir);
static int apply_rewrite_cond(request_rec *r, rewritecond_entry *p,
                              char *perdir, backrefinfo *briRR,
                              backrefinfo *briRC);

    /* URI transformation function */
static void  splitout_queryargs(request_rec *r, int qsappend);
static void  fully_qualify_uri(request_rec *r);
static void  reduce_uri(request_rec *r);
static void  expand_backref_inbuffer(pool *p, char *buf, int nbuf,
                                     backrefinfo *bri, char c);
static char *expand_tildepaths(request_rec *r, char *uri);
static void  expand_map_lookups(request_rec *r, char *uri, int uri_len);

    /* rewrite map support functions */
static char *lookup_map(request_rec *r, char *name, char *key);
static char *lookup_map_txtfile(request_rec *r, char *file, char *key);
#ifndef NO_DBM_REWRITEMAP
static char *lookup_map_dbmfile(request_rec *r, char *file, char *key);
#endif
static char *lookup_map_program(request_rec *r, int fpin,
                                int fpout, char *key);
static char *lookup_map_internal(request_rec *r,
                                 char *(*func)(request_rec *r, char *key),
                                 char *key);
static char *rewrite_mapfunc_toupper(request_rec *r, char *key);
static char *rewrite_mapfunc_tolower(request_rec *r, char *key);
static char *rewrite_mapfunc_escape(request_rec *r, char *key);
static char *rewrite_mapfunc_unescape(request_rec *r, char *key);
static char *select_random_value_part(request_rec *r, char *value);
static void  rewrite_rand_init(void);
static int   rewrite_rand(int l, int h);

    /* rewriting logfile support */
static void  open_rewritelog(server_rec *s, pool *p);
static void  rewritelog(request_rec *r, int level, const char *text, ...)
                        __attribute__((format(printf,3,4)));
static char *current_logtime(request_rec *r);

    /* rewriting lockfile support */
static void rewritelock_create(server_rec *s, pool *p);
static void rewritelock_open(server_rec *s, pool *p);
static void rewritelock_remove(void *data);
static void rewritelock_alloc(request_rec *r);
static void rewritelock_free(request_rec *r);

    /* program map support */
static void  run_rewritemap_programs(server_rec *s, pool *p);
static int   rewritemap_program_child(void *cmd, child_info *pinfo);

    /* env variable support */
static void  expand_variables_inbuffer(request_rec *r, char *buf, int buf_len);
static char *expand_variables(request_rec *r, char *str);
static char *lookup_variable(request_rec *r, char *var);
static char *lookup_header(request_rec *r, const char *name);

    /* caching functions */
static cache *init_cache(pool *p);
static char  *get_cache_string(cache *c, char *res, int mode, time_t mtime,
                               char *key);
static void   set_cache_string(cache *c, char *res, int mode, time_t mtime,
                               char *key, char *value);
static cacheentry *retrieve_cache_string(cache *c, char *res, char *key);
static void   store_cache_string(cache *c, char *res, cacheentry *ce);

    /* misc functions */
static char  *subst_prefix_path(request_rec *r, char *input, char *match,
                                char *subst);
static int    parseargline(char *str, char **a1, char **a2, char **a3);
static int    prefix_stat(const char *path, struct stat *sb);
static void   add_env_variable(request_rec *r, char *s);

    /* File locking */
static void fd_lock(request_rec *r, int fd);
static void fd_unlock(request_rec *r, int fd);

    /* Lexicographic Comparison */
static int compare_lexicography(char *cpNum1, char *cpNum2);

#endif /* _MOD_REWRITE_H */

/*EOF*/
