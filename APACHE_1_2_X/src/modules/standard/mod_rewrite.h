
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




    /* The NDBM support:
       We support only NDBM files. 
       But we have to stat the file for the mtime,
       so we also need to know the file extension */
#if HAS_NDBM_LIB
#include <ndbm.h>
#if (__FreeBSD__)
#define NDBM_FILE_SUFFIX ".db"
#else 
#define NDBM_FILE_SUFFIX ".pag"
#endif
#endif


    /* The locking support:
       Try to determine whether we should use fcntl() or flock().
       Would be better conf.h could provide this... :-( */
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
#ifndef MPE
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

    /* The locking support for the RewriteMap programs:
       Locking a pipe to the child works fine under most
       Unix derivates, but braindead SunOS 4.1.x has 
       problems with this approach... */
#define USE_PIPE_LOCKING 1
#ifdef SUNOS4
#undef USE_PIPE_LOCKING
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

#define MAPTYPE_TXT                 1<<0
#define MAPTYPE_DBM                 1<<1
#define MAPTYPE_PRG                 1<<2

#define ENGINE_DISABLED             1<<0
#define ENGINE_ENABLED              1<<1

#define OPTION_NONE                 1<<0
#define OPTION_INHERIT              1<<1

#define CACHEMODE_TS                1<<0
#define CACHEMODE_TTL               1<<1

#ifndef FALSE
#define FALSE 0
#define TRUE  !FALSE
#endif

#ifndef NO
#define NO    FALSE
#define YES   TRUE
#endif

#ifndef LONG_STRING_LEN
#define LONG_STRING_LEN 2048
#endif

#define MAX_ENV_FLAGS 5

#define EOS_PARANOIA(ca) ca[sizeof(ca)-1] = '\0'


/*
**
**  our private data structures we handle with
**
*/

    /* the list structures for holding the mapfile information
       and the rewrite rules */

typedef struct {
    char *name;                    /* the name of the map */
    char *datafile;                /* the file which contains the data of the map */
    char *checkfile;               /* the file which stays for existence of the map */
    int   type;                    /* the type of the map */
    int   fpin;                    /* in  filepointer for program maps */
    int   fpout;                   /* out filepointer for program maps */
} rewritemap_entry;

typedef struct {
    char    *input;                /* Input string of RewriteCond */
    char    *pattern;              /* the RegExp pattern string */
    regex_t *regexp;
    int      flags;                /* Flags which control the match */
} rewritecond_entry;

typedef struct {
    array_header *rewriteconds;    /* the corresponding RewriteCond entries */
    char         *pattern;         /* the RegExp pattern string */
    regex_t      *regexp;          /* the RegExp pattern compilation */
    char         *output;              /* the Substitution string */
    int           flags;               /* Flags which control the substitution */
    char         *forced_mimetype;     /* forced MIME type of substitution */
    int           forced_responsecode; /* forced HTTP redirect response status */
    char         *env[MAX_ENV_FLAGS+1];/* added environment variables */
    int           skip;                /* number of next rules to skip */
} rewriterule_entry;


    /* the per-server or per-virtual-server configuration
       statically generated once on startup for every server */

typedef struct {
    int           state;           /* the RewriteEngine state */
    int           options;         /* the RewriteOption state */
    char         *rewritelogfile;  /* the RewriteLog filename */
    int           rewritelogfp;    /* the RewriteLog open filepointer */
    int           rewriteloglevel; /* the RewriteLog level of verbosity */
    array_header *rewritemaps;     /* the RewriteMap entries */
    array_header *rewriteconds;    /* the RewriteCond entries (temporary) */
    array_header *rewriterules;    /* the RewriteRule entries */
} rewrite_server_conf;


    /* the per-directory configuration
       individually generated on-the-fly by Apache server for current request */

typedef struct {
    int           state;           /* the RewriteEngine state */
    int           options;         /* the RewriteOption state */
    array_header *rewriteconds;    /* the RewriteCond entries (temporary) */
    array_header *rewriterules;    /* the RewriteRule entries */
    char         *directory;       /* the directory where it applies */
    char         *baseurl;         /* the base-URL  where it applies */
} rewrite_perdir_conf;


    /* the cache structures */

typedef struct cacheentry {
    time_t time;
    char  *key;
    char  *value;
} cacheentry;

typedef struct cachelist {
    char         *resource;
    array_header *entries;
} cachelist;

typedef struct cache {
    pool         *pool;
    array_header *lists;
} cache;


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
static const char *cmd_rewriteengine  (cmd_parms *cmd, rewrite_perdir_conf *dconf, int flag);
static const char *cmd_rewriteoptions (cmd_parms *cmd, rewrite_perdir_conf *dconf, char *option);
static const char *cmd_rewriteoptions_setoption(pool *p, int *options, char *name);
static const char *cmd_rewritelog     (cmd_parms *cmd, void *dconf, char *a1);
static const char *cmd_rewriteloglevel(cmd_parms *cmd, void *dconf, char *a1);
static const char *cmd_rewritemap     (cmd_parms *cmd, void *dconf, char *a1, char *a2);

static const char *cmd_rewritebase(cmd_parms *cmd, rewrite_perdir_conf *dconf, char *a1);

static const char *cmd_rewritecond    (cmd_parms *cmd, rewrite_perdir_conf *dconf, char *str);
static const char *cmd_rewritecond_parseflagfield(pool *p, rewritecond_entry *new, char *str);
static const char *cmd_rewritecond_setflag       (pool *p, rewritecond_entry *cfg, char *key, char *val);

extern const char *cmd_rewriterule    (cmd_parms *cmd, rewrite_perdir_conf *dconf, char *str);
static const char *cmd_rewriterule_parseflagfield(pool *p, rewriterule_entry *new, char *str);
static const char *cmd_rewriterule_setflag       (pool *p, rewriterule_entry *cfg, char *key, char *val);

    /* initialisation */
static void init_module(server_rec *s, pool *p);

    /* runtime hooks */
static int hook_uri2file   (request_rec *r);
static int hook_mimetype   (request_rec *r);
static int hook_fixup      (request_rec *r);
static int handler_redirect(request_rec *r);

    /* rewriting engine */
static int apply_rewrite_list(request_rec *r, array_header *rewriterules, char *perdir);
static int apply_rewrite_rule(request_rec *r, rewriterule_entry *p, char *perdir); 
static int apply_rewrite_cond(request_rec *r, rewritecond_entry *p, char *perdir); 

    /* URI transformation function */
static void  splitout_queryargs(request_rec *r, int qsappend);
static void  reduce_uri(request_rec *r);
static char *expand_tildepaths(request_rec *r, char *uri);
static void  expand_map_lookups(request_rec *r, char *uri, int uri_len);

    /* DBM hashfile support functions */
static char *lookup_map(request_rec *r, char *name, char *key);
static char *lookup_map_txtfile(request_rec *r, char *file, char *key);
#if HAS_NDBM_LIB
static char *lookup_map_dbmfile(request_rec *r, char *file, char *key);
#endif
static char *lookup_map_program(request_rec *r, int fpin, int fpout, char *key);

    /* rewriting logfile support */
static void  open_rewritelog(server_rec *s, pool *p);
static void  rewritelog_child(void *cmd);
static void  rewritelog(request_rec *r, int level, const char *text, ...);
static char *current_logtime(request_rec *r);

    /* program map support */
static void  run_rewritemap_programs(server_rec *s, pool *p);
static void  rewritemap_program_child(void *cmd);

    /* env variable support */
static void  expand_variables_inbuffer(request_rec *r, char *buf, int buf_len);
static char *expand_variables(request_rec *r, char *str);
static char *lookup_variable(request_rec *r, char *var);
static char *lookup_header(request_rec *r, const char *name);

    /* caching functions */
static cache      *init_cache(pool *p);
static char       *get_cache_string(cache *c, char *res, int mode, time_t mtime, char *key);
static void        set_cache_string(cache *c, char *res, int mode, time_t mtime, char *key, char *value);
static cacheentry *retrieve_cache_string(cache *c, char *res, char *key);
static void        store_cache_string(cache *c, char *res, cacheentry *ce);

    /* misc functions */
static char  *subst_prefix_path(request_rec *r, char *input, char *match, char *subst);
static int    parseargline(char *str, char **a1, char **a2, char **a3);
static int    prefix_stat(const char *path, struct stat *sb);
static void   add_env_variable(request_rec *r, char *s);

    /* DNS functions */
static int    is_this_our_host(request_rec *r, char *testhost);
static int    isaddr(char *host);
static char **resolv_ipaddr_list(request_rec *r, char *name);

    /* Proxy Module check */
static int is_proxy_available(server_rec *s);

    /* File locking */
static void fd_lock(int fd);
static void fd_unlock(int fd);

    /* Lexicographic Comparison */
static int compare_lexicography(char *cpNum1, char *cpNum2);

#endif /* _MOD_REWRITE_H */

/*EOF*/
