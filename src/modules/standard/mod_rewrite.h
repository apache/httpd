/* ====================================================================
 * Copyright (c) 1996 The Apache Group.  All rights reserved.
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

/* $Id: mod_rewrite.h,v 1.4 1996/08/20 11:51:19 paul Exp $ */

#ifndef _MOD_REWRITE_H
#define _MOD_REWRITE_H 1

/*
**  mod_rewrite.h
**
**  URL Rewriting Module Header, Version 2.2 (xx-08-1996)
**
**  This module uses a regular-expression parser to rewrite requested URLs
**  on the fly. It can use external databases (either plain text, or
**  DBM) to provide a mapping function or generate real URIs (including
**  QUERY_INFO parts) for internal subprocessing or external request
**  redirection.
**
**  The documentation and latest release can be found on
**  http://www.engelschall.com/sw/mod_rewrite/
**
**  Copyright (c) 1996 The Apache Group
**  Copyright (c) 1996 Ralf S. Engelschall
**
**  Written for The Apache Group by
**      Ralf S. Engelschall
**      rse@engelschall.com
**      http://www.engelschall.com/~rse
*/




   /* try to see under which version we are running */
#if (MODULE_MAGIC_NUMBER >= 19960725)
#define HAVE_INTERNAL_REGEX 1
#endif

    /* now we go on and include more of our own stuff ... */
#ifndef HAVE_INTERNAL_REGEX
#include "regexp/regexp.h"
#endif
#if SUPPORT_DBM_REWRITEMAP
#include "sdbm/sdbm.h"
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

#define MAPTYPE_TXT                 1<<0
#define MAPTYPE_DBM                 1<<1
#define MAPTYPE_PRG                 1<<2

#define ENGINE_DISABLED             1<<0
#define ENGINE_ENABLED              1<<1

#define CACHEMODE_TS  1<<0
#define CACHEMODE_TTL 1<<1


/*
**
**  our private data structures we handle with
**
*/

    /* the list structures for holding the mapfile information
       and the rewrite rules */

typedef struct {
    char *name;                    /* the name of the map */
    char *file;                    /* the file of the map */
    int   type;                    /* the type of the map */
    int   fpin;                    /* in  filepointer for program maps */
    int   fpout;                   /* out filepointer for program maps */
} rewritemap_entry;

typedef struct {
    char   *input;                 /* Input string of RewriteCond */
    char   *pattern;               /* the RegExp pattern string */
#ifdef HAVE_INTERNAL_REGEX
    regex_t *regexp;
#else
    regexp *regexp;                /* the RegExp pattern compilation */
#endif
    int     flags;                 /* Flags which control the match */
} rewritecond_entry;

typedef struct {
    array_header *rewriteconds;    /* the corresponding RewriteCond entries */
    char         *pattern;         /* the RegExp pattern string */
#ifdef HAVE_INTERNAL_REGEX
    regex_t      *regexp;          /* the RegExp pattern compilation */
#else
    regexp       *regexp;
#endif
    char         *output;          /* the Substitution string */
    int           flags;           /* Flags which control the substitution */
    char         *forced_mimetype; /* forced MIME-type of substitution */
    int           skip;            /* number of next rules to skip */
} rewriterule_entry;

    /* the per-server or per-virtual-server configuration
       statically generated once on startup for every server */

typedef struct {
    int           state;           /* the RewriteEngine state */
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
    array_header *rewriteconds;    /* the RewriteCond entries (temporary) */
    array_header *rewriterules;    /* the RewriteRule entries */
    char *directory;               /* the directory where it applies */
    char *baseurl;                 /* the base-URL  where it applies */
} rewrite_perdir_conf;


    /* the cache structures */

typedef struct cacheentry {
    time_t time;
    char  *key;
    char  *value;
} cacheentry;

typedef struct cachelist {
    char  *resource;
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

    /* static config */
static command_rec command_table[];
static handler_rec handler_table[];

    /* config structure handling */
static void *config_server_create(pool *p, server_rec *s);
static void *config_server_merge (pool *p, void *basev, void *overridesv);
static void *config_perdir_create(pool *p, char *path);
static void *config_perdir_merge (pool *p, void *basev, void *overridesv);

    /* config directive handling */
static char *cmd_rewriteengine  (cmd_parms *cmd, rewrite_perdir_conf *dconf, int flag);
static char *cmd_rewritelog     (cmd_parms *cmd, void *dconf, char *a1);
static char *cmd_rewriteloglevel(cmd_parms *cmd, void *dconf, char *a1);
static char *cmd_rewritemap     (cmd_parms *cmd, void *dconf, char *a1, char *a2);

static char *cmd_rewritebase(cmd_parms *cmd, rewrite_perdir_conf *dconf, char *a1);

static char *cmd_rewritecond    (cmd_parms *cmd, rewrite_perdir_conf *dconf, char *str);
static char *cmd_rewritecond_parseflagfield(pool *p, rewritecond_entry *new, char *str);
static char *cmd_rewritecond_setflag       (pool *p, rewritecond_entry *cfg, char *key, char *val);

       char *cmd_rewriterule    (cmd_parms *cmd, rewrite_perdir_conf *dconf, char *str);
static char *cmd_rewriterule_parseflagfield(pool *p, rewriterule_entry *new, char *str);
static char *cmd_rewriterule_setflag       (pool *p, rewriterule_entry *cfg, char *key, char *val);

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
static void splitout_queryargs(request_rec *r);
static void reduce_uri(request_rec *r);
static char *expand_tildepaths(request_rec *r, char *uri);
static void expand_map_lookups(request_rec *r, char *uri);

    /* DBM hashfile support functions */
static char *lookup_map(request_rec *r, char *name, char *key);
static char *lookup_map_txtfile(request_rec *r, char *file, char *key);
#if SUPPORT_DBM_REWRITEMAP
static char *lookup_map_dbmfile(request_rec *r, char *file, char *key);
#endif
static char *lookup_map_program(request_rec *r, int fpin, int fpout, char *key);

    /* rewriting logfile support */
static void  open_rewritelog(server_rec *s, pool *p);
static void  rewritelog_child(void *cmd);
static void  rewritelog(request_rec *r, int level, char *text, ...);
static char *current_logtime(request_rec *r);

    /* program map support */
static void  run_rewritemap_programs(server_rec *s, pool *p);
static void  rewritemap_program_child(void *cmd);

    /* env variable support */
static void  expand_variables_inbuffer(request_rec *r, char *buf);
static char *expand_variables(request_rec *r, char *str);
static char *lookup_variable(request_rec *r, char *var);
static char *lookup_header(request_rec *r, char *name);

    /* caching functions */
static cache      *init_cache(pool *p);
static char       *get_cache_string(cache *c, char *res, int mode, time_t time, char *key);
static void        set_cache_string(cache *c, char *res, int mode, time_t time, char *key, char *value);
static cacheentry *retrieve_cache_string(cache *c, char *res, char *key);
static void        store_cache_string(cache *c, char *res, cacheentry *ce);

    /* misc functions */
static char  *subst_prefix_path(request_rec *r, char *input, char *match, char *subst);
static int    parseargline(char *str, char **a1, char **a2, char **a3);
static int    prefix_stat(const char *path, struct stat *sb);
static int    is_this_our_host(request_rec *r, char *testhost);
static char **make_hostname_list(request_rec *r, char *hostname);


#endif /* _MOD_REWRITE_H */
/*EOF*/
