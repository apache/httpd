/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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

#ifndef APACHE_HTTP_CORE_H
#define APACHE_HTTP_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************
 *
 * The most basic server code is encapsulated in a single module
 * known as the core, which is just *barely* functional enough to
 * serve documents, though not terribly well.
 *
 * Largely for NCSA back-compatibility reasons, the core needs to
 * make pieces of its config structures available to other modules.
 * The accessors are declared here, along with the interpretation
 * of one of them (allow_options).
 */

#define OPT_NONE 0
#define OPT_INDEXES 1
#define OPT_INCLUDES 2
#define OPT_SYM_LINKS 4
#define OPT_EXECCGI 8
#define OPT_UNSET 16
#define OPT_INCNOEXEC 32
#define OPT_SYM_OWNER 64
#define OPT_MULTI 128
#define OPT_ALL (OPT_INDEXES|OPT_INCLUDES|OPT_SYM_LINKS|OPT_EXECCGI)

/* options for get_remote_host() */
/* REMOTE_HOST returns the hostname, or NULL if the hostname
 * lookup fails.  It will force a DNS lookup according to the
 * HostnameLookups setting.
 */
#define REMOTE_HOST (0)

/* REMOTE_NAME returns the hostname, or the dotted quad if the
 * hostname lookup fails.  It will force a DNS lookup according
 * to the HostnameLookups setting.
 */
#define REMOTE_NAME (1)

/* REMOTE_NOLOOKUP is like REMOTE_NAME except that a DNS lookup is
 * never forced.
 */
#define REMOTE_NOLOOKUP (2)

/* REMOTE_DOUBLE_REV will always force a DNS lookup, and also force
 * a double reverse lookup, regardless of the HostnameLookups
 * setting.  The result is the (double reverse checked) hostname,
 * or NULL if any of the lookups fail.
 */
#define REMOTE_DOUBLE_REV (3)

#define SATISFY_ALL 0
#define SATISFY_ANY 1
#define SATISFY_NOSPEC 2

API_EXPORT(int) ap_allow_options (request_rec *);
API_EXPORT(int) ap_allow_overrides (request_rec *);
API_EXPORT(const char *) ap_default_type (request_rec *);     
API_EXPORT(const char *) ap_document_root (request_rec *); /* Don't use this!  If your request went
				      * through a Userdir, or something like
				      * that, it'll screw you.  But it's
				      * back-compatible...
				      */
API_EXPORT(const char *) ap_get_remote_host(conn_rec *conn, void *dir_config, int type);
API_EXPORT(const char *) ap_get_remote_logname(request_rec *r);

/* Used for constructing self-referencing URLs, and things like SERVER_PORT,
 * and SERVER_NAME.
 */
API_EXPORT(char *) ap_construct_url(pool *p, const char *uri, request_rec *r);
API_EXPORT(const char *) ap_get_server_name(request_rec *r);
API_EXPORT(unsigned) ap_get_server_port(const request_rec *r);
API_EXPORT(unsigned long) ap_get_limit_req_body(const request_rec *r);
API_EXPORT(void) ap_custom_response(request_rec *r, int status, char *string);
API_EXPORT(int) ap_exists_config_define(char *name);

/* Authentication stuff.  This is one of the places where compatibility
 * with the old config files *really* hurts; they don't discriminate at
 * all between different authentication schemes, meaning that we need
 * to maintain common state for all of them in the core, and make it
 * available to the other modules through interfaces.
 */
    
typedef struct {
    int method_mask;
    char *requirement;
} require_line;
     
API_EXPORT(const char *) ap_auth_type (request_rec *);
API_EXPORT(const char *) ap_auth_name (request_rec *);     
API_EXPORT(int) ap_satisfies (request_rec *r);
API_EXPORT(const array_header *) ap_requires (request_rec *);    

#ifdef WIN32
/* 
 * CGI Script stuff for Win32...
 */
typedef enum { eFileTypeUNKNOWN, eFileTypeBIN, eFileTypeEXE16, eFileTypeEXE32, 
               eFileTypeSCRIPT } file_type_e;
typedef enum { INTERPRETER_SOURCE_UNSET, INTERPRETER_SOURCE_REGISTRY, 
               INTERPRETER_SOURCE_SHEBANG } interpreter_source_e;
API_EXPORT(file_type_e) ap_get_win32_interpreter(const request_rec *, char **);
#endif

#ifdef CORE_PRIVATE

/*
 * Core is also unlike other modules in being implemented in more than
 * one file... so, data structures are declared here, even though most of
 * the code that cares really is in http_core.c.  Also, another accessor.
 */

char *ap_response_code_string (request_rec *r, int error_index);

extern API_VAR_EXPORT module core_module;

/* Per-directory configuration */

typedef unsigned char allow_options_t;
typedef unsigned char overrides_t;

typedef struct {
    /* path of the directory/regex/etc.  see also d_is_fnmatch below */
    char *d;
    /* the number of slashes in d */
    unsigned d_components;

    /* If (opts & OPT_UNSET) then no absolute assignment to options has
     * been made.
     * invariant: (opts_add & opts_remove) == 0
     * Which said another way means that the last relative (options + or -)
     * assignment made to each bit is recorded in exactly one of opts_add
     * or opts_remove.
     */
    allow_options_t opts;
    allow_options_t opts_add;
    allow_options_t opts_remove;
    overrides_t override;
    
    /* MIME typing --- the core doesn't do anything at all with this,
     * but it does know what to slap on a request for a document which
     * goes untyped by other mechanisms before it slips out the door...
     */
    
    char *ap_default_type;
  
    /* Authentication stuff.  Groan... */
    
    int satisfy;
    char *ap_auth_type;
    char *ap_auth_name;
    array_header *ap_requires;

    /* Custom response config. These can contain text or a URL to redirect to.
     * if response_code_strings is NULL then there are none in the config,
     * if it's not null then it's allocated to sizeof(char*)*RESPONSE_CODES.
     * This lets us do quick merges in merge_core_dir_configs().
     */
  
    char **response_code_strings;

    /* Hostname resolution etc */
#define HOSTNAME_LOOKUP_OFF	0
#define HOSTNAME_LOOKUP_ON	1
#define HOSTNAME_LOOKUP_DOUBLE	2
#define HOSTNAME_LOOKUP_UNSET	3
    unsigned int hostname_lookups : 4;

    signed int do_rfc1413 : 2;   /* See if client is advertising a username? */

    signed int content_md5 : 2;  /* calculate Content-MD5? */

#define USE_CANONICAL_NAME_OFF   (0)
#define USE_CANONICAL_NAME_ON    (1)
#define USE_CANONICAL_NAME_DNS   (2)
#define USE_CANONICAL_NAME_UNSET (3)
    unsigned use_canonical_name : 2;

    /* since is_fnmatch(conf->d) was being called so frequently in
     * directory_walk() and its relatives, this field was created and
     * is set to the result of that call.
     */
    unsigned d_is_fnmatch : 1;

    /* should we force a charset on any outgoing parameterless content-type?
     * if so, which charset?
     */
#define ADD_DEFAULT_CHARSET_OFF   (0)
#define ADD_DEFAULT_CHARSET_ON    (1)
#define ADD_DEFAULT_CHARSET_UNSET (2)
    unsigned add_default_charset : 2;
    char *add_default_charset_name;

    /* System Resource Control */
#ifdef RLIMIT_CPU
    struct rlimit *limit_cpu;
#endif
#if defined (RLIMIT_DATA) || defined (RLIMIT_VMEM) || defined(RLIMIT_AS)
    struct rlimit *limit_mem;
#endif
#ifdef RLIMIT_NPROC
    struct rlimit *limit_nproc;
#endif
    unsigned long limit_req_body;  /* limit on bytes in request msg body */

    /* logging options */
    enum { srv_sig_unset, srv_sig_off, srv_sig_on,
	    srv_sig_withmail } server_signature;
    int loglevel;
    
    /* Access control */
    array_header *sec;
    regex_t *r;

#ifdef WIN32
    /* Where to find interpreter to run scripts */
    interpreter_source_e script_interpreter_source;
#endif    
    
} core_dir_config;

/* Per-server core configuration */

typedef struct {
  
#ifdef GPROF
    char *gprof_dir;
#endif

    /* Name translations --- we want the core to be able to do *something*
     * so it's at least a minimally functional web server on its own (and
     * can be tested that way).  But let's keep it to the bare minimum:
     */
    char *ap_document_root;
  
    /* Access control */

    char *access_name;
    array_header *sec;
    array_header *sec_url;
} core_server_config;

/* for http_config.c */
void ap_core_reorder_directories(pool *, server_rec *);

/* for mod_perl */
CORE_EXPORT(void) ap_add_per_dir_conf (server_rec *s, void *dir_config);
CORE_EXPORT(void) ap_add_per_url_conf (server_rec *s, void *url_config);
CORE_EXPORT(void) ap_add_file_conf(core_dir_config *conf, void *url_config);
CORE_EXPORT_NONSTD(const char *) ap_limit_section (cmd_parms *cmd, void *dummy, const char *arg);

#endif

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_CORE_H */
