
/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
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
#define REMOTE_HOST (0)
#define REMOTE_NAME (1)

int allow_options (request_rec *);
int allow_overrides (request_rec *);
char *default_type (request_rec *);     
char *document_root (request_rec *); /* Don't use this!  If your request went
				      * through a Userdir, or something like
				      * that, it'll screw you.  But it's
				      * back-compatible...
				      */
extern const char *get_remote_host(conn_rec *conn, void *dir_config, int type);
extern const char *get_remote_logname(request_rec *r);
     
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
     
char *auth_type (request_rec *);
char *auth_name (request_rec *);     
array_header *requires (request_rec *);    

#ifdef CORE_PRIVATE

/*
 * Core is also unlike other modules in being implemented in more than
 * one file... so, data structures are declared here, even though most of
 * the code that cares really is in http_core.c.  Also, anothre accessor.
 */

char *response_code_string (request_rec *r, int error_index);

extern module core_module;

/* Per-directory configuration */

typedef char allow_options_t;
typedef char overrides_t;

typedef struct {
    char *d;
    allow_options_t opts;
    overrides_t override;
    
    /* MIME typing --- the core doesn't do anything at all with this,
     * but it does know what to slap on a request for a document which
     * goes untyped by other mechanisms before it slips out the door...
     */
    
    char *default_type;
  
    /* Authentication stuff.  Groan... */
    
    char *auth_type;
    char *auth_name;
    array_header *requires;

    int content_md5;
    
    /* Custom response config. These can contain text or a URL to redirect to.
     */
  
    char *response_code_strings[RESPONSE_CODES+1];

    /* Hostname resolution etc */
    int hostname_lookups;
    int do_rfc1413;   /* See if client is advertising a username? */

} core_dir_config;

/* Per-server core configuration */

typedef struct {
  
    /* Name translations --- we want the core to be able to do *something*
     * so it's at least a minimally functional web server on its own (and
     * can be tested that way).  But let's keep it to the bare minimum:
     */
    char *document_root;
  
    /* Access control */
  
    char *access_name;
    array_header *sec;
    array_header *sec_url;
} core_server_config;

#endif
