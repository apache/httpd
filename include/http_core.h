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

#ifndef APACHE_HTTP_CORE_H
#define APACHE_HTTP_CORE_H

#include "apr.h"
#include "apr_hash.h"
#include "apr_optional.h"
#include "util_filter.h"

#if APR_HAVE_STRUCT_RLIMIT
#include <sys/time.h>
#include <sys/resource.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @package CORE HTTP Daemon
 */

/* ****************************************************************
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

/* Make sure we don't write less than 8000 bytes at any one time.
 */
#define AP_MIN_BYTES_TO_WRITE  8000

/* default maximum of internal redirects */
# define AP_DEFAULT_MAX_INTERNAL_REDIRECTS 10

/* default maximum subrequest nesting level */
# define AP_DEFAULT_MAX_SUBREQ_DEPTH 10

/**
 * Retrieve the value of Options for this request
 * @param r The current request
 * @return the Options bitmask
 * @deffunc int ap_allow_options(request_rec *r)
 */
AP_DECLARE(int) ap_allow_options(request_rec *r);

/**
 * Retrieve the value of the AllowOverride for this request
 * @param r The current request
 * @return the overrides bitmask
 * @deffunc int ap_allow_overrides(request_rec *r)
 */
AP_DECLARE(int) ap_allow_overrides(request_rec *r);

/**
 * Retrieve the value of the DefaultType directive, or text/plain if not set
 * @param r The current request
 * @return The default type
 * @deffunc const char *ap_default_type(request_rec *r)
 */
AP_DECLARE(const char *) ap_default_type(request_rec *r);     

/**
 * Retrieve the document root for this server
 * @param r The current request
 * @warning Don't use this!  If your request went through a Userdir, or 
 * something like that, it'll screw you.  But it's back-compatible...
 * @return The document root
 * @deffunc const char *ap_document_root(request_rec *r)
 */
AP_DECLARE(const char *) ap_document_root(request_rec *r);

/**
 * Lookup the remote client's DNS name or IP address
 * @param conn The current connection
 * @param dir_config The directory config vector from the request
 * @param type The type of lookup to perform.  One of:
 * <pre>
 *     REMOTE_HOST returns the hostname, or NULL if the hostname
 *                 lookup fails.  It will force a DNS lookup according to the
 *                 HostnameLookups setting.
 *     REMOTE_NAME returns the hostname, or the dotted quad if the
 *                 hostname lookup fails.  It will force a DNS lookup according
 *                 to the HostnameLookups setting.
 *     REMOTE_NOLOOKUP is like REMOTE_NAME except that a DNS lookup is
 *                     never forced.
 *     REMOTE_DOUBLE_REV will always force a DNS lookup, and also force
 *                   a double reverse lookup, regardless of the HostnameLookups
 *                   setting.  The result is the (double reverse checked) 
 *                   hostname, or NULL if any of the lookups fail.
 * </pre>
 * @param str_is_ip unless NULL is passed, this will be set to non-zero on output when an IP address 
 *        string is returned
 * @return The remote hostname
 * @deffunc const char *ap_get_remote_host(conn_rec *conn, void *dir_config, int type, int *str_is_ip)
 */
AP_DECLARE(const char *) ap_get_remote_host(conn_rec *conn, void *dir_config, int type, int *str_is_ip);

/**
 * Retrieve the login name of the remote user.  Undef if it could not be
 * determined
 * @param r The current request
 * @return The user logged in to the client machine
 * @deffunc const char *ap_get_remote_logname(request_rec *r)
 */
AP_DECLARE(const char *) ap_get_remote_logname(request_rec *r);

/* Used for constructing self-referencing URLs, and things like SERVER_PORT,
 * and SERVER_NAME.
 */
/**
 * build a fully qualified URL from the uri and information in the request rec
 * @param p The pool to allocate the URL from
 * @param uri The path to the requested file
 * @param r The current request
 * @return A fully qualified URL
 * @deffunc char *ap_construct_url(apr_pool_t *p, const char *uri, request_rec *r)
 */
AP_DECLARE(char *) ap_construct_url(apr_pool_t *p, const char *uri, request_rec *r);

/**
 * Get the current server name from the request
 * @param r The current request
 * @return the server name
 * @deffunc const char *ap_get_server_name(request_rec *r)
 */
AP_DECLARE(const char *) ap_get_server_name(request_rec *r);

/**
 * Get the current server port
 * @param The current request
 * @return The server's port
 * @deffunc apr_port_t ap_get_server_port(const request_rec *r)
 */
AP_DECLARE(apr_port_t) ap_get_server_port(const request_rec *r);

/**
 * Return the limit on bytes in request msg body 
 * @param r The current request
 * @return the maximum number of bytes in the request msg body
 * @deffunc apr_off_t ap_get_limit_req_body(const request_rec *r)
 */
AP_DECLARE(apr_off_t) ap_get_limit_req_body(const request_rec *r);

/**
 * Return the limit on bytes in XML request msg body
 * @param r The current request
 * @return the maximum number of bytes in XML request msg body
 * @deffunc size_t ap_get_limit_xml_body(const request_rec *r)
 */
AP_DECLARE(size_t) ap_get_limit_xml_body(const request_rec *r);

/**
 * Install a custom response handler for a given status
 * @param r The current request
 * @param status The status for which the custom response should be used
 * @param string The custom response.  This can be a static string, a file
 *               or a URL
 */
AP_DECLARE(void) ap_custom_response(request_rec *r, int status, const char *string);

/**
 * Check if the current request is beyond the configured max. number of redirects or subrequests
 * @param r The current request
 * @return true (is exceeded) or false
 * @deffunc int ap_is_recursion_limit_exceeded(const request_rec *r)
 */
AP_DECLARE(int) ap_is_recursion_limit_exceeded(const request_rec *r);

/**
 * Check for a definition from the server command line
 * @param name The define to check for
 * @return 1 if defined, 0 otherwise
 * @deffunc int ap_exists_config_define(const char *name)
 */
AP_DECLARE(int) ap_exists_config_define(const char *name);
/* FIXME! See STATUS about how */
AP_DECLARE_NONSTD(int) ap_core_translate(request_rec *r);

/* Authentication stuff.  This is one of the places where compatibility
 * with the old config files *really* hurts; they don't discriminate at
 * all between different authentication schemes, meaning that we need
 * to maintain common state for all of them in the core, and make it
 * available to the other modules through interfaces.
 */
typedef struct require_line require_line;

/** A structure to keep track of authorization requirements */
struct require_line {
    /** Where the require line is in the config file. */
    apr_int64_t method_mask;
    /** The complete string from the command line */
    char *requirement;
};
     
/**
 * Return the type of authorization required for this request
 * @param r The current request
 * @return The authorization required
 * @deffunc const char *ap_auth_type(request_rec *r)
 */
AP_DECLARE(const char *) ap_auth_type(request_rec *r);

/**
 * Return the current Authorization realm
 * @param r The current request
 * @return The current authorization realm
 * @deffunc const char *ap_auth_name(request_rec *r)
 */
AP_DECLARE(const char *) ap_auth_name(request_rec *r);     

/**
 * How the requires lines must be met.
 * @param r The current request
 * @return How the requirements must be met.  One of:
 * <pre>
 *      SATISFY_ANY    -- any of the requirements must be met.
 *      SATISFY_ALL    -- all of the requirements must be met.
 *      SATISFY_NOSPEC -- There are no applicable satisfy lines
 * </pre>
 * @deffunc int ap_satisfies(request_rec *r)
 */
AP_DECLARE(int) ap_satisfies(request_rec *r);

/**
 * Retrieve information about all of the requires directives for this request
 * @param r The current request
 * @return An array of all requires directives for this request
 * @deffunc const apr_array_header_t *ap_requires(request_rec *r)
 */
AP_DECLARE(const apr_array_header_t *) ap_requires(request_rec *r);    

#ifdef CORE_PRIVATE

/*
 * Core is also unlike other modules in being implemented in more than
 * one file... so, data structures are declared here, even though most of
 * the code that cares really is in http_core.c.  Also, another accessor.
 */

AP_DECLARE_DATA extern module core_module;

/* Per-request configuration */

typedef struct {
    /* bucket brigade used by getline for look-ahead and 
     * ap_get_client_block for holding left-over request body */
    struct apr_bucket_brigade *bb;

    /* an array of per-request working data elements, accessed
     * by ID using ap_get_request_note()
     * (Use ap_register_request_note() during initialization
     * to add elements)
     */
    void **notes;

    /* There is a script processor installed on the output filter chain,
     * so it needs the default_handler to deliver a (script) file into
     * the chain so it can process it. Normally, default_handler only
     * serves files on a GET request (assuming the file is actual content),
     * since other methods are not content-retrieval. This flag overrides
     * that behavior, stating that the "content" is actually a script and
     * won't actually be delivered as the response for the non-GET method.
     */
    int deliver_script;
} core_request_config;

/* Standard entries that are guaranteed to be accessible via
 * ap_get_request_note() for each request (additional entries
 * can be added with ap_register_request_note())
 */
#define AP_NOTE_DIRECTORY_WALK 0
#define AP_NOTE_LOCATION_WALK  1
#define AP_NOTE_FILE_WALK      2
#define AP_NUM_STD_NOTES       3

/**
 * Reserve an element in the core_request_config->notes array
 * for some application-specific data
 * @return An integer key that can be passed to ap_get_request_note()
 *         during request processing to access this element for the
 *         current request.
 */
AP_DECLARE(apr_size_t) ap_register_request_note(void);

/**
 * Retrieve a pointer to an element in the core_request_config->notes array
 * @param r The request
 * @param note_num  A key for the element: either a value obtained from
 *        ap_register_request_note() or one of the predefined AP_NOTE_*
 *        values.
 * @return NULL if the note_num is invalid, otherwise a pointer to the
 *         requested note element.
 * @remark At the start of a request, each note element is NULL.  The
 *         handle provided by ap_get_request_note() is a pointer-to-pointer
 *         so that the caller can point the element to some app-specific
 *         data structure.  The caller should guarantee that any such
 *         structure will last as long as the request itself.
 */
AP_DECLARE(void **) ap_get_request_note(request_rec *r, apr_size_t note_num);

/* Per-directory configuration */

typedef unsigned char allow_options_t;
typedef unsigned char overrides_t;

/*
 * Bits of info that go into making an ETag for a file
 * document.  Why a long?  Because char historically
 * proved too short for Options, and int can be different
 * sizes on different platforms.
 */
typedef unsigned long etag_components_t;

#define ETAG_UNSET 0
#define ETAG_NONE  (1 << 0)
#define ETAG_MTIME (1 << 1)
#define ETAG_INODE (1 << 2)
#define ETAG_SIZE  (1 << 3)
#define ETAG_BACKWARD (ETAG_MTIME | ETAG_INODE | ETAG_SIZE)
#define ETAG_ALL   (ETAG_MTIME | ETAG_INODE | ETAG_SIZE)

typedef enum {
    srv_sig_unset,
    srv_sig_off,
    srv_sig_on,
    srv_sig_withmail
} server_signature_e;

typedef struct {
    /* path of the directory/regex/etc. see also d_is_fnmatch/absolute below */
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
    apr_array_header_t *ap_requires;

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
    const char *add_default_charset_name;

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
    apr_off_t limit_req_body;      /* limit on bytes in request msg body */
    long limit_xml_body;           /* limit on bytes in XML request msg body */

    /* logging options */

    server_signature_e server_signature;

    int loglevel;
    
    /* Access control */
    apr_array_header_t *sec_file;
    regex_t *r;

    const char *mime_type;       /* forced with ForceType  */
    const char *handler;         /* forced with SetHandler */
    const char *output_filters;  /* forced with SetOutputFilters */
    const char *input_filters;   /* forced with SetInputFilters */
    int accept_path_info;        /* forced with AcceptPathInfo */

    apr_hash_t *ct_output_filters; /* added with AddOutputFilterByType */

    /*
     * What attributes/data should be included in ETag generation?
     */
    etag_components_t etag_bits;
    etag_components_t etag_add;
    etag_components_t etag_remove;

    /*
     * Run-time performance tuning
     */
#define ENABLE_MMAP_OFF    (0)
#define ENABLE_MMAP_ON     (1)
#define ENABLE_MMAP_UNSET  (2)
    unsigned int enable_mmap : 2;  /* whether files in this dir can be mmap'ed */

#define ENABLE_SENDFILE_OFF    (0)
#define ENABLE_SENDFILE_ON     (1)
#define ENABLE_SENDFILE_UNSET  (2)
    unsigned int enable_sendfile : 2;  /* files in this dir can be mmap'ed */
    unsigned int allow_encoded_slashes : 1; /* URLs may contain %2f w/o being
                                             * pitched indiscriminately */
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
    const char *ap_document_root;
  
    /* Access control */

    char *access_name;
    apr_array_header_t *sec_dir;
    apr_array_header_t *sec_url;

    /* recursion backstopper */
    int redirect_limit; /* maximum number of internal redirects */
    int subreq_limit;   /* maximum nesting level of subrequests */
} core_server_config;

/* for AddOutputFiltersByType in core.c */
void ap_add_output_filters_by_type(request_rec *r);

/* for http_config.c */
void ap_core_reorder_directories(apr_pool_t *, server_rec *);

/* for mod_perl */
AP_CORE_DECLARE(void) ap_add_per_dir_conf(server_rec *s, void *dir_config);
AP_CORE_DECLARE(void) ap_add_per_url_conf(server_rec *s, void *url_config);
AP_CORE_DECLARE(void) ap_add_file_conf(core_dir_config *conf, void *url_config);
AP_CORE_DECLARE_NONSTD(const char *) ap_limit_section(cmd_parms *cmd, void *dummy, const char *arg);

#endif


/* ----------------------------------------------------------------------
 *
 * Runtime status/management
 */

typedef enum {
    ap_mgmt_type_string,
    ap_mgmt_type_long,
    ap_mgmt_type_hash
} ap_mgmt_type_e;

typedef union {
    const char *s_value;
    long i_value;
    apr_hash_t *h_value;
} ap_mgmt_value;

typedef struct {
    const char *description;
    const char *name;
    ap_mgmt_type_e vtype;
    ap_mgmt_value v;
} ap_mgmt_item_t;

/* Handles for core filters */
extern AP_DECLARE_DATA ap_filter_rec_t *ap_subreq_core_filter_handle;
extern AP_DECLARE_DATA ap_filter_rec_t *ap_core_output_filter_handle;
extern AP_DECLARE_DATA ap_filter_rec_t *ap_content_length_filter_handle;
extern AP_DECLARE_DATA ap_filter_rec_t *ap_net_time_filter_handle;
extern AP_DECLARE_DATA ap_filter_rec_t *ap_core_input_filter_handle;

/**
 * This hook provdes a way for modules to provide metrics/statistics about
 * their operational status.
 *
 * @param p A pool to use to create entries in the hash table
 * @param val The name of the parameter(s) that is wanted. This is
 *            tree-structured would be in the form ('*' is all the tree,
 *            'module.*' all of the module , 'module.foo.*', or
 *            'module.foo.bar' )
 * @param ht The hash table to store the results. Keys are item names, and
 *           the values point to ap_mgmt_item_t structures.
 * @ingroup hooks
 */
AP_DECLARE_HOOK(int, get_mgmt_items,
                (apr_pool_t *p, const char * val, apr_hash_t *ht))

/* ---------------------------------------------------------------------- */

/* ----------------------------------------------------------------------
 *
 * I/O logging with mod_logio
 */

APR_DECLARE_OPTIONAL_FN(void, ap_logio_add_bytes_out,
                        (conn_rec *c, apr_off_t bytes));

/* ---------------------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_CORE_H */
