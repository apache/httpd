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
 */

#ifndef UTIL_LDAP_H
#define UTIL_LDAP_H

#include <apr_ldap.h>

/* this whole thing disappears if LDAP is not enabled */
#ifdef APU_HAS_LDAP

/* APR header files */
#include <apr_thread_mutex.h>
#include <apr_thread_rwlock.h>
#include <apr_tables.h>
#include <apr_time.h>

/* Apache header files */
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"


/* Create a set of LDAP_DECLARE(type), LDLDAP_DECLARE(type) and 
 * LDAP_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define LDAP_DECLARE(type)            type
#define LDAP_DECLARE_NONSTD(type)     type
#define LDAP_DECLARE_DATA
#elif defined(LDAP_DECLARE_STATIC)
#define LDAP_DECLARE(type)            type __stdcall
#define LDAP_DECLARE_NONSTD(type)     type
#define LDAP_DECLARE_DATA
#elif defined(LDAP_DECLARE_EXPORT)
#define LDAP_DECLARE(type)            __declspec(dllexport) type __stdcall
#define LDAP_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define LDAP_DECLARE_DATA             __declspec(dllexport)
#else
#define LDAP_DECLARE(type)            __declspec(dllimport) type __stdcall
#define LDAP_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define LDAP_DECLARE_DATA             __declspec(dllimport)
#endif


/*
 * LDAP Connections
 */

/* Values that the deref member can have */
typedef enum {
    never=LDAP_DEREF_NEVER, 
    searching=LDAP_DEREF_SEARCHING, 
    finding=LDAP_DEREF_FINDING, 
    always=LDAP_DEREF_ALWAYS
} deref_options;

/* Structure representing an LDAP connection */
typedef struct util_ldap_connection_t {
    LDAP *ldap;
    apr_pool_t *pool;                   /* Pool from which this connection is created */
#if APR_HAS_THREADS
    apr_thread_mutex_t *lock;           /* Lock to indicate this connection is in use */
#endif
    int bound;                          /* Flag to indicate whether this connection is bound yet */

    const char *host;                   /* Name of the LDAP server (or space separated list) */
    int port;                           /* Port of the LDAP server */
    deref_options deref;                /* how to handle alias dereferening */

    const char *binddn;                 /* DN to bind to server (can be NULL) */
    const char *bindpw;                 /* Password to bind to server (can be NULL) */

    int secure;                         /* True if use SSL connection */

    const char *reason;                 /* Reason for an error failure */

    struct util_ldap_connection_t *next;
} util_ldap_connection_t;

/* LDAP cache state information */ 
typedef struct util_ldap_state_t {
    apr_pool_t *pool;           /* pool from which this state is allocated */
#if APR_HAS_THREADS
    apr_thread_mutex_t *mutex;          /* mutex lock for the connection list */
#endif

    apr_size_t cache_bytes;     /* Size (in bytes) of shared memory cache */
    long search_cache_ttl;      /* TTL for search cache */
    long search_cache_size;     /* Size (in entries) of search cache */
    long compare_cache_ttl;     /* TTL for compare cache */
    long compare_cache_size;    /* Size (in entries) of compare cache */

    struct util_ldap_connection_t *connections;
    char *cert_auth_file; 
    int   cert_file_type;
    int   ssl_support;
} util_ldap_state_t;


/**
 * Open a connection to an LDAP server
 * @param ldc A structure containing the expanded details of the server
 *            to connect to. The handle to the LDAP connection is returned
 *            as ldc->ldap.
 * @tip This function connects to the LDAP server and binds. It does not
 *      connect if already connected (ldc->ldap != NULL). Does not bind
 *      if already bound.
 * @return If successful LDAP_SUCCESS is returned.
 * @deffunc int util_ldap_connection_open(request_rec *r,
 *                                        util_ldap_connection_t *ldc)
 */
LDAP_DECLARE(int) util_ldap_connection_open(request_rec *r, 
                                            util_ldap_connection_t *ldc);

/**
 * Close a connection to an LDAP server
 * @param ldc A structure containing the expanded details of the server
 *            that was connected.
 * @tip This function unbinds from the LDAP server, and clears ldc->ldap.
 *      It is possible to rebind to this server again using the same ldc
 *      structure, using apr_ldap_open_connection().
 * @deffunc util_ldap_close_connection(util_ldap_connection_t *ldc)
 */
LDAP_DECLARE(void) util_ldap_connection_close(util_ldap_connection_t *ldc);

/**
 * Destroy a connection to an LDAP server
 * @param ldc A structure containing the expanded details of the server
 *            that was connected.
 * @tip This function is registered with the pool cleanup to close down the
 *      LDAP connections when the server is finished with them.
 * @deffunc apr_status_t util_ldap_connection_destroy(util_ldap_connection_t *ldc)
 */
LDAP_DECLARE_NONSTD(apr_status_t) util_ldap_connection_destroy(void *param);

/**
 * Find a connection in a list of connections
 * @param r The request record
 * @param host The hostname to connect to (multiple hosts space separated)
 * @param port The port to connect to
 * @param binddn The DN to bind with
 * @param bindpw The password to bind with
 * @param deref The dereferencing behavior
 * @param secure use SSL on the connection 
 * @tip Once a connection is found and returned, a lock will be acquired to
 *      lock that particular connection, so that another thread does not try and
 *      use this connection while it is busy. Once you are finished with a connection,
 *      apr_ldap_connection_close() must be called to release this connection.
 * @deffunc util_ldap_connection_t *util_ldap_connection_find(request_rec *r, const char *host, int port,
 *                                                           const char *binddn, const char *bindpw, deref_options deref,
 *                                                           int netscapessl, int starttls)
 */
LDAP_DECLARE(util_ldap_connection_t *) util_ldap_connection_find(request_rec *r, const char *host, int port,
                                                  const char *binddn, const char *bindpw, deref_options deref,
                                                  int secure);


/**
 * Compare two DNs for sameness
 * @param r The request record
 * @param ldc The LDAP connection being used.
 * @param url The URL of the LDAP connection - used for deciding which cache to use.
 * @param dn The first DN to compare.
 * @param reqdn The DN to compare the first DN to.
 * @param compare_dn_on_server Flag to determine whether the DNs should be checked using
 *                             LDAP calls or with a direct string comparision. A direct
 *                             string comparison is faster, but not as accurate - false
 *                             negative comparisons are possible.
 * @tip Two DNs can be equal and still fail a string comparison. Eg "dc=example,dc=com"
 *      and "dc=example, dc=com". Use the compare_dn_on_server unless there are serious
 *      performance issues.
 * @deffunc int util_ldap_cache_comparedn(request_rec *r, util_ldap_connection_t *ldc,
 *                                        const char *url, const char *dn, const char *reqdn,
 *                                        int compare_dn_on_server)
 */
LDAP_DECLARE(int) util_ldap_cache_comparedn(request_rec *r, util_ldap_connection_t *ldc, 
                              const char *url, const char *dn, const char *reqdn, 
                              int compare_dn_on_server);

/**
 * A generic LDAP compare function
 * @param r The request record
 * @param ldc The LDAP connection being used.
 * @param url The URL of the LDAP connection - used for deciding which cache to use.
 * @param dn The DN of the object in which we do the compare.
 * @param attrib The attribute within the object we are comparing for.
 * @param value The value of the attribute we are trying to compare for. 
 * @tip Use this function to determine whether an attribute/value pair exists within an
 *      object. Typically this would be used to determine LDAP group membership.
 * @deffunc int util_ldap_cache_compare(request_rec *r, util_ldap_connection_t *ldc,
 *                                      const char *url, const char *dn, const char *attrib, const char *value)
 */
LDAP_DECLARE(int) util_ldap_cache_compare(request_rec *r, util_ldap_connection_t *ldc,
                            const char *url, const char *dn, const char *attrib, const char *value);

/**
 * Checks a username/password combination by binding to the LDAP server
 * @param r The request record
 * @param ldc The LDAP connection being used.
 * @param url The URL of the LDAP connection - used for deciding which cache to use.
 * @param basedn The Base DN to search for the user in.
 * @param scope LDAP scope of the search.
 * @param attrs LDAP attributes to return in search.
 * @param filter The user to search for in the form of an LDAP filter. This filter must return
 *               exactly one user for the check to be successful.
 * @param bindpw The user password to bind as.
 * @param binddn The DN of the user will be returned in this variable.
 * @param retvals The values corresponding to the attributes requested in the attrs array.
 * @tip The filter supplied will be searched for. If a single entry is returned, an attempt
 *      is made to bind as that user. If this bind succeeds, the user is not validated.
 * @deffunc int util_ldap_cache_checkuserid(request_rec *r, util_ldap_connection_t *ldc,
 *                                          char *url, const char *basedn, int scope, char **attrs,
 *                                          char *filter, char *bindpw, char **binddn, char ***retvals)
 */
LDAP_DECLARE(int) util_ldap_cache_checkuserid(request_rec *r, util_ldap_connection_t *ldc,
                              const char *url, const char *basedn, int scope, char **attrs,
                              const char *filter, const char *bindpw, const char **binddn, const char ***retvals);

/**
 * Checks if SSL support is available in mod_ldap
 * @deffunc int util_ldap_ssl_supported(request_rec *r)
 */
LDAP_DECLARE(int) util_ldap_ssl_supported(request_rec *r);

/* from apr_ldap_cache.c */

/**
 * Init the LDAP cache
 * @param pool The pool to use to initialise the cache
 * @param reqsize The size of the shared memory segement to request. A size
 *                of zero requests the max size possible from
 *                apr_shmem_init()
 * @deffunc void util_ldap_cache_init(apr_pool_t *p)
 * @return The status code returned is the status code of the
 *         apr_smmem_init() call. Regardless of the status, the cache
 *         will be set up at least for in-process or in-thread operation.
 */
apr_status_t util_ldap_cache_init(apr_pool_t *pool, apr_size_t reqsize);

/**
 * Display formatted stats for cache
 * @param The pool to allocate the returned string from
 * @tip This function returns a string allocated from the provided pool that describes
 *      various stats about the cache.
 * @deffunc char *util_ald_cache_display(apr_pool_t *pool)
 */
char *util_ald_cache_display(apr_pool_t *pool);


/* from apr_ldap_cache_mgr.c */

/**
 * Display formatted stats for cache
 * @param The pool to allocate the returned string from
 * @tip This function returns a string allocated from the provided pool that describes
 *      various stats about the cache.
 * @deffunc char *util_ald_cache_display(apr_pool_t *pool)
 */
char *util_ald_cache_display(apr_pool_t *pool);

#endif /* APU_HAS_LDAP */
#endif /* UTIL_LDAP_H */
