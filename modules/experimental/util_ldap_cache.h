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


#ifndef APU_LDAP_CACHE_H
#define APU_LDAP_CACHE_H

/*
 * This switches LDAP support on or off.
 */

/* this whole thing disappears if LDAP is not enabled */
#if APR_HAS_LDAP


/*
 * LDAP Cache Manager
 */

#if APR_HAS_SHARED_MEMORY
#include <apr_shm.h>
#include <apr_rmm.h> /* EDD */
#endif

typedef struct util_cache_node_t {
    void *payload;		/* Pointer to the payload */
    apr_time_t add_time;	/* Time node was added to cache */
    struct util_cache_node_t *next;
} util_cache_node_t;

typedef struct util_ald_cache util_ald_cache_t;

struct util_ald_cache {
    unsigned long size;	                /* Size of cache array */
    unsigned long maxentries;           /* Maximum number of cache entries */
    unsigned long numentries;           /* Current number of cache entries */
    unsigned long fullmark;             /* Used to keep track of when cache becomes 3/4 full */
    apr_time_t marktime;                /* Time that the cache became 3/4 full */
    unsigned long (*hash)(void *);      /* Func to hash the payload */
    int (*compare)(void *, void *);     /* Func to compare two payloads */
    void * (*copy)(util_ald_cache_t *cache, void *); /* Func to alloc mem and copy payload to new mem */
    void (*free)(util_ald_cache_t *cache, void *); /* Func to free mem used by the payload */
    util_cache_node_t **nodes;

    unsigned long numpurges;    /* No. of times the cache has been purged */
    double avg_purgetime;       /* Average time to purge the cache */
    apr_time_t last_purge;      /* Time of the last purge */
    unsigned long npurged;      /* Number of elements purged in last purge. This is not
                                   obvious: it won't be 3/4 the size of the cache if 
                                   there were a lot of expired entries. */

    unsigned long fetches;      /* Number of fetches */
    unsigned long hits;         /* Number of cache hits */
    unsigned long inserts;      /* Number of inserts */
    unsigned long removes;      /* Number of removes */

#if APR_HAS_SHARED_MEMORY
    apr_shm_t *shm_addr;
    apr_rmm_t *rmm_addr;
#endif

};

#if APR_HAS_THREADS
#define LDAP_CACHE_LOCK_CREATE(p) \
    if (!st->util_ldap_cache_lock) apr_thread_rwlock_create(&st->util_ldap_cache_lock, st->pool)
#define LDAP_CACHE_WRLOCK() \
    apr_thread_rwlock_wrlock(st->util_ldap_cache_lock)
#define LDAP_CACHE_UNLOCK() \
    apr_thread_rwlock_unlock(st->util_ldap_cache_lock)
#define LDAP_CACHE_RDLOCK() \
    apr_thread_rwlock_rdlock(st->util_ldap_cache_lock)
#else
#define LDAP_CACHE_LOCK_CREATE(p)
#define LDAP_CACHE_WRLOCK()
#define LDAP_CACHE_UNLOCK()
#define LDAP_CACHE_RDLOCK()
#endif

#ifndef WIN32
#define ALD_MM_FILE_MODE ( S_IRUSR|S_IWUSR )
#else
#define ALD_MM_FILE_MODE ( _S_IREAD|_S_IWRITE )
#endif


/*
 * LDAP Cache
 */

/*
 * Maintain a cache of LDAP URLs that the server handles. Each node in
 * the cache contains the search cache for that URL, and a compare cache
 * for the URL. The compare cash is populated when doing require group
 * compares.
 */
typedef struct util_url_node_t {
    const char *url;
    util_ald_cache_t *search_cache;
    util_ald_cache_t *compare_cache;
    util_ald_cache_t *dn_compare_cache;
} util_url_node_t;

/*
 * We cache every successful search and bind operation, using the username 
 * as the key. Each node in the cache contains the returned DN, plus the 
 * password used to bind.
 */
typedef struct util_search_node_t {
    const char *username;		/* Cache key */
    const char *dn;			/* DN returned from search */
    const char *bindpw;			/* The most recently used bind password; 
					   NULL if the bind failed */
    apr_time_t lastbind;		/* Time of last successful bind */
    const char **vals;			/* Values of queried attributes */
} util_search_node_t;

/*
 * We cache every successful compare operation, using the DN, attrib, and
 * value as the key. 
 */
typedef struct util_compare_node_t {
    const char *dn;			/* DN, attrib and value combine to be the key */
    const char *attrib;			
    const char *value;
    apr_time_t lastcompare;
    int result;
} util_compare_node_t;

/*
 * We cache every successful compare dn operation, using the dn in the require
 * statement and the dn fetched based on the client-provided username.
 */
typedef struct util_dn_compare_node_t {
    const char *reqdn;		/* The DN in the require dn statement */
    const char *dn;			/* The DN found in the search */
} util_dn_compare_node_t;


/*
 * Function prototypes for LDAP cache
 */

/* util_ldap_cache.c */
unsigned long util_ldap_url_node_hash(void *n);
int util_ldap_url_node_compare(void *a, void *b);
void *util_ldap_url_node_copy(util_ald_cache_t *cache, void *c);
void util_ldap_url_node_free(util_ald_cache_t *cache, void *n);
unsigned long util_ldap_search_node_hash(void *n);
int util_ldap_search_node_compare(void *a, void *b);
void *util_ldap_search_node_copy(util_ald_cache_t *cache, void *c);
void util_ldap_search_node_free(util_ald_cache_t *cache, void *n);
unsigned long util_ldap_compare_node_hash(void *n);
int util_ldap_compare_node_compare(void *a, void *b);
void *util_ldap_compare_node_copy(util_ald_cache_t *cache, void *c);
void util_ldap_compare_node_free(util_ald_cache_t *cache, void *n);
unsigned long util_ldap_dn_compare_node_hash(void *n);
int util_ldap_dn_compare_node_compare(void *a, void *b);
void *util_ldap_dn_compare_node_copy(util_ald_cache_t *cache, void *c);
void util_ldap_dn_compare_node_free(util_ald_cache_t *cache, void *n);


/* util_ldap_cache_mgr.c */

/* Cache alloc and free function, dealing or not with shm */
void util_ald_free(util_ald_cache_t *cache, const void *ptr);
void *util_ald_alloc(util_ald_cache_t *cache, unsigned long size);
const char *util_ald_strdup(util_ald_cache_t *cache, const char *s);

/* Cache managing function */
unsigned long util_ald_hash_string(int nstr, ...);
void util_ald_cache_purge(util_ald_cache_t *cache);
util_url_node_t *util_ald_create_caches(util_ldap_state_t *s, const char *url);
util_ald_cache_t *util_ald_create_cache(util_ldap_state_t *st,
                                unsigned long (*hashfunc)(void *), 
                                int (*comparefunc)(void *, void *),
                                void * (*copyfunc)(util_ald_cache_t *cache, void *),
                                void (*freefunc)(util_ald_cache_t *cache, void *));
                                
void util_ald_destroy_cache(util_ald_cache_t *cache);
void *util_ald_cache_fetch(util_ald_cache_t *cache, void *payload);
void util_ald_cache_insert(util_ald_cache_t *cache, void *payload);
void util_ald_cache_remove(util_ald_cache_t *cache, void *payload);
char *util_ald_cache_display_stats(apr_pool_t *p, util_ald_cache_t *cache,
                                 char *name);

#endif /* APR_HAS_LDAP */
#endif /* APU_LDAP_CACHE_H */
