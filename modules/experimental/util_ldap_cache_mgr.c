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

/*
 * util_ldap_cache_mgr.c: LDAP cache manager things
 * 
 * Original code from auth_ldap module for Apache v1.3:
 * Copyright 1998, 1999 Enbridge Pipelines Inc. 
 * Copyright 1999-2001 Dave Carrigan
 */

#include <apr_ldap.h>
#include "util_ldap.h"
#include "util_ldap_cache.h"
#include <apr_strings.h>

#ifdef APU_HAS_LDAP

/* only here until strdup is gone */
#include <string.h>

/* here till malloc is gone */
#include <stdlib.h>

static const unsigned long primes[] =
{
  11,
  19,
  37,
  73,
  109,
  163,
  251,
  367,
  557,
  823,
  1237,
  1861,
  2777,
  4177,
  6247,
  9371,
  14057,
  21089,
  31627,
  47431,
  71143,
  106721,
  160073,
  240101,
  360163,
  540217,
  810343,
  1215497,
  1823231,
  2734867,
  4102283,
  6153409,
  9230113,
  13845163,
  0
};

void util_ald_free(const void *ptr)
{
#if APR_HAS_SHARED_MEMORY
    if (util_ldap_shm) {
        if (ptr)
            apr_rmm_free(util_ldap_rmm, apr_rmm_offset_get(util_ldap_rmm, (void *)ptr));
    } else {
        if (ptr)
            free((void *)ptr);
    }
#else
    if (ptr)
        free((void *)ptr);
#endif
}

void *util_ald_alloc(unsigned long size)
{
    if (0 == size)
        return NULL;
#if APR_HAS_SHARED_MEMORY
    if (util_ldap_shm) {
        return (void *)apr_rmm_addr_get(util_ldap_rmm, apr_rmm_calloc(util_ldap_rmm, size));
    } else {
        return (void *)calloc(sizeof(char), size);
    }
#else
    return (void *)calloc(sizeof(char), size);
#endif
}

const char *util_ald_strdup(const char *s)
{
#if APR_HAS_SHARED_MEMORY
    if (util_ldap_shm) {
        char *buf = (char *)apr_rmm_addr_get(util_ldap_rmm, apr_rmm_calloc(util_ldap_rmm, strlen(s)+1));
        if (buf) {
            strcpy(buf, s);
            return buf;
        }
        else {
            return NULL;
        }
    } else {
        return strdup(s);
    }
#else
    return strdup(s);
#endif
}


/*
 * Computes the hash on a set of strings. The first argument is the number
 * of strings to hash, the rest of the args are strings. 
 * Algorithm taken from glibc.
 */
unsigned long util_ald_hash_string(int nstr, ...)
{
    int i;
    va_list args;
    unsigned long h=0, g;
    char *str, *p;
  
    va_start(args, nstr);
    for (i=0; i < nstr; ++i) {
        str = va_arg(args, char *);
        for (p = str; *p; ++p) {
            h = ( h << 4 ) + *p;
            if ( ( g = h & 0xf0000000 ) ) {
	        h = h ^ (g >> 24);
	        h = h ^ g;
            }
        }
    }
    va_end(args);

    return h;
}


/*
  Purges a cache that has gotten full. We keep track of the time that we
  added the entry that made the cache 3/4 full, then delete all entries
  that were added before that time. It's pretty simplistic, but time to
  purge is only O(n), which is more important.
*/
void util_ald_cache_purge(util_ald_cache_t *cache)
{
    unsigned long i;
    util_cache_node_t *p, *q;
    apr_time_t t;

    if (!cache)
        return;
  
    cache->last_purge = apr_time_now();
    cache->npurged = 0;
    cache->numpurges++;

    for (i=0; i < cache->size; ++i) {
        p = cache->nodes[i];
        while (p != NULL) {
            if (p->add_time < cache->marktime) {
	        q = p->next;
	        (*cache->free)(p->payload);
	        util_ald_free(p);
	        cache->numentries--;
	        cache->npurged++;
	        p = q;
            }
            else {
	        p = p->next;
            }
        }
    }

    t = apr_time_now();
    cache->avg_purgetime = 
         ((t - cache->last_purge) + (cache->avg_purgetime * (cache->numpurges-1))) / 
         cache->numpurges;
}


/*
 * create caches
 */
util_url_node_t *util_ald_create_caches(util_ldap_state_t *st, const char *url)
{
    util_url_node_t *curl = NULL;
    util_ald_cache_t *search_cache;
    util_ald_cache_t *compare_cache;
    util_ald_cache_t *dn_compare_cache;

    /* create the three caches */
    search_cache = util_ald_create_cache(st->search_cache_size,
					  util_ldap_search_node_hash,
					  util_ldap_search_node_compare,
					  util_ldap_search_node_copy,
					  util_ldap_search_node_free);
    compare_cache = util_ald_create_cache(st->compare_cache_size,
					   util_ldap_compare_node_hash,
					   util_ldap_compare_node_compare,
					   util_ldap_compare_node_copy,
					   util_ldap_compare_node_free);
    dn_compare_cache = util_ald_create_cache(st->compare_cache_size,
					      util_ldap_dn_compare_node_hash,
					      util_ldap_dn_compare_node_compare,
					      util_ldap_dn_compare_node_copy,
					      util_ldap_dn_compare_node_free);

    /* check that all the caches initialised successfully */
    if (search_cache && compare_cache && dn_compare_cache) {

        curl = (util_url_node_t *)apr_pcalloc(st->pool, sizeof(util_url_node_t));
        curl->url = url;
        curl->search_cache = search_cache;
        curl->compare_cache = compare_cache;
        curl->dn_compare_cache = dn_compare_cache;

        util_ald_cache_insert(util_ldap_cache, curl);

    }

    return curl;
}


util_ald_cache_t *util_ald_create_cache(unsigned long maxentries,
                                unsigned long (*hashfunc)(void *), 
                                int (*comparefunc)(void *, void *),
                                void * (*copyfunc)(void *),
                                void (*freefunc)(void *))
{
    util_ald_cache_t *cache;
    unsigned long i;

    if (maxentries <= 0)
        return NULL;

    cache = (util_ald_cache_t *)util_ald_alloc(sizeof(util_ald_cache_t));
    if (!cache)
        return NULL;

    cache->maxentries = maxentries;
    cache->numentries = 0;
    cache->size = maxentries / 3;
    if (cache->size < 64) cache->size = 64;
        for (i = 0; primes[i] && primes[i] < cache->size; ++i) ;
            cache->size = primes[i]? primes[i] : primes[i-1];

    cache->nodes = (util_cache_node_t **)util_ald_alloc(cache->size * sizeof(util_cache_node_t *));
    if (!cache->nodes) {
        util_ald_free(cache);
        return NULL;
    }

    for (i=0; i < cache->size; ++i)
        cache->nodes[i] = NULL;

    cache->hash = hashfunc;
    cache->compare = comparefunc;
    cache->copy = copyfunc;
    cache->free = freefunc;

    cache->fullmark = cache->maxentries / 4 * 3;
    cache->marktime = 0;
    cache->avg_purgetime = 0.0;
    cache->numpurges = 0;
    cache->last_purge = 0;
    cache->npurged = 0;

    cache->fetches = 0;
    cache->hits = 0;
    cache->inserts = 0;
    cache->removes = 0;

    return cache;
}

void util_ald_destroy_cache(util_ald_cache_t *cache)
{
    unsigned long i;
    util_cache_node_t *p, *q;

    if (cache == NULL)
        return;

    for (i = 0; i < cache->size; ++i) {
        p = cache->nodes[i];
        q = NULL;
        while (p != NULL) {
            q = p->next;
           (*cache->free)(p->payload);
           util_ald_free(p);
           p = q;
        }
    }
    util_ald_free(cache->nodes);
    util_ald_free(cache);
}

void *util_ald_cache_fetch(util_ald_cache_t *cache, void *payload)
{
    int hashval;
    util_cache_node_t *p;

    if (cache == NULL)
        return NULL;

    cache->fetches++;

    hashval = (*cache->hash)(payload) % cache->size;
    for (p = cache->nodes[hashval]; 
         p && !(*cache->compare)(p->payload, payload);
    p = p->next) ;

    if (p != NULL) {
        cache->hits++;
        return p->payload;
    }
    else {
        return NULL;
    }
}

/*
 * Insert an item into the cache. 
 * *** Does not catch duplicates!!! ***
 */
void util_ald_cache_insert(util_ald_cache_t *cache, void *payload)
{
    int hashval;
    util_cache_node_t *node;

    if (cache == NULL || payload == NULL)
        return;

    cache->inserts++;
    hashval = (*cache->hash)(payload) % cache->size;
    node = (util_cache_node_t *)util_ald_alloc(sizeof(util_cache_node_t));
    node->add_time = apr_time_now();
    node->payload = (*cache->copy)(payload);
    node->next = cache->nodes[hashval];
    cache->nodes[hashval] = node;
    if (++cache->numentries == cache->fullmark) 
        cache->marktime=apr_time_now();
    if (cache->numentries >= cache->maxentries)
        util_ald_cache_purge(cache);
}

void util_ald_cache_remove(util_ald_cache_t *cache, void *payload)
{
    int hashval;
    util_cache_node_t *p, *q;
  
    if (cache == NULL)
        return;

    cache->removes++;
    hashval = (*cache->hash)(payload) % cache->size;
    for (p = cache->nodes[hashval], q=NULL;
         p && !(*cache->compare)(p->payload, payload);
         p = p->next) {
         q = p;
    }

    /* If p is null, it means that we couldn't find the node, so just return */
    if (p == NULL)
        return;

    if (q == NULL) {
        /* We found the node, and it's the first in the list */
        cache->nodes[hashval] = p->next;
    }
    else {
        /* We found the node and it's not the first in the list */
        q->next = p->next;
    }
    (*cache->free)(p->payload);
    util_ald_free(p);
    cache->numentries--;
}

char *util_ald_cache_display_stats(apr_pool_t *p, util_ald_cache_t *cache, char *name)
{
    unsigned long i;
    int totchainlen = 0;
    int nchains = 0;
    double chainlen;
    util_cache_node_t *n;
    char *buf;

    if (cache == NULL) {
        return "";
    }

    for (i=0; i < cache->size; ++i) {
        if (cache->nodes[i] != NULL) {
            nchains++;
            for (n = cache->nodes[i]; n != NULL; n = n->next)
	        totchainlen++;
        }
    }
    chainlen = nchains? (double)totchainlen / (double)nchains : 0;

    buf = apr_psprintf(p, 
             "<tr valign='top'>"
             "<td nowrap>%s</td>"
             "<td align='right' nowrap>%lu (%.0f%% full)</td>"
             "<td align='right'>%.1f</td>"
	     "<td align='right'>%lu/%lu</td>"
	     "<td align='right'>%.0f%%</td>"
             "<td align='right'>%lu/%lu</td>",
             name,
	     cache->numentries, 
	     (double)cache->numentries / (double)cache->maxentries * 100.0,
             chainlen,
	     cache->hits, 	     
	     cache->fetches,
	     (cache->fetches > 0 ? (double)(cache->hits) / (double)(cache->fetches) * 100.0 : 100.0),
	     cache->inserts,
	     cache->removes);

    if (cache->numpurges) {
        char str_ctime[APR_CTIME_LEN];

        apr_ctime(str_ctime, cache->last_purge);
        buf = apr_psprintf(p,
                           "%s"
	                   "<td align='right'>%lu</td>\n"
                           "<td align='right' nowrap>%s</td>\n", 
                           buf,
	                   cache->numpurges,
	                   str_ctime);
    }
    else {
        buf = apr_psprintf(p, 
                           "%s<td colspan='2' align='center'>(none)</td>\n",
                           buf);
    }

    buf = apr_psprintf(p, "%s<td align='right'>%.2g</td>\n</tr>", buf, cache->avg_purgetime);

    return buf;
}

char *util_ald_cache_display(apr_pool_t *pool)
{
    unsigned long i;
    char *buf, *t1, *t2, *t3;

    if (!util_ldap_cache) {
        return "<tr valign='top'><td nowrap colspan=7>Cache has not been enabled/initialised.</td></tr>";
    }

    buf = util_ald_cache_display_stats(pool, util_ldap_cache, "LDAP URL Cache");

    for (i=0; i < util_ldap_cache->size; ++i) {
        util_cache_node_t *p;
        for (p = util_ldap_cache->nodes[i]; p != NULL; p = p->next) {
            util_url_node_t *n;

            n = (util_url_node_t *)p->payload;

            t1 = apr_psprintf(pool, "%s (Searches)", n->url);
            t2 = apr_psprintf(pool, "%s (Compares)", n->url);
            t3 = apr_psprintf(pool, "%s (DNCompares)", n->url);

            buf = apr_psprintf(pool, "%s\n\n"
                                     "%s\n\n"
                                     "%s\n\n"
                                     "%s\n\n",
                                     buf,
                                     util_ald_cache_display_stats(pool, n->search_cache, t1),
                                     util_ald_cache_display_stats(pool, n->compare_cache, t2),
                                     util_ald_cache_display_stats(pool, n->dn_compare_cache, t3)
                              );
        }
    }
    return buf;
}

#endif /* APU_HAS_LDAP */
