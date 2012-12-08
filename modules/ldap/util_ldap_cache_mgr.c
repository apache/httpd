/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * util_ldap_cache_mgr.c: LDAP cache manager things
 *
 * Original code from auth_ldap module for Apache v1.3:
 * Copyright 1998, 1999 Enbridge Pipelines Inc.
 * Copyright 1999-2001 Dave Carrigan
 */

#include "httpd.h"
#include "util_ldap.h"
#include "util_ldap_cache.h"
#include <apr_strings.h>

APLOG_USE_MODULE(ldap);

#if APR_HAS_LDAP

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

void util_ald_free(util_ald_cache_t *cache, const void *ptr)
{
#if APR_HAS_SHARED_MEMORY
    if (cache->rmm_addr) {
        if (ptr)
            /* Free in shared memory */
            apr_rmm_free(cache->rmm_addr, apr_rmm_offset_get(cache->rmm_addr, (void *)ptr));
    }
    else {
        if (ptr)
            /* Cache shm is not used */
            free((void *)ptr);
    }
#else
    if (ptr)
        free((void *)ptr);
#endif
}

void *util_ald_alloc(util_ald_cache_t *cache, unsigned long size)
{
    if (0 == size)
        return NULL;
#if APR_HAS_SHARED_MEMORY
    if (cache->rmm_addr) {
        /* allocate from shared memory */
        apr_rmm_off_t block = apr_rmm_calloc(cache->rmm_addr, size);
        return block ? (void *)apr_rmm_addr_get(cache->rmm_addr, block) : NULL;
    }
    else {
        /* Cache shm is not used */
        return (void *)calloc(sizeof(char), size);
    }
#else
    return (void *)calloc(sizeof(char), size);
#endif
}

const char *util_ald_strdup(util_ald_cache_t *cache, const char *s)
{
#if APR_HAS_SHARED_MEMORY
    if (cache->rmm_addr) {
        /* allocate from shared memory */
        apr_rmm_off_t block = apr_rmm_calloc(cache->rmm_addr, strlen(s)+1);
        char *buf = block ? (char *)apr_rmm_addr_get(cache->rmm_addr, block) : NULL;
        if (buf) {
            strcpy(buf, s);
            return buf;
        }
        else {
            return NULL;
        }
    }
    else {
        /* Cache shm is not used */
        return strdup(s);
    }
#else
    return strdup(s);
#endif
}

/*
 * Duplicate a subgroupList from one compare entry to another.
 * Returns: ptr to a new copy of the subgroupList or NULL if allocation failed.
 */
util_compare_subgroup_t *util_ald_sgl_dup(util_ald_cache_t *cache, util_compare_subgroup_t *sgl_in)
{
    int i = 0;
    util_compare_subgroup_t *sgl_out = NULL;

    if (!sgl_in) {
        return NULL;
    }

    sgl_out = (util_compare_subgroup_t *) util_ald_alloc(cache, sizeof(util_compare_subgroup_t));
    if (sgl_out) {
        sgl_out->subgroupDNs = util_ald_alloc(cache, sizeof(char *) * sgl_in->len);
        if (sgl_out->subgroupDNs) {
            for (i = 0; i < sgl_in->len; i++) {
                sgl_out->subgroupDNs[i] = util_ald_strdup(cache, sgl_in->subgroupDNs[i]);
                if (!sgl_out->subgroupDNs[i]) {
                    /* We ran out of SHM, delete the strings we allocated for the SGL */
                    for (i = (i - 1); i >= 0; i--) {
                            util_ald_free(cache, sgl_out->subgroupDNs[i]);
                    }
                    util_ald_free(cache, sgl_out->subgroupDNs);
                    util_ald_free(cache, sgl_out);
                    sgl_out =  NULL;
                    break;
                }
            }
            /* We were able to allocate new strings for all the subgroups */
            if (sgl_out != NULL) {
                sgl_out->len = sgl_in->len;
            }
        }
    }

    return sgl_out;
}

/*
 * Delete an entire subgroupList.
 */
void util_ald_sgl_free(util_ald_cache_t *cache, util_compare_subgroup_t **sgl)
{
    int i = 0;
    if (sgl == NULL || *sgl == NULL) {
        return;
    }

    for (i = 0; i < (*sgl)->len; i++) {
        util_ald_free(cache, (*sgl)->subgroupDNs[i]);
    }
    util_ald_free(cache, *sgl);
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
    util_cache_node_t *p, *q, **pp;
    apr_time_t t;

    if (!cache)
        return;

    cache->last_purge = apr_time_now();
    cache->npurged = 0;
    cache->numpurges++;

    for (i=0; i < cache->size; ++i) {
        pp = cache->nodes + i;
        p = *pp;
        while (p != NULL) {
            if (p->add_time < cache->marktime) {
                q = p->next;
                (*cache->free)(cache, p->payload);
                util_ald_free(cache, p);
                cache->numentries--;
                cache->npurged++;
                p = *pp = q;
            }
            else {
                pp = &(p->next);
                p = *pp;
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
    util_url_node_t curl, *newcurl = NULL;
    util_ald_cache_t *search_cache;
    util_ald_cache_t *compare_cache;
    util_ald_cache_t *dn_compare_cache;

    /* create the three caches */
    search_cache = util_ald_create_cache(st,
                      st->search_cache_size,
                      util_ldap_search_node_hash,
                      util_ldap_search_node_compare,
                      util_ldap_search_node_copy,
                      util_ldap_search_node_free,
                      util_ldap_search_node_display);
    compare_cache = util_ald_create_cache(st,
                      st->compare_cache_size,
                      util_ldap_compare_node_hash,
                      util_ldap_compare_node_compare,
                      util_ldap_compare_node_copy,
                      util_ldap_compare_node_free,
                      util_ldap_compare_node_display);
    dn_compare_cache = util_ald_create_cache(st,
                      st->compare_cache_size,
                      util_ldap_dn_compare_node_hash,
                      util_ldap_dn_compare_node_compare,
                      util_ldap_dn_compare_node_copy,
                      util_ldap_dn_compare_node_free,
                      util_ldap_dn_compare_node_display);

    /* check that all the caches initialised successfully */
    if (search_cache && compare_cache && dn_compare_cache) {

        /* The contents of this structure will be duplicated in shared
           memory during the insert.  So use stack memory rather than
           pool memory to avoid a memory leak. */
        memset (&curl, 0, sizeof(util_url_node_t));
        curl.url = url;
        curl.search_cache = search_cache;
        curl.compare_cache = compare_cache;
        curl.dn_compare_cache = dn_compare_cache;

        newcurl = util_ald_cache_insert(st->util_ldap_cache, &curl);

    }

    return newcurl;
}


util_ald_cache_t *util_ald_create_cache(util_ldap_state_t *st,
                                long cache_size,
                                unsigned long (*hashfunc)(void *),
                                int (*comparefunc)(void *, void *),
                                void * (*copyfunc)(util_ald_cache_t *cache, void *),
                                void (*freefunc)(util_ald_cache_t *cache, void *),
                                void (*displayfunc)(request_rec *r, util_ald_cache_t *cache, void *))
{
    util_ald_cache_t *cache;
    unsigned long i;
#if APR_HAS_SHARED_MEMORY
    apr_rmm_off_t block;
#endif

    if (cache_size <= 0)
        return NULL;

#if APR_HAS_SHARED_MEMORY
    if (!st->cache_rmm) {
        cache = (util_ald_cache_t *)calloc(sizeof(util_ald_cache_t), 1);
    }
    else {
        block = apr_rmm_calloc(st->cache_rmm, sizeof(util_ald_cache_t));
        cache = block ? (util_ald_cache_t *)apr_rmm_addr_get(st->cache_rmm, block) : NULL;
    }
#else
    cache = (util_ald_cache_t *)calloc(sizeof(util_ald_cache_t), 1);
#endif
    if (!cache)
        return NULL;

#if APR_HAS_SHARED_MEMORY
    cache->rmm_addr = st->cache_rmm;
    cache->shm_addr = st->cache_shm;
#endif
    cache->maxentries = cache_size;
    cache->numentries = 0;
    cache->size = cache_size / 3;
    if (cache->size < 64) cache->size = 64;
        for (i = 0; primes[i] && primes[i] < cache->size; ++i) ;
            cache->size = primes[i]? primes[i] : primes[i-1];

    cache->nodes = (util_cache_node_t **)util_ald_alloc(cache, cache->size * sizeof(util_cache_node_t *));
    if (!cache->nodes) {
        /* This frees cache in the right way even if !APR_HAS_SHARED_MEMORY or !st->cache_rmm */
        util_ald_free(cache, cache);
        return NULL;
    }

    for (i=0; i < cache->size; ++i)
        cache->nodes[i] = NULL;

    cache->hash = hashfunc;
    cache->compare = comparefunc;
    cache->copy = copyfunc;
    cache->free = freefunc;
    cache->display = displayfunc;

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
           (*cache->free)(cache, p->payload);
           util_ald_free(cache, p);
           p = q;
        }
    }
    util_ald_free(cache, cache->nodes);
    util_ald_free(cache, cache);
}

void *util_ald_cache_fetch(util_ald_cache_t *cache, void *payload)
{
    unsigned long hashval;
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
void *util_ald_cache_insert(util_ald_cache_t *cache, void *payload)
{
    unsigned long hashval;
    void *tmp_payload;
    util_cache_node_t *node;

    /* sanity check */
    if (cache == NULL || payload == NULL) {
        return NULL;
    }

    /* check if we are full - if so, try purge */
    if (cache->numentries >= cache->maxentries) {
        util_ald_cache_purge(cache);
        if (cache->numentries >= cache->maxentries) {
            /* if the purge was not effective, we leave now to avoid an overflow */
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(01323)
                         "Purge of LDAP cache failed");
            return NULL;
        }
    }

    node = (util_cache_node_t *)util_ald_alloc(cache,
                                               sizeof(util_cache_node_t));
    if (node == NULL) {
        /*
         * XXX: The cache management should be rewritten to work
         * properly when LDAPSharedCacheSize is too small.
         */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, APLOGNO(01324)
                     "LDAPSharedCacheSize is too small. Increase it or "
                     "reduce LDAPCacheEntries/LDAPOpCacheEntries!");
        if (cache->numentries < cache->fullmark) {
            /*
             * We have not even reached fullmark, trigger a complete purge.
             * This is still better than not being able to add new entries
             * at all.
             */
            cache->marktime = apr_time_now();
        }
        util_ald_cache_purge(cache);
        node = (util_cache_node_t *)util_ald_alloc(cache,
                                                   sizeof(util_cache_node_t));
        if (node == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(01325)
                         "Could not allocate memory for LDAP cache entry");
            return NULL;
        }
    }

    /* Take a copy of the payload before proceeeding. */
    tmp_payload = (*cache->copy)(cache, payload);
    if (tmp_payload == NULL) {
        /*
         * XXX: The cache management should be rewritten to work
         * properly when LDAPSharedCacheSize is too small.
         */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, APLOGNO(01326)
                     "LDAPSharedCacheSize is too small. Increase it or "
                     "reduce LDAPCacheEntries/LDAPOpCacheEntries!");
        if (cache->numentries < cache->fullmark) {
            /*
             * We have not even reached fullmark, trigger a complete purge.
             * This is still better than not being able to add new entries
             * at all.
             */
            cache->marktime = apr_time_now();
        }
        util_ald_cache_purge(cache);
        tmp_payload = (*cache->copy)(cache, payload);
        if (tmp_payload == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(01327)
                         "Could not allocate memory for LDAP cache value");
            util_ald_free(cache, node);
            return NULL;
        }
    }
    payload = tmp_payload;

    /* populate the entry */
    cache->inserts++;
    hashval = (*cache->hash)(payload) % cache->size;
    node->add_time = apr_time_now();
    node->payload = payload;
    node->next = cache->nodes[hashval];
    cache->nodes[hashval] = node;

    /* if we reach the full mark, note the time we did so
     * for the benefit of the purge function
     */
    if (++cache->numentries == cache->fullmark) {
        cache->marktime=apr_time_now();
    }

    return node->payload;
}

void util_ald_cache_remove(util_ald_cache_t *cache, void *payload)
{
    unsigned long hashval;
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
    (*cache->free)(cache, p->payload);
    util_ald_free(cache, p);
    cache->numentries--;
}

char *util_ald_cache_display_stats(request_rec *r, util_ald_cache_t *cache, char *name, char *id)
{
    unsigned long i;
    int totchainlen = 0;
    int nchains = 0;
    double chainlen;
    util_cache_node_t *n;
    char *buf, *buf2;
    apr_pool_t *p = r->pool;

    if (cache == NULL) {
        return "";
    }

    for (i=0; i < cache->size; ++i) {
        if (cache->nodes[i] != NULL) {
            nchains++;
            for (n = cache->nodes[i];
                 n != NULL && n != n->next;
                 n = n->next) {
                totchainlen++;
            }
        }
    }
    chainlen = nchains? (double)totchainlen / (double)nchains : 0;

    if (id) {
        buf2 = apr_psprintf(p,
                 "<a href=\"%s?%s\">%s</a>",
             ap_escape_html(r->pool, ap_escape_uri(r->pool, r->uri)),
             id,
             name);
    }
    else {
        buf2 = name;
    }

    buf = apr_psprintf(p,
             "<tr valign='top'>"
             "<td nowrap>%s</td>"
             "<td align='right' nowrap>%lu (%.0f%% full)</td>"
             "<td align='right'>%.1f</td>"
             "<td align='right'>%lu/%lu</td>"
             "<td align='right'>%.0f%%</td>"
             "<td align='right'>%lu/%lu</td>",
         buf2,
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

    buf = apr_psprintf(p, "%s<td align='right'>%.2gms</td>\n</tr>", buf, cache->avg_purgetime);

    return buf;
}

char *util_ald_cache_display(request_rec *r, util_ldap_state_t *st)
{
    unsigned long i,j;
    char *buf, *t1, *t2, *t3;
    char *id1, *id2, *id3;
    char *argfmt = "cache=%s&id=%d&off=%d";
    char *scanfmt = "cache=%4s&id=%u&off=%u%1s";
    apr_pool_t *pool = r->pool;
    util_cache_node_t *p = NULL;
    util_url_node_t *n = NULL;

    util_ald_cache_t *util_ldap_cache = st->util_ldap_cache;


    if (!util_ldap_cache) {
        ap_rputs("<tr valign='top'><td nowrap colspan=7>Cache has not been enabled/initialised.</td></tr>", r);
        return NULL;
    }

    if (r->args && strlen(r->args)) {
        char cachetype[5], lint[2];
        unsigned int id, off;
        char date_str[APR_CTIME_LEN];

        if ((3 == sscanf(r->args, scanfmt, cachetype, &id, &off, lint)) &&
            (id < util_ldap_cache->size)) {

            if ((p = util_ldap_cache->nodes[id]) != NULL) {
                n = (util_url_node_t *)p->payload;
                buf = (char*)n->url;
            }
            else {
                buf = "";
            }

            ap_rprintf(r,
                       "<p>\n"
                       "<table border='0'>\n"
                       "<tr>\n"
                       "<td bgcolor='#000000'><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Cache Name:</b></font></td>"
                       "<td bgcolor='#ffffff'><font size='-1' face='Arial,Helvetica' color='#000000'><b>%s (%s)</b></font></td>"
                       "</tr>\n"
                       "</table>\n</p>\n",
                       buf,
                       cachetype[0] == 'm'? "Main" :
                       (cachetype[0] == 's' ? "Search" :
                        (cachetype[0] == 'c' ? "Compares" : "DNCompares")));

            switch (cachetype[0]) {
                case 'm':
                    if (util_ldap_cache->marktime) {
                        apr_ctime(date_str, util_ldap_cache->marktime);
                    }
                    else
                        date_str[0] = 0;

                    ap_rprintf(r,
                               "<p>\n"
                               "<table border='0'>\n"
                               "<tr>\n"
                               "<td bgcolor='#000000'><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Size:</b></font></td>"
                               "<td bgcolor='#ffffff'><font size='-1' face='Arial,Helvetica' color='#000000'><b>%ld</b></font></td>"
                               "</tr>\n"
                               "<tr>\n"
                               "<td bgcolor='#000000'><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Max Entries:</b></font></td>"
                               "<td bgcolor='#ffffff'><font size='-1' face='Arial,Helvetica' color='#000000'><b>%ld</b></font></td>"
                               "</tr>\n"
                               "<tr>\n"
                               "<td bgcolor='#000000'><font size='-1' face='Arial,Helvetica' color='#ffffff'><b># Entries:</b></font></td>"
                               "<td bgcolor='#ffffff'><font size='-1' face='Arial,Helvetica' color='#000000'><b>%ld</b></font></td>"
                               "</tr>\n"
                               "<tr>\n"
                               "<td bgcolor='#000000'><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Full Mark:</b></font></td>"
                               "<td bgcolor='#ffffff'><font size='-1' face='Arial,Helvetica' color='#000000'><b>%ld</b></font></td>"
                               "</tr>\n"
                               "<tr>\n"
                               "<td bgcolor='#000000'><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Full Mark Time:</b></font></td>"
                               "<td bgcolor='#ffffff'><font size='-1' face='Arial,Helvetica' color='#000000'><b>%s</b></font></td>"
                               "</tr>\n"
                               "</table>\n</p>\n",
                               util_ldap_cache->size,
                               util_ldap_cache->maxentries,
                               util_ldap_cache->numentries,
                               util_ldap_cache->fullmark,
                               date_str);

                    ap_rputs("<p>\n"
                             "<table border='0'>\n"
                             "<tr bgcolor='#000000'>\n"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>LDAP URL</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Size</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Max Entries</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b># Entries</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Full Mark</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Full Mark Time</b></font></td>"
                             "</tr>\n", r
                            );
                    for (i=0; i < util_ldap_cache->size; ++i) {
                        for (p = util_ldap_cache->nodes[i]; p != NULL; p = p->next) {

                            (*util_ldap_cache->display)(r, util_ldap_cache, p->payload);
                        }
                    }
                    ap_rputs("</table>\n</p>\n", r);


                    break;
                case 's':
                    ap_rputs("<p>\n"
                             "<table border='0'>\n"
                             "<tr bgcolor='#000000'>\n"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>LDAP Filter</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>User Name</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Last Bind</b></font></td>"
                             "</tr>\n", r
                            );
                    if (n) {
                        for (i=0; i < n->search_cache->size; ++i) {
                            for (p = n->search_cache->nodes[i]; p != NULL; p = p->next) {

                                (*n->search_cache->display)(r, n->search_cache, p->payload);
                            }
                        }
                    }
                    ap_rputs("</table>\n</p>\n", r);
                    break;
                case 'c':
                    ap_rputs("<p>\n"
                             "<table border='0'>\n"
                             "<tr bgcolor='#000000'>\n"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>DN</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Attribute</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Value</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Last Compare</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Result</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Sub-groups?</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>S-G Checked?</b></font></td>"
                             "</tr>\n", r
                            );
                    if (n) {
                        for (i=0; i < n->compare_cache->size; ++i) {
                            for (p = n->compare_cache->nodes[i]; p != NULL; p = p->next) {

                                (*n->compare_cache->display)(r, n->compare_cache, p->payload);
                            }
                        }
                    }
                    ap_rputs("</table>\n</p>\n", r);
                    break;
                case 'd':
                    ap_rputs("<p>\n"
                             "<table border='0'>\n"
                             "<tr bgcolor='#000000'>\n"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Require DN</b></font></td>"
                             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Actual DN</b></font></td>"
                             "</tr>\n", r
                            );
                    if (n) {
                        for (i=0; i < n->dn_compare_cache->size; ++i) {
                            for (p = n->dn_compare_cache->nodes[i]; p != NULL; p = p->next) {

                                (*n->dn_compare_cache->display)(r, n->dn_compare_cache, p->payload);
                            }
                        }
                    }
                    ap_rputs("</table>\n</p>\n", r);
                    break;
                default:
                    break;
            }

        }
        else {
            buf = "";
        }
    }
    else {
        ap_rputs("<p>\n"
                 "<table border='0'>\n"
                 "<tr bgcolor='#000000'>\n"
                 "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Cache Name</b></font></td>"
                 "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Entries</b></font></td>"
                 "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Avg. Chain Len.</b></font></td>"
                 "<td colspan='2'><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Hits</b></font></td>"
                 "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Ins/Rem</b></font></td>"
                 "<td colspan='2'><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Purges</b></font></td>"
                 "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Avg Purge Time</b></font></td>"
                 "</tr>\n", r
                );


        id1 = apr_psprintf(pool, argfmt, "main", 0, 0);
        buf = util_ald_cache_display_stats(r, st->util_ldap_cache, "LDAP URL Cache", id1);

        for (i=0; i < util_ldap_cache->size; ++i) {
            for (p = util_ldap_cache->nodes[i],j=0; p != NULL; p = p->next,j++) {

                n = (util_url_node_t *)p->payload;

                t1 = apr_psprintf(pool, "%s (Searches)", n->url);
                t2 = apr_psprintf(pool, "%s (Compares)", n->url);
                t3 = apr_psprintf(pool, "%s (DNCompares)", n->url);
                id1 = apr_psprintf(pool, argfmt, "srch", i, j);
                id2 = apr_psprintf(pool, argfmt, "cmpr", i, j);
                id3 = apr_psprintf(pool, argfmt, "dncp", i, j);

                buf = apr_psprintf(pool, "%s\n\n"
                                         "%s\n\n"
                                         "%s\n\n"
                                         "%s\n\n",
                                         buf,
                                         util_ald_cache_display_stats(r, n->search_cache, t1, id1),
                                         util_ald_cache_display_stats(r, n->compare_cache, t2, id2),
                                         util_ald_cache_display_stats(r, n->dn_compare_cache, t3, id3)
                                  );
            }
        }
        ap_rputs(buf, r);
        ap_rputs("</table>\n</p>\n", r);
    }

    return buf;
}

#endif /* APR_HAS_LDAP */
