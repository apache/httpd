/* Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
 * util_ldap_cache.c: LDAP cache things
 * 
 * Original code from auth_ldap module for Apache v1.3:
 * Copyright 1998, 1999 Enbridge Pipelines Inc. 
 * Copyright 1999-2001 Dave Carrigan
 */

#include <apr_ldap.h>
#include "util_ldap.h"
#include "util_ldap_cache.h"

#ifdef APU_HAS_LDAP

#define MODLDAP_SHMEM_CACHE "/tmp/mod_ldap_cache"


/* ------------------------------------------------------------------ */

unsigned long util_ldap_url_node_hash(void *n)
{
    util_url_node_t *node = (util_url_node_t *)n;
    return util_ald_hash_string(1, node->url);
}

int util_ldap_url_node_compare(void *a, void *b)
{
    util_url_node_t *na = (util_url_node_t *)a;
    util_url_node_t *nb = (util_url_node_t *)b;

    return(strcmp(na->url, nb->url) == 0);
}

void *util_ldap_url_node_copy(void *c)
{
    util_url_node_t *n = (util_url_node_t *)c;
    util_url_node_t *node = (util_url_node_t *)util_ald_alloc(sizeof(util_url_node_t));

    if (node) {
        if (!(node->url = util_ald_strdup(n->url))) {
            util_ald_free(node->url);
            return NULL;
        }
        node->search_cache = n->search_cache;
        node->compare_cache = n->compare_cache;
        node->dn_compare_cache = n->dn_compare_cache;
        return node;
    }
    else {
        return NULL;
    }
}

void util_ldap_url_node_free(void *n)
{
    util_url_node_t *node = (util_url_node_t *)n;

    util_ald_free(node->url);
    util_ald_destroy_cache(node->search_cache);
    util_ald_destroy_cache(node->compare_cache);
    util_ald_destroy_cache(node->dn_compare_cache);
    util_ald_free(node);
}

/* ------------------------------------------------------------------ */

/* Cache functions for search nodes */
unsigned long util_ldap_search_node_hash(void *n)
{
    util_search_node_t *node = (util_search_node_t *)n;
    return util_ald_hash_string(1, ((util_search_node_t *)(node))->username);
}

int util_ldap_search_node_compare(void *a, void *b)
{
    return(strcmp(((util_search_node_t *)a)->username,
		  ((util_search_node_t *)b)->username) == 0);
}

void *util_ldap_search_node_copy(void *c)
{
    util_search_node_t *node = (util_search_node_t *)c;
    util_search_node_t *newnode = util_ald_alloc(sizeof(util_search_node_t));

    /* safety check */
    if (newnode) {

        /* copy vals */
        if (node->vals) {
            int k = 0;
            int i = 0;
            while (node->vals[k++]);
            if (!(newnode->vals = util_ald_alloc(sizeof(char *) * (k+1)))) {
                util_ldap_search_node_free(newnode);
                return NULL;
            }
            while (node->vals[i]) {
                if (!(newnode->vals[i] = util_ald_strdup(node->vals[i]))) {
                    util_ldap_search_node_free(newnode);
                    return NULL;
                }
                i++;
            }
        }
        else {
            newnode->vals = NULL;
        }
        if (!(newnode->username = util_ald_strdup(node->username)) ||
            !(newnode->dn = util_ald_strdup(node->dn)) ||
            !(newnode->bindpw = util_ald_strdup(node->bindpw)) ) {
            util_ldap_search_node_free(newnode);
            return NULL;
        }
        newnode->lastbind = node->lastbind;

    }
    return (void *)newnode;
}

void util_ldap_search_node_free(void *n)
{
    int i = 0;
    util_search_node_t *node = (util_search_node_t *)n;
    if (node->vals) {
        while (node->vals[i]) {
            util_ald_free(node->vals[i++]);
        }
        util_ald_free(node->vals);
    }
    util_ald_free(node->username);
    util_ald_free(node->dn);
    util_ald_free(node->bindpw);
    util_ald_free(node);
}

/* ------------------------------------------------------------------ */

unsigned long util_ldap_compare_node_hash(void *n)
{
    util_compare_node_t *node = (util_compare_node_t *)n;
    return util_ald_hash_string(3, node->dn, node->attrib, node->value);
}

int util_ldap_compare_node_compare(void *a, void *b)
{
    util_compare_node_t *na = (util_compare_node_t *)a;
    util_compare_node_t *nb = (util_compare_node_t *)b;
    return (strcmp(na->dn, nb->dn) == 0 &&
	    strcmp(na->attrib, nb->attrib) == 0 &&
	    strcmp(na->value, nb->value) == 0);
}

void *util_ldap_compare_node_copy(void *c)
{
    util_compare_node_t *n = (util_compare_node_t *)c;
    util_compare_node_t *node = (util_compare_node_t *)util_ald_alloc(sizeof(util_compare_node_t));

    if (node) {
        if (!(node->dn = util_ald_strdup(n->dn)) ||
            !(node->attrib = util_ald_strdup(n->attrib)) ||
            !(node->value = util_ald_strdup(n->value))) {
            util_ldap_compare_node_free(node);
            return NULL;
        }
        node->lastcompare = n->lastcompare;
        node->result = n->result;
        return node;
    }
    else {
        return NULL;
    }
}

void util_ldap_compare_node_free(void *n)
{
    util_compare_node_t *node = (util_compare_node_t *)n;
    util_ald_free(node->dn);
    util_ald_free(node->attrib);
    util_ald_free(node->value);
    util_ald_free(node);
}

/* ------------------------------------------------------------------ */

unsigned long util_ldap_dn_compare_node_hash(void *n)
{
    return util_ald_hash_string(1, ((util_dn_compare_node_t *)n)->reqdn);
}

int util_ldap_dn_compare_node_compare(void *a, void *b)
{
    return (strcmp(((util_dn_compare_node_t *)a)->reqdn,
		   ((util_dn_compare_node_t *)b)->reqdn) == 0);
}

void *util_ldap_dn_compare_node_copy(void *c)
{
    util_dn_compare_node_t *n = (util_dn_compare_node_t *)c;
    util_dn_compare_node_t *node = (util_dn_compare_node_t *)util_ald_alloc(sizeof(util_dn_compare_node_t));
    if (node) {
        if (!(node->reqdn = util_ald_strdup(n->reqdn)) ||
            !(node->dn = util_ald_strdup(n->dn))) {
            util_ldap_dn_compare_node_free(node);
            return NULL;
        }
        return node;
    }
    else {
        return NULL;
    }
}

void util_ldap_dn_compare_node_free(void *n)
{
    util_dn_compare_node_t *node = (util_dn_compare_node_t *)n;
    util_ald_free(node->reqdn);
    util_ald_free(node->dn);
    util_ald_free(node);
}


/* ------------------------------------------------------------------ */
apr_status_t util_ldap_cache_child_kill(void *data);
apr_status_t util_ldap_cache_module_kill(void *data);

apr_status_t util_ldap_cache_module_kill(void *data)
{
#if APR_HAS_SHARED_MEMORY
    if (util_ldap_shm != NULL) {
        apr_status_t result = apr_shm_destroy(util_ldap_shm);
        util_ldap_shm = NULL;
        return result;
    }
#endif
    util_ald_destroy_cache(util_ldap_cache);
    return APR_SUCCESS;
}

apr_status_t util_ldap_cache_init(apr_pool_t *pool, apr_size_t reqsize)
{
#if APR_HAS_SHARED_MEMORY
    apr_status_t result;

    result = apr_shm_create(&util_ldap_shm, reqsize, MODLDAP_SHMEM_CACHE, pool);
    if (result == EEXIST) {
        /*
         * The cache could have already been created (i.e. we may be a child process).  See
         * if we can attach to the existing shared memory
         */
        result = apr_shm_attach(&util_ldap_shm, MODLDAP_SHMEM_CACHE, pool);
    } 
    if (result != APR_SUCCESS) {
        return result;
    }

    /* This will create a rmm "handler" to get into the shared memory area */
    apr_rmm_init(&util_ldap_rmm, NULL,
			(void *)apr_shm_baseaddr_get(util_ldap_shm), reqsize, pool);
#endif

    apr_pool_cleanup_register(pool, NULL, util_ldap_cache_module_kill, apr_pool_cleanup_null);

    util_ldap_cache = util_ald_create_cache(50,
				     util_ldap_url_node_hash,
				     util_ldap_url_node_compare,
				     util_ldap_url_node_copy,
				     util_ldap_url_node_free);
    return APR_SUCCESS;
}


#endif /* APU_HAS_LDAP */
