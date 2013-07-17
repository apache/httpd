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
 * util_ldap_cache.c: LDAP cache things
 *
 * Original code from auth_ldap module for Apache v1.3:
 * Copyright 1998, 1999 Enbridge Pipelines Inc.
 * Copyright 1999-2001 Dave Carrigan
 */

#include "httpd.h"
#include "util_ldap.h"
#include "util_ldap_cache.h"
#include <apr_strings.h>

#if APR_HAS_LDAP

/* ------------------------------------------------------------------ */

unsigned long util_ldap_url_node_hash(void *n)
{
    util_url_node_t *node = n;
    return util_ald_hash_string(1, node->url);
}

int util_ldap_url_node_compare(void *a, void *b)
{
    util_url_node_t *na = a;
    util_url_node_t *nb = b;

    return (strcmp(na->url, nb->url) == 0);
}

void *util_ldap_url_node_copy(util_ald_cache_t *cache, void *c)
{
    util_url_node_t *n = c;
    util_url_node_t *node = util_ald_alloc(cache, sizeof *node);

    if (node) {
        if (!(node->url = util_ald_strdup(cache, n->url))) {
            util_ald_free(cache, node);
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

void util_ldap_url_node_free(util_ald_cache_t *cache, void *n)
{
    util_url_node_t *node = n;

    util_ald_free(cache, node->url);
    util_ald_destroy_cache(node->search_cache);
    util_ald_destroy_cache(node->compare_cache);
    util_ald_destroy_cache(node->dn_compare_cache);
    util_ald_free(cache, node);
}

void util_ldap_url_node_display(request_rec *r, util_ald_cache_t *cache, void *n)
{
    util_url_node_t *node = n;
    char date_str[APR_CTIME_LEN];
    const char *type_str;
    util_ald_cache_t *cache_node;
    int x;

    for (x=0;x<3;x++) {
        switch (x) {
            case 0:
                cache_node = node->search_cache;
                type_str = "Searches";
                break;
            case 1:
                cache_node = node->compare_cache;
                type_str = "Compares";
                break;
            case 2:
            default:
                cache_node = node->dn_compare_cache;
                type_str = "DN Compares";
                break;
        }

        if (cache_node->marktime) {
            apr_ctime(date_str, cache_node->marktime);
        }
        else
            date_str[0] = 0;

        ap_rprintf(r,
                   "<tr valign='top'>"
                   "<td nowrap>%s (%s)</td>"
                   "<td nowrap>%ld</td>"
                   "<td nowrap>%ld</td>"
                   "<td nowrap>%ld</td>"
                   "<td nowrap>%ld</td>"
                   "<td nowrap>%s</td>"
                   "</tr>",
                   node->url,
                   type_str,
                   cache_node->size,
                   cache_node->maxentries,
                   cache_node->numentries,
                   cache_node->fullmark,
                   date_str);
    }

}

/* ------------------------------------------------------------------ */

/* Cache functions for search nodes */
unsigned long util_ldap_search_node_hash(void *n)
{
    util_search_node_t *node = n;
    return util_ald_hash_string(1, node->username);
}

int util_ldap_search_node_compare(void *a, void *b)
{
    util_search_node_t *na = a;
    util_search_node_t *nb = b;

    return (strcmp(na->username, nb->username) == 0);
}

void *util_ldap_search_node_copy(util_ald_cache_t *cache, void *c)
{
    util_search_node_t *node = c;
    util_search_node_t *newnode = util_ald_alloc(cache, sizeof *newnode);

    /* safety check */
    if (newnode) {

        /* copy vals */
        if (node->vals) {
            int k = node->numvals;
            int i = 0;
            if (!(newnode->vals = util_ald_alloc(cache, sizeof(char *) * (k+1)))) {
                util_ldap_search_node_free(cache, newnode);
                return NULL;
            }
            newnode->numvals = node->numvals;
            for (;k;k--) {
                if (node->vals[i]) {
                    if (!(newnode->vals[i] = util_ald_strdup(cache, node->vals[i]))) {
                        util_ldap_search_node_free(cache, newnode);
                        return NULL;
                    }
                }
                else
                    newnode->vals[i] = NULL;
                i++;
            }
        }
        else {
            newnode->vals = NULL;
        }
        if (!(newnode->username = util_ald_strdup(cache, node->username)) ||
            !(newnode->dn = util_ald_strdup(cache, node->dn)) ) {
            util_ldap_search_node_free(cache, newnode);
            return NULL;
        }
        if(node->bindpw) {
            if(!(newnode->bindpw = util_ald_strdup(cache, node->bindpw))) {
                util_ldap_search_node_free(cache, newnode);
                return NULL;
            }
        } else {
            newnode->bindpw = NULL;
        }
        newnode->lastbind = node->lastbind;

    }
    return (void *)newnode;
}

void util_ldap_search_node_free(util_ald_cache_t *cache, void *n)
{
    int i = 0;
    util_search_node_t *node = n;
    int k = node->numvals;

    if (node->vals) {
        for (;k;k--,i++) {
            if (node->vals[i]) {
                util_ald_free(cache, node->vals[i]);
            }
        }
        util_ald_free(cache, node->vals);
    }
    util_ald_free(cache, node->username);
    util_ald_free(cache, node->dn);
    util_ald_free(cache, node->bindpw);
    util_ald_free(cache, node);
}

void util_ldap_search_node_display(request_rec *r, util_ald_cache_t *cache, void *n)
{
    util_search_node_t *node = n;
    char date_str[APR_CTIME_LEN];

    apr_ctime(date_str, node->lastbind);

    ap_rprintf(r,
               "<tr valign='top'>"
               "<td nowrap>%s</td>"
               "<td nowrap>%s</td>"
               "<td nowrap>%s</td>"
               "</tr>",
               node->username,
               node->dn,
               date_str);
}

/* ------------------------------------------------------------------ */

unsigned long util_ldap_compare_node_hash(void *n)
{
    util_compare_node_t *node = n;
    return util_ald_hash_string(3, node->dn, node->attrib, node->value);
}

int util_ldap_compare_node_compare(void *a, void *b)
{
    util_compare_node_t *na = a;
    util_compare_node_t *nb = b;

    return (strcmp(na->dn, nb->dn) == 0 &&
            strcmp(na->attrib, nb->attrib) == 0 &&
            strcmp(na->value, nb->value) == 0);
}

void *util_ldap_compare_node_copy(util_ald_cache_t *cache, void *c)
{
    util_compare_node_t *n = c;
    util_compare_node_t *node = util_ald_alloc(cache, sizeof *node);

    if (node) {
        if (!(node->dn = util_ald_strdup(cache, n->dn)) ||
            !(node->attrib = util_ald_strdup(cache, n->attrib)) ||
            !(node->value = util_ald_strdup(cache, n->value)) ||
            ((n->subgroupList) && !(node->subgroupList = util_ald_sgl_dup(cache, n->subgroupList)))) {
            util_ldap_compare_node_free(cache, node);
            return NULL;
        }
        node->lastcompare = n->lastcompare;
        node->result = n->result;
        node->sgl_processed = n->sgl_processed;
        return node;
    }
    else {
        return NULL;
    }
}

void util_ldap_compare_node_free(util_ald_cache_t *cache, void *n)
{
    util_compare_node_t *node = n;

    util_ald_sgl_free(cache, &(node->subgroupList));
    util_ald_free(cache, node->dn);
    util_ald_free(cache, node->attrib);
    util_ald_free(cache, node->value);
    util_ald_free(cache, node);
}

void util_ldap_compare_node_display(request_rec *r, util_ald_cache_t *cache, void *n)
{
    util_compare_node_t *node = n;
    char date_str[APR_CTIME_LEN];
    char *cmp_result;
    char *sub_groups_val;
    char *sub_groups_checked;

    apr_ctime(date_str, node->lastcompare);

    if (node->result == LDAP_COMPARE_TRUE) {
        cmp_result = "LDAP_COMPARE_TRUE";
    }
    else if (node->result == LDAP_COMPARE_FALSE) {
        cmp_result = "LDAP_COMPARE_FALSE";
    }
    else {
        cmp_result = apr_itoa(r->pool, node->result);
    }

    if(node->subgroupList) {
        sub_groups_val = "Yes";
    }
    else {
        sub_groups_val = "No";
    }

    if(node->sgl_processed) {
        sub_groups_checked = "Yes";
    }
    else {
        sub_groups_checked = "No";
    }

    ap_rprintf(r,
               "<tr valign='top'>"
               "<td nowrap>%s</td>"
               "<td nowrap>%s</td>"
               "<td nowrap>%s</td>"
               "<td nowrap>%s</td>"
               "<td nowrap>%s</td>"
               "<td nowrap>%s</td>"
               "<td nowrap>%s</td>"
               "</tr>",
               node->dn,
               node->attrib,
               node->value,
               date_str,
               cmp_result,
               sub_groups_val,
               sub_groups_checked);
}

/* ------------------------------------------------------------------ */

unsigned long util_ldap_dn_compare_node_hash(void *n)
{
    util_dn_compare_node_t *node = n;
    return util_ald_hash_string(1, node->reqdn);
}

int util_ldap_dn_compare_node_compare(void *a, void *b)
{
    util_dn_compare_node_t *na = a;
    util_dn_compare_node_t *nb = b;

    return (strcmp(na->reqdn, nb->reqdn) == 0);
}

void *util_ldap_dn_compare_node_copy(util_ald_cache_t *cache, void *c)
{
    util_dn_compare_node_t *n = c;
    util_dn_compare_node_t *node = util_ald_alloc(cache, sizeof *node);

    if (node) {
        if (!(node->reqdn = util_ald_strdup(cache, n->reqdn)) ||
            !(node->dn = util_ald_strdup(cache, n->dn))) {
            util_ldap_dn_compare_node_free(cache, node);
            return NULL;
        }
        return node;
    }
    else {
        return NULL;
    }
}

void util_ldap_dn_compare_node_free(util_ald_cache_t *cache, void *n)
{
    util_dn_compare_node_t *node = n;
    util_ald_free(cache, node->reqdn);
    util_ald_free(cache, node->dn);
    util_ald_free(cache, node);
}

void util_ldap_dn_compare_node_display(request_rec *r, util_ald_cache_t *cache, void *n)
{
    util_dn_compare_node_t *node = n;

    ap_rprintf(r,
               "<tr valign='top'>"
               "<td nowrap>%s</td>"
               "<td nowrap>%s</td>"
               "</tr>",
               node->reqdn,
               node->dn);
}


/* ------------------------------------------------------------------ */
static apr_status_t util_ldap_cache_module_kill(void *data)
{
    util_ldap_state_t *st = data;

    util_ald_destroy_cache(st->util_ldap_cache);
#if APR_HAS_SHARED_MEMORY
    if (st->cache_rmm != NULL) {
        apr_rmm_destroy (st->cache_rmm);
        st->cache_rmm = NULL;
    }
    if (st->cache_shm != NULL) {
        apr_status_t result = apr_shm_destroy(st->cache_shm);
        st->cache_shm = NULL;
        return result;
    }
#endif
    return APR_SUCCESS;
}

apr_status_t util_ldap_cache_init(apr_pool_t *pool, util_ldap_state_t *st)
{
#if APR_HAS_SHARED_MEMORY
    apr_status_t result;
    apr_size_t size;

    if (st->cache_bytes > 0) {
        if (st->cache_file) {
            /* Remove any existing shm segment with this name. */
            apr_shm_remove(st->cache_file, st->pool);
        }

        size = APR_ALIGN_DEFAULT(st->cache_bytes);

        result = apr_shm_create(&st->cache_shm, size, st->cache_file, st->pool);
        if (result != APR_SUCCESS) {
            return result;
        }

        /* Determine the usable size of the shm segment. */
        size = apr_shm_size_get(st->cache_shm);

        /* This will create a rmm "handler" to get into the shared memory area */
        result = apr_rmm_init(&st->cache_rmm, NULL,
                              apr_shm_baseaddr_get(st->cache_shm), size,
                              st->pool);
        if (result != APR_SUCCESS) {
            return result;
        }
    }

#endif

    apr_pool_cleanup_register(st->pool, st , util_ldap_cache_module_kill, apr_pool_cleanup_null);

    st->util_ldap_cache =
        util_ald_create_cache(st,
                              st->search_cache_size,
                              util_ldap_url_node_hash,
                              util_ldap_url_node_compare,
                              util_ldap_url_node_copy,
                              util_ldap_url_node_free,
                              util_ldap_url_node_display);
    return APR_SUCCESS;
}


#endif /* APR_HAS_LDAP */
