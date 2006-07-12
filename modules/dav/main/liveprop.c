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

#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_errno.h"
#include "apr_strings.h"
#include "util_xml.h"   /* for apr_text_header */
#include "mod_dav.h"


static apr_hash_t *dav_liveprop_uris = NULL;
static long dav_liveprop_count = 0;


static apr_status_t dav_cleanup_liveprops(void *ctx)
{
    dav_liveprop_uris = NULL;
    dav_liveprop_count = 0;
    return APR_SUCCESS;
}

static void dav_register_liveprop_namespace(apr_pool_t *p, const char *uri)
{
    long value;

    if (dav_liveprop_uris == NULL) {
        dav_liveprop_uris = apr_hash_make(p);
        apr_pool_cleanup_register(p, NULL, dav_cleanup_liveprops, apr_pool_cleanup_null);
    }

    value = (long)apr_hash_get(dav_liveprop_uris, uri, APR_HASH_KEY_STRING);
    if (value != 0) {
        /* already registered */
        return;
    }

    /* start at 1, and count up */
    apr_hash_set(dav_liveprop_uris, uri, APR_HASH_KEY_STRING,
                 (void *)++dav_liveprop_count);
}

DAV_DECLARE(long) dav_get_liveprop_ns_index(const char *uri)
{
    return (long)apr_hash_get(dav_liveprop_uris, uri, APR_HASH_KEY_STRING);
}

DAV_DECLARE(long) dav_get_liveprop_ns_count(void)
{
    return dav_liveprop_count;
}

DAV_DECLARE(void) dav_add_all_liveprop_xmlns(apr_pool_t *p,
                                             apr_text_header *phdr)
{
    apr_hash_index_t *idx = apr_hash_first(p, dav_liveprop_uris);

    for ( ; idx != NULL; idx = apr_hash_next(idx) ) {
        const void *key;
        void *val;
        const char *s;

        apr_hash_this(idx, &key, NULL, &val);

        s = apr_psprintf(p, " xmlns:lp%ld=\"%s\"", (long)val, (const char *)key);
        apr_text_append(p, phdr, s);
    }
}

DAV_DECLARE(int) dav_do_find_liveprop(const char *ns_uri, const char *name,
                                      const dav_liveprop_group *group,
                                      const dav_hooks_liveprop **hooks)
{
    const char * const *uris = group->namespace_uris;
    const dav_liveprop_spec *scan;
    int ns;

    /* first: locate the namespace in the namespace table */
    for (ns = 0; uris[ns] != NULL; ++ns)
        if (strcmp(ns_uri, uris[ns]) == 0)
            break;
    if (uris[ns] == NULL) {
        /* not our property (the namespace matched none of ours) */
        return 0;
    }

    /* second: look for the property in the liveprop specs */
    for (scan = group->specs; scan->name != NULL; ++scan)
        if (ns == scan->ns && strcmp(name, scan->name) == 0) {
            *hooks = group->hooks;
            return scan->propid;
        }

    /* not our property (same namespace, but no matching prop name) */
    return 0;
}

DAV_DECLARE(long) dav_get_liveprop_info(int propid,
                                       const dav_liveprop_group *group,
                                       const dav_liveprop_spec **info)
{
    const dav_liveprop_spec *scan;

    for (scan = group->specs; scan->name != NULL; ++scan) {
        if (scan->propid == propid) {
            *info = scan;

            /* map the provider-local NS into a global NS index */
            return dav_get_liveprop_ns_index(group->namespace_uris[scan->ns]);
        }
    }

    /* assert: should not reach this point */
    *info = NULL;
    return 0;
}

DAV_DECLARE(void) dav_register_liveprop_group(apr_pool_t *p,
                                              const dav_liveprop_group *group)
{
    /* register the namespace URIs */
    const char * const * uris = group->namespace_uris;

    for ( ; *uris != NULL; ++uris) {
        dav_register_liveprop_namespace(p, *uris);
    }
}
