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
 */

#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_errno.h"
#include "apr_strings.h"
#include "util_xml.h"   /* for apr_text_header */
#include "mod_dav.h"


static apr_hash_t *dav_liveprop_uris = NULL;
static int dav_liveprop_count = 0;


static apr_status_t dav_cleanup_liveprops(void *ctx)
{
    dav_liveprop_uris = NULL;
    dav_liveprop_count = 0;
    return APR_SUCCESS;
}

static void dav_register_liveprop_namespace(apr_pool_t *p, const char *uri)
{
    int value;

    if (dav_liveprop_uris == NULL) {
        dav_liveprop_uris = apr_hash_make(p);
        apr_pool_cleanup_register(p, NULL, dav_cleanup_liveprops, apr_pool_cleanup_null);
    }

    value = (int)apr_hash_get(dav_liveprop_uris, uri, APR_HASH_KEY_STRING);
    if (value != 0) {
        /* already registered */
        return;
    }

    /* start at 1, and count up */
    apr_hash_set(dav_liveprop_uris, uri, APR_HASH_KEY_STRING,
                 (void *)++dav_liveprop_count);
}

DAV_DECLARE(int) dav_get_liveprop_ns_index(const char *uri)
{
    return (int)apr_hash_get(dav_liveprop_uris, uri, APR_HASH_KEY_STRING);
}

int dav_get_liveprop_ns_count(void)
{
    return dav_liveprop_count;
}

void dav_add_all_liveprop_xmlns(apr_pool_t *p, apr_text_header *phdr)
{
    apr_hash_index_t *idx = apr_hash_first(p, dav_liveprop_uris);

    for ( ; idx != NULL; idx = apr_hash_next(idx) ) {
        const void *key;
        void *val;
        const char *s;

        apr_hash_this(idx, &key, NULL, &val);

        s = apr_psprintf(p, " xmlns:lp%d=\"%s\"", (int)val, (const char *)key);
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

DAV_DECLARE(int) dav_get_liveprop_info(int propid,
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
