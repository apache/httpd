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

#include "httpd.h"
#include "util_xml.h"
#include "apr_strings.h"
#include "ap_provider.h"

#include "mod_dav.h"

/* forward-declare */
static const dav_hooks_liveprop dav_core_hooks_liveprop;

/*
** The namespace URIs that we use. There will only ever be "DAV:".
*/
static const char * const dav_core_namespace_uris[] =
{
    "DAV:",
    NULL        /* sentinel */
};

/*
** Define each of the core properties that this provider will handle.
** Note that all of them are in the DAV: namespace, which has a
** provider-local index of 0.
*/
static const dav_liveprop_spec dav_core_props[] =
{
    { 0, "comment",              DAV_PROPID_comment,              1 },
    { 0, "creator-displayname",  DAV_PROPID_creator_displayname,  1 },
    { 0, "displayname",          DAV_PROPID_displayname,          1 },
    { 0, "resourcetype",         DAV_PROPID_resourcetype,         0 },
    { 0, "source",               DAV_PROPID_source,               1 },

    { 0 }        /* sentinel */
};

static const dav_liveprop_group dav_core_liveprop_group =
{
    dav_core_props,
    dav_core_namespace_uris,
    &dav_core_hooks_liveprop
};

static dav_prop_insert dav_core_insert_prop(const dav_resource *resource,
                                            int propid, dav_prop_insert what,
                                            apr_text_header *phdr)
{
    const char *value = NULL;
    const char *s;
    apr_pool_t *p = resource->pool;
    const dav_liveprop_spec *info;
    long global_ns;

    switch (propid)
    {
    case DAV_PROPID_resourcetype:
        { /* additional type info provided by external modules ? */
            int i;

            apr_array_header_t *extensions =
                ap_list_provider_names(p, DAV_RESOURCE_TYPE_GROUP, "0");
            ap_list_provider_names_t *entry =
                (ap_list_provider_names_t *)extensions->elts;

            for (i = 0; i < extensions->nelts; i++, entry++) {
                const dav_resource_type_provider *res_hooks =
                    dav_get_resource_type_providers(entry->provider_name);
                const char *name = NULL, *uri = NULL;

                if (!res_hooks || !res_hooks->get_resource_type)
                    continue;

                if (!res_hooks->get_resource_type(resource, &name, &uri) &&
                    name) {

                    if (!uri || !strcasecmp(uri, "DAV:"))
                        value = apr_pstrcat(p, value ? value : "",
                                            "<D:", name, "/>", NULL);
                    else
                        value = apr_pstrcat(p, value ? value : "",
                                            "<x:", name,
                                            " xmlns:x=\"", uri,
                                            "\"/>", NULL);
                }
            }
        }
        switch (resource->type) {
        case DAV_RESOURCE_TYPE_VERSION:
            if (resource->baselined) {
                value = apr_pstrcat(p, value ? value : "", "<D:baseline/>", NULL);
                break;
            }
            /* fall through */
        case DAV_RESOURCE_TYPE_REGULAR:
        case DAV_RESOURCE_TYPE_WORKING:
            if (resource->collection) {
                value = apr_pstrcat(p, value ? value : "", "<D:collection/>", NULL);
            }
            else {
                /* ### should we denote lock-null resources? */
                if (value == NULL) {
                    value = "";        /* becomes: <D:resourcetype/> */
                }
            }
            break;
        case DAV_RESOURCE_TYPE_HISTORY:
            value = apr_pstrcat(p, value ? value : "", "<D:version-history/>", NULL);
            break;
        case DAV_RESOURCE_TYPE_WORKSPACE:
            value = apr_pstrcat(p, value ? value : "", "<D:collection/>", NULL);
            break;
        case DAV_RESOURCE_TYPE_ACTIVITY:
            value = apr_pstrcat(p, value ? value : "", "<D:activity/>", NULL);
            break;

        default:
            /* ### bad juju */
            return DAV_PROP_INSERT_NOTDEF;
        }
        break;

    case DAV_PROPID_comment:
    case DAV_PROPID_creator_displayname:
    case DAV_PROPID_displayname:
    case DAV_PROPID_source:
    default:
        /*
        ** This property is known, but not defined as a liveprop. However,
        ** it may be a dead property.
        */
        return DAV_PROP_INSERT_NOTDEF;
    }

    /* assert: value != NULL */

    /* get the information and global NS index for the property */
    global_ns = dav_get_liveprop_info(propid, &dav_core_liveprop_group, &info);

    /* assert: info != NULL && info->name != NULL */

    if (what == DAV_PROP_INSERT_SUPPORTED) {
        s = apr_pstrcat(p,
                         "<D:supported-live-property D:name=\"", info->name,
                         "\" D:namespace=\"", dav_core_namespace_uris[info->ns],
                         "\"/>" DEBUG_CR, NULL);
    }
    else if (what == DAV_PROP_INSERT_VALUE && *value != '\0') {
        s = apr_psprintf(p, "<lp%ld:%s>%s</lp%ld:%s>" DEBUG_CR,
                         global_ns, info->name, value, global_ns, info->name);
    }
    else {
        s = apr_psprintf(p, "<lp%ld:%s/>" DEBUG_CR, global_ns, info->name);
    }
    apr_text_append(p, phdr, s);

    /* we inserted what was asked for */
    return what;
}

static int dav_core_is_writable(const dav_resource *resource, int propid)
{
    const dav_liveprop_spec *info;

    (void) dav_get_liveprop_info(propid, &dav_core_liveprop_group, &info);
    return info->is_writable;
}

static dav_error * dav_core_patch_validate(const dav_resource *resource,
                                           const apr_xml_elem *elem,
                                           int operation, void **context,
                                           int *defer_to_dead)
{
    /* all of our writable props go in the dead prop database */
    *defer_to_dead = 1;

    return NULL;
}

static const dav_hooks_liveprop dav_core_hooks_liveprop = {
    dav_core_insert_prop,
    dav_core_is_writable,
    dav_core_namespace_uris,
    dav_core_patch_validate,
    NULL,       /* patch_exec */
    NULL,       /* patch_commit */
    NULL,       /* patch_rollback */
};

DAV_DECLARE_NONSTD(int) dav_core_find_liveprop(
    const dav_resource *resource,
    const char *ns_uri, const char *name,
    const dav_hooks_liveprop **hooks)
{
    return dav_do_find_liveprop(ns_uri, name, &dav_core_liveprop_group, hooks);
}

DAV_DECLARE_NONSTD(void) dav_core_insert_all_liveprops(
    request_rec *r,
    const dav_resource *resource,
    dav_prop_insert what,
    apr_text_header *phdr)
{
    (void) dav_core_insert_prop(resource, DAV_PROPID_resourcetype,
                                what, phdr);
}

DAV_DECLARE_NONSTD(void) dav_core_register_uris(apr_pool_t *p)
{
    /* register the namespace URIs */
    dav_register_liveprop_group(p, &dav_core_liveprop_group);
}
