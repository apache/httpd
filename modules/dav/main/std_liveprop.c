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

#include "httpd.h"
#include "util_xml.h"
#include "apr_strings.h"

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
    const char *value;
    const char *s;
    apr_pool_t *p = resource->pool;
    const dav_liveprop_spec *info;
    int global_ns;

    switch (propid)
    {
    case DAV_PROPID_resourcetype:
        switch (resource->type) {
        case DAV_RESOURCE_TYPE_VERSION:
            if (resource->baselined) {
                value = "<D:baseline/>";
                break;
            }
            /* fall through */
        case DAV_RESOURCE_TYPE_REGULAR:
        case DAV_RESOURCE_TYPE_WORKING:
            if (resource->collection) {
                value = "<D:collection/>";
            }
            else {
                /* ### should we denote lock-null resources? */

                value = "";        /* becomes: <D:resourcetype/> */
            }
            break;
        case DAV_RESOURCE_TYPE_HISTORY:
            value = "<D:version-history/>";
            break;
        case DAV_RESOURCE_TYPE_WORKSPACE:
            value = "<D:collection/>";
            break;
        case DAV_RESOURCE_TYPE_ACTIVITY:
            value = "<D:activity/>";
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
        s = apr_psprintf(p,
                         "<D:supported-live-property D:name=\"%s\" "
                         "D:namespace=\"%s\"/>" DEBUG_CR,
                         info->name, dav_core_namespace_uris[info->ns]);
    }
    else if (what == DAV_PROP_INSERT_VALUE && *value != '\0') {
        s = apr_psprintf(p, "<lp%d:%s>%s</lp%d:%s>" DEBUG_CR,
                         global_ns, info->name, value, global_ns, info->name);
    }
    else {
        s = apr_psprintf(p, "<lp%d:%s/>" DEBUG_CR, global_ns, info->name);
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

int dav_core_find_liveprop(const dav_resource *resource,
                           const char *ns_uri, const char *name,
                           const dav_hooks_liveprop **hooks)
{
    return dav_do_find_liveprop(ns_uri, name, &dav_core_liveprop_group, hooks);
}

void dav_core_insert_all_liveprops(request_rec *r,
                                   const dav_resource *resource,
                                   dav_prop_insert what, apr_text_header *phdr)
{
    (void) dav_core_insert_prop(resource, DAV_PROPID_resourcetype,
                                what, phdr);
}

void dav_core_register_uris(apr_pool_t *p)
{
    /* register the namespace URIs */
    dav_register_liveprop_group(p, &dav_core_liveprop_group);
}
