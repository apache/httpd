/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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
** DAV extension module for Apache 2.0.*
**  - Property database handling (repository-independent)
**
** NOTES:
**
**   PROPERTY DATABASE
**
**   This version assumes that there is a per-resource database provider
**   to record properties. The database provider decides how and where to
**   store these databases.
**
**   The DBM keys for the properties have the following form:
**
**     namespace ":" propname
**
**   For example: 5:author
**
**   The namespace provides an integer index into the namespace table
**   (see below). propname is simply the property name, without a namespace
**   prefix.
**
**   A special case exists for properties that had a prefix starting with
**   "xml". The XML Specification reserves these for future use. mod_dav
**   stores and retrieves them unchanged. The keys for these properties
**   have the form:
**
**     ":" propname
**
**   The propname will contain the prefix and the property name. For
**   example, a key might be ":xmlfoo:name"
**
**   The ":name" style will also be used for properties that do not
**   exist within a namespace.
**
**   The DBM values consist of two null-terminated strings, appended
**   together (the null-terms are retained and stored in the database).
**   The first string is the xml:lang value for the property. An empty
**   string signifies that a lang value was not in context for the value.
**   The second string is the property value itself.
**
**
**   NAMESPACE TABLE
**
**   The namespace table is an array that lists each of the namespaces
**   that are in use by the properties in the given propdb. Each entry
**   in the array is a simple URI.
**
**   For example: http://www.foo.bar/standards/props/
**
**   The prefix used for the property is stripped and the URI for it
**   is entered into the namespace table. Also, any namespaces used
**   within the property value will be entered into the table (and
**   stripped from the child elements).
**
**   The namespaces are stored in the DBM database under the "METADATA" key.
**
**
**   STRIPPING NAMESPACES
**
**   Within the property values, the namespace declarations (xmlns...)
**   are stripped. Each element and attribute will have its prefix removed
**   and a new prefix inserted.
**
**   This must be done so that we can return multiple properties in a
**   PROPFIND which may have (originally) used conflicting prefixes. For
**   that case, we must bind all property value elements to new namespace
**   values.
**
**   This implies that clients must NOT be sensitive to the namespace
**   prefix used for their properties. It WILL change when the properties
**   are returned (we return them as "ns<index>", e.g. "ns5"). Also, the
**   property value can contain ONLY XML elements and CDATA. PI and comment
**   elements will be stripped. CDATA whitespace will be preserved, but
**   whitespace within element tags will be altered. Attribute ordering
**   may be altered. Element and CDATA ordering will be preserved.
**
**
**   ATTRIBUTES ON PROPERTY NAME ELEMENTS
**
**   When getting/setting properties, the XML used looks like:
**
**     <prop>
**       <propname1>value</propname1>
**       <propname2>value</propname1>
**     </prop>
**
**   This implementation (mod_dav) DOES NOT save any attributes that are
**   associated with the <propname1> element. The property value is deemed
**   to be only the contents ("value" in the above example).
**
**   We do store the xml:lang value (if any) that applies to the context
**   of the <propname1> element. Whether the xml:lang attribute is on
**   <propname1> itself, or from a higher level element, we will store it
**   with the property value.
**
**
**   VERSIONING
**
**   The DBM db contains a key named "METADATA" that holds database-level
**   information, such as the namespace table. The record also contains the
**   db's version number as the very first 16-bit value. This first number
**   is actually stored as two single bytes: the first byte is a "major"
**   version number. The second byte is a "minor" number.
**
**   If the major number is not what mod_dav expects, then the db is closed
**   immediately and an error is returned. A minor number change is
**   acceptable -- it is presumed that old/new dav_props.c can deal with
**   the database format. For example, a newer dav_props might update the
**   minor value and append information to the end of the metadata record
**   (which would be ignored by previous versions).
**
**
** ISSUES:
**
**   At the moment, for the dav_get_allprops() and dav_get_props() functions,
**   we must return a set of xmlns: declarations for ALL known namespaces
**   in the file. There isn't a way to filter this because we don't know
**   which are going to be used or not. Examining property names is not
**   sufficient because the property values could use entirely different
**   namespaces.
**
**   ==> we must devise a scheme where we can "garbage collect" the namespace
**       entries from the property database.
*/

#include "apr.h"
#include "apr_strings.h"

#define APR_WANT_STDIO
#define APR_WANT_BYTEFUNC
#include "apr_want.h"

#include "mod_dav.h"

#include "http_log.h"
#include "http_request.h"

/*
** There is some rough support for writable DAV:getcontenttype and
** DAV:getcontentlanguage properties. If this #define is (1), then
** this support is disabled.
**
** We are disabling it because of a lack of support in GET and PUT
** operations. For GET, it would be "expensive" to look for a propdb,
** open it, and attempt to extract the Content-Type and Content-Language
** values for the response.
** (Handling the PUT would not be difficult, though)
*/
#define DAV_DISABLE_WRITABLE_PROPS     1

#define DAV_EMPTY_VALUE                "\0"    /* TWO null terms */

struct dav_propdb {
    apr_pool_t *p;                /* the pool we should use */
    request_rec *r;               /* the request record */

    const dav_resource *resource; /* the target resource */

    int deferred;                 /* open of db has been deferred */
    dav_db *db;                   /* underlying database containing props */

    apr_array_header_t *ns_xlate; /* translation of an elem->ns to URI */
    dav_namespace_map *mapping;   /* namespace mapping */

    dav_lockdb *lockdb;           /* the lock database */

    dav_buffer wb_lock;           /* work buffer for lockdiscovery property */

    /* if we ever run a GET subreq, it will be stored here */
    request_rec *subreq;

    /* hooks we should use for processing (based on the target resource) */
    const dav_hooks_db *db_hooks;
};

/* NOTE: dav_core_props[] and the following enum must stay in sync. */
/* ### move these into a "core" liveprop provider? */
static const char * const dav_core_props[] =
{
    "getcontenttype",
    "getcontentlanguage",
    "lockdiscovery",
    "supportedlock",

    NULL        /* sentinel */
};
enum {
    DAV_PROPID_CORE_getcontenttype = DAV_PROPID_CORE,
    DAV_PROPID_CORE_getcontentlanguage,
    DAV_PROPID_CORE_lockdiscovery,
    DAV_PROPID_CORE_supportedlock,

    DAV_PROPID_CORE_UNKNOWN
};

/*
** This structure is used to track information needed for a rollback.
*/
typedef struct dav_rollback_item {
    /* select one of the two rollback context structures based on the
       value of dav_prop_ctx.is_liveprop */
    dav_deadprop_rollback *deadprop;
    dav_liveprop_rollback *liveprop;

} dav_rollback_item;


static int dav_find_liveprop_provider(dav_propdb *propdb,
                                      const char *ns_uri,
                                      const char *propname,
                                      const dav_hooks_liveprop **provider)
{
    int propid;

    *provider = NULL;

    if (ns_uri == NULL) {
        /* policy: liveprop providers cannot define no-namespace properties */
        return DAV_PROPID_CORE_UNKNOWN;
    }

    /* check liveprop providers first, so they can define core properties */
    propid = dav_run_find_liveprop(propdb->resource, ns_uri, propname,
                                   provider);
    if (propid != 0) {
        return propid;
    }

    /* check for core property */
    if (strcmp(ns_uri, "DAV:") == 0) {
        const char * const *p = dav_core_props;

        for (propid = DAV_PROPID_CORE; *p != NULL; ++p, ++propid)
            if (strcmp(propname, *p) == 0) {
                return propid;
            }
    }

    /* no provider for this property */
    return DAV_PROPID_CORE_UNKNOWN;
}

static void dav_find_liveprop(dav_propdb *propdb, apr_xml_elem *elem)
{
    const char *ns_uri;
    dav_elem_private *priv = elem->priv;
    const dav_hooks_liveprop *hooks;


    if (elem->ns == APR_XML_NS_NONE)
        ns_uri = NULL;
    else if (elem->ns == APR_XML_NS_DAV_ID)
        ns_uri = "DAV:";
    else
        ns_uri = APR_XML_GET_URI_ITEM(propdb->ns_xlate, elem->ns);

    priv->propid = dav_find_liveprop_provider(propdb, ns_uri, elem->name,
                                              &hooks);

    /* ### this test seems redundant... */
    if (priv->propid != DAV_PROPID_CORE_UNKNOWN) {
        priv->provider = hooks;
    }
}

/* is the live property read/write? */
static int dav_rw_liveprop(dav_propdb *propdb, dav_elem_private *priv)
{
    int propid = priv->propid;

    /*
    ** Check the liveprop provider (if this is a provider-defined prop)
    */
    if (priv->provider != NULL) {
        return (*priv->provider->is_writable)(propdb->resource, propid);
    }

    /* these are defined as read-only */
    if (propid == DAV_PROPID_CORE_lockdiscovery
#if DAV_DISABLE_WRITABLE_PROPS
        || propid == DAV_PROPID_CORE_getcontenttype
        || propid == DAV_PROPID_CORE_getcontentlanguage
#endif
        || propid == DAV_PROPID_CORE_supportedlock
        ) {

        return 0;
    }

    /* these are defined as read/write */
    if (propid == DAV_PROPID_CORE_getcontenttype
        || propid == DAV_PROPID_CORE_getcontentlanguage
        || propid == DAV_PROPID_CORE_UNKNOWN) {

        return 1;
    }

    /*
    ** We don't recognize the property, so it must be dead (and writable)
    */
    return 1;
}

/* do a sub-request to fetch properties for the target resource's URI. */
static void dav_do_prop_subreq(dav_propdb *propdb)
{
    /* perform a "GET" on the resource's URI (note that the resource
       may not correspond to the current request!). */
    propdb->subreq = ap_sub_req_lookup_uri(propdb->resource->uri, propdb->r,
                                           NULL);
}

static dav_error * dav_insert_coreprop(dav_propdb *propdb,
                                       int propid, const char *name,
                                       dav_prop_insert what,
                                       apr_text_header *phdr,
                                       dav_prop_insert *inserted)
{
    const char *value = NULL;
    dav_error *err;

    *inserted = DAV_PROP_INSERT_NOTDEF;

    /* fast-path the common case */
    if (propid == DAV_PROPID_CORE_UNKNOWN)
        return NULL;

    switch (propid) {

    case DAV_PROPID_CORE_lockdiscovery:
        if (propdb->lockdb != NULL) {
            dav_lock *locks;

            if ((err = dav_lock_query(propdb->lockdb, propdb->resource,
                                      &locks)) != NULL) {
                return dav_push_error(propdb->p, err->status, 0,
                                      "DAV:lockdiscovery could not be "
                                      "determined due to a problem fetching "
                                      "the locks for this resource.",
                                      err);
            }

            /* fast-path the no-locks case */
            if (locks == NULL) {
                value = "";
            }
            else {
                /*
                ** This may modify the buffer. value may point to
                ** wb_lock.pbuf or a string constant.
                */
                value = dav_lock_get_activelock(propdb->r, locks,
                                                &propdb->wb_lock);

                /* make a copy to isolate it from changes to wb_lock */
                value = apr_pstrdup(propdb->p, propdb->wb_lock.buf);
            }
        }
        break;

    case DAV_PROPID_CORE_supportedlock:
        if (propdb->lockdb != NULL) {
            value = (*propdb->lockdb->hooks->get_supportedlock)(propdb->resource);
        }
        break;

    case DAV_PROPID_CORE_getcontenttype:
        if (propdb->subreq == NULL) {
            dav_do_prop_subreq(propdb);
        }
        if (propdb->subreq->content_type != NULL) {
            value = propdb->subreq->content_type;
        }
        break;

    case DAV_PROPID_CORE_getcontentlanguage:
    {
        const char *lang;

        if (propdb->subreq == NULL) {
            dav_do_prop_subreq(propdb);
        }
        if ((lang = apr_table_get(propdb->subreq->headers_out,
                                 "Content-Language")) != NULL) {
            value = lang;
        }
        break;
    }

    default:
        /* fall through to interpret as a dead property */
        break;
    }

    /* if something was supplied, then insert it */
    if (value != NULL) {
        const char *s;

        if (what == DAV_PROP_INSERT_SUPPORTED) {
            /* use D: prefix to refer to the DAV: namespace URI,
             * and let the namespace attribute default to "DAV:"
             */
            s = apr_psprintf(propdb->p,
                            "<D:supported-live-property D:name=\"%s\"/>" DEBUG_CR,
                            name);
        }
        else if (what == DAV_PROP_INSERT_VALUE && *value != '\0') {
            /* use D: prefix to refer to the DAV: namespace URI */
            s = apr_psprintf(propdb->p, "<D:%s>%s</D:%s>" DEBUG_CR,
                            name, value, name);
        }
        else {
            /* use D: prefix to refer to the DAV: namespace URI */
            s = apr_psprintf(propdb->p, "<D:%s/>" DEBUG_CR, name);
        }
        apr_text_append(propdb->p, phdr, s);

        *inserted = what;
    }

    return NULL;
}

static dav_error * dav_insert_liveprop(dav_propdb *propdb,
                                       const apr_xml_elem *elem,
                                       dav_prop_insert what,
                                       apr_text_header *phdr,
                                       dav_prop_insert *inserted)
{
    dav_elem_private *priv = elem->priv;

    *inserted = DAV_PROP_INSERT_NOTDEF;

    if (priv->provider == NULL) {
        /* this is a "core" property that we define */
        return dav_insert_coreprop(propdb, priv->propid, elem->name,
                                   what, phdr, inserted);
    }

    /* ask the provider (that defined this prop) to insert the prop */
    *inserted = (*priv->provider->insert_prop)(propdb->resource, priv->propid,
                                               what, phdr);

    return NULL;
}

static void dav_output_prop_name(apr_pool_t *pool,
                                 const dav_prop_name *name,
                                 dav_xmlns_info *xi,
                                 apr_text_header *phdr)
{
    const char *s;

    if (*name->ns == '\0')
        s = apr_psprintf(pool, "<%s/>" DEBUG_CR, name->name);
    else {
        const char *prefix = dav_xmlns_add_uri(xi, name->ns);

        s = apr_psprintf(pool, "<%s:%s/>" DEBUG_CR, prefix, name->name);
    }

    apr_text_append(pool, phdr, s);
}

static void dav_insert_xmlns(apr_pool_t *p, const char *pre_prefix, int ns,
                             const char *ns_uri, apr_text_header *phdr)
{
    const char *s;

    s = apr_psprintf(p, " xmlns:%s%d=\"%s\"", pre_prefix, ns, ns_uri);
    apr_text_append(p, phdr, s);
}

static dav_error *dav_really_open_db(dav_propdb *propdb, int ro)
{
    dav_error *err;

    /* we're trying to open the db; turn off the 'deferred' flag */
    propdb->deferred = 0;

    /* ask the DB provider to open the thing */
    err = (*propdb->db_hooks->open)(propdb->p, propdb->resource, ro,
                                    &propdb->db);
    if (err != NULL) {
        return dav_push_error(propdb->p, HTTP_INTERNAL_SERVER_ERROR,
                              DAV_ERR_PROP_OPENING,
                              "Could not open the property database.",
                              err);
    }

    /*
    ** NOTE: propdb->db could be NULL if we attempted to open a readonly
    **       database that doesn't exist. If we require read/write
    **       access, then a database was created and opened.
    */

    return NULL;
}

dav_error *dav_open_propdb(request_rec *r, dav_lockdb *lockdb,
                           const dav_resource *resource,
                           int ro,
                           apr_array_header_t * ns_xlate,
                           dav_propdb **p_propdb)
{
    dav_propdb *propdb = apr_pcalloc(r->pool, sizeof(*propdb));

    *p_propdb = NULL;

#if DAV_DEBUG
    if (resource->uri == NULL) {
        return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                             "INTERNAL DESIGN ERROR: resource must define "
                             "its URI.");
    }
#endif

    propdb->r = r;
    apr_pool_create(&propdb->p, r->pool);
    propdb->resource = resource;
    propdb->ns_xlate = ns_xlate;

    propdb->db_hooks = DAV_GET_HOOKS_PROPDB(r);

    propdb->lockdb = lockdb;

    /* always defer actual open, to avoid expense of accessing db
     * when only live properties are involved
     */
    propdb->deferred = 1;

    /* ### what to do about closing the propdb on server failure? */

    *p_propdb = propdb;
    return NULL;
}

void dav_close_propdb(dav_propdb *propdb)
{
    if (propdb->db != NULL) {
        (*propdb->db_hooks->close)(propdb->db);
    }

    /* Currently, mod_dav's pool usage doesn't clearing this pool. */
#if 0
    apr_pool_destroy(propdb->p);
#endif
    return;
}

dav_get_props_result dav_get_allprops(dav_propdb *propdb, dav_prop_insert what)
{
    const dav_hooks_db *db_hooks = propdb->db_hooks;
    apr_text_header hdr = { 0 };
    apr_text_header hdr_ns = { 0 };
    dav_get_props_result result = { 0 };
    int found_contenttype = 0;
    int found_contentlang = 0;
    dav_prop_insert unused_inserted;

    /* if not just getting supported live properties,
     * scan all properties in the dead prop database
     */
    if (what != DAV_PROP_INSERT_SUPPORTED) {
        if (propdb->deferred) {
            /* ### what to do with db open error? */
            (void) dav_really_open_db(propdb, 1 /*ro*/);
        }

        /* initialize the result with some start tags... */
        apr_text_append(propdb->p, &hdr,
                        "<D:propstat>" DEBUG_CR
                        "<D:prop>" DEBUG_CR);

        /* if there ARE properties, then scan them */
        if (propdb->db != NULL) {
            dav_xmlns_info *xi = dav_xmlns_create(propdb->p);
            dav_prop_name name;

            /* define (up front) any namespaces the db might need */
            (void) (*db_hooks->define_namespaces)(propdb->db, xi);

            /* get the first property name, beginning the scan */
            (void) (*db_hooks->first_name)(propdb->db, &name);
            while (name.ns != NULL) {

                /*
                ** We also look for <DAV:getcontenttype> and
                ** <DAV:getcontentlanguage>. If they are not stored as dead
                ** properties, then we need to perform a subrequest to get
                ** their values (if any).
                */
                if (*name.ns == 'D' && strcmp(name.ns, "DAV:") == 0
                    && *name.name == 'g') {
                    if (strcmp(name.name, "getcontenttype") == 0) {
                        found_contenttype = 1;
                    }
                    else if (strcmp(name.name, "getcontentlanguage") == 0) {
                        found_contentlang = 1;
                    }
                }

                if (what == DAV_PROP_INSERT_VALUE) {
                    dav_error *err;
                    int found;

                    if ((err = (*db_hooks->output_value)(propdb->db, &name,
                                                         xi, &hdr,
                                                         &found)) != NULL) {
                        /* ### anything better to do? */
                        /* ### probably should enter a 500 error */
                        goto next_key;
                    }
                    /* assert: found == 1 */
                }
                else {
                    /* the value was not requested, so just add an empty
                       tag specifying the property name. */
                    dav_output_prop_name(propdb->p, &name, xi, &hdr);
                }

              next_key:
                (void) (*db_hooks->next_name)(propdb->db, &name);
            }

            /* all namespaces have been entered into xi. generate them into
               the output now. */
            dav_xmlns_generate(xi, &hdr_ns);

        } /* propdb->db != NULL */

        /* add namespaces for all the liveprop providers */
        dav_add_all_liveprop_xmlns(propdb->p, &hdr_ns);
    }

    /* ask the liveprop providers to insert their properties */
    dav_run_insert_all_liveprops(propdb->r, propdb->resource, what, &hdr);

    /* insert the standard properties */
    /* ### should be handling the return errors here */
    (void)dav_insert_coreprop(propdb,
                              DAV_PROPID_CORE_supportedlock, "supportedlock",
                              what, &hdr, &unused_inserted);
    (void)dav_insert_coreprop(propdb,
                              DAV_PROPID_CORE_lockdiscovery, "lockdiscovery",
                              what, &hdr, &unused_inserted);

    /* if we didn't find these, then do the whole subreq thing. */
    if (!found_contenttype) {
        /* ### should be handling the return error here */
        (void)dav_insert_coreprop(propdb,
                                  DAV_PROPID_CORE_getcontenttype,
                                  "getcontenttype",
                                  what, &hdr, &unused_inserted);
    }
    if (!found_contentlang) {
        /* ### should be handling the return error here */
        (void)dav_insert_coreprop(propdb,
                                  DAV_PROPID_CORE_getcontentlanguage,
                                  "getcontentlanguage",
                                  what, &hdr, &unused_inserted);
    }

    /* if not just reporting on supported live props,
     * terminate the result */
    if (what != DAV_PROP_INSERT_SUPPORTED) {
        apr_text_append(propdb->p, &hdr,
                        "</D:prop>" DEBUG_CR
                        "<D:status>HTTP/1.1 200 OK</D:status>" DEBUG_CR
                        "</D:propstat>" DEBUG_CR);
    }

    result.propstats = hdr.first;
    result.xmlns = hdr_ns.first;
    return result;
}

dav_get_props_result dav_get_props(dav_propdb *propdb, apr_xml_doc *doc)
{
    const dav_hooks_db *db_hooks = propdb->db_hooks;
    apr_xml_elem *elem = dav_find_child(doc->root, "prop");
    apr_text_header hdr_good = { 0 };
    apr_text_header hdr_bad = { 0 };
    apr_text_header hdr_ns = { 0 };
    int have_good = 0;
    dav_get_props_result result = { 0 };
    char *marks_liveprop;
    dav_xmlns_info *xi;
    int xi_filled = 0;

    /* ### NOTE: we should pass in TWO buffers -- one for keys, one for
       the marks */

    /* we will ALWAYS provide a "good" result, even if it is EMPTY */
    apr_text_append(propdb->p, &hdr_good,
                   "<D:propstat>" DEBUG_CR
                   "<D:prop>" DEBUG_CR);

    /* ### the marks should be in a buffer! */
    /* allocate zeroed-memory for the marks. These marks indicate which
       liveprop namespaces we've generated into the output xmlns buffer */

    /* same for the liveprops */
    marks_liveprop = apr_pcalloc(propdb->p, dav_get_liveprop_ns_count() + 1);

    xi = dav_xmlns_create(propdb->p);

    for (elem = elem->first_child; elem; elem = elem->next) {
        dav_elem_private *priv;
        dav_error *err;
        dav_prop_insert inserted;
        dav_prop_name name;

        /*
        ** First try live property providers; if they don't handle
        ** the property, then try looking it up in the propdb.
        */

        if (elem->priv == NULL) {
            elem->priv = apr_pcalloc(propdb->p, sizeof(*priv));
        }
        priv = elem->priv;

        /* cache the propid; dav_get_props() could be called many times */
        if (priv->propid == 0)
            dav_find_liveprop(propdb, elem);

        if (priv->propid != DAV_PROPID_CORE_UNKNOWN) {

            /* insert the property. returns 1 if an insertion was done. */
            if ((err = dav_insert_liveprop(propdb, elem, DAV_PROP_INSERT_VALUE,
                                           &hdr_good, &inserted)) != NULL) {
                /* ### need to propagate the error to the caller... */
                /* ### skip it for now, as if nothing was inserted */
            }
            if (inserted == DAV_PROP_INSERT_VALUE) {
                have_good = 1;

                /*
                ** Add the liveprop's namespace URIs. Note that provider==NULL
                ** for core properties.
                */
                if (priv->provider != NULL) {
                    const char * const * scan_ns_uri;

                    for (scan_ns_uri = priv->provider->namespace_uris;
                         *scan_ns_uri != NULL;
                         ++scan_ns_uri) {
                        int ns;

                        ns = dav_get_liveprop_ns_index(*scan_ns_uri);
                        if (marks_liveprop[ns])
                            continue;
                        marks_liveprop[ns] = 1;

                        dav_insert_xmlns(propdb->p, "lp", ns, *scan_ns_uri,
                                         &hdr_ns);
                    }
                }

                /* property added. move on to the next property. */
                continue;
            }
            else if (inserted == DAV_PROP_INSERT_NOTDEF) {
                /* nothing to do. fall thru to allow property to be handled
                   as a dead property */
            }
#if DAV_DEBUG
            else {
#if 0
                /* ### need to change signature to return an error */
                return dav_new_error(propdb->p, HTTP_INTERNAL_SERVER_ERROR, 0,
                                     "INTERNAL DESIGN ERROR: insert_liveprop "
                                     "did not insert what was asked for.");
#endif
            }
#endif
        }

        /* The property wasn't a live property, so look in the dead property
           database. */

        /* make sure propdb is really open */
        if (propdb->deferred) {
            /* ### what to do with db open error? */
            (void) dav_really_open_db(propdb, 1 /*ro*/);
        }

        if (elem->ns == APR_XML_NS_NONE)
            name.ns = "";
        else
            name.ns = APR_XML_GET_URI_ITEM(propdb->ns_xlate, elem->ns);
        name.name = elem->name;

        /* only bother to look if a database exists */
        if (propdb->db != NULL) {
            int found;

            if ((err = (*db_hooks->output_value)(propdb->db, &name,
                                                 xi, &hdr_good,
                                                 &found)) != NULL) {
                /* ### what to do? continue doesn't seem right... */
                continue;
            }

            if (found) {
                have_good = 1;

                /* if we haven't added the db's namespaces, then do so... */
                if (!xi_filled) {
                    (void) (*db_hooks->define_namespaces)(propdb->db, xi);
                    xi_filled = 1;
                }
                continue;
            }
        }

        /* not found as a live OR dead property. add a record to the "bad"
           propstats */

        /* make sure we've started our "bad" propstat */
        if (hdr_bad.first == NULL) {
            apr_text_append(propdb->p, &hdr_bad,
                            "<D:propstat>" DEBUG_CR
                            "<D:prop>" DEBUG_CR);
        }

        /* output this property's name (into the bad propstats) */
        dav_output_prop_name(propdb->p, &name, xi, &hdr_bad);
    }

    apr_text_append(propdb->p, &hdr_good,
                    "</D:prop>" DEBUG_CR
                    "<D:status>HTTP/1.1 200 OK</D:status>" DEBUG_CR
                    "</D:propstat>" DEBUG_CR);

    /* default to start with the good */
    result.propstats = hdr_good.first;

    /* we may not have any "bad" results */
    if (hdr_bad.first != NULL) {
        /* "close" the bad propstat */
        apr_text_append(propdb->p, &hdr_bad,
                        "</D:prop>" DEBUG_CR
                        "<D:status>HTTP/1.1 404 Not Found</D:status>" DEBUG_CR
                        "</D:propstat>" DEBUG_CR);

        /* if there are no good props, then just return the bad */
        if (!have_good) {
            result.propstats = hdr_bad.first;
        }
        else {
            /* hook the bad propstat to the end of the good one */
            hdr_good.last->next = hdr_bad.first;
        }
    }

    /* add in all the various namespaces, and return them */
    dav_xmlns_generate(xi, &hdr_ns);
    result.xmlns = hdr_ns.first;

    return result;
}

void dav_get_liveprop_supported(dav_propdb *propdb,
                                const char *ns_uri,
                                const char *propname,
                                apr_text_header *body)
{
    int propid;
    const dav_hooks_liveprop *hooks;

    propid = dav_find_liveprop_provider(propdb, ns_uri, propname, &hooks);

    if (propid != DAV_PROPID_CORE_UNKNOWN) {
        if (hooks == NULL) {
            /* this is a "core" property that we define */
            dav_prop_insert unused_inserted;
            dav_insert_coreprop(propdb, propid, propname,
                                DAV_PROP_INSERT_SUPPORTED, body, &unused_inserted);
        }
        else {
            (*hooks->insert_prop)(propdb->resource, propid,
                                  DAV_PROP_INSERT_SUPPORTED, body);
        }
    }
}

void dav_prop_validate(dav_prop_ctx *ctx)
{
    dav_propdb *propdb = ctx->propdb;
    apr_xml_elem *prop = ctx->prop;
    dav_elem_private *priv;

    priv = ctx->prop->priv = apr_pcalloc(propdb->p, sizeof(*priv));

    /*
    ** Check to see if this is a live property, and fill the fields
    ** in the XML elem, as appropriate.
    **
    ** Verify that the property is read/write. If not, then it cannot
    ** be SET or DELETEd.
    */
    if (priv->propid == 0) {
        dav_find_liveprop(propdb, prop);

        /* it's a liveprop if a provider was found */
        /* ### actually the "core" props should really be liveprops, but
           ### there is no "provider" for those and the r/w props are
           ### treated as dead props anyhow */
        ctx->is_liveprop = priv->provider != NULL;
    }

    if (!dav_rw_liveprop(propdb, priv)) {
        ctx->err = dav_new_error(propdb->p, HTTP_CONFLICT,
                                 DAV_ERR_PROP_READONLY,
                                 "Property is read-only.");
        return;
    }

    if (ctx->is_liveprop) {
        int defer_to_dead = 0;

        ctx->err = (*priv->provider->patch_validate)(propdb->resource,
                                                     prop, ctx->operation,
                                                     &ctx->liveprop_ctx,
                                                     &defer_to_dead);
        if (ctx->err != NULL || !defer_to_dead)
            return;

        /* clear is_liveprop -- act as a dead prop now */
        ctx->is_liveprop = 0;
    }

    /*
    ** The property is supposed to be stored into the dead-property
    ** database. Make sure the thing is truly open (and writable).
    */
    if (propdb->deferred
        && (ctx->err = dav_really_open_db(propdb, 0 /* ro */)) != NULL) {
        return;
    }

    /*
    ** There should be an open, writable database in here!
    **
    ** Note: the database would be NULL if it was opened readonly and it
    **       did not exist.
    */
    if (propdb->db == NULL) {
        ctx->err = dav_new_error(propdb->p, HTTP_INTERNAL_SERVER_ERROR,
                                 DAV_ERR_PROP_NO_DATABASE,
                                 "Attempted to set/remove a property "
                                 "without a valid, open, read/write "
                                 "property database.");
        return;
    }

    if (ctx->operation == DAV_PROP_OP_SET) {
        /*
        ** Prep the element => propdb namespace index mapping, inserting
        ** namespace URIs into the propdb that don't exist.
        */
        (void) (*propdb->db_hooks->map_namespaces)(propdb->db,
                                                   propdb->ns_xlate,
                                                   &propdb->mapping);
    }
    else if (ctx->operation == DAV_PROP_OP_DELETE) {
        /*
        ** There are no checks to perform here. If a property exists, then
        ** we will delete it. If it does not exist, then it does not matter
        ** (see S12.13.1).
        **
        ** Note that if a property does not exist, that does not rule out
        ** that a SET will occur during this PROPPATCH (thusly creating it).
        */
    }
}

void dav_prop_exec(dav_prop_ctx *ctx)
{
    dav_propdb *propdb = ctx->propdb;
    dav_error *err = NULL;
    dav_elem_private *priv = ctx->prop->priv;

    ctx->rollback = apr_pcalloc(propdb->p, sizeof(*ctx->rollback));

    if (ctx->is_liveprop) {
        err = (*priv->provider->patch_exec)(propdb->resource,
                                            ctx->prop, ctx->operation,
                                            ctx->liveprop_ctx,
                                            &ctx->rollback->liveprop);
    }
    else {
        dav_prop_name name;

        if (ctx->prop->ns == APR_XML_NS_NONE)
            name.ns = "";
        else
            name.ns = APR_XML_GET_URI_ITEM(propdb->ns_xlate, ctx->prop->ns);
        name.name = ctx->prop->name;

        /* save the old value so that we can do a rollback. */
        if ((err = (*propdb->db_hooks
                    ->get_rollback)(propdb->db, &name,
                                    &ctx->rollback->deadprop)) != NULL)
            goto error;

        if (ctx->operation == DAV_PROP_OP_SET) {

            /* Note: propdb->mapping was set in dav_prop_validate() */
            err = (*propdb->db_hooks->store)(propdb->db, &name, ctx->prop,
                                             propdb->mapping);

            /*
            ** If an error occurred, then assume that we didn't change the
            ** value. Remove the rollback item so that we don't try to set
            ** its value during the rollback.
            */
            /* ### euh... where is the removal? */
        }
        else if (ctx->operation == DAV_PROP_OP_DELETE) {

            /*
            ** Delete the property. Ignore errors -- the property is there, or
            ** we are deleting it for a second time.
            */
            /* ### but what about other errors? */
            (void) (*propdb->db_hooks->remove)(propdb->db, &name);
        }
    }

  error:
    /* push a more specific error here */
    if (err != NULL) {
        /*
        ** Use HTTP_INTERNAL_SERVER_ERROR because we shouldn't have seen
        ** any errors at this point.
        */
        ctx->err = dav_push_error(propdb->p, HTTP_INTERNAL_SERVER_ERROR,
                                  DAV_ERR_PROP_EXEC,
                                  "Could not execute PROPPATCH.", err);
    }
}

void dav_prop_commit(dav_prop_ctx *ctx)
{
    dav_elem_private *priv = ctx->prop->priv;

    /*
    ** Note that a commit implies ctx->err is NULL. The caller should assume
    ** a status of HTTP_OK for this case.
    */

    if (ctx->is_liveprop) {
        (*priv->provider->patch_commit)(ctx->propdb->resource,
                                        ctx->operation,
                                        ctx->liveprop_ctx,
                                        ctx->rollback->liveprop);
    }
}

void dav_prop_rollback(dav_prop_ctx *ctx)
{
    dav_error *err = NULL;
    dav_elem_private *priv = ctx->prop->priv;

    /* do nothing if there is no rollback information. */
    if (ctx->rollback == NULL)
        return;

    /*
    ** ### if we have an error, and a rollback occurs, then the namespace
    ** ### mods should not happen at all. Basically, the namespace management
    ** ### is simply a bitch.
    */

    if (ctx->is_liveprop) {
        err = (*priv->provider->patch_rollback)(ctx->propdb->resource,
                                                ctx->operation,
                                                ctx->liveprop_ctx,
                                                ctx->rollback->liveprop);
    }
    else {
        err = (*ctx->propdb->db_hooks
               ->apply_rollback)(ctx->propdb->db, ctx->rollback->deadprop);
    }

    if (err != NULL) {
        if (ctx->err == NULL)
            ctx->err = err;
        else {
            dav_error *scan = err;

            /* hook previous errors at the end of the rollback error */
            while (scan->prev != NULL)
                scan = scan->prev;
            scan->prev = ctx->err;
            ctx->err = err;
        }
    }
}
