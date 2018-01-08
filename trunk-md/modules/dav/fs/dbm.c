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
** DAV extension module for Apache 2.0.*
**  - Database support using DBM-style databases,
**    part of the filesystem repository implementation
*/

/*
** This implementation uses a SDBM database per file and directory to
** record the properties. These databases are kept in a subdirectory (of
** the directory in question or the directory that holds the file in
** question) named by the macro DAV_FS_STATE_DIR (.DAV). The filename of the
** database is equivalent to the target filename, and is
** DAV_FS_STATE_FILE_FOR_DIR (.state_for_dir) for the directory itself.
*/

#include "apr_strings.h"
#include "apr_file_io.h"

#include "apr_dbm.h"

#define APR_WANT_BYTEFUNC
#include "apr_want.h"       /* for ntohs and htons */

#include "mod_dav.h"
#include "repos.h"
#include "http_log.h"
#include "http_main.h"      /* for ap_server_conf */

APLOG_USE_MODULE(dav_fs);

struct dav_db {
    apr_pool_t *pool;
    apr_dbm_t *file;

    /* when used as a property database: */

    int version;                /* *minor* version of this db */

    dav_buffer ns_table;        /* table of namespace URIs */
    short ns_count;             /* number of entries in table */
    int ns_table_dirty;         /* ns_table was modified */
    apr_hash_t *uri_index;      /* map URIs to (1-based) table indices */

    dav_buffer wb_key;          /* work buffer for dav_gdbm_key */

    apr_datum_t iter;           /* iteration key */
};

/* -------------------------------------------------------------------------
 *
 * GENERIC DBM ACCESS
 *
 * For the most part, this just uses the APR DBM functions. They are wrapped
 * a bit with some error handling (using the mod_dav error functions).
 */

void dav_dbm_get_statefiles(apr_pool_t *p, const char *fname,
                            const char **state1, const char **state2)
{
    if (fname == NULL)
        fname = DAV_FS_STATE_FILE_FOR_DIR;

    apr_dbm_get_usednames(p, fname, state1, state2);
}

static dav_error * dav_fs_dbm_error(dav_db *db, apr_pool_t *p,
                                    apr_status_t status)
{
    int errcode;
    const char *errstr;
    dav_error *err;
    char errbuf[200];

    if (status == APR_SUCCESS)
        return NULL;

    p = db ? db->pool : p;

    /* There might not be a <db> if we had problems creating it. */
    if (db == NULL) {
        errcode = 1;
        errstr = "Could not open property database.";
        if (APR_STATUS_IS_EDSOOPEN(status))
            ap_log_error(APLOG_MARK, APLOG_CRIT, status, ap_server_conf, APLOGNO(00576)
            "The DBM driver could not be loaded");
    }
    else {
        (void) apr_dbm_geterror(db->file, &errcode, errbuf, sizeof(errbuf));
        errstr = apr_pstrdup(p, errbuf);
    }

    err = dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, errcode, status, errstr);
    return err;
}

/* ensure that our state subdirectory is present */
/* ### does this belong here or in dav_fs_repos.c ?? */
void dav_fs_ensure_state_dir(apr_pool_t * p, const char *dirname)
{
    const char *pathname = apr_pstrcat(p, dirname, "/" DAV_FS_STATE_DIR, NULL);

    /* ### do we need to deal with the umask? */

    /* just try to make it, ignoring any resulting errors */
    (void) apr_dir_make(pathname, APR_OS_DEFAULT, p);
}

/* dav_dbm_open_direct:  Opens a *dbm database specified by path.
 *    ro = boolean read-only flag.
 */
dav_error * dav_dbm_open_direct(apr_pool_t *p, const char *pathname, int ro,
                                dav_db **pdb)
{
    apr_status_t status;
    apr_dbm_t *file = NULL;

    *pdb = NULL;

    if ((status = apr_dbm_open(&file, pathname,
                               ro ? APR_DBM_READONLY : APR_DBM_RWCREATE,
                               APR_OS_DEFAULT, p))
                != APR_SUCCESS
        && !ro) {
        /* ### do something with 'status' */

        /* we can't continue if we couldn't open the file
           and we need to write */
        return dav_fs_dbm_error(NULL, p, status);
    }

    /* may be NULL if we tried to open a non-existent db as read-only */
    if (file != NULL) {
        /* we have an open database... return it */
        *pdb = apr_pcalloc(p, sizeof(**pdb));
        (*pdb)->pool = p;
        (*pdb)->file = file;
    }

    return NULL;
}

static dav_error * dav_dbm_open(apr_pool_t * p, const dav_resource *resource,
                                int ro, dav_db **pdb)
{
    const char *dirpath;
    const char *fname;
    const char *pathname;

    /* Get directory and filename for resource */
    /* ### should test this result value... */
    (void) dav_fs_dir_file_name(resource, &dirpath, &fname);

    /* If not opening read-only, ensure the state dir exists */
    if (!ro) {
        /* ### what are the perf implications of always checking this? */
        dav_fs_ensure_state_dir(p, dirpath);
    }

    pathname = apr_pstrcat(p, dirpath, "/" DAV_FS_STATE_DIR "/",
                              fname ? fname : DAV_FS_STATE_FILE_FOR_DIR,
                              NULL);

    /* ### readers cannot open while a writer has this open; we should
       ### perform a few retries with random pauses. */

    /* ### do we need to deal with the umask? */

    return dav_dbm_open_direct(p, pathname, ro, pdb);
}

void dav_dbm_close(dav_db *db)
{
    apr_dbm_close(db->file);
}

dav_error * dav_dbm_fetch(dav_db *db, apr_datum_t key, apr_datum_t *pvalue)
{
    apr_status_t status;

    if (!key.dptr) {
        /* no key could be created (namespace not known) => no value */
        memset(pvalue, 0, sizeof(*pvalue));
        status = APR_SUCCESS;
    } else {
        status = apr_dbm_fetch(db->file, key, pvalue);
    }

    return dav_fs_dbm_error(db, NULL, status);
}

dav_error * dav_dbm_store(dav_db *db, apr_datum_t key, apr_datum_t value)
{
    apr_status_t status = apr_dbm_store(db->file, key, value);

    return dav_fs_dbm_error(db, NULL, status);
}

dav_error * dav_dbm_delete(dav_db *db, apr_datum_t key)
{
    apr_status_t status = apr_dbm_delete(db->file, key);

    return dav_fs_dbm_error(db, NULL, status);
}

int dav_dbm_exists(dav_db *db, apr_datum_t key)
{
    return apr_dbm_exists(db->file, key);
}

static dav_error * dav_dbm_firstkey(dav_db *db, apr_datum_t *pkey)
{
    apr_status_t status = apr_dbm_firstkey(db->file, pkey);

    return dav_fs_dbm_error(db, NULL, status);
}

static dav_error * dav_dbm_nextkey(dav_db *db, apr_datum_t *pkey)
{
    apr_status_t status = apr_dbm_nextkey(db->file, pkey);

    return dav_fs_dbm_error(db, NULL, status);
}

void dav_dbm_freedatum(dav_db *db, apr_datum_t data)
{
    apr_dbm_freedatum(db->file, data);
}

/* -------------------------------------------------------------------------
 *
 * PROPERTY DATABASE FUNCTIONS
 */


#define DAV_GDBM_NS_KEY         "METADATA"
#define DAV_GDBM_NS_KEY_LEN     8

typedef struct {
    unsigned char major;
#define DAV_DBVSN_MAJOR         4
    /*
    ** V4 -- 0.9.9 ..
    **       Prior versions could have keys or values with invalid
    **       namespace prefixes as a result of the xmlns="" form not
    **       resetting the default namespace to be "no namespace". The
    **       namespace would be set to "" which is invalid; it should
    **       be set to "no namespace".
    **
    ** V3 -- 0.9.8
    **       Prior versions could have values with invalid namespace
    **       prefixes due to an incorrect mapping of input to propdb
    **       namespace indices. Version bumped to obsolete the old
    **       values.
    **
    ** V2 -- 0.9.7
    **       This introduced the xml:lang value into the property value's
    **       record in the propdb.
    **
    ** V1 -- .. 0.9.6
    **       Initial version.
    */


    unsigned char minor;
#define DAV_DBVSN_MINOR         0

    short ns_count;

} dav_propdb_metadata;

struct dav_deadprop_rollback {
    apr_datum_t key;
    apr_datum_t value;
};

struct dav_namespace_map {
    int *ns_map;
};

/*
** Internal function to build a key
**
** WARNING: returns a pointer to a "static" buffer holding the key. The
**          value must be copied or no longer used if this function is
**          called again.
*/
static apr_datum_t dav_build_key(dav_db *db, const dav_prop_name *name)
{
    char nsbuf[20];
    apr_size_t l_ns, l_name = strlen(name->name);
    apr_datum_t key = { 0 };

    /*
     * Convert namespace ID to a string. "no namespace" is an empty string,
     * so the keys will have the form ":name". Otherwise, the keys will
     * have the form "#:name".
     */
    if (*name->ns == '\0') {
        nsbuf[0] = '\0';
        l_ns = 0;
    }
    else {
        long ns_id = (long)apr_hash_get(db->uri_index, name->ns,
                                      APR_HASH_KEY_STRING);


        if (ns_id == 0) {
            /* the namespace was not found(!) */
            return key;         /* zeroed */
        }

        l_ns = apr_snprintf(nsbuf, sizeof(nsbuf), "%ld", ns_id - 1);
    }

    /* assemble: #:name */
    dav_set_bufsize(db->pool, &db->wb_key, l_ns + 1 + l_name + 1);
    memcpy(db->wb_key.buf, nsbuf, l_ns);
    db->wb_key.buf[l_ns] = ':';
    memcpy(&db->wb_key.buf[l_ns + 1], name->name, l_name + 1);

    /* build the database key */
    key.dsize = l_ns + 1 + l_name + 1;
    key.dptr = db->wb_key.buf;

    return key;
}

static void dav_append_prop(apr_pool_t *pool,
                            const char *name, const char *value,
                            apr_text_header *phdr)
{
    const char *s;
    const char *lang = value;

    /* skip past the xml:lang value */
    value += strlen(lang) + 1;

    if (*value == '\0') {
        /* the property is an empty value */
        if (*name == ':') {
            /* "no namespace" case */
            s = apr_psprintf(pool, "<%s/>" DEBUG_CR, name+1);
        }
        else {
            s = apr_psprintf(pool, "<ns%s/>" DEBUG_CR, name);
        }
    }
    else if (*lang != '\0') {
        if (*name == ':') {
            /* "no namespace" case */
            s = apr_psprintf(pool, "<%s xml:lang=\"%s\">%s</%s>" DEBUG_CR,
                             name+1, lang, value, name+1);
        }
        else {
            s = apr_psprintf(pool, "<ns%s xml:lang=\"%s\">%s</ns%s>" DEBUG_CR,
                             name, lang, value, name);
        }
    }
    else if (*name == ':') {
        /* "no namespace" case */
        s = apr_psprintf(pool, "<%s>%s</%s>" DEBUG_CR, name+1, value, name+1);
    }
    else {
        s = apr_psprintf(pool, "<ns%s>%s</ns%s>" DEBUG_CR, name, value, name);
    }

    apr_text_append(pool, phdr, s);
}

static dav_error * dav_propdb_open(apr_pool_t *pool,
                                   const dav_resource *resource, int ro,
                                   dav_db **pdb)
{
    dav_db *db;
    dav_error *err;
    apr_datum_t key;
    apr_datum_t value = { 0 };

    *pdb = NULL;

    /*
    ** Return if an error occurred, or there is no database.
    **
    ** NOTE: db could be NULL if we attempted to open a readonly
    **       database that doesn't exist. If we require read/write
    **       access, then a database was created and opened.
    */
    if ((err = dav_dbm_open(pool, resource, ro, &db)) != NULL
        || db == NULL)
        return err;

    db->uri_index = apr_hash_make(pool);

    key.dptr = DAV_GDBM_NS_KEY;
    key.dsize = DAV_GDBM_NS_KEY_LEN;
    if ((err = dav_dbm_fetch(db, key, &value)) != NULL) {
        /* ### push a higher-level description? */
        return err;
    }

    if (value.dptr == NULL) {
        dav_propdb_metadata m = {
            DAV_DBVSN_MAJOR, DAV_DBVSN_MINOR, 0
        };

        /*
        ** If there is no METADATA key, then the database may be
        ** from versions 0.9.0 .. 0.9.4 (which would be incompatible).
        ** These can be identified by the presence of an NS_TABLE entry.
        */
        key.dptr = "NS_TABLE";
        key.dsize = 8;
        if (dav_dbm_exists(db, key)) {
            dav_dbm_close(db);

            /* call it a major version error */
            return dav_new_error(pool, HTTP_INTERNAL_SERVER_ERROR,
                                 DAV_ERR_PROP_BAD_MAJOR, 0,
                                 "Prop database has the wrong major "
                                 "version number and cannot be used.");
        }

        /* initialize a new metadata structure */
        dav_set_bufsize(pool, &db->ns_table, sizeof(m));
        memcpy(db->ns_table.buf, &m, sizeof(m));
    }
    else {
        dav_propdb_metadata m;
        long ns;
        const char *uri;

        dav_set_bufsize(pool, &db->ns_table, value.dsize);
        memcpy(db->ns_table.buf, value.dptr, value.dsize);

        memcpy(&m, value.dptr, sizeof(m));
        if (m.major != DAV_DBVSN_MAJOR) {
            dav_dbm_close(db);

            return dav_new_error(pool, HTTP_INTERNAL_SERVER_ERROR,
                                 DAV_ERR_PROP_BAD_MAJOR, 0,
                                 "Prop database has the wrong major "
                                 "version number and cannot be used.");
        }
        db->version = m.minor;
        db->ns_count = ntohs(m.ns_count);

        dav_dbm_freedatum(db, value);

        /* create db->uri_index */
        for (ns = 0, uri = db->ns_table.buf + sizeof(dav_propdb_metadata);
             ns++ < db->ns_count;
             uri += strlen(uri) + 1) {

            /* we must copy the key, in case ns_table.buf moves */
            apr_hash_set(db->uri_index,
                         apr_pstrdup(pool, uri), APR_HASH_KEY_STRING,
                         (void *)ns);
        }
    }

    *pdb = db;
    return NULL;
}

static void dav_propdb_close(dav_db *db)
{

    if (db->ns_table_dirty) {
        dav_propdb_metadata m;
        apr_datum_t key;
        apr_datum_t value;
        dav_error *err;

        key.dptr = DAV_GDBM_NS_KEY;
        key.dsize = DAV_GDBM_NS_KEY_LEN;

        value.dptr = db->ns_table.buf;
        value.dsize = db->ns_table.cur_len;

        /* fill in the metadata that we store into the prop db. */
        m.major = DAV_DBVSN_MAJOR;
        m.minor = db->version;          /* ### keep current minor version? */
        m.ns_count = htons(db->ns_count);

        memcpy(db->ns_table.buf, &m, sizeof(m));

        err = dav_dbm_store(db, key, value);
        if (err != NULL)
            ap_log_error(APLOG_MARK, APLOG_WARNING, err->aprerr, ap_server_conf,
                         APLOGNO(00577) "Error writing propdb: %s", err->desc);
    }

    dav_dbm_close(db);
}

static dav_error * dav_propdb_define_namespaces(dav_db *db, dav_xmlns_info *xi)
{
    int ns;
    const char *uri = db->ns_table.buf + sizeof(dav_propdb_metadata);

    /* within the prop values, we use "ns%d" for prefixes... register them */
    for (ns = 0; ns < db->ns_count; ++ns, uri += strlen(uri) + 1) {

        /* Empty URIs signify the empty namespace. These do not get a
           namespace prefix. when we generate the value, we will simply
           leave off the prefix, which is defined by mod_dav to be the
           empty namespace. */
        if (*uri == '\0')
            continue;

        /* ns_table.buf can move, so copy its value (we want the values to
           last as long as the provided dav_xmlns_info). */
        dav_xmlns_add(xi,
                      apr_psprintf(xi->pool, "ns%d", ns),
                      apr_pstrdup(xi->pool, uri));
    }

    return NULL;
}

static dav_error * dav_propdb_output_value(dav_db *db,
                                           const dav_prop_name *name,
                                           dav_xmlns_info *xi,
                                           apr_text_header *phdr,
                                           int *found)
{
    apr_datum_t key = dav_build_key(db, name);
    apr_datum_t value;
    dav_error *err;

    if ((err = dav_dbm_fetch(db, key, &value)) != NULL)
        return err;
    if (value.dptr == NULL) {
        *found = 0;
        return NULL;
    }
    *found = 1;

    dav_append_prop(db->pool, key.dptr, value.dptr, phdr);

    dav_dbm_freedatum(db, value);

    return NULL;
}

static dav_error * dav_propdb_map_namespaces(
    dav_db *db,
    const apr_array_header_t *namespaces,
    dav_namespace_map **mapping)
{
    dav_namespace_map *m = apr_palloc(db->pool, sizeof(*m));
    int i;
    int *pmap;
    const char **puri;

    /*
    ** Iterate over the provided namespaces. If a namespace already appears
    ** in our internal map of URI -> ns_id, then store that in the map. If
    ** we don't know the namespace yet, then add it to the map and to our
    ** table of known namespaces.
    */
    m->ns_map = pmap = apr_palloc(db->pool, namespaces->nelts * sizeof(*pmap));
    for (i = namespaces->nelts, puri = (const char **)namespaces->elts;
         i-- > 0;
         ++puri, ++pmap) {

        const char *uri = *puri;
        apr_size_t uri_len = strlen(uri);
        long ns_id = (long)apr_hash_get(db->uri_index, uri, uri_len);

        if (ns_id == 0) {
            dav_check_bufsize(db->pool, &db->ns_table, uri_len + 1);
            memcpy(db->ns_table.buf + db->ns_table.cur_len, uri, uri_len + 1);
            db->ns_table.cur_len += uri_len + 1;

            /* copy the uri in case the passed-in namespaces changes in
               some way. */
            apr_hash_set(db->uri_index, apr_pstrdup(db->pool, uri), uri_len,
                         (void *)((long)(db->ns_count + 1)));

            db->ns_table_dirty = 1;

            *pmap = db->ns_count++;
        }
        else {
            *pmap = ns_id - 1;
        }
    }

    *mapping = m;
    return NULL;
}

static dav_error * dav_propdb_store(dav_db *db, const dav_prop_name *name,
                                    const apr_xml_elem *elem,
                                    dav_namespace_map *mapping)
{
    apr_datum_t key = dav_build_key(db, name);
    apr_datum_t value;

    /* Note: mapping->ns_map was set up in dav_propdb_map_namespaces() */

    /* ### use a db- subpool for these values? clear on exit? */

    /* quote all the values in the element */
    /* ### be nice to do this without affecting the element itself */
    /* ### of course, the cast indicates Badness is occurring here */
    apr_xml_quote_elem(db->pool, (apr_xml_elem *)elem);

    /* generate a text blob for the xml:lang plus the contents */
    apr_xml_to_text(db->pool, elem, APR_XML_X2T_LANG_INNER, NULL,
                    mapping->ns_map,
                    (const char **)&value.dptr, &value.dsize);

    return dav_dbm_store(db, key, value);
}

static dav_error * dav_propdb_remove(dav_db *db, const dav_prop_name *name)
{
    apr_datum_t key = dav_build_key(db, name);
    return dav_dbm_delete(db, key);
}

static int dav_propdb_exists(dav_db *db, const dav_prop_name *name)
{
    apr_datum_t key = dav_build_key(db, name);
    return dav_dbm_exists(db, key);
}

static const char *dav_get_ns_table_uri(dav_db *db, int ns_id)
{
    const char *p = db->ns_table.buf + sizeof(dav_propdb_metadata);

    while (ns_id--)
        p += strlen(p) + 1;

    return p;
}

static void dav_set_name(dav_db *db, dav_prop_name *pname)
{
    const char *s = db->iter.dptr;

    if (s == NULL) {
        pname->ns = pname->name = NULL;
    }
    else if (*s == ':') {
        pname->ns = "";
        pname->name = s + 1;
    }
    else {
        int id = atoi(s);

        pname->ns = dav_get_ns_table_uri(db, id);
        if (s[1] == ':') {
            pname->name = s + 2;
        }
        else {
            pname->name = ap_strchr_c(s + 2, ':') + 1;
        }
    }
}

static dav_error * dav_propdb_next_name(dav_db *db, dav_prop_name *pname)
{
    dav_error *err;

    /* free the previous key. note: if the loop is aborted, then the DBM
       will toss the key (via pool cleanup) */
    if (db->iter.dptr != NULL)
        dav_dbm_freedatum(db, db->iter);

    if ((err = dav_dbm_nextkey(db, &db->iter)) != NULL)
        return err;

    /* skip past the METADATA key */
    if (db->iter.dptr != NULL && *db->iter.dptr == 'M')
        return dav_propdb_next_name(db, pname);

    dav_set_name(db, pname);
    return NULL;
}

static dav_error * dav_propdb_first_name(dav_db *db, dav_prop_name *pname)
{
    dav_error *err;

    if ((err = dav_dbm_firstkey(db, &db->iter)) != NULL)
        return err;

    /* skip past the METADATA key */
    if (db->iter.dptr != NULL && *db->iter.dptr == 'M')
        return dav_propdb_next_name(db, pname);

    dav_set_name(db, pname);
    return NULL;
}

static dav_error * dav_propdb_get_rollback(dav_db *db,
                                           const dav_prop_name *name,
                                           dav_deadprop_rollback **prollback)
{
    dav_deadprop_rollback *rb = apr_pcalloc(db->pool, sizeof(*rb));
    apr_datum_t key;
    apr_datum_t value;
    dav_error *err;

    key = dav_build_key(db, name);
    rb->key.dptr = apr_pstrdup(db->pool, key.dptr);
    rb->key.dsize = key.dsize;

    if ((err = dav_dbm_fetch(db, key, &value)) != NULL)
        return err;
    if (value.dptr != NULL) {
        rb->value.dptr = apr_pmemdup(db->pool, value.dptr, value.dsize);
        rb->value.dsize = value.dsize;
    }

    *prollback = rb;
    return NULL;
}

static dav_error * dav_propdb_apply_rollback(dav_db *db,
                                             dav_deadprop_rollback *rollback)
{
    if (!rollback) {
        return NULL; /* no rollback, nothing to do */
    }

    if (rollback->value.dptr == NULL) {
        /* don't fail if the thing isn't really there. */
        (void) dav_dbm_delete(db, rollback->key);
        return NULL;
    }

    return dav_dbm_store(db, rollback->key, rollback->value);
}

const dav_hooks_db dav_hooks_db_dbm =
{
    dav_propdb_open,
    dav_propdb_close,
    dav_propdb_define_namespaces,
    dav_propdb_output_value,
    dav_propdb_map_namespaces,
    dav_propdb_store,
    dav_propdb_remove,
    dav_propdb_exists,
    dav_propdb_first_name,
    dav_propdb_next_name,
    dav_propdb_get_rollback,
    dav_propdb_apply_rollback,

    NULL /* ctx */
};
