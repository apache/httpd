/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
*/

#ifndef _MOD_DAV_H_
#define _MOD_DAV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "httpd.h"
#include "util_xml.h"
#include "ap_hooks.h"
#include "apr_hash.h"

#include <limits.h>     /* for INT_MAX */


#define DAV_VERSION		AP_SERVER_BASEREVISION

#define DAV_XML_HEADER		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
#define DAV_XML_CONTENT_TYPE	"text/xml; charset=\"utf-8\""

#define DAV_READ_BLOCKSIZE	2048	/* used for reading input blocks */

#define DAV_RESPONSE_BODY_1	"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<HTML><HEAD>\n<TITLE>"
#define DAV_RESPONSE_BODY_2	"</TITLE>\n</HEAD><BODY>\n<H1>"
#define DAV_RESPONSE_BODY_3	"</H1>\n"
#define DAV_RESPONSE_BODY_4	"</BODY></HTML>\n"

#define DAV_DO_COPY		0
#define DAV_DO_MOVE		1


#if 1
#define DAV_DEBUG 1
#define DEBUG_CR	"\n"
#define DBG0(f)		ap_log_error(APLOG_MARK, \
				APLOG_ERR|APLOG_NOERRNO, 0, NULL, (f))
#define DBG1(f,a1)	ap_log_error(APLOG_MARK, \
				APLOG_ERR|APLOG_NOERRNO, 0, NULL, f, a1)
#define DBG2(f,a1,a2)	ap_log_error(APLOG_MARK, \
				APLOG_ERR|APLOG_NOERRNO, 0, NULL, f, a1, a2)
#define DBG3(f,a1,a2,a3) ap_log_error(APLOG_MARK, \
			       APLOG_ERR|APLOG_NOERRNO, 0, NULL, f, a1, a2, a3)
#else
#undef DAV_DEBUG
#define DEBUG_CR	""
#endif

#define DAV_INFINITY	INT_MAX	/* for the Depth: header */


/* --------------------------------------------------------------------
**
** ERROR MANAGEMENT
*/

/*
** dav_error structure.
**
** In most cases, mod_dav uses a pointer to a dav_error structure. If the
** pointer is NULL, then no error has occurred.
**
** In certain cases, a dav_error structure is directly used. In these cases,
** a status value of 0 means that an error has not occurred.
**
** Note: this implies that status != 0 whenever an error occurs.
**
** The desc field is optional (it may be NULL). When NULL, it typically
** implies that Apache has a proper description for the specified status.
*/
typedef struct dav_error {
    int status;			/* suggested HTTP status (0 for no error) */
    int error_id;		/* DAV-specific error ID */
    const char *desc;		/* DAV:responsedescription and error log */

    int save_errno;		/* copy of errno causing the error */

    struct dav_error *prev;	/* previous error (in stack) */

    /* deferred computation of the description */
    void (*compute_desc)(struct dav_error *err, apr_pool_t *p);
    int ctx_i;
    const char *ctx_s;
    void *ctx_p;

} dav_error;

/*
** Create a new error structure. save_errno will be filled with the current
** errno value.
*/
dav_error *dav_new_error(apr_pool_t *p, int status, int error_id, const char *desc);

/*
** Push a new error description onto the stack of errors.
**
** This function is used to provide an additional description to an existing
** error.
**
** <status> should contain the caller's view of what the current status is,
** given the underlying error. If it doesn't have a better idea, then the
** caller should pass prev->status.
**
** <error_id> can specify a new error_id since the topmost description has
** changed.
*/
dav_error *dav_push_error(apr_pool_t *p, int status, int error_id, const char *desc,
			  dav_error *prev);


/* error ID values... */

/* IF: header errors */
#define DAV_ERR_IF_PARSE		100	/* general parsing error */
#define DAV_ERR_IF_MULTIPLE_NOT		101	/* multiple "Not" found */
#define DAV_ERR_IF_UNK_CHAR		102	/* unknown char in header */
#define DAV_ERR_IF_ABSENT		103	/* no locktokens given */
#define DAV_ERR_IF_TAGGED		104	/* in parsing tagged-list */
#define DAV_ERR_IF_UNCLOSED_PAREN	105	/* in no-tagged-list */

/* Prop DB errors */
#define DAV_ERR_PROP_BAD_MAJOR		200	/* major version was wrong */
#define DAV_ERR_PROP_READONLY		201	/* prop is read-only */
#define DAV_ERR_PROP_NO_DATABASE	202	/* writeable db not avail */
#define DAV_ERR_PROP_NOT_FOUND		203	/* prop not found */
#define DAV_ERR_PROP_BAD_LOCKDB		204	/* could not open lockdb */
#define DAV_ERR_PROP_OPENING		205	/* problem opening propdb */
#define DAV_ERR_PROP_EXEC		206	/* problem exec'ing patch */

/* Predefined DB errors */
/* ### any to define?? */

/* Predefined locking system errors */
#define DAV_ERR_LOCK_OPENDB		400	/* could not open lockdb */
#define DAV_ERR_LOCK_NO_DB		401	/* no database defined */
#define DAV_ERR_LOCK_CORRUPT_DB		402	/* DB is corrupt */
#define DAV_ERR_LOCK_UNK_STATE_TOKEN	403	/* unknown State-token */
#define DAV_ERR_LOCK_PARSE_TOKEN	404	/* bad opaquelocktoken */
#define DAV_ERR_LOCK_SAVE_LOCK		405	/* err saving locks */

/*
** Some comments on Error ID values:
**
** The numbers do not necessarily need to be unique. Uniqueness simply means
** that two errors that have not been predefined above can be distinguished
** from each other. At the moment, mod_dav does not use this distinguishing
** feature, but it could be used in the future to collapse <response> elements
** into groups based on the error ID (and associated responsedescription).
**
** If a compute_desc is provided, then the error ID should be unique within
** the context of the compute_desc function (so the function can figure out
** what to filled into the desc).
**
** Basically, subsystems can ignore defining new error ID values if they want
** to. The subsystems *do* need to return the predefined errors when
** appropriate, so that mod_dav can figure out what to do. Subsystems can
** simply leave the error ID field unfilled (zero) if there isn't an error
** that must be placed there.
*/


/* --------------------------------------------------------------------
**
** HOOK STRUCTURES
**
** These are here for forward-declaration purposes. For more info, see
** the section title "HOOK HANDLING" for more information, plus each
** structure definition.
*/

/* forward-declare this structure */
typedef struct dav_hooks_propdb dav_hooks_propdb;
typedef struct dav_hooks_locks dav_hooks_locks;
typedef struct dav_hooks_vsn dav_hooks_vsn;
typedef struct dav_hooks_repository dav_hooks_repository;
typedef struct dav_hooks_liveprop dav_hooks_liveprop;

/* ### deprecated name */
typedef dav_hooks_propdb dav_hooks_db;


/* --------------------------------------------------------------------
**
** RESOURCE HANDLING
*/

/*
** Resource Types:
** The base protocol defines only file and collection resources.
** The versioning protocol defines several additional resource types
** to represent artifacts of a version control system.
*/
typedef enum {
    DAV_RESOURCE_TYPE_REGULAR,      /* file or collection, working resource
				       or revision */
    DAV_RESOURCE_TYPE_REVISION,     /* explicit revision-id */
    DAV_RESOURCE_TYPE_HISTORY,      /* explicit history-id */
    DAV_RESOURCE_TYPE_WORKSPACE,    /* workspace */
    DAV_RESOURCE_TYPE_ACTIVITY,     /* activity */
    DAV_RESOURCE_TYPE_CONFIGURATION /* configuration */
} dav_resource_type;

/*
** Opaque, repository-specific information for a resource.
*/
typedef struct dav_resource_private dav_resource_private;

/* Resource descriptor, generated by a repository provider.
 * Note: the lock-null state is not explicitly represented here,
 * since it may be expensive to compute. Use dav_get_resource_state()
 * to determine whether a non-existent resource is a lock-null resource.
 */
typedef struct dav_resource {
    dav_resource_type type;

    int exists;		/* 0 => null resource */
    int collection;	/* 0 => file (if type == DAV_RESOURCE_TYPE_REGULAR) */
    int versioned;	/* 0 => unversioned */
    int working;	/* 0 => revision (if versioned) */
    int baselined;	/* 0 => not baselined */

    const char *uri;	/* the URI for this resource */

    dav_resource_private *info;

    const dav_hooks_repository *hooks;	/* hooks used for this resource */

} dav_resource;

/*
** Lock token type. Lock providers define the details of a lock token.
** However, all providers are expected to at least be able to parse
** the "opaquelocktoken" scheme, which is represented by a uuid_t.
*/
typedef struct dav_locktoken dav_locktoken;


/* --------------------------------------------------------------------
**
** BUFFER HANDLING
**
** These buffers are used as a lightweight buffer reuse mechanism. Apache
** provides sub-pool creation and destruction to much the same effect, but
** the sub-pools are a bit more general and heavyweight than these buffers.
*/

/* buffer for reuse; can grow to accomodate needed size */
typedef struct
{
    apr_size_t alloc_len;	/* how much has been allocated */
    apr_size_t cur_len;		/* how much is currently being used */
    char *buf;			/* buffer contents */
} dav_buffer;
#define DAV_BUFFER_MINSIZE	256	/* minimum size for buffer */
#define DAV_BUFFER_PAD		64	/* amount of pad when growing */

/* set the cur_len to the given size and ensure space is available */
void dav_set_bufsize(apr_pool_t *p, dav_buffer *pbuf, apr_size_t size);

/* initialize a buffer and copy the specified (null-term'd) string into it */
void dav_buffer_init(apr_pool_t *p, dav_buffer *pbuf, const char *str);

/* check that the buffer can accomodate <extra_needed> more bytes */
void dav_check_bufsize(apr_pool_t *p, dav_buffer *pbuf, apr_size_t extra_needed);

/* append a string to the end of the buffer, adjust length */
void dav_buffer_append(apr_pool_t *p, dav_buffer *pbuf, const char *str);

/* place a string on the end of the buffer, do NOT adjust length */
void dav_buffer_place(apr_pool_t *p, dav_buffer *pbuf, const char *str);

/* place some memory on the end of a buffer; do NOT adjust length */
void dav_buffer_place_mem(apr_pool_t *p, dav_buffer *pbuf, const void *mem,
                          apr_size_t amt, apr_size_t pad);


/* --------------------------------------------------------------------
**
** HANDY UTILITIES
*/

/* contains results from one of the getprop functions */
typedef struct
{
    ap_text * propstats;	/* <propstat> element text */
    ap_text * xmlns;		/* namespace decls for <response> elem */
} dav_get_props_result;

/* holds the contents of a <response> element */
typedef struct dav_response
{
    const char *href;		/* always */
    const char *desc;		/* optional description at <response> level */

    /* use status if propresult.propstats is NULL. */
    dav_get_props_result propresult;

    int status;

    struct dav_response *next;
} dav_response;

typedef struct
{
    request_rec *rnew;		/* new subrequest */
    dav_error err;		/* potential error response */
} dav_lookup_result;


dav_lookup_result dav_lookup_uri(const char *uri, request_rec *r);

/* ### this stuff is private to dav/fs/repos.c; move it... */
/* format a time string (buf must be at least DAV_TIMEBUF_SIZE chars) */
#define DAV_STYLE_ISO8601	1
#define DAV_STYLE_RFC822	2
#define DAV_TIMEBUF_SIZE	30

int dav_get_depth(request_rec *r, int def_depth);

int dav_validate_root(const ap_xml_doc *doc, const char *tagname);
ap_xml_elem *dav_find_child(const ap_xml_elem *elem, const char *tagname);


/* --------------------------------------------------------------------
**
** DAV PLUGINS
*/

/* ### docco ... */

/* ### add a repository friendly-name to the get_resource */
AP_DECLARE_HOOK(int, get_resource, (request_rec *r, const char *root_dir,
                                    const char *workspace))

AP_DECLARE_HOOK(const dav_hooks_locks *, get_lock_hooks, (request_rec *r))
AP_DECLARE_HOOK(const dav_hooks_propdb *, get_propdb_hooks, (request_rec *r))
AP_DECLARE_HOOK(const dav_hooks_vsn *, get_vsn_hooks, (request_rec *r))

AP_DECLARE_HOOK(void, gather_propsets, (apr_array_header_t *uris))
AP_DECLARE_HOOK(int, find_liveprop, (request_rec *r,
                                     const char *ns_uri, const char *name,
                                     const dav_hooks_liveprop **hooks))
AP_DECLARE_HOOK(void, insert_all_liveprops, (request_rec *r,
                                             const dav_resource *resource,
                                             int insvalue,
                                             ap_text_header *phdr))

#define DAV_KEY_RESOURCE        "dav-resource"
#define DAV_KEY_LOCK_HOOKS      "dav-lock-hooks"
#define DAV_KEY_PROPDB_HOOKS    "dav-propdb-hooks"
#define DAV_KEY_VSN_HOOKS       "dav-vsn-hooks"

const dav_hooks_locks *dav_get_lock_hooks(request_rec *r);
const dav_hooks_propdb *dav_get_propdb_hooks(request_rec *r);
const dav_hooks_vsn *dav_get_vsn_hooks(request_rec *r);

void dav_register_liveprop_namespace(apr_pool_t *pool, const char *uri);
int dav_get_liveprop_ns_index(const char *uri);
int dav_get_liveprop_ns_count(void);
void dav_add_all_liveprop_xmlns(apr_pool_t *p, ap_text_header *phdr);


/* ### deprecated */
#define DAV_GET_HOOKS_PROPDB(r)         dav_get_propdb_hooks(r)
#define DAV_GET_HOOKS_LOCKS(r)          dav_get_lock_hooks(r)
#define DAV_GET_HOOKS_VSN(r)            dav_get_vsn_hooks(r)


/* --------------------------------------------------------------------
**
** IF HEADER PROCESSING
**
** Here is the definition of the If: header from RFC 2518, S9.4:
**
**    If = "If" ":" (1*No-tag-list | 1*Tagged-list)
**    No-tag-list = List
**    Tagged-list = Resource 1*List
**    Resource = Coded-URL
**    List = "(" 1*(["Not"](State-token | "[" entity-tag "]")) ")"
**    State-token = Coded-URL
**    Coded-URL = "<" absoluteURI ">"        ; absoluteURI from RFC 2616
**
** List corresponds to dav_if_state_list. No-tag-list corresponds to
** dav_if_header with uri==NULL. Tagged-list corresponds to a sequence of
** dav_if_header structures with (duplicate) uri==Resource -- one
** dav_if_header per state_list. A second Tagged-list will start a new
** sequence of dav_if_header structures with the new URI.
**
** A summary of the semantics, mapped into our structures:
**    - Chained dav_if_headers: OR
**    - Chained dav_if_state_lists: AND
**    - NULL uri matches all resources
*/

typedef enum
{
    dav_if_etag,
    dav_if_opaquelock
} dav_if_state_type;

typedef struct dav_if_state_list
{
    dav_if_state_type type;

    int condition;
#define DAV_IF_COND_NORMAL	0
#define DAV_IF_COND_NOT		1	/* "Not" was applied */

    const char *etag;	/* etag */
    dav_locktoken *locktoken;   /* locktoken */

    struct dav_if_state_list *next;
} dav_if_state_list;

typedef struct dav_if_header
{
    const char *uri;
    apr_size_t uri_len;
    struct dav_if_state_list *state;
    struct dav_if_header *next;

    int dummy_header;	/* used internally by the lock/etag validation */
} dav_if_header;

typedef struct dav_locktoken_list 
{
    dav_locktoken *locktoken;
    struct dav_locktoken_list *next;
} dav_locktoken_list;

dav_error * dav_get_locktoken_list(request_rec *r, dav_locktoken_list **ltl);


/* --------------------------------------------------------------------
**
** LIVE PROPERTY HANDLING
*/

typedef enum {
    DAV_PROP_INSERT_NOTME,	/* prop not defined by this provider */
    DAV_PROP_INSERT_NOTDEF,	/* property is defined by this provider,
				   but nothing was inserted because the
				   (live) property is not defined for this
				   resource (it may be present as a dead
				   property). */
    DAV_PROP_INSERT_NAME,	/* a property name (empty elem) was
				   inserted into the text block */
    DAV_PROP_INSERT_VALUE	/* a property name/value pair was inserted
				   into the text block */
} dav_prop_insert;

typedef enum {
    DAV_PROP_RW_NOTME,		/* not my property */
    DAV_PROP_RW_NO,		/* property is NOT writeable */
    DAV_PROP_RW_YES		/* property IS writeable */
} dav_prop_rw;

/* opaque type for PROPPATCH rollback information */
typedef struct dav_liveprop_rollback dav_liveprop_rollback;

struct dav_hooks_liveprop
{
    /*
    ** This URI is returned in the DAV: header to let clients know what
    ** sets of live properties are supported by the installation. mod_dav
    ** will place open/close angle brackets around this value (much like
    ** a Coded-URL); quotes and brackets should not be in the value.
    **
    ** Example:    http://apache.org/dav/props/
    **
    ** (of course, use your own domain to ensure a unique value)
    */
    const char * propset_uri;

    /*
    ** Find a property, returning a non-zero, unique, opaque identifier.
    **
    ** NOTE: Providers must ensure this identifier is universally unique.
    **       See the registration table below.
    ** ### it would be nice to avoid this uniqueness constraint. however,
    ** ### that would mean our xml_elem annotation concept would need to
    ** ### change (w.r.t. the fact that it acts as a cache for find_prop).
    **
    ** Returns 0 if the property is not defined by this provider.
    */
    int (*find_prop)(const char *ns_uri, const char *name);

    /*
    ** Insert a property name/value into a text block. The property to
    ** insert is identified by the propid value. Providers should return
    ** DAV_PROP_INSERT_NOTME if they do not define the specified propid.
    ** If insvalue is true, then the property's value should be inserted;
    ** otherwise, an empty element (ie. just the prop's name) should be
    ** inserted.
    **
    ** Returns one of DAV_PROP_INSERT_* based on what happened.
    **
    ** ### we may need more context... ie. the lock database
    */
    dav_prop_insert (*insert_prop)(const dav_resource *resource,
				   int propid, int insvalue,
				   ap_text_header *phdr);

    /*
    ** Insert all known/defined property names (and values). This is
    ** similar to insert_prop, but *all* properties will be inserted
    ** rather than specific, individual properties.
    */
    void (*insert_all)(const dav_resource *resource, int insvalue,
		       ap_text_header *phdr);

    /*
    ** Determine whether a given property is writeable.
    **
    ** ### we may want a different semantic. i.e. maybe it should be
    ** ### "can we write <value> into this property?"
    **
    ** Returns appropriate read/write status.
    */
    dav_prop_rw (*is_writeable)(const dav_resource *resource, int propid);

    /*
    ** This member defines the set of namespace URIs that the provider
    ** uses for its properties. When insert_all is called, it will be
    ** passed a list of integers that map from indices into this list
    ** to namespace IDs for output generation.
    **
    ** The last entry in this list should be a NULL value (sentinel).
    */
    const char * const * namespace_uris;

    /*
    ** ### this is not the final design. we want an open-ended way for
    ** ### liveprop providers to attach *new* properties. To this end,
    ** ### we'll have a "give me a list of the props you define", a way
    ** ### to check for a prop's existence, a way to validate a set/remove
    ** ### of a prop, and a way to execute/commit/rollback that change.
    */

    /*
    ** Validate that the live property can be assigned a value, and that
    ** the provided value is valid.
    **
    ** elem will point to the XML element that names the property. For
    ** example:
    **     <lp1:executable>T</lp1:executable>
    **
    ** The provider can access the cdata fields and the child elements
    ** to extract the relevant pieces.
    **
    ** operation is one of DAV_PROP_OP_SET or _DELETE.
    **
    ** The provider may return a value in *context which will be passed
    ** to each of the exec/commit/rollback functions. For example, this
    ** may contain an internal value which has been processed from the
    ** input element.
    **
    ** The provider must set defer_to_dead to true (non-zero) or false.
    ** If true, then the set/remove is deferred to the dead property
    ** database. Note: it will be set to zero on entry.
    */
    dav_error * (*patch_validate)(const dav_resource *resource,
				  const ap_xml_elem *elem,
				  int operation,
				  void **context,
				  int *defer_to_dead);

    /* ### doc... */
    dav_error * (*patch_exec)(dav_resource *resource,
			      const ap_xml_elem *elem,
			      int operation,
			      void *context,
			      dav_liveprop_rollback **rollback_ctx);

    /* ### doc... */
    void (*patch_commit)(dav_resource *resource,
			 int operation,
			 void *context,
			 dav_liveprop_rollback *rollback_ctx);

    /* ### doc... */
    dav_error * (*patch_rollback)(dav_resource *resource,
				  int operation,
				  void *context,
				  dav_liveprop_rollback *rollback_ctx);
};

/*
** Property Identifier Registration
**
** At the moment, mod_dav requires live property providers to ensure that
** each property returned has a unique value. For now, this is done through
** central registration (there are no known providers other than the default,
** so this remains manageable).
**
** WARNING: the TEST ranges should never be "shipped".
*/
#define DAV_PROPID_CORE		10000	/* ..10099. defined by mod_dav */
#define DAV_PROPID_FS		10100	/* ..10299.
					   mod_dav filesystem provider. */
#define DAV_PROPID_TEST1	10300	/* ..10399 */
#define DAV_PROPID_TEST2	10400	/* ..10499 */
#define DAV_PROPID_TEST3	10500	/* ..10599 */
/* Next: 10600 */


/* --------------------------------------------------------------------
**
** DATABASE FUNCTIONS
*/

typedef struct dav_db dav_db;
typedef struct
{
    char *dptr;
    apr_size_t dsize;
} dav_datum;

/* hook functions to enable pluggable databases */
struct dav_hooks_propdb
{
    dav_error * (*open)(apr_pool_t *p, const dav_resource *resource, int ro,
			dav_db **pdb);
    void (*close)(dav_db *db);

    /*
    ** Fetch the value from the database. If the value does not exist,
    ** then *pvalue should be zeroed.
    **
    ** Note: it is NOT an error for the key/value pair to not exist.
    */
    dav_error * (*fetch)(dav_db *db, dav_datum key, dav_datum *pvalue);

    dav_error * (*store)(dav_db *db, dav_datum key, dav_datum value);
    dav_error * (*remove)(dav_db *db, dav_datum key);

    /* returns 1 if the record specified by "key" exists; 0 otherwise */
    int (*exists)(dav_db *db, dav_datum key);

    dav_error * (*firstkey)(dav_db *db, dav_datum *pkey);
    dav_error * (*nextkey)(dav_db *db, dav_datum *pkey);

    void (*freedatum)(dav_db *db, dav_datum data);
};


/* --------------------------------------------------------------------
**
** LOCK FUNCTIONS
*/

/* Used to represent a Timeout header of "Infinity" */
#define DAV_TIMEOUT_INFINITE 0

time_t dav_get_timeout(request_rec *r);

/*
** Opaque, provider-specific information for a lock database.
*/
typedef struct dav_lockdb_private dav_lockdb_private;

/*
** Opaque, provider-specific information for a lock record.
*/
typedef struct dav_lock_private dav_lock_private;

/*
** Lock database type. Lock providers are urged to implement a "lazy" open, so
** doing an "open" is cheap until something is actually needed from the DB.
*/
typedef struct
{
    const dav_hooks_locks *hooks;	/* the hooks used for this lockdb */
    int ro;				/* was it opened readonly? */

    dav_lockdb_private *info;

} dav_lockdb;

typedef enum {
    DAV_LOCKSCOPE_UNKNOWN,
    DAV_LOCKSCOPE_EXCLUSIVE,
    DAV_LOCKSCOPE_SHARED
} dav_lock_scope;

typedef enum {
    DAV_LOCKTYPE_UNKNOWN,
    DAV_LOCKTYPE_WRITE
} dav_lock_type;

typedef enum {
    DAV_LOCKREC_DIRECT,			/* lock asserted on this resource */
    DAV_LOCKREC_INDIRECT,		/* lock inherited from a parent */
    DAV_LOCKREC_INDIRECT_PARTIAL	/* most info is not filled in */
} dav_lock_rectype;

/*
** dav_lock: hold information about a lock on a resource.
**
** This structure is used for both direct and indirect locks. A direct lock
** is a lock applied to a specific resource by the client. An indirect lock
** is one that is inherited from a parent resource by virtue of a non-zero
** Depth: header when the lock was applied.
**
** mod_dav records both types of locks in the lock database, managing their
** addition/removal as resources are moved about the namespace.
**
** Note that the lockdb is free to marshal this structure in any form that
** it likes.
**
** For a "partial" lock, the <rectype> and <locktoken> fields must be filled
** in. All other (user) fields should be zeroed. The lock provider will
** usually fill in the <info> field, and the <next> field may be used to
** construct a list of partial locks.
**
** The lock provider MUST use the info field to store a value such that a
** dav_lock structure can locate itself in the underlying lock database.
** This requirement is needed for refreshing: when an indirect dav_lock is
** refreshed, its reference to the direct lock does not specify the direct's
** resource, so the only way to locate the (refreshed, direct) lock in the
** database is to use the info field.
**
** Note that <is_locknull> only refers to the resource where this lock was
** found.
** ### hrm. that says the abstraction is wrong. is_locknull may disappear.
*/
typedef struct dav_lock
{
    dav_lock_rectype rectype;	/* type of lock record */
    int is_locknull;		/* lock establishes a locknull resource */

    /* ### put the resource in here? */

    dav_lock_scope scope;	/* scope of the lock */
    dav_lock_type type;		/* type of lock */
    int depth;			/* depth of the lock */
    time_t timeout;		/* when the lock will timeout */

    const dav_locktoken *locktoken;	/* the token that was issued */

    const char *owner;		/* (XML) owner of the lock */
    const char *auth_user;	/* auth'd username owning lock */

    dav_lock_private *info;	/* private to the lockdb */

    struct dav_lock *next;	/* for managing a list of locks */
} dav_lock;

/* Property-related public lock functions */
const char *dav_lock_get_activelock(request_rec *r, dav_lock *locks,
				    dav_buffer *pbuf);

/* LockDB-related public lock functions */
dav_error * dav_lock_parse_lockinfo(request_rec *r,
				    const dav_resource *resrouce,
				    dav_lockdb *lockdb,
				    const ap_xml_doc *doc,
				    dav_lock **lock_request);
int dav_unlock(request_rec *r, const dav_resource *resource,
	       const dav_locktoken *locktoken);
dav_error * dav_add_lock(request_rec *r, const dav_resource *resource,
			 dav_lockdb *lockdb, dav_lock *request,
			 dav_response **response);
dav_error * dav_notify_created(request_rec *r,
			       dav_lockdb *lockdb,
			       const dav_resource *resource,
			       int resource_state,
			       int depth);

dav_error * dav_lock_query(dav_lockdb *lockdb, const dav_resource *resource,
			   dav_lock **locks);

dav_error * dav_validate_request(request_rec *r, dav_resource *resource,
				 int depth, dav_locktoken *locktoken,
				 dav_response **response, int flags,
                                 dav_lockdb *lockdb);
/*
** flags:
**    0x0F -- reserved for <dav_lock_scope> values
**
**    other flags, detailed below
*/
#define DAV_VALIDATE_RESOURCE   0x0010  /* validate just the resource */
#define DAV_VALIDATE_PARENT     0x0020  /* validate resource AND its parent */
#define DAV_VALIDATE_ADD_LD     0x0040  /* add DAV:lockdiscovery into
                                           the 424 DAV:response */
#define DAV_VALIDATE_USE_424    0x0080  /* return 424 status, not 207 */
#define DAV_VALIDATE_IS_PARENT  0x0100  /* for internal use */

/* Lock-null related public lock functions */
int dav_get_resource_state(request_rec *r, const dav_resource *resource);

/* Lock provider hooks. Locking is optional, so there may be no
 * lock provider for a given repository.
 */
struct dav_hooks_locks
{
    /* Return the supportedlock property for this provider */
    /* ### maybe this should take a resource argument? */
    const char * (*get_supportedlock)(void);

    /* Parse a lock token URI, returning a lock token object allocated
     * in the given pool.
     */
    dav_error * (*parse_locktoken)(
        apr_pool_t *p,
        const char *char_token,
        dav_locktoken **locktoken_p
    );

    /* Format a lock token object into a URI string, allocated in
     * the given pool.
     *
     * Always returns non-NULL.
     */
    const char * (*format_locktoken)(
        apr_pool_t *p,
        const dav_locktoken *locktoken
    );

    /* Compare two lock tokens.
     *
     * Result < 0  => lt1 < lt2
     * Result == 0 => lt1 == lt2
     * Result > 0  => lt1 > lt2
     */
    int (*compare_locktoken)(
        const dav_locktoken *lt1,
        const dav_locktoken *lt2
    );

    /* Open the provider's lock database.
     *
     * The provider may or may not use a "real" database for locks
     * (a lock could be an attribute on a resource, for example).
     *
     * The provider may choose to use the value of the DAVLockDB directive
     * (as returned by dav_get_lockdb_path()) to decide where to place
     * any storage it may need.
     *
     * The request storage pool should be associated with the lockdb,
     * so it can be used in subsequent operations.
     *
     * If ro != 0, only readonly operations will be performed.
     * If force == 0, the open can be "lazy"; no subsequent locking operations
     * may occur.
     * If force != 0, locking operations will definitely occur.
     */
    dav_error * (*open_lockdb)(
        request_rec *r,
        int ro,
        int force,
        dav_lockdb **lockdb
    );

    /* Indicates completion of locking operations */
    void (*close_lockdb)(
        dav_lockdb *lockdb
    );

    /* Take a resource out of the lock-null state. */
    dav_error * (*remove_locknull_state)(
        dav_lockdb *lockdb,
        const dav_resource *resource
    );

    /*
    ** Create a (direct) lock structure for the given resource. A locktoken
    ** will be created.
    **
    ** The lock provider may store private information into lock->info.
    */
    dav_error * (*create_lock)(dav_lockdb *lockdb,
			       const dav_resource *resource,
			       dav_lock **lock);

    /*
    ** Get the locks associated with the specified resource.
    **
    ** If resolve_locks is true (non-zero), then any indirect locks are
    ** resolved to their actual, direct lock (i.e. the reference to followed
    ** to the original lock).
    **
    ** The locks, if any, are returned as a linked list in no particular
    ** order. If no locks are present, then *locks will be NULL.
    */
    dav_error * (*get_locks)(dav_lockdb *lockdb,
			     const dav_resource *resource,
			     int calltype,
			     dav_lock **locks);

#define DAV_GETLOCKS_RESOLVED	0	/* resolve indirects to directs */
#define DAV_GETLOCKS_PARTIAL	1	/* leave indirects partially filled */
#define DAV_GETLOCKS_COMPLETE	2	/* fill out indirect locks */

    /*
    ** Find a particular lock on a resource (specified by its locktoken).
    **
    ** *lock will be set to NULL if the lock is not found.
    **
    ** Note that the provider can optimize the unmarshalling -- only one
    ** lock (or none) must be constructed and returned.
    **
    ** If partial_ok is true (non-zero), then an indirect lock can be
    ** partially filled in. Otherwise, another lookup is done and the
    ** lock structure will be filled out as a DAV_LOCKREC_INDIRECT.
    */
    dav_error * (*find_lock)(dav_lockdb *lockdb,
			     const dav_resource *resource,
			     const dav_locktoken *locktoken,
			     int partial_ok,
			     dav_lock **lock);

    /*
    ** Quick test to see if the resource has *any* locks on it.
    **
    ** This is typically used to determine if a non-existent resource
    ** has a lock and is (therefore) a locknull resource.
    **
    ** WARNING: this function may return TRUE even when timed-out locks
    **          exist (i.e. it may not perform timeout checks).
    */
    dav_error * (*has_locks)(dav_lockdb *lockdb,
			     const dav_resource *resource,
			     int *locks_present);

    /*
    ** Append the specified lock(s) to the set of locks on this resource.
    **
    ** If "make_indirect" is true (non-zero), then the specified lock(s)
    ** should be converted to an indirect lock (if it is a direct lock)
    ** before appending. Note that the conversion to an indirect lock does
    ** not alter the passed-in lock -- the change is internal the
    ** append_locks function.
    **
    ** Multiple locks are specified using the lock->next links.
    */
    dav_error * (*append_locks)(dav_lockdb *lockdb,
				const dav_resource *resource,
				int make_indirect,
				const dav_lock *lock);

    /*
    ** Remove any lock that has the specified locktoken.
    **
    ** If locktoken == NULL, then ALL locks are removed.
    */
    dav_error * (*remove_lock)(dav_lockdb *lockdb,
			       const dav_resource *resource,
			       const dav_locktoken *locktoken);

    /*
    ** Refresh all locks, found on the specified resource, which has a
    ** locktoken in the provided list.
    **
    ** If the lock is indirect, then the direct lock is referenced and
    ** refreshed.
    **
    ** Each lock that is updated is returned in the <locks> argument.
    ** Note that the locks will be fully resolved.
    */
    dav_error * (*refresh_locks)(dav_lockdb *lockdb,
				 const dav_resource *resource,
				 const dav_locktoken_list *ltl,
				 time_t new_time,
				 dav_lock **locks);

    /*
    ** Look up the resource associated with a particular locktoken.
    **
    ** The search begins at the specified <start_resource> and the lock
    ** specified by <locktoken>.
    **
    ** If the resource/token specifies an indirect lock, then the direct
    ** lock will be looked up, and THAT resource will be returned. In other
    ** words, this function always returns the resource where a particular
    ** lock (token) was asserted.
    **
    ** NOTE: this function pointer is allowed to be NULL, indicating that
    **       the provider does not support this type of functionality. The
    **       caller should then traverse up the repository hierarchy looking
    **       for the resource defining a lock with this locktoken.
    */
    dav_error * (*lookup_resource)(dav_lockdb *lockdb,
				   const dav_locktoken *locktoken,
				   const dav_resource *start_resource,
				   const dav_resource **resource);
};

/* what types of resources can be discovered by dav_get_resource_state() */
#define DAV_RESOURCE_LOCK_NULL	10	/* resource lock-null */
#define DAV_RESOURCE_NULL	11	/* resource null */
#define DAV_RESOURCE_EXISTS	12	/* resource exists */
#define DAV_RESOURCE_ERROR	13	/* an error occurred */


/* --------------------------------------------------------------------
**
** PROPERTY HANDLING
*/

typedef struct dav_propdb dav_propdb;


dav_error *dav_open_propdb(
    request_rec *r,
    dav_lockdb *lockdb,
    dav_resource *resource,
    int ro,
    apr_array_header_t *ns_xlate,
    dav_propdb **propdb);

void dav_close_propdb(dav_propdb *db);

dav_get_props_result dav_get_props(
    dav_propdb *db,
    ap_xml_doc *doc);

dav_get_props_result dav_get_allprops(
    dav_propdb *db,
    int getvals);

/*
** 3-phase property modification.
**
**   1) validate props. readable? unlocked? ACLs allow access?
**   2) execute operation (set/delete)
**   3) commit or rollback
**
** ### eventually, auth must be available. a ref to the request_rec (which
** ### contains the auth info) should be in the shared context struct.
**
** Each function may alter the error values and information contained within
** the context record. This should be done as an "increasing" level of
** error, rather than overwriting any previous error.
**
** Note that commit() cannot generate errors. It should simply free the
** rollback information.
**
** rollback() may generate additional errors because the rollback operation
** can sometimes fail(!).
**
** The caller should allocate an array of these, one per operation. It should
** be zero-initialized, then the db, operation, and prop fields should be
** filled in before calling dav_prop_validate. Note that the set/delete
** operations are order-dependent. For a given (logical) context, the same
** pointer must be passed to each phase.
**
** error_type is an internal value, but will have the same numeric value
** for each possible "desc" value. This allows the caller to group the
** descriptions via the error_type variable, rather than through string
** comparisons. Note that "status" does not provide enough granularity to
** differentiate/group the "desc" values.
**
** Note that the propdb will maintain some (global) context across all
** of the property change contexts. This implies that you can have only
** one open transaction per propdb.
*/
typedef struct dav_prop_ctx
{
    dav_propdb *propdb;

    int operation;
#define DAV_PROP_OP_SET		1	/* set a property value */
#define DAV_PROP_OP_DELETE	2	/* delete a prop value */
/* ### add a GET? */

    ap_xml_elem *prop;			/* property to affect */

    dav_error *err;			/* error (if any) */

    /* private items to the propdb */
    int is_liveprop;
    void *liveprop_ctx;
    struct dav_rollback_item *rollback;	/* optional rollback info */

    /* private to mod_dav.c */
    request_rec *r;

} dav_prop_ctx;

void dav_prop_validate(dav_prop_ctx *ctx);
void dav_prop_exec(dav_prop_ctx *ctx);
void dav_prop_commit(dav_prop_ctx *ctx);
void dav_prop_rollback(dav_prop_ctx *ctx);

#define DAV_PROP_CTX_HAS_ERR(dpc)	((dpc).err && (dpc).err->status >= 300)


/* --------------------------------------------------------------------
**
** WALKER STRUCTURE
*/

/* private, opaque info structure for repository walking context */
typedef struct dav_walker_private dav_walker_private;

/* directory tree walking context */
typedef struct dav_walker_ctx
{
    int walk_type;
#define DAV_WALKTYPE_AUTH	1	/* limit to authorized files */
#define DAV_WALKTYPE_ALL	2	/* walk normal files */
#define DAV_WALKTYPE_HIDDEN	4	/* walk hidden files */
#define DAV_WALKTYPE_LOCKNULL	8	/* walk locknull resources */

    int postfix;		/* call func for dirs after files */

    dav_error * (*func)(struct dav_walker_ctx *ctx, int calltype);
#define DAV_CALLTYPE_MEMBER	1	/* called for a member resource */
#define DAV_CALLTYPE_COLLECTION	2	/* called for a collection */
#define DAV_CALLTYPE_LOCKNULL	3	/* called for a locknull resource */
#define DAV_CALLTYPE_POSTFIX	4	/* postfix call for a collection */

    apr_pool_t *pool;

    request_rec *r;			/* original request */
    dav_buffer uri;			/* current URI */
    const dav_resource *resource;	/* current resource */
    const dav_resource *res2;		/* optional secondary resource */

    const dav_resource *root;		/* RO: root resource of the walk */

    dav_lockdb *lockdb;

    dav_response *response;		/* OUT: multistatus responses */

    /* for PROPFIND operations */
    ap_xml_doc *doc;
    int propfind_type;
#define DAV_PROPFIND_IS_ALLPROP		1
#define DAV_PROPFIND_IS_PROPNAME	2
#define DAV_PROPFIND_IS_PROP		3

    ap_text *propstat_404;	/* (cached) propstat giving a 404 error */

    /* for COPY and MOVE operations */
    int is_move;
    dav_buffer work_buf;

    const dav_if_header *if_header;	/* for validation */
    const dav_locktoken *locktoken;	/* for UNLOCK */
    const dav_lock *lock;		/* for LOCK */
    int skip_root;			/* for dav_inherit_locks() */

    int flags;

    dav_walker_private *info;           /* for use by repository manager */

} dav_walker_ctx;

void dav_add_response(dav_walker_ctx *ctx, const char *href, int status,
		      dav_get_props_result *propstats);


/* --------------------------------------------------------------------
**
** "STREAM" STRUCTURE
**
** mod_dav uses this abstraction for interacting with the repository
** while fetching/storing resources. mod_dav views resources as a stream
** of bytes.
**
** Note that the structure is opaque -- it is private to the repository
** that created the stream in the repository's "open" function.
*/

typedef struct dav_stream dav_stream;

typedef enum {
    DAV_MODE_READ,		/* open for reading */
    DAV_MODE_READ_SEEKABLE,	/* open for random access reading */
    DAV_MODE_WRITE_TRUNC,	/* truncate and open for writing */
    DAV_MODE_WRITE_SEEKABLE	/* open for writing; random access */
} dav_stream_mode;


/* --------------------------------------------------------------------
**
** REPOSITORY FUNCTIONS
*/

/* Repository provider hooks */
struct dav_hooks_repository
{
    /* Flag for whether repository requires special GET handling.
     * If resources in the repository are not visible in the
     * filesystem location which URLs map to, then special handling
     * is required to first fetch a resource from the repository,
     * respond to the GET request, then free the resource copy.
     */
    int handle_get;

    /* Get a resource descriptor for the URI in a request.
     * A descriptor is returned even if the resource does not exist.
     * The return value should only be NULL for some kind of fatal error.
     *
     * The root_dir is the root of the directory for which this repository
     * is configured.
     * The workspace is the value of any Target-Selector header, or NULL
     * if there is none.
     *
     * The provider may associate the request storage pool with the resource,
     * to use in other operations on that resource.
     */
    dav_resource * (*get_resource)(
        request_rec *r,
        const char *root_dir,
        const char *workspace
    );

    /* Get a resource descriptor for the parent of the given resource.
     * The resources need not exist.  NULL is returned if the resource 
     * is the root collection.
     */
    dav_resource * (*get_parent_resource)(
        const dav_resource *resource
    );

    /* Determine whether two resource descriptors refer to the same resource.
    *
     * Result != 0 => the resources are the same.
     */
    int (*is_same_resource)(
        const dav_resource *res1,
        const dav_resource *res2
    );

    /* Determine whether one resource is a parent (immediate or otherwise)
     * of another.
     *
     * Result != 0 => res1 is a parent of res2.
     */
    int (*is_parent_resource)(
        const dav_resource *res1,
        const dav_resource *res2
    );

    /*
    ** Open a stream for this resource, using the specified mode. The
    ** stream will be returned in *stream.
    */
    dav_error * (*open_stream)(const dav_resource *resource,
			       dav_stream_mode mode,
			       dav_stream **stream);

    /*
    ** Close the specified stream.
    **
    ** mod_dav will (ideally) make sure to call this. For safety purposes,
    ** a provider should (ideally) register a cleanup function with the
    ** request pool to get this closed and cleaned up.
    **
    ** Note the possibility of an error from the close -- it is entirely
    ** feasible that the close does a "commit" of some kind, which can
    ** produce an error.
    **
    ** commit should be TRUE (non-zero) or FALSE (0) if the stream was
    ** opened for writing. This flag states whether to retain the file
    ** or not.
    ** Note: the commit flag is ignored for streams opened for reading.
    */
    dav_error * (*close_stream)(dav_stream *stream, int commit);

    /*
    ** Read data from the stream.
    **
    ** The size of the buffer is passed in *bufsize, and the amount read
    ** is returned in *bufsize.
    **
    ** *bufsize should be set to zero when the end of file is reached.
    ** As a corollary, this function should always read at least one byte
    ** on each call, until the EOF condition is met.
    */
    dav_error * (*read_stream)(dav_stream *stream,
			       void *buf, apr_size_t *bufsize);

    /*
    ** Write data to the stream.
    **
    ** All of the bytes must be written, or an error should be returned.
    */
    dav_error * (*write_stream)(dav_stream *stream,
				const void *buf, apr_size_t bufsize);

    /*
    ** Seek to an absolute position in the stream. This is used to support
    ** Content-Range in a GET/PUT.
    **
    ** NOTE: if this function is NULL (which is allowed), then any
    **       operations using Content-Range will be refused.
    */
    dav_error * (*seek_stream)(dav_stream *stream, off_t abs_position);

    /*
    ** If a GET is processed using a stream (open_stream, read_stream)
    ** rather than via a sub-request (on get_pathname), then this function
    ** is used to provide the repository with a way to set the headers
    ** in the response.
    **
    ** It may be NULL if get_pathname is provided.
    */
    dav_error * (*set_headers)(request_rec *r,
			       const dav_resource *resource);

    /* Get a pathname for the file represented by the resource descriptor.
     * A provider may need to create a temporary copy of the file, if it is
     * not directly accessible in a filesystem. free_handle_p will be set by
     * the provider to point to information needed to clean up any temporary
     * storage used.
     *
     * Returns NULL if the file could not be made accessible.
     */
    const char * (*get_pathname)(
        const dav_resource *resource,
        void **free_handle_p
    );

    /* Free any temporary storage associated with a file made accessible by
     * get_pathname().
     */
    void (*free_file)(
        void *free_handle
    );

    /* Create a collection resource. The resource must not already exist.
     *
     * Result == NULL if the collection was created successfully. Also, the
     * resource object is updated to reflect that the resource exists, and
     * is a collection.
     */
    dav_error * (*create_collection)(
        apr_pool_t *p, dav_resource *resource
    );

    /* Copy one resource to another. The destination must not exist.
     * Handles both files and collections. Properties are copied as well.
     * The depth argument is ignored for a file, and can be either 0 or
     * DAV_INFINITY for a collection.
     * If an error occurs in a child resource, then the return value is
     * non-NULL, and *response is set to a multistatus response.
     * If the copy is successful, the dst resource object is
     * updated to reflect that the resource exists.
     */
    dav_error * (*copy_resource)(
        const dav_resource *src,
        dav_resource *dst,
	int depth,
        dav_response **response
    );

    /* Move one resource to another. The destination must not exist.
     * Handles both files and collections. Properties are moved as well.
     * If an error occurs in a child resource, then the return value is
     * non-NULL, and *response is set to a multistatus response.
     * If the move is successful, the src and dst resource objects are
     * updated to reflect that the source no longer exists, and the
     * destination does.
     */
    dav_error * (*move_resource)(
        dav_resource *src,
        dav_resource *dst,
        dav_response **response
    );

    /* Remove a resource. Handles both files and collections.
     * Removes any associated properties as well.
     * If an error occurs in a child resource, then the return value is
     * non-NULL, and *response is set to a multistatus response.
     * If the delete is successful, the resource object is updated to
     * reflect that the resource no longer exists.
     */
    dav_error * (*remove_resource)(
        dav_resource *resource,
        dav_response **response
    );

    /* Walk a resource hierarchy.
     *
     * Iterates over the resource hierarchy specified by wctx->resource.
     * Parameter for control of the walk and the callback are specified
     * by wctx.
     *
     * An HTTP_* status code is returned if an error occurs during the
     * walk or the callback indicates an error. OK is returned on success.
     */
    dav_error * (*walk)(dav_walker_ctx *wctx, int depth);

    /* Get the entity tag for a resource */
    const char * (*getetag)(const dav_resource *resource);
};


/* --------------------------------------------------------------------
**
** VERSIONING FUNCTIONS
*/

/* dav_get_target_selector:
 *
 * Returns any Target-Selector header in a request
 * (used by versioning clients)
 */
const char *dav_get_target_selector(request_rec *r);

/* Ensure that a resource is writable. If there is no versioning
 * provider, then this is essentially a no-op. Versioning repositories
 * require explicit resource creation and checkout before they can
 * be written to. If a new resource is to be created, or an existing
 * resource deleted, the parent collection must be checked out as well.
 *
 * Set the parent_only flag to only make the parent collection writable.
 * Otherwise, both parent and child are made writable as needed. If the
 * child does not exist, then a new versioned resource is created and
 * checked out.
 *
 * The parent_resource and parent_was_writable arguments are optional
 * (i.e. they may be NULL). If parent_only is set, then the
 * resource_existed and resource_was_writable arguments are ignored.
 *
 * The previous states of the resources are returned, so they can be
 * restored after the operation completes (see
 * dav_revert_resource_writability())
 */
dav_error *dav_ensure_resource_writable(request_rec *r,
					dav_resource *resource,
                                        int parent_only,
					dav_resource **parent_resource,
					int *resource_existed,
					int *resource_was_writable,
					int *parent_was_writable);

/* Revert the writability of resources back to what they were
 * before they were modified. If undo == 0, then the resource
 * modifications are maintained (i.e. they are checked in).
 * If undo != 0, then resource modifications are discarded
 * (i.e. they are unchecked out).
 *
 * The resource and parent_resource arguments are optional
 * (i.e. they may be NULL).
 */
dav_error *dav_revert_resource_writability(request_rec *r,
					   dav_resource *resource,
					   dav_resource *parent_resource,
					   int undo,
					   int resource_existed,
					   int resource_was_writable,
					   int parent_was_writable);

/* Versioning provider hooks */
struct dav_hooks_vsn
{
    /* Return supported versioning level
     * for the Versioning header
     */
    const char * (*get_vsn_header)(void);

    /* Create a new (empty) resource. If successful,
     * the resource object state is updated appropriately.
     */
    dav_error * (*mkresource)(dav_resource *resource);

    /* Checkout a resource. If successful, the resource
     * object state is updated appropriately.
     */
    dav_error * (*checkout)(dav_resource *resource);

    /* Uncheckout a resource. If successful, the resource
     * object state is updated appropriately.
     */
    dav_error * (*uncheckout)(dav_resource *resource);

    /* Checkin a working resource. If successful, the resource
     * object state is updated appropriately.
     */
    dav_error * (*checkin)(dav_resource *resource);

    /* Determine whether a non-versioned (or non-existent) resource
     * is versionable. Returns != 0 if resource can be versioned.
     */
    int (*versionable)(const dav_resource *resource);

    /* Determine whether auto-versioning is enabled for a resource
     * (which may not exist, or may not be versioned).
     * Returns != 0 if auto-versioning is enabled.
     */
    int (*auto_version_enabled)(const dav_resource *resource);
};


/* --------------------------------------------------------------------
**
** MISCELLANEOUS STUFF
*/

/* allow providers access to the per-directory parameters */
apr_table_t *dav_get_dir_params(const request_rec *r);

/* fetch the "LimitXMLRequestBody" in force for this resource */
apr_size_t dav_get_limit_xml_body(const request_rec *r);

typedef struct {
    int propid;				/* live property ID */
    const dav_hooks_liveprop *provider;	/* the provider defining this prop */
} dav_elem_private;    

#ifdef __cplusplus
}
#endif

#endif /* _MOD_DAV_H_ */
