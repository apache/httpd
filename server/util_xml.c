/*
** Copyright (C) 1998-2000 Greg Stein. All Rights Reserved.
**
** By using this file, you agree to the terms and conditions set forth in
** the LICENSE.html file which can be found at the top level of the mod_dav
** distribution or at http://www.webdav.org/mod_dav/license-1.html.
**
** Contact information:
**   Greg Stein, PO Box 760, Palo Alto, CA, 94302
**   gstein@lyra.org, http://www.webdav.org/mod_dav/
*/

/*
** DAV extension module for Apache 1.3.*
**  - XML parser for the body of a request
**
** Written by Greg Stein, gstein@lyra.org, http://www.lyra.org/
*/

/* James Clark's Expat parser */
#include <xmlparse.h>

#include "httpd.h"
#include "http_protocol.h"
#include "http_log.h"

#include "mod_dav.h"


/* errors related to namespace processing */
#define DAV_NS_ERROR_UNKNOWN_PREFIX	(DAV_NS_ERROR_BASE)

/* test for a namespace prefix that begins with [Xx][Mm][Ll] */
#define DAV_NS_IS_RESERVED(name) \
	( (name[0] == 'X' || name[0] == 'x') && \
	  (name[1] == 'M' || name[1] == 'm') && \
	  (name[2] == 'L' || name[2] == 'l') )

/* content for parsing */
typedef struct dav_xml_ctx {
    dav_xml_doc *doc;		/* the doc we're parsing */
    ap_pool *p;			/* the pool we allocate from */
    dav_xml_elem *cur_elem;	/* current element */

    int error;			/* an error has occurred */
    /* errors may be DAV_NS_ERROR_* or other errors defined here (none yet) */

} dav_xml_ctx;

/* struct for scoping namespace declarations */
typedef struct dav_xml_ns_scope {
    const char *prefix;		/* prefix used for this ns */
    int ns;			/* index into namespace table */
    int emptyURI;		/* the namespace URI is the empty string */
    struct dav_xml_ns_scope *next;	/* next scoped namespace */
} dav_xml_ns_scope;

/* ### need a similar mechanism for xml:lang values */


/* return namespace table index for a given prefix */
static int dav_find_prefix(dav_xml_ctx *ctx, const char *prefix)
{
    dav_xml_elem *elem = ctx->cur_elem;

    /*
    ** Walk up the tree, looking for a namespace scope that defines this
    ** prefix.
    */
    for (; elem; elem = elem->parent) {
	dav_xml_ns_scope *ns_scope = elem->ns_scope;

	for (ns_scope = elem->ns_scope; ns_scope; ns_scope = ns_scope->next) {
	    if (strcmp(prefix, ns_scope->prefix) == 0) {
		if (ns_scope->emptyURI) {
		    /*
		    ** It is possible to set the default namespace to an
		    ** empty URI string; this resets the default namespace
		    ** to mean "no namespace." We just found the prefix
		    ** refers to an empty URI, so return "no namespace."
		    */
		    return DAV_NS_NONE;
		}

		return ns_scope->ns;
	    }
	}
    }

    /*
     * If the prefix is empty (""), this means that a prefix was not
     * specified in the element/attribute. The search that was performed
     * just above did not locate a default namespace URI (which is stored
     * into ns_scope with an empty prefix). This means the element/attribute
     * has "no namespace". We have a reserved value for this.
     */
    if (*prefix == '\0') {
	return DAV_NS_NONE;
    }

    /* not found */
    return DAV_NS_ERROR_UNKNOWN_PREFIX;
}

static void dav_start_handler(void *userdata, const char *name, const char **attrs)
{
    dav_xml_ctx *ctx = userdata;
    dav_xml_elem *elem;
    dav_xml_attr *attr;
    dav_xml_attr *prev;
    char *colon;
    const char *quoted;

    /* punt once we find an error */
    if (ctx->error)
	return;

    elem = ap_pcalloc(ctx->p, sizeof(*elem));

    /* prep the element */
    elem->name = ap_pstrdup(ctx->p, name);

    /* fill in the attributes (note: ends up in reverse order) */
    while (*attrs) {
	attr = ap_palloc(ctx->p, sizeof(*attr));
	attr->name = ap_pstrdup(ctx->p, *attrs++);
	attr->value = ap_pstrdup(ctx->p, *attrs++);
	attr->next = elem->attr;
	elem->attr = attr;
    }

    /* hook the element into the tree */
    if (ctx->cur_elem == NULL) {
	/* no current element; this also becomes the root */
	ctx->cur_elem = ctx->doc->root = elem;
    }
    else {
	/* this element appeared within the current elem */
	elem->parent = ctx->cur_elem;

	/* set up the child/sibling links */
	if (elem->parent->last_child == NULL) {
	    /* no first child either */
	    elem->parent->first_child = elem->parent->last_child = elem;
	}
	else {
	    /* hook onto the end of the parent's children */
	    elem->parent->last_child->next = elem;
	    elem->parent->last_child = elem;
	}

	/* this element is now the current element */
	ctx->cur_elem = elem;
    }

    /* scan the attributes for namespace declarations */
    for (prev = NULL, attr = elem->attr;
	 attr;
	 attr = attr->next) {
	if (strncmp(attr->name, "xmlns", 5) == 0) {
	    const char *prefix = &attr->name[5];
	    dav_xml_ns_scope *ns_scope;

	    /* test for xmlns:foo= form and xmlns= form */
	    if (*prefix == ':')
		++prefix;
	    else if (*prefix != '\0') {
		/* advance "prev" since "attr" is still present */
		prev = attr;
		continue;
	    }

	    /* quote the URI before we ever start working with it */
	    quoted = dav_quote_string(ctx->p, attr->value, 1);

	    /* build and insert the new scope */
	    ns_scope = ap_pcalloc(ctx->p, sizeof(*ns_scope));
	    ns_scope->prefix = prefix;
	    ns_scope->ns = dav_insert_uri(ctx->doc->namespaces, quoted);
	    ns_scope->emptyURI = *quoted == '\0';
	    ns_scope->next = elem->ns_scope;
	    elem->ns_scope = ns_scope;

	    /* remove this attribute from the element */
	    if (prev == NULL)
		elem->attr = attr->next;
	    else
		prev->next = attr->next;

	    /* Note: prev will not be advanced since we just removed "attr" */
	}
	else if (strcmp(attr->name, "xml:lang") == 0) {
	    /* save away the language (in quoted form) */
	    elem->lang = dav_quote_string(ctx->p, attr->value, 1);

	    /* remove this attribute from the element */
	    if (prev == NULL)
		elem->attr = attr->next;
	    else
		prev->next = attr->next;

	    /* Note: prev will not be advanced since we just removed "attr" */
	}
	else {
	    /* advance "prev" since "attr" is still present */
	    prev = attr;
	}
    }

    /*
    ** If an xml:lang attribute didn't exist (lang==NULL), then copy the
    ** language from the parent element (if present).
    **
    ** NOTE: dav_elem_size() *depends* upon this pointer equality.
    */
    if (elem->lang == NULL && elem->parent != NULL)
	elem->lang = elem->parent->lang;

    /* adjust the element's namespace */
    colon = strchr(elem->name, ':');
    if (colon == NULL) {
	/*
	 * The element is using the default namespace, which will always
	 * be found. Either it will be "no namespace", or a default
	 * namespace URI has been specified at some point.
	 */
	elem->ns = dav_find_prefix(ctx, "");
    }
    else if (DAV_NS_IS_RESERVED(elem->name)) {
	elem->ns = DAV_NS_NONE;
    }
    else {
	*colon = '\0';
	elem->ns = dav_find_prefix(ctx, elem->name);
	elem->name = colon + 1;

	if (DAV_NS_IS_ERROR(elem->ns)) {
	    ctx->error = elem->ns;
	    return;
	}
    }

    /* adjust all remaining attributes' namespaces */
    for (attr = elem->attr; attr; attr = attr->next) {
	colon = strchr(attr->name, ':');
	if (colon == NULL) {
	    /*
	     * Attributes do NOT use the default namespace. Therefore,
	     * we place them into the "no namespace" category.
	     */
	    attr->ns = DAV_NS_NONE;
	}
	else if (DAV_NS_IS_RESERVED(attr->name)) {
	    attr->ns = DAV_NS_NONE;
	}
	else {
	    *colon = '\0';
	    attr->ns = dav_find_prefix(ctx, attr->name);
	    attr->name = colon + 1;

	    if (DAV_NS_IS_ERROR(attr->ns)) {
		ctx->error = attr->ns;
		return;
	    }
	}
    }
}

static void dav_end_handler(void *userdata, const char *name)
{
    dav_xml_ctx *ctx = userdata;

    /* punt once we find an error */
    if (ctx->error)
	return;

    /* pop up one level */
    ctx->cur_elem = ctx->cur_elem->parent;
}

static void dav_cdata_handler(void *userdata, const char *data, int len)
{
    dav_xml_ctx *ctx = userdata;
    dav_xml_elem *elem;
    dav_text_header *hdr;
    const char *s;

    /* punt once we find an error */
    if (ctx->error)
	return;

    elem = ctx->cur_elem;
    s = ap_pstrndup(ctx->p, data, len);

    if (elem->last_child == NULL) {
	/* no children yet. this cdata follows the start tag */
	hdr = &elem->first_cdata;
    }
    else {
	/* child elements exist. this cdata follows the last child. */
	hdr = &elem->last_child->following_cdata;
    }

    dav_text_append(ctx->p, hdr, s);
}

int dav_parse_input(request_rec * r, dav_xml_doc **pdoc)
{
    int result;
    dav_xml_ctx ctx =
    {0};
    XML_Parser parser;

    if ((result = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK)) != OK)
	return result;

    if (r->remaining == 0) {
	*pdoc = NULL;
	return OK;
    }

    ctx.p = r->pool;
    ctx.doc = ap_pcalloc(ctx.p, sizeof(*ctx.doc));

    ctx.doc->namespaces = ap_make_array(ctx.p, 5, sizeof(const char *));
    dav_insert_uri(ctx.doc->namespaces, "DAV:");

    /* ### we should get the encoding from Content-Encoding */
    parser = XML_ParserCreate(NULL);
    if (parser == NULL) {
	/* ### anything better to do? */
	fprintf(stderr, "Ouch!  XML_ParserCreate() failed!\n");
	exit(1);
    }

    XML_SetUserData(parser, (void *) &ctx);
    XML_SetElementHandler(parser, dav_start_handler, dav_end_handler);
    XML_SetCharacterDataHandler(parser, dav_cdata_handler);

    if (ap_should_client_block(r)) {
	long len;
	char *buffer;
	char end;
	int rv;
	size_t total_read = 0;
	size_t limit_xml_body = dav_get_limit_xml_body(r);

	/* allocate our working buffer */
	buffer = ap_palloc(r->pool, DAV_READ_BLOCKSIZE);

	/* read the body, stuffing it into the parser */
	while ((len = ap_get_client_block(r, buffer, DAV_READ_BLOCKSIZE)) > 0) {
	    total_read += len;
	    if (limit_xml_body && total_read > limit_xml_body) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
			      "XML request body is larger than the configured "
			      "limit of %lu", (unsigned long)limit_xml_body);
		goto read_error;
	    }

	    rv = XML_Parse(parser, buffer, len, 0);
	    if (rv == 0)
		goto parser_error;
	}
	if (len == -1) {
	    /* ap_get_client_block() has logged an error */
	    goto read_error;
	}

	/* tell the parser that we're done */
	rv = XML_Parse(parser, &end, 0, 1);
	if (rv == 0)
	    goto parser_error;
    }

    XML_ParserFree(parser);

    if (ctx.error) {
	switch (ctx.error) {
	case DAV_NS_ERROR_UNKNOWN_PREFIX:
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, r,
			  "An undefined namespace prefix was used.");
	    break;

	default:
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, r,
			  "There was an error within the XML request body.");
	    break;
	}

	/* Apache will supply a default error, plus the error log above. */
	return HTTP_BAD_REQUEST;
    }

    /* ### assert: ctx.cur_elem == NULL */

    *pdoc = ctx.doc;

    return OK;

  parser_error:
    {
	enum XML_Error err = XML_GetErrorCode(parser);

	/* ### fix this error message (default vs special) */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, r,
		      "XML parser error code: %s (%d).",
		      XML_ErrorString(err), err);

	XML_ParserFree(parser);

	/* Apache will supply a default error, plus the error log above. */
	return HTTP_BAD_REQUEST;
    }

  read_error:
    XML_ParserFree(parser);

    /* Apache will supply a default error, plus whatever was logged. */
    return HTTP_BAD_REQUEST;
}
