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
**  - XML parser for the body of a request
*/

/* James Clark's Expat parser */
#include "xmlparse.h"

#include "httpd.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_core.h"
#include "apr_strings.h"

#include "util_xml.h"


#define DEBUG_CR "\r\n"

#define AP_XML_READ_BLOCKSIZE	2048	/* used for reading input blocks */

/* errors related to namespace processing */
#define AP_XML_NS_ERROR_UNKNOWN_PREFIX	(AP_XML_NS_ERROR_BASE)

/* test for a namespace prefix that begins with [Xx][Mm][Ll] */
#define AP_XML_NS_IS_RESERVED(name) \
	( (name[0] == 'X' || name[0] == 'x') && \
	  (name[1] == 'M' || name[1] == 'm') && \
	  (name[2] == 'L' || name[2] == 'l') )


/* content for parsing */
typedef struct ap_xml_ctx {
    ap_xml_doc *doc;		/* the doc we're parsing */
    apr_pool_t *p;		/* the pool we allocate from */
    ap_xml_elem *cur_elem;	/* current element */

    int error;			/* an error has occurred */
    /* errors may be AP_XML_NS_ERROR_* or other private errors which will
       be defined here (none yet) */

} ap_xml_ctx;

/* struct for scoping namespace declarations */
typedef struct ap_xml_ns_scope {
    const char *prefix;		/* prefix used for this ns */
    int ns;			/* index into namespace table */
    int emptyURI;		/* the namespace URI is the empty string */
    struct ap_xml_ns_scope *next;	/* next scoped namespace */
} ap_xml_ns_scope;


/* return namespace table index for a given prefix */
static int find_prefix(ap_xml_ctx *ctx, const char *prefix)
{
    ap_xml_elem *elem = ctx->cur_elem;

    /*
    ** Walk up the tree, looking for a namespace scope that defines this
    ** prefix.
    */
    for (; elem; elem = elem->parent) {
	ap_xml_ns_scope *ns_scope = elem->ns_scope;

	for (ns_scope = elem->ns_scope; ns_scope; ns_scope = ns_scope->next) {
	    if (strcmp(prefix, ns_scope->prefix) == 0) {
		if (ns_scope->emptyURI) {
		    /*
		    ** It is possible to set the default namespace to an
		    ** empty URI string; this resets the default namespace
		    ** to mean "no namespace." We just found the prefix
		    ** refers to an empty URI, so return "no namespace."
		    */
		    return AP_XML_NS_NONE;
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
	return AP_XML_NS_NONE;
    }

    /* not found */
    return AP_XML_NS_ERROR_UNKNOWN_PREFIX;
}

static void start_handler(void *userdata, const char *name, const char **attrs)
{
    ap_xml_ctx *ctx = userdata;
    ap_xml_elem *elem;
    ap_xml_attr *attr;
    ap_xml_attr *prev;
    char *colon;
    const char *quoted;
    char *elem_name;

    /* punt once we find an error */
    if (ctx->error)
	return;

    elem = apr_pcalloc(ctx->p, sizeof(*elem));

    /* prep the element */
    elem->name = elem_name = apr_pstrdup(ctx->p, name);

    /* fill in the attributes (note: ends up in reverse order) */
    while (*attrs) {
	attr = apr_palloc(ctx->p, sizeof(*attr));
	attr->name = apr_pstrdup(ctx->p, *attrs++);
	attr->value = apr_pstrdup(ctx->p, *attrs++);
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
	    ap_xml_ns_scope *ns_scope;

	    /* test for xmlns:foo= form and xmlns= form */
	    if (*prefix == ':')
		++prefix;
	    else if (*prefix != '\0') {
		/* advance "prev" since "attr" is still present */
		prev = attr;
		continue;
	    }

	    /* quote the URI before we ever start working with it */
	    quoted = ap_xml_quote_string(ctx->p, attr->value, 1);

	    /* build and insert the new scope */
	    ns_scope = apr_pcalloc(ctx->p, sizeof(*ns_scope));
	    ns_scope->prefix = prefix;
	    ns_scope->ns = ap_xml_insert_uri(ctx->doc->namespaces, quoted);
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
	    elem->lang = ap_xml_quote_string(ctx->p, attr->value, 1);

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
    ** NOTE: elem_size() *depends* upon this pointer equality.
    */
    if (elem->lang == NULL && elem->parent != NULL)
	elem->lang = elem->parent->lang;

    /* adjust the element's namespace */
    colon = ap_strchr(elem_name, ':');
    if (colon == NULL) {
	/*
	 * The element is using the default namespace, which will always
	 * be found. Either it will be "no namespace", or a default
	 * namespace URI has been specified at some point.
	 */
	elem->ns = find_prefix(ctx, "");
    }
    else if (AP_XML_NS_IS_RESERVED(elem->name)) {
	elem->ns = AP_XML_NS_NONE;
    }
    else {
	*colon = '\0';
	elem->ns = find_prefix(ctx, elem->name);
	elem->name = colon + 1;

	if (AP_XML_NS_IS_ERROR(elem->ns)) {
	    ctx->error = elem->ns;
	    return;
	}
    }

    /* adjust all remaining attributes' namespaces */
    for (attr = elem->attr; attr; attr = attr->next) {
        /*
         * ap_xml_attr defines this as "const" but we dup'd it, so we
         * know that we can change it. a bit hacky, but the existing
         * structure def is best.
         */
        char *attr_name = (char *)attr->name;

	colon = ap_strchr(attr_name, ':');
	if (colon == NULL) {
	    /*
	     * Attributes do NOT use the default namespace. Therefore,
	     * we place them into the "no namespace" category.
	     */
	    attr->ns = AP_XML_NS_NONE;
	}
	else if (AP_XML_NS_IS_RESERVED(attr->name)) {
	    attr->ns = AP_XML_NS_NONE;
	}
	else {
	    *colon = '\0';
	    attr->ns = find_prefix(ctx, attr->name);
	    attr->name = colon + 1;

	    if (AP_XML_NS_IS_ERROR(attr->ns)) {
		ctx->error = attr->ns;
		return;
	    }
	}
    }
}

static void end_handler(void *userdata, const char *name)
{
    ap_xml_ctx *ctx = userdata;

    /* punt once we find an error */
    if (ctx->error)
	return;

    /* pop up one level */
    ctx->cur_elem = ctx->cur_elem->parent;
}

static void cdata_handler(void *userdata, const char *data, int len)
{
    ap_xml_ctx *ctx = userdata;
    ap_xml_elem *elem;
    ap_text_header *hdr;
    const char *s;

    /* punt once we find an error */
    if (ctx->error)
	return;

    elem = ctx->cur_elem;
    s = apr_pstrndup(ctx->p, data, len);

    if (elem->last_child == NULL) {
	/* no children yet. this cdata follows the start tag */
	hdr = &elem->first_cdata;
    }
    else {
	/* child elements exist. this cdata follows the last child. */
	hdr = &elem->last_child->following_cdata;
    }

    ap_text_append(ctx->p, hdr, s);
}

API_EXPORT(int) ap_xml_parse_input(request_rec * r, ap_xml_doc **pdoc)
{
    int result;
    ap_xml_ctx ctx =
    {0};
    XML_Parser parser;

    if ((result = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK)) != OK)
	return result;

    if (r->remaining == 0) {
	*pdoc = NULL;
	return OK;
    }

    ctx.p = r->pool;
    ctx.doc = apr_pcalloc(ctx.p, sizeof(*ctx.doc));

    ctx.doc->namespaces = apr_make_array(ctx.p, 5, sizeof(const char *));
    ap_xml_insert_uri(ctx.doc->namespaces, "DAV:");

    /* ### we should get the encoding from Content-Encoding */
    parser = XML_ParserCreate(NULL);
    if (parser == NULL) {
	/* ### anything better to do? */
	fprintf(stderr, "Ouch!  XML_ParserCreate() failed!\n");
	exit(1);
    }

    XML_SetUserData(parser, (void *) &ctx);
    XML_SetElementHandler(parser, start_handler, end_handler);
    XML_SetCharacterDataHandler(parser, cdata_handler);

    if (ap_should_client_block(r)) {
	long len;
	char *buffer;
	char end;
	int rv;
	size_t total_read = 0;
	size_t limit_xml_body = ap_get_limit_xml_body(r);

	/* allocate our working buffer */
	buffer = apr_palloc(r->pool, AP_XML_READ_BLOCKSIZE);

	/* read the body, stuffing it into the parser */
	while ((len = ap_get_client_block(r, buffer, AP_XML_READ_BLOCKSIZE)) > 0) {
	    total_read += len;
	    if (limit_xml_body && total_read > limit_xml_body) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
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
	case AP_XML_NS_ERROR_UNKNOWN_PREFIX:
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
			  "An undefined namespace prefix was used.");
	    break;

	default:
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
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
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
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

API_EXPORT(void) ap_text_append(apr_pool_t * p, ap_text_header *hdr,
                                const char *text)
{
    ap_text *t = apr_palloc(p, sizeof(*t));

    t->text = text;
    t->next = NULL;

    if (hdr->first == NULL) {
	/* no text elements yet */
	hdr->first = hdr->last = t;
    }
    else {
	/* append to the last text element */
	hdr->last->next = t;
	hdr->last = t;
    }
}


/* ---------------------------------------------------------------
**
** XML UTILITY FUNCTIONS
*/

/*
** ap_xml_quote_string: quote an XML string
**
** Replace '<', '>', and '&' with '&lt;', '&gt;', and '&amp;'.
** If quotes is true, then replace '"' with '&quot;'.
**
** quotes is typically set to true for XML strings that will occur within
** double quotes -- attribute values.
*/
API_EXPORT(const char *) ap_xml_quote_string(apr_pool_t *p, const char *s,
                                             int quotes)
{
    const char *scan;
    int len = 0;
    int extra = 0;
    char *qstr;
    char *qscan;
    char c;

    for (scan = s; (c = *scan) != '\0'; ++scan, ++len) {
	if (c == '<' || c == '>')
	    extra += 3;		/* &lt; or &gt; */
	else if (c == '&')
	    extra += 4;		/* &amp; */
	else if (quotes && c == '"')
	    extra += 5;		/* &quot; */
    }

    /* nothing to do? */
    if (extra == 0)
	return s;

    qstr = apr_palloc(p, len + extra + 1);
    for (scan = s, qscan = qstr; (c = *scan) != '\0'; ++scan) {
	if (c == '<') {
	    *qscan++ = '&';
	    *qscan++ = 'l';
	    *qscan++ = 't';
	    *qscan++ = ';';
	}
	else if (c == '>') {
	    *qscan++ = '&';
	    *qscan++ = 'g';
	    *qscan++ = 't';
	    *qscan++ = ';';
	}
	else if (c == '&') {
	    *qscan++ = '&';
	    *qscan++ = 'a';
	    *qscan++ = 'm';
	    *qscan++ = 'p';
	    *qscan++ = ';';
	}
	else if (quotes && c == '"') {
	    *qscan++ = '&';
	    *qscan++ = 'q';
	    *qscan++ = 'u';
	    *qscan++ = 'o';
	    *qscan++ = 't';
	    *qscan++ = ';';
	}
	else {
	    *qscan++ = c;
	}
    }

    *qscan = '\0';
    return qstr;
}

/* how many characters for the given integer? */
#define AP_XML_NS_LEN(ns) ((ns) < 10 ? 1 : (ns) < 100 ? 2 : (ns) < 1000 ? 3 : \
			 (ns) < 10000 ? 4 : (ns) < 100000 ? 5 : \
			 (ns) < 1000000 ? 6 : (ns) < 10000000 ? 7 : \
			 (ns) < 100000000 ? 8 : (ns) < 1000000000 ? 9 : 10)

static int text_size(const ap_text *t)
{
    int size = 0;

    for (; t; t = t->next)
	size += strlen(t->text);
    return size;
}

static size_t elem_size(const ap_xml_elem *elem, int style,
			apr_array_header_t *namespaces, int *ns_map)
{
    size_t size;

    if (style == AP_XML_X2T_FULL || style == AP_XML_X2T_FULL_NS_LANG) {
	const ap_xml_attr *attr;

	size = 0;

	if (style == AP_XML_X2T_FULL_NS_LANG) {
	    int i;

	    /*
	    ** The outer element will contain xmlns:ns%d="%s" attributes
	    ** and an xml:lang attribute, if applicable.
	    */

	    for (i = namespaces->nelts; i--;) {
		/* compute size of: ' xmlns:ns%d="%s"' */
		size += (9 + AP_XML_NS_LEN(i) + 2 +
			 strlen(AP_XML_GET_URI_ITEM(namespaces, i)) + 1);
	    }

	    if (elem->lang != NULL) {
		/* compute size of: ' xml:lang="%s"' */
		size += 11 + strlen(elem->lang) + 1;
	    }
	}

	if (elem->ns == AP_XML_NS_NONE) {
	    /* compute size of: <%s> */
	    size += 1 + strlen(elem->name) + 1;
	}
	else {
	    int ns = ns_map ? ns_map[elem->ns] : elem->ns;

	    /* compute size of: <ns%d:%s> */
	    size += 3 + AP_XML_NS_LEN(ns) + 1 + strlen(elem->name) + 1;
	}

	if (AP_XML_ELEM_IS_EMPTY(elem)) {
	    /* insert a closing "/" */
	    size += 1;
	}
	else {
	    /*
	     * two of above plus "/":
	     *     <ns%d:%s> ... </ns%d:%s>
	     * OR  <%s> ... </%s>
	     */
	    size = 2 * size + 1;
	}

	for (attr = elem->attr; attr; attr = attr->next) {
	    if (attr->ns == AP_XML_NS_NONE) {
		/* compute size of: ' %s="%s"' */
		size += 1 + strlen(attr->name) + 2 + strlen(attr->value) + 1;
	    }
	    else {
		/* compute size of: ' ns%d:%s="%s"' */
		size += 3 + AP_XML_NS_LEN(attr->ns) + 1 + strlen(attr->name) + 2 + strlen(attr->value) + 1;
	    }
	}

	/*
	** If the element has an xml:lang value that is *different* from
	** its parent, then add the thing in: ' xml:lang="%s"'.
	**
	** NOTE: we take advantage of the pointer equality established by
	** the parsing for "inheriting" the xml:lang values from parents.
	*/
	if (elem->lang != NULL &&
	    (elem->parent == NULL || elem->lang != elem->parent->lang)) {
	    size += 11 + strlen(elem->lang) + 1;
	}
    }
    else if (style == AP_XML_X2T_LANG_INNER) {
	/*
	 * This style prepends the xml:lang value plus a null terminator.
	 * If a lang value is not present, then we insert a null term.
	 */
	size = elem->lang ? strlen(elem->lang) + 1 : 1;
    }
    else
	size = 0;

    size += text_size(elem->first_cdata.first);

    for (elem = elem->first_child; elem; elem = elem->next) {
	/* the size of the child element plus the CDATA that follows it */
	size += (elem_size(elem, AP_XML_X2T_FULL, NULL, ns_map) +
		 text_size(elem->following_cdata.first));
    }

    return size;
}

static char *write_text(char *s, const ap_text *t)
{
    for (; t; t = t->next) {
	size_t len = strlen(t->text);
	memcpy(s, t->text, len);
	s += len;
    }
    return s;
}

static char *write_elem(char *s, const ap_xml_elem *elem, int style,
			apr_array_header_t *namespaces, int *ns_map)
{
    const ap_xml_elem *child;
    size_t len;
    int ns;

    if (style == AP_XML_X2T_FULL || style == AP_XML_X2T_FULL_NS_LANG) {
	int empty = AP_XML_ELEM_IS_EMPTY(elem);
	const ap_xml_attr *attr;

	if (elem->ns == AP_XML_NS_NONE) {
	    len = sprintf(s, "<%s", elem->name);
	}
	else {
	    ns = ns_map ? ns_map[elem->ns] : elem->ns;
	    len = sprintf(s, "<ns%d:%s", ns, elem->name);
	}
	s += len;

	for (attr = elem->attr; attr; attr = attr->next) {
	    if (attr->ns == AP_XML_NS_NONE)
		len = sprintf(s, " %s=\"%s\"", attr->name, attr->value);
	    else
		len = sprintf(s, " ns%d:%s=\"%s\"", attr->ns, attr->name, attr->value);
	    s += len;
	}

	/* add the xml:lang value if necessary */
	if (elem->lang != NULL &&
	    (style == AP_XML_X2T_FULL_NS_LANG ||
	     elem->parent == NULL ||
	     elem->lang != elem->parent->lang)) {
	    len = sprintf(s, " xml:lang=\"%s\"", elem->lang);
	    s += len;
	}

	/* add namespace definitions, if required */
	if (style == AP_XML_X2T_FULL_NS_LANG) {
	    int i;

	    for (i = namespaces->nelts; i--;) {
		len = sprintf(s, " xmlns:ns%d=\"%s\"", i,
			      AP_XML_GET_URI_ITEM(namespaces, i));
		s += len;
	    }
	}

	/* no more to do. close it up and go. */
	if (empty) {
	    *s++ = '/';
	    *s++ = '>';
	    return s;
	}

	/* just close it */
	*s++ = '>';
    }
    else if (style == AP_XML_X2T_LANG_INNER) {
	/* prepend the xml:lang value */
	if (elem->lang != NULL) {
	    len = strlen(elem->lang);
	    memcpy(s, elem->lang, len);
	    s += len;
	}
	*s++ = '\0';
    }

    s = write_text(s, elem->first_cdata.first);

    for (child = elem->first_child; child; child = child->next) {
	s = write_elem(s, child, AP_XML_X2T_FULL, NULL, ns_map);
	s = write_text(s, child->following_cdata.first);
    }

    if (style == AP_XML_X2T_FULL || style == AP_XML_X2T_FULL_NS_LANG) {
	if (elem->ns == AP_XML_NS_NONE) {
	    len = sprintf(s, "</%s>", elem->name);
	}
	else {
	    ns = ns_map ? ns_map[elem->ns] : elem->ns;
	    len = sprintf(s, "</ns%d:%s>", ns, elem->name);
	}
	s += len;
    }

    return s;
}

API_EXPORT(void) ap_xml_quote_elem(apr_pool_t *p, ap_xml_elem *elem)
{
    ap_text *scan_txt;
    ap_xml_attr *scan_attr;
    ap_xml_elem *scan_elem;

    /* convert the element's text */
    for (scan_txt = elem->first_cdata.first;
	 scan_txt != NULL;
	 scan_txt = scan_txt->next) {
	scan_txt->text = ap_xml_quote_string(p, scan_txt->text, 0);
    }
    for (scan_txt = elem->following_cdata.first;
	 scan_txt != NULL;
	 scan_txt = scan_txt->next) {
	scan_txt->text = ap_xml_quote_string(p, scan_txt->text, 0);
    }

    /* convert the attribute values */
    for (scan_attr = elem->attr;
	 scan_attr != NULL;
	 scan_attr = scan_attr->next) {
	scan_attr->value = ap_xml_quote_string(p, scan_attr->value, 1);
    }

    /* convert the child elements */
    for (scan_elem = elem->first_child;
	 scan_elem != NULL;
	 scan_elem = scan_elem->next) {
	ap_xml_quote_elem(p, scan_elem);
    }
}

/* convert an element to a text string */
API_EXPORT(void) ap_xml_to_text(apr_pool_t * p, const ap_xml_elem *elem,
                                int style, apr_array_header_t *namespaces,
                                int *ns_map, const char **pbuf, size_t *psize)
{
    /* get the exact size, plus a null terminator */
    size_t size = elem_size(elem, style, namespaces, ns_map) + 1;
    char *s = apr_palloc(p, size);

    (void) write_elem(s, elem, style, namespaces, ns_map);
    s[size - 1] = '\0';

    *pbuf = s;
    if (psize)
	*psize = size;
}

API_EXPORT(const char *) ap_xml_empty_elem(apr_pool_t * p,
                                           const ap_xml_elem *elem)
{
    if (elem->ns == AP_XML_NS_NONE) {
	/*
	 * The prefix (xml...) is already within the prop name, or
	 * the element simply has no prefix.
	 */
	return apr_psprintf(p, "<%s/>" DEBUG_CR, elem->name);
    }

    return apr_psprintf(p, "<ns%d:%s/>" DEBUG_CR, elem->ns, elem->name);
}

/* return the URI's (existing) index, or insert it and return a new index */
API_EXPORT(int) ap_xml_insert_uri(apr_array_header_t *uri_array,
                                  const char *uri)
{
    int i;
    const char **pelt;

    for (i = uri_array->nelts; i--;) {
	if (strcmp(uri, AP_XML_GET_URI_ITEM(uri_array, i)) == 0)
	    return i;
    }

    pelt = apr_push_array(uri_array);
    *pelt = uri;		/* assume uri is const or in a pool */
    return uri_array->nelts - 1;
}
