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

#ifndef UTIL_XML_H
#define UTIL_XML_H

#ifdef __cplusplus
extern "C" {
#endif

#include "httpd.h"
#include "apr_lib.h"


/* -------------------------------------------------------------------- */

/* ### these will need to move at some point to a more logical spot */

/* simple strutures to keep a linked list of pieces of text */
typedef struct ap_text
{
    const char *text;
    struct ap_text *next;
} ap_text;

typedef struct
{
    ap_text *first;
    ap_text *last;
} ap_text_header;

API_EXPORT(void) ap_text_append(apr_pool_t *p, ap_text_header *hdr,
                                const char *text);


/* --------------------------------------------------------------------
**
** XML PARSING
*/

/*
** Qualified namespace values
**
** AP_XML_NS_DAV_ID
**    We always insert the "DAV:" namespace URI at the head of the
**    namespace array. This means that it will always be at ID==0,
**    making it much easier to test for.
**
** AP_XML_NS_NONE
**    This special ID is used for two situations:
**
**    1) The namespace prefix begins with "xml" (and we do not know
**       what it means). Namespace prefixes with "xml" (any case) as
**       their first three characters are reserved by the XML Namespaces
**       specification for future use. mod_dav will pass these through
**       unchanged. When this identifier is used, the prefix is LEFT in
**       the element/attribute name. Downstream processing should not
**       prepend another prefix.
**
**    2) The element/attribute does not have a namespace.
**
**       a) No prefix was used, and a default namespace has not been
**          defined.
**       b) No prefix was used, and the default namespace was specified
**          to mean "no namespace". This is done with a namespace
**          declaration of:  xmlns=""
**          (this declaration is typically used to override a previous
**          specification for the default namespace)
**
**       In these cases, we need to record that the elem/attr has no
**       namespace so that we will not attempt to prepend a prefix.
**       All namespaces that are used will have a prefix assigned to
**       them -- mod_dav will never set or use the default namespace
**       when generating XML. This means that "no prefix" will always
**       mean "no namespace".
**
**    In both cases, the XML generation will avoid prepending a prefix.
**    For the first case, this means the original prefix/name will be
**    inserted into the output stream. For the latter case, it means
**    the name will have no prefix, and since we never define a default
**    namespace, this means it will have no namespace.
**
** Note: currently, mod_dav understands the "xmlns" prefix and the
**     "xml:lang" attribute. These are handled specially (they aren't
**     left within the XML tree), so the AP_XML_NS_NONE value won't ever
**     really apply to these values.
*/
#define AP_XML_NS_DAV_ID	0	/* namespace ID for "DAV:" */
#define AP_XML_NS_NONE		-10	/* no namespace for this elem/attr */

#define AP_XML_NS_ERROR_BASE	-100	/* used only during processing */
#define AP_XML_NS_IS_ERROR(e)	((e) <= AP_XML_NS_ERROR_BASE)

/*
** ap_xml_doc: holds a parsed XML document
** ap_xml_elem: holds a parsed XML element
** ap_xml_attr: holds a parsed XML attribute
*/

typedef struct ap_xml_attr
{
    const char *name;			/* attribute name */
    int ns;				/* index into namespace array */

    const char *value;			/* attribute value */

    struct ap_xml_attr *next;		/* next attribute */
} ap_xml_attr;

typedef struct ap_xml_elem
{
    const char *name;			/* element name */
    int ns;				/* index into namespace array */
    const char *lang;			/* xml:lang for attrs/contents */

    ap_text_header first_cdata;	/* cdata right after start tag */
    ap_text_header following_cdata;	/* cdata after MY end tag */

    struct ap_xml_elem *parent;	/* parent element */
    struct ap_xml_elem *next;		/* next (sibling) element */
    struct ap_xml_elem *first_child;	/* first child element */
    struct ap_xml_attr *attr;		/* first attribute */

    /* used only during parsing */
    struct ap_xml_elem *last_child;	/* last child element */
    struct ap_xml_ns_scope *ns_scope;	/* namespaces scoped by this elem */

    /* used by modules during request processing */
    void *private;
} ap_xml_elem;

#define AP_XML_ELEM_IS_EMPTY(e)	((e)->first_child == NULL && \
				 (e)->first_cdata.first == NULL)

typedef struct ap_xml_doc
{
    ap_xml_elem *root;		/* root element */
    apr_array_header_t *namespaces;	/* array of namespaces used */
} ap_xml_doc;

API_EXPORT(int) ap_xml_parse_input(request_rec *r, ap_xml_doc **pdoc);


/* Converts an XML element tree to flat text */
API_EXPORT(void) ap_xml_to_text(apr_pool_t *p, const ap_xml_elem *elem,
				int style, apr_array_header_t *namespaces,
				int *ns_map, const char **pbuf, size_t *psize);

/* style argument values: */
#define AP_XML_X2T_FULL		0	/* start tag, contents, end tag */
#define AP_XML_X2T_INNER 	1	/* contents only */
#define AP_XML_X2T_LANG_INNER	2	/* xml:lang + inner contents */
#define AP_XML_X2T_FULL_NS_LANG	3	/* FULL + ns defns + xml:lang */

API_EXPORT(const char *) ap_xml_empty_elem(apr_pool_t *p,
                                           const ap_xml_elem *elem);

API_EXPORT(const char *) ap_xml_quote_string(apr_pool_t *p, const char *s,
                                             int quotes);
API_EXPORT(void) ap_xml_quote_elem(apr_pool_t *p, ap_xml_elem *elem);

/* manage an array of unique URIs: ap_xml_insert_uri() and AP_XML_URI_ITEM() */

/* return the URI's (existing) index, or insert it and return a new index */
API_EXPORT(int) ap_xml_insert_uri(apr_array_header_t *uri_array,
                                  const char *uri);
#define AP_XML_GET_URI_ITEM(ary, i)    (((const char * const *)(ary)->elts)[i])

#endif /* UTIL_XML_H */
