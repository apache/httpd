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
**  - various utilities, repository-independent
**
** Written by Greg Stein, gstein@lyra.org, http://www.lyra.org/
*/

#include "mod_dav.h"

#include "http_request.h"
#include "http_config.h"
#include "http_vhost.h"
#include "http_log.h"
#include "http_protocol.h"


dav_error *dav_new_error(pool *p, int status, int error_id, const char *desc)
{
    int save_errno = errno;
    dav_error *err = ap_pcalloc(p, sizeof(*err));

    /* DBG3("dav_new_error: %d %d %s", status, error_id, desc ? desc : "(no desc)"); */

    err->status = status;
    err->error_id = error_id;
    err->desc = desc;
    err->save_errno = save_errno;

    return err;
}

dav_error *dav_push_error(pool *p, int status, int error_id, const char *desc,
			  dav_error *prev)
{
    dav_error *err = ap_pcalloc(p, sizeof(*err));

    err->status = status;
    err->error_id = error_id;
    err->desc = desc;
    err->prev = prev;

    return err;
}

void dav_text_append(pool * p, dav_text_header *hdr, const char *text)
{
    dav_text *t = ap_palloc(p, sizeof(*t));

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

void dav_check_bufsize(pool * p, dav_buffer *pbuf, size_t extra_needed)
{
    /* grow the buffer if necessary */
    if (pbuf->cur_len + extra_needed > pbuf->alloc_len) {
	char *newbuf;

	pbuf->alloc_len += extra_needed + DAV_BUFFER_PAD;
	newbuf = ap_palloc(p, pbuf->alloc_len);
	memcpy(newbuf, pbuf->buf, pbuf->cur_len);
	pbuf->buf = newbuf;
    }
}

void dav_set_bufsize(pool * p, dav_buffer *pbuf, size_t size)
{
    /* NOTE: this does not retain prior contents */

    /* NOTE: this function is used to init the first pointer, too, since
       the PAD will be larger than alloc_len (0) for zeroed structures */

    /* grow if we don't have enough for the requested size plus padding */
    if (size + DAV_BUFFER_PAD > pbuf->alloc_len) {
	/* set the new length; min of MINSIZE */
	pbuf->alloc_len = size + DAV_BUFFER_PAD;
	if (pbuf->alloc_len < DAV_BUFFER_MINSIZE)
	    pbuf->alloc_len = DAV_BUFFER_MINSIZE;

	pbuf->buf = ap_palloc(p, pbuf->alloc_len);
    }
    pbuf->cur_len = size;
}


/* initialize a buffer and copy the specified (null-term'd) string into it */
void dav_buffer_init(pool *p, dav_buffer *pbuf, const char *str)
{
    dav_set_bufsize(p, pbuf, strlen(str));
    memcpy(pbuf->buf, str, pbuf->cur_len + 1);
}

/* append a string to the end of the buffer, adjust length */
void dav_buffer_append(pool *p, dav_buffer *pbuf, const char *str)
{
    size_t len = strlen(str);

    dav_check_bufsize(p, pbuf, len + 1);
    memcpy(pbuf->buf + pbuf->cur_len, str, len + 1);
    pbuf->cur_len += len;
}

/* place a string on the end of the buffer, do NOT adjust length */
void dav_buffer_place(pool *p, dav_buffer *pbuf, const char *str)
{
    size_t len = strlen(str);

    dav_check_bufsize(p, pbuf, len + 1);
    memcpy(pbuf->buf + pbuf->cur_len, str, len + 1);
}

/* place some memory on the end of a buffer; do NOT adjust length */
void dav_buffer_place_mem(pool *p, dav_buffer *pbuf, const void *mem,
                          size_t amt, size_t pad)
{
    dav_check_bufsize(p, pbuf, amt + pad);
    memcpy(pbuf->buf + pbuf->cur_len, mem, amt);
}


#if APACHE_RELEASE == 10304100
/* ### this code can be used for 1.3.4 installations. use this function
 * ### instead of ap_sub_req_method_uri()
 */
/*
 * ### don't look at this code.
 * ### it is a Crime Against All That is Right and Good
 */
#include "http_core.h"		/* for SATISFY_* */
static request_rec *gross_hack(const char *new_file, const request_rec * r)
{
    request_rec *rnew = ap_sub_req_lookup_uri(new_file, r);
    int res;

    /* ### these aren't exported properly from the headers */
    extern int ap_check_access(request_rec *);	/* check access on non-auth basis */
    extern int ap_check_user_id(request_rec *);		/* obtain valid username from client auth */
    extern int ap_check_auth(request_rec *);	/* check (validated) user is authorized here */

    if (rnew->status != HTTP_OK)
	return rnew;

    /* re-run portions with a modified method */
    rnew->method = r->method;
    rnew->method_number = r->method_number;

    if ((ap_satisfies(rnew) == SATISFY_ALL
	 || ap_satisfies(rnew) == SATISFY_NOSPEC)
	? ((res = ap_check_access(rnew))
	   || (ap_some_auth_required(rnew)
	       && ((res = ap_check_user_id(rnew))
		   || (res = ap_check_auth(rnew)))))
	: ((res = ap_check_access(rnew))
	   && (!ap_some_auth_required(rnew)
	       || ((res = ap_check_user_id(rnew))
		   || (res = ap_check_auth(rnew)))))
	) {
	rnew->status = res;
    }

    return rnew;
}
#endif /* APACHE_RELEASE == 10304100 */

/*
** dav_lookup_uri()
**
** Extension for ap_sub_req_lookup_uri() which can't handle absolute
** URIs properly.
**
** If NULL is returned, then an error occurred with parsing the URI or
** the URI does not match the current server.
*/
dav_lookup_result dav_lookup_uri(const char *uri, request_rec * r)
{
    dav_lookup_result result = { 0 };
    const char *scheme;
    unsigned short port = ntohs(r->connection->local_addr.sin_port);
    uri_components comp;
    char *new_file;
    const char *domain;

    /* first thing to do is parse the URI into various components */
    if (ap_parse_uri_components(r->pool, uri, &comp) != HTTP_OK) {
	result.err.status = HTTP_BAD_REQUEST;
	result.err.desc = "Invalid syntax in Destination URI.";
	return result;
    }

    /* the URI must be an absoluteURI (WEBDAV S9.3) */
    if (comp.scheme == NULL) {
	result.err.status = HTTP_BAD_REQUEST;
	result.err.desc = "Destination URI must be an absolute URI.";
	return result;
    }

    /* ### not sure this works if the current request came in via https: */
    scheme = r->parsed_uri.scheme;
    if (scheme == NULL)
	scheme = ap_http_method(r);

    /* insert a port if the URI did not contain one */
    if (comp.port == 0)
	comp.port = ap_default_port_for_scheme(comp.scheme);

    /* now, verify that the URI uses the same scheme as the current request.
       the port, must match our port.
       the URI must not have a query (args) or a fragment
     */
    if (strcasecmp(comp.scheme, scheme) != 0 ||
	comp.port != port) {
	result.err.status = HTTP_BAD_GATEWAY;
	result.err.desc = ap_psprintf(r->pool,
				      "Destination URI refers to different "
				      "scheme or port (%s://hostname:%d)\n"
				      "(want: %s://hostname:%d)",
				      comp.scheme ? comp.scheme : scheme,
				      comp.port ? comp.port : port,
				      scheme, port);
	return result;
    }
    if (comp.query != NULL || comp.fragment != NULL) {
	result.err.status = HTTP_BAD_REQUEST;
	result.err.desc =
	    "Destination URI contains invalid components "
	    "(a query or a fragment).";
	return result;
    }

    /* we have verified the scheme, port, and general structure */

    /*
    ** Hrm.  IE5 will pass unqualified hostnames for both the 
    ** Host: and Destination: headers.  This breaks the
    ** http_vhost.c::matches_aliases function.
    **
    ** For now, qualify unqualified comp.hostnames with
    ** r->server->server_hostname.
    **
    ** ### this is a big hack. Apache should provide a better way.
    ** ### maybe the admin should list the unqualified hosts in a
    ** ### <ServerAlias> block?
    */
    if (strrchr(comp.hostname, '.') == NULL &&
	(domain = strchr(r->server->server_hostname, '.')) != NULL) {
	comp.hostname = ap_pstrcat(r->pool, comp.hostname, domain, NULL);
    }

    /* now, if a hostname was provided, then verify that it represents the
       same server as the current connection. note that we just use our
       port, since we've verified the URI matches ours */
    if (comp.hostname != NULL &&
	!ap_matches_request_vhost(r, comp.hostname, port)) {
	result.err.status = HTTP_BAD_GATEWAY;
	result.err.desc = "Destination URI refers to a different server.";
	return result;
    }

    /* we have verified that the requested URI denotes the same server as
       the current request. Therefore, we can use ap_sub_req_lookup_uri() */

    /* reconstruct a URI as just the path */
    new_file = ap_unparse_uri_components(r->pool, &comp, UNP_OMITSITEPART);

    /*
     * Lookup the URI and return the sub-request. Note that we use the
     * same HTTP method on the destination. This allows the destination
     * to apply appropriate restrictions (e.g. readonly).
     */
#if APACHE_RELEASE == 10304100
    result.rnew = gross_hack(new_file, r);
#else
    result.rnew = ap_sub_req_method_uri(r->method, new_file, r);
#endif

    return result;
}

/* ---------------------------------------------------------------
**
** XML UTILITY FUNCTIONS
*/

/* validate that the root element uses a given DAV: tagname (TRUE==valid) */
int dav_validate_root(const dav_xml_doc *doc, const char *tagname)
{
    return doc->root &&
	doc->root->ns == DAV_NS_DAV_ID &&
	strcmp(doc->root->name, tagname) == 0;
}

/* find and return the (unique) child with a given DAV: tagname */
dav_xml_elem *dav_find_child(const dav_xml_elem *elem, const char *tagname)
{
    dav_xml_elem *child = elem->first_child;

    for (; child; child = child->next)
	if (child->ns == DAV_NS_DAV_ID && !strcmp(child->name, tagname))
	    return child;
    return NULL;
}


/* how many characters for the given integer? */
#define DAV_NS_LEN(ns)	((ns) < 10 ? 1 : (ns) < 100 ? 2 : (ns) < 1000 ? 3 : \
			 (ns) < 10000 ? 4 : (ns) < 100000 ? 5 : \
			 (ns) < 1000000 ? 6 : (ns) < 10000000 ? 7 : \
			 (ns) < 100000000 ? 8 : (ns) < 1000000000 ? 9 : 10)

static int dav_text_size(const dav_text *t)
{
    int size = 0;

    for (; t; t = t->next)
	size += strlen(t->text);
    return size;
}

static size_t dav_elem_size(const dav_xml_elem *elem, int style,
                            array_header *namespaces, int *ns_map)
{
    size_t size;

    if (style == DAV_X2T_FULL || style == DAV_X2T_FULL_NS_LANG) {
	const dav_xml_attr *attr;

	size = 0;

	if (style == DAV_X2T_FULL_NS_LANG) {
	    int i;

	    /*
	    ** The outer element will contain xmlns:ns%d="%s" attributes
	    ** and an xml:lang attribute, if applicable.
	    */

	    for (i = namespaces->nelts; i--;) {
		/* compute size of: ' xmlns:ns%d="%s"' */
		size += (9 + DAV_NS_LEN(i) + 2 +
			 strlen(DAV_GET_URI_ITEM(namespaces, i)) + 1);
	    }

	    if (elem->lang != NULL) {
		/* compute size of: ' xml:lang="%s"' */
		size += 11 + strlen(elem->lang) + 1;
	    }
	}

	if (elem->ns == DAV_NS_NONE) {
	    /* compute size of: <%s> */
	    size += 1 + strlen(elem->name) + 1;
	}
	else {
	    int ns = ns_map ? ns_map[elem->ns] : elem->ns;

	    /* compute size of: <ns%d:%s> */
	    size += 3 + DAV_NS_LEN(ns) + 1 + strlen(elem->name) + 1;
	}

	if (DAV_ELEM_IS_EMPTY(elem)) {
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
	    if (attr->ns == DAV_NS_NONE) {
		/* compute size of: ' %s="%s"' */
		size += 1 + strlen(attr->name) + 2 + strlen(attr->value) + 1;
	    }
	    else {
		/* compute size of: ' ns%d:%s="%s"' */
		size += 3 + DAV_NS_LEN(attr->ns) + 1 + strlen(attr->name) + 2 + strlen(attr->value) + 1;
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
    else if (style == DAV_X2T_LANG_INNER) {
	/*
	 * This style prepends the xml:lang value plus a null terminator.
	 * If a lang value is not present, then we insert a null term.
	 */
	size = elem->lang ? strlen(elem->lang) + 1 : 1;
    }
    else
	size = 0;

    size += dav_text_size(elem->first_cdata.first);

    for (elem = elem->first_child; elem; elem = elem->next) {
	/* the size of the child element plus the CDATA that follows it */
	size += (dav_elem_size(elem, DAV_X2T_FULL, NULL, ns_map) +
		 dav_text_size(elem->following_cdata.first));
    }

    return size;
}

static char *dav_write_text(char *s, const dav_text *t)
{
    for (; t; t = t->next) {
	size_t len = strlen(t->text);
	memcpy(s, t->text, len);
	s += len;
    }
    return s;
}

static char *dav_write_elem(char *s, const dav_xml_elem *elem, int style,
			    array_header *namespaces, int *ns_map)
{
    const dav_xml_elem *child;
    size_t len;
    int ns;

    if (style == DAV_X2T_FULL || style == DAV_X2T_FULL_NS_LANG) {
	int empty = DAV_ELEM_IS_EMPTY(elem);
	const dav_xml_attr *attr;

	if (elem->ns == DAV_NS_NONE) {
	    len = sprintf(s, "<%s", elem->name);
	}
	else {
	    ns = ns_map ? ns_map[elem->ns] : elem->ns;
	    len = sprintf(s, "<ns%d:%s", ns, elem->name);
	}
	s += len;

	for (attr = elem->attr; attr; attr = attr->next) {
	    if (attr->ns == DAV_NS_NONE)
		len = sprintf(s, " %s=\"%s\"", attr->name, attr->value);
	    else
		len = sprintf(s, " ns%d:%s=\"%s\"", attr->ns, attr->name, attr->value);
	    s += len;
	}

	/* add the xml:lang value if necessary */
	if (elem->lang != NULL &&
	    (style == DAV_X2T_FULL_NS_LANG ||
	     elem->parent == NULL ||
	     elem->lang != elem->parent->lang)) {
	    len = sprintf(s, " xml:lang=\"%s\"", elem->lang);
	    s += len;
	}

	/* add namespace definitions, if required */
	if (style == DAV_X2T_FULL_NS_LANG) {
	    int i;

	    for (i = namespaces->nelts; i--;) {
		len = sprintf(s, " xmlns:ns%d=\"%s\"", i,
			      DAV_GET_URI_ITEM(namespaces, i));
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
    else if (style == DAV_X2T_LANG_INNER) {
	/* prepend the xml:lang value */
	if (elem->lang != NULL) {
	    len = strlen(elem->lang);
	    memcpy(s, elem->lang, len);
	    s += len;
	}
	*s++ = '\0';
    }

    s = dav_write_text(s, elem->first_cdata.first);

    for (child = elem->first_child; child; child = child->next) {
	s = dav_write_elem(s, child, DAV_X2T_FULL, NULL, ns_map);
	s = dav_write_text(s, child->following_cdata.first);
    }

    if (style == DAV_X2T_FULL || style == DAV_X2T_FULL_NS_LANG) {
	if (elem->ns == DAV_NS_NONE) {
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

/* convert an element to a text string */
void dav_xml2text(pool * p,
		  const dav_xml_elem *elem,
		  int style,
		  array_header *namespaces,
		  int *ns_map,
		  const char **pbuf,
		  size_t *psize)
{
    /* get the exact size, plus a null terminator */
    size_t size = dav_elem_size(elem, style, namespaces, ns_map) + 1;
    char *s = ap_palloc(p, size);

    (void) dav_write_elem(s, elem, style, namespaces, ns_map);
    s[size - 1] = '\0';

    *pbuf = s;
    if (psize)
	*psize = size;
}

const char *dav_empty_elem(pool * p, const dav_xml_elem *elem)
{
    if (elem->ns == DAV_NS_NONE) {
	/*
	 * The prefix (xml...) is already within the prop name, or
	 * the element simply has no prefix.
	 */
	return ap_psprintf(p, "<%s/>" DEBUG_CR, elem->name);
    }

    return ap_psprintf(p, "<ns%d:%s/>" DEBUG_CR, elem->ns, elem->name);
}

/*
** dav_quote_string: quote an XML string
**
** Replace '<', '>', and '&' with '&lt;', '&gt;', and '&amp;'.
** If quotes is true, then replace '"' with '&quot;'.
**
** quotes is typically set to true for XML strings that will occur within
** double quotes -- attribute values.
*/
const char * dav_quote_string(pool *p, const char *s, int quotes)
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

    qstr = ap_palloc(p, len + extra + 1);
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

void dav_quote_xml_elem(pool *p, dav_xml_elem *elem)
{
    dav_text *scan_txt;
    dav_xml_attr *scan_attr;
    dav_xml_elem *scan_elem;

    /* convert the element's text */
    for (scan_txt = elem->first_cdata.first;
	 scan_txt != NULL;
	 scan_txt = scan_txt->next) {
	scan_txt->text = dav_quote_string(p, scan_txt->text, 0);
    }
    for (scan_txt = elem->following_cdata.first;
	 scan_txt != NULL;
	 scan_txt = scan_txt->next) {
	scan_txt->text = dav_quote_string(p, scan_txt->text, 0);
    }

    /* convert the attribute values */
    for (scan_attr = elem->attr;
	 scan_attr != NULL;
	 scan_attr = scan_attr->next) {
	scan_attr->value = dav_quote_string(p, scan_attr->value, 1);
    }

    /* convert the child elements */
    for (scan_elem = elem->first_child;
	 scan_elem != NULL;
	 scan_elem = scan_elem->next) {
	dav_quote_xml_elem(p, scan_elem);
    }
}

/* ---------------------------------------------------------------
**
** Timeout header processing
**
*/

/* dav_get_timeout:  If the Timeout: header exists, return a time_t
 *    when this lock is expected to expire.  Otherwise, return
 *    a time_t of DAV_TIMEOUT_INFINITE.
 *
 *    It's unclear if DAV clients are required to understand
 *    Seconds-xxx and Infinity time values.  We assume that they do.
 *    In addition, for now, that's all we understand, too.
 */
time_t dav_get_timeout(request_rec *r)
{
    time_t now, expires = DAV_TIMEOUT_INFINITE;

    const char *timeout_const = ap_table_get(r->headers_in, "Timeout");
    const char *timeout = ap_pstrdup(r->pool, timeout_const), *val;

    if (timeout == NULL)
	return DAV_TIMEOUT_INFINITE;

    /* Use the first thing we understand, or infinity if
     * we don't understand anything.
     */

    while ((val = ap_getword_white(r->pool, &timeout)) && strlen(val)) {
	if (!strncmp(val, "Infinite", 8)) {
	    return DAV_TIMEOUT_INFINITE;
	}

	if (!strncmp(val, "Second-", 7)) {
	    val += 7;
	    /* ### We need to handle overflow better:
	     * ### timeout will be <= 2^32 - 1
	     */
	    expires = atol(val);
	    now     = time(NULL);
	    return now + expires;
	}
    }

    return DAV_TIMEOUT_INFINITE;
}

/* ---------------------------------------------------------------
**
** If Header processing
**
*/

/* add_if_resource returns a new if_header, linking it to next_ih.
 */
static dav_if_header *dav_add_if_resource(pool *p, dav_if_header *next_ih,
					  const char *uri, size_t uri_len)
{
    dav_if_header *ih;

    if ((ih = ap_pcalloc(p, sizeof(*ih))) == NULL)
	return NULL;

    ih->uri = uri;
    ih->uri_len = uri_len;
    ih->next = next_ih;

    return ih;
}

/* add_if_state adds a condition to an if_header.
 */
static dav_error * dav_add_if_state(pool *p, dav_if_header *ih,
				    const char *state_token,
				    dav_if_state_type t, int condition,
				    const dav_hooks_locks *locks_hooks)
{
    dav_if_state_list *new_sl;

    new_sl = ap_pcalloc(p, sizeof(*new_sl));

    new_sl->condition = condition;
    new_sl->type      = t;
    
    if (t == dav_if_opaquelock) {
	dav_error *err;

	if ((err = (*locks_hooks->parse_locktoken)(p, state_token,
						   &new_sl->locktoken)) != NULL) {
	    /* ### maybe add a higher-level description */
	    return err;
	}
    }
    else
	new_sl->etag = state_token;

    new_sl->next = ih->state;
    ih->state = new_sl;

    return NULL;
}

/* fetch_next_token returns the substring from str+1
 * to the next occurence of char term, or \0, whichever
 * occurs first.  Leading whitespace is ignored.
 */
static char *dav_fetch_next_token(char **str, char term)
{
    char *sp;
    char *token;
	
    token = *str + 1;

    while (*token && (*token == ' ' || *token == '\t'))
	token++;

    if ((sp = strchr(token, term)) == NULL)
	return NULL;

    *sp = '\0';
    *str = sp;
    return token;
}

/* dav_process_if_header:
 *
 *   If NULL (no error) is returned, then **if_header points to the
 *   "If" productions structure (or NULL if "If" is not present).
 *
 *   ### this part is bogus:
 *   If an error is encountered, the error is logged.  Parent should
 *   return err->status.
 */
static dav_error * dav_process_if_header(request_rec *r, dav_if_header **p_ih)
{
    dav_error *err;
    char *str;
    char *list;
    const char *state_token;
    const char *uri = NULL;	/* scope of current production; NULL=no-tag */
    size_t uri_len;
    dav_if_header *ih = NULL;
    uri_components parsed_uri;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    enum {no_tagged, tagged, unknown} list_type = unknown;
    int condition;
	
    *p_ih = NULL;

    if ((str = ap_pstrdup(r->pool, ap_table_get(r->headers_in, "If"))) == NULL)
	return NULL;

    while (*str) {
	switch(*str) {
	case '<':
	    /* Tagged-list production - following states apply to this uri */
	    if (list_type == no_tagged
		|| ((uri = dav_fetch_next_token(&str, '>')) == NULL)) {
		return dav_new_error(r->pool, HTTP_BAD_REQUEST,
				     DAV_ERR_IF_TAGGED,
				     "Invalid If-header: unclosed \"<\" or "
				     "unexpected tagged-list production.");
	    }
            
            /* 2518 specifies this must be an absolute URI; just take the
             * relative part for later comparison against r->uri */
            if (ap_parse_uri_components(r->pool, uri, &parsed_uri) != HTTP_OK) {
                return dav_new_error(r->pool, HTTP_BAD_REQUEST,
                                     DAV_ERR_IF_TAGGED,
                                     "Invalid URI in tagged If-header.");
            }
	    /* note that parsed_uri.path is allocated; we can trash it */

	    /* clean up the URI a bit */
	    ap_getparents(parsed_uri.path);
	    uri_len = strlen(parsed_uri.path);
	    if (uri_len > 1 && parsed_uri.path[uri_len - 1] == '/')
		parsed_uri.path[--uri_len] = '\0';

	    uri = parsed_uri.path;
	    list_type = tagged;
	    break;

	case '(':
	    /* List production */

	    /* If a uri has not been encountered, this is a No-Tagged-List */
	    if (list_type == unknown)
		list_type = no_tagged;

	    if ((list = dav_fetch_next_token(&str, ')')) == NULL) {
		return dav_new_error(r->pool, HTTP_BAD_REQUEST,
				     DAV_ERR_IF_UNCLOSED_PAREN,
				     "Invalid If-header: unclosed \"(\".");
	    }

	    if ((ih = dav_add_if_resource(r->pool, ih, uri, uri_len)) == NULL) {
		/* ### dav_add_if_resource() should return an error for us! */
		return dav_new_error(r->pool, HTTP_BAD_REQUEST,
				     DAV_ERR_IF_PARSE,
				     "Internal server error parsing \"If:\" "
				     "header.");
	    }

	    condition = DAV_IF_COND_NORMAL;

	    while (*list) {
		/* List is the entire production (in a uri scope) */

		switch (*list) {
		case '<':
		    if ((state_token = dav_fetch_next_token(&list, '>')) == NULL) {
			/* ### add a description to this error */
			return dav_new_error(r->pool, HTTP_BAD_REQUEST,
					     DAV_ERR_IF_PARSE, NULL);
		    }

		    if ((err = dav_add_if_state(r->pool, ih, state_token, dav_if_opaquelock,
						condition, locks_hooks)) != NULL) {
			/* ### maybe add a higher level description */
			return err;
		    }
		    condition = DAV_IF_COND_NORMAL;
		    break;

		case '[':
		    if ((state_token = dav_fetch_next_token(&list, ']')) == NULL) {
			/* ### add a description to this error */
			return dav_new_error(r->pool, HTTP_BAD_REQUEST,
					     DAV_ERR_IF_PARSE, NULL);
		    }

		    if ((err = dav_add_if_state(r->pool, ih, state_token, dav_if_etag,
						condition, locks_hooks)) != NULL) {
			/* ### maybe add a higher level description */
			return err;
		    }
		    condition = DAV_IF_COND_NORMAL;
		    break;

		case 'N':
		    if (list[1] == 'o' && list[2] == 't') {
			if (condition != DAV_IF_COND_NORMAL) {
			    return dav_new_error(r->pool, HTTP_BAD_REQUEST,
						 DAV_ERR_IF_MULTIPLE_NOT,
						 "Invalid \"If:\" header: "
						 "Multiple \"not\" entries "
						 "for the same state.");
			}
			condition = DAV_IF_COND_NOT;
		    }
		    list += 2;
		    break;

		case ' ':
		case '\t':
		    break;

		default:
		    return dav_new_error(r->pool, HTTP_BAD_REQUEST,
					 DAV_ERR_IF_UNK_CHAR,
                                         ap_psprintf(r->pool,
                                                     "Invalid \"If:\" "
                                                     "header: Unexpected "
                                                     "character encountered "
                                                     "(0x%02x, '%c').",
                                                     *list, *list));
		}

		list++;
	    }
	    break;

	case ' ':
	case '\t':
	    break;

	default:
	    return dav_new_error(r->pool, HTTP_BAD_REQUEST,
				 DAV_ERR_IF_UNK_CHAR,
                                 ap_psprintf(r->pool,
                                             "Invalid \"If:\" header: "
                                             "Unexpected character "
                                             "encountered (0x%02x, '%c').",
                                             *str, *str));
	}

	str++;
    }

    *p_ih = ih;
    return NULL;
}

static int dav_find_submitted_locktoken(const dav_if_header *if_header,
					const dav_lock *lock_list,
					const dav_hooks_locks *locks_hooks)
{
    for (; if_header != NULL; if_header = if_header->next) {
	const dav_if_state_list *state_list;

	for (state_list = if_header->state;
	     state_list != NULL;
	     state_list = state_list->next) {

	    if (state_list->type == dav_if_opaquelock) {
		const dav_lock *lock;

		/* given state_list->locktoken, match it */

		/*
		** The resource will have one or more lock tokens. We only
		** need to match one of them against any token in the
		** If: header.
		**
		** One token case: It is an exclusive or shared lock. Either
		**                 way, we must find it.
		**
		** N token case: They are shared locks. By policy, we need
		**               to match only one. The resource's other
		**               tokens may belong to somebody else (so we
		**               shouldn't see them in the If: header anyway)
		*/
		for (lock = lock_list; lock != NULL; lock = lock->next) {

		    if (!(*locks_hooks->compare_locktoken)(state_list->locktoken, lock->locktoken)) {
			return 1;
		    }
		}
	    }
	}
    }

    return 0;
}

/* dav_validate_resource_state:
 *    Returns NULL if path/uri meets if-header and lock requirements
 */
static dav_error * dav_validate_resource_state(pool *p,
					       const dav_resource *resource,
					       dav_lockdb *lockdb,
					       const dav_if_header *if_header,
                                               int flags,
					       dav_buffer *pbuf,
                                               request_rec *r)
{
    dav_error *err;
    const char *uri;
    const char *etag;
    const dav_hooks_locks *locks_hooks = (lockdb ? lockdb->hooks : NULL);
    const dav_if_header *ifhdr_scan;
    dav_if_state_list *state_list;
    dav_lock *lock_list;
    dav_lock *lock;
    int num_matched;
    int num_that_apply;
    int seen_locktoken;
    size_t uri_len;
    const char *reason = NULL;

    /* DBG1("validate: <%s>", resource->uri); */

    /*
    ** The resource will have one of three states:
    **
    ** 1) No locks. We have no special requirements that the user supply
    **    specific locktokens. One of the state lists must match, and
    **    we're done.
    **
    ** 2) One exclusive lock. The locktoken must appear *anywhere* in the
    **    If: header. Of course, asserting the token in a "Not" term will
    **    quickly fail that state list :-). If the locktoken appears in
    **    one of the state lists *and* one state list matches, then we're
    **    done.
    **
    ** 3) One or more shared locks. One of the locktokens must appear
    **    *anywhere* in the If: header. If one of the locktokens appears,
    **    and we match one state list, then we are done.
    **
    ** The <seen_locktoken> variable determines whether we have seen one
    ** of this resource's locktokens in the If: header.
    */

    /*
    ** If this is a new lock request, <flags> will contain the requested
    ** lock scope.  Three rules apply:
    **
    ** 1) Do not require a (shared) locktoken to be seen (when we are
    **    applying another shared lock)
    ** 2) If the scope is exclusive and we see any locks, fail.
    ** 3) If the scope is shared and we see an exclusive lock, fail.
    */

    if (lockdb == NULL) {
	/* we're in State 1. no locks. */
	lock_list = NULL;
    }
    else {
	/*
	** ### hrm... we don't need to have these fully
	** ### resolved since we're only looking at the
	** ### locktokens...
	**
	** ### use get_locks w/ calltype=PARTIAL
	*/
	if ((err = dav_lock_query(lockdb, resource, &lock_list)) != NULL) {
	    return dav_push_error(p,
				  HTTP_INTERNAL_SERVER_ERROR, 0,
				  "The locks could not be queried for "
				  "verification against a possible \"If:\" "
				  "header.",
				  err);
	}

	/* lock_list now determines whether we're in State 1, 2, or 3. */
    }

    /* 
    ** For a new, exclusive lock: if any locks exist, fail.
    ** For a new, shared lock:    if an exclusive lock exists, fail.
    **                            else, do not require a token to be seen.
    */
    if (flags & DAV_LOCKSCOPE_EXCLUSIVE) {
	if (lock_list != NULL) {
	    return dav_new_error(p, HTTP_LOCKED, 0, 
				 "Existing lock(s) on the requested resource "
				 "prevent an exclusive lock.");
	}

	/*
	** There are no locks, so we can pretend that we've already met
	** any requirement to find the resource's locks in an If: header.
	*/
	seen_locktoken = 1;
    }
    else if (flags & DAV_LOCKSCOPE_SHARED) {
	/*
	** Strictly speaking, we don't need this loop. Either the first
	** (and only) lock will be EXCLUSIVE, or none of them will be.
	*/
        for (lock = lock_list; lock != NULL; lock = lock->next) {
            if (lock->scope == DAV_LOCKSCOPE_EXCLUSIVE) {
		return dav_new_error(p, HTTP_LOCKED, 0,
				     "The requested resource is already "
				     "locked exclusively.");
            }
        }

	/*
	** The locks on the resource (if any) are all shared. Set the
	** <seen_locktoken> flag to indicate that we do not need to find
	** the locks in an If: header.
	*/
        seen_locktoken = 1;
    }
    else {
	/*
	** For methods other than LOCK:
	**
	** If we have no locks, then <seen_locktoken> can be set to true --
	** pretending that we've already met the requirement of seeing one
	** of the resource's locks in the If: header.
	**
	** Otherwise, it must be cleared and we'll look for one.
	*/
        seen_locktoken = (lock_list == NULL);
    }

    /*
    ** If there is no If: header, then we can shortcut some logic:
    **
    ** 1) if we do not need to find a locktoken in the (non-existent) If:
    **    header, then we are successful.
    **
    ** 2) if we must find a locktoken in the (non-existent) If: header, then
    **    we fail.
    */
    if (if_header == NULL) {
	if (seen_locktoken)
	    return NULL;

	return dav_new_error(p, HTTP_LOCKED, 0,
			     "This resource is locked and an \"If:\" header "
			     "was not supplied to allow access to the "
			     "resource.");
    }
    /* the If: header is present */

    /*
    ** If a dummy header is present (because of a Lock-Token: header), then
    ** we are required to find that token in this resource's set of locks.
    ** If we have no locks, then we immediately fail.
    **
    ** This is a 400 (Bad Request) since they should only submit a locktoken
    ** that actually exists.
    **
    ** Don't issue this response if we're talking about the parent resource.
    ** It is okay for that resource to NOT have this locktoken.
    ** (in fact, it certainly will not: a dummy_header only occurs for the
    **  UNLOCK method, the parent is checked only for locknull resources,
    **  and the parent certainly does not have the (locknull's) locktoken)
    */
    if (lock_list == NULL && if_header->dummy_header) {
        if (flags & DAV_VALIDATE_IS_PARENT)
            return NULL;
	return dav_new_error(p, HTTP_BAD_REQUEST, 0,
			     "The locktoken specified in the \"Lock-Token:\" "
			     "header is invalid because this resource has no "
			     "outstanding locks.");
    }

    /*
    ** Prepare the input URI. We want the URI to never have a trailing slash.
    **
    ** When URIs are placed into the dav_if_header structure, they are
    ** guaranteed to never have a trailing slash. If the URIs are equivalent,
    ** then it doesn't matter if they both lack a trailing slash -- they're
    ** still equivalent.
    **
    ** Note: we could also ensure that a trailing slash is present on both
    ** URIs, but the majority of URIs provided to us via a resource walk
    ** will not contain that trailing slash.
    */
    uri = resource->uri;
    uri_len = strlen(uri);
    if (uri[uri_len - 1] == '/') {
	dav_set_bufsize(p, pbuf, uri_len);
	memcpy(pbuf->buf, uri, uri_len);
	pbuf->buf[--uri_len] = '\0';
	uri = pbuf->buf;
    }

    /* get the resource's etag; we may need it during the checks */
    etag = (*resource->hooks->getetag)(resource);

    /* how many state_lists apply to this URI? */
    num_that_apply = 0;

    /* If there are if-headers, fail if this resource
     * does not match at least one state_list.
     */
    for (ifhdr_scan = if_header;
	 ifhdr_scan != NULL;
	 ifhdr_scan = ifhdr_scan->next) {

	/* DBG2("uri=<%s>  if_uri=<%s>", uri, ifhdr_scan->uri ? ifhdr_scan->uri : "(no uri)"); */

	if (ifhdr_scan->uri != NULL
	    && (uri_len != ifhdr_scan->uri_len
		|| memcmp(uri, ifhdr_scan->uri, uri_len) != 0)) {
	    /*
	    ** A tagged-list's URI doesn't match this resource's URI.
	    ** Skip to the next state_list to see if it will match.
	    */
	    continue;
	}

	/* this state_list applies to this resource */

	/*
	** ### only one state_list should ever apply! a no-tag, or a tagged
	** ### where S9.4.2 states only one can match.
	**
	** ### revamp this code to loop thru ifhdr_scan until we find the
	** ### matching state_list. process it. stop.
	*/
	++num_that_apply;

	/* To succeed, resource must match *all* of the states
	 * specified in the state_list.
	 */
	for (state_list = ifhdr_scan->state;
	     state_list != NULL;
	     state_list = state_list->next) {

	    switch(state_list->type) {
	    case dav_if_etag:
	    {
		int mismatch = strcmp(state_list->etag, etag);

		if (state_list->condition == DAV_IF_COND_NORMAL && mismatch) {
		    /*
		    ** The specified entity-tag does not match the
		    ** entity-tag on the resource. This state_list is
		    ** not going to match. Bust outta here.
		    */
		    reason =
			"an entity-tag was specified, but the resource's "
			"actual ETag does not match.";
		    goto state_list_failed;
		}
		else if (state_list->condition == DAV_IF_COND_NOT
			 && !mismatch) {
		    /*
		    ** The specified entity-tag DOES match the
		    ** entity-tag on the resource. This state_list is
		    ** not going to match. Bust outta here.
		    */
		    reason =
			"an entity-tag was specified using the \"Not\" form, "
			"but the resource's actual ETag matches the provided "
			"entity-tag.";
		    goto state_list_failed;
		}
		break;
	    }

	    case dav_if_opaquelock:
		if (lockdb == NULL) {
		    if (state_list->condition == DAV_IF_COND_NOT) {
			/* the locktoken is definitely not there! (success) */
			continue;
		    }

		    /* condition == DAV_IF_COND_NORMAL */

		    /*
		    ** If no lockdb is provided, then validation fails for
		    ** this state_list (NORMAL means we were supposed to
		    ** find the token, which we obviously cannot do without
		    ** a lock database).
		    **
		    ** Go and try the next state list.
		    */
		    reason =
			"a State-token was supplied, but a lock database "
			"is not available for to provide the required lock.";
		    goto state_list_failed;
		}

		/* Resource validation 'fails' if:
		 *    ANY  of the lock->locktokens match
		 *         a NOT state_list->locktoken,
		 * OR
		 *    NONE of the lock->locktokens match
		 *         a NORMAL state_list->locktoken.
		 */
		num_matched = 0;
		for (lock = lock_list; lock != NULL; lock = lock->next) {

		    /*
		    DBG2("compare: rsrc=%s  ifhdr=%s",
			 (*locks_hooks->format_locktoken)(p, lock->locktoken),
			 (*locks_hooks->format_locktoken)(p, state_list->locktoken));
		    */

		    /* nothing to do if the locktokens do not match. */
		    if ((*locks_hooks->compare_locktoken)(state_list->locktoken, lock->locktoken)) {
			continue;
		    }

		    /*
		    ** We have now matched up one of the resource's locktokens
		    ** to a locktoken in a State-token in the If: header.
		    ** Note this fact, so that we can pass the overall
		    ** requirement of seeing at least one of the resource's
		    ** locktokens.
		    */
		    seen_locktoken = 1;

		    if (state_list->condition == DAV_IF_COND_NOT) {
			/*
			** This state requires that the specified locktoken
			** is NOT present on the resource. But we just found
			** it. There is no way this state-list can now
			** succeed, so go try another one.
			*/
			reason =
			    "a State-token was supplied, which used a "
			    "\"Not\" condition. The State-token was found "
			    "in the locks on this resource";
			goto state_list_failed;
		    }

		    /* condition == DAV_IF_COND_NORMAL */

                    /* Validate auth_user:  If an authenticated user created
                    ** the lock, only the same user may submit that locktoken
                    ** to manipulate a resource.
                    */
                    if (lock->auth_user && 
                        (!r->connection->user ||
                         strcmp(lock->auth_user, r->connection->user))) {
                        const char *errmsg;

                        errmsg = ap_pstrcat(p, "User \"",
                                            r->connection->user, 
                                            "\" submitted a locktoken created "
                                            "by user \"",
                                            lock->auth_user, "\".", NULL);
                        return dav_new_error(p, HTTP_UNAUTHORIZED, 0, errmsg);
                    }

		    /*
		    ** We just matched a specified State-Token to one of the
		    ** resource's locktokens.
		    **
		    ** Break out of the lock scan -- we only needed to find
		    ** one match (actually, there shouldn't be any other
		    ** matches in the lock list).
		    */
		    num_matched = 1;
		    break;
		}

		if (num_matched == 0
		    && state_list->condition == DAV_IF_COND_NORMAL) {
		    /*
		    ** We had a NORMAL state, meaning that we should have
		    ** found the State-Token within the locks on this
		    ** resource. We didn't, so this state_list must fail.
		    */
		    reason =
			"a State-token was supplied, but it was not found "
			"in the locks on this resource.";
		    goto state_list_failed;
		}

		break;

	    } /* switch */
	} /* foreach ( state_list ) */

	/*
	** We've checked every state in this state_list and none of them
	** have failed. Since all of them succeeded, then we have a matching
	** state list and we may be done.
	**
	** The next requirement is that we have seen one of the resource's
	** locktokens (if any). If we have, then we can just exit. If we
	** haven't, then we need to keep looking.
	*/
	if (seen_locktoken) {
	    /* woo hoo! */
	    return NULL;
	}

	/*
	** Haven't seen one. Let's break out of the search and just look
	** for a matching locktoken.
	*/
	break;

	/*
	** This label is used when we detect that a state_list is not
	** going to match this resource. We bust out and try the next
	** state_list.
	*/
      state_list_failed:
	;

    } /* foreach ( ifhdr_scan ) */

    /*
    ** The above loop exits for one of two reasons:
    **   1) a state_list matched and seen_locktoken is false.
    **   2) all if_header structures were scanned, without (1) occurring
    */

    if (ifhdr_scan == NULL) {
	/*
	** We finished the loop without finding any matching state lists.
	*/

	/*
	** If none of the state_lists apply to this resource, then we
	** may have succeeded. Note that this scenario implies a
	** tagged-list with no matching state_lists. If the If: header
	** was a no-tag-list, then it would have applied to this resource.
	**
	** S9.4.2 states that when no state_lists apply, then the header
	** should be ignored.
	**
	** If we saw one of the resource's locktokens, then we're done.
	** If we did not see a locktoken, then we fail.
	*/
	if (num_that_apply == 0) {
	    if (seen_locktoken)
		return NULL;

	    /*
	    ** We may have aborted the scan before seeing the locktoken.
	    ** Rescan the If: header to see if we can find the locktoken
	    ** somewhere.
	    */
	    if (dav_find_submitted_locktoken(if_header, lock_list,
					     locks_hooks)) {
		/*
		** We found a match! We're set... none of the If: header
		** assertions apply (implicit success), and the If: header
		** specified the locktoken somewhere. We're done.
		*/
		return NULL;
	    }

	    return dav_new_error(p, HTTP_LOCKED, 0 /* error_id */,
				 "This resource is locked and the \"If:\" "
				 "header did not specify one of the "
				 "locktokens for this resource's lock(s).");
	}
	/* else: one or more state_lists were applicable, but failed. */

	/*
	** If the dummy_header did not match, then they specified an
	** incorrect token in the Lock-Token header. Forget whether the
	** If: statement matched or not... we'll tell them about the
	** bad Lock-Token first. That is considered a 400 (Bad Request).
	*/
	if (if_header->dummy_header) {
	    return dav_new_error(p, HTTP_BAD_REQUEST, 0,
				 "The locktoken specified in the "
				 "\"Lock-Token:\" header did not specify one "
				 "of this resource's locktoken(s).");
	}

	if (reason == NULL) {
	    return dav_new_error(p, HTTP_PRECONDITION_FAILED, 0,
				 "The preconditions specified by the \"If:\" "
				 "header did not match this resource.");
	}

	return dav_new_error(p, HTTP_PRECONDITION_FAILED, 0,
			     ap_psprintf(p,
					 "The precondition(s) specified by "
					 "the \"If:\" header did not match "
					 "this resource. At least one "
					 "failure is because: %s", reason));
    }

    /* assert seen_locktoken == 0 */

    /*
    ** ifhdr_scan != NULL implies we found a matching state_list.
    **
    ** Since we're still here, it also means that we have not yet found
    ** one the resource's locktokens in the If: header.
    **
    ** Scan all the if_headers and states looking for one of this
    ** resource's locktokens. Note that we need to go back and scan them
    ** all -- we may have aborted a scan with a failure before we saw a
    ** matching token.
    **
    ** Note that seen_locktoken == 0 implies lock_list != NULL which implies
    ** locks_hooks != NULL.
    */
    if (dav_find_submitted_locktoken(if_header, lock_list, locks_hooks)) {
	/*
	** We found a match! We're set... we have a matching state list,
	** and the If: header specified the locktoken somewhere. We're done.
	*/
	return NULL;
    }

    /*
    ** We had a matching state list, but the user agent did not specify one
    ** of this resource's locktokens. Tell them so.
    **
    ** Note that we need to special-case the message on whether a "dummy"
    ** header exists. If it exists, yet we didn't see a needed locktoken,
    ** then that implies the dummy header (Lock-Token header) did NOT
    ** specify one of this resource's locktokens. (this implies something
    ** in the real If: header matched)
    **
    ** We want to note the 400 (Bad Request) in favor of a 423 (Locked).
    */
    if (if_header->dummy_header) {
	return dav_new_error(p, HTTP_BAD_REQUEST, 0,
			     "The locktoken specified in the "
			     "\"Lock-Token:\" header did not specify one "
			     "of this resource's locktoken(s).");
    }

    return dav_new_error(p, HTTP_LOCKED, 1 /* error_id */,
			 "This resource is locked and the \"If:\" header "
			 "did not specify one of the "
			 "locktokens for this resource's lock(s).");
}

/* dav_validate_walker:  Walker callback function to validate resource state */
static dav_error * dav_validate_walker(dav_walker_ctx *ctx, int calltype)
{
    dav_error *err;

    if ((err = dav_validate_resource_state(ctx->pool, ctx->resource,
					   ctx->lockdb,
					   ctx->if_header, ctx->flags,
					   &ctx->work_buf, ctx->r)) == NULL) {
	/* There was no error, so just bug out. */
	return NULL;
    }

    /*
    ** If we have a serious server error, or if the request itself failed,
    ** then just return error (not a multistatus).
    */
    if (ap_is_HTTP_SERVER_ERROR(err->status)
        || (*ctx->resource->hooks->is_same_resource)(ctx->resource,
                                                     ctx->root)) {
	/* ### maybe push a higher-level description? */
	return err;
    }

    /* associate the error with the current URI */
    dav_add_response(ctx, ctx->uri.buf, err->status, NULL);

    return NULL;
}

/*
** dav_validate_request:  Validate if-headers (and check for locks) on:
**    (1) r->filename @ depth;
**    (2) Parent of r->filename if check_parent == 1
**
** The check of parent should be done when it is necessary to verify that
** the parent collection will accept a new member (ie current resource
** state is null).
**
** Return OK on successful validation.
** On error, return appropriate HTTP_* code, and log error. If a multi-stat
** error is necessary, response will point to it, else NULL.
*/
dav_error * dav_validate_request(request_rec *r, dav_resource *resource,
				 int depth, dav_locktoken *locktoken,
				 dav_response **response, int flags,
                                 dav_lockdb *lockdb)
{
    dav_error *err;
    int result;
    dav_if_header *if_header;
    int lock_db_opened_locally = 0;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    const dav_hooks_repository *repos_hooks = resource->hooks;
    dav_buffer work_buf = { 0 };
    dav_response *new_response;

#if DAV_DEBUG
    if (depth && response == NULL) {
	/*
	** ### bleck. we can't return errors for other URIs unless we have
        ** ### a "response" ptr.
	*/
	return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "DESIGN ERROR: dav_validate_request called "
                             "with depth>0, but no response ptr.");
    }
#endif

    if (response != NULL)
	*response = NULL;

    /* Do the standard checks for conditional requests using 
     * If-..-Since, If-Match etc */
    if ((result = ap_meets_conditions(r)) != OK) {
	/* ### fix this up... how? */
	return dav_new_error(r->pool, result, 0, NULL);
    }

    /* always parse (and later process) the If: header */
    if ((err = dav_process_if_header(r, &if_header)) != NULL) {
	/* ### maybe add higher-level description */
	return err;
    }

    /* If a locktoken was specified, create a dummy if_header with which
     * to validate resources.  In the interim, figure out why DAV uses
     * locktokens in an if-header without a Lock-Token header to refresh
     * locks, but a Lock-Token header without an if-header to remove them.
     */
    if (locktoken != NULL) {
	dav_if_header *ifhdr_new;

	ifhdr_new = ap_pcalloc(r->pool, sizeof(*ifhdr_new));
	ifhdr_new->uri = resource->uri;
	ifhdr_new->uri_len = strlen(resource->uri);
	ifhdr_new->dummy_header = 1;

	ifhdr_new->state = ap_pcalloc(r->pool, sizeof(*ifhdr_new->state));
	ifhdr_new->state->type = dav_if_opaquelock;
	ifhdr_new->state->condition = DAV_IF_COND_NORMAL;
	ifhdr_new->state->locktoken = locktoken;

	ifhdr_new->next = if_header;
	if_header = ifhdr_new;
    }

    /*
    ** If necessary, open the lock database (read-only, lazily);
    ** the validation process may need to retrieve or update lock info.
    ** Otherwise, assume provided lockdb is valid and opened rw.
    */
    if (lockdb == NULL) {
        if (locks_hooks != NULL) {
            if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
	        /* ### maybe insert higher-level comment */
	        return err;
            }
            lock_db_opened_locally = 1;
        }
        else {
            return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
				 "Resource validation failed because no "
				 "lock hooks were found.");
        }
    }

    /* (1) Validate the specified resource, at the specified depth */
    if (resource->exists && depth > 0) {
	dav_walker_ctx ctx = { 0 };

	ctx.walk_type = DAV_WALKTYPE_ALL;
	ctx.postfix = 0;
	ctx.func = dav_validate_walker;
	ctx.pool = r->pool;
	ctx.if_header = if_header;
	ctx.r = r;
        ctx.flags = flags;
        ctx.resource = resource;

	if (lockdb != NULL) {
	    ctx.lockdb = lockdb;
	    ctx.walk_type |= DAV_WALKTYPE_LOCKNULL;
	}

	dav_buffer_init(r->pool, &ctx.uri, resource->uri);

	err = (*repos_hooks->walk)(&ctx, DAV_INFINITY);
	if (err == NULL) {
            *response = ctx.response;
	}
        /* else: implies a 5xx status code occurred. */
    }
    else {
	err = dav_validate_resource_state(r->pool, resource, lockdb,
					  if_header, flags, &work_buf, r);
    }

    /* (2) Validate the parent resource if requested */
    if (err == NULL && (flags & DAV_VALIDATE_PARENT)) {
        dav_resource *parent_resource = (*repos_hooks->get_parent_resource)(resource);

	if (parent_resource == NULL) {
	    err = dav_new_error(r->pool, HTTP_FORBIDDEN, 0,
				"Cannot access parent of repository root.");
	}
	else {
	    err = dav_validate_resource_state(r->pool, parent_resource, lockdb,
					      if_header,
                                              flags | DAV_VALIDATE_IS_PARENT,
                                              &work_buf, r);
	    
	    /*
	    ** This error occurred on the parent resource. This implies that
	    ** we have to create a multistatus response (to report the error
	    ** against a URI other than the Request-URI). "Convert" this error
	    ** into a multistatus response.
	    */
	    if (err != NULL) {
		new_response = ap_pcalloc(r->pool, sizeof(*new_response));
		
		new_response->href = parent_resource->uri;
		new_response->status = err->status;
		new_response->desc =
		    "A validation error has occurred on the parent resource, "
		    "preventing the operation on the resource specified by "
		    "the Request-URI.";
                if (err->desc != NULL) {
                    new_response->desc = ap_pstrcat(r->pool,
                                                    new_response->desc,
                                                    " The error was: ",
                                                    err->desc, NULL);
                }
		
		/* assert: DAV_VALIDATE_PARENT implies response != NULL */
		new_response->next = *response;
		*response = new_response;
		
		err = NULL;
	    }
	}
    }

    if (lock_db_opened_locally)
        (*locks_hooks->close_lockdb)(lockdb);

    /*
    ** If we don't have a (serious) error, and we have multistatus responses,
    ** then we need to construct an "error". This error will be the overall
    ** status returned, and the multistatus responses will go into its body.
    **
    ** For certain methods, the overall error will be a 424. The default is
    ** to construct a standard 207 response.
    */
    if (err == NULL && response != NULL && *response != NULL) {
        dav_text *propstat = NULL;

        if ((flags & DAV_VALIDATE_USE_424) != 0) {
            /* manufacture a 424 error to hold the multistatus response(s) */
            return dav_new_error(r->pool, HTTP_FAILED_DEPENDENCY, 0,
                                 "An error occurred on another resource, "
                                 "preventing the requested operation on "
                                 "this resource.");
        }

        /*
        ** Whatever caused the error, the Request-URI should have a 424
        ** associated with it since we cannot complete the method.
        **
        ** For a LOCK operation, insert an empty DAV:lockdiscovery property.
        ** For other methods, return a simple 424.
        */
        if ((flags & DAV_VALIDATE_ADD_LD) != 0) {
            propstat = ap_pcalloc(r->pool, sizeof(*propstat));
            propstat->text =
                "<D:propstat>" DEBUG_CR
                "<D:prop><D:lockdiscovery/></D:prop>" DEBUG_CR
                "<D:status>HTTP/1.1 424 Failed Dependency</D:status>" DEBUG_CR
                "</D:propstat>" DEBUG_CR;
        }

        /* create the 424 response */
        new_response = ap_pcalloc(r->pool, sizeof(*new_response));
        new_response->href = resource->uri;
        new_response->status = HTTP_FAILED_DEPENDENCY;
        new_response->propresult.propstats = propstat;
        new_response->desc =
            "An error occurred on another resource, preventing the "
            "requested operation on this resource.";

        new_response->next = *response;
        *response = new_response;

        /* manufacture a 207 error for the multistatus response(s) */
        return dav_new_error(r->pool, HTTP_MULTI_STATUS, 0,
                             "Error(s) occurred on resources during the "
                             "validation process.");
    }

    return err;
}

/* dav_get_locktoken_list:
 *
 * Sets ltl to a locktoken_list of all positive locktokens in header,
 * else NULL if no If-header, or no positive locktokens.
 */
dav_error * dav_get_locktoken_list(request_rec *r, dav_locktoken_list **ltl) 
{
    dav_error *err;
    dav_if_header *if_header;
    dav_if_state_list *if_state;
    dav_locktoken_list *lock_token = NULL;		
	
    *ltl = NULL;

    if ((err = dav_process_if_header(r, &if_header)) != NULL) {
	/* ### add a higher-level description? */
	return err;
    }
 			
    while (if_header != NULL) {
	if_state = if_header->state;	/* Begining of the if_state linked list */
	while (if_state != NULL)	{
	    if (if_state->condition == DAV_IF_COND_NORMAL
	        && if_state->type == dav_if_opaquelock) {
		lock_token = ap_pcalloc(r->pool, sizeof(dav_locktoken_list));
		lock_token->locktoken = if_state->locktoken;
		lock_token->next = *ltl;
		*ltl = lock_token;
	    }
	    if_state = if_state->next; 
	}
	if_header = if_header->next;
    }
    if (*ltl == NULL) {
	/* No nodes added */
	return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_ABSENT,
			     "No locktokens were specified in the \"If:\" "
			     "header, so the refresh could not be performed.");
    }

    return NULL;
}

/* dav_get_target_selector:
 *
 * Returns any Target-Selector header in a request
 * (used by versioning clients)
 */
const char *dav_get_target_selector(request_rec *r)
{
    return ap_table_get(r->headers_in, "Target-Selector");
}

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
					  int *parent_was_writable)
{
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_resource *parent = NULL;
    const char *body;
    int auto_version;
    dav_error *err;

    if (parent_resource != NULL)
        *parent_resource = NULL;

    if (!parent_only) {
        *resource_existed = resource->exists;
        *resource_was_writable = 0;
    }

    if (parent_was_writable != NULL)
        *parent_was_writable = 0;

    /* if a Target-Selector header is present, then the client knows about
     * versioning, so it should not be relying on implicit versioning
     */
    auto_version = (dav_get_target_selector(r) == NULL);

    /* check parent resource if requested or if resource must be created */
    if (!resource->exists || parent_only) {
	parent = (*resource->hooks->get_parent_resource)(resource);
        if (parent == NULL || !parent->exists) {
	    body = ap_psprintf(r->pool,
			       "Missing one or more intermediate collections. "
			       "Cannot create resource %s.",
			       ap_escape_html(r->pool, resource->uri));
	    return dav_new_error(r->pool, HTTP_CONFLICT, 0, body);
        }

        if (parent_resource != NULL)
	    *parent_resource = parent;

	/* if parent not versioned, assume child can be created */
	if (!parent->versioned) {
            if (!parent_only)
	        *resource_was_writable = 1;

            if (parent_was_writable != NULL)
	        *parent_was_writable = 1;
	    return NULL;
	}

	/* if no versioning provider, something is terribly wrong */
	if (vsn_hooks == NULL) {
	    return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
				 "INTERNAL ERROR: "
                                 "versioned resource with no versioning "
				 "provider?");
	}

        /* remember whether parent was already writable */
        if (parent_was_writable != NULL)
	    *parent_was_writable = parent->working;

	/* parent must be checked out */
	if (!parent->working) {
	    if ((err = (*vsn_hooks->checkout)(parent)) != NULL) {
		body = ap_psprintf(r->pool,
				   "Unable to checkout parent collection. "
				   "Cannot create resource %s.",
				   ap_escape_html(r->pool, resource->uri));
		return dav_push_error(r->pool, HTTP_CONFLICT, 0, body, err);
	    }
	}

	/* if not just checking parent, create new child resource */
        if (!parent_only) {
	    if ((err = (*vsn_hooks->mkresource)(resource)) != NULL) {
	        body = ap_psprintf(r->pool,
			           "Unable to create versioned resource %s.",
			           ap_escape_html(r->pool, resource->uri));
	        return dav_push_error(r->pool, HTTP_CONFLICT, 0, body, err);
	    }
        }
    }
    else {
	/* resource exists: if not versioned, then assume it is writable */
	if (!resource->versioned) {
	    *resource_was_writable = 1;
	    return NULL;
	}

	*resource_was_writable = resource->working;
    }

    /* if not just checking parent, make sure child resource is checked out */
    if (!parent_only && !resource->working) {
	if ((err = (*vsn_hooks->checkout)(resource)) != NULL) {
	    body = ap_psprintf(r->pool,
			       "Unable to checkout resource %s.",
			       ap_escape_html(r->pool, resource->uri));
	    return dav_push_error(r->pool, HTTP_CONFLICT, 0, body, err);
	}
    }

    return NULL;
}

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
					   int parent_was_writable)
{
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    const char *body;
    dav_error *err;

    if (resource != NULL) {
        if (!resource_was_writable
	    && resource->versioned && resource->working) {

            if (undo)
                err = (*vsn_hooks->uncheckout)(resource);
            else
                err = (*vsn_hooks->checkin)(resource);

            if (err != NULL) {
	        body = ap_psprintf(r->pool,
			           "Unable to %s resource %s.",
                                   undo ? "uncheckout" : "checkin",
			           ap_escape_html(r->pool, resource->uri));
                return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
				      body, err);
            }
        }

        if (undo && !resource_existed && resource->exists) {
	    dav_response *response;

	    /* ### should we do anything with the response? */
            if ((err = (*resource->hooks->remove_resource)(resource,
							   &response)) != NULL) {
	        body = ap_psprintf(r->pool,
			           "Unable to undo creation of resource %s.",
			           ap_escape_html(r->pool, resource->uri));
                return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
				      body, err);
            }
        }
    }

    if (parent_resource != NULL && !parent_was_writable
	&& parent_resource->versioned && parent_resource->working) {

	if (undo)
	    err = (*vsn_hooks->uncheckout)(parent_resource);
	else
	    err = (*vsn_hooks->checkin)(parent_resource);

	if (err != NULL) {
	    body = ap_psprintf(r->pool,
			       "Unable to %s parent collection of %s.",
			       undo ? "uncheckout" : "checkin",
			       ap_escape_html(r->pool, resource->uri));
	    return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
				  body, err);
	}
    }

    return NULL;
}

/* return the URI's (existing) index, or insert it and return a new index */
int dav_insert_uri(array_header *uri_array, const char *uri)
{
    int i;
    const char **pelt;

    for (i = uri_array->nelts; i--;) {
	if (strcmp(uri, DAV_GET_URI_ITEM(uri_array, i)) == 0)
	    return i;
    }

    pelt = ap_push_array(uri_array);
    *pelt = uri;		/* assume uri is const or in a pool */
    return uri_array->nelts - 1;
}
