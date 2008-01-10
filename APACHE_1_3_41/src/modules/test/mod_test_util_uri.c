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
 * This module is intended to test the util_uri routines by parsing a
 * bunch of urls and comparing the results with what we expect to
 * see.
 *
 * Usage:
 *
 * <Location /test-util-uri>
 * SetHandler test-util-uri
 * </Location>
 *
 * Then make a request to /test-util-uri.  An html table of errors will
 * be output... and a total count of errors.
 */

#include "httpd.h"
#include "http_protocol.h"
#include "http_config.h"
#include "http_main.h"

typedef struct {
    const char *scheme;
    const char *user;
    const char *password;
    const char *hostname;
    const char *port_str;
    const char *path;
    const char *query;
    const char *fragment;
} test_uri_t;

#define T_scheme	0x01
#define T_user		0x02
#define T_password	0x04
#define T_hostname	0x08
#define T_port_str	0x10
#define T_path		0x20
#define T_query		0x40
#define T_fragment	0x80
#define T_MAX		0x100

/* The idea is that we list here a bunch of url pieces that we want
 * stitched together in every way that's valid.
 */
static const test_uri_t uri_tests[] = {
    { "http", "userid", "passwd", "hostname.goes.here", "80", "/path/goes/here", "query-here", "frag-here" },
    { "http", "", "passwd", "hostname.goes.here", "80", "/path/goes/here", "query-here", "frag-here" },
    { "http", "userid", "", "hostname.goes.here", "80", "/path/goes/here", "query-here", "frag-here" },
    { "http", "userid", "passwd", "", "80", "/path/goes/here", "query-here", "frag-here" },
    { "http", "userid", "passwd", "hostname.goes.here", "", "/path/goes/here", "query-here", "frag-here" },
#if 0
    /* An empty path means two different things depending on whether this is a
     * relative or an absolute uri... consider <a href="#frag"> versus "GET
     * http://hostname HTTP/1.1".  So this is why parse_uri_components returns
     * a NULL for path when it doesn't find one, instead of returning an empty
     * string.
     *
     * We don't really need to test it explicitly since path has no explicit
     * character that indicates its precense, and so we test empty paths all
     * the time by varying T_path in the loop.  It would just cost us extra
     * code to special case the empty path string...
     */
    { "http", "userid", "passwd", "hostname.goes.here", "80", "", "query-here", "frag-here" },
#endif
    { "http", "userid", "passwd", "hostname.goes.here", "80", "/path/goes/here", "", "frag-here" },
    { "http", "userid", "passwd", "hostname.goes.here", "80", "/path/goes/here", "query-here", "" },
    { "https", "user@d", "pa:swd", "hostname.goes.here.", "", "/~path/goes/here", "query&query?crud", "frag-here?baby" }

};

static char *my_stpcpy(char *d, const char *s)
{
    while((*d = *s)) {
	++d;
	++s;
    }
    return d;
}

/* return the number of failures */
static unsigned iterate_pieces(request_rec *r, const test_uri_t *pieces, int row)
{
    unsigned u;
    pool *sub;
    char *input_uri;
    char *strp;
    uri_components result;
    unsigned expect;
    int status;
    unsigned failures;

    failures = 0;

    input_uri = ap_palloc(r->pool,
	strlen(pieces->scheme) + 3
	+ strlen(pieces->user) + 1
	+ strlen(pieces->password) + 1
	+ strlen(pieces->hostname) + 1
	+ strlen(pieces->port_str) + 1
	+ strlen(pieces->path) +
	+ strlen(pieces->query) + 1
	+ strlen(pieces->fragment) + 1
	+ 1);

    for (u = 0; u < T_MAX; ++u) {
	strp = input_uri;
	expect = 0;

	/* a scheme requires a hostinfo and vice versa */
	/* a hostinfo requires a hostname */
	if (u & (T_scheme|T_user|T_password|T_hostname|T_port_str)) {
	    expect |= T_scheme;
	    strp = my_stpcpy(strp, pieces->scheme);
	    *strp++ = ':';
	    *strp++ = '/';
	    *strp++ = '/';
	    /* can't have password without user */
	    if (u & (T_user|T_password)) {
		expect |= T_user;
		strp = my_stpcpy(strp, pieces->user);
		if (u & T_password) {
		    expect |= T_password;
		    *strp++ = ':';
		    strp = my_stpcpy(strp, pieces->password);
		}
		*strp++ = '@';
	    }
	    expect |= T_hostname;
	    strp = my_stpcpy(strp, pieces->hostname);
	    if (u & T_port_str) {
		expect |= T_port_str;
		*strp++ = ':';
		strp = my_stpcpy(strp, pieces->port_str);
	    }
	}
	if (u & T_path) {
	    expect |= T_path;
	    strp = my_stpcpy(strp, pieces->path);
	}
	if (u & T_query) {
	    expect |= T_query;
	    *strp++ = '?';
	    strp = my_stpcpy(strp, pieces->query);
	}
	if (u & T_fragment) {
	    expect |= T_fragment;
	    *strp++ = '#';
	    strp = my_stpcpy(strp, pieces->fragment);
	}
	*strp = 0;

	sub = ap_make_sub_pool(r->pool);
	status = ap_parse_uri_components(sub, input_uri, &result);
	if (status == HTTP_OK) {
#define CHECK(f)							\
	    if ((expect & T_##f)					\
		&& (result.f == NULL || strcmp(result.f, pieces->f))) { \
		status = HTTP_INTERNAL_SERVER_ERROR;			\
	    }								\
	    else if (!(expect & T_##f) && result.f != NULL) {		\
		status = HTTP_INTERNAL_SERVER_ERROR;			\
	    }
	    CHECK(scheme)
	    CHECK(user)
	    CHECK(password)
	    CHECK(hostname)
	    CHECK(port_str)
	    CHECK(path)
	    CHECK(query)
	    CHECK(fragment)
#undef CHECK
	}
	if (status != HTTP_OK) {
	    ap_rprintf(r, "<tr><td>%d</td><td>0x%02x</td><td>0x%02x</td><td>%d</td><td>\"%s\"</td>", row, u, expect, status, input_uri);
#define DUMP(f) 							\
	    if (result.f) {						\
		ap_rvputs(r, "<td>\"", result.f, "\"<br>", NULL);		\
	    }								\
	    else {							\
		ap_rputs("<td>NULL<br>", r);				\
	    }								\
	    if (expect & T_##f) {					\
		ap_rvputs(r, "\"", pieces->f, "\"</td>", NULL);		\
	    }								\
	    else {							\
		ap_rputs("NULL</td>", r);					\
	    }
	    DUMP(scheme);
	    DUMP(user);
	    DUMP(password);
	    DUMP(hostname);
	    DUMP(port_str);
	    DUMP(path);
	    DUMP(query);
	    DUMP(fragment);
#undef DUMP
	    ap_rputs("</tr>\n", r);
	    ++failures;
	}
	ap_destroy_pool(sub);
    }
    return failures;
}

static int test_util_uri(request_rec *r)
{
    unsigned total_failures;
    int i;

    r->allowed |= (1 << M_GET);
    if (r->method_number != M_GET)
	return DECLINED;

    r->content_type = "text/html";		
    ap_send_http_header(r);
#ifdef CHARSET_EBCDIC
    /* Server-generated response, converted */
    ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, r->ebcdic.conv_out = 1);
#endif
    if(r->header_only) {
	return 0;
    }
    ap_hard_timeout("test_util_uri", r);

    ap_rputs(
DOCTYPE_HTML_2_0 "
<html><body>
<p>Key:
<dl>
<dt>row
<dd>entry number in the uri_tests array
<dt>u
<dd>fields under test
<dt>expected
<dd>fields expected in the result
<dt>status
<dd>response from parse_uri_components, or 500 if unexpected results
<dt>input uri
<dd>the uri given to parse_uri_components
</dl>
<p>The remaining fields are the pieces returned from parse_uri_components, and
the values we expected for each piece (resp.).
<p>Only failures are displayed.
<p>
<table><tr><th>row</th><th>u</th><th>expect</th><th>status</th><th>input uri</th>", r);
#define HEADER(f) ap_rprintf(r, "<th>" #f "<br>0x%02x</th>", T_##f)
    HEADER(scheme);
    HEADER(user);
    HEADER(password);
    HEADER(hostname);
    HEADER(port_str);
    HEADER(path);
    HEADER(query);
    HEADER(fragment);
#undef HEADER

    if (r->args) {
	i = atoi(r->args);
	total_failures = iterate_pieces(r, &uri_tests[i], i);
    }
    else {
	total_failures = 0;
	for (i = 0; i < sizeof(uri_tests) / sizeof(uri_tests[0]); ++i) {
	    total_failures += iterate_pieces(r, &uri_tests[i], i);
	    if (total_failures > 256) {
		ap_rprintf(r, "</table>\n<b>Stopped early to save your browser "
			   "from certain death!</b>\nTOTAL FAILURES = %u\n",
			   total_failures);
		return OK;
	    }
	}
    }
    ap_rprintf(r, "</table>\nTOTAL FAILURES = %u\n", total_failures);

    return OK;
}

static const handler_rec test_util_uri_handlers[] =
{
    {"test-util-uri", test_util_uri},
    {NULL}
};

module test_util_uri_module = {
    STANDARD_MODULE_STUFF,
    NULL,                       /* initializer */
    NULL,			/* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    NULL,			/* command table */
    test_util_uri_handlers,	/* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    NULL,                       /* logger */
    NULL                        /* header parser */
};
