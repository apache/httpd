#define HTTPD_TEST_REQUIRE_APACHE 2

#if CONFIG_FOR_HTTPD_TEST

<Location /test_apr_uri>
   SetHandler test-apr-uri
</Location>

#endif

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
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/*
 * This module is intended to test the apr_uri routines by parsing a
 * bunch of urls and comparing the results with what we expect to
 * see.
 *
 * Usage:
 *
 * <Location /test-apr-uri>
 * SetHandler test-apr-uri
 * </Location>
 *
 * Then make a request to /test-apr-uri.  An html apr_table_t of errors will
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

#define T_scheme        0x01
#define T_user          0x02
#define T_password      0x04
#define T_hostname      0x08
#define T_port_str      0x10
#define T_path          0x20
#define T_query         0x40
#define T_fragment      0x80
#define T_MAX           0x100

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
     * character that indicates its presence, and so we test empty paths all
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
    apr_pool_t *sub;
    char *input_uri;
    char *strp;
    apr_uri_t result;
    unsigned expect;
    int status;
    unsigned failures;

    failures = 0;

    input_uri = apr_palloc(r->pool,
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

        apr_pool_create_ex(&sub, r->pool, NULL, NULL);
        status = apr_uri_parse(sub, input_uri, &result);
        if (status == APR_SUCCESS) {
#define CHECK(f)                                                        \
            if ((expect & T_##f)                                        \
                && (result.f == NULL || strcmp(result.f, pieces->f))) { \
                status = HTTP_INTERNAL_SERVER_ERROR;                    \
            }                                                           \
            else if (!(expect & T_##f) && result.f != NULL) {           \
                status = HTTP_INTERNAL_SERVER_ERROR;                    \
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
        if (status != APR_SUCCESS) {
            ap_rprintf(r, "<tr><td>%d</td><td>0x%02x</td><td>0x%02x</td><td>%d</td><td>\"%s\"</td>", row, u, expect, status, input_uri);
#define DUMP(f)                                                         \
            if (result.f) {                                             \
                ap_rvputs(r, "<td>\"", result.f, "\"<br>", NULL);               \
            }                                                           \
            else {                                                      \
                ap_rputs("<td>NULL<br>", r);                            \
            }                                                           \
            if (expect & T_##f) {                                       \
                ap_rvputs(r, "\"", pieces->f, "\"</td>", NULL);         \
            }                                                           \
            else {                                                      \
                ap_rputs("NULL</td>", r);                                       \
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
        apr_pool_destroy(sub);
    }
    return failures;
}

static int test_apr_uri_handler(request_rec *r)
{
    unsigned total_failures;
    int i;

    r->allowed |= (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET)
        return DECLINED;

    if (strcmp(r->handler, "test-apr-uri")) {
        return DECLINED;
    }

    r->content_type = "text/html";              

    ap_rputs(
DOCTYPE_HTML_2_0 "\n\
<html><body>\n\
<p>Key:\n\
<dl>\n\
<dt>row\n\
<dd>entry number in the uri_tests array\n\
<dt>u\n\
<dd>fields under test\n\
<dt>expected\n\
<dd>fields expected in the result\n\
<dt>status\n\
<dd>response from parse_uri_components, or 500 if unexpected results\n\
<dt>input uri\n\
<dd>the uri given to parse_uri_components\n\
</dl>\n\
<p>The remaining fields are the pieces returned from parse_uri_components, and\n\
the values we expected for each piece (resp.).\n\
<p>Only failures are displayed.\n\
<p>\n\
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

static void test_apr_uri_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(test_apr_uri_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA test_apr_uri_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    test_apr_uri_register_hooks  /* register hooks                      */
};
