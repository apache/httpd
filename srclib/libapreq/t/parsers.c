/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

#include "apreq_parser.h"
#include "apreq_util.h"
#include "apreq_error.h"
#include "apr_strings.h"
#include "apr_xml.h"
#include "at.h"

#define CRLF "\015\012"

static apr_pool_t *p;

static char url_data[] = "alpha=one&beta=two;omega=last%2";

static char form_data[] =
"--AaB03x" CRLF                                           /* 10 chars
 012345678901234567890123456789012345678901234567890123456789 */
"content-disposition: form-data; name=\"field1\"" CRLF    /* 47 chars */
"content-type: text/plain;charset=windows-1250" CRLF
"content-transfer-encoding: quoted-printable" CRLF CRLF
"Joe owes =80100." CRLF
"--AaB03x" CRLF
"content-disposition: form-data; name=\"pics\"; filename=\"file1.txt\"" CRLF
"Content-Type: text/plain" CRLF CRLF
"... contents of file1.txt ..." CRLF CRLF
"--AaB03x" CRLF
"content-disposition: form-data; name=\"\"" CRLF
"content-type: text/plain;" CRLF " charset=windows-1250" CRLF
"content-transfer-encoding: quoted-printable" CRLF CRLF
"Joe owes =80100." CRLF
"--AaB03x--" CRLF;

static char xml_data[] =
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"
"<methodCall>"
"  <methodName>foo.bar</methodName>"
"  <params>"
"    <param><value><int>1</int></value></param>"
"  </params>"
"</methodCall>";

static char rel_data[] = /*offsets: 122, 522, */
"--f93dcbA3" CRLF
"Content-Type: application/xml; charset=UTF-8" CRLF
"Content-Length: 400" CRLF
"Content-ID: <980119.X53GGT@example.com>" CRLF CRLF /*122*/
"<?xml version=\"1.0\"?>" CRLF
"<uploadDocument>"
"  <title>My Proposal</title>"
"  <author>E. X. Ample</author>"
"  <summary>A proposal for a new project.</summary>"
"  <notes image=\"cid:980119.X17AXM@example.com\">(see handwritten region)</notes>"
"  <keywords>project proposal funding</keywords>"
"  <readonly>false</readonly>"
"  <filename>image.png</filename>"
"  <content>cid:980119.X25MNC@example.com</content>"
"</uploadDocument>" /*400*/ CRLF
"--f93dcbA3" CRLF /*14*/
"Content-Type: image/png" CRLF
"Content-Transfer-Encoding: binary" CRLF
"Content-ID: <980119.X25MNC@example.com>" CRLF CRLF /*103*/
"...Binary data here..."  /*22*/ CRLF
"--f93dcbA3" CRLF /*14*/
"Content-Type: image/png" CRLF
"Content-Transfer-Encoding: binary" CRLF
"Content-ID: <980119.X17AXM@example.com>" CRLF CRLF
"...Binary data here..." CRLF
"--f93dcbA3--" CRLF;

static char mix_data[] =
"--AaB03x" CRLF
"Content-Disposition: form-data; name=\"submit-name\"" CRLF CRLF
"Larry" CRLF
"--AaB03x" CRLF
"Content-Disposition: form-data; name=\"files\"" CRLF
"Content-Type: multipart/mixed; boundary=BbC04y" CRLF CRLF
"--BbC04y" CRLF
"Content-Disposition: file; filename=\"file1.txt\"" CRLF
"Content-Type: text/plain" CRLF CRLF
"... contents of file1.txt ..." CRLF
"--BbC04y" CRLF
"Content-Disposition: file; filename=\"file2.gif\"" CRLF
"Content-Type: image/gif" CRLF
"Content-Transfer-Encoding: binary" CRLF CRLF
"...contents of file2.gif..." CRLF
"--BbC04y--" CRLF
"--AaB03x  " CRLF
"content-disposition: form-data; name=\"field1\"" CRLF
"content-type: text/plain;charset=windows-1250" CRLF
"content-transfer-encoding: quoted-printable" CRLF CRLF
"Joe owes =80100." CRLF
"--AaB03x--"; /* omit CRLF, which is ok per rfc 2046 */


#define URL_ENCTYPE "application/x-www-form-urlencoded"
#define MFD_ENCTYPE "multipart/form-data"
#define MR_ENCTYPE "multipart/related"
#define XML_ENCTYPE "application/xml"

static void locate_default_parsers(dAT, void *ctx)
{

#ifdef __ELF__
    apreq_parser_function_t f;

    AT_trace_on();

    f = apreq_parser(URL_ENCTYPE);
    AT_EQ(f, (apreq_parser_function_t)apreq_parse_urlencoded, "%pp");

    f = apreq_parser(MFD_ENCTYPE);
    AT_EQ(f, (apreq_parser_function_t)apreq_parse_multipart, "%pp");

    f = apreq_parser(MR_ENCTYPE);
    AT_EQ(f, (apreq_parser_function_t)apreq_parse_multipart, "%pp");

    AT_trace_off();
#else
    AT_skip(3, "skipping ELF-dependent tests");
#endif

}

static void parse_urlencoded(dAT, void *ctx)
{
    apr_status_t rv;
    apr_bucket_alloc_t *ba;
    apr_bucket_brigade *bb;
    apreq_parser_t *parser;
    apr_table_t *body;

    body = apr_table_make(p, APREQ_DEFAULT_NELTS);
    ba = apr_bucket_alloc_create(p);
    bb = apr_brigade_create(p, ba);
    parser = apreq_parser_make(p, ba, URL_ENCTYPE, apreq_parse_urlencoded,
                               100, NULL, NULL, NULL);

    APR_BRIGADE_INSERT_HEAD(bb,
        apr_bucket_immortal_create(url_data,strlen(url_data),
                                   bb->bucket_alloc));

    rv = apreq_parser_run(parser, body, bb);
    AT_int_eq(rv, APR_INCOMPLETE);

    APR_BRIGADE_INSERT_HEAD(bb,
        apr_bucket_immortal_create("blast",5,
                                   bb->bucket_alloc));
    APR_BRIGADE_INSERT_TAIL(bb,
           apr_bucket_eos_create(bb->bucket_alloc));

    rv = apreq_parser_run(parser, body, bb);
    AT_int_eq(rv, APR_SUCCESS);

    AT_str_eq(apr_table_get(body,"alpha"), "one");
    AT_str_eq(apr_table_get(body,"beta"), "two");
    AT_str_eq(apr_table_get(body,"omega"),"last+last");

}

static void parse_multipart(dAT, void *ctx)
{
    apr_size_t i, j;
    apr_bucket_alloc_t *ba;


    for (j = 0; j <= strlen(form_data); ++j) {

        ba = apr_bucket_alloc_create(p);

        /* AT_localize checks the inner loop tests itself
         * (and interprets any such failures as being fatal),
         * because doing IO to Test::Harness is just too slow
         * when this many (~1M) tests are involved.
         */

        AT_localize();

        for (i = 0; i <= strlen(form_data); ++i) {
            const char *val;
            char *val2;
            apr_size_t len;
            apr_table_t *t, *body;
            apreq_parser_t *parser;
            apr_bucket_brigade *bb, *vb, *tail;
            apr_status_t rv;
            apr_bucket *e, *f;

            bb = apr_brigade_create(p, ba);
            body = apr_table_make(p, APREQ_DEFAULT_NELTS);
            parser = apreq_parser_make(p, ba, MFD_ENCTYPE
                                       "; charset=\"iso-8859-1\""
                                       "; boundary=\"AaB03x\"",
                                       apreq_parse_multipart,
                                       1000, NULL, NULL, NULL);

            e = apr_bucket_immortal_create(form_data,
                                           strlen(form_data),
                                           bb->bucket_alloc);
            APR_BRIGADE_INSERT_HEAD(bb, e);
            APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(bb->bucket_alloc));

            /* Split e into three buckets */
            apr_bucket_split(e, j);
            f = APR_BUCKET_NEXT(e);
            if (i < j)
                apr_bucket_split(e, i);
            else
                apr_bucket_split(f, i - j);

            tail = apr_brigade_split(bb, f);
            rv = apreq_parser_run(parser, body, bb);
            AT_int_eq(rv, (j < strlen(form_data)) ? APR_INCOMPLETE : APR_SUCCESS);
            rv = apreq_parser_run(parser, body, tail);
            AT_int_eq(rv, APR_SUCCESS);
            AT_int_eq(apr_table_elts(body)->nelts, 3);

            val = apr_table_get(body,"field1");
            AT_str_eq(val, "Joe owes =80100.");
            t = apreq_value_to_param(val)->info;
            val = apr_table_get(t, "content-transfer-encoding");
            AT_str_eq(val, "quoted-printable");

            val = apr_table_get(body, "pics");
            AT_str_eq(val, "file1.txt");
            t = apreq_value_to_param(val)->info;
            vb = apreq_value_to_param(val)->upload;
            apr_brigade_pflatten(vb, &val2, &len, p);
            AT_int_eq(len, strlen("... contents of file1.txt ..." CRLF));
            AT_mem_eq(val2 ,"... contents of file1.txt ..." CRLF, len);
            val = apr_table_get(t, "content-type");
            AT_str_eq(val, "text/plain");

            val = apr_table_get(body, "");
            AT_str_eq(val, "Joe owes =80100.");
            t = apreq_value_to_param(val)->info;
            val = apr_table_get(t, "content-type");
            AT_int_eq(apreq_header_attribute(val, "charset", 7, &val, &len),
                      APR_SUCCESS);
            AT_str_eq(val, "windows-1250");

            apr_brigade_cleanup(vb);
            apr_brigade_cleanup(bb);
        }

#ifdef APR_POOL_DEBUG
        apr_bucket_alloc_destroy(ba);
#endif
        AT_delocalize();
        apr_pool_clear(p);
    }
}

static void parse_disable_uploads(dAT, void *ctx)
{
    const char *val;
    apr_table_t *t, *body;
    apr_status_t rv;
    apr_bucket_alloc_t *ba;
    apr_bucket_brigade *bb;
    apr_bucket *e;
    apreq_parser_t *parser;
    apreq_hook_t *hook;

    ba = apr_bucket_alloc_create(p);
    bb = apr_brigade_create(p, ba);

    e = apr_bucket_immortal_create(form_data, strlen(form_data), ba);
    APR_BRIGADE_INSERT_HEAD(bb, e);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(bb->bucket_alloc));

    body = apr_table_make(p, APREQ_DEFAULT_NELTS);
    hook = apreq_hook_make(p, apreq_hook_disable_uploads, NULL, NULL);

    parser = apreq_parser_make(p, ba, MFD_ENCTYPE
                               "; charset=\"iso-8859-1\""
                               "; boundary=\"AaB03x\"",
                               apreq_parse_multipart,
                               1000, NULL, hook, NULL);


    rv = apreq_parser_run(parser, body, bb);
    AT_int_eq(rv, APREQ_ERROR_GENERAL);
    AT_int_eq(apr_table_elts(body)->nelts, 1);

    val = apr_table_get(body,"field1");
    AT_str_eq(val, "Joe owes =80100.");
    t = apreq_value_to_param(val)->info;
    val = apr_table_get(t, "content-transfer-encoding");
    AT_str_eq(val, "quoted-printable");

    val = apr_table_get(body, "pics");
    AT_is_null(val);
}


static void parse_generic(dAT, void *ctx)
{
    char *val;
    apr_size_t vlen;
    apr_status_t rv;
    apreq_param_t *dummy;
    apreq_parser_t *parser;
    apr_table_t *body;
    apr_bucket_alloc_t *ba = apr_bucket_alloc_create(p);
    apr_bucket_brigade *bb = apr_brigade_create(p, ba);
    apr_bucket *e = apr_bucket_immortal_create(xml_data,
                                               strlen(xml_data),
                                               ba);

    APR_BRIGADE_INSERT_HEAD(bb, e);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(ba));

    body = apr_table_make(p, APREQ_DEFAULT_NELTS);

    parser = apreq_parser_make(p, ba, "application/xml",
                               apreq_parse_generic, 1000, NULL, NULL, NULL);

    rv = apreq_parser_run(parser, body, bb);
    AT_int_eq(rv, APR_SUCCESS);
    dummy = *(apreq_param_t **)parser->ctx;
    AT_not_null(dummy);
    apr_brigade_pflatten(dummy->upload, &val, &vlen, p);

    AT_int_eq(vlen, strlen(xml_data));
    AT_mem_eq(val, xml_data, vlen);
}

static void hook_discard(dAT, void *ctx)
{
    apr_status_t rv;
    apreq_param_t *dummy;
    apreq_parser_t *parser;
    apreq_hook_t *hook;
    apr_table_t *body;
    apr_bucket_alloc_t *ba = apr_bucket_alloc_create(p);
    apr_bucket_brigade *bb = apr_brigade_create(p, ba);
    apr_bucket *e = apr_bucket_immortal_create(xml_data,
                                               strlen(xml_data),
                                               ba);

    APR_BRIGADE_INSERT_HEAD(bb, e);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(ba));

    body = apr_table_make(p, APREQ_DEFAULT_NELTS);

    hook = apreq_hook_make(p, apreq_hook_discard_brigade, NULL, NULL);
    parser = apreq_parser_make(p, ba, "application/xml",
                               apreq_parse_generic, 1000, NULL, hook, NULL);


    rv = apreq_parser_run(parser, body, bb);
    AT_int_eq(rv, APR_SUCCESS);
    dummy = *(apreq_param_t **)parser->ctx;
    AT_not_null(dummy);
    AT_not_null(dummy->upload);
    AT_ok(APR_BRIGADE_EMPTY(dummy->upload), "brigade has no contents");
}


static void parse_related(dAT, void *ctx)
{
    char ct[] = "multipart/related; boundary=f93dcbA3; "
        "type=application/xml; start=\"<980119.X53GGT@example.com>\"";
    char data[] = "...Binary data here...";
    int dlen = strlen(data);
    const char *val;
    char *val2;
    apr_size_t vlen;
    apr_status_t rv;
    int ns_map = 0;
    apr_xml_doc *doc;
    apr_table_t *body;
    apreq_parser_t *parser;
    apreq_hook_t *xml_hook;
    apreq_param_t *param;
    apr_bucket_alloc_t *ba = apr_bucket_alloc_create(p);
    apr_bucket_brigade *bb = apr_brigade_create(p, ba);
    apr_bucket *e = apr_bucket_immortal_create(rel_data,
                                                   strlen(rel_data),
                                                   bb->bucket_alloc);

    APR_BRIGADE_INSERT_HEAD(bb, e);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(bb->bucket_alloc));
    xml_hook = apreq_hook_make(p, apreq_hook_apr_xml_parser, NULL, NULL);

    body =   apr_table_make(p, APREQ_DEFAULT_NELTS);
    parser = apreq_parser_make(p, ba, ct, apreq_parse_multipart,
                               1000, NULL, xml_hook, NULL);

    rv = apreq_parser_run(parser, body, bb);
    AT_int_eq(rv, APR_SUCCESS);

    val = apr_table_get(body, "<980119.X53GGT@example.com>");
    AT_not_null(val);
    param = apreq_value_to_param(val);

    AT_not_null(param);
    AT_not_null(param->info);
    val = apr_table_get(param->info, "Content-Length");
    AT_str_eq(val, "400");
    AT_not_null(param->upload);
    apr_brigade_pflatten(param->upload, &val2, &vlen, p);
    AT_int_eq(vlen, 400);
    AT_mem_eq(val2, rel_data + 122, 400);

    doc = *(apr_xml_doc **)xml_hook->ctx;
    apr_xml_to_text(p, doc->root, APR_XML_X2T_FULL,
                    doc->namespaces, &ns_map, &val, &vlen);
    AT_int_eq(vlen, 400 - 22);
    AT_mem_eq(val, rel_data + 122 + 23, 400 - 23);


    val = apr_table_get(body, "<980119.X25MNC@example.com>");
    AT_not_null(val);
    param = apreq_value_to_param(val);
    AT_not_null(param);
    AT_not_null(param->upload);
    apr_brigade_pflatten(param->upload, &val2, &vlen, p);
    AT_int_eq(vlen, dlen);
    AT_mem_eq(val2, data, vlen);

    val = apr_table_get(body, "<980119.X17AXM@example.com>");
    AT_not_null(val);
    param = apreq_value_to_param(val);
    AT_not_null(param);
    AT_not_null(param->upload);
    apr_brigade_pflatten(param->upload, &val2, &vlen, p);
    AT_int_eq(vlen, dlen);
    AT_mem_eq(val2, data, vlen);
}

typedef struct {
    const char *key;
    const char *val;
} array_elt;


static void parse_mixed(dAT, void *ctx)
{
    const char *val;
    char *val2;
    apr_size_t vlen;
    apr_status_t rv;
    apreq_param_t *param;
    const apr_array_header_t *arr;
    array_elt *elt;
    char ct[] = MFD_ENCTYPE "; charset=\"iso-8859-1\"; boundary=\"AaB03x\"";
    apreq_parser_t *parser;
    apr_table_t *body = apr_table_make(p, APREQ_DEFAULT_NELTS);
    apr_bucket_alloc_t *ba = apr_bucket_alloc_create(p);
    apr_bucket_brigade *bb = apr_brigade_create(p, ba);
    apr_bucket *e = apr_bucket_immortal_create(mix_data,
                                                   strlen(mix_data),
                                                   bb->bucket_alloc);

    APR_BRIGADE_INSERT_HEAD(bb, e);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(bb->bucket_alloc));

    parser = apreq_parser_make(p, ba, ct, apreq_parse_multipart,
                               1000, NULL, NULL, NULL);

    rv = apreq_parser_run(parser, body, bb);
    AT_int_eq(rv, APR_SUCCESS);

    val = apr_table_get(body, "submit-name");
    AT_not_null(val);
    AT_str_eq(val, "Larry");

    val = apr_table_get(body,"field1");
    AT_str_eq(val, "Joe owes =80100.");

    val = apr_table_get(body, "files");
    AT_not_null(val);
    AT_str_eq(val, "file1.txt");
    param = apreq_value_to_param(val);

    AT_not_null(param->upload);
    apr_brigade_pflatten(param->upload, &val2, &vlen, p);
    AT_int_eq(vlen, strlen("... contents of file1.txt ..."));
    AT_mem_eq(val2, "... contents of file1.txt ...", vlen);

    arr = apr_table_elts(body);
    AT_int_eq(arr->nelts, 4);

    elt = (array_elt *)&arr->elts[2 * arr->elt_size];
    AT_str_eq(elt->key, "files");
    AT_str_eq(elt->val, "file2.gif");

    param = apreq_value_to_param(elt->val);
    AT_not_null(param->upload);
    apr_brigade_pflatten(param->upload, &val2, &vlen, p);
    AT_int_eq(vlen, strlen("...contents of file2.gif..."));
    AT_mem_eq(val2, "...contents of file2.gif...", vlen);

}


#define dT(func, plan) {#func, func, plan}

int main(int argc, char *argv[])
{
    apr_pool_t *test_pool;
    unsigned i, plan = 0;
    dAT;
    at_test_t test_list [] = {
        dT(locate_default_parsers, 3),
        dT(parse_urlencoded, 5),
        dT(parse_multipart, sizeof form_data),
        dT(parse_disable_uploads, 5),
        dT(parse_generic, 4),
        dT(hook_discard, 4),
        dT(parse_related, 20),
        dT(parse_mixed, 15)
    };

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&p, NULL);
    apr_pool_create(&test_pool, NULL);
    apreq_initialize(p);


    AT = at_create(0, at_report_stdout_make());

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        plan += test_list[i].plan;

    AT_begin(plan);

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        AT_run(&test_list[i]);

    AT_end();

    return 0;
}


