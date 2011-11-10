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

#include "apreq_param.h"
#include "apreq_util.h"
#include "apreq_error.h"
#include "apr_strings.h"
#include "at.h"


static const char query_string[] = "a=1;quux=foo+bar&a=2&plus=%2B;"
                                   "uplus=%U002b;okie=dokie;foo=a%E1;"
                                   "novalue1;novalue2=";
static apr_table_t *args;
static apr_pool_t *p;


static void request_make(dAT, void *ctx)
{
    apr_status_t s;
    args = apr_table_make(p, APREQ_DEFAULT_NELTS);
    AT_not_null(args);
    s = apreq_parse_query_string(p, args, query_string);
    AT_int_eq(s, APR_SUCCESS);
    AT_int_eq(apr_table_elts(args)->nelts, 9);
}


static void request_args_get(dAT, void *ctx)
{
    const char *val;
    const apreq_param_t *param;

    AT_str_eq(apr_table_get(args,"a"), "1");

    val = apr_table_get(args,"quux");
    AT_str_eq(val, "foo bar");
    param = apreq_value_to_param(val);
    AT_int_eq(param->v.dlen, 7);

    AT_str_eq(apr_table_get(args,"plus"), "+");
    AT_str_eq(apr_table_get(args,"uplus"), "+");
    AT_str_eq(apr_table_get(args,"okie"), "dokie");
    AT_str_eq(apr_table_get(args,"novalue1"), "");
    AT_str_eq(apr_table_get(args,"novalue2"),"");
}

static void params_as(dAT, void *ctx)
{
    const char *val;
    apr_array_header_t *arr;
    arr = apreq_params_as_array(p,args,"a");
    AT_int_eq(arr->nelts, 2);
    val = apreq_params_as_string(p,args,"a",APREQ_JOIN_AS_IS);
    AT_str_eq(val, "1, 2");
    val = apreq_params_as_string(p,args,"does_not_exist",APREQ_JOIN_AS_IS);
    AT_str_eq(val, "");
}

static void string_decoding_in_place(dAT, void *ctx)
{
    char *s1 = apr_palloc(p,4096);
    char *s2 = apr_palloc(p,4096);
    char *s3;

    strcpy(s1, "bend it like beckham");
    strcpy(s2, "dandy %3Edons");

    AT_str_eq(s1,"bend it like beckham");
    apreq_unescape(s1);
    AT_str_eq(s1, "bend it like beckham");
    s3 = apreq_escape(p, s1, 20);
    AT_str_eq(s3, "bend+it+like+beckham");
    apreq_unescape(s3);
    AT_str_eq(s3,"bend it like beckham");

    AT_str_eq(s2,"dandy %3Edons");
    apreq_unescape(s2);
    AT_str_eq(s2,"dandy >dons");
    s3 = apreq_escape(p, s2, 11);
    AT_str_eq(s3,"dandy+%3Edons");
    apreq_unescape(s3);
    AT_str_eq(s3,"dandy >dons");
}

static void header_attributes(dAT, void *ctx)
{
    const char *hdr = "text/plain; boundary=\"-foo-\", charset=ISO-8859-1";
    const char *val;
    apr_size_t vlen;
    apr_status_t s;

    s = apreq_header_attribute(hdr, "none", 4, &val, &vlen);
    AT_int_eq(s, APREQ_ERROR_NOATTR);

    s = apreq_header_attribute(hdr, "set", 3, &val, &vlen);
    AT_int_eq(s, APREQ_ERROR_NOATTR);

    s = apreq_header_attribute(hdr, "boundary", 8, &val, &vlen);
    AT_int_eq(s, APR_SUCCESS);
    AT_int_eq(vlen, 5);
    AT_mem_eq(val, "-foo-", 5);

    s = apreq_header_attribute(hdr, "charset", 7, &val, &vlen);
    AT_int_eq(s, APR_SUCCESS);
    AT_int_eq(vlen, 10);
    AT_mem_eq(val, "ISO-8859-1", 10);

    hdr = "max-age=20; no-quote=\"...";

    s = apreq_header_attribute(hdr, "max-age", 7, &val, &vlen);
    AT_int_eq(s, APR_SUCCESS);
    AT_int_eq(vlen, 2);
    AT_mem_eq(val, "20", 2);

    s = apreq_header_attribute(hdr, "age", 3, &val, &vlen);
    AT_int_eq(s, APREQ_ERROR_BADSEQ);

    s = apreq_header_attribute(hdr, "no-quote", 8, &val, &vlen);
    AT_int_eq(s, APREQ_ERROR_BADSEQ);

}


static void make_param(dAT, void *ctx)
{
    apreq_param_t *param, *decode;
    apr_status_t s;
    apr_size_t nlen = 3, vlen = 11;
    char *name = apr_palloc(p,nlen+1);
    char *val = apr_palloc(p,vlen+1);
    char *encode;
    strcpy(name, "foo");
    strcpy(val, "bar > alpha");

    param = apreq_param_make(p, name, nlen, val, vlen);
    AT_str_eq(param->v.name, name);
    AT_int_eq(param->v.dlen, vlen);
    AT_str_eq(param->v.data, val);

    encode = apreq_param_encode(p, param);
    AT_str_eq(encode, "foo=bar+%3E+alpha");

    s = apreq_param_decode(&decode, p, encode, nlen, vlen+2);
    AT_int_eq(s, APR_SUCCESS);
    AT_str_eq(decode->v.name, name);
    AT_int_eq(decode->v.dlen, vlen);
    AT_str_eq(decode->v.data, val);
}

static void quote_strings(dAT, void *ctx)
{
    apr_size_t exp_len, res_len, res_quote_len;
    char *res = apr_palloc(p,24);
    char *res_quote = apr_palloc(p,24);
    const char *expr;
    int i;
    const char * arr[] = {"cest", "\"cest", "ce\"st", "\"cest\""};
    const char * arr_quote[] =
        {"\"cest\"", "\"\\\"cest\"", "\"ce\\\"st\"", "\"\\\"cest\\\"\""};
    apr_size_t arr_len[] = {4, 5, 5, 6};
    apr_size_t arr_quote_len[] = {6, 8, 8, 10};

    for (i=0; i<4; i++) {
        res_len = apreq_quote(res, arr[i], arr_len[i]);
        AT_int_eq(res_len, arr_quote_len[i]);
        AT_mem_eq(res, arr_quote[i], res_len);
        res_quote_len = apreq_quote_once(res_quote, res, res_len);
        AT_int_eq(res_quote_len, res_len);
        AT_mem_eq(res_quote, res, res_len);
        res_len = apreq_quote_once(res, arr[i], arr_len[i]);
        exp_len = (i == 3) ? arr_len[i] : arr_quote_len[i];
        expr = (i == 3) ? arr[i] : arr_quote[i];
        AT_int_eq(res_len, exp_len);
        AT_mem_eq(res, expr, exp_len);
    }
}

#define dT(func, plan) {#func, func, plan}

int main(int argc, char *argv[])
{
    unsigned i, plan = 0;
    dAT;
    at_test_t test_list [] = {
        dT(request_make, 3),
        dT(request_args_get, 8),
        dT(params_as, 3),
        dT(string_decoding_in_place, 8),
        dT(header_attributes, 13),
        dT(make_param, 8),
        dT(quote_strings, 24),
    };

    apr_initialize();
    atexit(apr_terminate);
    apr_pool_create(&p, NULL);

    apreq_initialize(p);

    AT = at_create(0, at_report_stdout_make());
    AT_trace_on();
    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        plan += test_list[i].plan;

    AT_begin(plan);

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        AT_run(&test_list[i]);

    AT_end();

    return 0;
}

