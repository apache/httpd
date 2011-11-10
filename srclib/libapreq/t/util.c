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

#include "apr_strings.h"
#include "apreq_error.h"
#include "apreq_util.h"
#include "at.h"


static void test_atoi64f(dAT, void *ctx)
{
    AT_int_eq(apreq_atoi64f("0"), 0);
    AT_int_eq(apreq_atoi64f("-1"), -1);
    AT_int_eq(apreq_atoi64f("-"), 0);
    AT_int_eq(apreq_atoi64f("5"), 5);
    AT_int_eq(apreq_atoi64f("3.333"), 3);
    AT_int_eq(apreq_atoi64f("33k"), 33 * 1024);
    AT_int_eq(apreq_atoi64f(" +8M "), 8 * 1024 * 1024);
    AT_ok(apreq_atoi64f("44GB") == (apr_int64_t)44 * 1024 * 1024 * 1024,
          "44GB test");
    AT_ok(apreq_atoi64f("0xaBcDefg") == (apr_int64_t)11259375 * 1024 * 1024 * 1024,
          "hex test");
}

static void test_atoi64t(dAT, void *ctx)
{
    AT_int_eq(apreq_atoi64t("0"), 0);
    AT_int_eq(apreq_atoi64t("-1"), -1);
    AT_int_eq(apreq_atoi64t("-g088l3dyg00k"), 0);
    AT_int_eq(apreq_atoi64t("5s"), 5);
    AT_int_eq(apreq_atoi64t("3.333"), 3);
    AT_int_eq(apreq_atoi64t("33d"), 33 * 60 * 60 * 24);
    AT_int_eq(apreq_atoi64t(" +8M "), 8 * 60 * 60 * 24 * 30);
    AT_int_eq(apreq_atoi64t("+9m"), 9 * 60);
    AT_int_eq(apreq_atoi64t("6h"), 6 * 60 * 60);

}

static void test_index(dAT, void *ctx)
{
    const char haystack[] = "Four score and seven years ago";
    apr_size_t hlen = sizeof haystack - 1;
    AT_int_eq(apreq_index(haystack, hlen, "Four", 4, APREQ_MATCH_FULL),
              0);
    AT_int_eq(apreq_index(haystack, hlen, "Four", 4, APREQ_MATCH_PARTIAL),
              0);
    AT_int_eq(apreq_index(haystack, hlen, "Fourteen", 8, APREQ_MATCH_FULL),
              -1);
    AT_int_eq(apreq_index(haystack, hlen, "Fourteen", 8, APREQ_MATCH_PARTIAL),
              -1);
    AT_int_eq(apreq_index(haystack, hlen, "agoraphobia", 11, APREQ_MATCH_FULL),
              -1);
    AT_int_eq(apreq_index(haystack, hlen, "agoraphobia", 11, APREQ_MATCH_PARTIAL),
              hlen - 3);
}

#define A_GRAVE  0xE5
#define KATAKANA_A 0xFF71

static void test_decode(dAT, void *ctx)
{
    apr_size_t elen;
    char src1[] = "%C3%80%E3%82%a2"; /* A_GRAVE KATAKANA_A as utf8 */
    unsigned char expect[6];

    AT_int_eq(apreq_decode((char *)expect, &elen, src1, sizeof(src1) -1),
              APR_SUCCESS);
    AT_int_eq(elen, 5);
    AT_int_eq(expect[0], 0xC3);
    AT_int_eq(expect[1], 0x80);
    AT_int_eq(expect[2], 0xE3);
    AT_int_eq(expect[3], 0x82);
    AT_int_eq(expect[4], 0xA2);
}

static void test_charset_divine(dAT, void *ctx)
{
    apr_size_t elen;
    char src1[] = "%C3%80%E3%82%a2"; /* A_GRAVE KATAKANA_A as utf8 */
    char src2[] = "pound%A3";/* latin-1 */
    char src3[] = "euro%80";/* cp-1252 */
    char expect[7];

    AT_int_eq(apreq_decode(expect, &elen, src1, sizeof(src1) -1),
              APR_SUCCESS);

    AT_int_eq(apreq_charset_divine(expect, elen), APREQ_CHARSET_UTF8);

    AT_int_eq(apreq_decode(expect, &elen, src2, sizeof(src2) -1),
              APR_SUCCESS);

    AT_int_eq(apreq_charset_divine(expect, elen), APREQ_CHARSET_LATIN1);
    AT_int_eq(apreq_decode(expect, &elen, src3, sizeof(src3) -1),
              APR_SUCCESS);

    AT_int_eq(apreq_charset_divine(expect, elen), APREQ_CHARSET_CP1252);

}


static void test_decodev(dAT, void *ctx)
{
    char src1[] = "%2540%2";
    char src2[] = "0%u0";
    char src3[] = "041";
    struct iovec iovec1[] = {
        { src1, sizeof(src1) - 1 },
        { src2, sizeof(src2) - 1 },
        { src3, sizeof(src3) - 1 },
    };
    struct iovec iovec2[] = {
        { src1, sizeof(src1) - 1 },
        { src2, sizeof(src2) - 1 },
    };
    const char expect1[] = "%40 A";
    const char expect2[] = "%40 ";
    char dest[sizeof(src1) + sizeof(src2) + sizeof(src3)];
    apr_size_t dest_len;
    apr_status_t status;

    status = apreq_decodev(dest, &dest_len, iovec1, 3);
    AT_int_eq(status, APR_SUCCESS);
    AT_int_eq(dest_len, sizeof(expect1) - 1);
    AT_mem_eq(dest, expect1, sizeof(expect1) - 1);

    status = apreq_decodev(dest, &dest_len, iovec2, 2);
    AT_int_eq(status, APR_INCOMPLETE);
    AT_int_eq(dest_len, sizeof(expect2) - 1);
    AT_mem_eq(dest, expect2, sizeof(expect2) - 1);
}


static void test_encode(dAT, void *ctx)
{

}

static void test_cp1252_to_utf8(dAT, void *ctx)
{
    char src1[] = "%C3%80%E3%82%a2"; /* A_GRAVE KATAKANA_A as utf8 */
    char src2[5];
    unsigned char expect[16];
    apr_size_t slen;

    AT_int_eq(apreq_decode((char *)src2, &slen, src1, sizeof(src1) -1),
              APR_SUCCESS);
    AT_int_eq(apreq_cp1252_to_utf8((char *)expect, src2, 5),
              12);

    /* 0xC3 */
    AT_int_eq(expect[0], 0xC0 | (0xC3 >> 6));
    AT_int_eq(expect[1], 0xC3 - 0x40);

    /* 0x20AC */
    AT_int_eq(expect[2], 0xE0 | (0x20AC >> 12));
    AT_int_eq(expect[3], 0x80 | ((0x20AC >> 6) & 0x3F));
    AT_int_eq(expect[4], 0x80 | (0x20AC & 0x3F));

    /* 0xE3 */
    AT_int_eq(expect[5], 0xC3);
    AT_int_eq(expect[6], 0xE3 - 0x40);

    /* 0x201A */
    AT_int_eq(expect[7], 0xE0 | (0x201A >> 12));
    AT_int_eq(expect[8], 0x80 | ((0x201A >> 6) & 0x3F));
    AT_int_eq(expect[9], 0x80 | (0x201A & 0x3F));


    /* 0xA2 */
    AT_int_eq(expect[10], 0xC0 | (0xA2 >> 6));
    AT_int_eq(expect[11], 0xA2);

}

static void test_quote(dAT, void *ctx)
{
    size_t len;
    char dst[64];

    len = apreq_quote(dst, "foo", 3);
    AT_int_eq(len, 5);
    AT_str_eq(dst, "\"foo\"");

    len = apreq_quote(dst, "\"foo", 4);
    AT_int_eq(len, 7);
    AT_str_eq(dst, "\"\\\"foo\"");

    len = apreq_quote(dst, "foo\\bar", 7);
    AT_int_eq(len, 10);
    AT_str_eq(dst, "\"foo\\\\bar\"");

    len = apreq_quote(dst, "foo\0bar", 7);
    AT_int_eq(len, 10);
    AT_str_eq(dst, "\"foo\\0bar\"");
}

static void test_quote_once(dAT, void *ctx)
{
    size_t len;
    char dst[64];

    len = apreq_quote_once(dst, "foo", 3);
    AT_int_eq(len, 5);
    AT_str_eq(dst, "\"foo\"");

    len = apreq_quote_once(dst, "\"foo", 4);
    AT_int_eq(len, 7);
    AT_str_eq(dst, "\"\\\"foo\"");

    len = apreq_quote_once(dst, "foo\"", 4);
    AT_int_eq(len, 7);
    AT_str_eq(dst, "\"foo\\\"\"");

    len = apreq_quote_once(dst, "foo\0bar", 7);
    AT_int_eq(len, 10);
    AT_str_eq(dst, "\"foo\\0bar\"");

    /* null byte must be escaped, even when there are already double
       quotes */
    len = apreq_quote_once(dst, "\"foo\0bar\"", 9);
    AT_int_eq(len, 14);
    AT_str_eq(dst, "\"\\\"foo\\0bar\\\"\"");

    len = apreq_quote_once(dst, "\"foo\"", 5);
    AT_int_eq(len, 5);
    AT_str_eq(dst, "\"foo\"");

    len = apreq_quote_once(dst, "'foo'", 5);
    AT_int_eq(len, 7);
    AT_str_eq(dst, "\"'foo'\"");

    len = apreq_quote_once(dst, "\"fo\\o\"", 6);
    AT_int_eq(len, 6);
    AT_str_eq(dst, "\"fo\\o\"");

    len = apreq_quote_once(dst, "\"foo\"bar\"", 9);
    AT_int_eq(len, 14);
    AT_str_eq(dst, "\"\\\"foo\\\"bar\\\"\"");
}

static void test_join(dAT, void *ctx)
{

}

static void test_brigade_fwrite(dAT, void *ctx)
{

}

static void test_file_mktemp(dAT, void *ctx)
{


}

static void test_header_attribute(dAT, void *ctx)
{
    const char hdr[] = "filename=\"filename=foo\" filename=\"quux.txt\"";
    const char *val;
    apr_size_t vlen;

    AT_int_eq(apreq_header_attribute(hdr+4, "name", 4, &val, &vlen),
              APR_SUCCESS);
    AT_int_eq(vlen, 12);
    AT_mem_eq("filename=foo", val, 12);

    AT_int_eq(apreq_header_attribute(hdr+4, "filename", 8, &val, &vlen),
              APR_SUCCESS);
    AT_int_eq(vlen, 8);
    AT_mem_eq("quux.txt", val, 8);

}

static void test_brigade_concat(dAT, void *ctx)
{

}



#define dT(func, plan) #func, func, plan, NULL


int main(int argc, char *argv[])
{
    unsigned i, plan = 0;
    apr_pool_t *p;
    dAT;
    at_test_t test_list [] = {
        { dT(test_atoi64f, 9) },
        { dT(test_atoi64t, 9) },
        { dT(test_index, 6) },
        { dT(test_decode, 7) },
        { dT(test_charset_divine, 6) },
        { dT(test_decodev, 6) },
        { dT(test_encode, 0) },
        { dT(test_cp1252_to_utf8, 14) },
        { dT(test_quote, 8) },
        { dT(test_quote_once, 18), },
        { dT(test_join, 0) },
        { dT(test_brigade_fwrite, 0) },
        { dT(test_file_mktemp, 0) },
        { dT(test_header_attribute, 6) },
        { dT(test_brigade_concat, 0) },
    };

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&p, NULL);

    AT = at_create(0, at_report_stdout_make());

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        plan += test_list[i].plan;

    AT_begin(plan);

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        AT_run(&test_list[i]);

    AT_end();

    return 0;
}
