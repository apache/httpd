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
#include "apreq_cookie.h"
#include "apreq_error.h"
#include "apreq_module.h"
#include "apreq_util.h"
#include "at.h"

static const char nscookies[] = "a=1; foo=bar; fl=left; fr=right;bad; "
                                "ns=foo=1&bar=2,frl=right-left; "
                                "flr=left-right; fll=left-left; "
                                "good_one=1;=;bad";

static const char rfccookies[] = "$Version=1; first=a;$domain=quux;second=be,"
                                 "$Version=1;third=cie";

static const char wpcookies[] = "wordpressuser_c580712eb86cad2660b3601ac"
                                "04202b2=admin; wordpresspass_c580712eb8"
                                "6cad2660b3601ac04202b2=7ebeeed42ef50720"
                                "940f5b8db2f9db49; rs_session=59ae9b8b50"
                                "3e3af7d17b97e7f77f7ea5; dbx-postmeta=gr"
                                "abit=0-,1-,2-,3-,4-,5-,6-&advancedstuff"
                                "=0-,1+,2-";

static const char cgcookies1[] = "UID=MTj9S8CoAzMAAFEq21YAAAAG|c85a9e59db"
                                 "92b261408eb7539ff7f949b92c7d58; $Versio"
                                 "n=0;SID=MTj9S8CoAzMAAFEq21YAAAAG|c85a9e"
                                 "59db92b261408eb7539ff7f949b92c7d58;$Dom"
                                 "ain=www.xxxx.com;$Path=/";

static const char cgcookies2[] = "UID=Gh9VxX8AAAIAAHP7h6AAAAAC|2e809a9cc9"
                                 "9c2dca778c385ebdefc5cb86c95dc3; SID=Gh9"
                                 "VxX8AAAIAAHP7h6AAAAAC|2e809a9cc99c2dca7"
                                 "78c385ebdefc5cb86c95dc3; $Version=1";

static const char cgcookies3[] = "UID=hCijN8CoAzMAAGVDO2QAAAAF|50299f0793"
                                 "43fd6146257c105b1370f2da78246a; SID=hCi"
                                 "jN8CoAzMAAGVDO2QAAAAF|50299f079343fd614"
                                 "6257c105b1370f2da78246a; $Path=\"/\"; $"
                                 "Domain=\"www.xxxx.com\"";

static const char cgcookies4[] = "SID=66XUEH8AAAIAAFmLLRkAAAAV|2a48c4ae2e"
                                 "9fb8355e75192db211f0779bdce244; UID=66X"
                                 "UEH8AAAIAAFmLLRkAAAAV|2a48c4ae2e9fb8355"
                                 "e75192db211f0779bdce244; __utma=1441491"
                                 "62.4479471199095321000.1234471650.12344"
                                 "71650.1234471650.1; __utmb=144149162.24"
                                 ".10.1234471650; __utmc=144149162; __utm"
                                 "z=\"144149162.1234471650.1.1.utmcsr=szu"
                                 "kaj.xxxx.pl|utmccn=(referral)|utmcmd=re"
                                 "ferral|utmcct=/internet/0,0.html\"";

static apr_table_t *jar, *jar2, *jar3, *jar4, *jar5, *jar6, *jar7;
static apr_pool_t *p;

static void jar_make(dAT, void *ctx)
{
    jar = apr_table_make(p, APREQ_DEFAULT_NELTS);
    AT_not_null(jar);
    AT_int_eq(apreq_parse_cookie_header(p, jar, nscookies), APREQ_ERROR_NOTOKEN);
    jar2 = apr_table_make(p, APREQ_DEFAULT_NELTS);
    AT_not_null(jar2);
    AT_int_eq(apreq_parse_cookie_header(p, jar2, rfccookies), APR_SUCCESS);
    jar3 = apr_table_make(p, APREQ_DEFAULT_NELTS);
    AT_not_null(jar3);
    AT_int_eq(apreq_parse_cookie_header(p, jar3, wpcookies), APREQ_ERROR_NOTOKEN);
    jar4 = apr_table_make(p, APREQ_DEFAULT_NELTS);
    AT_not_null(jar4);
    AT_int_eq(apreq_parse_cookie_header(p, jar4, cgcookies1), APREQ_ERROR_MISMATCH);
    jar5 = apr_table_make(p, APREQ_DEFAULT_NELTS);
    AT_not_null(jar5);
    AT_int_eq(apreq_parse_cookie_header(p, jar5, cgcookies2), APREQ_ERROR_MISMATCH);
    jar6 = apr_table_make(p, APREQ_DEFAULT_NELTS);
    AT_not_null(jar6);
    AT_int_eq(apreq_parse_cookie_header(p, jar6, cgcookies3), APREQ_ERROR_MISMATCH);
    jar7 = apr_table_make(p, APREQ_DEFAULT_NELTS);
    AT_not_null(jar7);
    AT_int_eq(apreq_parse_cookie_header(p, jar7, cgcookies4), APR_SUCCESS);
}

static void jar_get_rfc(dAT, void *ctx)
{
    const char *val;
    AT_not_null(val = apr_table_get(jar2, "first"));
    AT_str_eq(val, "a");
    AT_not_null(val = apr_table_get(jar2, "second"));
    AT_str_eq(val, "be");
    AT_not_null(val = apr_table_get(jar2, "third"));
    AT_str_eq(val, "cie");
}

static void jar_get_ns(dAT, void *ctx)
{

    AT_str_eq(apr_table_get(jar, "a"), "1");

    /* ignore wacky cookies that don't have an '=' sign */
    AT_is_null(apr_table_get(jar, "bad"));

    /* accept wacky cookies that contain multiple '=' */
    AT_str_eq(apr_table_get(jar, "ns"), "foo=1&bar=2");

    AT_str_eq(apr_table_get(jar,"foo"), "bar");
    AT_str_eq(apr_table_get(jar,"fl"),  "left");
    AT_str_eq(apr_table_get(jar,"fr"),  "right");
    AT_str_eq(apr_table_get(jar,"frl"), "right-left");
    AT_str_eq(apr_table_get(jar,"flr"), "left-right");
    AT_str_eq(apr_table_get(jar,"fll"), "left-left");
    AT_is_null(apr_table_get(jar,""));
}


static void netscape_cookie(dAT, void *ctx)
{
    char expires[APR_RFC822_DATE_LEN];
    char *val;
    apreq_cookie_t *c;

    *(const char **)&val = apr_table_get(jar, "foo");
    AT_not_null(val);

    c = apreq_value_to_cookie(val);

    AT_str_eq(c->v.data, "bar");
    AT_int_eq(apreq_cookie_version(c), 0);
    AT_str_eq(apreq_cookie_as_string(c, p), "foo=bar");

    c->domain = apr_pstrdup(p, "example.com");
    AT_str_eq(apreq_cookie_as_string(c, p), "foo=bar; domain=example.com");

    c->path = apr_pstrdup(p, "/quux");
    AT_str_eq(apreq_cookie_as_string(c, p),
              "foo=bar; path=/quux; domain=example.com");

    apreq_cookie_expires(c, "+1y");
    apr_rfc822_date(expires, apr_time_now()
                             + apr_time_from_sec(apreq_atoi64t("+1y")));
    expires[7] = '-';
    expires[11] = '-';
    val = apr_pstrcat(p, "foo=bar; path=/quux; domain=example.com; expires=",
                      expires, NULL);

    AT_str_eq(apreq_cookie_as_string(c, p), val);
}


static void rfc_cookie(dAT, void *ctx)
{
    apreq_cookie_t *c = apreq_cookie_make(p,"rfc",3,"out",3);
    const char *expected;
    long expires;

    AT_str_eq(c->v.data, "out");

    apreq_cookie_version_set(c, 1);
    AT_int_eq(apreq_cookie_version(c), 1);
    AT_str_eq(apreq_cookie_as_string(c,p),"rfc=out; Version=1");

    c->domain = apr_pstrdup(p, "example.com");

#ifndef WIN32

    AT_str_eq(apreq_cookie_as_string(c,p),
              "rfc=out; Version=1; domain=\"example.com\"");
    c->path = apr_pstrdup(p, "/quux");
    AT_str_eq(apreq_cookie_as_string(c,p),
              "rfc=out; Version=1; path=\"/quux\"; domain=\"example.com\"");

    apreq_cookie_expires(c, "+3m");
    expires = apreq_atoi64t("+3m");
    expected = apr_psprintf(p, "rfc=out; Version=1; path=\"/quux\"; "
                       "domain=\"example.com\"; max-age=%ld",
                       expires);
    AT_str_eq(apreq_cookie_as_string(c,p), expected);

#else

    expected = "rfc=out; Version=1; domain=\"example.com\"";
    AT_str_eq(apreq_cookie_as_string(c,p), expected);

    c->path = apr_pstrdup(p, "/quux");
    expected = "rfc=out; Version=1; path=\"/quux\"; domain=\"example.com\"";
    AT_str_eq(apreq_cookie_as_string(c,p), expected);

    apreq_cookie_expires(c, "+3m");
    expires = apreq_atoi64t("+3m");
    expected = apr_psprintf(p, "rfc=out; Version=1; path=\"/quux\"; "
                           "domain=\"example.com\"; max-age=%ld",
                           expires);
    AT_str_eq(apreq_cookie_as_string(c,p), expected);

#endif

}


#define dT(func, plan) #func, func, plan, NULL


int main(int argc, char *argv[])
{
    unsigned i, plan = 0;
    dAT;
    at_test_t test_list [] = {
        { dT(jar_make, 14) },
        { dT(jar_get_rfc, 6), "1 3 5" },
        { dT(jar_get_ns, 10) },
        { dT(netscape_cookie, 7) },
        { dT(rfc_cookie, 6) },
    };

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&p, NULL);

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
