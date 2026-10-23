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

#include "../httpdunit.h"

#include "httpd.h"
#include "apr_strings.h"

/*
 * Test Fixture -- runs once per test
 */

static apr_pool_t *g_pool;

static void util_setup(void)
{
    if (apr_pool_create(&g_pool, NULL) != APR_SUCCESS) {
        exit(1);
    }
}

static void util_teardown(void)
{
    apr_pool_destroy(g_pool);
}

/*
 * ap_test_token()
 */

struct ap_test_token_case {
    const char *list;
    const char *token;
    int expected;
};

const struct ap_test_token_case ap_test_token_cases[] = {
    { "one, two, three",   "one",   1 },
    { "one, two, three",   "two",   1 },
    { "one, two, three",   "three", 1 },
    { "one,two,three",     "two",   1 },
    { NULL,                "token", 0 },

    /* Regression test for CVE-2017-7668 */
    { "one, two, \0three", "three", 0 },

    /*
     * Dubious compatibility cases
     */
    { ",\x01,one,,two,/,,three,,", "one",   1 },
    { ",\x01,one,,two,/,,three,,", "two",   1 },
    { ",\x01,one,,two,/,,three,,", "three", 1 },
    { ",\x01,one,,two,/,,three,,", "\x01",  0 },
    { ",\x01,one,,two,/,,three,,", "/",     0 },
};

const size_t ap_test_token_cases_len = sizeof(ap_test_token_cases) /
                                       sizeof(ap_test_token_cases[0]);

HTTPD_START_LOOP_TEST(find_token_correctly_parses_token_list, ap_test_token_cases_len)
{
    const struct ap_test_token_case *c = &ap_test_token_cases[_i];
    int result;

    result = ap_find_token(g_pool, c->list, c->token);
    ck_assert_int_eq(result, c->expected);
}
END_TEST


/*
 * ap_cstr_stripws()
 */

struct ap_cstr_stripws_case {
    const char *input;
    const char *expected;
};

const struct ap_cstr_stripws_case ap_cstr_stripws_cases[] = {
    { "", "" },
    { " ", "" },
    { "\t\r\n", "" },
    { "value", "value" },
    { "value ", "value" },
    { "value\t ", "value" },
    { " value ", " value" },
};

const size_t ap_cstr_stripws_cases_len = sizeof(ap_cstr_stripws_cases) /
                                         sizeof(ap_cstr_stripws_cases[0]);

HTTPD_START_LOOP_TEST(cstr_stripws_strips_trailing_whitespace, ap_cstr_stripws_cases_len)
{
    const struct ap_cstr_stripws_case *c = &ap_cstr_stripws_cases[_i];
    char *str = apr_pstrdup(g_pool, c->input);
    char *end = ap_cstr_stripws(str);

    ck_assert_str_eq(str, c->expected);
    ck_assert_ptr_eq(end, str + strlen(c->expected));
}
END_TEST


/*
 * ap_escape_quotes()
 */

struct ap_escape_quotes_case {
    const char *input;
    const char *expected;
};

#define ESCQ    "\\\""

const struct ap_escape_quotes_case ap_test_escape_quotes_cases[] = {
    { "one", "one" },
    { "o\"ne", "o"ESCQ"ne" },
    { "o"ESCQ"ne", "o"ESCQ"ne" },
    { "one\\", "one\\" },
    { "o\\ne", "o\\ne" },
    { "o\\"ESCQ"ne", "o\\\\"ESCQ"ne" }, /* 1st \ escapes 2nd, following '"' needs \ */
};

const size_t ap_test_escape_quotes_cases_len = sizeof(ap_test_escape_quotes_cases) /
    sizeof(ap_test_escape_quotes_cases[0]);

HTTPD_START_LOOP_TEST(check_escape_quotes, ap_test_escape_quotes_cases_len)
{
    const struct ap_escape_quotes_case *c = &ap_test_escape_quotes_cases[_i];
    const char *result;

    result = ap_escape_quotes(g_pool, c->input);
    ck_assert_str_eq(result, c->expected);
}
END_TEST


/*
 * ap_size_parameter_parse()
 */

struct ap_size_parameter_parse_case {
    const char *input;
    apr_status_t expected_rv;
    apr_int64_t expected;       /* for a 64-bit apr_off_t */
};

const struct ap_size_parameter_parse_case ap_size_parameter_parse_cases[] = {
    { "0",                    APR_SUCCESS, 0 },
    { "1",                    APR_SUCCESS, 1 },
    { "-1",                   APR_SUCCESS, -1 },
    { "1024",                 APR_SUCCESS, 1024 },
    { "0b",                   APR_SUCCESS, 0 },
    { "1b",                   APR_SUCCESS, 1 },
    { "512B",                 APR_SUCCESS, 512 },
    { "1k",                   APR_SUCCESS, 1024 },
    { "1K",                   APR_SUCCESS, 1024 },
    { "10k",                  APR_SUCCESS, 10240 },
    { "1m",                   APR_SUCCESS, 1024 * 1024 },
    { "2M",                   APR_SUCCESS, 2 * 1024 * 1024 },
    { "1g",                   APR_SUCCESS, 1024 * 1024 * 1024 },
    { "4G",                   APR_SUCCESS, APR_INT64_C(4) * 1024 * 1024 * 1024 },
    { "-2k",                  APR_SUCCESS, -2048 },
    { "",                     APR_EINVAL,  0 },
    { "k",                    APR_EINVAL,  0 },
    { "-",                    APR_EINVAL,  0 },
    { "1t",                   APR_EINVAL,  0 },
    { "1kb",                  APR_EINVAL,  0 },
    { "1 k",                  APR_EINVAL,  0 },
    { "1k ",                  APR_EINVAL,  0 },
    { "2 ",                   APR_EINVAL,  0 },
    { "0x10",                 APR_EINVAL,  0 },
    { "1.5k",                 APR_EINVAL,  0 },
    /* overflows whether apr_off_t is 32 or 64 bits wide */
    { "99999999999999999999", APR_ERANGE,  0 },
    { "9223372036854775807k", APR_ERANGE,  0 },
    { "9007199254740992m",    APR_ERANGE,  0 },
    { "-9007199254740992m",   APR_ERANGE,  0 },
    { "8589934592g",          APR_ERANGE,  0 },
};

const size_t ap_size_parameter_parse_cases_len =
    sizeof(ap_size_parameter_parse_cases) /
    sizeof(ap_size_parameter_parse_cases[0]);

HTTPD_START_LOOP_TEST(size_parameter_parse_handles_suffixes, ap_size_parameter_parse_cases_len)
{
    const struct ap_size_parameter_parse_case *c = &ap_size_parameter_parse_cases[_i];
    apr_status_t expected_rv = c->expected_rv;
    apr_off_t value = 0;
    apr_status_t rv;

    /* A value which does not fit a narrower apr_off_t is a range error. */
    if (expected_rv == APR_SUCCESS && (apr_off_t)c->expected != c->expected) {
        expected_rv = APR_ERANGE;
    }

    rv = ap_size_parameter_parse(c->input, &value);
    ck_assert_int_eq(rv, expected_rv);
    if (expected_rv == APR_SUCCESS) {
        ck_assert_int_eq(value, (apr_off_t)c->expected);
    }
}
END_TEST


/*
 * ap_parse_retry_after()
 */

#define RA_DATE "Sun, 06 Nov 1994 08:49:37 GMT"
#define RA_BASE APR_INT64_C(784111777)  /* RA_DATE in seconds since the epoch */
#define RA_MAX  (-1)                    /* saturated to APR_INT64_MAX */

struct ap_parse_retry_after_case {
    const char *input;
    const char *date;           /* Date header of the response or NULL */
    apr_int64_t now;            /* local time in seconds */
    apr_status_t expected_rv;
    apr_int64_t expected;       /* delay in seconds */
};

const struct ap_parse_retry_after_case ap_parse_retry_after_cases[] = {
    /* delay-seconds */
    { "0",                    NULL, RA_BASE,       APR_SUCCESS, 0 },
    { "120",                  NULL, RA_BASE,       APR_SUCCESS, 120 },
    { "007",                  NULL, RA_BASE,       APR_SUCCESS, 7 },
    { " \t3\t ",              NULL, RA_BASE,       APR_SUCCESS, 3 },
    { "9223372036853",        NULL, RA_BASE,       APR_SUCCESS, APR_INT64_C(9223372036853) },
    { "9223372036855",        NULL, RA_BASE,       APR_SUCCESS, RA_MAX },
    { "99999999999999999999999999", NULL, RA_BASE, APR_SUCCESS, RA_MAX },
    /* HTTP-date, IMF-fixdate */
    { RA_DATE,                NULL, RA_BASE - 60,  APR_SUCCESS, 60 },
    { RA_DATE,                NULL, RA_BASE,       APR_SUCCESS, 0 },
    { RA_DATE,                NULL, RA_BASE + 60,  APR_SUCCESS, 0 },
    { RA_DATE "  ",           NULL, RA_BASE - 5,   APR_SUCCESS, 5 },
    { "Thu, 01 Jan 1970 00:00:00 GMT", NULL, RA_BASE, APR_SUCCESS, 0 },
    { "Fri, 19 Jan 2038 03:14:07 GMT", NULL, 2147483647 - 9, APR_SUCCESS, 9 },
    { "Sat, 29 Feb 2020 12:00:00 GMT", NULL, APR_INT64_C(1582977600) - 3, APR_SUCCESS, 3 },
    { "Sun, 06 Nov 1994 08:49:60 GMT", NULL, RA_BASE - 3, APR_SUCCESS, 26 },
    /* the day name is checked for its syntax only */
    { "Mon, 06 Nov 1994 08:49:37 GMT", NULL, RA_BASE - 5, APR_SUCCESS, 5 },
    /* HTTP-date, rfc850-date and asctime-date */
    { "Sunday, 06-Nov-94 08:49:37 GMT", NULL, RA_BASE - 5, APR_SUCCESS, 5 },
    { "Sun Nov  6 08:49:37 1994", NULL, RA_BASE - 5, APR_SUCCESS, 5 },
    { "Sun Nov 06 08:49:37 1994", NULL, RA_BASE - 5, APR_SUCCESS, 5 },
    { "Sun Nov 16 08:49:37 1994", NULL, RA_BASE - 5 + 10 * 86400, APR_SUCCESS, 5 },
    /* a two digit year is not more than 50 years in the future */
    { "Sunday, 06-Nov-44 08:49:37 GMT", NULL, RA_BASE, APR_SUCCESS, APR_INT64_C(1577923200) },
    { "Sunday, 06-Nov-45 08:49:37 GMT", NULL, RA_BASE, APR_SUCCESS, 0 },
    /* the Date of the response wins over the local clock */
    { RA_DATE, "Sun, 06 Nov 1994 08:49:07 GMT", RA_BASE + 3600, APR_SUCCESS, 30 },
    { RA_DATE, "Sun, 06 Nov 1994 08:49:07 GMT", RA_BASE - 3600, APR_SUCCESS, 30 },
    { RA_DATE, "Sun, 06 Nov 1994 08:50:07 GMT", RA_BASE - 3600, APR_SUCCESS, 0 },
    /* a Date which is not an HTTP-date is not used */
    { RA_DATE, "garbage",     RA_BASE - 7,         APR_SUCCESS, 7 },
    { RA_DATE, "Sun, 06 Nov 1994 08:49:07 PST", RA_BASE - 7, APR_SUCCESS, 7 },
    { RA_DATE, "",            RA_BASE - 7,         APR_SUCCESS, 7 },
    /* not delay-seconds */
    { "",                     NULL, RA_BASE,       APR_EINVAL, 0 },
    { " \t",                  NULL, RA_BASE,       APR_EINVAL, 0 },
    { "+5",                   NULL, RA_BASE,       APR_EINVAL, 0 },
    { "-5",                   NULL, RA_BASE,       APR_EINVAL, 0 },
    { "5.0",                  NULL, RA_BASE,       APR_EINVAL, 0 },
    { "1e3",                  NULL, RA_BASE,       APR_EINVAL, 0 },
    { "0x10",                 NULL, RA_BASE,       APR_EINVAL, 0 },
    { "1 2",                  NULL, RA_BASE,       APR_EINVAL, 0 },
    { "120, 60",              NULL, RA_BASE,       APR_EINVAL, 0 },
    { "120,",                 NULL, RA_BASE,       APR_EINVAL, 0 },
    { "5 seconds",            NULL, RA_BASE,       APR_EINVAL, 0 },
    /* not an HTTP-date: anything around or after a valid date */
    { RA_DATE ", 120",        NULL, RA_BASE,       APR_EINVAL, 0 },
    { "120, " RA_DATE,        NULL, RA_BASE,       APR_EINVAL, 0 },
    { RA_DATE ", " RA_DATE,   NULL, RA_BASE,       APR_EINVAL, 0 },
    { RA_DATE "junk",         NULL, RA_BASE,       APR_EINVAL, 0 },
    { RA_DATE " 5",           NULL, RA_BASE,       APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37 GMT\r",  NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sunday, 06-Nov-94 08:49:37 GMT, 120", NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun Nov  6 08:49:37 1994 junk",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun Nov  6 08:49:37 1994 GMT",     NULL, RA_BASE, APR_EINVAL, 0 },
    /* not an HTTP-date: a time zone other than GMT */
    { "Sun, 06 Nov 1994 08:49:37 PST",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37 UTC",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37 +0100",  NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37 gmt",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sunday, 06-Nov-94 08:49:37 PST",   NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37",        NULL, RA_BASE, APR_EINVAL, 0 },
    /* not an HTTP-date: the grammar is case sensitive and exact */
    { "Xyz, 06 Nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "sun, 06 Nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 6 Nov 1994 08:49:37 GMT",     NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 94 08:49:37 GMT",      NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 8:49:37 GMT",     NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun,  06 Nov 1994 08:49:37 GMT",   NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37  GMT",   NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06\tNov 1994 08:49:37 GMT",   NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08-49-37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sunday, 06-Nov-1994 08:49:37 GMT", NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06-Nov-94 08:49:37 GMT",      NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sunday, 06 Nov 1994 08:49:37 GMT", NULL, RA_BASE, APR_EINVAL, 0 },
    { "sunday, 06-Nov-94 08:49:37 GMT",   NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun Nov 6 08:49:37 1994",          NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun Nov   6 08:49:37 1994",        NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun Nov  6 08:49:37 94",           NULL, RA_BASE, APR_EINVAL, 0 },
    /* not an HTTP-date: values out of range */
    { "Sun, 00 Nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 32 Nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 31 Apr 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Wed, 29 Feb 1995 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 29 Feb 1900 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Foo 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 24:00:00 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:60:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:61 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 0a Nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 19x4 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 +8:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "not a date",                       NULL, RA_BASE, APR_EINVAL, 0 },
    { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                              NULL, RA_BASE,       APR_EINVAL, 0 },
};

const size_t ap_parse_retry_after_cases_len =
    sizeof(ap_parse_retry_after_cases) /
    sizeof(ap_parse_retry_after_cases[0]);

HTTPD_START_LOOP_TEST(parse_retry_after_handles_seconds_and_dates, ap_parse_retry_after_cases_len)
{
    const struct ap_parse_retry_after_case *c = &ap_parse_retry_after_cases[_i];
    apr_interval_time_t delay = -1;
    apr_status_t rv;

    rv = ap_parse_retry_after(&delay, c->input, c->date,
                              apr_time_from_sec(c->now));
    ck_assert_int_eq(rv, c->expected_rv);
    if (rv == APR_SUCCESS) {
        ck_assert(delay == (c->expected == RA_MAX ? APR_INT64_MAX
                                                  : apr_time_from_sec(c->expected)));
    }
}
END_TEST

START_TEST(parse_retry_after_rejects_null)
{
    apr_interval_time_t delay = 0;

    ck_assert_int_eq(ap_parse_retry_after(&delay, NULL, NULL, 0), APR_EINVAL);
}
END_TEST

/* The delay never wraps around, whatever the local clock says. */
START_TEST(parse_retry_after_saturates_for_extreme_clocks)
{
    const char *far = "Fri, 31 Dec 9999 23:59:59 GMT";
    const char *old = "Sunday, 06-Nov-94 08:49:37 GMT";
    apr_interval_time_t delay;

    delay = 0;
    ck_assert_int_eq(ap_parse_retry_after(&delay, far, NULL, APR_INT64_MIN),
                     APR_SUCCESS);
    ck_assert(delay == APR_INT64_MAX);

    delay = 0;
    ck_assert_int_eq(ap_parse_retry_after(&delay, far, NULL,
                                          APR_INT64_MIN + APR_INT64_C(1000000000000)),
                     APR_SUCCESS);
    ck_assert(delay == APR_INT64_MAX);

    delay = 0;
    ck_assert_int_eq(ap_parse_retry_after(&delay, far, NULL, -1), APR_SUCCESS);
    ck_assert(delay == APR_INT64_C(253402300799) * APR_USEC_PER_SEC + 1);

    /* a two digit year is resolved against any clock, too */
    delay = 0;
    ck_assert_int_eq(ap_parse_retry_after(&delay, old, NULL, APR_INT64_MIN),
                     APR_SUCCESS);
    ck_assert(delay == APR_INT64_MAX);

    delay = -1;
    ck_assert_int_eq(ap_parse_retry_after(&delay, old, NULL, APR_INT64_MAX),
                     APR_SUCCESS);
    ck_assert(delay == 0);
}
END_TEST


/*
 * Test Case Boilerplate
 */
HTTPD_BEGIN_TEST_CASE_WITH_FIXTURE(util, util_setup, util_teardown)
#include "test/unit/util.tests"
HTTPD_END_TEST_CASE
