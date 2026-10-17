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
 * Test Case Boilerplate
 */
HTTPD_BEGIN_TEST_CASE_WITH_FIXTURE(util, util_setup, util_teardown)
#include "test/unit/util.tests"
HTTPD_END_TEST_CASE
