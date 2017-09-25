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
 * Test Case Boilerplate
 */
HTTPD_BEGIN_TEST_CASE_WITH_FIXTURE(util, util_setup, util_teardown)
#include "test/unit/util.tests"
HTTPD_END_TEST_CASE
