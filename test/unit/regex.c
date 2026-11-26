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
#include "ap_regex.h"
#include "apr_strings.h"

/*
 * Test Fixture -- runs once per test
 */

static apr_pool_t *g_pool;

static void regex_setup(void)
{
    if (apr_pool_create(&g_pool, NULL) != APR_SUCCESS) {
        exit(1);
    }
}

static void regex_teardown(void)
{
    apr_pool_destroy(g_pool);
}

/*
 * ap_regexec() must fill every slot of the vector: groups which did not
 * participate in the match (and slots beyond the last group) get -1/-1.
 */

START_TEST(regexec_fills_unused_slots_with_minus_one)
{
    ap_regex_t re;
    ap_regmatch_t pmatch[AP_MAX_REG_MATCH];
    int i;

    for (i = 0; i < AP_MAX_REG_MATCH; ++i) {
        pmatch[i].rm_so = pmatch[i].rm_eo = 12345;
    }

    ck_assert_int_eq(ap_regcomp(&re, "^(a)(x)?(c)?", 0), 0);
    ck_assert_int_eq(ap_regexec(&re, "abc", AP_MAX_REG_MATCH, pmatch, 0), 0);

    ck_assert_int_eq(pmatch[0].rm_so, 0);
    ck_assert_int_eq(pmatch[0].rm_eo, 1);
    ck_assert_int_eq(pmatch[1].rm_so, 0);
    ck_assert_int_eq(pmatch[1].rm_eo, 1);
    for (i = 2; i < AP_MAX_REG_MATCH; ++i) {
        ck_assert_int_eq(pmatch[i].rm_so, -1);
        ck_assert_int_eq(pmatch[i].rm_eo, -1);
    }
    ap_regfree(&re);
}
END_TEST

/*
 * ap_pregsub() with a match vector that was never (fully) filled in: slots
 * with negative or inverted offsets must expand to nothing.
 */

struct ap_pregsub_case {
    const char *input;
    const char *source;
    ap_regmatch_t pmatch[3];
    const char *expected;
};

const struct ap_pregsub_case ap_pregsub_cases[] = {
    /* a regular match */
    { "<$0|$1|$2>", "abc", { {0, 3}, {1, 2}, {-1, -1} }, "<abc|b|>" },
    /* nothing matched at all (as ap_regexec() leaves a reset vector) */
    { "<$0|$1|$2>", "abc", { {-1, -1}, {-1, -1}, {-1, -1} }, "<||>" },
    /* negative start, positive end */
    { "<$1>", "abc", { {0, 3}, {-1, 2}, {-1, -1} }, "<>" },
    /* negative start, negative end but inverted */
    { "<$1>", "abc", { {0, 3}, {-5, -1}, {-1, -1} }, "<>" },
    /* inverted offsets: negative length */
    { "<$1>", "abc", { {0, 3}, {2, 1}, {-1, -1} }, "<>" },
    /* empty group */
    { "<$1>", "abc", { {0, 3}, {1, 1}, {-1, -1} }, "<>" },
    /* a group above nmatch is ignored */
    { "<$5>", "abc", { {0, 3}, {1, 2}, {-1, -1} }, "<>" },
};

const size_t ap_pregsub_cases_len = sizeof(ap_pregsub_cases) /
                                    sizeof(ap_pregsub_cases[0]);

HTTPD_START_LOOP_TEST(pregsub_rejects_bogus_offsets, ap_pregsub_cases_len)
{
    const struct ap_pregsub_case *c = &ap_pregsub_cases[_i];
    ap_regmatch_t pmatch[3];
    char *result;

    memcpy(pmatch, c->pmatch, sizeof(pmatch));
    result = ap_pregsub(g_pool, c->input, c->source, 3, pmatch);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, c->expected);
}
END_TEST

/*
 * ap_rxplus_match() must not hand out a pointer/length for a group which
 * did not participate in the match.
 */

START_TEST(rxplus_match_rejects_unset_groups)
{
    ap_rxplus_t *rx = ap_rxplus_compile(g_pool, "/^(a)(x)?(c)?/");
    const char *match = NULL;
    int len = 0;

    ck_assert_ptr_nonnull(rx);
    ck_assert_int_eq(ap_rxplus_exec(g_pool, rx, "abc", NULL), 1);

    ap_rxplus_match(rx, 1, &len, &match);
    ck_assert_int_eq(len, 1);
    ck_assert_ptr_nonnull(match);
    ck_assert_int_eq(match[0], 'a');

    match = NULL;
    len = 0;
    ap_rxplus_match(rx, 2, &len, &match);
    ck_assert_int_eq(len, -1);
    ck_assert_ptr_null(match);
}
END_TEST

/*
 * ap_rxplus_exec() with the 'g' flag must terminate on patterns that match
 * the empty string, and still substitute all non-empty matches.
 */

struct ap_rxplus_exec_case {
    const char *expr;
    const char *subject;
    const char *expected;
};

const struct ap_rxplus_exec_case ap_rxplus_exec_cases[] = {
    { "s/b/-/g",   "abcb", "a-c-" },
    /* leftmost match is empty at offset 0: substituted once, no recursion */
    { "s/x*/-/g",  "abc",  "-abc" },
    { "s/b*/-/g",  "abc",  "-abc" },
    { "s/^/-/g",   "abc",  "-abc" },
    /* non-empty match consumed, then a single empty match on the empty
     * remainder, then no further recursion */
    { "s/c*$/-/g", "abc",  "ab--" },
    { "s/b+/-/g",  "abbc", "a-c" },
};

const size_t ap_rxplus_exec_cases_len = sizeof(ap_rxplus_exec_cases) /
                                        sizeof(ap_rxplus_exec_cases[0]);

HTTPD_START_LOOP_TEST(rxplus_exec_terminates_on_empty_matches, ap_rxplus_exec_cases_len)
{
    const struct ap_rxplus_exec_case *c = &ap_rxplus_exec_cases[_i];
    ap_rxplus_t *rx = ap_rxplus_compile(g_pool, c->expr);
    char *result = NULL;

    ck_assert_ptr_nonnull(rx);
    ck_assert_int_ge(ap_rxplus_exec(g_pool, rx, c->subject, &result), 1);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, c->expected);
}
END_TEST

/*
 * Test Case Boilerplate
 */
HTTPD_BEGIN_TEST_CASE_WITH_FIXTURE(regex, regex_setup, regex_teardown)
#include "test/unit/regex.tests"
HTTPD_END_TEST_CASE
