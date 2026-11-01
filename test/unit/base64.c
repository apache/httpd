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

static void base64_setup(void)
{
    if (apr_pool_create(&g_pool, NULL) != APR_SUCCESS) {
        exit(1);
    }
}

static void base64_teardown(void)
{
    apr_pool_destroy(g_pool);
}

/*
 * Tests
 */

/*
 * case[0]: encoded value
 * case[1]: expected decoded value
 */
static const char * const base64_cases[][2] = {
    /* Test case 1 derived from RFC 3548 sec. 7. */
    { "FPucA9l+", "\x14\xfb\x9c\x03\xd9\x7e" },
    { "aGVsbG8=", "hello" },
    { "dGVzdA==", "test" },
    { "",          "" },
};
static const size_t base64_cases_len = sizeof(base64_cases) /
                                       sizeof(base64_cases[0]);

HTTPD_START_LOOP_TEST(strict_decoding_works, base64_cases_len)
{
    const char *encoded  = base64_cases[_i][0];
    const char *expected = base64_cases[_i][1];
    char *decoded;
    apr_size_t len;
    apr_status_t status;

    status = ap_pbase64decode_strict(g_pool, encoded, &decoded, &len);

    ck_assert_int_eq(status, APR_SUCCESS);
    ck_assert_uint_eq(len, strlen(expected));
    ck_assert(!memcmp(decoded, expected, len));
}
END_TEST

START_TEST(strict_decoding_works_with_embedded_nulls)
{
    static unsigned char expected[] = { 'n', '\0', 'u', '\0', 'l', '\0', 'l' };
    char *decoded;
    apr_size_t len;
    apr_status_t status;

    status = ap_pbase64decode_strict(g_pool, "bgB1AGwAbA==", &decoded, &len);

    ck_assert_int_eq(status, APR_SUCCESS);
    ck_assert_uint_eq(len, sizeof(expected));
    ck_assert(!memcmp(decoded, expected, len));
}
END_TEST

START_TEST(strict_decoding_produces_null_terminated_buffer)
{
    char *decoded;
    apr_size_t len;

    ap_pbase64decode_strict(g_pool, "aaaabbbbccccdddd", &decoded, &len);

    ck_assert(decoded[len] == '\0');
}
END_TEST

START_TEST(strict_decoding_allows_all_base64_characters)
{
    char *decoded;
    apr_size_t len;
    apr_status_t status;

    status = ap_pbase64decode_strict(g_pool,
                                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                     "abcdefghijklmnopqrstuvwxyz"
                                     "0123456789+/",
                                     &decoded, &len);;

    ck_assert_int_eq(status, APR_SUCCESS);
}
END_TEST

static const char * const invalid_chars[] = {
    "bad?",
    "not-good",
    "also_bad",
    "a\x01sd",
};
static const size_t invalid_chars_len = sizeof(invalid_chars) /
                                        sizeof(invalid_chars[0]);

HTTPD_START_LOOP_TEST(strict_decoding_rejects_non_base64_characters, invalid_chars_len)
{
    char *decoded = NULL;
    apr_size_t len = (apr_size_t) -1;
    apr_status_t status;

    status = ap_pbase64decode_strict(g_pool, invalid_chars[_i], &decoded, &len);

    ck_assert_int_eq(status, APR_EINVAL);
    ck_assert(decoded == NULL);
    ck_assert_uint_eq(len, (apr_size_t) -1);
}
END_TEST

static const char * const invalid_padding[] = {
    "AAAA=",    /* no padding needed here */
    "AA=",      /* not enough padding */
    "AA===",    /* too much padding */
    "A===",     /* only one or two padding characters allowed */
    "A==",
    "==",
    "AAA=AAA=", /* mid-string padding prohibited */
    "AAA",      /* missing padding entirely */
    "AA",       /* missing padding entirely */
    "A",        /* just completely wrong */
    "AAb=",     /* one-padded strings must end in one of AEIMQUYcgkosw048 */
    "Ab==",     /* two-padded strings must end in one of AQgw */
};
static const size_t invalid_padding_len = sizeof(invalid_padding) /
                                          sizeof(invalid_padding[0]);

HTTPD_START_LOOP_TEST(strict_decoding_rejects_incorrect_padding, invalid_padding_len)
{
    char *decoded = NULL;
    apr_size_t len = (apr_size_t) -1;
    apr_status_t status;

    status = ap_pbase64decode_strict(g_pool, invalid_padding[_i], &decoded,
                                     &len);

    ck_assert_int_eq(status, APR_EINVAL);
    ck_assert(decoded == NULL);
    ck_assert_uint_eq(len, (apr_size_t) -1);
}
END_TEST

/*
 * Test Case Boilerplate
 */
HTTPD_BEGIN_TEST_CASE_WITH_FIXTURE(base64, base64_setup, base64_teardown)
#include "test/unit/base64.tests"
HTTPD_END_TEST_CASE
