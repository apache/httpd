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

/* XXX This'll almost certainly cause headaches... Need a better way to test
 * module helper functions.
 *
 * - What if the user doesn't want to, or can't, build mod_auth_digest?
 * - How do we make sure the Makefile rebuilds us when the module changes?
 */
#include "../../modules/aaa/mod_auth_digest.c"

/*
 * Test Fixture -- runs once per test
 */

static apr_pool_t  *g_pool;
static request_rec *g_request;

/* XXX: duplicated from the authn.c tests; find a way to pull this into a helper
 * library */
static void mod_auth_digest_setup(void)
{
    if (apr_pool_create(&g_pool, NULL) != APR_SUCCESS) {
        exit(1);
    }

    /* Stub out just enough of a request_req to get the tests working.
     * Unfortunately this couples us to implementation details in the code being
     * tested, but the logic to get a "real" request_rec requires spinning up
     * half of the world. */
    g_request = apr_pcalloc(g_pool, sizeof(*g_request));
    if (!g_request) {
        exit(1);
    }

    g_request->pool = g_pool;
    g_request->headers_in = apr_table_make(g_pool, 1);

    if (!g_request->headers_in) {
        exit(1);
    }
}

static void mod_auth_digest_teardown(void)
{
    apr_pool_destroy(g_pool);
}

/*
 * get_digest_rec()
 *
 * Note that this function is an implementation detail, so the tests might not
 * have the longest lifetime.
 */

/* TODO: more functional tests! */

START_TEST(get_digest_rec_uses_empty_string_for_key_without_value)
{
    digest_header_rec resp = { 0 };
    apr_table_set(g_request->headers_in, "Authorization",
                  "Digest username=user, nc");

    get_digest_rec(g_request, &resp);

    ck_assert_str_eq(resp.username,    "user");
    ck_assert_str_eq(resp.nonce_count, "");
}
END_TEST

/*
 * Regression test for CVE-2017-9788. Note that it only reliably fails if APR
 * fills memory with something other than NULL; otherwise you can get false
 * positives. But it's better than nothing.
 */
START_TEST(get_digest_rec_does_not_use_uninitialized_memory_for_key_without_value)
{
    digest_header_rec resp = { 0 };
    apr_table_set(g_request->headers_in, "Authorization", "Digest nc");

    get_digest_rec(g_request, &resp);

    ck_assert_str_eq(resp.nonce_count, "");
}
END_TEST

/*
 * Test Case Boilerplate
 */
HTTPD_BEGIN_TEST_CASE_WITH_FIXTURE(mod_auth_digest, mod_auth_digest_setup, mod_auth_digest_teardown)
#include "test/unit/mod_auth_digest.tests"
HTTPD_END_TEST_CASE
