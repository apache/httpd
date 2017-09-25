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
#include "http_config.h"
#include "http_protocol.h"

/*
 * Test Fixture -- runs once per test
 */

static apr_pool_t  *g_pool;
static request_rec *g_request;

static void authn_setup(void)
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

static void authn_teardown(void)
{
    apr_pool_destroy(g_pool);
}

/*
 * ap_get_basic_auth_components()
 */

static const char * const basic_auth_cases[][3] = {
    /*
     * case[0] - Authorization header value
     * case[1] - expected username
     * case[2] - expected password
     */
    { "Basic Ym9iOm15cGFzcw==",    "bob", "mypass" },
    { "Basic    Ym9iOm15cGFzcw==", "bob", "mypass" },
    { "Basic Ym9iOg==",            "bob", "" },
    { "Basic Om15cGFzcw==",        "",    "mypass" },
    { "Basic Og==",                "",    "" },

    /*
     * Dubious compatibility cases
     */

    /* HT is disallowed per 7235, but ap_get_basic_auth_pw() allowed it */
    { "Basic \tYm9iOm15cGFzcw==",  "bob", "mypass" },
    /* username without colon separator, technically disallowed per 2617 */
    { "Basic Ym9i",                "bob", "" },
    /* no data at all, technically disallowed per 2617/7235 */
    { "Basic ",                    "",    "" },
    { "Basic",                     "",    "" },
    /* completely invalid junk, disallowed per 2617/7235 */
    { "Basic ?*J#kd92%$@",         "",    "" },
};
static const size_t basic_auth_cases_len = sizeof(basic_auth_cases) /
                                           sizeof(basic_auth_cases[0]);

HTTPD_START_LOOP_TEST(test_get_basic_auth_components_correctly_decodes_credentials, basic_auth_cases_len)
{
    const char *header_val    = basic_auth_cases[_i][0];
    const char *expected_user = basic_auth_cases[_i][1];
    const char *expected_pass = basic_auth_cases[_i][2];

    apr_status_t status;
    const char *username;
    const char *password;

    apr_table_setn(g_request->headers_in, "Authorization", header_val);

    status = ap_get_basic_auth_components(g_request, &username, &password);

    ck_assert_int_eq(status, APR_SUCCESS);
    ck_assert_str_eq(username, expected_user);
    ck_assert_str_eq(password, expected_pass);
}
END_TEST

START_TEST(test_get_basic_auth_components_fails_without_Authorization_header)
{
    apr_status_t status;

    status = ap_get_basic_auth_components(g_request, NULL, NULL);
    ck_assert_int_eq(status, APR_EINVAL);
}
END_TEST

START_TEST(test_get_basic_auth_components_fails_with_non_Basic_credentials)
{
    apr_status_t status;

    apr_table_setn(g_request->headers_in, "Authorization",
                   "Digest Ym9iOm15cGFzcw==");

    status = ap_get_basic_auth_components(g_request, NULL, NULL);
    ck_assert_int_eq(status, APR_EINVAL);
}
END_TEST

START_TEST(test_get_basic_auth_components_uses_Proxy_Authorization_for_proxied_requests)
{
    apr_status_t status;
    const char *username;
    const char *password;

    g_request->proxyreq = PROXYREQ_PROXY;
    apr_table_setn(g_request->headers_in, "Proxy-Authorization",
                   "Basic Ym9iOm15cGFzcw==");

    status = ap_get_basic_auth_components(g_request, &username, &password);

    ck_assert_int_eq(status, APR_SUCCESS);
    ck_assert_str_eq(username, "bob");
    ck_assert_str_eq(password, "mypass");
}
END_TEST

/*
 * Test Case Boilerplate
 */
HTTPD_BEGIN_TEST_CASE_WITH_FIXTURE(authn, authn_setup, authn_teardown)
#include "test/unit/authn.tests"
HTTPD_END_TEST_CASE
