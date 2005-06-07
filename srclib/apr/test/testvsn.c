/* Copyright 2000-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>

#include "testutil.h"
#include "apr_version.h"
#include "apr_general.h"


static void test_strings(abts_case *tc, void *data)
{
    ABTS_STR_EQUAL(tc, APR_VERSION_STRING, apr_version_string());
}

static void test_ints(abts_case *tc, void *data)
{
    apr_version_t vsn;

    apr_version(&vsn);

    ABTS_INT_EQUAL(tc, APR_MAJOR_VERSION, vsn.major);
    ABTS_INT_EQUAL(tc, APR_MINOR_VERSION, vsn.minor);
    ABTS_INT_EQUAL(tc, APR_PATCH_VERSION, vsn.patch);
}

abts_suite *testvsn(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test_strings, NULL);
    abts_run_test(suite, test_ints, NULL);

    return suite;
}

