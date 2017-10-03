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

#include "httpdunit.h"

#include "apr_general.h"

static Suite *main_test_suite(void)
{
    Suite *suite = suite_create("main");

    /* The list of test cases is automatically generated from the test/unit
     * directory by the build system. */
#   include "test/httpdunit.cases"

    return suite;
}

int main(int argc, const char * const argv[])
{
    SRunner *runner;
    int failed;

    /* Initialize APR and create our test runner. */
    apr_app_initialize(&argc, &argv, NULL);
    runner = srunner_create(main_test_suite());

    /* Log TAP to stdout. */
    srunner_set_tap(runner, "-");

    /* Run the tests and collect failures. */
    srunner_run_all(runner, CK_SILENT /* output only TAP */);
    failed = srunner_ntests_failed(runner);

    /* Clean up. */
    srunner_free(runner);
    apr_terminate();

    return failed ? 1 : 0;
}
