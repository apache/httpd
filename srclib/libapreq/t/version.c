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

#include "apreq_version.h"
#include "at.h"

static void version_string(dAT, void *ctx)
{
    const char *vstring = apreq_version_string();
    AT_not_null(vstring);
    AT_str_eq(vstring, APREQ_VERSION_STRING);
}
static void version_type(dAT, void *ctx)
{
    apr_version_t v;
    apreq_version(&v);
    AT_int_eq(v.major, APREQ_MAJOR_VERSION);
    AT_int_eq(v.minor, APREQ_MINOR_VERSION);
    AT_int_eq(v.patch, APREQ_PATCH_VERSION);
#ifdef APREQ_IS_DEV_VERSION
    AT_int_eq(v.is_dev, 1);
#else
    AT_int_eq(v.is_dev, 0);
#endif
}

int main(int argc, char *argv[])
{
    apr_pool_t *p;
    unsigned i, plan = 0;
    dAT;
    at_test_t test_list [] = {
        {"version_string", version_string, 2, NULL, "1"},
        {"version_type", version_type, 4}
    };

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&p, NULL);

    AT = at_create(0, at_report_stdout_make());

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        plan += test_list[i].plan;

    AT_begin(plan);

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        AT_run(&test_list[i]);

    AT_end();

    return 0;
}
