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

#include "apr_strings.h"
#include "apreq_error.h"
#include "at.h"


static void test_strerror(dAT)
{
    char buf[256], *str;

    str = apreq_strerror(APREQ_ERROR_GENERAL, buf, sizeof buf);
    AT_ptr_eq(str, buf);
    AT_str_eq(str, "Internal apreq error");

    str = apreq_strerror(APREQ_ERROR_TAINTED, buf, sizeof buf);
    AT_str_eq(str, "Attempt to perform unsafe action with tainted data");

    str = apreq_strerror(APREQ_ERROR_BADSEQ, buf, sizeof buf);
    AT_str_eq(str, "Invalid byte sequence");

    str = apreq_strerror(APREQ_ERROR_NODATA, buf, sizeof buf);
    AT_str_eq(str, "Missing input data");

    str = apreq_strerror(APREQ_ERROR_GENERAL+99, buf, sizeof buf);
    AT_str_eq(str, "Error string not yet specified by apreq");




    /* Test some common APR status codes also */

    str = apreq_strerror(APR_EINIT, buf, sizeof buf);
    AT_str_eq(str, "There is no error, this value signifies an initialized "
                   "error code");

    str = apreq_strerror(APR_INCOMPLETE, buf, sizeof buf);
    AT_str_eq(str, "Partial results are valid but processing is incomplete");

    str = apreq_strerror(APR_EOF, buf, sizeof buf);
    AT_str_eq(str, "End of file found");

    str = apreq_strerror(APR_ENOTIMPL, buf, sizeof buf);
    AT_str_eq(str, "This function has not been implemented on this platform");

 }

#define dT(func, plan) #func, func, plan


int main(int argc, char *argv[])
{
    unsigned i, plan = 0;
    apr_pool_t *p;
    dAT;
    at_test_t test_list [] = {
        { dT(test_strerror, 10), "1" }
    };

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&p, NULL);

    AT = at_create(p, 0, at_report_stdout_make(p));

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        plan += test_list[i].plan;

    AT_begin(plan);

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        AT_run(&test_list[i]);

    AT_end();

    return 0;
}
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

#include "apreq_error.h"
#include "apr_strings.h"

/*
 * stuffbuffer - like apr_cpystrn() but returns the address of the
 * dest buffer instead of the address of the terminating '\0'
 */
static char *stuffbuffer(char *buf, apr_size_t bufsize, const char *s)
{
    apr_cpystrn(buf,s,bufsize);
    return buf;
}

static const char *apreq_error_string(apr_status_t statcode)
{
    switch (statcode) {


/* 0's: generic error status codes */

    case APREQ_ERROR_GENERAL:
        return "Internal apreq error";

    case APREQ_ERROR_TAINTED:
        return "Attempt to perform unsafe action with tainted data";


/* 10's: malformed input */

    case APREQ_ERROR_BADDATA:
        return "Malformed input data";

    case APREQ_ERROR_BADCHAR:
        return "Invalid character";

    case APREQ_ERROR_BADSEQ:
        return "Invalid byte sequence";

    case APREQ_ERROR_BADATTR:
        return "Unrecognized attribute";

    case APREQ_ERROR_BADHEADER:
        return "Malformed header string";


/* 20's: missing input */

    case APREQ_ERROR_NODATA:
        return "Missing input data";

    case APREQ_ERROR_NOTOKEN:
        return "Expected token not present";

    case APREQ_ERROR_NOATTR:
        return "Missing attribute";

    case APREQ_ERROR_NOHEADER:
        return "Missing header";

    case APREQ_ERROR_NOPARSER:
        return "Missing parser";


/* 30's: configuration conflicts */

    case APREQ_ERROR_MISMATCH:
        return "Conflicting information";

    case APREQ_ERROR_OVERLIMIT:
        return "Exceeds configured maximum limit";

    case APREQ_ERROR_NOTEMPTY:
        return "Setting already configured";


    default:
        return "Error string not yet specified by apreq";
    }
}


APREQ_DECLARE(char *) apreq_strerror(apr_status_t statcode, char *buf,
                                 apr_size_t bufsize)
{
    if (statcode < APR_OS_START_USERERR || statcode >= APR_OS_START_EAIERR)
        return apr_strerror(statcode, buf, bufsize);
    return stuffbuffer(buf, bufsize, apreq_error_string(statcode));
}

