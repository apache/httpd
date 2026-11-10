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

/*
 * Regression test for md_util_parse_retry_after() (modules/md/md_util.c).
 *
 * This links against the same $(MD_LIB_OBJS) as the a2md binary, so it
 * exercises the exact object code a2md ships, built without httpd
 * (MD_A2MD_BUILD). mod_md compiles md_util.c again, without that define,
 * to link it into its own DSO, but it is the same source with the same
 * function body: there is only one implementation of the parser, and
 * this is its only regression test.
 *
 * Plain pass/fail on stdout, non-zero exit on any failure: a2md does not
 * link libcheck, so this avoids adding that dependency just for a test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <apr_general.h>
#include <apr_time.h>

#include "md_util.h"

#define RA_DATE "Sun, 06 Nov 1994 08:49:37 GMT"
#define RA_BASE APR_INT64_C(784111777)  /* RA_DATE in seconds since the epoch */
#define RA_MAX  (-1)                    /* saturated to APR_INT64_MAX */

struct retry_after_case {
    const char *input;
    const char *date;           /* Date header of the response or NULL */
    apr_int64_t now;            /* local time in seconds */
    apr_status_t expected_rv;
    apr_int64_t expected;       /* delay in seconds */
};

static const struct retry_after_case cases[] = {
    /* delay-seconds */
    { "0",                    NULL, RA_BASE,       APR_SUCCESS, 0 },
    { "120",                  NULL, RA_BASE,       APR_SUCCESS, 120 },
    { "007",                  NULL, RA_BASE,       APR_SUCCESS, 7 },
    { " \t3\t ",              NULL, RA_BASE,       APR_SUCCESS, 3 },
    { "9223372036853",        NULL, RA_BASE,       APR_SUCCESS, APR_INT64_C(9223372036853) },
    { "9223372036855",        NULL, RA_BASE,       APR_SUCCESS, RA_MAX },
    { "99999999999999999999999999", NULL, RA_BASE, APR_SUCCESS, RA_MAX },
    /* HTTP-date, IMF-fixdate */
    { RA_DATE,                NULL, RA_BASE - 60,  APR_SUCCESS, 60 },
    { RA_DATE,                NULL, RA_BASE,       APR_SUCCESS, 0 },
    { RA_DATE,                NULL, RA_BASE + 60,  APR_SUCCESS, 0 },
    { RA_DATE "  ",           NULL, RA_BASE - 5,   APR_SUCCESS, 5 },
    { "Thu, 01 Jan 1970 00:00:00 GMT", NULL, RA_BASE, APR_SUCCESS, 0 },
    { "Fri, 19 Jan 2038 03:14:07 GMT", NULL, 2147483647 - 9, APR_SUCCESS, 9 },
    { "Sat, 29 Feb 2020 12:00:00 GMT", NULL, APR_INT64_C(1582977600) - 3, APR_SUCCESS, 3 },
    { "Sun, 06 Nov 1994 08:49:60 GMT", NULL, RA_BASE - 3, APR_SUCCESS, 26 },
    /* the day name is checked for its syntax only */
    { "Mon, 06 Nov 1994 08:49:37 GMT", NULL, RA_BASE - 5, APR_SUCCESS, 5 },
    /* HTTP-date, rfc850-date and asctime-date */
    { "Sunday, 06-Nov-94 08:49:37 GMT", NULL, RA_BASE - 5, APR_SUCCESS, 5 },
    { "Sun Nov  6 08:49:37 1994", NULL, RA_BASE - 5, APR_SUCCESS, 5 },
    { "Sun Nov 06 08:49:37 1994", NULL, RA_BASE - 5, APR_SUCCESS, 5 },
    { "Sun Nov 16 08:49:37 1994", NULL, RA_BASE - 5 + 10 * 86400, APR_SUCCESS, 5 },
    /* a two digit year is not more than 50 years in the future */
    { "Sunday, 06-Nov-44 08:49:37 GMT", NULL, RA_BASE, APR_SUCCESS, APR_INT64_C(1577923200) },
    { "Sunday, 06-Nov-45 08:49:37 GMT", NULL, RA_BASE, APR_SUCCESS, 0 },
    /* the Date of the response wins over the local clock */
    { RA_DATE, "Sun, 06 Nov 1994 08:49:07 GMT", RA_BASE + 3600, APR_SUCCESS, 30 },
    { RA_DATE, "Sun, 06 Nov 1994 08:49:07 GMT", RA_BASE - 3600, APR_SUCCESS, 30 },
    { RA_DATE, "Sun, 06 Nov 1994 08:50:07 GMT", RA_BASE - 3600, APR_SUCCESS, 0 },
    /* a Date which is not an HTTP-date is not used */
    { RA_DATE, "garbage",     RA_BASE - 7,         APR_SUCCESS, 7 },
    { RA_DATE, "Sun, 06 Nov 1994 08:49:07 PST", RA_BASE - 7, APR_SUCCESS, 7 },
    { RA_DATE, "",            RA_BASE - 7,         APR_SUCCESS, 7 },
    /* not delay-seconds */
    { "",                     NULL, RA_BASE,       APR_EINVAL, 0 },
    { " \t",                  NULL, RA_BASE,       APR_EINVAL, 0 },
    { "+5",                   NULL, RA_BASE,       APR_EINVAL, 0 },
    { "-5",                   NULL, RA_BASE,       APR_EINVAL, 0 },
    { "5.0",                  NULL, RA_BASE,       APR_EINVAL, 0 },
    { "1e3",                  NULL, RA_BASE,       APR_EINVAL, 0 },
    { "0x10",                 NULL, RA_BASE,       APR_EINVAL, 0 },
    { "1 2",                  NULL, RA_BASE,       APR_EINVAL, 0 },
    { "120, 60",              NULL, RA_BASE,       APR_EINVAL, 0 },
    { "120,",                 NULL, RA_BASE,       APR_EINVAL, 0 },
    { "5 seconds",            NULL, RA_BASE,       APR_EINVAL, 0 },
    /* not an HTTP-date: anything around or after a valid date */
    { RA_DATE ", 120",        NULL, RA_BASE,       APR_EINVAL, 0 },
    { "120, " RA_DATE,        NULL, RA_BASE,       APR_EINVAL, 0 },
    { RA_DATE ", " RA_DATE,   NULL, RA_BASE,       APR_EINVAL, 0 },
    { RA_DATE "junk",         NULL, RA_BASE,       APR_EINVAL, 0 },
    { RA_DATE " 5",           NULL, RA_BASE,       APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37 GMT\r",  NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sunday, 06-Nov-94 08:49:37 GMT, 120", NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun Nov  6 08:49:37 1994 junk",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun Nov  6 08:49:37 1994 GMT",     NULL, RA_BASE, APR_EINVAL, 0 },
    /* not an HTTP-date: a time zone other than GMT */
    { "Sun, 06 Nov 1994 08:49:37 PST",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37 UTC",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37 +0100",  NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37 gmt",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sunday, 06-Nov-94 08:49:37 PST",   NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37",        NULL, RA_BASE, APR_EINVAL, 0 },
    /* not an HTTP-date: the grammar is case sensitive and exact */
    { "Xyz, 06 Nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "sun, 06 Nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 6 Nov 1994 08:49:37 GMT",     NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 94 08:49:37 GMT",      NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 8:49:37 GMT",     NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun,  06 Nov 1994 08:49:37 GMT",   NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:37  GMT",   NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06\tNov 1994 08:49:37 GMT",   NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08-49-37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sunday, 06-Nov-1994 08:49:37 GMT", NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06-Nov-94 08:49:37 GMT",      NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sunday, 06 Nov 1994 08:49:37 GMT", NULL, RA_BASE, APR_EINVAL, 0 },
    { "sunday, 06-Nov-94 08:49:37 GMT",   NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun Nov 6 08:49:37 1994",          NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun Nov   6 08:49:37 1994",        NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun Nov  6 08:49:37 94",           NULL, RA_BASE, APR_EINVAL, 0 },
    /* not an HTTP-date: values out of range */
    { "Sun, 00 Nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 32 Nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 31 Apr 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Wed, 29 Feb 1995 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 29 Feb 1900 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Foo 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 24:00:00 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:60:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 08:49:61 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 0a Nov 1994 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 19x4 08:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "Sun, 06 Nov 1994 +8:49:37 GMT",    NULL, RA_BASE, APR_EINVAL, 0 },
    { "not a date",                       NULL, RA_BASE, APR_EINVAL, 0 },
    { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                              NULL, RA_BASE,       APR_EINVAL, 0 },
};

static int run_case(size_t i, const struct retry_after_case *c)
{
    apr_interval_time_t delay = -1;
    apr_status_t rv = md_util_parse_retry_after(&delay, c->input, c->date,
                                                apr_time_from_sec(c->now));
    apr_interval_time_t expected_delay = c->expected == RA_MAX
        ? APR_INT64_MAX : apr_time_from_sec(c->expected);

    if (rv != c->expected_rv) {
        printf("FAIL [%lu] %-12s rv=%d expected=%d\n",
              (unsigned long)i, c->input, (int)rv, (int)c->expected_rv);
        return 0;
    }
    if (rv == APR_SUCCESS && delay != expected_delay) {
        printf("FAIL [%lu] %-12s delay=%" APR_INT64_T_FMT
              " expected=%" APR_INT64_T_FMT "\n",
              (unsigned long)i, c->input, (apr_int64_t)delay,
              (apr_int64_t)expected_delay);
        return 0;
    }
    return 1;
}

static int test_extreme_clocks(void)
{
    const char *far = "Fri, 31 Dec 9999 23:59:59 GMT";
    const char *old = "Sunday, 06-Nov-94 08:49:37 GMT";
    apr_interval_time_t delay;
    int ok = 1;

    delay = 0;
    if (md_util_parse_retry_after(&delay, far, NULL, APR_INT64_MIN) != APR_SUCCESS
        || delay != APR_INT64_MAX) {
        printf("FAIL extreme_clocks: far/APR_INT64_MIN\n");
        ok = 0;
    }

    delay = 0;
    if (md_util_parse_retry_after(&delay, far, NULL,
                                  APR_INT64_MIN + APR_INT64_C(1000000000000)) != APR_SUCCESS
        || delay != APR_INT64_MAX) {
        printf("FAIL extreme_clocks: far/near-min\n");
        ok = 0;
    }

    delay = 0;
    if (md_util_parse_retry_after(&delay, far, NULL, -1) != APR_SUCCESS
        || delay != APR_INT64_C(253402300799) * APR_USEC_PER_SEC + 1) {
        printf("FAIL extreme_clocks: far/-1\n");
        ok = 0;
    }

    /* a two digit year is resolved against any clock, too */
    delay = 0;
    if (md_util_parse_retry_after(&delay, old, NULL, APR_INT64_MIN) != APR_SUCCESS
        || delay != APR_INT64_MAX) {
        printf("FAIL extreme_clocks: old/APR_INT64_MIN\n");
        ok = 0;
    }

    delay = -1;
    if (md_util_parse_retry_after(&delay, old, NULL, APR_INT64_MAX) != APR_SUCCESS
        || delay != 0) {
        printf("FAIL extreme_clocks: old/APR_INT64_MAX\n");
        ok = 0;
    }

    return ok;
}

int main(int argc, const char * const *argv)
{
    size_t i;
    int failures = 0;
    apr_interval_time_t delay = 0;
    apr_status_t rv;

    rv = apr_app_initialize(&argc, &argv, NULL);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "error initializing APR (error code %d)\n", (int)rv);
        return 1;
    }
    if (atexit(apr_terminate)) {
        perror("error registering atexit");
        return 1;
    }

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (!run_case(i, &cases[i])) {
            ++failures;
        }
    }
    if (md_util_parse_retry_after(&delay, NULL, NULL, 0) != APR_EINVAL) {
        printf("FAIL rejects_null\n");
        ++failures;
    }
    if (!test_extreme_clocks()) {
        ++failures;
    }

    if (failures) {
        printf("%d of %lu cases failed\n", failures,
              (unsigned long)(sizeof(cases) / sizeof(cases[0]) + 2));
        return 1;
    }
    printf("All %lu md_util_parse_retry_after() cases passed\n",
          (unsigned long)(sizeof(cases) / sizeof(cases[0]) + 2));
    return 0;
}
