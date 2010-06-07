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

#include "util_time.h"


/* Number of characters needed to format the microsecond part of a timestamp.
 * Microseconds have 6 digits plus one separator character makes 7.
 *   */
#define AP_CTIME_USEC_LENGTH      7


/* Cache for exploded values of recent timestamps
 */

struct exploded_time_cache_element {
    apr_int64_t t;
    apr_time_exp_t xt;
    apr_int64_t t_validate; /* please see comments in cached_explode() */
};

/* the "+ 1" is for the current second: */
#define TIME_CACHE_SIZE (AP_TIME_RECENT_THRESHOLD + 1)

/* Note that AP_TIME_RECENT_THRESHOLD is defined to
 * be a power of two minus one in util_time.h, so that
 * we can replace a modulo operation with a bitwise AND
 * when hashing items into a cache of size
 * AP_TIME_RECENT_THRESHOLD+1
 */
#define TIME_CACHE_MASK (AP_TIME_RECENT_THRESHOLD)

static struct exploded_time_cache_element exploded_cache_localtime[TIME_CACHE_SIZE];
static struct exploded_time_cache_element exploded_cache_gmt[TIME_CACHE_SIZE];


static apr_status_t cached_explode(apr_time_exp_t *xt, apr_time_t t,
                                   struct exploded_time_cache_element *cache,
                                   int use_gmt)
{
    apr_int64_t seconds = apr_time_sec(t);
    struct exploded_time_cache_element *cache_element =
        &(cache[seconds & TIME_CACHE_MASK]);
    struct exploded_time_cache_element cache_element_snapshot;

    /* The cache is implemented as a ring buffer.  Each second,
     * it uses a different element in the buffer.  The timestamp
     * in the element indicates whether the element contains the
     * exploded time for the current second (vs the time
     * 'now - AP_TIME_RECENT_THRESHOLD' seconds ago).  If the
     * cached value is for the current time, we use it.  Otherwise,
     * we compute the apr_time_exp_t and store it in this
     * cache element. Note that the timestamp in the cache
     * element is updated only after the exploded time.  Thus
     * if two threads hit this cache element simultaneously
     * at the start of a new second, they'll both explode the
     * time and store it.  I.e., the writers will collide, but
     * they'll be writing the same value.
     */
    if (cache_element->t >= seconds) {
        /* There is an intentional race condition in this design:
         * in a multithreaded app, one thread might be reading
         * from this cache_element to resolve a timestamp from
         * TIME_CACHE_SIZE seconds ago at the same time that
         * another thread is copying the exploded form of the
         * current time into the same cache_element.  (I.e., the
         * first thread might hit this element of the ring buffer
         * just as the element is being recycled.)  This can
         * also happen at the start of a new second, if a
         * reader accesses the cache_element after a writer
         * has updated cache_element.t but before the writer
         * has finished updating the whole cache_element.
         *
         * Rather than trying to prevent this race condition
         * with locks, we allow it to happen and then detect
         * and correct it.  The detection works like this:
         *   Step 1: Take a "snapshot" of the cache element by
         *           copying it into a temporary buffer.
         *   Step 2: Check whether the snapshot contains consistent
         *           data: the timestamps at the start and end of
         *           the cache_element should both match the 'seconds'
         *           value that we computed from the input time.
         *           If these three don't match, then the snapshot
         *           shows the cache_element in the middle of an
         *           update, and its contents are invalid.
         *   Step 3: If the snapshot is valid, use it.  Otherwise,
         *           just give up on the cache and explode the
         *           input time.
         */
        memcpy(&cache_element_snapshot, cache_element,
               sizeof(struct exploded_time_cache_element));
        if ((seconds != cache_element_snapshot.t) ||
            (seconds != cache_element_snapshot.t_validate)) {
            /* Invalid snapshot */
            if (use_gmt) {
                return apr_time_exp_gmt(xt, t);
            }
            else {
                return apr_time_exp_lt(xt, t);
            }
        }
        else {
            /* Valid snapshot */
            memcpy(xt, &(cache_element_snapshot.xt),
                   sizeof(apr_time_exp_t));
        }
    }
    else {
        apr_status_t r;
        if (use_gmt) {
            r = apr_time_exp_gmt(xt, t);
        }
        else {
            r = apr_time_exp_lt(xt, t);
        }
        if (r != APR_SUCCESS) {
            return r;
        }
        cache_element->t = seconds;
        memcpy(&(cache_element->xt), xt, sizeof(apr_time_exp_t));
        cache_element->t_validate = seconds;
    }
    xt->tm_usec = (int)apr_time_usec(t);
    return APR_SUCCESS;
}


AP_DECLARE(apr_status_t) ap_explode_recent_localtime(apr_time_exp_t * tm,
                                                     apr_time_t t)
{
    return cached_explode(tm, t, exploded_cache_localtime, 0);
}

AP_DECLARE(apr_status_t) ap_explode_recent_gmt(apr_time_exp_t * tm,
                                               apr_time_t t)
{
    return cached_explode(tm, t, exploded_cache_gmt, 1);
}

AP_DECLARE(apr_status_t) ap_recent_ctime(char *date_str, apr_time_t t)
{
    int len = APR_CTIME_LEN;
    return ap_recent_ctime_ex(date_str, t, AP_CTIME_OPTION_NONE, &len);
}

AP_DECLARE(apr_status_t) ap_recent_ctime_ex(char *date_str, apr_time_t t,
                                            int option, int *len)
{
    /* ### This code is a clone of apr_ctime(), except that it
     * uses ap_explode_recent_localtime() instead of apr_time_exp_lt().
     */
    apr_time_exp_t xt;
    const char *s;
    int real_year;
    int needed;


    /* Calculate the needed buffer length */
    needed = APR_CTIME_LEN;
    if (option & AP_CTIME_OPTION_USEC) {
        needed += AP_CTIME_USEC_LENGTH;
    }

    /* Check the provided buffer length */
    if (len && *len >= needed) {
        *len = needed;
    }
    else {
        if (len != NULL) {
            *len = 0;
        }
        return APR_ENOMEM;
    }

    /* example without options: "Wed Jun 30 21:49:08 1993" */
    /*                           123456789012345678901234  */

    ap_explode_recent_localtime(&xt, t);
    s = &apr_day_snames[xt.tm_wday][0];
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = ' ';
    s = &apr_month_snames[xt.tm_mon][0];
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = ' ';
    *date_str++ = xt.tm_mday / 10 + '0';
    *date_str++ = xt.tm_mday % 10 + '0';
    *date_str++ = ' ';
    *date_str++ = xt.tm_hour / 10 + '0';
    *date_str++ = xt.tm_hour % 10 + '0';
    *date_str++ = ':';
    *date_str++ = xt.tm_min / 10 + '0';
    *date_str++ = xt.tm_min % 10 + '0';
    *date_str++ = ':';
    *date_str++ = xt.tm_sec / 10 + '0';
    *date_str++ = xt.tm_sec % 10 + '0';
    if (option & AP_CTIME_OPTION_USEC) {
        int div;
        int usec = (int)xt.tm_usec;
        *date_str++ = '.';
        for (div=100000; div>0; div=div/10) {
            *date_str++ = usec / div + '0';
            usec = usec % div;
        }
    }
    *date_str++ = ' ';
    real_year = 1900 + xt.tm_year;
    *date_str++ = real_year / 1000 + '0';
    *date_str++ = real_year % 1000 / 100 + '0';
    *date_str++ = real_year % 100 / 10 + '0';
    *date_str++ = real_year % 10 + '0';
    *date_str++ = 0;

    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_recent_rfc822_date(char *date_str, apr_time_t t)
{
    /* ### This code is a clone of apr_rfc822_date(), except that it
     * uses ap_explode_recent_gmt() instead of apr_time_exp_gmt().
     */
    apr_time_exp_t xt;
    const char *s;
    int real_year;

    ap_explode_recent_gmt(&xt, t);

    /* example: "Sat, 08 Jan 2000 18:31:41 GMT" */
    /*           12345678901234567890123456789  */

    s = &apr_day_snames[xt.tm_wday][0];
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = ',';
    *date_str++ = ' ';
    *date_str++ = xt.tm_mday / 10 + '0';
    *date_str++ = xt.tm_mday % 10 + '0';
    *date_str++ = ' ';
    s = &apr_month_snames[xt.tm_mon][0];
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = *s++;
    *date_str++ = ' ';
    real_year = 1900 + xt.tm_year;
    /* This routine isn't y10k ready. */
    *date_str++ = real_year / 1000 + '0';
    *date_str++ = real_year % 1000 / 100 + '0';
    *date_str++ = real_year % 100 / 10 + '0';
    *date_str++ = real_year % 10 + '0';
    *date_str++ = ' ';
    *date_str++ = xt.tm_hour / 10 + '0';
    *date_str++ = xt.tm_hour % 10 + '0';
    *date_str++ = ':';
    *date_str++ = xt.tm_min / 10 + '0';
    *date_str++ = xt.tm_min % 10 + '0';
    *date_str++ = ':';
    *date_str++ = xt.tm_sec / 10 + '0';
    *date_str++ = xt.tm_sec % 10 + '0';
    *date_str++ = ' ';
    *date_str++ = 'G';
    *date_str++ = 'M';
    *date_str++ = 'T';
    *date_str++ = 0;
    return APR_SUCCESS;
}
