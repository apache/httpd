/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2001 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

#include "util_time.h"

/* Cache for exploded values of recent timestamps
 */

struct exploded_time_cache_element {
    apr_int64_t t;
    apr_exploded_time_t xt;
    apr_int64_t t_validate; /* please see comments in cached_explode() */
};

/* the "+ 1" is for the current second: */
#define TIME_CACHE_SIZE (AP_TIME_RECENT_THRESHOLD + 1)

static struct exploded_time_cache_element exploded_cache_localtime[TIME_CACHE_SIZE];
static struct exploded_time_cache_element exploded_cache_gmt[TIME_CACHE_SIZE];


static apr_status_t cached_explode(apr_exploded_time_t *xt, apr_time_t t,
                                   struct exploded_time_cache_element *cache,
                                   int use_gmt)
{
    apr_int64_t seconds = t / APR_USEC_PER_SEC;
    struct exploded_time_cache_element *cache_element =
        &(cache[seconds % TIME_CACHE_SIZE]);
    struct exploded_time_cache_element cache_element_snapshot;

    /* The cache is implemented as a ring buffer.  Each second,
     * it uses a different element in the buffer.  The timestamp
     * in the element indicates whether the element contains the
     * exploded time for the current second (vs the time
     * 'now - AP_TIME_RECENT_THRESHOLD' seconds ago).  If the
     * cached value is for the current time, we use it.  Otherwise,
     * we compute the apr_exploded_time_t and store it in this
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
                return apr_explode_gmt(xt, t);
            }
            else {
                return apr_explode_localtime(xt, t);
            }
        }
        else {
            /* Valid snapshot */
            memcpy(xt, &(cache_element_snapshot.xt),
                   sizeof(apr_exploded_time_t));
        }
    }
    else {
        apr_status_t r;
        if (use_gmt) {
            r = apr_explode_gmt(xt, t);
        }
        else {
            r = apr_explode_localtime(xt, t);
        }
        if (!APR_STATUS_IS_SUCCESS(r)) {
            return r;
        }
        cache_element->t = seconds;
        memcpy(&(cache_element->xt), xt, sizeof(apr_exploded_time_t));
        cache_element->t_validate = seconds;
    }
    xt->tm_usec = t % APR_USEC_PER_SEC;
    return APR_SUCCESS;
}


AP_DECLARE(apr_status_t) ap_explode_recent_localtime(apr_exploded_time_t * tm,
                                                     apr_time_t t)
{
    return cached_explode(tm, t, exploded_cache_localtime, 0);
}

AP_DECLARE(apr_status_t) ap_explode_recent_gmt(apr_exploded_time_t * tm,
                                               apr_time_t t)
{
    return cached_explode(tm, t, exploded_cache_gmt, 1);
}
