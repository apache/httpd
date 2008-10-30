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

/* #define APR_RING_DEBUG 1 */

#include "simple_types.h"
#include "simple_event.h"

void
simple_register_timer(simple_core_t * sc,
                      simple_timer_cb cb,
                      void *baton, apr_time_t relative_time)
{
    simple_timer_t *elem = NULL;
    simple_timer_t *ep = NULL;
    int inserted = 0;
    apr_time_t t = apr_time_now() + relative_time;

    apr_thread_mutex_lock(sc->mtx);

    APR_RING_CHECK_CONSISTENCY(&sc->timer_ring, simple_timer_t, link);
    APR_RING_CHECK_CONSISTENCY(&sc->dead_timer_ring, simple_timer_t, link);

    if (!APR_RING_EMPTY(&sc->dead_timer_ring, simple_timer_t, link)) {
        elem = APR_RING_FIRST(&sc->dead_timer_ring);
        APR_RING_REMOVE(elem, link);
        APR_RING_CHECK_CONSISTENCY(&sc->dead_timer_ring, simple_timer_t,
                                   link);
    }
    else {
        elem =
            (simple_timer_t *) apr_pcalloc(sc->pool, sizeof(simple_timer_t));
    }

    APR_RING_ELEM_INIT(elem, link);
    elem->expires = t;
    elem->cb = cb;
    elem->baton = baton;

    APR_RING_CHECK_CONSISTENCY(&sc->timer_ring, simple_timer_t, link);

    /* pqXXXXXX: skiplist would be a nice optimization here. */
    if (!APR_RING_EMPTY(&sc->timer_ring, simple_timer_t, link)) {
        ep = APR_RING_FIRST(&sc->timer_ring);
        while (inserted == 0 &&
               ep != APR_RING_SENTINEL(&sc->timer_ring, simple_timer_t, link))
        {
            if (ep->expires < elem->expires) {
                APR_RING_CHECK_CONSISTENCY(&sc->timer_ring, simple_timer_t,
                                           link);
                APR_RING_INSERT_BEFORE(ep, elem, link);
                inserted = 1;
                APR_RING_CHECK_CONSISTENCY(&sc->timer_ring, simple_timer_t,
                                           link);
            }
            ep = APR_RING_NEXT(ep, link);
        }
    }

    APR_RING_CHECK_CONSISTENCY(&sc->timer_ring, simple_timer_t, link);

    if (!inserted) {
        APR_RING_INSERT_TAIL(&sc->timer_ring, elem, simple_timer_t, link);
    }

    APR_RING_CHECK_CONSISTENCY(&sc->timer_ring, simple_timer_t, link);

    apr_thread_mutex_unlock(sc->mtx);
}
