/* Copyright 2005 The Apache Software Foundation or its licensors, as
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

#include "apr_poll.h"
#include "apr_ring.h"
#include "apr_thread_cond.h"
#include "apr_thread_mutex.h"

#include "io_multiplexer.h"

extern server_rec *ap_server_conf;

APR_RING_HEAD(timeout_ring_header_t, conn_state_t);

struct io_multiplexer {
    int stopped;
    apr_thread_mutex_t *lock;
    apr_thread_mutex_t *pollset_lock;
    apr_pollset_t *pollset;
    apr_int32_t num_pending_events;
    const apr_pollfd_t *next_pending_event;
    struct timeout_ring_header_t pending_timeouts;
    struct timeout_ring_header_t expired_timeouts;
    volatile int poll_sequence_num;
};

static apr_status_t io_multiplexer_remove_internal(io_multiplexer *iom,
                                                   multiplexable *m);

apr_status_t io_multiplexer_create(io_multiplexer **iom, apr_pool_t *p,
                                   apr_uint32_t max_descriptors)
{
    apr_status_t rv;
    *iom = (io_multiplexer *)apr_palloc(p, sizeof(**iom));
    rv = apr_thread_mutex_create(&((*iom)->lock), APR_THREAD_MUTEX_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    rv = apr_thread_mutex_create(&((*iom)->pollset_lock),
                                 APR_THREAD_MUTEX_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    rv = apr_pollset_create(&((*iom)->pollset), max_descriptors, p,
                            APR_POLLSET_THREADSAFE);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    (*iom)->stopped = 0;
    (*iom)->num_pending_events = 0;
    (*iom)->next_pending_event = NULL;
    APR_RING_INIT(&((*iom)->pending_timeouts), conn_state_t, timeout_list);
    APR_RING_INIT(&((*iom)->expired_timeouts), conn_state_t, timeout_list);
    (*iom)->poll_sequence_num = 0;
    
    return APR_SUCCESS;
}

#define DEFAULT_POLL_TIMEOUT 1000000

apr_status_t io_multiplexer_get_event(io_multiplexer *iom,
                                      apr_pollfd_t *event)
{
    apr_status_t rv;
    rv = apr_thread_mutex_lock(iom->pollset_lock);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    rv = apr_thread_mutex_lock(iom->lock);
    if (rv != APR_SUCCESS) {
        apr_thread_mutex_unlock(iom->pollset_lock);
        return rv;
    }
    if (iom->stopped) {
        apr_thread_mutex_unlock(iom->lock);
        apr_thread_mutex_unlock(iom->pollset_lock);
        return APR_EINVAL;
    }
    for (;;) {
        /* Invariant: at the start of each iteration of this loop, the
         * active thread holds iom->lock.
         */
         if (!APR_RING_EMPTY(&(iom->expired_timeouts), conn_state_t, timeout_list)) {
             /* There are some timeout notifications remaining
              * from the last poll.  Return the next one.
              */
             conn_state_t *cs = APR_RING_FIRST(&(iom->expired_timeouts));
             APR_RING_REMOVE(cs, timeout_list);
             *event = cs->pfd;
             event->rtnevents |= IOM_POLL_TIMEOUT;
             apr_thread_mutex_unlock(iom->lock);
             return apr_thread_mutex_unlock(iom->pollset_lock);
         }
         else if (iom->num_pending_events > 0) {
            /* There are some events remaining from the last
             * poll.  Return the next one.
             */
            *event = *(iom->next_pending_event++);
            apr_pollset_remove(iom->pollset, event);
            iom->num_pending_events--;
            apr_thread_mutex_unlock(iom->lock);
            return apr_thread_mutex_unlock(iom->pollset_lock);
        }
        else {
            /* No unprocessed events remain from the previous poll,
             * so initiate a new poll.
             */
            apr_int32_t num_pending_events = 0;
            const apr_pollfd_t *next_pending_event;
            apr_interval_time_t poll_timeout;
            int i;
            
            if (APR_RING_EMPTY(&(iom->pending_timeouts), conn_state_t,
                               timeout_list)) {
                poll_timeout = DEFAULT_POLL_TIMEOUT;
            }
            else {
                /* If there are pending timeouts, check whether
                 * any of them have expired.  If none have expired,
                 * use the expiration time on the first one to
                 * determine how long the poll should block.
                 */
                apr_time_t now = apr_time_now();
                conn_state_t *cs = APR_RING_FIRST(&(iom->pending_timeouts));
                if (cs->expiration_time <= now) {
                    do {
                        APR_RING_REMOVE(cs, timeout_list);
                        apr_pollset_remove(iom->pollset, &(cs->pfd));
                        APR_RING_INSERT_TAIL(&(iom->expired_timeouts), cs,
                                             conn_state_t, timeout_list);
                        if (APR_RING_EMPTY(&(iom->pending_timeouts),
                                           conn_state_t, timeout_list)) {
                            break;
                        }
                        cs = APR_RING_FIRST(&(iom->pending_timeouts));
                    } while (cs->expiration_time <= now);
                    continue;
                }
                else {
                    poll_timeout = cs->expiration_time - now;
                }
            }

            apr_thread_mutex_unlock(iom->lock);

            rv = apr_pollset_poll(iom->pollset, poll_timeout,
                                  &num_pending_events, &next_pending_event);

            if ((rv != APR_SUCCESS) && !APR_STATUS_IS_TIMEUP(rv) && !APR_STATUS_IS_EINTR(rv)) {
                apr_thread_mutex_unlock(iom->pollset_lock);
                return rv;
            }
            apr_thread_mutex_lock(iom->lock);
            
            if (num_pending_events > 0) {
                iom->num_pending_events = num_pending_events;
                iom->next_pending_event = next_pending_event;
                for (i = 0; i < num_pending_events; i++) {
                    multiplexable *m = (multiplexable *)next_pending_event[i].client_data;
                    if (m != NULL) {
                        io_multiplexer_remove_internal(iom, m);
                    }
                }
            }
        }
    }
}

apr_status_t io_multiplexer_stop(io_multiplexer *iom, int graceful) {
    iom->stopped = 1;
    return APR_SUCCESS;
}

apr_status_t io_multiplexer_add(io_multiplexer *iom, multiplexable *m,
                                long timeout_in_usec)
{
    apr_status_t rv;
    apr_thread_mutex_lock(iom->lock);
    if (iom->stopped) {
        rv = APR_EINVAL;
    }
    else if (m->type == IOM_CONNECTION) {
        APR_RING_REMOVE(m->c->cs, timeout_list);
        m->c->cs->pfd.client_data = m;
        rv = apr_pollset_add(iom->pollset, &(m->c->cs->pfd));
        if (timeout_in_usec >= 0) {
            /* XXX: Keep the pending_timeouts list sorted */
            m->c->cs->expiration_time = apr_time_now() + timeout_in_usec;
            APR_RING_INSERT_TAIL(&(iom->pending_timeouts), m->c->cs,
                                 conn_state_t, timeout_list);
        }
    }
    else if (m->type == IOM_LISTENER) {
        apr_pollfd_t desc;
        desc.desc_type = APR_POLL_SOCKET;
        desc.desc.s = m->l->sd;
        desc.reqevents = APR_POLLIN;
        desc.client_data = m;
        rv = apr_pollset_add(iom->pollset, &desc);
    }
    else {
        rv = APR_EINVALSOCK;
    }
    apr_thread_mutex_unlock(iom->lock);
    return rv;
}

apr_status_t io_multiplexer_remove(io_multiplexer *iom, multiplexable *m)
{
    apr_status_t rv;
    apr_thread_mutex_lock(iom->lock);
    rv = io_multiplexer_remove_internal(iom, m);
    apr_thread_mutex_unlock(iom->lock);
    return rv;
}

static apr_status_t io_multiplexer_remove_internal(io_multiplexer *iom,
                                                   multiplexable *m)
{
    apr_status_t rv;
    if (iom->stopped) {
        rv = APR_EINVAL;
    }
    else if (m->type == IOM_CONNECTION) {
        APR_RING_REMOVE(m->c->cs, timeout_list);
        rv = apr_pollset_remove(iom->pollset, &(m->c->cs->pfd));
    }
    else if (m->type == IOM_LISTENER) {
        apr_pollfd_t desc;
        desc.desc_type = APR_POLL_SOCKET;
        desc.desc.s = m->l->sd;
        desc.reqevents = APR_POLLIN;
        desc.client_data = NULL;
        rv = apr_pollset_remove(iom->pollset, &desc);
    }
    else {
        rv = APR_EINVALSOCK;
    }
    return rv;
}

