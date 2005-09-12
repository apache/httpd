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

#ifndef APACHE_MPM_EVENT_IOMUX_H
#define APACHE_MPM_EVENT_IOMUX_H

#include "apr_pools.h"
#include "apr_network_io.h"
#include "apr_poll.h"

#include "ap_listen.h"
#include "httpd.h"

typedef struct io_multiplexer io_multiplexer;

typedef struct {
    enum { IOM_LISTENER, IOM_CONNECTION } type;
    union {
        ap_listen_rec *l;
        conn_rec *c;
    };
} multiplexable;

/* Flag to set in apr_pollfd_t.rtnevents upon timeout
 * XXX: Find a way to make sure this never collides with any value
 *      set by APR
 */
#define IOM_POLL_TIMEOUT 0x8000

apr_status_t io_multiplexer_create(io_multiplexer **iom, apr_pool_t *p,
                                   apr_uint32_t max_descriptors);

apr_status_t io_multiplexer_get_event(io_multiplexer *iom, apr_pollfd_t *event);

apr_status_t io_multiplexer_stop(io_multiplexer *iom, int graceful);

#define IOM_TIMEOUT_INFINITE -1

apr_status_t io_multiplexer_add(io_multiplexer *iom, multiplexable *m,
                                long timeout_in_usec);

apr_status_t io_multiplexer_remove(io_multiplexer *iom, multiplexable *m);

#endif /* APACHE_MPM_EVENT_IOMUX_H */

