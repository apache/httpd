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

#include "apr.h"
#include "apr_pools.h"
#include "apr_poll.h"

#ifndef APACHE_MPM_SIMPLE_EVENT_H
#define APACHE_MPM_SIMPLE_EVENT_H

/* pqXXXXXX: Pool based cleanups
 */

void
simple_register_timer(simple_core_t * sc,
                      simple_timer_cb cb,
                      void *baton,
                      apr_time_t relative_time,
                      apr_pool_t *shutdown_pool);

void
simple_timer_run(simple_timer_t *ep);

#if THESE_ARE_JUST_IDEAS_PATCHES_WELCOME
/**
 * @see apr_poll.h for watch_for values
 */
void
simple_register_sock_io(simple_core_t * sc,
                        simple_io_sock_cb cb,
                        void *baton,
                        apr_socket_t * sock,
                        int watch_for, apr_time_t relative_timeout);

/**
 * @see apr_poll.h for watch_for values
 */
void
simple_register_file_io(simple_core_t * sc,
                        simple_io_file_cb cb,
                        void *baton,
                        apr_file_t * file,
                        int watch_for, apr_time_t relative_timeout);

#endif

#endif /* APACHE_MPM_SIMPLE_EVENT_H */
