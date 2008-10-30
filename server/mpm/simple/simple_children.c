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

#include "httpd.h"
#include "http_config.h"
#include "simple_types.h"
#include "simple_event.h"
#include "simple_run.h"
#include "simple_children.h"
#include "apr_hash.h"

#define SPAWN_CHILDREN_INTERVAL (apr_time_from_sec(5))

static void simple_kill_random_child(simple_core_t * sc)
{
    apr_thread_mutex_lock(sc->mtx);
    /* See comment in simple_spawn_child for why we check here. */
    if (!sc->run_single_process) {
    }
    apr_thread_mutex_unlock(sc->mtx);
}

static void simple_spawn_child(simple_core_t * sc)
{
    apr_thread_mutex_lock(sc->mtx);
    /* Although we could cut this off 'earlier', and not even invoke this 
     * function, I would like to keep the functions invoked when in debug mode
     * to be as close as possible to those when not in debug... So, we just skip
     * the actual spawn itself, but go through all of the motions...
     */
    if (!sc->run_single_process) {

    }
    apr_thread_mutex_unlock(sc->mtx);
}

void simple_check_children_size(simple_core_t * sc, void *baton)
{
    unsigned int count;
    int wanted;
    int i;

    simple_register_timer(sc,
                          simple_check_children_size,
                          NULL, SPAWN_CHILDREN_INTERVAL);

    if (sc->run_single_process && sc->restart_num == 2) {
        static int run = 0;
        /* This is kinda of hack, but rather than spawning a child process, 
         * we register the normal IO handlers in the main event loop....
         */
        if (run == 0) {
            simple_single_process_hack(sc);
            run++;
        }
    }

    {
        apr_thread_mutex_lock(sc->mtx);
        count = apr_hash_count(sc->children);
        wanted = sc->procmgr.proc_count;
        apr_thread_mutex_unlock(sc->mtx);
    }

    if (count > wanted) {
        /* kill some kids */
        int to_kill = count - wanted;
        for (i = 0; i < to_kill; i++) {
            simple_kill_random_child(sc);
        }
    }
    else if (count < wanted) {
        /* spawn some kids */
        int to_spawn = wanted - count;
        for (i = 0; i < to_spawn; i++) {
            simple_spawn_child(sc);
        }
    }
    else {
        /* juuuuust right. */
    }
}
