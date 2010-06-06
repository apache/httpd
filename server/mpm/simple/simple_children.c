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
#include "http_log.h"
#include "simple_children.h"
#include "apr_hash.h"

#include <unistd.h> /* For fork() */

#define SPAWN_CHILDREN_INTERVAL (apr_time_from_sec(5))

APLOG_USE_MODULE(mpm_simple);

static void simple_kill_random_child(simple_core_t * sc)
{
    /* See comment in simple_spawn_child for why we check here. */
    if (!sc->run_single_process) {
        apr_hash_index_t *hi;
        simple_child_t *child = NULL;

        apr_thread_mutex_lock(sc->mtx);
        hi = apr_hash_first(sc->pool, sc->children);
        if (hi != NULL) {
            apr_hash_this(hi, NULL, NULL, (void **)&child); 
            apr_hash_set(sc->children, &child->pid, sizeof(child->pid), NULL);
        }
        apr_thread_mutex_unlock(sc->mtx);
        
        if (child != NULL) {
            kill(child->pid, 9);
            /* TODO: recycle child object */
        }
    }
}

static void clean_child_exit(int code) __attribute__ ((noreturn));
static void clean_child_exit(int code)
{
    /* TODO: Pool cleanups.... sigh. */
    exit(code);
}

static int simple_spawn_child(simple_core_t * sc)
{
    pid_t pid = 0;
    int rv = 0;
    /* Although we could cut this off 'earlier', and not even invoke this 
     * function, I would like to keep the functions invoked when in debug mode
     * to be as close as possible to those when not in debug... So, we just skip
     * the actual spawn itself, but go through all of the motions...
     */
    if (!sc->run_single_process) {
        if (sc->spawn_via == SIMPLE_SPAWN_FORK) {
            
            pid = fork();
            if (pid == -1) {
                rv = errno;
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                             "simple_spawn_child: Unable to fork new process");
                return rv;
            }
            
            if (pid == 0) {
                /* this is the child process */
                
                rv = simple_child_loop(sc);

                if (rv) {
                    clean_child_exit(APEXIT_CHILDFATAL);
                }
                else {
                    clean_child_exit(0);
                }
            }
        }
        else {
            /* TODO: SIMPLE_SPAWN_EXEC */
            abort();
        }
    }

    if (pid != 0) {
        simple_child_t *child;

        apr_thread_mutex_lock(sc->mtx);

        child = apr_palloc(sc->pool, sizeof(simple_child_t));
        child->pid = pid;
        apr_hash_set(sc->children, &child->pid, sizeof(child->pid), child);

        apr_thread_mutex_unlock(sc->mtx);
    }
    
    return 0;
}

void simple_check_children_size(simple_core_t * sc, void *baton)
{
    unsigned int count;
    int wanted;
    int i;

    simple_register_timer(sc,
                          simple_check_children_size,
                          NULL, SPAWN_CHILDREN_INTERVAL,
                          sc->pool);

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
        int rv = 0;
        /* spawn some kids */
        int to_spawn = wanted - count;
        for (i = 0; rv == 0 && i < to_spawn; i++) {
            rv = simple_spawn_child(sc);
        }
    }
    else {
        /* juuuuust right. */
    }
}
