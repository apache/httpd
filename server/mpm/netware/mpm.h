/* Copyright 2001-2004 The Apache Software Foundation
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

#include "scoreboard.h"

#ifndef APACHE_MPM_THREADED_H
#define APACHE_MPM_THREADED_H

#define THREADED_MPM

#define MPM_NAME "NetWare_Threaded"

/*#define AP_MPM_WANT_RECLAIM_CHILD_PROCESSES
  #define AP_MPM_WANT_WAIT_OR_TIMEOUT
  #define AP_MPM_WANT_PROCESS_CHILD_STATUS
  #define AP_MPM_WANT_SET_PIDFILE
  #define AP_MPM_WANT_SET_SCOREBOARD
  #define AP_MPM_WANT_SET_LOCKFILE 
*/
#define AP_MPM_WANT_SET_MAX_REQUESTS
#define AP_MPM_WANT_SET_MAX_MEM_FREE
#define AP_MPM_DISABLE_NAGLE_ACCEPTED_SOCK
/*#define AP_MPM_WANT_SET_COREDUMPDIR
  #define AP_MPM_WANT_SET_ACCEPT_LOCK_MECH 
*/

#define MPM_CHILD_PID(i) (ap_scoreboard_image->parent[i].pid)
#define MPM_NOTE_CHILD_KILLED(i) (MPM_CHILD_PID(i) = 0)

extern int ap_threads_per_child;
extern int ap_thread_stack_size;
extern int ap_max_workers_limit;
extern server_rec *ap_server_conf;

#endif /* APACHE_MPM_THREADED_H */
