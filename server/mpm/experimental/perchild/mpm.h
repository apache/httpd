/* Copyright 2000-2004 The Apache Software Foundation
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

#include "httpd.h"
#include "mpm_default.h"
#include "unixd.h"

#ifndef APACHE_MPM_PERCHILD_H
#define APACHE_MPM_PERCHILD_H

#define PERCHILD_MPM

#define MPM_NAME "Perchild"

#define AP_MPM_WANT_RECLAIM_CHILD_PROCESSES
#define AP_MPM_WANT_WAIT_OR_TIMEOUT
#define AP_MPM_WANT_PROCESS_CHILD_STATUS
#define AP_MPM_WANT_SET_PIDFILE
#define AP_MPM_WANT_SET_SCOREBOARD
#define AP_MPM_WANT_SET_LOCKFILE
#define AP_MPM_WANT_SET_MAX_REQUESTS
#define AP_MPM_WANT_SET_COREDUMPDIR
#define AP_MPM_WANT_SET_ACCEPT_LOCK_MECH
#define AP_MPM_WANT_SIGNAL_SERVER
#define AP_MPM_WANT_SET_STACKSIZE
#define AP_MPM_WANT_FATAL_SIGNAL_HANDLER
#define AP_MPM_USES_POD

#define MPM_CHILD_PID(i) (ap_scoreboard_image->parent[i].pid)
#define MPM_NOTE_CHILD_KILLED(i) (MPM_CHILD_PID(i) = 0)
#define MPM_ACCEPT_FUNC unixd_accept

/* Table of child status */
#define SERVER_DEAD 0
#define SERVER_DYING 1
#define SERVER_ALIVE 2

typedef struct ap_ctable{
    pid_t pid;
    unsigned char status;
} ap_ctable;

extern int ap_threads_per_child;
extern int ap_max_daemons_limit;
extern server_rec *ap_server_conf;

#endif /* APACHE_MPM_PERCHILD_H */
