/* Copyright 2000-2004 Apache Software Foundation
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

#ifndef APACHE_MPM_DEFAULT_H
#define APACHE_MPM_DEFAULT_H

/* Number of threads to spawn off by default --- also, if fewer than
 * this free when the caretaker checks, it will spawn more.
 */
#ifndef DEFAULT_START_THREAD
#define DEFAULT_START_THREAD 5
#endif

/* Maximum number of *free* server threads --- more than this, and
 * they will die off.
 */

#ifndef DEFAULT_MAX_SPARE_THREAD
#define DEFAULT_MAX_SPARE_THREAD 10
#endif

/* Minimum --- fewer than this, and more will be created */

#ifndef DEFAULT_MIN_SPARE_THREAD
#define DEFAULT_MIN_SPARE_THREAD 5
#endif

/* Number of servers to spawn off by default
 */
#ifndef DEFAULT_NUM_DAEMON
#define DEFAULT_NUM_DAEMON 2
#endif

/* File used for accept locking, when we use a file */
#ifndef DEFAULT_LOCKFILE
#define DEFAULT_LOCKFILE DEFAULT_REL_RUNTIMEDIR "/accept.lock"
#endif

/* Where the main/parent process's pid is logged */
#ifndef DEFAULT_PIDLOG
#define DEFAULT_PIDLOG DEFAULT_REL_RUNTIMEDIR "/httpd.pid"
#endif

/*
 * Interval, in microseconds, between scoreboard maintenance.
 */
#ifndef SCOREBOARD_MAINTENANCE_INTERVAL
#define SCOREBOARD_MAINTENANCE_INTERVAL 1000000
#endif

/* Number of requests to try to handle in a single process.  If <= 0,
 * the children don't die off.
 */
#ifndef DEFAULT_MAX_REQUESTS_PER_CHILD
#define DEFAULT_MAX_REQUESTS_PER_CHILD 10000
#endif

#endif /* AP_MPM_DEFAULT_H */
