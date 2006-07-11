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

/**
 * @file  netware/mpm_default.h
 * @brief Defaults for Netware MPM
 *
 * @addtogroup APACHE_MPM_NETWARE
 * @{
 */
#ifndef APACHE_MPM_DEFAULT_H
#define APACHE_MPM_DEFAULT_H

/* Number of servers to spawn off by default --- also, if fewer than
 * this free when the caretaker checks, it will spawn more.
 */
#ifndef DEFAULT_START_DAEMON
#define DEFAULT_START_DAEMON 1
#endif

/* Maximum number of *free* server processes --- more than this, and
 * they will die off.
 */

#ifndef DEFAULT_MAX_FREE_DAEMON
#define DEFAULT_MAX_FREE_DAEMON 1
#endif

/* Minimum --- fewer than this, and more will be created */

#ifndef DEFAULT_MIN_FREE_DAEMON
#define DEFAULT_MIN_FREE_DAEMON 1
#endif

/* Limit on the threads per process.  Clients will be locked out if more than
 * this  * HARD_SERVER_LIMIT are needed.
 *
 * We keep this for one reason it keeps the size of the scoreboard file small
 * enough that we can read the whole thing without worrying too much about
 * the overhead.
 */
#ifndef HARD_THREAD_LIMIT
#define HARD_THREAD_LIMIT 2048
#endif

#ifndef DEFAULT_THREADS_PER_CHILD
#define DEFAULT_THREADS_PER_CHILD 50
#endif

/* Number of threads to spawn off by default --- also, if fewer than
 * this free when the caretaker checks, it will spawn more.
 */
#ifndef DEFAULT_START_THREADS
#define DEFAULT_START_THREADS DEFAULT_THREADS_PER_CHILD
#endif

/* Maximum number of *free* threads --- more than this, and
 * they will die off.
 */

#ifndef DEFAULT_MAX_FREE_THREADS
#define DEFAULT_MAX_FREE_THREADS 100
#endif

/* Minimum --- fewer than this, and more will be created */

#ifndef DEFAULT_MIN_FREE_THREADS
#define DEFAULT_MIN_FREE_THREADS 10
#endif

/* Check for definition of DEFAULT_REL_RUNTIMEDIR */
#ifndef DEFAULT_REL_RUNTIMEDIR
#define DEFAULT_REL_RUNTIMEDIR "logs"
#endif

/* File used for accept locking, when we use a file */
/*#ifndef DEFAULT_LOCKFILE
  #define DEFAULT_LOCKFILE DEFAULT_REL_RUNTIMEDIR "/accept.lock"
  #endif
*/

/* Where the main/parent process's pid is logged */
/*#ifndef DEFAULT_PIDLOG
  #define DEFAULT_PIDLOG DEFAULT_REL_RUNTIMEDIR "/httpd.pid"
  #endif
*/

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
#define DEFAULT_MAX_REQUESTS_PER_CHILD 0
#endif

/* Default stack size allocated for each worker thread.
 */
#ifndef DEFAULT_THREAD_STACKSIZE
#define DEFAULT_THREAD_STACKSIZE 65536
#endif

#endif /* AP_MPM_DEFAULT_H */
/** @} */
