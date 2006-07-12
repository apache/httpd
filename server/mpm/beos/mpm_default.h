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
 * @file  beos/mpm_default.h
 * @brief beos MPM defaults
 *
 * @addtogroup APACHE_MPM_BEOS
 * @{
 */
#ifndef APACHE_MPM_DEFAULT_H
#define APACHE_MPM_DEFAULT_H

/* we use the child (c) as zero in our code... */
#define AP_ID_FROM_CHILD_THREAD(c, t)     t
/* as the child is always zero, just return the id... */
#define AP_CHILD_THREAD_FROM_ID(i)        0 , i

/* Number of threads to spawn off by default --- also, if fewer than
 * this free when the caretaker checks, it will spawn more.
 */
#ifndef DEFAULT_START_THREADS
#define DEFAULT_START_THREADS 10
#endif

#ifdef NO_THREADS
#define DEFAULT_THREADS 1
#endif
#ifndef DEFAULT_THREADS
#define DEFAULT_THREADS 10
#endif

/* The following 2 settings are used to control the number of threads
 * we have available.  Normally the DEFAULT_MAX_FREE_THREADS is set
 * to the same as the HARD_THREAD_LIMIT to avoid churning of starting
 * new threads to replace threads killed off...
 */

/* Maximum number of *free* threads --- more than this, and
 * they will die off.
 */
#ifndef DEFAULT_MAX_FREE_THREADS
#define DEFAULT_MAX_FREE_THREADS HARD_THREAD_LIMIT
#endif

/* Minimum --- fewer than this, and more will be created */
#ifndef DEFAULT_MIN_FREE_THREADS
#define DEFAULT_MIN_FREE_THREADS 1
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

/* Number of requests to try to handle in a single process.  If == 0,
 * the children don't die off.
 */
#ifndef DEFAULT_MAX_REQUESTS_PER_THREAD
#define DEFAULT_MAX_REQUESTS_PER_THREAD 0
#endif

#endif /* AP_MPM_DEFAULT_H */
/** @} */
