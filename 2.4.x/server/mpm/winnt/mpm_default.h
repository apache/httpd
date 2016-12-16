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
 * @file  winnt/mpm_default.h
 * @brief win32 MPM defaults
 *
 * @defgroup APACHE_MPM_WINNT WinNT MPM
 * @ingroup APACHE_INTERNAL
 * @{
 */

#ifndef APACHE_MPM_DEFAULT_H
#define APACHE_MPM_DEFAULT_H

/* Default limit on the maximum setting of the ThreadsPerChild configuration
 * directive.  This limit can be overridden with the ThreadLimit directive.
 * This limit directly influences the amount of shared storage that is allocated
 * for the scoreboard. DEFAULT_THREAD_LIMIT represents a good compromise
 * between scoreboard size and the ability of the server to handle the most
 * common installation requirements.
 */
#ifndef DEFAULT_THREAD_LIMIT
#define DEFAULT_THREAD_LIMIT 1920
#endif

/* The ThreadLimit directive can be used to override the DEFAULT_THREAD_LIMIT.
 * ThreadLimit cannot be tuned larger than MAX_THREAD_LIMIT.
 * This is a sort of compile-time limit to help catch typos.
 */
#ifndef MAX_THREAD_LIMIT
#define MAX_THREAD_LIMIT 15000
#endif

/* Number of threads started in the child process in the absence
 * of a ThreadsPerChild configuration directive
 */
#ifndef DEFAULT_THREADS_PER_CHILD
#define DEFAULT_THREADS_PER_CHILD 64
#endif

/* Max number of child processes allowed.
 */
#define HARD_SERVER_LIMIT 1

#endif /* AP_MPM_DEFAULT_H */
/** @} */
