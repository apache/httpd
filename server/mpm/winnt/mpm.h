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
 * @file  winnt/mpm.h
 * @brief MPM for Windows NT
 * 
 * this is the place to make declarations that are MPM specific but that must be 
 * shared with non-mpm specific code in the server.  Hummm, perhaps we can
 * move most of this stuff to mpm_common.h?
 *
 * @defgroup APACHE_MPM_WINNT WinNT MPM
 * @ingroup  APACHE_OS_WIN32 APACHE_MPM
 * @{
 */

#ifndef APACHE_MPM_H
#define APACHE_MPM_H

#include "scoreboard.h"

#define MPM_NAME "WinNT"

#define AP_MPM_NO_SET_ACCEPT_LOCK_MECH
#define AP_MPM_NO_RECLAIM_CHILD_PROCESSES
#define AP_MPM_NO_WAIT_OR_TIMEOUT
#define AP_MPM_NO_PROCESS_CHILD_STATUS
#define AP_MPM_NO_POD
#define AP_MPM_NO_SET_LOCKFILE
#define AP_MPM_NO_SET_COREDUMPDIR
#define AP_MPM_NO_SET_SCOREBOARD
#define AP_MPM_NO_SET_GRACEFUL_SHUTDOWN
#define AP_MPM_NO_SIGNAL_SERVER
#define AP_MPM_NO_FATAL_SIGNAL_HANDLER

extern int ap_threads_per_child;
extern int ap_thread_limit;

#endif /* APACHE_MPM_H */
/** @} */
