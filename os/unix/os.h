/* Copyright 1999-2005 The Apache Software Foundation or its licensors, as
 * applicable.
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

#ifndef APACHE_OS_H
#define APACHE_OS_H

#include "apr.h"
#include "ap_config.h"

#ifndef PLATFORM
#define PLATFORM "Unix"
#endif

/* On platforms where AP_NEED_SET_MUTEX_PERMS is defined, modules
 * should call unixd_set_*_mutex_perms on mutexes created in the
 * parent process. */
#define AP_NEED_SET_MUTEX_PERMS

#ifdef _OSD_POSIX
pid_t os_fork(const char *user);
#endif

#endif	/* !APACHE_OS_H */
