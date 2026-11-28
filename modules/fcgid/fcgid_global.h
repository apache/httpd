/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

#ifndef FCGID_GLOBAL_H
#define FCGID_GLOBAL_H
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

#if AP_MODULE_MAGIC_AT_LEAST(20100606,0)
APLOG_USE_MODULE(fcgid);
#endif

#ifdef FCGID_APXS_BUILD
#include "fcgid_config.h"
#endif

/* FCGID_PATH_MAX
 * - includes terminating '\0'
 * - based on minimum supported path length (on Unix at least)
 * - should be used in declarations, but logic should use sizeof
 *   wherever possible
 */
#ifndef FCGID_PATH_MAX
#ifdef _POSIX_PATH_MAX
#define FCGID_PATH_MAX _POSIX_PATH_MAX
#else
#define FCGID_PATH_MAX 256
#endif
#endif

/* FCGID_CMDLINE_MAX
 * - includes terminating '\0'
 * - FCGID_PATH_MAX represents the executable, remainder represents
 *   the args
 * - should be used in declarations, but logic should use sizeof
 *   wherever possible
 */
#ifndef FCGID_CMDLINE_MAX
#define FCGID_CMDLINE_MAX (FCGID_PATH_MAX + 256)
#endif

#define fcgid_min(a,b)    (((a) < (b)) ? (a) : (b))

#endif
