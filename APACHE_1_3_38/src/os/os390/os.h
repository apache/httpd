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

#ifndef APACHE_OS_H
#define APACHE_OS_H

#define PLATFORM "OS390"

/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */

#if !defined(INLINE) && defined(USE_GNU_INLINE)
/* Compiler supports inline, so include the inlineable functions as
 * part of the header
 */
#define INLINE extern ap_inline

INLINE int ap_os_is_path_absolute(const char *file);

#include "os-inline.c"
#endif

#ifndef INLINE
/* Compiler does not support inline, so prototype the inlineable functions
 * as normal
 */
extern int ap_os_is_path_absolute(const char *file);
#endif

/* Other ap_os_ routines not used by this platform */

#define ap_os_is_filename_valid(f)          (1)
#define ap_os_kill(pid, sig)                kill(pid, sig)

#endif /*! APACHE_OS_H*/
