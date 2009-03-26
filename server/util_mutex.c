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

/*
 * util_mutex.c: Useful functions for determining allowable
 *               mutexes and mutex settings
 */


#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_config.h"
#include "util_mutex.h"

AP_DECLARE(apr_status_t) ap_parse_mutex(const char *arg, apr_pool_t *pool,
                                        apr_lockmech_e *mutexmech,
                                        const char **mutexfile)
{
    /* Split arg into meth and file */
    char *meth = apr_pstrdup(pool, arg);
    char *file = strchr(meth, ':');
    if (file) {
        *(file++) = '\0';
        if (!*file) {
            file = NULL;
        }
    }

    if (!strcasecmp(meth, "none") || !strcasecmp(meth, "no")) {
        return APR_ENOLOCK;
    }

    /* APR determines temporary filename unless overridden below,
     * we presume file indicates an mutexfile is a file path
     * unless the method sets mutexfile=file and NULLs file
     */
    *mutexfile = NULL;

    /* NOTE: previously, 'yes' implied 'sem' */
    if (!strcasecmp(meth, "default") || !strcasecmp(meth, "yes")) {
        *mutexmech = APR_LOCK_DEFAULT;
    }
#if APR_HAS_FCNTL_SERIALIZE
    else if (!strcasecmp(meth, "fcntl") || !strcasecmp(meth, "file")) {
        *mutexmech = APR_LOCK_FCNTL;
    }
#endif
#if APR_HAS_FLOCK_SERIALIZE
    else if (!strcasecmp(meth, "flock") || !strcasecmp(meth, "file")) {
        *mutexmech = APR_LOCK_FLOCK;
    }
#endif
#if APR_HAS_POSIXSEM_SERIALIZE
    else if (!strcasecmp(meth, "posixsem") || !strcasecmp(meth, "sem")) {
        *mutexmech = APR_LOCK_POSIXSEM;
        /* Posix/SysV semaphores aren't file based, use the literal name
         * if provided and fall back on APR's default if not.  Today, APR
         * will ignore it, but once supported it has an absurdly short limit.
         */
        if (file) {
            *mutexfile = apr_pstrdup(pool, file);

            file = NULL;
        }
    }
#endif
#if APR_HAS_SYSVSEM_SERIALIZE
    else if (!strcasecmp(meth, "sysvsem") || !strcasecmp(meth, "sem")) {
        *mutexmech = APR_LOCK_SYSVSEM;
    }
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    else if (!strcasecmp(meth, "pthread")) {
        *mutexmech = APR_LOCK_PROC_PTHREAD;
    }
#endif
    else {
        return APR_ENOTIMPL;
    }

    /* Unless the method above assumed responsibility for setting up
     * mutexfile and NULLing out file, presume it is a file we
     * are looking to use
     */
    if (file) {
        *mutexfile = ap_server_root_relative(pool, file);
        if (!*mutexfile) {
            return APR_BADARG;
        }
    }

    return APR_SUCCESS;
}
