/* Copyright 2000-2005 The Apache Software Foundation or its licensors, as
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

#include "apr_arch_file_io.h"

APR_DECLARE(apr_status_t) apr_file_lock(apr_file_t *thefile, int type)
{
#ifdef _WIN32_WCE
    /* The File locking is unsuported on WCE */
    return APR_ENOTIMPL;
#else
    const DWORD len = 0xffffffff;
    DWORD flags; 

    flags = ((type & APR_FLOCK_NONBLOCK) ? LOCKFILE_FAIL_IMMEDIATELY : 0)
          + (((type & APR_FLOCK_TYPEMASK) == APR_FLOCK_SHARED) 
                                       ? 0 : LOCKFILE_EXCLUSIVE_LOCK);
    if (apr_os_level >= APR_WIN_NT) {
        /* Syntax is correct, len is passed for LengthLow and LengthHigh*/
        OVERLAPPED offset;
        memset (&offset, 0, sizeof(offset));
        if (!LockFileEx(thefile->filehand, flags, 0, len, len, &offset))
            return apr_get_os_error();
    }
    else {
        if (!LockFile(thefile->filehand, 0, 0, len, 0))
            return apr_get_os_error();
    }

    return APR_SUCCESS;
#endif /* !defined(_WIN32_WCE) */
}

APR_DECLARE(apr_status_t) apr_file_unlock(apr_file_t *thefile)
{
#ifdef _WIN32_WCE
    return APR_ENOTIMPL;
#else
    DWORD len = 0xffffffff;

    if (apr_os_level >= APR_WIN_NT) {
        /* Syntax is correct, len is passed for LengthLow and LengthHigh*/
        OVERLAPPED offset;
        memset (&offset, 0, sizeof(offset));
        if (!UnlockFileEx(thefile->filehand, 0, len, len, &offset))
            return apr_get_os_error();
    }
    else {
        if (!UnlockFile(thefile->filehand, 0, 0, len, 0))
            return apr_get_os_error();
    }

    return APR_SUCCESS;
#endif /* !defined(_WIN32_WCE) */
}
