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

#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_user.h"
#include "apr_private.h"
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for _POSIX_THREAD_SAFE_FUNCTIONS */
#endif

APR_DECLARE(apr_status_t) apr_gid_name_get(char **groupname, apr_gid_t groupid,
                                           apr_pool_t *p)
{
    struct group *gr;

#if APR_HAS_THREADS && defined(_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
    struct group grp;
    char grbuf[512];

    if (getgrgid_r(groupid, &grp, grbuf, sizeof(grbuf), &gr)) {
#else
    if ((gr = getgrgid(groupid)) == NULL) {
#endif
        return errno;
    }
    *groupname = apr_pstrdup(p, gr->gr_name);
    return APR_SUCCESS;
}
  
APR_DECLARE(apr_status_t) apr_gid_get(apr_gid_t *groupid, 
                                      const char *groupname, apr_pool_t *p)
{
    struct group *gr;

#if APR_HAS_THREADS && defined(_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRNAM_R)
    struct group grp;
    char grbuf[512];

    if (getgrnam_r(groupname, &grp, grbuf, sizeof(grbuf), &gr)) {
#else
    if ((gr = getgrnam(groupname)) == NULL) {
#endif
        return errno;
    }
    *groupid = gr->gr_gid;
    return APR_SUCCESS;
}
