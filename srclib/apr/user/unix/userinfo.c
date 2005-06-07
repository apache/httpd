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
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for _POSIX_THREAD_SAFE_FUNCTIONS */
#endif
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#define PWBUF_SIZE 512

static apr_status_t getpwnam_safe(const char *username,
                                  struct passwd *pw,
                                  char pwbuf[PWBUF_SIZE])
{
    struct passwd *pwptr;
#if APR_HAS_THREADS && defined(_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
    /* IRIX getpwnam_r() returns 0 and sets pwptr to NULL on failure */
    if (!getpwnam_r(username, pw, pwbuf, PWBUF_SIZE, &pwptr) && pwptr) {
        /* nothing extra to do on success */
#else
    if ((pwptr = getpwnam(username)) != NULL) {
        memcpy(pw, pwptr, sizeof *pw);
#endif
    }
    else {
        if (errno == 0) {
            /* this can happen with getpwnam() on FreeBSD 4.3 */
            return APR_EGENERAL;
        }
        return errno;
    }
    return APR_SUCCESS;
}

APR_DECLARE(apr_status_t) apr_uid_homepath_get(char **dirname,
                                               const char *username,
                                               apr_pool_t *p)
{
    struct passwd pw;
    char pwbuf[PWBUF_SIZE];
    apr_status_t rv;

    if ((rv = getpwnam_safe(username, &pw, pwbuf)) != APR_SUCCESS)
        return rv;

#ifdef OS2
    /* Need to manually add user name for OS/2 */
    *dirname = apr_pstrcat(p, pw.pw_dir, pw.pw_name, NULL);
#else
    *dirname = apr_pstrdup(p, pw.pw_dir);
#endif
    return APR_SUCCESS;
}



APR_DECLARE(apr_status_t) apr_uid_current(apr_uid_t *uid,
                                          apr_gid_t *gid,
                                          apr_pool_t *p)
{
    *uid = getuid();
    *gid = getgid();
  
    return APR_SUCCESS;
}




APR_DECLARE(apr_status_t) apr_uid_get(apr_uid_t *uid, apr_gid_t *gid,
                                      const char *username, apr_pool_t *p)
{
    struct passwd pw;
    char pwbuf[PWBUF_SIZE];
    apr_status_t rv;
        
    if ((rv = getpwnam_safe(username, &pw, pwbuf)) != APR_SUCCESS)
        return rv;

    *uid = pw.pw_uid;
    *gid = pw.pw_gid;

    return APR_SUCCESS;
}

APR_DECLARE(apr_status_t) apr_uid_name_get(char **username, apr_uid_t userid,
                                           apr_pool_t *p)
{
    struct passwd *pw;
#if APR_HAS_THREADS && defined(_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWUID_R)
    struct passwd pwd;
    char pwbuf[PWBUF_SIZE];

    if (getpwuid_r(userid, &pwd, pwbuf, sizeof(pwbuf), &pw)) {
#else
    if ((pw = getpwuid(userid)) == NULL) {
#endif
        return errno;
    }
    *username = apr_pstrdup(p, pw->pw_name);
    return APR_SUCCESS;
}
