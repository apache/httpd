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
 
#include <assert.h>
#include <apr_strings.h>

#ifndef AP_ENABLE_EXCEPTION_HOOK
#define AP_ENABLE_EXCEPTION_HOOK 0
#endif

#include <mpm_common.h>
#include <httpd.h>
#include <http_log.h>
#include <ap_mpm.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef WIN32
#include "mpm_winnt.h"
#endif
#if AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include "md_util.h"
#include "mod_md_os.h"

apr_status_t md_try_chown(const char *fname, unsigned int uid, int gid, apr_pool_t *p)
{
#if AP_NEED_SET_MUTEX_PERMS
    if (-1 == chown(fname, (uid_t)uid, (gid_t)gid)) {
        apr_status_t rv = APR_FROM_OS_ERROR(errno);
        if (!APR_STATUS_IS_ENOENT(rv)) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, rv, p, APLOGNO(10082)
                         "Can't change owner of %s", fname);
        }
        return rv;
    }
    return APR_SUCCESS;
#else 
    return APR_ENOTIMPL;
#endif
}

apr_status_t md_make_worker_accessible(const char *fname, apr_pool_t *p)
{
#if AP_NEED_SET_MUTEX_PERMS
    return md_try_chown(fname, ap_unixd_config.user_id, -1, p);
#else 
    return APR_ENOTIMPL;
#endif
}

#ifdef WIN32

apr_status_t md_server_graceful(apr_pool_t *p, server_rec *s)
{
    return APR_ENOTIMPL;
}
 
#else

apr_status_t md_server_graceful(apr_pool_t *p, server_rec *s)
{ 
    apr_status_t rv;
    
    (void)p;
    (void)s;
    rv = (kill(getppid(), AP_SIG_GRACEFUL) < 0)? APR_ENOTIMPL : APR_SUCCESS;
    ap_log_error(APLOG_MARK, APLOG_TRACE1, errno, NULL, "sent signal to parent");
    return rv;
}

#endif

