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
 * @file  suexec.h
 * @brief user-definable variables for the suexec wrapper code.
 *        (See README.configure on how to customize these variables.)
 */


#ifndef _SUEXEC_H
#define _SUEXEC_H

/*
 * Include ap_config_layout so we can work out where the default htdocsdir
 * and logsdir are.
 */
#include "ap_config_layout.h"

/*
 * HTTPD_USER -- Define as the username under which Apache normally
 *               runs.  This is the only user allowed to execute
 *               this program.
 */
#ifndef AP_HTTPD_USER
#define AP_HTTPD_USER "www"
#endif

/*
 * UID_MIN -- Define this as the lowest UID allowed to be a target user
 *            for suEXEC.  For most systems, 500 or 100 is common.
 */
#ifndef AP_UID_MIN
#define AP_UID_MIN 100
#endif

/*
 * GID_MIN -- Define this as the lowest GID allowed to be a target group
 *            for suEXEC.  For most systems, 100 is common.
 */
#ifndef AP_GID_MIN
#define AP_GID_MIN 100
#endif

/*
 * USERDIR_SUFFIX -- Define to be the subdirectory under users'
 *                   home directories where suEXEC access should
 *                   be allowed.  All executables under this directory
 *                   will be executable by suEXEC as the user so
 *                   they should be "safe" programs.  If you are
 *                   using a "simple" UserDir directive (ie. one
 *                   without a "*" in it) this should be set to
 *                   the same value.  suEXEC will not work properly
 *                   in cases where the UserDir directive points to
 *                   a location that is not the same as the user's
 *                   home directory as referenced in the passwd file.
 *
 *                   If you have VirtualHosts with a different
 *                   UserDir for each, you will need to define them to
 *                   all reside in one parent directory; then name that
 *                   parent directory here.  IF THIS IS NOT DEFINED
 *                   PROPERLY, ~USERDIR CGI REQUESTS WILL NOT WORK!
 *                   See the suEXEC documentation for more detailed
 *                   information.
 */
#ifndef AP_USERDIR_SUFFIX
#define AP_USERDIR_SUFFIX "public_html"
#endif

/*
 * LOG_EXEC -- Define this as a filename if you want all suEXEC
 *             transactions and errors logged for auditing and
 *             debugging purposes.
 */
#ifndef AP_LOG_EXEC
#define AP_LOG_EXEC DEFAULT_EXP_LOGFILEDIR "/suexec_log" /* Need me? */
#endif

/*
 * DOC_ROOT -- Define as the DocumentRoot set for Apache.  This
 *             will be the only hierarchy (aside from UserDirs)
 *             that can be used for suEXEC behavior.
 */
#ifndef AP_DOC_ROOT
#define AP_DOC_ROOT DEFAULT_EXP_HTDOCSDIR
#endif

/*
 * SAFE_PATH -- Define a safe PATH environment to pass to CGI executables.
 *
 */
#ifndef AP_SAFE_PATH
#define AP_SAFE_PATH "/usr/local/bin:/usr/bin:/bin"
#endif

#endif /* _SUEXEC_H */
