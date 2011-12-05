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
 * This file will include OS specific functions which are not inlineable.
 * Any inlineable functions should be defined in os-inline.c instead.
 */

#ifdef _OSD_POSIX

#include "os.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_lib.h"

#define USER_LEN 8

APLOG_USE_MODULE(core);

typedef enum
{
    bs2_unknown,     /* not initialized yet. */
    bs2_noFORK,      /* no fork() because -X flag was specified */
    bs2_FORK,        /* only fork() because uid != 0 */
    bs2_UFORK        /* Normally, ufork() is used to switch identities. */
} bs2_ForkType;

static bs2_ForkType forktype = bs2_unknown;

/* Determine the method for forking off a child in such a way as to
 * set both the POSIX and BS2000 user id's to the unprivileged user.
 */
static bs2_ForkType os_forktype(int one_process)
{
    /* have we checked the OS version before? If yes return the previous
     * result - the OS release isn't going to change suddenly!
     */
    if (forktype == bs2_unknown) {
        /* not initialized yet */

        /* No fork if the one_process option was set */
        if (one_process) {
            forktype = bs2_noFORK;
        }
        /* If the user is unprivileged, use the normal fork() only. */
        else if (getuid() != 0) {
            forktype = bs2_FORK;
        }
        else
            forktype = bs2_UFORK;
    }
    return forktype;
}



/* This routine complements the setuid() call: it causes the BS2000 job
 * environment to be switched to the target user's user id.
 * That is important if CGI scripts try to execute native BS2000 commands.
 */
int os_init_job_environment(server_rec *server, const char *user_name, int one_process)
{
    bs2_ForkType            type = os_forktype(one_process);

    /* We can be sure that no change to uid==0 is possible because of
     * the checks in http_core.c:set_user()
     */

    if (one_process) {

        type = forktype = bs2_noFORK;

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, APLOGNO(02170)
                     "The debug mode of Apache should only "
                     "be started by an unprivileged user!");
        return 0;
    }

    return 0;
}

/* BS2000 requires a "special" version of fork() before a setuid() call */
pid_t os_fork(const char *user)
{
    pid_t pid;
    char  username[USER_LEN+1];

    switch (os_forktype(0)) {

      case bs2_FORK:
        pid = fork();
        break;

      case bs2_UFORK:
        apr_cpystrn(username, user, sizeof username);

        /* Make user name all upper case - for some versions of ufork() */
        ap_str_toupper(username);

        pid = ufork(username);
        if (pid == -1 && errno == EPERM) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, errno,
                         ap_server_conf, APLOGNO(02171) "ufork: Possible mis-configuration "
                         "for user %s - Aborting.", user);
            exit(1);
        }
        break;

      default:
        pid = 0;
        break;
    }

    return pid;
}

#else /* _OSD_POSIX */
void bs2000_os_is_not_here()
{
}
#endif /* _OSD_POSIX */
