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

/* The purpose of this file is to store the code that MOST mpm's will need
 * this does not mean a function only goes into this file if every MPM needs
 * it.  It means that if a function is needed by more than one MPM, and
 * future maintenance would be served by making the code common, then the
 * function belongs here.
 *
 * This is going in src/main because it is not platform specific, it is
 * specific to multi-process servers, but NOT to Unix.  Which is why it
 * does not belong in src/os/unix
 */

#include "apr.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"
#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_getopt.h"
#include "apr_optional.h"
#include "apr_allocator.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_main.h"
#include "mpm_common.h"
#include "ap_mpm.h"
#include "ap_listen.h"
#include "util_mutex.h"

#include "scoreboard.h"

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#if AP_ENABLE_EXCEPTION_HOOK
APR_HOOK_STRUCT(
    APR_HOOK_LINK(fatal_exception)
    APR_HOOK_LINK(monitor)
    APR_HOOK_LINK(drop_privileges)
    APR_HOOK_LINK(mpm)
    APR_HOOK_LINK(mpm_query)
    APR_HOOK_LINK(mpm_note_child_killed)
    APR_HOOK_LINK(mpm_register_timed_callback)
    APR_HOOK_LINK(mpm_get_name)
)
AP_IMPLEMENT_HOOK_RUN_ALL(int, fatal_exception,
                          (ap_exception_info_t *ei), (ei), OK, DECLINED)
#else
APR_HOOK_STRUCT(
    APR_HOOK_LINK(monitor)
    APR_HOOK_LINK(drop_privileges)
    APR_HOOK_LINK(mpm)
    APR_HOOK_LINK(mpm_query)
    APR_HOOK_LINK(mpm_note_child_killed)
    APR_HOOK_LINK(mpm_register_timed_callback)
    APR_HOOK_LINK(mpm_get_name)
)
#endif
AP_IMPLEMENT_HOOK_RUN_ALL(int, monitor,
                          (apr_pool_t *p, server_rec *s), (p, s), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int, drop_privileges,
                          (apr_pool_t * pchild, server_rec * s),
                          (pchild, s), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int, mpm,
                            (apr_pool_t *pconf, apr_pool_t *plog, server_rec *s),
                            (pconf, plog, s), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int, mpm_query,
                            (int query_code, int *result, apr_status_t *_rv),
                            (query_code, result, _rv), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(apr_status_t, mpm_note_child_killed,
                            (int childnum),
                            (childnum), APR_ENOTIMPL)
AP_IMPLEMENT_HOOK_RUN_FIRST(apr_status_t, mpm_register_timed_callback,
                            (apr_time_t t, ap_mpm_callback_fn_t *cbfn, void *baton),
                            (t, cbfn, baton), APR_ENOTIMPL)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *, mpm_get_name,
                            (void),
                            (), NULL)

/* number of calls to wait_or_timeout between writable probes */
#ifndef INTERVAL_OF_WRITABLE_PROBES
#define INTERVAL_OF_WRITABLE_PROBES 10
#endif
static int wait_or_timeout_counter;

void ap_wait_or_timeout(apr_exit_why_e *status, int *exitcode, apr_proc_t *ret,
                        apr_pool_t *p, server_rec *s)
{
    apr_status_t rv;

    ++wait_or_timeout_counter;
    if (wait_or_timeout_counter == INTERVAL_OF_WRITABLE_PROBES) {
        wait_or_timeout_counter = 0;
        ap_run_monitor(p, s);
    }

    rv = apr_proc_wait_all_procs(ret, exitcode, status, APR_NOWAIT, p);
    if (APR_STATUS_IS_EINTR(rv)) {
        ret->pid = -1;
        return;
    }

    if (APR_STATUS_IS_CHILD_DONE(rv)) {
        return;
    }

    apr_sleep(1000000);
    ret->pid = -1;
    return;
}

#if defined(TCP_NODELAY)
void ap_sock_disable_nagle(apr_socket_t *s)
{
    /* The Nagle algorithm says that we should delay sending partial
     * packets in hopes of getting more data.  We don't want to do
     * this; we are not telnet.  There are bad interactions between
     * persistent connections and Nagle's algorithm that have very severe
     * performance penalties.  (Failing to disable Nagle is not much of a
     * problem with simple HTTP.)
     *
     * In spite of these problems, failure here is not a shooting offense.
     */
    apr_status_t status = apr_socket_opt_set(s, APR_TCP_NODELAY, 1);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, status, ap_server_conf,
                     "apr_socket_opt_set: (TCP_NODELAY)");
    }
}
#endif

#ifdef HAVE_GETPWNAM
AP_DECLARE(uid_t) ap_uname2id(const char *name)
{
    struct passwd *ent;

    if (name[0] == '#')
        return (atoi(&name[1]));

    if (!(ent = getpwnam(name))) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "%s: bad user name %s", ap_server_argv0, name);
        exit(1);
    }

    return (ent->pw_uid);
}
#endif

#ifdef HAVE_GETGRNAM
AP_DECLARE(gid_t) ap_gname2id(const char *name)
{
    struct group *ent;

    if (name[0] == '#')
        return (atoi(&name[1]));

    if (!(ent = getgrnam(name))) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "%s: bad group name %s", ap_server_argv0, name);
        exit(1);
    }

    return (ent->gr_gid);
}
#endif

#ifndef HAVE_INITGROUPS
int initgroups(const char *name, gid_t basegid)
{
#if defined(_OSD_POSIX) || defined(OS2) || defined(WIN32) || defined(NETWARE)
    return 0;
#else
    gid_t groups[NGROUPS_MAX];
    struct group *g;
    int index = 0;

    setgrent();

    groups[index++] = basegid;

    while (index < NGROUPS_MAX && ((g = getgrent()) != NULL)) {
        if (g->gr_gid != basegid) {
            char **names;

            for (names = g->gr_mem; *names != NULL; ++names) {
                if (!strcmp(*names, name))
                    groups[index++] = g->gr_gid;
            }
        }
    }

    endgrent();

    return setgroups(index, groups);
#endif
}
#endif /* def NEED_INITGROUPS */

/* standard mpm configuration handling */
const char *ap_pid_fname = NULL;

const char *ap_mpm_set_pidfile(cmd_parms *cmd, void *dummy,
                               const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (cmd->server->is_virtual) {
        return "PidFile directive not allowed in <VirtualHost>";
    }

    ap_pid_fname = arg;
    return NULL;
}

int ap_max_requests_per_child = 0;

const char *ap_mpm_set_max_requests(cmd_parms *cmd, void *dummy,
                                    const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_max_requests_per_child = atoi(arg);

    return NULL;
}

char ap_coredump_dir[MAX_STRING_LEN];
int ap_coredumpdir_configured;

const char *ap_mpm_set_coredumpdir(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    apr_status_t rv;
    apr_finfo_t finfo;
    const char *fname;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    fname = ap_server_root_relative(cmd->pool, arg);
    if (!fname) {
        return apr_pstrcat(cmd->pool, "Invalid CoreDumpDirectory path ",
                           arg, NULL);
    }
    if ((rv = apr_stat(&finfo, fname, APR_FINFO_TYPE, cmd->pool)) != APR_SUCCESS) {
        return apr_pstrcat(cmd->pool, "CoreDumpDirectory ", fname,
                           " does not exist", NULL);
    }
    if (finfo.filetype != APR_DIR) {
        return apr_pstrcat(cmd->pool, "CoreDumpDirectory ", fname,
                           " is not a directory", NULL);
    }
    apr_cpystrn(ap_coredump_dir, fname, sizeof(ap_coredump_dir));
    ap_coredumpdir_configured = 1;
    return NULL;
}

int ap_graceful_shutdown_timeout = 0;

const char * ap_mpm_set_graceful_shutdown(cmd_parms *cmd, void *dummy,
                                          const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    ap_graceful_shutdown_timeout = atoi(arg);
    return NULL;
}

apr_uint32_t ap_max_mem_free = APR_ALLOCATOR_MAX_FREE_UNLIMITED;

const char *ap_mpm_set_max_mem_free(cmd_parms *cmd, void *dummy,
                                    const char *arg)
{
    long value;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    value = strtol(arg, NULL, 0);
    if (value < 0 || errno == ERANGE)
        return apr_pstrcat(cmd->pool, "Invalid MaxMemFree value: ",
                           arg, NULL);

    ap_max_mem_free = (apr_uint32_t)value * 1024;

    return NULL;
}

apr_size_t ap_thread_stacksize = 0; /* use system default */

const char *ap_mpm_set_thread_stacksize(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    long value;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    value = strtol(arg, NULL, 0);
    if (value < 0 || errno == ERANGE)
        return apr_pstrcat(cmd->pool, "Invalid ThreadStackSize value: ",
                           arg, NULL);

    ap_thread_stacksize = (apr_size_t)value;

    return NULL;
}

AP_DECLARE(apr_status_t) ap_mpm_query(int query_code, int *result)
{
    apr_status_t rv;

    if (ap_run_mpm_query(query_code, result, &rv) == DECLINED) {
        rv = APR_EGENERAL;
    }

    return rv;
}

AP_DECLARE(apr_status_t) ap_mpm_note_child_killed(int childnum)
{
    return ap_run_mpm_note_child_killed(childnum);
}

AP_DECLARE(apr_status_t) ap_mpm_register_timed_callback(apr_time_t t, ap_mpm_callback_fn_t *cbfn, void *baton)
{
    return ap_run_mpm_register_timed_callback(t, cbfn, baton);
}

AP_DECLARE(const char *)ap_show_mpm(void)
{
    const char *name = ap_run_mpm_get_name();

    if (!name) {
        name = "";
    }

    return name;
}
