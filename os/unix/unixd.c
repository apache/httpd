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

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_main.h"
#include "http_log.h"
#include "unixd.h"
#include "mpm_common.h"
#include "os.h"
#include "ap_mpm.h"
#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "apr_portable.h"
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
/* XXX */
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#ifdef HAVE_SYS_SEM_H
#include <sys/sem.h>
#endif
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

unixd_config_rec ap_unixd_config;


AP_DECLARE(void) ap_unixd_set_rlimit(cmd_parms *cmd, struct rlimit **plimit,
                                     const char *arg,
                                     const char * arg2, int type)
{
#if (defined(RLIMIT_CPU) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_NPROC) || defined(RLIMIT_AS)) && APR_HAVE_STRUCT_RLIMIT && APR_HAVE_GETRLIMIT
    char *str;
    struct rlimit *limit;
    /* If your platform doesn't define rlim_t then typedef it in ap_config.h */
    rlim_t cur = 0;
    rlim_t max = 0;

    *plimit = (struct rlimit *)apr_pcalloc(cmd->pool, sizeof(**plimit));
    limit = *plimit;
    if ((getrlimit(type, limit)) != 0)  {
        *plimit = NULL;
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, cmd->server,
                     "%s: getrlimit failed", cmd->cmd->name);
        return;
    }

    if ((str = ap_getword_conf(cmd->pool, &arg))) {
        if (!strcasecmp(str, "max")) {
            cur = limit->rlim_max;
        }
        else {
            cur = atol(str);
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                     "Invalid parameters for %s", cmd->cmd->name);
        return;
    }

    if (arg2 && (str = ap_getword_conf(cmd->pool, &arg2))) {
        max = atol(str);
    }

    /* if we aren't running as root, cannot increase max */
    if (geteuid()) {
        limit->rlim_cur = cur;
        if (max) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                         "Must be uid 0 to raise maximum %s", cmd->cmd->name);
        }
    }
    else {
        if (cur) {
            limit->rlim_cur = cur;
        }
        if (max) {
            limit->rlim_max = max;
        }
    }
#else

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                 "Platform does not support rlimit for %s", cmd->cmd->name);
#endif
}

APR_HOOK_STRUCT(
               APR_HOOK_LINK(get_suexec_identity)
)

AP_IMPLEMENT_HOOK_RUN_FIRST(ap_unix_identity_t *, get_suexec_identity,
                         (const request_rec *r), (r), NULL)

static apr_status_t ap_unix_create_privileged_process(
                              apr_proc_t *newproc, const char *progname,
                              const char * const *args,
                              const char * const *env,
                              apr_procattr_t *attr, ap_unix_identity_t *ugid,
                              apr_pool_t *p)
{
    int i = 0;
    const char **newargs;
    char *newprogname;
    char *execuser, *execgroup;
    const char *argv0;

    if (!ap_unixd_config.suexec_enabled) {
        return apr_proc_create(newproc, progname, args, env, attr, p);
    }

    argv0 = ap_strrchr_c(progname, '/');
    /* Allow suexec's "/" check to succeed */
    if (argv0 != NULL) {
        argv0++;
    }
    else {
        argv0 = progname;
    }


    if (ugid->userdir) {
        execuser = apr_psprintf(p, "~%ld", (long) ugid->uid);
    }
    else {
        execuser = apr_psprintf(p, "%ld", (long) ugid->uid);
    }
    execgroup = apr_psprintf(p, "%ld", (long) ugid->gid);

    if (!execuser || !execgroup) {
        return APR_ENOMEM;
    }

    i = 0;
    if (args) {
        while (args[i]) {
            i++;
            }
    }
    /* allocate space for 4 new args, the input args, and a null terminator */
    newargs = apr_palloc(p, sizeof(char *) * (i + 4));
    newprogname = SUEXEC_BIN;
    newargs[0] = SUEXEC_BIN;
    newargs[1] = execuser;
    newargs[2] = execgroup;
    newargs[3] = apr_pstrdup(p, argv0);

    /*
    ** using a shell to execute suexec makes no sense thus
    ** we force everything to be APR_PROGRAM, and never
    ** APR_SHELLCMD
    */
    if(apr_procattr_cmdtype_set(attr, APR_PROGRAM) != APR_SUCCESS) {
        return APR_EGENERAL;
    }

    i = 1;
    do {
        newargs[i + 3] = args[i];
    } while (args[i++]);

    return apr_proc_create(newproc, newprogname, newargs, env, attr, p);
}

AP_DECLARE(apr_status_t) ap_os_create_privileged_process(
    const request_rec *r,
    apr_proc_t *newproc, const char *progname,
    const char * const *args,
    const char * const *env,
    apr_procattr_t *attr, apr_pool_t *p)
{
    ap_unix_identity_t *ugid = ap_run_get_suexec_identity(r);

    if (ugid == NULL) {
        return apr_proc_create(newproc, progname, args, env, attr, p);
    }

    return ap_unix_create_privileged_process(newproc, progname, args, env,
                                              attr, ugid, p);
}

/* XXX move to APR and externalize (but implement differently :) ) */
static apr_lockmech_e proc_mutex_mech(apr_proc_mutex_t *pmutex)
{
    const char *mechname = apr_proc_mutex_name(pmutex);

    if (!strcmp(mechname, "sysvsem")) {
        return APR_LOCK_SYSVSEM;
    }
    else if (!strcmp(mechname, "flock")) {
        return APR_LOCK_FLOCK;
    }
    return APR_LOCK_DEFAULT;
}

AP_DECLARE(apr_status_t) ap_unixd_set_proc_mutex_perms(apr_proc_mutex_t *pmutex)
{
    if (!geteuid()) {
        apr_lockmech_e mech = proc_mutex_mech(pmutex);

        switch(mech) {
#if APR_HAS_SYSVSEM_SERIALIZE
        case APR_LOCK_SYSVSEM:
        {
            apr_os_proc_mutex_t ospmutex;
#if !APR_HAVE_UNION_SEMUN
            union semun {
                long val;
                struct semid_ds *buf;
                unsigned short *array;
            };
#endif
            union semun ick;
            struct semid_ds buf;

            apr_os_proc_mutex_get(&ospmutex, pmutex);
            buf.sem_perm.uid = ap_unixd_config.user_id;
            buf.sem_perm.gid = ap_unixd_config.group_id;
            buf.sem_perm.mode = 0600;
            ick.buf = &buf;
            if (semctl(ospmutex.crossproc, 0, IPC_SET, ick) < 0) {
                return errno;
            }
        }
        break;
#endif
#if APR_HAS_FLOCK_SERIALIZE
        case APR_LOCK_FLOCK:
        {
            const char *lockfile = apr_proc_mutex_lockfile(pmutex);

            if (lockfile) {
                if (chown(lockfile, ap_unixd_config.user_id,
                          -1 /* no gid change */) < 0) {
                    return errno;
                }
            }
        }
        break;
#endif
        default:
            /* do nothing */
            break;
        }
    }
    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_unixd_set_global_mutex_perms(apr_global_mutex_t *gmutex)
{
#if !APR_PROC_MUTEX_IS_GLOBAL
    apr_os_global_mutex_t osgmutex;
    apr_os_global_mutex_get(&osgmutex, gmutex);
    return ap_unixd_set_proc_mutex_perms(osgmutex.proc_mutex);
#else  /* APR_PROC_MUTEX_IS_GLOBAL */
    /* In this case, apr_proc_mutex_t and apr_global_mutex_t are the same. */
    return ap_unixd_set_proc_mutex_perms(gmutex);
#endif /* APR_PROC_MUTEX_IS_GLOBAL */
}

AP_DECLARE(apr_status_t) ap_unixd_accept(void **accepted, ap_listen_rec *lr,
                                         apr_pool_t *ptrans)
{
    apr_socket_t *csd;
    apr_status_t status;
#ifdef _OSD_POSIX
    int sockdes;
#endif

    *accepted = NULL;
    status = apr_socket_accept(&csd, lr->sd, ptrans);
    if (status == APR_SUCCESS) {
        *accepted = csd;
#ifdef _OSD_POSIX
        apr_os_sock_get(&sockdes, csd);
        if (sockdes >= FD_SETSIZE) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
                         "new file descriptor %d is too large; you probably need "
                         "to rebuild Apache with a larger FD_SETSIZE "
                         "(currently %d)",
                         sockdes, FD_SETSIZE);
            apr_socket_close(csd);
            return APR_EINTR;
        }
#endif
        return APR_SUCCESS;
    }

    if (APR_STATUS_IS_EINTR(status)) {
        return status;
    }
    /* Our old behaviour here was to continue after accept()
     * errors.  But this leads us into lots of troubles
     * because most of the errors are quite fatal.  For
     * example, EMFILE can be caused by slow descriptor
     * leaks (say in a 3rd party module, or libc).  It's
     * foolish for us to continue after an EMFILE.  We also
     * seem to tickle kernel bugs on some platforms which
     * lead to never-ending loops here.  So it seems best
     * to just exit in most cases.
     */
    switch (status) {
#if defined(HPUX11) && defined(ENOBUFS)
        /* On HPUX 11.x, the 'ENOBUFS, No buffer space available'
         * error occurs because the accept() cannot complete.
         * You will not see ENOBUFS with 10.20 because the kernel
         * hides any occurrence from being returned to user space.
         * ENOBUFS with 11.x's TCP/IP stack is possible, and could
         * occur intermittently. As a work-around, we are going to
         * ignore ENOBUFS.
         */
        case ENOBUFS:
#endif

#ifdef EPROTO
        /* EPROTO on certain older kernels really means
         * ECONNABORTED, so we need to ignore it for them.
         * See discussion in new-httpd archives nh.9701
         * search for EPROTO.
         *
         * Also see nh.9603, search for EPROTO:
         * There is potentially a bug in Solaris 2.x x<6,
         * and other boxes that implement tcp sockets in
         * userland (i.e. on top of STREAMS).  On these
         * systems, EPROTO can actually result in a fatal
         * loop.  See PR#981 for example.  It's hard to
         * handle both uses of EPROTO.
         */
        case EPROTO:
#endif
#ifdef ECONNABORTED
        case ECONNABORTED:
#endif
        /* Linux generates the rest of these, other tcp
         * stacks (i.e. bsd) tend to hide them behind
         * getsockopt() interfaces.  They occur when
         * the net goes sour or the client disconnects
         * after the three-way handshake has been done
         * in the kernel but before userland has picked
         * up the socket.
         */
#ifdef ECONNRESET
        case ECONNRESET:
#endif
#ifdef ETIMEDOUT
        case ETIMEDOUT:
#endif
#ifdef EHOSTUNREACH
        case EHOSTUNREACH:
#endif
#ifdef ENETUNREACH
        case ENETUNREACH:
#endif
        /* EAGAIN/EWOULDBLOCK can be returned on BSD-derived
         * TCP stacks when the connection is aborted before
         * we call connect, but only because our listener
         * sockets are non-blocking (AP_NONBLOCK_WHEN_MULTI_LISTEN)
         */
#ifdef EAGAIN
        case EAGAIN:
#endif
#ifdef EWOULDBLOCK
#if !defined(EAGAIN) || EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
#endif
            break;
#ifdef ENETDOWN
        case ENETDOWN:
            /*
             * When the network layer has been shut down, there
             * is not much use in simply exiting: the parent
             * would simply re-create us (and we'd fail again).
             * Use the CHILDFATAL code to tear the server down.
             * @@@ Martin's idea for possible improvement:
             * A different approach would be to define
             * a new APEXIT_NETDOWN exit code, the reception
             * of which would make the parent shutdown all
             * children, then idle-loop until it detected that
             * the network is up again, and restart the children.
             * Ben Hyde noted that temporary ENETDOWN situations
             * occur in mobile IP.
             */
            ap_log_error(APLOG_MARK, APLOG_EMERG, status, ap_server_conf,
                         "apr_socket_accept: giving up.");
            return APR_EGENERAL;
#endif /*ENETDOWN*/

        default:
            /* If the socket has been closed in ap_close_listeners()
             * by the restart/stop action, we may get EBADF.
             * Do not print an error in this case.
             */
            if (!lr->active) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, status, ap_server_conf,
                             "apr_socket_accept failed for inactive listener");
                return status;
            }
            ap_log_error(APLOG_MARK, APLOG_ERR, status, ap_server_conf,
                         "apr_socket_accept: (client socket)");
            return APR_EGENERAL;
    }
    return status;
}


#ifdef _OSD_POSIX

#include "apr_lib.h"

#define USER_LEN 8

typedef enum
{
    bs2_unknown,     /* not initialized yet. */
    bs2_noFORK,      /* no fork() because -X flag was specified */
    bs2_FORK,        /* only fork() because uid != 0 */
    bs2_UFORK        /* Normally, ufork() is used to switch identities. */
} bs2_ForkType;

static bs2_ForkType forktype = bs2_unknown;


static void ap_str_toupper(char *str)
{
    while (*str) {
        *str = apr_toupper(*str);
        ++str;
    }
}

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

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server,
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
                         NULL, "ufork: Possible mis-configuration "
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

#endif /* _OSD_POSIX */

