/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#include "ap_config.h"
#define CORE_PRIVATE
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

unixd_config_rec unixd_config;

/* Set group privileges.
 *
 * Note that we use the username as set in the config files, rather than
 * the lookup of to uid --- the same uid may have multiple passwd entries,
 * with different sets of groups for each.
 */

static int set_group_privs(void)
{
    if (!geteuid()) {
	const char *name;

	/* Get username if passed as a uid */

	if (unixd_config.user_name[0] == '#') {
	    struct passwd *ent;
	    uid_t uid = atoi(&unixd_config.user_name[1]);

	    if ((ent = getpwuid(uid)) == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			 "getpwuid: couldn't determine user name from uid %u, "
			 "you probably need to modify the User directive",
			 (unsigned)uid);
		return -1;
	    }

	    name = ent->pw_name;
	}
	else
	    name = unixd_config.user_name;

#if !defined(OS2) && !defined(TPF)
	/* OS/2 and TPF don't support groups. */

	/*
	 * Set the GID before initgroups(), since on some platforms
	 * setgid() is known to zap the group list.
	 */
	if (setgid(unixd_config.group_id) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"setgid: unable to set group id to Group %u",
			(unsigned)unixd_config.group_id);
	    return -1;
	}

	/* Reset `groups' attributes. */

	if (initgroups(name, unixd_config.group_id) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"initgroups: unable to set groups for User %s "
			"and Group %u", name, (unsigned)unixd_config.group_id);
	    return -1;
	}
#endif /* !defined(OS2) && !defined(TPF) */
    }
    return 0;
}


AP_DECLARE(int) unixd_setup_child(void)
{
    if (set_group_privs()) {
	return -1;
    }
#ifdef MPE
    /* Only try to switch if we're running as MANAGER.SYS */
    if (geteuid() == 1 && unixd_config.user_id > 1) {
	GETPRIVMODE();
	if (setuid(unixd_config.user_id) == -1) {
	    GETUSERMODE();
	    ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"setuid: unable to change to uid: %ld",
                        (long) unixd_config.user_id);
	    exit(1);
	}
	GETUSERMODE();
    }
#else
    /* Only try to switch if we're running as root */
    if (!geteuid() && (
#ifdef _OSD_POSIX
	os_init_job_environment(server_conf, unixd_config.user_name, one_process) != 0 || 
#endif
	setuid(unixd_config.user_id) == -1)) {
	ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
		    "setuid: unable to change to uid: %ld",
                    (long) unixd_config.user_id);
	return -1;
    }
#endif
    return 0;
}


AP_DECLARE(const char *) unixd_set_user(cmd_parms *cmd, void *dummy, 
                                        const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    unixd_config.user_name = arg;
    unixd_config.user_id = ap_uname2id(arg);
#if !defined (BIG_SECURITY_HOLE) && !defined (OS2)
    if (unixd_config.user_id == 0) {
	return "Error:\tApache has not been designed to serve pages while\n"
		"\trunning as root.  There are known race conditions that\n"
		"\twill allow any local user to read any file on the system.\n"
		"\tIf you still desire to serve pages as root then\n"
		"\tadd -DBIG_SECURITY_HOLE to the CFLAGS env variable\n"
		"\tand then rebuild the server.\n"
		"\tIt is strongly suggested that you instead modify the User\n"
		"\tdirective in your httpd.conf file to list a non-root\n"
		"\tuser.\n";
    }
#endif

    return NULL;
}

AP_DECLARE(const char *) unixd_set_group(cmd_parms *cmd, void *dummy, 
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    unixd_config.group_id = ap_gname2id(arg);

    return NULL;
}

AP_DECLARE(void) unixd_pre_config(apr_pool_t *ptemp)
{
    apr_finfo_t wrapper;

    unixd_config.user_name = DEFAULT_USER;
    unixd_config.user_id = ap_uname2id(DEFAULT_USER);
    unixd_config.group_id = ap_gname2id(DEFAULT_GROUP);

    /* Check for suexec */
    unixd_config.suexec_enabled = 0;
    if ((apr_stat(&wrapper, SUEXEC_BIN, 
                  APR_FINFO_NORM, ptemp)) != APR_SUCCESS) {
        return;
    }

    /* XXX - apr_stat is incapable of checking suid bits (grumble) */
    /* if ((wrapper.filetype & S_ISUID) && wrapper.user == 0) { */
        unixd_config.suexec_enabled = 1;
    /* } */
}


AP_DECLARE(void) unixd_set_rlimit(cmd_parms *cmd, struct rlimit **plimit, 
                           const char *arg, const char * arg2, int type)
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

    if (!unixd_config.suexec_enabled) {
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

AP_DECLARE(apr_status_t) unixd_set_proc_mutex_perms(apr_proc_mutex_t *pmutex)
{
/* MPM shouldn't call us unless we're actually using a SysV sem;
 * this is just to avoid compile issues on systems without that
 * feature
 */
#if APR_HAS_SYSVSEM_SERIALIZE
    apr_os_proc_mutex_t ospmutex;
#if !APR_HAVE_UNION_SEMUN
    union semun {
        long val;
        struct semid_ds *buf;
        ushort *array;
    };
#endif
    union semun ick;
    struct semid_ds buf;

    if (!geteuid()) {
        apr_os_proc_mutex_get(&ospmutex, pmutex);
        buf.sem_perm.uid = unixd_config.user_id;
        buf.sem_perm.gid = unixd_config.group_id;
        buf.sem_perm.mode = 0600;
        ick.buf = &buf;
        if (semctl(ospmutex.crossproc, 0, IPC_SET, ick) < 0) {
            return errno;
        }
    }
#endif
    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) unixd_set_global_mutex_perms(apr_global_mutex_t *gmutex)
{
#if !APR_PROC_MUTEX_IS_GLOBAL
    apr_os_global_mutex_t osgmutex;
    apr_os_global_mutex_get(&osgmutex, gmutex);
    return unixd_set_proc_mutex_perms(osgmutex.proc_mutex);
#else  /* APR_PROC_MUTEX_IS_GLOBAL */
    /* In this case, apr_proc_mutex_t and apr_global_mutex_t are the same. */
    return unixd_set_proc_mutex_perms(gmutex);
#endif /* APR_PROC_MUTEX_IS_GLOBAL */
}

AP_DECLARE(apr_status_t) unixd_accept(void **accepted, ap_listen_rec *lr,
                                        apr_pool_t *ptrans)
{
    apr_socket_t *csd;
    apr_status_t status;
    int sockdes;

    *accepted = NULL;
    status = apr_accept(&csd, lr->sd, ptrans);
    if (status == APR_SUCCESS) { 
        *accepted = csd;
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
#ifdef TPF
        if (sockdes == 0) {                  /* 0 is invalid socket for TPF */
            return APR_EINTR;
        }
#endif
        return status;
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
                         "apr_accept: giving up.");
            return APR_EGENERAL;
#endif /*ENETDOWN*/

#ifdef TPF
        case EINACT:
            ap_log_error(APLOG_MARK, APLOG_EMERG, status, ap_server_conf,
                         "offload device inactive");
            return APR_EGENERAL;
            break;
        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         "select/accept error (%d)", status);
            return APR_EGENERAL;
#else
        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, status, ap_server_conf,
                         "apr_accept: (client socket)");
            return APR_EGENERAL;
#endif
    }
    return status;
}

