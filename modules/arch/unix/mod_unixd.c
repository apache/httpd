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
#include "mpm_common.h"
#include "os.h"
#include "ap_mpm.h"
#include "mod_unixd.h"
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

#ifndef DEFAULT_USER
#define DEFAULT_USER "#-1"
#endif
#ifndef DEFAULT_GROUP
#define DEFAULT_GROUP "#-1"
#endif

#if 0
typedef struct {
  const char *user_name;
  uid_t user_id;
  gid_t group_id;
  const char *chroot_dir;
} unixd_config_t;
#else
/*
 * TODO: clean up the separation between this code
 *       and its data structures and unixd.c, as shown
 *       by the fact that we include unixd.h. Create
 *       mod_unixd.h which does what we need and
 *       clean up unixd.h for what it no longer needs
 */
#include "unixd.h"
#endif


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

        if (ap_unixd_config.user_name[0] == '#') {
            struct passwd *ent;
            uid_t uid = atol(&ap_unixd_config.user_name[1]);

            if ((ent = getpwuid(uid)) == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "getpwuid: couldn't determine user name from uid %ld, "
                         "you probably need to modify the User directive",
                         (long)uid);
                return -1;
            }

            name = ent->pw_name;
        }
        else
            name = ap_unixd_config.user_name;

        /*
         * Set the GID before initgroups(), since on some platforms
         * setgid() is known to zap the group list.
         */
        if (setgid(ap_unixd_config.group_id) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                        "setgid: unable to set group id to Group %u",
                        (unsigned)ap_unixd_config.group_id);
            return -1;
        }

        /* Reset `groups' attributes. */

        if (initgroups(name, ap_unixd_config.group_id) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                        "initgroups: unable to set groups for User %s "
                        "and Group %u", name, (unsigned)ap_unixd_config.group_id);
            return -1;
        }
    }
    return 0;
}


static int 
unixd_drop_privileges(apr_pool_t *pool, server_rec *s)
{
    int rv = set_group_privs();

    if (rv) {
        return rv;
    }

    if (NULL != ap_unixd_config.chroot_dir) {
        if (geteuid()) {
            rv = errno;
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Cannot chroot when not started as root");
            return rv;
        }

        if (chdir(ap_unixd_config.chroot_dir) != 0) {
            rv = errno;
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Can't chdir to %s", ap_unixd_config.chroot_dir);
            return rv;
        }

        if (chroot(ap_unixd_config.chroot_dir) != 0) {
            rv = errno;
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Can't chroot to %s", ap_unixd_config.chroot_dir);
            return rv;
        }

        if (chdir("/") != 0) {
            rv = errno;
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Can't chdir to new root");
            return rv;
        }
    }

#ifdef MPE
    /* Only try to switch if we're running as MANAGER.SYS */
    if (geteuid() == 1 && ap_unixd_config.user_id > 1) {
        GETPRIVMODE();
        if (setuid(ap_unixd_config.user_id) == -1) {
            GETUSERMODE();
            rv = errno;
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                        "setuid: unable to change to uid: %ld",
                        (long) ap_unixd_config.user_id);
            return rv;
        }
        GETUSERMODE();
    }
#else
    /* Only try to switch if we're running as root */
    if (!geteuid() && (
#ifdef _OSD_POSIX
        os_init_job_environment(NULL, ap_unixd_config.user_name, ap_exists_config_define("DEBUG")) != 0 ||
#endif
        setuid(ap_unixd_config.user_id) == -1)) {
        rv = errno;
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                    "setuid: unable to change to uid: %ld",
                    (long) ap_unixd_config.user_id);
        return rv;
    }
#if defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
    /* this applies to Linux 2.4+ */
    if (ap_coredumpdir_configured) {
        if (prctl(PR_SET_DUMPABLE, 1)) {
            rv = errno;
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "set dumpable failed - this child will not coredump"
                         " after software errors");
            return rv;
        }
    }
#endif
#endif

    return OK;
}


static const char *
unixd_set_user(cmd_parms *cmd, void *dummy,
               const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_unixd_config.user_name = arg;
    ap_unixd_config.user_id = ap_uname2id(arg);
#if !defined (BIG_SECURITY_HOLE)
    if (ap_unixd_config.user_id == 0) {
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

static const char* 
unixd_set_group(cmd_parms *cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_unixd_config.group_id = ap_gname2id(arg);

    return NULL;
}

static const char* 
unixd_set_chroot_dir(cmd_parms *cmd, void *dummy,
                    const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    if (!ap_is_directory(cmd->pool, arg)) {
        return "ChrootDir must be a valid directory";
    }

    ap_unixd_config.chroot_dir = arg;
    return NULL;
}

static int 
unixd_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                 apr_pool_t *ptemp)
{
    apr_finfo_t wrapper;
    ap_unixd_config.user_name = DEFAULT_USER;
    ap_unixd_config.user_id = ap_uname2id(DEFAULT_USER);
    ap_unixd_config.group_id = ap_gname2id(DEFAULT_GROUP);

    ap_unixd_config.chroot_dir = NULL; /* none */

    /* Check for suexec */
    ap_unixd_config.suexec_enabled = 0;
    if ((apr_stat(&wrapper, SUEXEC_BIN, APR_FINFO_NORM, ptemp))
         == APR_SUCCESS) {
        if ((wrapper.protection & APR_USETID) && wrapper.user == 0) {
            ap_unixd_config.suexec_enabled = 1;
        }
    }

    ap_sys_privileges_handlers(1);
    return OK;
}

AP_DECLARE(int) ap_unixd_setup_child(void)
{
    if (set_group_privs()) {
        return -1;
    }

    if (NULL != ap_unixd_config.chroot_dir) {
        if (geteuid()) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Cannot chroot when not started as root");
            return -1;
        }
        if (chdir(ap_unixd_config.chroot_dir) != 0) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Can't chdir to %s", ap_unixd_config.chroot_dir);
            return -1;
        }
        if (chroot(ap_unixd_config.chroot_dir) != 0) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Can't chroot to %s", ap_unixd_config.chroot_dir);
            return -1;
        }
        if (chdir("/") != 0) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Can't chdir to new root");
            return -1;
        }
    }

#ifdef MPE
    /* Only try to switch if we're running as MANAGER.SYS */
    if (geteuid() == 1 && ap_unixd_config.user_id > 1) {
        GETPRIVMODE();
        if (setuid(ap_unixd_config.user_id) == -1) {
            GETUSERMODE();
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                        "setuid: unable to change to uid: %ld",
                        (long) ap_unixd_config.user_id);
            exit(1);
        }
        GETUSERMODE();
    }
#else
    /* Only try to switch if we're running as root */
    if (!geteuid() && (
#ifdef _OSD_POSIX
        os_init_job_environment(NULL, ap_unixd_config.user_name, ap_exists_config_define("DEBUG")) != 0 ||
#endif
        setuid(ap_unixd_config.user_id) == -1)) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                    "setuid: unable to change to uid: %ld",
                    (long) ap_unixd_config.user_id);
        return -1;
    }
#if defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
    /* this applies to Linux 2.4+ */
    if (ap_coredumpdir_configured) {
        if (prctl(PR_SET_DUMPABLE, 1)) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "set dumpable failed - this child will not coredump"
                         " after software errors");
        }
    }
#endif
#endif
    return 0;
}

static void unixd_hooks(apr_pool_t *pool)
{
    ap_hook_pre_config(unixd_pre_config,
                       NULL, NULL, APR_HOOK_FIRST);

    ap_hook_drop_privileges(unixd_drop_privileges,
                            NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec unixd_cmds[] = {
    AP_INIT_TAKE1("User", unixd_set_user, NULL, RSRC_CONF,
                  "Effective user id for this server"),
    AP_INIT_TAKE1("Group", unixd_set_group, NULL, RSRC_CONF,
                  "Effective group id for this server"),
    AP_INIT_TAKE1("ChrootDir", unixd_set_chroot_dir, NULL, RSRC_CONF,
                  "The directory to chroot(2) into"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA unixd_module = {
    MPM20_MODULE_STUFF,
    ap_mpm_rewrite_args,
    NULL,
    NULL,
    NULL,
    NULL,
    unixd_cmds,
    unixd_hooks
};

