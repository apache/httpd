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

#include "simple_api.h"

#ifndef DEFAULT_USER
#define DEFAULT_USER "#-1"
#endif
#ifndef DEFAULT_GROUP
#define DEFAULT_GROUP "#-1"
#endif

typedef struct {
  const char *user_name;
  uid_t user_id;
  gid_t group_id;
  const char *chroot_dir;
} unixd_config_t;


unixd_config_t unixd_config;

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
            uid_t uid = atol(&unixd_config.user_name[1]);

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


static int 
unixd_drop_privileges(apr_pool_t *pool, server_rec *s)
{
    int rv = set_group_privs();

    if (rv) {
        return rv;
    }

    if (NULL != unixd_config.chroot_dir) {
        if (geteuid()) {
            rv = errno;
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Cannot chroot when not started as root");
            return rv;
        }

        if (chdir(unixd_config.chroot_dir) != 0) {
            rv = errno;
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Can't chdir to %s", unixd_config.chroot_dir);
            return rv;
        }

        if (chroot(unixd_config.chroot_dir) != 0) {
            rv = errno;
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "Can't chroot to %s", unixd_config.chroot_dir);
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
    if (geteuid() == 1 && unixd_config.user_id > 1) {
        GETPRIVMODE();
        if (setuid(unixd_config.user_id) == -1) {
            GETUSERMODE();
            rv = errno;
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                        "setuid: unable to change to uid: %ld",
                        (long) unixd_config.user_id);
            return rv;
        }
        GETUSERMODE();
    }
#else
    /* Only try to switch if we're running as root */
    if (!geteuid() && (
#ifdef _OSD_POSIX
        os_init_job_environment(NULL, unixd_config.user_name, ap_exists_config_define("DEBUG")) != 0 ||
#endif
        setuid(unixd_config.user_id) == -1)) {
        rv = errno;
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                    "setuid: unable to change to uid: %ld",
                    (long) unixd_config.user_id);
        return rv;
    }
#if defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
    /* this applies to Linux 2.4+ */
#ifdef AP_MPM_WANT_SET_COREDUMPDIR
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

static const char* 
unixd_set_group(cmd_parms *cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    unixd_config.group_id = ap_gname2id(arg);

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

    unixd_config.chroot_dir = arg;
    return NULL;
}

static int 
unixd_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                 apr_pool_t *ptemp)
{
    unixd_config.user_name = DEFAULT_USER;
    unixd_config.user_id = ap_uname2id(DEFAULT_USER);
    unixd_config.group_id = ap_gname2id(DEFAULT_GROUP);

    unixd_config.chroot_dir = NULL; /* none */

    return OK;
}

static void unixd_hooks(apr_pool_t *pool)
{
    ap_hook_pre_config(unixd_pre_config,
                       NULL, NULL, APR_HOOK_FIRST);

    ap_hook_simple_drop_privileges(unixd_drop_privileges,
                                   NULL, NULL, APR_HOOK_FIRST);
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
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    unixd_cmds,
    unixd_hooks
};
