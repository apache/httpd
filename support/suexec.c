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
 * suexec.c -- "Wrapper" support program for suEXEC behaviour for Apache
 *
 ***********************************************************************
 *
 * NOTE! : DO NOT edit this code!!!  Unless you know what you are doing,
 *         editing this code might open up your system in unexpected
 *         ways to would-be crackers.  Every precaution has been taken
 *         to make this code as safe as possible; alter it at your own
 *         risk.
 *
 ***********************************************************************
 *
 *
 */

#include "apr.h"
#include "ap_config.h"
#include "suexec.h"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#if defined(PATH_MAX)
#define AP_MAXPATH PATH_MAX
#elif defined(MAXPATHLEN)
#define AP_MAXPATH MAXPATHLEN
#else
#define AP_MAXPATH 8192
#endif

#define AP_ENVBUF 256

extern char **environ;
static FILE *log = NULL;

static const char *const safe_env_lst[] =
{
    /* variable name starts with */
    "HTTP_",
    "SSL_",

    /* variable name is */
    "AUTH_TYPE=",
    "CONTENT_LENGTH=",
    "CONTENT_TYPE=",
    "DATE_GMT=",
    "DATE_LOCAL=",
    "DOCUMENT_NAME=",
    "DOCUMENT_PATH_INFO=",
    "DOCUMENT_ROOT=",
    "DOCUMENT_URI=",
    "GATEWAY_INTERFACE=",
    "HTTPS=",
    "LAST_MODIFIED=",
    "PATH_INFO=",
    "PATH_TRANSLATED=",
    "QUERY_STRING=",
    "QUERY_STRING_UNESCAPED=",
    "REMOTE_ADDR=",
    "REMOTE_HOST=",
    "REMOTE_IDENT=",
    "REMOTE_PORT=",
    "REMOTE_USER=",
    "REDIRECT_HANDLER=",
    "REDIRECT_QUERY_STRING=",
    "REDIRECT_REMOTE_USER=",
    "REDIRECT_STATUS=",
    "REDIRECT_URL=",
    "REQUEST_METHOD=",
    "REQUEST_URI=",
    "SCRIPT_FILENAME=",
    "SCRIPT_NAME=",
    "SCRIPT_URI=",
    "SCRIPT_URL=",
    "SERVER_ADMIN=",
    "SERVER_NAME=",
    "SERVER_ADDR=",
    "SERVER_PORT=",
    "SERVER_PROTOCOL=",
    "SERVER_SIGNATURE=",
    "SERVER_SOFTWARE=",
    "UNIQUE_ID=",
    "USER_NAME=",
    "TZ=",
    NULL
};


static void err_output(int is_error, const char *fmt, va_list ap)
{
#ifdef AP_LOG_EXEC
    time_t timevar;
    struct tm *lt;

    if (!log) {
        if ((log = fopen(AP_LOG_EXEC, "a")) == NULL) {
            fprintf(stderr, "suexec failure: could not open log file\n");
            perror("fopen");
            exit(1);
        }
    }

    if (is_error) {
        fprintf(stderr, "suexec policy violation: see suexec log for more "
                        "details\n");
    }

    time(&timevar);
    lt = localtime(&timevar);

    fprintf(log, "[%d-%.2d-%.2d %.2d:%.2d:%.2d]: ",
            lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
            lt->tm_hour, lt->tm_min, lt->tm_sec);

    vfprintf(log, fmt, ap);

    fflush(log);
#endif /* AP_LOG_EXEC */
    return;
}

static void log_err(const char *fmt,...)
{
#ifdef AP_LOG_EXEC
    va_list ap;

    va_start(ap, fmt);
    err_output(1, fmt, ap); /* 1 == is_error */
    va_end(ap);
#endif /* AP_LOG_EXEC */
    return;
}

static void log_no_err(const char *fmt,...)
{
#ifdef AP_LOG_EXEC
    va_list ap;

    va_start(ap, fmt);
    err_output(0, fmt, ap); /* 0 == !is_error */
    va_end(ap);
#endif /* AP_LOG_EXEC */
    return;
}

static void clean_env(void)
{
    char pathbuf[512];
    char **cleanenv;
    char **ep;
    int cidx = 0;
    int idx;

    /* While cleaning the environment, the environment should be clean.
     * (e.g. malloc() may get the name of a file for writing debugging info.
     * Bad news if MALLOC_DEBUG_FILE is set to /etc/passwd.  Sprintf() may be
     * susceptible to bad locale settings....)
     * (from PR 2790)
     */
    char **envp = environ;
    char *empty_ptr = NULL;

    environ = &empty_ptr; /* VERY safe environment */

    if ((cleanenv = (char **) calloc(AP_ENVBUF, sizeof(char *))) == NULL) {
        log_err("failed to malloc memory for environment\n");
        exit(120);
    }

    sprintf(pathbuf, "PATH=%s", AP_SAFE_PATH);
    cleanenv[cidx] = strdup(pathbuf);
    cidx++;

    for (ep = envp; *ep && cidx < AP_ENVBUF-1; ep++) {
        for (idx = 0; safe_env_lst[idx]; idx++) {
            if (!strncmp(*ep, safe_env_lst[idx],
                         strlen(safe_env_lst[idx]))) {
                cleanenv[cidx] = *ep;
                cidx++;
                break;
            }
        }
    }

    cleanenv[cidx] = NULL;

    environ = cleanenv;
}

int main(int argc, char *argv[])
{
    int userdir = 0;        /* ~userdir flag             */
    uid_t uid;              /* user information          */
    gid_t gid;              /* target group placeholder  */
    char *target_uname;     /* target user name          */
    char *target_gname;     /* target group name         */
    char *target_homedir;   /* target home directory     */
    char *actual_uname;     /* actual user name          */
    char *actual_gname;     /* actual group name         */
    char *prog;             /* name of this program      */
    char *cmd;              /* command to be executed    */
    char cwd[AP_MAXPATH];   /* current working directory */
    char dwd[AP_MAXPATH];   /* docroot working directory */
    struct passwd *pw;      /* password entry holder     */
    struct group *gr;       /* group entry holder        */
    struct stat dir_info;   /* directory info holder     */
    struct stat prg_info;   /* program info holder       */

    /*
     * Start with a "clean" environment
     */
    clean_env();

    prog = argv[0];
    /*
     * Check existence/validity of the UID of the user
     * running this program.  Error out if invalid.
     */
    uid = getuid();
    if ((pw = getpwuid(uid)) == NULL) {
        log_err("crit: invalid uid: (%ld)\n", uid);
        exit(102);
    }
    /*
     * See if this is a 'how were you compiled' request, and
     * comply if so.
     */
    if ((argc > 1)
        && (! strcmp(argv[1], "-V"))
        && ((uid == 0)
#ifdef _OSD_POSIX
        /* User name comparisons are case insensitive on BS2000/OSD */
            || (! strcasecmp(AP_HTTPD_USER, pw->pw_name)))
#else  /* _OSD_POSIX */
            || (! strcmp(AP_HTTPD_USER, pw->pw_name)))
#endif /* _OSD_POSIX */
        ) {
#ifdef AP_DOC_ROOT
        fprintf(stderr, " -D AP_DOC_ROOT=\"%s\"\n", AP_DOC_ROOT);
#endif
#ifdef AP_GID_MIN
        fprintf(stderr, " -D AP_GID_MIN=%d\n", AP_GID_MIN);
#endif
#ifdef AP_HTTPD_USER
        fprintf(stderr, " -D AP_HTTPD_USER=\"%s\"\n", AP_HTTPD_USER);
#endif
#ifdef AP_LOG_EXEC
        fprintf(stderr, " -D AP_LOG_EXEC=\"%s\"\n", AP_LOG_EXEC);
#endif
#ifdef AP_SAFE_PATH
        fprintf(stderr, " -D AP_SAFE_PATH=\"%s\"\n", AP_SAFE_PATH);
#endif
#ifdef AP_SUEXEC_UMASK
        fprintf(stderr, " -D AP_SUEXEC_UMASK=%03o\n", AP_SUEXEC_UMASK);
#endif
#ifdef AP_UID_MIN
        fprintf(stderr, " -D AP_UID_MIN=%d\n", AP_UID_MIN);
#endif
#ifdef AP_USERDIR_SUFFIX
        fprintf(stderr, " -D AP_USERDIR_SUFFIX=\"%s\"\n", AP_USERDIR_SUFFIX);
#endif
        exit(0);
    }
    /*
     * If there are a proper number of arguments, set
     * all of them to variables.  Otherwise, error out.
     */
    if (argc < 4) {
        log_err("too few arguments\n");
        exit(101);
    }
    target_uname = argv[1];
    target_gname = argv[2];
    cmd = argv[3];

    /*
     * Check to see if the user running this program
     * is the user allowed to do so as defined in
     * suexec.h.  If not the allowed user, error out.
     */
#ifdef _OSD_POSIX
    /* User name comparisons are case insensitive on BS2000/OSD */
    if (strcasecmp(AP_HTTPD_USER, pw->pw_name)) {
        log_err("user mismatch (%s instead of %s)\n", pw->pw_name, AP_HTTPD_USER);
        exit(103);
    }
#else  /*_OSD_POSIX*/
    if (strcmp(AP_HTTPD_USER, pw->pw_name)) {
        log_err("user mismatch (%s instead of %s)\n", pw->pw_name, AP_HTTPD_USER);
        exit(103);
    }
#endif /*_OSD_POSIX*/

    /*
     * Check for a leading '/' (absolute path) in the command to be executed,
     * or attempts to back up out of the current directory,
     * to protect against attacks.  If any are
     * found, error out.  Naughty naughty crackers.
     */
    if ((cmd[0] == '/') || (!strncmp(cmd, "../", 3))
        || (strstr(cmd, "/../") != NULL)) {
        log_err("invalid command (%s)\n", cmd);
        exit(104);
    }

    /*
     * Check to see if this is a ~userdir request.  If
     * so, set the flag, and remove the '~' from the
     * target username.
     */
    if (!strncmp("~", target_uname, 1)) {
        target_uname++;
        userdir = 1;
    }

    /*
     * Error out if the target username is invalid.
     */
    if (strspn(target_uname, "1234567890") != strlen(target_uname)) {
        if ((pw = getpwnam(target_uname)) == NULL) {
            log_err("invalid target user name: (%s)\n", target_uname);
            exit(105);
        }
    }
    else {
        if ((pw = getpwuid(atoi(target_uname))) == NULL) {
            log_err("invalid target user id: (%s)\n", target_uname);
            exit(121);
        }
    }

    /*
     * Error out if the target group name is invalid.
     */
    if (strspn(target_gname, "1234567890") != strlen(target_gname)) {
        if ((gr = getgrnam(target_gname)) == NULL) {
            log_err("invalid target group name: (%s)\n", target_gname);
            exit(106);
        }
    }
    else {
        if ((gr = getgrgid(atoi(target_gname))) == NULL) {
            log_err("invalid target group id: (%s)\n", target_gname);
            exit(106);
        }
    }
    gid = gr->gr_gid;
    actual_gname = strdup(gr->gr_name);

#ifdef _OSD_POSIX
    /*
     * Initialize BS2000 user environment
     */
    {
        pid_t pid;
        int status;

        switch (pid = ufork(target_uname)) {
        case -1:    /* Error */
            log_err("failed to setup bs2000 environment for user %s: %s\n",
                    target_uname, strerror(errno));
            exit(150);
        case 0:     /* Child */
            break;
        default:    /* Father */
            while (pid != waitpid(pid, &status, 0))
                ;
            /* @@@ FIXME: should we deal with STOP signals as well? */
            if (WIFSIGNALED(status)) {
                kill (getpid(), WTERMSIG(status));
            }
            exit(WEXITSTATUS(status));
        }
    }
#endif /*_OSD_POSIX*/

    /*
     * Save these for later since initgroups will hose the struct
     */
    uid = pw->pw_uid;
    actual_uname = strdup(pw->pw_name);
    target_homedir = strdup(pw->pw_dir);

    /*
     * Log the transaction here to be sure we have an open log
     * before we setuid().
     */
    log_no_err("uid: (%s/%s) gid: (%s/%s) cmd: %s\n",
               target_uname, actual_uname,
               target_gname, actual_gname,
               cmd);

    /*
     * Error out if attempt is made to execute as root or as
     * a UID less than AP_UID_MIN.  Tsk tsk.
     */
    if ((uid == 0) || (uid < AP_UID_MIN)) {
        log_err("cannot run as forbidden uid (%d/%s)\n", uid, cmd);
        exit(107);
    }

    /*
     * Error out if attempt is made to execute as root group
     * or as a GID less than AP_GID_MIN.  Tsk tsk.
     */
    if ((gid == 0) || (gid < AP_GID_MIN)) {
        log_err("cannot run as forbidden gid (%d/%s)\n", gid, cmd);
        exit(108);
    }

    /*
     * Change UID/GID here so that the following tests work over NFS.
     *
     * Initialize the group access list for the target user,
     * and setgid() to the target group. If unsuccessful, error out.
     */
    if (((setgid(gid)) != 0) || (initgroups(actual_uname, gid) != 0)) {
        log_err("failed to setgid (%ld: %s)\n", gid, cmd);
        exit(109);
    }

    /*
     * setuid() to the target user.  Error out on fail.
     */
    if ((setuid(uid)) != 0) {
        log_err("failed to setuid (%ld: %s)\n", uid, cmd);
        exit(110);
    }

    /*
     * Get the current working directory, as well as the proper
     * document root (dependant upon whether or not it is a
     * ~userdir request).  Error out if we cannot get either one,
     * or if the current working directory is not in the docroot.
     * Use chdir()s and getcwd()s to avoid problems with symlinked
     * directories.  Yuck.
     */
    if (getcwd(cwd, AP_MAXPATH) == NULL) {
        log_err("cannot get current working directory\n");
        exit(111);
    }

    if (userdir) {
        if (((chdir(target_homedir)) != 0) ||
            ((chdir(AP_USERDIR_SUFFIX)) != 0) ||
            ((getcwd(dwd, AP_MAXPATH)) == NULL) ||
            ((chdir(cwd)) != 0)) {
            log_err("cannot get docroot information (%s)\n", target_homedir);
            exit(112);
        }
    }
    else {
        if (((chdir(AP_DOC_ROOT)) != 0) ||
            ((getcwd(dwd, AP_MAXPATH)) == NULL) ||
            ((chdir(cwd)) != 0)) {
            log_err("cannot get docroot information (%s)\n", AP_DOC_ROOT);
            exit(113);
        }
    }

    if ((strncmp(cwd, dwd, strlen(dwd))) != 0) {
        log_err("command not in docroot (%s/%s)\n", cwd, cmd);
        exit(114);
    }

    /*
     * Stat the cwd and verify it is a directory, or error out.
     */
    if (((lstat(cwd, &dir_info)) != 0) || !(S_ISDIR(dir_info.st_mode))) {
        log_err("cannot stat directory: (%s)\n", cwd);
        exit(115);
    }

    /*
     * Error out if cwd is writable by others.
     */
    if ((dir_info.st_mode & S_IWOTH) || (dir_info.st_mode & S_IWGRP)) {
        log_err("directory is writable by others: (%s)\n", cwd);
        exit(116);
    }

    /*
     * Error out if we cannot stat the program.
     */
    if (((lstat(cmd, &prg_info)) != 0) || (S_ISLNK(prg_info.st_mode))) {
        log_err("cannot stat program: (%s)\n", cmd);
        exit(117);
    }

    /*
     * Error out if the program is writable by others.
     */
    if ((prg_info.st_mode & S_IWOTH) || (prg_info.st_mode & S_IWGRP)) {
        log_err("file is writable by others: (%s/%s)\n", cwd, cmd);
        exit(118);
    }

    /*
     * Error out if the file is setuid or setgid.
     */
    if ((prg_info.st_mode & S_ISUID) || (prg_info.st_mode & S_ISGID)) {
        log_err("file is either setuid or setgid: (%s/%s)\n", cwd, cmd);
        exit(119);
    }

    /*
     * Error out if the target name/group is different from
     * the name/group of the cwd or the program.
     */
    if ((uid != dir_info.st_uid) ||
        (gid != dir_info.st_gid) ||
        (uid != prg_info.st_uid) ||
        (gid != prg_info.st_gid)) {
        log_err("target uid/gid (%ld/%ld) mismatch "
                "with directory (%ld/%ld) or program (%ld/%ld)\n",
                uid, gid,
                dir_info.st_uid, dir_info.st_gid,
                prg_info.st_uid, prg_info.st_gid);
        exit(120);
    }
    /*
     * Error out if the program is not executable for the user.
     * Otherwise, she won't find any error in the logs except for
     * "[error] Premature end of script headers: ..."
     */
    if (!(prg_info.st_mode & S_IXUSR)) {
        log_err("file has no execute permission: (%s/%s)\n", cwd, cmd);
        exit(121);
    }

#ifdef AP_SUEXEC_UMASK
    /*
     * umask() uses inverse logic; bits are CLEAR for allowed access.
     */
    if ((~AP_SUEXEC_UMASK) & 0022) {
        log_err("notice: AP_SUEXEC_UMASK of %03o allows "
                "write permission to group and/or other\n", AP_SUEXEC_UMASK);
    }
    umask(AP_SUEXEC_UMASK);
#endif /* AP_SUEXEC_UMASK */

    /*
     * ask fcntl(2) to set the FD_CLOEXEC flag on the log file,
     * so it'll be automagically closed if the exec() call succeeds.
     */
    if (log != NULL) {
        fflush(log);
        setbuf(log,NULL);
        if ((fcntl(fileno(log), F_SETFD, FD_CLOEXEC) == -1)) {
            log_err("error: can't set close-on-exec flag");
            exit(122);
        }
    }

    /*
     * Execute the command, replacing our image with its own.
     */
#ifdef NEED_HASHBANG_EMUL
    /* We need the #! emulation when we want to execute scripts */
    {
        extern char **environ;

        ap_execve(cmd, &argv[3], environ);
    }
#else /*NEED_HASHBANG_EMUL*/
    execv(cmd, &argv[3]);
#endif /*NEED_HASHBANG_EMUL*/

    /*
     * (I can't help myself...sorry.)
     *
     * Uh oh.  Still here.  Where's the kaboom?  There was supposed to be an
     * EARTH-shattering kaboom!
     *
     * Oh well, log the failure and error out.
     */
    log_err("(%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);
    exit(255);
}
