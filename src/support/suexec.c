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
 * Error messages in the suexec logfile are prefixed with severity values
 * similar to those used by the main server:
 *
 *  Sev     Meaning
 * emerg:  Failure of some basic system function
 * alert:  Bug in the way Apache is communicating with suexec
 * crit:   Basic information is missing, invalid, or incorrect
 * error:  Script permission/configuration error
 * warn:   
 * notice: Some issue of which the sysadmin/webmaster ought to be aware
 * info:   Normal activity message
 * debug:  Self-explanatory
 */

#include "ap_config.h"
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdarg.h>

#include "suexec.h"

/*
 ***********************************************************************
 * There is no initgroups() in QNX, so I believe this is safe :-)
 * Use cc -osuexec -3 -O -mf -DQNX suexec.c to compile.
 *
 * May 17, 1997.
 * Igor N. Kovalenko -- infoh@mail.wplus.net
 ***********************************************************************
 */

#if defined(NEED_INITGROUPS)
int initgroups(const char *name, gid_t basegid)
{
/* QNX and MPE do not appear to support supplementary groups. */
    return 0;
}
#endif

#if defined(NEED_STRERROR)
extern char *sys_errlist[];
#define strerror(x) sys_errlist[(x)]
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

char *safe_env_lst[] =
{
    /* variable name starts with */
    "HTTP_",

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
    "FILEPATH_INFO=",
    "GATEWAY_INTERFACE=",
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
    "REDIRECT_QUERY_STRING=",
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
    "SERVER_SOFTWARE=",
    "UNIQUE_ID=",
    "USER_NAME=",
    "TZ=",
    NULL
};


static void err_output(const char *fmt, va_list ap)
{
#ifdef LOG_EXEC
    time_t timevar;
    struct tm *lt;

    if (!log) {
	if ((log = fopen(LOG_EXEC, "a")) == NULL) {
	    fprintf(stderr, "failed to open log file\n");
	    perror("fopen");
	    exit(1);
	}
    }

    time(&timevar);
    lt = localtime(&timevar);

    fprintf(log, "[%d-%.2d-%.2d %.2d:%.2d:%.2d]: ",
	    lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
	    lt->tm_hour, lt->tm_min, lt->tm_sec);

    vfprintf(log, fmt, ap);

    fflush(log);
#endif /* LOG_EXEC */
    return;
}

static void log_err(const char *fmt,...)
{
#ifdef LOG_EXEC
    va_list ap;

    va_start(ap, fmt);
    err_output(fmt, ap);
    va_end(ap);
#endif /* LOG_EXEC */
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
        log_err("emerg: failed to malloc memory for environment\n");
	exit(120);
    }

    sprintf(pathbuf, "PATH=%s", SAFE_PATH);
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
    int userdir = 0;		/* ~userdir flag             */
    uid_t uid;			/* user information          */
    gid_t gid;			/* target group placeholder  */
    char *target_uname;		/* target user name          */
    char *target_gname;		/* target group name         */
    char *target_homedir;	/* target home directory     */
    char *actual_uname;		/* actual user name          */
    char *actual_gname;		/* actual group name         */
    char *prog;			/* name of this program      */
    char *cmd;			/* command to be executed    */
    char cwd[AP_MAXPATH];	/* current working directory */
    char dwd[AP_MAXPATH];	/* docroot working directory */
    struct passwd *pw;		/* password entry holder     */
    struct group *gr;		/* group entry holder        */
    struct stat dir_info;	/* directory info holder     */
    struct stat prg_info;	/* program info holder       */

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
            || (! strcasecmp(HTTPD_USER, pw->pw_name)))
#else  /* _OSD_POSIX */
            || (! strcmp(HTTPD_USER, pw->pw_name)))
#endif /* _OSD_POSIX */
        ) {
#ifdef DOC_ROOT
        fprintf(stderr, " -D DOC_ROOT=\"%s\"\n", DOC_ROOT);
#endif
#ifdef GID_MIN
        fprintf(stderr, " -D GID_MIN=%d\n", GID_MIN);
#endif
#ifdef HTTPD_USER
        fprintf(stderr, " -D HTTPD_USER=\"%s\"\n", HTTPD_USER);
#endif
#ifdef LOG_EXEC
        fprintf(stderr, " -D LOG_EXEC=\"%s\"\n", LOG_EXEC);
#endif
#ifdef SAFE_PATH
        fprintf(stderr, " -D SAFE_PATH=\"%s\"\n", SAFE_PATH);
#endif
#ifdef SUEXEC_UMASK
        fprintf(stderr, " -D SUEXEC_UMASK=%03o\n", SUEXEC_UMASK);
#endif
#ifdef UID_MIN
        fprintf(stderr, " -D UID_MIN=%d\n", UID_MIN);
#endif
#ifdef USERDIR_SUFFIX
        fprintf(stderr, " -D USERDIR_SUFFIX=\"%s\"\n", USERDIR_SUFFIX);
#endif
        exit(0);
    }
    /*
     * If there are a proper number of arguments, set
     * all of them to variables.  Otherwise, error out.
     */
    if (argc < 4) {
	log_err("alert: too few arguments\n");
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
    if (strcasecmp(HTTPD_USER, pw->pw_name)) {
        log_err("crit: calling user mismatch (%s instead of %s)\n",
		pw->pw_name, HTTPD_USER);
	exit(103);
    }
#else  /* _OSD_POSIX */
    if (strcmp(HTTPD_USER, pw->pw_name)) {
        log_err("crit: calling user mismatch (%s instead of %s)\n",
		pw->pw_name, HTTPD_USER);
	exit(103);
    }
#endif /* _OSD_POSIX */

    /*
     * Check for a leading '/' (absolute path) in the command to be executed,
     * or attempts to back up out of the current directory,
     * to protect against attacks.  If any are
     * found, error out.  Naughty naughty crackers.
     */
    if ((cmd[0] == '/') || (!strncmp(cmd, "../", 3))
	|| (strstr(cmd, "/../") != NULL)) {
        log_err("error: invalid command (%s)\n", cmd);
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
    if ((pw = getpwnam(target_uname)) == NULL) {
	log_err("crit: invalid target user name: (%s)\n", target_uname);
	exit(105);
    }

    /*
     * Error out if the target group name is invalid.
     */
    if (strspn(target_gname, "1234567890") != strlen(target_gname)) {
	if ((gr = getgrnam(target_gname)) == NULL) {
	    log_err("crit: invalid target group name: (%s)\n", target_gname);
	    exit(106);
	}
	gid = gr->gr_gid;
	actual_gname = strdup(gr->gr_name);
    }
    else {
	gid = atoi(target_gname);
	actual_gname = strdup(target_gname);
    }

#ifdef _OSD_POSIX
    /*
     * Initialize BS2000 user environment
     */
    {
	pid_t pid;
	int status;

	switch (pid = ufork(target_uname))
	{
	case -1:	/* Error */
	    log_err("emerg: failed to setup bs2000 environment for user "
		    "%s: %s\n",
		    target_uname, strerror(errno));
	    exit(150);
	case 0:	/* Child */
	    break;
	default:	/* Father */
	    while (pid != waitpid(pid, &status, 0))
		;
	    /* @@@ FIXME: should we deal with STOP signals as well? */
	    if (WIFSIGNALED(status)) {
		kill (getpid(), WTERMSIG(status));
	    }
	    exit(WEXITSTATUS(status));
	}
    }
#endif /* _OSD_POSIX */

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
    log_err("info: (target/actual) uid: (%s/%s) gid: (%s/%s) cmd: %s\n",
	    target_uname, actual_uname,
	    target_gname, actual_gname,
	    cmd);

    /*
     * Error out if attempt is made to execute as root or as
     * a UID less than UID_MIN.  Tsk tsk.
     */
    if ((uid == 0) || (uid < UID_MIN)) {
	log_err("crit: cannot run as forbidden uid (%d/%s)\n", uid, cmd);
	exit(107);
    }

    /*
     * Error out if attempt is made to execute as root group
     * or as a GID less than GID_MIN.  Tsk tsk.
     */
    if ((gid == 0) || (gid < GID_MIN)) {
	log_err("crit: cannot run as forbidden gid (%d/%s)\n", gid, cmd);
	exit(108);
    }

    /*
     * Change UID/GID here so that the following tests work over NFS.
     *
     * Initialize the group access list for the target user,
     * and setgid() to the target group. If unsuccessful, error out.
     */
    if (((setgid(gid)) != 0) || (initgroups(actual_uname, gid) != 0)) {
	log_err("emerg: failed to setgid (%ld: %s)\n", gid, cmd);
	exit(109);
    }

    /*
     * setuid() to the target user.  Error out on fail.
     */
    if ((setuid(uid)) != 0) {
	log_err("emerg: failed to setuid (%ld: %s)\n", uid, cmd);
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
	log_err("emerg: cannot get current working directory\n");
	exit(111);
    }

    if (userdir) {
	if (((chdir(target_homedir)) != 0) ||
	    ((chdir(USERDIR_SUFFIX)) != 0) ||
	    ((getcwd(dwd, AP_MAXPATH)) == NULL) ||
	    ((chdir(cwd)) != 0)) {
	    log_err("emerg: cannot get docroot information (%s)\n",
		    target_homedir);
	    exit(112);
	}
    }
    else {
	if (((chdir(DOC_ROOT)) != 0) ||
	    ((getcwd(dwd, AP_MAXPATH)) == NULL) ||
	    ((chdir(cwd)) != 0)) {
	    log_err("emerg: cannot get docroot information (%s)\n", DOC_ROOT);
	    exit(113);
	}
    }

    if ((strncmp(cwd, dwd, strlen(dwd))) != 0) {
	log_err("error: command not in docroot (%s/%s)\n", cwd, cmd);
	exit(114);
    }

    /*
     * Stat the cwd and verify it is a directory, or error out.
     */
    if (((lstat(cwd, &dir_info)) != 0) || !(S_ISDIR(dir_info.st_mode))) {
	log_err("error: cannot stat directory: (%s)\n", cwd);
	exit(115);
    }

    /*
     * Error out if cwd is writable by others.
     */
    if ((dir_info.st_mode & S_IWOTH) || (dir_info.st_mode & S_IWGRP)) {
	log_err("error: directory is writable by others: (%s)\n", cwd);
	exit(116);
    }

    /*
     * Error out if we cannot stat the program.
     */
    if (((lstat(cmd, &prg_info)) != 0) || (S_ISLNK(prg_info.st_mode))) {
	log_err("error: cannot stat program: (%s)\n", cmd);
	exit(117);
    }

    /*
     * Error out if the program is writable by others.
     */
    if ((prg_info.st_mode & S_IWOTH) || (prg_info.st_mode & S_IWGRP)) {
	log_err("error: file is writable by others: (%s/%s)\n", cwd, cmd);
	exit(118);
    }

    /*
     * Error out if the file is setuid or setgid.
     */
    if ((prg_info.st_mode & S_ISUID) || (prg_info.st_mode & S_ISGID)) {
	log_err("error: file is either setuid or setgid: (%s/%s)\n", cwd, cmd);
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
	log_err("error: target uid/gid (%ld/%ld) mismatch "
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
	log_err("error: file has no execute permission: (%s/%s)\n", cwd, cmd);
	exit(121);
    }

#ifdef SUEXEC_UMASK
    /*
     * umask() uses inverse logic; bits are CLEAR for allowed access.
     */
    if ((~SUEXEC_UMASK) & 0022) {
	log_err("notice: SUEXEC_UMASK of %03o allows "
		"write permission to group and/or other\n", SUEXEC_UMASK);
    }
    umask(SUEXEC_UMASK);
#endif /* SUEXEC_UMASK */

    /* 
     * Be sure to close the log file so the CGI can't
     * mess with it.  If the exec fails, it will be reopened 
     * automatically when log_err is called.  Note that the log
     * might not actually be open if LOG_EXEC isn't defined.
     * However, the "log" cell isn't ifdef'd so let's be defensive
     * and assume someone might have done something with it
     * outside an ifdef'd LOG_EXEC block.
     */
    if (log != NULL) {
	fclose(log);
	log = NULL;
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
    log_err("emerg: (%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);
    exit(255);
}
