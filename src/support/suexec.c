
/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/*
 * suexec.c -- "Wrapper" support program for suEXEC behaviour for Apache
 *
 * A MotherSoft Product for the Apache WWW server.
 * (http://www.louisville.edu/~jadour01/mothersoft/)
 *
 * Codebase originally from Majordomo(v1.93) release.
 * Heavy modifications by:
 *    Jason A. Dour (jad@bcc.louisville.edu)
 *    Randy Terbush (randy@zyzzyva.com)
 *
 * Version 0.0.3 - Jason A. Dour
 *    Third alpha.  Added NNAME and NGID directives to fix
 * portability problem -- various systems have different
 * values for nobody and nogroup.  Yuck.  Submitted to the
 * Apache development group for consideration.
 *
 * Version 0.0.2 - Jason A. Dour
 *    Second alpha.  Cleaned up code and comments.  Fixed some
 * test-case bugs.  Cleaned up and locked down the groups access
 * list.  Fixed setgid behaviour.  Added more paranoia checks.
 * Added ~userid support.  Cleaned up exit codes.
 *
 * Version 0.0.1 - Randy Terbush
 *    First assigned version. Heavily modified to act as generic
 * SUID wrapper for Apache.  Submitted to the Apache development
 * group for conjsideration.
 *
 * Version Primordial Ooze - Jason A. Dour
 *    First version.   Heavily modified from MDomo source.  Acted
 * only for ~userdir requests out of the ~userdir/cgi-bin dir.  Not
 * extremely useful...but it worked.
 */


/* ********** USER-DEFINED VARIABLES ********** */

/*
 * HTTPD_USER -- Define as the username under which Apache normally
 *               runs.  This is the only user allowed to execute
 *               this program.
 */
#define HTTPD_USER "www"

/*
 * LOG_EXEC -- Define this as a filename if you want all suEXEC
 *             transactions and errors logged for auditing and
 *             debugging purposes.
 */
#define LOG_EXEC "/usr/local/etc/httpd/logs/cgi.log" /* Need me? */

/*
 * DOC_ROOT -- Define as the DocuemntRoot set for Apache.  This
 *             will be the only hierarchy (aside from UserDirs)
 *             that can be used for suEXEC behaviour.
 */
#define DOC_ROOT "/usr/local/etc/httpd/htdocs"

/*
 * NNAME -- Define this as the name for the nobody account
 *          on your operating system.  Most systems will just
 *          need the default 'nobody'.
 */
#define NNAME "nobody"

/* NGID -- Define this as the *number* for the nogroup group
 *         on your operating system.  Most systems will have
 *         a -1 or -2.  Others might have something above
 *         65000.
 */
#define NGID -1



/* ********** DO NOT EDIT BELOW THIS LINE ********** */

#include <sys/param.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <strings.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/resource.h>


static FILE *log;

static void
err_output (const char *fmt, va_list ap)
{
    time_t timevar;
    struct tm *lt;

    if (!log)
	if ((log = fopen (LOG_EXEC, "a")) == NULL)
	{
	    fprintf (stderr, "failed to open log file\n");
	    perror ("fopen");
	}

    time (&timevar);
    lt = localtime (&timevar);
    
    fprintf (log, "[%.2d:%.2d:%.2d %.2d-%.2d-%.2d]: ", lt->tm_hour, lt->tm_min,
	     lt->tm_sec, lt->tm_mday, lt->tm_mon, lt->tm_year);
    
    vfprintf (log, fmt, ap);

    fflush (log);
    return;
}

void
log_err (const char *fmt, ...)
{
#ifdef LOG_EXEC
    va_list     ap;

    va_start (ap, fmt);
    err_output (fmt, ap);
    va_end(ap);
#endif /* LOG_EXEC */
    return;
}

int
main(int argc, char *argv[], char **env)
{
    int doclen;
    int homedir = 0;
    uid_t uid;
    char *server_uid;
    char *server_gid;
    char *prog;
    char *cmd;
    char *cwd;
    char *buf = NULL;
    struct passwd *pw;
    struct group *gr;
    struct stat dir_info;
    struct stat prg_info;
    struct rlimit limits;

    

    prog = argv[0];
    if (argc < 4)
    {
	log_err ("too few arguments\n");
	exit(101);
    }
    server_uid = argv[1];
    server_gid = argv[2];
    cmd = argv[3];

    getrlimit ( RLIMIT_NOFILE, &limits );
    if (limits.rlim_cur < limits.rlim_max)
    {
      limits.rlim_cur = 256;
      if (setrlimit (RLIMIT_NOFILE, &limits) < 0)
	log_err ("Cannot exceed hard limit for open files\n");
    }

    uid = getuid();
    if ((pw = getpwuid (uid)) == NULL)
    {
	log_err ("invalid uid: (%ld)\n", uid);
	exit (102);
    }
    
    if (strcmp (HTTPD_USER, pw->pw_name))
    {
	log_err ("user mismatch (%s)\n", pw->pw_name);
	exit (103);
    }
    
    if (strchr (cmd, '/') != (char) NULL )
    {
	log_err ("invalid command (%s)\n", cmd);
	exit (104);
    }

    if (!strncmp( "~", server_uid, 1))
    {
	server_uid++;
	homedir = 1;
    }

    cwd = getcwd (buf, MAXPATHLEN);

    if (homedir)
    {
	doclen = strlen (pw->pw_dir);
	if (strncmp (cwd, pw->pw_dir, doclen))
	{   
	    log_err ("invalid command (%s/%s)\n", cwd, cmd);
	    exit (105);
	}
    } else {
	doclen = strlen (DOC_ROOT);
	if (strncmp (cwd, DOC_ROOT, doclen))
	{
	    log_err ("invalid command (%s/%s)\n", cwd, cmd);
	    exit (105);
	}
    }

    if ( (lstat (cwd, &dir_info))     ||
         !(S_ISDIR(dir_info.st_mode)) )
    {
	log_err ("cannot stat directory: (%s)\n", cwd);
	exit (106);
    }
    
    if ((dir_info.st_mode & S_IWOTH) || (dir_info.st_mode & S_IWGRP))
    {
	log_err ("directory is writable by others: (%s)\n", cwd);
	exit (107);
    }

    if ((lstat (cmd, &prg_info)) || (S_ISLNK(prg_info.st_mode)))
    {
	log_err ("cannot stat program: (%s)\n", cmd);
	exit (108);
    }

    if ((prg_info.st_mode & S_IWOTH) || (prg_info.st_mode & S_IWGRP))
    {
	log_err ("file is writable by others: (%s/%s)\n", cwd, cmd);
	exit (109);
    }

    if ((prg_info.st_mode & S_ISUID) || (prg_info.st_mode & S_ISGID))
    {
	log_err ("file is either setuid or setgid: (%s/%s)\n",cwd,cmd);
	exit (110);
    }

    if ( (pw = getpwnam (server_uid)) == NULL )
    {
	log_err ("invalid target user name: (%s)\n", server_uid);
	exit (111);
    }

    if ( (gr = getgrnam (server_gid)) == NULL )
    {
	log_err ("invalid target group name: (%s)\n", server_gid);
	exit (112);
    }

    if ( (pw->pw_uid != dir_info.st_uid) ||
	 (gr->gr_gid != dir_info.st_gid) ||
	 (pw->pw_uid != prg_info.st_uid) ||
	 (gr->gr_gid != prg_info.st_gid) )
    {
	log_err ("target uid/gid (%ld/%ld) mismatch with directory (%ld/%ld) or program (%ld/%ld)\n",
		 pw->pw_uid, gr->gr_gid,
		 dir_info.st_uid, dir_info.st_gid,
		 prg_info.st_uid, prg_info.st_gid);
	exit (113);
    }

    if (pw->pw_uid == 0)
    {
	log_err ("cannot run as uid 0 (%s)\n", cmd);
	exit (114);
    }
	
    if (gr->gr_gid == 0)
    {
	log_err ("cannot run as gid 0 (%s)\n", cmd);
	exit (115);
    }

    /* log the transaction here to be sure we have an open log before setuid() */
    log_err ("uid: (%s) gid: (%s) %s\n", server_uid, server_gid, cmd);

    if ( (initgroups (NNAME,NGID) != 0) ||
         (setgid (gr->gr_gid)      != 0) )
    {
        log_err ("failed to initialize groups or setgid (%ld: %s/%s)\n", gr->gr_gid, cwd, cmd);
        exit (116);
    }

    if ((setuid (pw->pw_uid)) != 0)
    {
	log_err ("failed to setuid (%ld: %s/%s)\n", pw->pw_uid, cwd, cmd);
	exit (117);
    }

    execve (cmd, &argv[3], env);

    log_err ("exec failed (%s)\n", cmd);
    exit(255);
}
