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
 * A MotherSoft Product for the Apache WWW server.
 * (http://www.louisville.edu/~jadour01/mothersoft/)
 *
 * Codebase originally from Majordomo(v1.93) release.
 * Heavy modifications by:
 *    Jason A. Dour (jad@bcc.louisville.edu)
 *    Randy Terbush (randy@zyzzyva.com)
 *
 * Version 0.1.0 - Jason A. Dour
 *    First beta.  Removed HAVE_RLIMIT and related rlimit code
 * now that the server handles the funcitonality.  Moved user-
 * defined code to suexec.h.  Added "DON'T EDIT" warning in code.
 * No more "security by obscurity"...comments added at each step.
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


#include "suexec.h"

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
    int doclen;             /* length of the docroot     */
    int userdir = 0;        /* ~userdir flag             */
    uid_t uid;              /* user information          */
    char *target_uname;     /* target user name          */
    char *target_gname;     /* target group name         */
    char *prog;             /* name of this program      */
    char *cmd;              /* command to be executed    */
    char *cwd;              /* current working directory */
    char *buf = NULL;       /* temporary buffer          */
    struct passwd *pw;      /* password entry holder     */
    struct group *gr;       /* group entry holder        */
    struct stat dir_info;   /* directory info holder     */
    struct stat prg_info;   /* program info holder       */

    

    /*
     * If there are a proper number of arguments, set
     * all of them to variables.  Otherwise, error out.
     */
    prog = argv[0];
    if (argc < 4)
    {
	log_err ("too few arguments\n");
	exit(101);
    }
    target_uname = argv[1];
    target_gname = argv[2];
    cmd = argv[3];

    /*
     * Check existence/validity of the UID of the user
     * running this program.  Error out if invalid.
     */
    uid = getuid();
    if ((pw = getpwuid (uid)) == NULL)
    {
	log_err ("invalid uid: (%ld)\n", uid);
	exit (102);
    }
    
    /*
     * Check to see if the user running this program
     * is the user allowed to do so as defined in
     * suexec.h.  If not the allowed user, error out.
     */
    if (strcmp (HTTPD_USER, pw->pw_name))
    {
	log_err ("user mismatch (%s)\n", pw->pw_name);
	exit (103);
    }
    
    /*
     * Check for a '/' in the command to be executed,
     * to protect against attacks.  If a '/' is
     * found, error out.  Naughty naughty crackers.
     */
    if (strchr (cmd, '/') != (char) NULL )
    {
	log_err ("invalid command (%s)\n", cmd);
	exit (104);
    }

    /*
     * Check to see if this is a ~userdir request.  If
     * so, set the flag, and remove the '~' from the
     * target username.
     */
    if (!strncmp( "~", target_uname, 1))
    {
	target_uname++;
	userdir = 1;
    }

    /*
     * Get the current working directory, as well as
     * the proper document root (dependant upon whether
     * or not it is a ~userdir request.  Error out if
     * we cannot get either one, or if the command is
     * not in the docroot.
     */
    if ((cwd = getcwd (buf, MAXPATHLEN)) == NULL)
    {
        log_err ("cannot get current working directory\n");
        exit (105);
    }
    if (userdir)
    {
	doclen = strlen (pw->pw_dir);
	if (strncmp (cwd, pw->pw_dir, doclen))
        {   
	    log_err ("command not in docroot (%s/%s)\n", cwd, cmd);
	    exit (106);
	}
    } else {
	doclen = strlen (DOC_ROOT);
	if (strncmp (cwd, DOC_ROOT, doclen))
        {
	    log_err ("command not in docroot (%s/%s)\n", cwd, cmd);
	    exit (106);
	}
    }

    /*
     * Stat the cwd and verify it is a directory, or error out.
     */
    if ( (lstat (cwd, &dir_info))     ||
         !(S_ISDIR(dir_info.st_mode)) )
    {
	log_err ("cannot stat directory: (%s)\n", cwd);
	exit (107);
    }

    /*
     * Error out if cwd is writable by others.
     */
    if ((dir_info.st_mode & S_IWOTH) || (dir_info.st_mode & S_IWGRP))
    {
	log_err ("directory is writable by others: (%s)\n", cwd);
	exit (108);
    }

    /*
     * Error out if we cannot stat the program.
     */
    if ((lstat (cmd, &prg_info)) || (S_ISLNK(prg_info.st_mode)))
    {
	log_err ("cannot stat program: (%s)\n", cmd);
	exit (109);
    }

    /*
     * Error out if the program is writable by others.
     */
    if ((prg_info.st_mode & S_IWOTH) || (prg_info.st_mode & S_IWGRP))
    {
	log_err ("file is writable by others: (%s/%s)\n", cwd, cmd);
	exit (110);
    }

    /*
     * Error out if the file is setuid or setgid.
     */
    if ((prg_info.st_mode & S_ISUID) || (prg_info.st_mode & S_ISGID))
    {
	log_err ("file is either setuid or setgid: (%s/%s)\n",cwd,cmd);
	exit (111);
    }

    /*
     * Error out if the target username is invalid.
     */
    if ( (pw = getpwnam (target_uname)) == NULL )
    {
	log_err ("invalid target user name: (%s)\n", target_uname);
	exit (112);
    }

    /*
     * Error out if the target group name is invalid.
     */
    if ( (gr = getgrnam (target_gname)) == NULL )
    {
	log_err ("invalid target group name: (%s)\n", target_gname);
	exit (113);
    }

    /*
     * Error out if the target name/group is different from
     * the name/group of the cwd or the program.
     */
    if ( (pw->pw_uid != dir_info.st_uid) ||
	 (gr->gr_gid != dir_info.st_gid) ||
	 (pw->pw_uid != prg_info.st_uid) ||
	 (gr->gr_gid != prg_info.st_gid) )
    {
	log_err ("target uid/gid (%ld/%ld) mismatch with directory (%ld/%ld) or program (%ld/%ld)\n",
		 pw->pw_uid, gr->gr_gid,
		 dir_info.st_uid, dir_info.st_gid,
		 prg_info.st_uid, prg_info.st_gid);
	exit (114);
    }

    /*
     * Error out if attempt is made to execute as root.  Tsk tsk.
     */
    if (pw->pw_uid == 0)
    {
	log_err ("cannot run as uid 0 (%s)\n", cmd);
	exit (115);
    }

    /*
     * Error out if attempt is made to execute as root group.  Tsk tsk.
     */
    if (gr->gr_gid == 0)
    {
	log_err ("cannot run as gid 0 (%s)\n", cmd);
	exit (116);
    }

    /*
     * Log the transaction here to be sure we have an open log 
     * before we setuid().
     */
    log_err ("uid: (%s) gid: (%s) %s\n", target_uname, target_gname, cmd);

    /*
     * Initialize the group access list for the target user,
     * and setgid() to the target group. If unsuccessful, error out.
     */
    if ( (initgroups (NNAME,NGID) != 0) ||
         (setgid (gr->gr_gid)      != 0) )
    {
        log_err ("failed to initialize groups or setgid (%ld: %s/%s)\n", gr->gr_gid, cwd, cmd);
        exit (117);
    }

    /*
     * setuid() to the target user.  Error out on fail.
     */
    if ((setuid (pw->pw_uid)) != 0)
    {
	log_err ("failed to setuid (%ld: %s/%s)\n", pw->pw_uid, cwd, cmd);
	exit (118);
    }

    /*
     * Execute the command, replacing our image with its own.
     */
    execve (cmd, &argv[3], env);

    /*
     * (I can't help myself...sorry.)
     *
     * Uh oh.  Still here.  Where's the kaboom?  There was supposed to be an
     * EARTH-shattering kaboom!
     *
     * Oh well, log the failure and error out.
     */
    log_err ("exec failed (%s)\n", cmd);
    exit(255);
}
