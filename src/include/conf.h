
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
 * conf.h: system-dependant #defines and includes...
 * See README for a listing of what they mean
 */

#ifndef QNX
#include <sys/param.h>
#endif

/* Define one of these according to your system. */
#if defined(SUNOS4)
#define HAS_GMTOFF
#define HAVE_RESOURCE 1
#undef NO_KILLPG
#undef NO_SETSID
char *crypt(char *pw, char *salt);
#define JMP_BUF sigjmp_buf
#define HAVE_MMAP
#include <sys/time.h>     
#define NEED_STRERROR

#elif defined(SOLARIS2)
#undef HAS_GMTOFF
#define NO_KILLPG
#undef NO_SETSID
#define HAVE_RESOURCE 1
#define bzero(a,b) memset(a,0,b)
#define getwd(d) getcwd(d,MAX_STRING_LEN)
#define JMP_BUF sigjmp_buf
#define FCNTL_SERIALIZED_ACCEPT
#define HAVE_MMAP
#define HAVE_CRYPT_H

#elif defined(IRIX)
#undef HAS_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define JMP_BUF sigjmp_buf
#define FCNTL_SERIALIZED_ACCEPT
#define HAVE_SHMGET
#define HAVE_CRYPT_H
 
#elif defined(HPUX)
#define HAVE_RESOURCE 1
#undef HAS_GMTOFF
#define NO_KILLPG
#undef NO_SETSID
#ifndef _HPUX_SOURCE
#define _HPUX_SOURCE
#endif
#define getwd(d) getcwd(d,MAX_STRING_LEN)
#define JMP_BUF sigjmp_buf
#define HAVE_MMAP

#elif defined(AIX)
#undef HAS_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define NEED_SELECT_H
#define JMP_BUF sigjmp_buf

#elif defined(ULTRIX)
#define HAS_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define ULTRIX_BRAIN_DEATH
#define NEED_STRDUP
/* If you have Ultrix 4.3, and are using cc, const is broken */
#ifndef __ultrix__ /* Hack to check for pre-Ultrix 4.4 cc */
#define const /* Not implemented */
#endif
#define JMP_BUF sigjmp_buf

#elif defined(OSF1)
#define HAS_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define JMP_BUF sigjmp_buf
#define HAVE_MMAP
#define HAVE_CRYPT_H

#elif defined(SEQUENT)
#define HAS_GMTOFF
#undef NO_KILLPG
#define NO_SETSID
#define NEED_STRDUP
#define tolower(c) (isupper(c) ? tolower(c) : c)

#elif defined(NEXT)
#include <libc.h>
typedef unsigned short mode_t;
#define HAS_GMTOFF
#undef NO_KILLPG
#define NO_SETSID
#define NEED_STRDUP
#undef _POSIX_SOURCE
#ifndef FD_CLOEXEC
#define FD_CLOEXEC 1
#endif
#ifndef S_ISDIR
#define S_ISDIR(m)      (((m)&(S_IFMT)) == (S_IFDIR))
#endif
#ifndef S_ISREG
#define S_ISREG(m)      (((m)&(S_IFMT)) == (S_IFREG))
#endif
#ifndef S_IXUSR
#define S_IXUSR 00100
#endif
#ifndef S_IRGRP
#define S_IRGRP 00040
#endif
#ifndef S_IXGRP
#define S_IXGRP 00010
#endif
#ifndef S_IROTH
#define S_IROTH 00004
#endif
#ifndef S_IXOTH
#define S_IXOTH 00001
#endif
#ifndef S_IRUSR
#define S_IRUSR S_IREAD
#endif
#ifndef S_IWUSR
#define S_IWUSR S_IWRITE
#endif
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define waitpid(a,b,c) wait4(a,(union wait *)b,c,NULL)
typedef int pid_t;
#define JMP_BUF jmp_buf
#define NO_USE_SIGACTION

#elif defined(LINUX)
#undef HAS_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#undef NEED_STRDUP
#define JMP_BUF sigjmp_buf
#define FCNTL_SERIALIZED_ACCEPT
#include <sys/time.h>     

#elif defined(SCO)
#undef HAS_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define NEED_INITGROUPS
#define JMP_BUF sigjmp_buf
#define SIGURG SIGUSR1 /* but note, this signal will be sent to a process group if enabled (for OOB data). It is not currently enabled. */
#define getwd(d) getcwd(d,MAX_STRING_LEN)

#elif defined(SCO5)

#define JMP_BUF sigjmp_buf
#define SIGURG SIGUSR1
#define NEED_SELECT_H
#define FCNTL_SERIALIZED_ACCEPT
#define HAVE_MMAP
#define SecureWare

/* Although SCO 5 defines these in <strings.h> (note the "s") they don't have
consts. Sigh. */
extern int strcasecmp(const char *,const char *);
extern int strncasecmp(const char *,const char *,unsigned);

#elif defined(CONVEXOS)
#define HAS_GMTOFF
#define NEED_STRDUP
#define getwd(d) getcwd(d,MAX_STRING_LEN)

#elif defined(AUX)
#undef HAS_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define NEED_STRDUP
#define JMP_BUF sigjmp_buf
/* fcntl() locking is expensive with NFS */
#undef FLOCK_SERIALIZED_ACCEPT
#define HAVE_SHMGET
#define MOVEBREAK		0x4000000
/* These are to let -Wall compile more cleanly */
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *,const char *,unsigned);

#elif defined(SVR4)
#define NO_KILLPG
#undef  NO_SETSID
#undef NEED_STRDUP
#define NEED_STRCASECMP
#define NEED_STRNCASECMP
#define bzero(a,b) memset(a,0,b)
#define JMP_BUF sigjmp_buf
#define getwd(d) getcwd(d,MAX_STRING_LEN)
/* A lot of SVR4 systems need this */
#define FCNTL_SERIALIZED_ACCEPT

#elif defined(DGUX)
#define NO_KILLPG
#undef  NO_SETSID
#undef NEED_STRDUP
#define NEED_STRCASECMP
#define NEED_STRNCASECMP
#define bzero(a,b) memset(a,0,b)
#define JMP_BUF sigjmp_buf
#define getwd(d) getcwd(d,MAX_STRING_LEN)
/* A lot of SVR4 systems need this */
#define FCNTL_SERIALIZED_ACCEPT

#elif defined(__NetBSD__)
#define HAS_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define JMP_BUF sigjmp_buf

#elif defined(UTS21)
#undef HAS_GMTOFF
#undef NO_KILLPG
#define NO_SETSID
#define NEED_WAITPID
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define strftime(buf,bufsize,fmt,tm)    ascftime(buf,fmt,tm)
#include <sys/types.h>

#elif defined(APOLLO)
#undef HAS_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define timezone	_bky_timezone

#elif defined(__FreeBSD__) || defined(__bsdi__)
#define HAS_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define JMP_BUF sigjmp_buf
#define HAVE_MMAP

#elif defined(QNX)
#undef NO_KILLPG
#undef NO_SETSID
#define NEED_INITGROUPS
#define NEED_SELECT_H
#define JMP_BUF sigjmp_buf

#elif defined(LYNXOS)
#undef NO_KILLPG
#undef NO_SETSID
#define NO_TIMEZONE
#define NEED_STRCASECMP
#define NEED_STRNCASECMP
#define NEED_INITGROUPS
#define JMP_BUF jmp_buf

#elif defined(__EMX__)
/* Defines required for EMX OS/2 port. */
#define JMP_BUF sigjmp_buf
#define NO_KILLPG
#define NEED_STRCASECMP
#define NEED_STRNCASECMP
#define NO_SETSID
/* Add some drive name support */
#define chdir _chdir2

/* Unknown system - Edit these to match */
#else
#ifdef BSD
#define HAS_GMTOFF
#else
#undef HAS_GMTOFF
#endif
/* NO_KILLPG is set on systems that don't have killpg */
#undef NO_KILLPG
/* NO_SETSID is set on systems that don't have setsid */
#undef NO_SETSID
/* NEED_STRDUP is set on stupid systems that don't have strdup. */
#undef NEED_STRDUP
#endif

/* Do we have sys/resource.h; assume that BSD does. */
#ifndef HAVE_RESOURCE
#ifdef BSD
#define HAVE_RESOURCE 1
#else
#define HAVE_RESOURCE 0
#endif
#endif /* HAVE_RESOURCE */

/*
 * The particular directory style your system supports. If you have dirent.h
 * in /usr/include (POSIX) or /usr/include/sys (SYSV), #include 
 * that file and define DIR_TYPE to be dirent. Otherwise, if you have 
 * /usr/include/sys/dir.h, define DIR_TYPE to be direct and include that
 * file. If you have neither, I'm confused.
 */

#include <sys/types.h>

#if !defined(NEXT) && !defined(CONVEXOS)
#include <dirent.h>
#define DIR_TYPE dirent
#else
#include <sys/dir.h>
#define DIR_TYPE direct
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#ifdef NEED_SELECT_H
#include <sys/select.h>
#endif
#include <ctype.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>  /* for inet_ntoa */
#include <time.h>  /* for ctime */
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <limits.h>
#ifndef QNX
#include <memory.h>
#endif

#if HAVE_RESOURCE
#include <sys/resource.h>
#ifdef SUNOS4
int getrlimit( int, struct rlimit *);
int setrlimit( int, struct rlimit *);
#endif
#endif
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif
#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#define MAP_ANON MAP_ANONYMOUS
#endif

#if defined(HAVE_MMAP) && defined(NO_MMAP)
#undef HAVE_MMAP
#endif

#ifndef LOGNAME_MAX
#define LOGNAME_MAX 25
#endif

#ifndef NEXT
#include <unistd.h>
#endif

#ifdef ultrix
#define ULTRIX_BRAIN_DEATH
#endif

#ifndef S_ISLNK
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif

/* Finding offsets of elements within structures.
 * Taken from the X code... they've sweated portability of this stuff
 * so we don't have to.  Sigh...
 */

#if defined(CRAY) || defined(__arm)
#if __STDC__
#define XtOffset(p_type,field) _Offsetof(p_type,field)
#else
#ifdef CRAY2
#define XtOffset(p_type,field) \
	(sizeof(int)*((unsigned int)&(((p_type)NULL)->field)))

#else	/* !CRAY2 */

#define XtOffset(p_type,field) ((unsigned int)&(((p_type)NULL)->field))

#endif	/* !CRAY2 */
#endif  /* __STDC__ */
#else	/* ! (CRAY || __arm) */

#define XtOffset(p_type,field) \
	((long) (((char *) (&(((p_type)NULL)->field))) - ((char *) NULL)))

#endif /* !CRAY */

#ifdef offsetof
#define XtOffsetOf(s_type,field) offsetof(s_type,field)
#else
#define XtOffsetOf(s_type,field) XtOffset(s_type*,field)
#endif

#ifdef SUNOS_LIB_PROTOTYPES
/* Prototypes needed to get a clean compile with gcc -Wall.
 * Believe it or not, these do have to be declared, at least on SunOS,
 * because they aren't mentioned in the relevant system headers.
 * Sun Quality Software.  Gotta love it.
 */

int getopt (int, char **, char *);

int strcasecmp (char *, char *);
int strncasecmp (char *, char *, int);
int toupper(int);
int tolower(int);     
     
int printf (char *, ...);     
int fprintf (FILE *, char *, ...);
int fputs (char *, FILE *);
int fread (char *, int, int, FILE *);     
int fwrite (char *, int, int, FILE *);     
int fflush (FILE *);
int fclose (FILE *);
int ungetc (int, FILE *);
int _filbuf (FILE *);		/* !!! */
int _flsbuf (unsigned char, FILE *); /* !!! */
int sscanf (char *, char *, ...);
void setbuf (FILE *, char *);
void perror (char *);
     
time_t time (time_t *);
int strftime (char *, int, char *, struct tm *);
     
int initgroups (char *, int);     
int wait3 (int *, int, void*);	/* Close enough for us... */
int lstat (const char *, struct stat *);
int stat (const char *, struct stat *);     
int flock (int, int);
int getwd (char *);
#ifndef NO_KILLPG
int killpg(int, int);
#endif
int socket (int, int, int);     
int setsockopt (int, int, int, const char*, int);
int listen (int, int);     
int bind (int, struct sockaddr *, int);     
int connect (int, struct sockaddr *, int);
int accept (int, struct sockaddr *, int *);
int shutdown (int, int);     

int getsockname (int s, struct sockaddr *name, int *namelen);
int getpeername (int s, struct sockaddr *name, int *namelen);
int gethostname (char *name, int namelen);     
void syslog (int, char *, ...);
char *mktemp (char *);
     
#include <stdarg.h>
long vfprintf (FILE *, char *, va_list);
     
#endif
