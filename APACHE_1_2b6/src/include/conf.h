/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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
#define HAVE_GMTOFF
#define HAVE_SYS_RESOURCE_H
#undef NO_KILLPG
#undef NO_SETSID
char *crypt(const char *pw, const char *salt);
#define JMP_BUF sigjmp_buf
#define HAVE_MMAP
#include <sys/time.h>     
#define NEED_STRERROR
typedef int rlim_t;

#elif defined(SOLARIS2)
#undef HAVE_GMTOFF
#define NO_KILLPG
#undef NO_SETSID
#define HAVE_SYS_RESOURCE_H
#define bzero(a,b) memset(a,0,b)
#define getwd(d) getcwd(d,MAX_STRING_LEN)
#define JMP_BUF sigjmp_buf
#define USE_FCNTL_SERIALIZED_ACCEPT
#define HAVE_MMAP
#define HAVE_CRYPT_H
int gethostname(char *name, int namelen);

#elif defined(IRIX)
#undef HAVE_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define JMP_BUF sigjmp_buf
#define USE_FCNTL_SERIALIZED_ACCEPT
#define HAVE_SHMGET
#define HAVE_CRYPT_H
#define NO_LONG_DOUBLE

#elif defined(HPUX) || defined(HPUX10)
#define HAVE_SYS_RESOURCE_H
#undef HAVE_GMTOFF
#define NO_KILLPG
#undef NO_SETSID
#ifndef _HPUX_SOURCE
#define _HPUX_SOURCE
#endif
#ifndef HPUX10
#define getwd(d) getcwd(d,MAX_STRING_LEN)
#endif
#define JMP_BUF sigjmp_buf
#define HAVE_SHMGET
#ifndef HPUX10
typedef int rlim_t;
#endif

#elif defined(AIX)
#undef HAVE_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define HAVE_SYS_SELECT_H
#define JMP_BUF sigjmp_buf
#ifndef __ps2__
#define HAVE_MMAP
#define DEFAULT_GROUP "nobody"
#endif
#define DEFAULT_USER "nobody"
typedef int rlim_t;

#elif defined(ULTRIX)
#define HAVE_GMTOFF
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
#define HAVE_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define JMP_BUF sigjmp_buf
#define HAVE_MMAP
#define HAVE_CRYPT_H
#define NO_LONG_DOUBLE

#elif defined(PARAGON)
#define HAVE_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define JMP_BUF sigjmp_buf
#define HAVE_MMAP
#define HAVE_CRYPT_H
#define NO_LONG_DOUBLE
typedef int rlim_t;

#elif defined(SEQUENT)
#define HAVE_GMTOFF
#undef NO_KILLPG
#define NO_SETSID
#define NEED_STRDUP
#define tolower(c) (isupper(c) ? tolower(c) : c)

#elif defined(NEXT)
typedef unsigned short mode_t;
#define HAVE_GMTOFF
#undef NO_KILLPG
#define NO_SETSID
#define NEED_STRDUP
#define NO_UNISTD_H
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
#ifndef S_IWGRP
#define S_IWGRP	000020
#endif
#ifndef S_IWOTH
#define S_IWOTH 000002
#ifndef rlim_t
typedef int rlim_t;
#endif
typedef u_long  n_long;
#endif

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define waitpid(a,b,c) wait4((a) == -1 ? 0 : (a),(union wait *)(b),c,NULL)
typedef int pid_t;
#define JMP_BUF jmp_buf
#define NO_USE_SIGACTION

#elif defined(LINUX)
#undef HAVE_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#undef NEED_STRDUP
#define JMP_BUF sigjmp_buf
#define USE_FCNTL_SERIALIZED_ACCEPT
#include <sys/time.h>     

#elif defined(SCO)
#undef HAVE_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define NEED_INITGROUPS
#define JMP_BUF sigjmp_buf
#define SIGURG SIGUSR1 /* but note, this signal will be sent to a process group if enabled (for OOB data). It is not currently enabled. */
#define getwd(d) getcwd(d,MAX_STRING_LEN)

#elif defined(SCO5)

#define JMP_BUF sigjmp_buf
#define SIGURG SIGUSR1
#define HAVE_SYS_SELECT_H
#define USE_FCNTL_SERIALIZED_ACCEPT
#define HAVE_MMAP
#define HAVE_SYS_RESOURCE_H
#define SecureWare

/* Although SCO 5 defines these in <strings.h> (note the "s") they don't have
consts. Sigh. */
extern int strcasecmp(const char *,const char *);
extern int strncasecmp(const char *,const char *,unsigned);

#elif defined(CONVEXOS)
#define HAVE_GMTOFF
#define NEED_STRDUP
#define getwd(d) getcwd(d,MAX_STRING_LEN)

#elif defined(AUX)
/* These are to let -Wall compile more cleanly */
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *,const char *,unsigned);
extern int set42sig(), getopt(), getpeername(), bzero();
extern int listen(), bind(), socket(), getsockname();
extern int accept(), gethostname(), connect(), lstat();
extern int select(), killpg(), shutdown();
extern int initgroups(), setsockopt();
extern char *crypt();
extern char *getwd();
#include <sys/time.h>
#undef HAVE_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define NEED_STRDUP
#define JMP_BUF sigjmp_buf
/* fcntl() locking is expensive with NFS */
#undef USE_FLOCK_SERIALIZED_ACCEPT
#define HAVE_SHMGET
#define MOVEBREAK		0x4000000
/*
 * NOTE: If when you run Apache under A/UX and you get a warning
 * that httpd couldn't move break, then the above value for
 * MOVEBREAK (64megs) is too large for your setup. Try reducing
 * to 0x2000000 which is still PLENTY of space. I doubt if
 * even on heavy systems sbrk() would be called at all...
 */
#define NO_LINGCLOSE

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
#define USE_FCNTL_SERIALIZED_ACCEPT

#elif defined(UW)
#define NO_KILLPG
#undef  NO_SETSID
#undef NEED_STRDUP
#define NEED_STRCASECMP
#define NEED_STRNCASECMP
#define bzero(a,b) memset(a,0,b)
#define JMP_BUF sigjmp_buf
#define getwd(d) getcwd(d,MAX_STRING_LEN)
#define HAVE_RESOURCE
#define HAVE_MMAP
#define HAVE_SHMGET
#define HAVE_CRYPT_H
#define HAVE_SYS_SELECT_H
#define HAVE_SYS_RESOURCE_H
#include <sys/time.h>
#define _POSIX_SOURCE

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
#define USE_FCNTL_SERIALIZED_ACCEPT

#elif defined(__NetBSD__) || defined(__OpenBSD__)
#define HAVE_SYS_RESOURCE_H
#define HAVE_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define JMP_BUF sigjmp_buf
#define DEFAULT_USER "nobody"
#define DEFAULT_GROUP "nogroup"

#elif defined(UTS21)
#undef HAVE_GMTOFF
#undef NO_KILLPG
#define NO_SETSID
#define NEED_WAITPID
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define strftime(buf,bufsize,fmt,tm)    ascftime(buf,fmt,tm)
#include <sys/types.h>

#elif defined(APOLLO)
#undef HAVE_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID

#elif defined(__FreeBSD__) || defined(__bsdi__)
#define HAVE_SYS_RESOURCE_H
#define HAVE_GMTOFF
#undef NO_KILLPG
#undef NO_SETSID
#define JMP_BUF sigjmp_buf
#define HAVE_MMAP
#define DEFAULT_USER "nobody"
#define DEFAULT_GROUP "nogroup"
typedef quad_t rlim_t;

#elif defined(QNX)
#undef NO_KILLPG
#undef NO_SETSID
#define NEED_INITGROUPS
#define NEED_SELECT_H
#define NEED_PROCESS_H
#define HAVE_SYS_SELECT_H

#include <unix.h>

#define JMP_BUF sigjmp_buf

#elif defined(LYNXOS)
#undef NO_KILLPG
#undef NO_SETSID
#define NEED_STRCASECMP
#define NEED_STRNCASECMP
#define NEED_INITGROUPS
#define JMP_BUF jmp_buf

#elif defined(UXPDS)
#undef NEED_STRCASECMP
#undef NEED_STRNCASECMP
#undef NEED_STRDUP
#undef HAS_GMTOFF
#define NO_KILLPG
#undef NO_SETSID
#define HAVE_RESOURCE 1
#define bzero(a,b) memset(a,0,b)
#define getwd(d) getcwd(d,MAX_STRING_LEN)
#define JMP_BUF sigjmp_buf
#define USE_FCNTL_SERIALIZED_ACCEPT
#define HAVE_MMAP
#define HAVE_CRYPT_H
 
#elif defined(__EMX__)
/* Defines required for EMX OS/2 port. */
#define JMP_BUF sigjmp_buf
#define NO_KILLPG
#define NEED_STRCASECMP
#define NEED_STRNCASECMP
#define NO_SETSID
/* Add some drive name support */
#define chdir _chdir2
#include <sys/time.h>     
#define MAXSOCKETS 4096
#define HAVE_MMAP
    
#elif defined(__MACHTEN__)
typedef int rlim_t;
#define JMP_BUF sigjmp_buf
#undef NO_KILLPG
#define NO_SETSID
#define HAS_GMTOFF
#ifndef __MACHTEN_PPC__
#ifndef __MACHTEN_68K__
#define __MACHTEN_68K__
#endif
#define FLOCK_SERIALIZED_ACCEPT
#define NO_USE_SIGACTION
#undef NEED_STRDUP
#else
#define FCNTL_SERIALIZED_ACCEPT
#endif

/* Convex OS v11 */
#elif defined(CONVEXOS11)
#define NO_TIMEZONE
#include <stdio.h>
#include <sys/types.h>
#define JMB_BUF jmp_buf
typedef int rlim_t;

#elif defined(ISC)
#include <net/errno.h>     
#define NO_KILLPG
#undef NO_SETSID
#define HAVE_SHMGET
#define SIGURG SIGUSR1
#define JMP_BUF sigjmp_buf
#define USE_FCNTL_SERIALIZED_ACCEPT
#define getwd(d) getcwd(d,MAX_STRING_LEN)

/* Unknown system - Edit these to match */
#else
#ifdef BSD
#define HAVE_GMTOFF
#else
#undef HAVE_GMTOFF
#endif
/* NO_KILLPG is set on systems that don't have killpg */
#undef NO_KILLPG
/* NO_SETSID is set on systems that don't have setsid */
#undef NO_SETSID
/* NEED_STRDUP is set on stupid systems that don't have strdup. */
#undef NEED_STRDUP
#endif

/* Do we have sys/resource.h; assume that BSD does. */
#ifndef HAVE_SYS_RESOURCE_H
#ifdef BSD
#define HAVE_SYS_RESOURCE_H
#endif
#endif /* HAVE_SYS_RESOURCE_H */

/*
 * The particular directory style your system supports. If you have dirent.h
 * in /usr/include (POSIX) or /usr/include/sys (SYSV), #include 
 * that file and define DIR_TYPE to be dirent. Otherwise, if you have 
 * /usr/include/sys/dir.h, define DIR_TYPE to be direct and include that
 * file. If you have neither, I'm confused.
 */

#include <sys/types.h>
#include <stdarg.h>
/*
 * We use snprintf() to avoid overflows, but we include
 * our own version (ap_snprintf). Allow for people to use their
 * snprintf() if they want
 */
#ifdef HAVE_SNPRINTF
#define ap_snprintf     snprintf
#define ap_vsnprintf    vsnprintf
#else
int ap_snprintf(char *buf, size_t len, const char *format,...);
int ap_vsnprintf(char *buf, size_t len, const char *format, va_list ap);
#endif

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
#ifdef HAVE_SYS_SELECT_H
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
#if !defined(QNX) && !defined(CONVEXOS11) && !defined(NEXT)
#include <memory.h>
#endif
#ifdef NEED_PROCESS_H
#include <process.h>
#endif

#include <regex.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#ifdef SUNOS4
int getrlimit( int, struct rlimit *);
int setrlimit( int, struct rlimit *);
#endif
#endif
#ifdef HAVE_MMAP
#ifndef __EMX__
/* This file is not needed for OS/2 */
#include <sys/mman.h>
#endif
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
#ifndef __EMX__
/* Don't define this for OS/2 */
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif
#endif

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
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
     
long vfprintf (FILE *, char *, va_list);
     
#endif
