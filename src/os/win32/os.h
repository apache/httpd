/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
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

#ifndef APACHE_OS_H
#define APACHE_OS_H

/* 
 * Compile the server including all the Windows NT 4.0 header files by 
 * default. We still want the server to run on Win95/98 so use 
 * runtime checks before calling NT specific functions to verify we are 
 * really running on an NT system.
 */
#define _WIN32_WINNT 0x0400

#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <process.h>
#include <malloc.h>
#include <io.h>
#include <fcntl.h>

#define PLATFORM "Win32"

/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c
 */

/* temporarily replace crypt */
/* char *crypt(const char *pw, const char *salt); */
#define crypt(buf,salt)	    (buf)

/* Although DIR_TYPE is dirent (see nt/readdir.h) we need direct.h for
   chdir() */
#include <direct.h>

#define STATUS
#ifndef STRICT
#define STRICT
#endif
#define CASE_BLIND_FILESYSTEM
#define NO_WRITEV
#define NO_SETSID
#define NO_USE_SIGACTION
#define NO_TIMES
#define NO_GETTIMEOFDAY
#define USE_LONGJMP
#define HAVE_MMAP
#define USE_MMAP_SCOREBOARD
#define MULTITHREAD
#define HAVE_CANONICAL_FILENAME
#define HAVE_DRIVE_LETTERS
typedef int uid_t;
typedef int gid_t;
typedef int pid_t;
typedef int mode_t;
typedef char * caddr_t;

/*
Define export types. API_EXPORT_NONSTD is a nasty hack to avoid having to declare
every configuration function as __stdcall.
*/

#ifdef SHARED_MODULE
# define API_VAR_EXPORT		__declspec(dllimport)
# define API_EXPORT(type)    __declspec(dllimport) type __stdcall
# define API_EXPORT_NONSTD(type)    __declspec(dllimport) type
#else
# define API_VAR_EXPORT		__declspec(dllexport)
# define API_EXPORT(type)    __declspec(dllexport) type __stdcall
# define API_EXPORT_NONSTD(type)    __declspec(dllexport) type
#endif
#define MODULE_VAR_EXPORT   __declspec(dllexport)

#define strcasecmp(s1, s2) stricmp(s1, s2)
#define strncasecmp(s1, s2, n) strnicmp(s1, s2, n)
#define lstat(x, y) stat(x, y)
#define S_ISLNK(m) (0)
#define S_ISREG(m) ((m & _S_IFREG) == _S_IFREG)
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & S_IFDIR) == S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m)      (((m)&(S_IFREG)) == (S_IFREG))
#endif
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define JMP_BUF jmp_buf
#define sleep(t) Sleep(t*1000)
#define O_CREAT _O_CREAT
#define O_RDWR _O_RDWR
#define SIGPIPE 17
/* Seems Windows is not a subgenius */
#define NO_SLACK
#include <stddef.h>

#define NO_OTHER_CHILD
#define NO_RELIABLE_PIPED_LOGS

__inline int ap_os_is_path_absolute(const char *file)
{
  /* For now, just do the same check that http_request.c and mod_alias.c
   * do. 
   */
  return file[0] == '/' || file[1] == ':';
}

#define stat(f,ps)  os_stat(f,ps)
API_EXPORT(int) os_stat(const char *szPath,struct stat *pStat);

API_EXPORT(int) os_strftime(char *s, size_t max, const char *format, const struct tm *tm);

#define _spawnv(mode,cmdname,argv)	    os_spawnv(mode,cmdname,argv)
#define spawnv(mode,cmdname,argv)	    os_spawnv(mode,cmdname,argv)
API_EXPORT(int) os_spawnv(int mode,const char *cmdname,const char *const *argv);
#define _spawnve(mode,cmdname,argv,envp)    os_spawnve(mode,cmdname,argv,envp)
#define spawnve(mode,cmdname,argv,envp)	    os_spawnve(mode,cmdname,argv,envp)
API_EXPORT(int) os_spawnve(int mode,const char *cmdname,const char *const *argv,const char *const *envp);
#define _spawnle			    os_spawnle
#define spawnle				    os_spawnle
API_EXPORT(int) os_spawnle(int mode,const char *cmdname,...);

/* OS-dependent filename routines in util_win32.c */

API_EXPORT(int) ap_os_is_filename_valid(const char *file);

/* Abstractions for dealing with shared object files (DLLs on Win32).
 * These are used by mod_so.c
 */
#define ap_os_dso_handle_t  HINSTANCE
#define ap_os_dso_init()
#define ap_os_dso_load(l)   LoadLibraryEx(l, NULL, LOAD_WITH_ALTERED_SEARCH_PATH)
#define ap_os_dso_unload(l) FreeLibrary(l)
#define ap_os_dso_sym(h,s)  GetProcAddress(h,s)
#define ap_os_dso_error()   ""	/* for now */

/* Other ap_os_ routines not used by this platform */
#define ap_os_kill(pid, sig)                kill(pid, sig)

#endif   /* ! APACHE_OS_H */
