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

#ifndef APACHE_OS_H
#define APACHE_OS_H

#ifdef WIN32

/* 
 * Compile the server including all the Windows NT 4.0 header files by 
 * default. We still want the server to run on Win95/98 so use 
 * runtime checks before calling NT specific functions to verify we are 
 * really running on an NT system.
 */
#define _WIN32_WINNT 0x0400

/* If it isn't too late, prevent windows.h from including the original
 * winsock.h header, so that we can still include winsock2.h
 */
#if !defined(_WINSOCKAPI_) || !defined(_WINDOWS_)
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#else
#include <windows.h>
#endif
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
#define HAVE_UNC_PATHS
typedef int uid_t;
typedef int gid_t;
typedef int pid_t;
typedef int tid_t;
#ifdef _MSC_VER
/* modified to match declaration in sys/stat.h */
typedef unsigned short mode_t;
#endif
typedef char * caddr_t;

/*
Define export types. API_EXPORT_NONSTD is a nasty hack to avoid having to declare
every configuration function as __stdcall.
*/

#ifdef SHARED_MODULE
#define API_VAR_EXPORT          __declspec(dllimport)
#define API_EXPORT(type)        __declspec(dllimport) type __stdcall
#define API_EXPORT_NONSTD(type) __declspec(dllimport) type __cdecl
#else
#define API_VAR_EXPORT          __declspec(dllexport)
#define API_EXPORT(type)        __declspec(dllexport) type __stdcall
#define API_EXPORT_NONSTD(type) __declspec(dllexport) type __cdecl
#endif
#define MODULE_VAR_EXPORT   __declspec(dllexport)

#define strcasecmp(s1, s2) stricmp(s1, s2)
#define strncasecmp(s1, s2, n) strnicmp(s1, s2, n)
#define lstat(x, y) stat(x, y)
#ifndef S_ISLNK
#define S_ISLNK(m) (0)
#endif
#ifndef S_ISREG
#define S_ISREG(m) ((m & _S_IFREG) == _S_IFREG)
#endif
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & _S_IFDIR) == _S_IFDIR)
#endif
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define JMP_BUF jmp_buf
#define sleep(t) Sleep(t*1000)
#ifndef O_CREAT
#define O_CREAT _O_CREAT
#endif
#ifndef O_RDWR
#define O_RDWR _O_RDWR
#endif
#define SIGPIPE 17
/* Seems Windows is not a subgenius */
#define NO_SLACK
#include <stddef.h>

/* MSVC asserts that strtol "errno is set to ERANGE 
 * if overflow or underflow occurs"
 * Ergo we can use the library strtol safely.
 */
#define ap_strtol strtol

#define NO_OTHER_CHILD
#define NO_RELIABLE_PIPED_LOGS

__inline int ap_os_is_path_absolute(const char *file)
{
  /* For now, just do the same check that http_request.c and mod_alias.c
   * do. 
   */
  return file && (file[0] == '/' || (file[1] == ':' && file[2] == '/'));
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
API_EXPORT_NONSTD(int) os_spawnle(int mode,const char *cmdname,...);

/* OS-dependent filename routines in util_win32.c */

API_EXPORT(int) ap_os_is_filename_valid(const char *file);

/* Abstractions for dealing with shared object files (DLLs on Win32).
 * These are used by mod_so.c
 */
#define ap_os_dso_handle_t  HINSTANCE
#define ap_os_dso_init()
#define ap_os_dso_unload(l) FreeLibrary(l)
#define ap_os_dso_sym(h,s)  GetProcAddress(h,s)

API_EXPORT(ap_os_dso_handle_t) ap_os_dso_load(const char *);
API_EXPORT(const char *) ap_os_dso_error(void);

/* Other ap_os_ routines not used by this platform */
#define ap_os_kill(pid, sig)                kill(pid, sig)

/* Some Win32isms */
#define HAVE_ISNAN
#define isnan(n) _isnan(n)
#define HAVE_ISINF
#define isinf(n) (!_finite(n))

#define gettid() ((tid_t)GetCurrentThreadId())

#endif /* WIN32 */

#endif   /* ! APACHE_OS_H */
