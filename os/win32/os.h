/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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

#ifndef APACHE_OS_H
#define APACHE_OS_H
/* 
 * Compile the server including all the Windows NT 4.0 header files by 
 * default. We still want the server to run on Win95/98 so use 
 * runtime checks before calling NT specific functions to verify we are 
 * really running on an NT system.
 *
 * Delegate windows include to the apr.h header, if USER or GDI declarations
 * are required (for a window rather than console application), include
 * windows.h prior to any other Apache header files.
 */

#ifndef _WIN32
#define _WIN32
#endif

#include "apr_general.h"
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
#define NO_USE_SIGACTION
/* #undef HAVE_TIMES */
#define USE_LONGJMP
#define HAVE_CANONICAL_FILENAME
#define HAVE_DRIVE_LETTERS
#define HAVE_SENDFILE

typedef int uid_t;
typedef int gid_t;
typedef int pid_t;
typedef int mode_t;
typedef char * caddr_t;

#define HAVE_MEMMOVE

#define S_ISLNK(m) (0)
#define S_ISREG(m) ((m & _S_IFREG) == _S_IFREG)
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & S_IFDIR) == S_IFDIR)
#endif

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define JMP_BUF jmp_buf
#define O_CREAT _O_CREAT
#define O_RDWR _O_RDWR
/* Seems Windows is not a subgenius */
#define NO_SLACK
#define APACHE_MPM_DIR  "modules/mpm/winnt" /* generated on unix */

#include <stddef.h>

__inline int ap_os_is_path_absolute(const char *file)
{
  /* For now, just do the same check that http_request.c and mod_alias.c
   * do. 
   */
  return file[0] == '/' || file[1] == ':';
}

/* OS-dependent filename routines in util_win32.c */
API_EXPORT(char *) ap_os_canonical_filename(apr_pool_t *p, const char *file);
API_EXPORT(char *) ap_os_case_canonical_filename(apr_pool_t *pPool, const char *szFile);
API_EXPORT(char *) ap_os_systemcase_filename(apr_pool_t *pPool, const char *szFile);
API_EXPORT(int) ap_os_is_filename_valid(const char *file);

#define ap_os_dso_error()   ""	/* for now */
/* Other ap_os_ routines not used by this platform */
#define ap_os_kill(pid, sig)                kill(pid, sig)

typedef void thread;
typedef void event;


#endif   /* ! APACHE_OS_H */
