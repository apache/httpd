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

#define PLATFORM "NETWARE"

/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */

typedef int int32;
typedef int uid_t;
typedef int gid_t;

#include "ap_config.h"
#include <string.h>
#include <stddef.h>
#include <nwthread.h>
#include <nwmalloc.h>
#include <nwnamspc.h>
#include <nwadv.h>
#include <ws2nlm.h>
#include <winsock2.h>
#include <fcntl.h>

#define NO_LINGCLOSE
#define NO_SLACK
#define HAVE_UNISTD_H
#define NO_SETSID
#define NO_KILLPG
#define NO_WRITEV
#define NO_GETTIMEOFDAY
#define NO_TIMES
#define NO_USE_SIGACTION
#define USE_LONGJMP
#define MULTITHREAD

#define NO_RELIABLE_PIPED_LOGS
#define CASE_BLIND_FILESYSTEM
#define NO_OTHER_CHILD

#define USE_HSREGEX
#define NETDB_USE_INTERNET
#define N_PLAT_NLM
#define APX386
#define ALLOC_USE_MALLOC
#define OPTIMIZE_TIMEOUTS
#define FD_SETSIZE 128
#define NO_DBM_REWRITEMAP



#define crypt(buf,salt)	    (buf)
#define sleep(t) delay(t*1000)
#define getpid GetThreadID
#define lstat(x, y) stat(x, y)
#define ap_os_is_filename_valid(f)          (1)
#define strcasecmp(s1, s2) stricmp(s1, s2)
#define strncasecmp(s1, s2, n) strnicmp(s1, s2, n)
#define mktemp(s) tmpnam(s)
#define _getch(c) getch(c)


/* Prototypes */
void AMCSocketCleanup(void);
static void clean_parent_exit(int code);

inline int ap_os_is_path_absolute(const char *file)
{
    if (strstr(file, ":/"))
        return 1;
    else
        return 0;
}

#define ap_os_dso_handle_t  void *
void ap_os_dso_init(void);
void *ap_os_dso_load(const char *);
void ap_os_dso_unload(void *);
void *ap_os_dso_sym(void *, const char *);
const char *ap_os_dso_error(void);
char *remove_filename(char*);
char *bslash2slash(char*);
#endif /*! APACHE_OS_H*/

