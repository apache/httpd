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

#define PLATFORM "NETWARE"
#define HAVE_CANONICAL_FILENAME

/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */

typedef signed long int32;
typedef int uid_t;
typedef int gid_t;
typedef int tid_t;

#include "ap_config.h"
#include <string.h>
#include <stddef.h>
#include <nwthread.h>
#include <nwmalloc.h>
#include <nwnamspc.h>
#include <nwlib.h>
#include <nwadv.h>
#include <ws2nlm.h>
#include <winsock2.h>
#include <fcntl.h>
#include <dirent.h>

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
#define getpid() ((pid_t)GetThreadGroupID())
#define gettid() ((tid_t)GetThreadID())
/* Netware doesn't have symlinks so S_ISLNK is always false */
#define S_ISLNK(m) 0
/* Netware doesn't have isnan,isinf so they always return false */
#define isnan(m) 0
#define isinf(m) 0
#define lstat(x, y) stat(x, y)
#define strcasecmp(s1, s2) stricmp(s1, s2)
#define strncasecmp(s1, s2, n) strnicmp(s1, s2, n)
#define mktemp(s) tmpnam(s)
#define _getch getch

/* Watcom reports that ERANGE is returned properly for any out of bounds
 * conditions, with a MIN/MAX_LONG value.  This should be safe.
 */
#define ap_strtol strtol

#define opendir_411(p) os_opendir(p)
#define opendir(p) os_opendir(p)
DIR *os_opendir (const char *pathname);

#define readdir_411(p) os_readdir(p)
#define readdir(p) os_readdir(p)
DIR *os_readdir (DIR *dirP);

#define closedir_510(p) os_closedir(p)
#define closedir(p) os_closedir(p)
int os_closedir (DIR *dirP);

/* Prototypes */
void AMCSocketCleanup(void);
void clean_parent_exit(int code);

#ifdef __GNUC__
static
#endif
inline int ap_os_is_path_absolute(const char *file)
{
    char *s = strstr (file, "://");

    /* First make sure we aren't looking at a URL such as
        a proxy:http://blah.
    */
    if (!s) {
        s = strchr (file, ':');
    
        if (s) {
            if (strncmp(s, "://", 3) != 0)
	        /* XXX: we assume that everything before the : is letters */
                return 1;
        }
        else {
            if (file[0] == '/')
                return 1;
        }
    }
    	
    return 0;
}

#define ap_os_dso_handle_t  void *
void ap_os_dso_init(void);
void *ap_os_dso_load(const char *);
void ap_os_dso_unload(void *);
void *ap_os_dso_sym(void *, const char *);
void ap_os_dso_unsym(void *handle, const char *symname);
const char *ap_os_dso_error(void);
char *remove_filename(char*);
char *bslash2slash(char*);
void init_name_space(void);
int ap_os_is_filename_valid(const char *file);
char *ap_os_http_method(void *r);
unsigned short ap_os_default_port(void *r);
#endif /*! APACHE_OS_H*/

