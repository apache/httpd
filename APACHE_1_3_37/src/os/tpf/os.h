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

/*
 * This file is included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */

#define PLATFORM "TPF"
#ifndef TPF
#define TPF 1
#endif
#if !defined(TPF64BIT) && !defined(TPF41)
#define TPF41
#endif

/*---------------------------------------------------------------------*/
#ifdef TPF64BIT
/*---------------------------------------------------------------------*/
#define TPF_HAVE_NONSOCKET_SELECT
#define TPF_HAVE_SAWNC
#define HAVE_SYSLOG
#define TPF_HAVE_SIGACTION
#define HAVE_SYS_SELECT_H
#define HAVE_ISNAN
#define HAVE_ISINF
#define TPF_FORK_EXTENDED
#include <stdlib.h>
#include <tpf/tpfeq.h>
#include <tpf/tpfio.h>
#include <tpf/sysapi.h>
#include <time.h>
#include <tpf/i_netd.h>
#include <strings.h>
#include <unistd.h>
#endif /* TPF64BIT */

/*---------------------------------------------------------------------*/
#ifdef TPF41
/*---------------------------------------------------------------------*/

/************************************************************************
 *  TPF41 PJ26895 provides support for non_socket_select.
 *  You can determine if this apar is applied to your system by looking
 *  at i$pwbl.h.  If the function non_socket_select is defined,
 *  then add #define TPF_HAVE_NONSOCKET_SELECT
 *  else add #define TPF_NO_NONSOCKET_SELECT
 *
 *  One of these two #defines is required and must be added here in os.h
 *  before the following check.
 ************************************************************************/

#if !defined(TPF_HAVE_NONSOCKET_SELECT) && !defined(TPF_NO_NONSOCKET_SELECT)
   #error "You must define whether your system supports non_socket_select()"
   #error "See src/os/tpf/os.h for instructions"
#endif

#if defined(TPF_HAVE_NONSOCKET_SELECT) && defined(TPF_NO_NONSOCKET_SELECT)
   #error "TPF_HAVE_NONSOCKET_SELECT and TPF_NO_NONSOCKET_SELECT"
   #error "cannot both be defined"
   #error "See src/os/tpf/os.h for instructions"
#endif

/************************************************************************
 *  TPF41 PJ27387 or PJ26188 provides support for tpf_sawnc.
 *  You can determine if this apar is applied to your system by looking at
 *  tpfapi.h or i$fsdd.h.  If the function tpf_sawnc is defined,
 *  then add #define TPF_HAVE_SAWNC
 *  else add #define TPF_NO_SAWNC
 *
 *  One of these two #defines is required and must be added here in os.h
 *  before the following check.
 ************************************************************************/

#if !defined(TPF_HAVE_SAWNC) && !defined(TPF_NO_SAWNC)
   #error "You must define whether your system supports tpf_sawnc()"
   #error "See src/os/tpf/os.h for instructions"
#endif

#if defined(TPF_HAVE_SAWNC) && defined(TPF_NO_SAWNC)
   #error "TPF_HAVE_SAWNC and TPF_NO_SAWNC"
   #error "cannot both be defined"
   #error "See src/os/tpf/os.h for instructions"
#endif

/* if the compiler defined errno then undefine it
   and pick up the correct definition from errno.h */
#if defined(errno) && !defined(__errnoh)
#undef errno
#include <errno.h>
#endif

/* If TPF41 APAR PJ27277 (which shipped on TPF41 PUT13) has been applied */
/* then we want to #define TPF_FORK_EXTENDED so Perl CGIs will work. */
/* Rather than hardcoding it we'll check for "environ" in stdlib.h, */
/* which was also added by TPF41 PJ27277. */
#include <stdlib.h>
#if defined(environ) && !defined(TPF_FORK_EXTENDED)
#define TPF_FORK_EXTENDED
#endif
#define WUNTRACED 0 /* TPF41's waitpid() doesn't support WUNTRACED */
#include <tpfeq.h>
#include <tpfio.h>
#include <sysapi.h>  
#include <sysgtime.h>
#include <i$netd.h>
#include <strings.h>
#ifndef __strings_h
#define NEED_STRCASECMP
#define NEED_STRNCASECMP
#endif
#define NEED_STRDUP
#define NO_GETTIMEOFDAY
#ifndef _POSIX_SOURCE
#define _POSIX_SOURCE 1
#endif
#ifndef USE_HSREGEX
#define USE_HSREGEX 1
#endif
#include <unistd.h>
#define crypt(buf,salt) ((char *)buf)
#undef  offsetof
#define offsetof(s_type,field) ((size_t)&(((s_type*)0)->field))

#endif /* TPF41 */

/*---------------------------------------------------------------------*/
/* common                                                              */
/*---------------------------------------------------------------------*/
#define AP_LONGEST_LONG long long
/* byte order of machine (12: little endian, 21: big endian) */
#define AP_BYTE_ORDER 21 /* TPF is big endian */
#define CHARSET_EBCDIC 1
#define PRIMECRAS 0x010000
#define JMP_BUF jmp_buf
#define HAVE_SHMGET
#define HAVE_SYS_PARAM_H
#define NEED_INITGROUPS
#define NEED_SIGNAL_INTERRUPT
#define NO_LINGCLOSE
#define NO_MMAP
#define NO_OTHER_CHILD
#define NO_PIPED_LOGS
#define NO_RELIABLE_PIPED_LOGS
#define NO_SETSID
#define NO_SLACK
#define NO_TIMES
#ifndef TPF_HAVE_SIGACTION
#define NO_USE_SIGACTION
#endif
#define USE_LONGJMP
#define USE_SHMGET_SCOREBOARD
#define USE_TPF_ACCEPT
#define HAVE_TPF_CORE_SERIALIZED_ACCEPT
#define USE_TPF_SELECT
#define S_IREAD S_IRUSR
#define S_IWRITE S_IWUSR
#define S_IEXEC S_IXUSR
#define HAVE_UNISTD_H 1
#ifndef NO_DL_NEEDED
#define NO_DL_NEEDED 1
#endif

#include "ap_config.h"

#if !defined(INLINE) && defined(USE_GNU_INLINE)
/* Compiler supports inline, so include the inlineable functions as
 * part of the header
 */
#define INLINE extern ap_inline
#include "os-inline.c"
#endif

#ifndef INLINE
/* Compiler does not support inline, so prototype the inlineable functions
 * as normal
 */
extern int ap_os_is_path_absolute(const char *f);
#endif

/* Other ap_os_ routines not used by this platform */

#define ap_os_is_filename_valid(f)          (1)
#define ap_os_kill(pid, sig)                kill(pid, sig)

/*---------------------------------------------------------------------*/
#ifdef TPF41
/*---------------------------------------------------------------------*/
#ifndef __strings_h

#define FD_SETSIZE    2048 
 
typedef long fd_mask;

#define NBBY    8    /* number of bits in a byte */
#define NFDBITS (sizeof(fd_mask) * NBBY)
#define  howmany(x, y)  (((x)+((y)-1))/(y))

typedef struct fd_set { 
        fd_mask fds_bits [howmany(FD_SETSIZE, NFDBITS)];
} fd_set; 

#define FD_CLR(n, p)((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)((p)->fds_bits[(n)/NFDBITS] & (1 <<((n) % NFDBITS)))
#define FD_ZERO(p)   memset((char *)(p), 0, sizeof(*(p)))
#endif /* __strings_h */
    
#ifdef FD_SET
#undef FD_SET
#define FD_SET(n, p) (0)
#endif /* FD_SET */

#endif /* TPF41 */

/*---------------------------------------------------------------------*/
/* common                                                              */
/*---------------------------------------------------------------------*/
#define TPF_MUTEX_KEY_SIZE (sizeof(pid_t)*2+1)

/* TPF doesn't have, or need, tzset (it is used in mod_expires.c) */
#define tzset()
 
/* definitions for the file descriptor inheritance table */
#define TPF_FD_LIST_SIZE 4000

/* seconds to delay after shutdown/restart signals have been sent */
#ifndef TPF_SHUTDOWN_SIGNAL_DELAY
#define TPF_SHUTDOWN_SIGNAL_DELAY 2
#endif

/* seconds to delay after closing the port as part of shutdown */
#ifndef TPF_SHUTDOWN_CLOSING_DELAY
#define TPF_SHUTDOWN_CLOSING_DELAY 3
#endif

#ifndef AP_OS_RECLAIM_LOOP_ADJUSTMENTS
/* expedite shutdown/restart in http_main.c's reclaim_child_processes
   function by skipping some of the loop iterations                  */
#define AP_OS_RECLAIM_LOOP_ADJUSTMENTS                                \
        if (tries == 4) {                                             \
           tries += 1; /* skip try #5 */                              \
        } else {                                                      \
           if (tries == 8) {                                          \
              tries += 3; /* skip try #9, #10, & #11 */               \
           }                                                          \
        }
#endif /* AP_OS_RECLAIM_LOOP_ADJUSTMENTS */

enum FILE_TYPE { PIPE_OUT = 1, PIPE_IN, PIPE_ERR };

typedef struct tpf_fd_item {
    int            fd;
    enum FILE_TYPE file_type;
    char           *fname;
}TPF_FD_ITEM;

typedef struct tpf_fd_list {
    void           *next_avail_byte;
    void           *last_avail_byte;
    unsigned int   nbr_of_items;
    TPF_FD_ITEM    first_item;
}TPF_FD_LIST;

typedef struct apache_input {
    void                *scoreboard_heap;   /* scoreboard system heap address */
    int                 slot;               /* child number */
    int                 generation;         /* server generation number */
    int                 listeners[10];
    time_t              restart_time;
    TPF_FD_LIST         *tpf_fds;           /* fd inheritance table ptr */
    void                *shm_static_ptr;    /* shm ptr for static pages */
} APACHE_TPF_INPUT;

typedef union ebw_area {
    INETD_SERVER_INPUT parent;
    APACHE_TPF_INPUT   child;
} EBW_AREA;
 
extern void *tpf_shm_static_ptr;            /* mod_tpf_shm_static */
#define TPF_SHM_STATIC_SIZE 200000
#define MMAP_SEGMENT_SIZE 32767             /* writev can handle 32767 */
#define _SYS_UIO_H_                         /* writev */

typedef struct tpf_fork_child {
     char  *filename;
     enum { FORK_NAME = 1, FORK_FILE = 2 } prog_type;
     void  *subprocess_env;
} TPF_FORK_CHILD;

int tpf_accept(int sockfd, struct sockaddr *peer, int *paddrlen);
extern int tpf_child;

struct server_rec;
pid_t os_fork(struct server_rec *s, int slot);
void ap_tpf_zinet_checks(int standalone,
                         const char *servername,
                         struct server_rec *s);
int os_check_server(char *server);
void show_os_specific_compile_settings(void);
char *getpass(const char *prompt);
int killpg(pid_t pgrp, int sig);
extern char *ap_server_argv0;
#include <signal.h>
#if defined(TPF41) && !defined(SIGPIPE)
#define SIGPIPE 14
#endif
#if defined(TPF41) && defined(NSIG)
#undef NSIG
#endif
void ap_tpf_save_argv(int argc, char **argv);
int tpf_select(int maxfds, fd_set *reads, fd_set *writes, fd_set *excepts,
               struct timeval *tv);
void os_tpf_child(APACHE_TPF_INPUT *input_parms);
#if defined(TPF64BIT) || defined(__PIPE_)
static void *ap_tpf_get_shared_mem(size_t size);
#endif

/* various #defines for ServerType/ZINET model checks: */

#define TPF_SERVERTYPE_MSG \
        "ServerType inetd is not supported on TPF" \
        " -- Apache startup aborted"

#ifdef INETD_IDCF_MODEL_DAEMON
#define TPF_STANDALONE_CONFLICT_MSG \
        "ServerType standalone requires ZINET model DAEMON or NOLISTEN" \
        " -- Apache startup aborted"
#define TPF_NOLISTEN_WARNING \
        "ZINET model DAEMON is preferred over model NOLISTEN"
#else
#define INETD_IDCF_MODEL_DAEMON -1
#define TPF_STANDALONE_CONFLICT_MSG \
        "ServerType standalone requires ZINET model NOLISTEN" \
        " -- Apache startup aborted"
#endif

#define TPF_UNABLE_TO_DETERMINE_ZINET_MODEL \
        "Unable to determine ZINET model: inetd_getServer(\"%s\") " \
        "call failed -- Apache startup aborted"

#endif /*! APACHE_OS_H*/
