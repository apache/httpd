#ifndef APACHE_OS_H
#define APACHE_OS_H

#define PLATFORM "TPF"

#ifdef errno
#undef errno
#endif

/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */

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

/* Sorry if this is ugly, but the include order doesn't allow me
 * to use request_rec here... */
struct request_rec;
extern int ap_checkconv(struct request_rec *r);
 
#include <strings.h>
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
#define  FD_ZERO(p)   memset((char *)(p), 0, sizeof(*(p)))
#endif
    
#ifdef FD_SET
#undef FD_SET
#define FD_SET(n, p) (0)
#endif

#define  RESOURCE_KEY ((void*) 0xC1C2C1C3)

/* TPF doesn't have, or need, tzset (it is used in mod_expires.c) */
#define tzset()

#include <i$netd.h>
struct apache_input {
    INETD_SERVER_INPUT  inetd_server;
    void                *scoreboard_heap;   /* scoreboard system heap address */
    int                 scoreboard_fd;      /* scoreboard file descriptor */
    int                 slot;               /* child number */
    int                 generation;         /* server generation number */
    int                 listeners[10];
    time_t              restart_time;
};

typedef struct apache_input APACHE_TPF_INPUT;

typedef struct tpf_fork_child {
     char  *filename;
     enum { FORK_NAME = 1, FORK_FILE = 2 } prog_type;
     void  *subprocess_env;
}TPF_FORK_CHILD;

int tpf_accept(int sockfd, struct sockaddr *peer, int *paddrlen);
extern int tpf_child;

struct server_rec;
pid_t os_fork(struct server_rec *s, int slot);
int os_check_server(char *server);
char *getpass(const char *prompt);
extern char *ap_server_argv0;
extern int scoreboard_fd;
#include <signal.h>
#ifndef SIGPIPE
#define SIGPIPE 14
#endif
#ifdef NSIG
#undef NSIG
#endif
#endif /*! APACHE_OS_H*/
