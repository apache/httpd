/*
** File locking
**
** Snarfed from mod_rewrite.c. Munged up for our use.
*/

#include "ap_config.h"

    /* The locking support:
     * Try to determine whether we should use fcntl() or flock().
     * Would be better ap_config.h could provide this... :-(
     * Small monkey business to ensure that fcntl is preferred,
     * unless we specified USE_FLOCK_SERIALIZED_ACCEPT during compile.
     */
#if defined(HAVE_FCNTL_SERIALIZED_ACCEPT) && !defined(USE_FLOCK_SERIALIZED_ACCEPT)
#define USE_FCNTL 1
#include <fcntl.h>
#elif defined(HAVE_FLOCK_SERIALIZED_ACCEPT)
#define USE_FLOCK 1
#include <sys/file.h>
#endif
#if !defined(USE_FCNTL) && !defined(USE_FLOCK)
#define USE_FLOCK 1
#if !defined(MPE) && !defined(WIN32) && !defined(NETWARE)
#include <sys/file.h>
#endif
#ifndef LOCK_UN
#undef USE_FLOCK
#define USE_FCNTL 1
#include <fcntl.h>
#endif
#endif
#ifdef AIX
#undef USE_FLOCK
#define USE_FCNTL 1
#include <fcntl.h>
#endif
#ifdef WIN32
#undef USE_FCNTL
#define USE_LOCKING
#include <sys/locking.h>
#endif
#ifdef NETWARE
#undef USE_FCNTL
#define USE_SEM_LOCKING
#include <nwsemaph.h>
LONG locking_sem = 0;
#endif


#ifdef USE_FCNTL
/* ugly interface requires this structure to be "live" for a while */
static struct flock   lock_it;
static struct flock unlock_it;
#endif

/* NOTE: this function blocks until it acquires the lock */
int sdbm_fd_lock(int fd, int readonly)
{
    int rc;

#ifdef USE_FCNTL
    lock_it.l_whence = SEEK_SET; /* from current point */
    lock_it.l_start  = 0;        /* -"- */
    lock_it.l_len    = 0;        /* until end of file */
    lock_it.l_type   = readonly ? F_RDLCK : F_WRLCK;  /* set lock type */
    lock_it.l_pid    = 0;        /* pid not actually interesting */

    while (   ((rc = fcntl(fd, F_SETLKW, &lock_it)) < 0)
              && (errno == EINTR)                               ) {
        continue;
    }
#endif
#ifdef USE_FLOCK
    while (   ((rc = flock(fd, readonly ? LOCK_SH : LOCK_EX)) < 0)
              && (errno == EINTR)               ) {
        continue;
    }
#endif
#ifdef USE_LOCKING
    /* ### this doesn't allow simultaneous reads! */
    /* ### this doesn't block forever */
    /* Lock the first byte */
    lseek(fd, 0, SEEK_SET);
    rc = _locking(fd, _LK_LOCK, 1);
#endif
#ifdef USE_SEM_LOCKING
	if ((locking_sem != 0) && (TimedWaitOnLocalSemaphore (locking_sem, 10000) != 0))
		rc = -1;
	else
		rc = 1;
#endif

    return rc;
}

int sdbm_fd_unlock(int fd)
{
    int rc;

#ifdef USE_FCNTL
    unlock_it.l_whence = SEEK_SET; /* from current point */
    unlock_it.l_start  = 0;        /* -"- */
    unlock_it.l_len    = 0;        /* until end of file */
    unlock_it.l_type   = F_UNLCK;  /* unlock */
    unlock_it.l_pid    = 0;        /* pid not actually interesting */

    rc = fcntl(fd, F_SETLKW, &unlock_it);
#endif
#ifdef USE_FLOCK
    rc = flock(fd, LOCK_UN);
#endif
#ifdef USE_LOCKING
    lseek(fd, 0, SEEK_SET);
    rc = _locking(fd, _LK_UNLCK, 1);
#endif
#ifdef USE_SEM_LOCKING
	if (locking_sem)
		SignalLocalSemaphore (locking_sem);
	rc = 1;
#endif

    return rc;
}
