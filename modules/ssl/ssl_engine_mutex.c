/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_mutex.c
**  Semaphore for Mutual Exclusion
*/

/* ====================================================================
 * Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * 4. The names "mod_ssl" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    rse@engelschall.com.
 *
 * 5. Products derived from this software may not be called "mod_ssl"
 *    nor may "mod_ssl" appear in their names without prior
 *    written permission of Ralf S. Engelschall.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
                             /* ``Real programmers confuse
                                  Christmas and Halloween
                                  because DEC 25 = OCT 31.''
                                             -- Unknown     */
#include "mod_ssl.h"


/*  _________________________________________________________________
**
**  Mutex Support (Common)
**  _________________________________________________________________
*/

void ssl_mutex_init(server_rec *s, pool *p)
{
    SSLModConfigRec *mc = myModConfig();

    if (mc->nMutexMode == SSL_MUTEXMODE_FILE)
        ssl_mutex_file_create(s, p);
    else if (mc->nMutexMode == SSL_MUTEXMODE_SEM)
        ssl_mutex_sem_create(s, p);
    return;
}

void ssl_mutex_reinit(server_rec *s, pool *p)
{
    SSLModConfigRec *mc = myModConfig();

    if (mc->nMutexMode == SSL_MUTEXMODE_FILE)
        ssl_mutex_file_open(s, p);
    else if (mc->nMutexMode == SSL_MUTEXMODE_SEM)
        ssl_mutex_sem_open(s, p);
    return;
}

void ssl_mutex_on(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig();
    BOOL ok = TRUE;

    if (mc->nMutexMode == SSL_MUTEXMODE_FILE)
        ok = ssl_mutex_file_acquire();
    else if (mc->nMutexMode == SSL_MUTEXMODE_SEM)
        ok = ssl_mutex_sem_acquire();
    if (!ok)
        ssl_log(s, SSL_LOG_WARN, "Failed to acquire global mutex lock");
    return;
}

void ssl_mutex_off(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig();
    BOOL ok = TRUE;

    if (mc->nMutexMode == SSL_MUTEXMODE_FILE)
        ok = ssl_mutex_file_release();
    else if (mc->nMutexMode == SSL_MUTEXMODE_SEM)
        ok = ssl_mutex_sem_release();
    if (!ok)
        ssl_log(s, SSL_LOG_WARN, "Failed to release global mutex lock");
    return;
}

void ssl_mutex_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig();

    if (mc->nMutexMode == SSL_MUTEXMODE_FILE)
        ssl_mutex_file_remove(s);
    else if (mc->nMutexMode == SSL_MUTEXMODE_SEM)
        ssl_mutex_sem_remove(s);
    return;
}


/*  _________________________________________________________________
**
**  Mutex Support (Lockfile)
**  _________________________________________________________________
*/

void ssl_mutex_file_create(server_rec *s, pool *p)
{
#ifndef WIN32
    SSLModConfigRec *mc = myModConfig();

    /* create the lockfile */
    unlink(mc->szMutexFile);
    if ((mc->nMutexFD = ap_popenf(p, mc->szMutexFile,
                                  O_WRONLY|O_CREAT, SSL_MUTEX_LOCK_MODE)) < 0) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Parent process could not create SSLMutex lockfile %s",
                mc->szMutexFile);
        ssl_die();
    }
    ap_pclosef(p, mc->nMutexFD);

    /* make sure the childs have access to this file */
#ifndef OS2
    if (geteuid() == 0 /* is superuser */)
        chown(mc->szMutexFile, ap_user_id, -1 /* no gid change */);
#endif

    /* open the lockfile for real */
    if ((mc->nMutexFD = ap_popenf(p, mc->szMutexFile,
                                  O_WRONLY, SSL_MUTEX_LOCK_MODE)) < 0) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Parent could not open SSLMutex lockfile %s",
                mc->szMutexFile);
        ssl_die();
    }
#endif
    return;
}

void ssl_mutex_file_open(server_rec *s, pool *p)
{
#ifndef WIN32
    SSLModConfigRec *mc = myModConfig();

    /* open the lockfile (once per child) to get a unique fd */
    if ((mc->nMutexFD = ap_popenf(p, mc->szMutexFile,
                                  O_WRONLY, SSL_MUTEX_LOCK_MODE)) < 0) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Child could not open SSLMutex lockfile %s",
                mc->szMutexFile);
        ssl_die();
    }
#endif
    return;
}

void ssl_mutex_file_remove(void *data)
{
#ifndef WIN32
    SSLModConfigRec *mc = myModConfig();

    /* remove the mutex lockfile */
    unlink(mc->szMutexFile);
#endif
    return;
}

#ifndef WIN32
#ifdef SSL_USE_FCNTL
static struct flock   lock_it;
static struct flock unlock_it;
#endif
#endif

BOOL ssl_mutex_file_acquire(void)
{
    int rc = -1;
#ifndef WIN32
    SSLModConfigRec *mc = myModConfig();

#ifdef SSL_USE_FCNTL
    lock_it.l_whence = SEEK_SET; /* from current point */
    lock_it.l_start  = 0;        /* -"- */
    lock_it.l_len    = 0;        /* until end of file */
    lock_it.l_type   = F_WRLCK;  /* set exclusive/write lock */
    lock_it.l_pid    = 0;        /* pid not actually interesting */

    while (   ((rc = fcntl(mc->nMutexFD, F_SETLKW, &lock_it)) < 0)
           && (errno == EINTR)                                    ) 
        ;
#endif
#ifdef SSL_USE_FLOCK
    while (   ((rc = flock(mc->nMutexFD, LOCK_EX)) < 0)
           && (errno == EINTR)                         )
        ;
#endif
#endif

    if (rc < 0)
        return FALSE;
    else
        return TRUE;
}

BOOL ssl_mutex_file_release(void)
{
    int rc = -1;
#ifndef WIN32
    SSLModConfigRec *mc = myModConfig();

#ifdef SSL_USE_FCNTL
    unlock_it.l_whence = SEEK_SET; /* from current point */
    unlock_it.l_start  = 0;        /* -"- */
    unlock_it.l_len    = 0;        /* until end of file */
    unlock_it.l_type   = F_UNLCK;  /* unlock */
    unlock_it.l_pid    = 0;        /* pid not actually interesting */

    while (   (rc = fcntl(mc->nMutexFD, F_SETLKW, &unlock_it)) < 0
           && (errno == EINTR)                                    )
        ;
#endif
#ifdef SSL_USE_FLOCK
    while (   (rc = flock(mc->nMutexFD, LOCK_UN)) < 0
           && (errno == EINTR)                       ) 
        ;
#endif
#endif

    if (rc < 0)
        return FALSE;
    else
        return TRUE;
}

/*  _________________________________________________________________
**
**  Mutex Support (Process Semaphore)
**  _________________________________________________________________
*/

void ssl_mutex_sem_create(server_rec *s, pool *p)
{
#ifdef SSL_CAN_USE_SEM
    int semid;
    SSLModConfigRec *mc = myModConfig();
#ifdef SSL_HAVE_IPCSEM
    union ssl_ipc_semun semctlarg;
    struct semid_ds semctlbuf;
#endif

#ifdef SSL_HAVE_IPCSEM
    semid = semget(IPC_PRIVATE, 1, IPC_CREAT|IPC_EXCL|S_IRUSR|S_IWUSR);
    if (semid == -1 && errno == EEXIST)
        semid = semget(IPC_PRIVATE, 1, IPC_EXCL|S_IRUSR|S_IWUSR);
    if (semid == -1) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Parent process could not create private SSLMutex semaphore");
        ssl_die();
    }
    semctlarg.val = 0;
    if (semctl(semid, 0, SETVAL, semctlarg) < 0) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Parent process could not initialize SSLMutex semaphore value");
        ssl_die();
    }
    semctlbuf.sem_perm.uid  = ap_user_id;
    semctlbuf.sem_perm.gid  = ap_group_id;
    semctlbuf.sem_perm.mode = 0660;
    semctlarg.buf = &semctlbuf;
    if (semctl(semid, 0, IPC_SET, semctlarg) < 0) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Parent process could not set permissions for SSLMutex semaphore");
        ssl_die();
    }
#endif
#ifdef SSL_HAVE_W32SEM
    semid = (int)ap_create_mutex("mod_ssl_mutex");
#endif
    mc->nMutexSEMID = semid;
#endif
    return;
}

void ssl_mutex_sem_open(server_rec *s, pool *p)
{
#ifdef SSL_CAN_USE_SEM
#ifdef SSL_HAVE_W32SEM
    SSLModConfigRec *mc = myModConfig();

    mc->nMutexSEMID = (int)ap_open_mutex("mod_ssl_mutex");
#endif
#endif
    return;
}

void ssl_mutex_sem_remove(void *data)
{
#ifdef SSL_CAN_USE_SEM
    SSLModConfigRec *mc = myModConfig();

#ifdef SSL_HAVE_IPCSEM
    semctl(mc->nMutexSEMID, 0, IPC_RMID, 0);
#endif
#ifdef SSL_HAVE_W32SEM
    ap_destroy_mutex((mutex *)mc->nMutexSEMID);
#endif
#endif
    return;
}

BOOL ssl_mutex_sem_acquire(void)
{
    int rc = 0;
#ifdef SSL_CAN_USE_SEM
    SSLModConfigRec *mc = myModConfig();

#ifdef SSL_HAVE_IPCSEM
    struct sembuf sb[] = {
        { 0, 0, 0 },       /* wait for semaphore */
        { 0, 1, SEM_UNDO } /* increment semaphore */
    };

    while (   (rc = semop(mc->nMutexSEMID, sb, 2)) < 0
           && (errno == EINTR)                        ) 
        ;
#endif
#ifdef SSL_HAVE_W32SEM
    rc = ap_acquire_mutex((mutex *)mc->nMutexSEMID);
#endif
#endif
    if (rc != 0)
        return FALSE;
    else
        return TRUE;
}

BOOL ssl_mutex_sem_release(void)
{
    int rc = 0;
#ifdef SSL_CAN_USE_SEM
    SSLModConfigRec *mc = myModConfig();

#ifdef SSL_HAVE_IPCSEM
    struct sembuf sb[] = {
        { 0, -1, SEM_UNDO } /* decrements semaphore */
    };

    while (   (rc = semop(mc->nMutexSEMID, sb, 1)) < 0 
           && (errno == EINTR)                        ) 
        ;
#endif
#ifdef SSL_HAVE_W32SEM
    rc = ap_release_mutex((mutex *)mc->nMutexSEMID);
#endif
#endif
    if (rc != 0)
        return FALSE;
    else
        return TRUE;
}

