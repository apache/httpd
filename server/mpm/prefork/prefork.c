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

/*
 * httpd.c: simple http daemon for answering WWW file requests
 *
 * 
 * 03-21-93  Rob McCool wrote original code (up to NCSA HTTPd 1.3)
 * 
 * 03-06-95  blong
 *  changed server number for child-alone processes to 0 and changed name
 *   of processes
 *
 * 03-10-95  blong
 *      Added numerous speed hacks proposed by Robert S. Thau (rst@ai.mit.edu) 
 *      including set group before fork, and call gettime before to fork
 *      to set up libraries.
 *
 * 04-14-95  rst / rh
 *      Brandon's code snarfed from NCSA 1.4, but tinkered to work with the
 *      Apache server, and also to have child processes do accept() directly.
 *
 * April-July '95 rst
 *      Extensive rework for Apache.
 */

/* TODO: this is a cobbled together prefork MPM example... it should mostly
 * TODO: behave like apache-1.3... here's a short list of things I think
 * TODO: need cleaning up still:
 * TODO: - use ralf's mm stuff for the shared mem and mutexes
 * TODO: - clean up scoreboard stuff when we figure out how to do it in 2.0
 */

#define CORE_PRIVATE

#include "apr_portable.h"
#include "httpd.h"
#include "mpm_default.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"		/* for get_remote_host */
#include "http_connection.h"
#include "scoreboard.h"
#include "ap_mpm.h"
#include "unixd.h"
#include "iol_socket.h"
#include "ap_listen.h"
#ifdef USE_SHMGET_SCOREBOARD
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#endif

#ifdef HAVE_BSTRING_H
#include <bstring.h>		/* for IRIX, FD_SET calls bzero() */
#endif

/* config globals */

static int ap_max_requests_per_child=0;
static char *ap_pid_fname=NULL;
static char *ap_scoreboard_fname=NULL;
static char *ap_lock_fname;
static char *ap_server_argv0=NULL;
static int ap_daemons_to_start=0;
static int ap_daemons_min_free=0;
static int ap_daemons_max_free=0;
static int ap_daemons_limit=0;
static time_t ap_restart_time=0;
static int ap_extended_status = 0;

/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with MaxClients changes across SIGUSR1 restarts.  We use this
 * value to optimize routines that have to scan the entire scoreboard.
 */
static int max_daemons_limit = -1;

static char ap_coredump_dir[MAX_STRING_LEN];

/* *Non*-shared http_main globals... */

static server_rec *server_conf;
static ap_socket_t *sd;
static fd_set listenfds;
static int listenmaxfd;

/* one_process --- debugging mode variable; can be set from the command line
 * with the -X flag.  If set, this gets you the child_main loop running
 * in the process which originally started up (no detach, no make_child),
 * which is a pretty nice debugging environment.  (You'll get a SIGHUP
 * early in standalone_main; just continue through.  This is the server
 * trying to kill off any child processes which it might have lying
 * around --- Apache doesn't keep track of their pids, it just sends
 * SIGHUP to the process group, ignoring it in the root process.
 * Continue through and you'll be fine.).
 */

static int one_process = 0;

#ifdef HAS_OTHER_CHILD
/* used to maintain list of children which aren't part of the scoreboard */
typedef struct other_child_rec other_child_rec;
struct other_child_rec {
    other_child_rec *next;
    int pid;
    void (*maintenance) (int, void *, ap_wait_t);
    void *data;
    int write_fd;
};
static other_child_rec *other_children;
#endif

static ap_context_t *pconf;		/* Pool for config stuff */
static ap_context_t *pchild;		/* Pool for httpd child stuff */

static int my_pid;	/* it seems silly to call getpid all the time */
#ifndef MULTITHREAD
static int my_child_num;
#endif

#ifdef TPF
int tpf_child = 0;
char tpf_server_name[INETD_SERVNAME_LENGTH+1];
#endif /* TPF */

static scoreboard *ap_scoreboard_image = NULL;

#ifdef GPROF
/* 
 * change directory for gprof to plop the gmon.out file
 * configure in httpd.conf:
 * GprofDir logs/   -> $ServerRoot/logs/gmon.out
 * GprofDir logs/%  -> $ServerRoot/logs/gprof.$pid/gmon.out
 */
static void chdir_for_gprof(void)
{
    core_server_config *sconf = 
	ap_get_module_config(server_conf->module_config, &core_module);    
    char *dir = sconf->gprof_dir;

    if(dir) {
	char buf[512];
	int len = strlen(sconf->gprof_dir) - 1;
	if(*(dir + len) == '%') {
	    dir[len] = '\0';
	    ap_snprintf(buf, sizeof(buf), "%sgprof.%d", dir, (int)getpid());
	} 
	dir = ap_server_root_relative(pconf, buf[0] ? buf : dir);
	if(mkdir(dir, 0755) < 0 && errno != EEXIST) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
			 "gprof: error creating directory %s", dir);
	}
    }
    else {
	dir = ap_server_root_relative(pconf, "logs");
    }

    chdir(dir);
}
#else
#define chdir_for_gprof()
#endif

/* a clean exit from a child with proper cleanup */
static void clean_child_exit(int code) __attribute__ ((noreturn));
static void clean_child_exit(int code)
{
    if (pchild) {
	ap_destroy_pool(pchild);
    }
    chdir_for_gprof();
    exit(code);
}

#if defined(USE_FCNTL_SERIALIZED_ACCEPT) || defined(USE_FLOCK_SERIALIZED_ACCEPT)
static void expand_lock_fname(ap_context_t *p)
{
    /* XXXX possibly bogus cast */
    ap_lock_fname = ap_psprintf(p, "%s.%lu",
	ap_server_root_relative(p, ap_lock_fname), (unsigned long)getpid());
}
#endif

#if defined (USE_USLOCK_SERIALIZED_ACCEPT)

#include <ulocks.h>

static ulock_t uslock = NULL;

#define accept_mutex_child_init(x)

static void accept_mutex_init(ap_context_t *p)
{
    ptrdiff_t old;
    usptr_t *us;


    /* default is 8, allocate enough for all the children plus the parent */
    if ((old = usconfig(CONF_INITUSERS, HARD_SERVER_LIMIT + 1)) == -1) {
	perror("usconfig(CONF_INITUSERS)");
	exit(-1);
    }

    if ((old = usconfig(CONF_LOCKTYPE, US_NODEBUG)) == -1) {
	perror("usconfig(CONF_LOCKTYPE)");
	exit(-1);
    }
    if ((old = usconfig(CONF_ARENATYPE, US_SHAREDONLY)) == -1) {
	perror("usconfig(CONF_ARENATYPE)");
	exit(-1);
    }
    if ((us = usinit("/dev/zero")) == NULL) {
	perror("usinit");
	exit(-1);
    }

    if ((uslock = usnewlock(us)) == NULL) {
	perror("usnewlock");
	exit(-1);
    }
}

static void accept_mutex_on(void)
{
    switch (ussetlock(uslock)) {
    case 1:
	/* got lock */
	break;
    case 0:
	fprintf(stderr, "didn't get lock\n");
	clean_child_exit(APEXIT_CHILDFATAL);
    case -1:
	perror("ussetlock");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}

static void accept_mutex_off(void)
{
    if (usunsetlock(uslock) == -1) {
	perror("usunsetlock");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}

#elif defined (USE_PTHREAD_SERIALIZED_ACCEPT)

/* This code probably only works on Solaris ... but it works really fast
 * on Solaris.  Note that pthread mutexes are *NOT* released when a task
 * dies ... the task has to free it itself.  So we block signals and
 * try to be nice about releasing the mutex.
 */

#include <pthread.h>

static pthread_mutex_t *accept_mutex = (void *)(caddr_t) -1;
static int have_accept_mutex;
static sigset_t accept_block_mask;
static sigset_t accept_previous_mask;

static void accept_mutex_child_cleanup(void *foo)
{
    if (accept_mutex != (void *)(caddr_t)-1
	&& have_accept_mutex) {
	pthread_mutex_unlock(accept_mutex);
    }
}

static void accept_mutex_child_init(ap_context_t *p)
{
    ap_register_cleanup(p, NULL, accept_mutex_child_cleanup, ap_null_cleanup);
}

static void accept_mutex_cleanup(void *foo)
{
    if (accept_mutex != (void *)(caddr_t)-1
	&& munmap((caddr_t) accept_mutex, sizeof(*accept_mutex))) {
	perror("munmap");
    }
    accept_mutex = (void *)(caddr_t)-1;
}

static void accept_mutex_init(ap_context_t *p)
{
    pthread_mutexattr_t mattr;
    int fd;

    fd = open("/dev/zero", O_RDWR);
    if (fd == -1) {
	perror("open(/dev/zero)");
	exit(APEXIT_INIT);
    }
    accept_mutex = (pthread_mutex_t *) mmap((caddr_t) 0, sizeof(*accept_mutex),
				 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (accept_mutex == (void *) (caddr_t) - 1) {
	perror("mmap");
	exit(APEXIT_INIT);
    }
    close(fd);
    if ((errno = pthread_mutexattr_init(&mattr))) {
	perror("pthread_mutexattr_init");
	exit(APEXIT_INIT);
    }
    if ((errno = pthread_mutexattr_setpshared(&mattr,
						PTHREAD_PROCESS_SHARED))) {
	perror("pthread_mutexattr_setpshared");
	exit(APEXIT_INIT);
    }
    if ((errno = pthread_mutex_init(accept_mutex, &mattr))) {
	perror("pthread_mutex_init");
	exit(APEXIT_INIT);
    }
    sigfillset(&accept_block_mask);
    sigdelset(&accept_block_mask, SIGHUP);
    sigdelset(&accept_block_mask, SIGTERM);
    sigdelset(&accept_block_mask, SIGUSR1);
    ap_register_cleanup(p, NULL, accept_mutex_cleanup, ap_null_cleanup);
}

static void accept_mutex_on(void)
{
    int err;

    if (sigprocmask(SIG_BLOCK, &accept_block_mask, &accept_previous_mask)) {
	perror("sigprocmask(SIG_BLOCK)");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
    if ((err = pthread_mutex_lock(accept_mutex))) {
	errno = err;
	perror("pthread_mutex_lock");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
    have_accept_mutex = 1;
}

static void accept_mutex_off(void)
{
    int err;

    if ((err = pthread_mutex_unlock(accept_mutex))) {
	errno = err;
	perror("pthread_mutex_unlock");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
    /* There is a slight race condition right here... if we were to die right
     * now, we'd do another pthread_mutex_unlock.  Now, doing that would let
     * another process into the mutex.  pthread mutexes are designed to be
     * fast, as such they don't have protection for things like testing if the
     * thread owning a mutex is actually unlocking it (or even any way of
     * testing who owns the mutex).
     *
     * If we were to unset have_accept_mutex prior to releasing the mutex
     * then the race could result in the server unable to serve hits.  Doing
     * it this way means that the server can continue, but an additional
     * child might be in the critical section ... at least it's still serving
     * hits.
     */
    have_accept_mutex = 0;
    if (sigprocmask(SIG_SETMASK, &accept_previous_mask, NULL)) {
	perror("sigprocmask(SIG_SETMASK)");
	clean_child_exit(1);
    }
}

#elif defined (USE_SYSVSEM_SERIALIZED_ACCEPT)

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#ifdef NEED_UNION_SEMUN
/* it makes no sense, but this isn't defined on solaris */
union semun {
    long val;
    struct semid_ds *buf;
    ushort *array;
};

#endif

static int sem_id = -1;
static struct sembuf op_on;
static struct sembuf op_off;

/* We get a random semaphore ... the lame sysv semaphore interface
 * means we have to be sure to clean this up or else we'll leak
 * semaphores.
 */
static void accept_mutex_cleanup(void *foo)
{
    union semun ick;

    if (sem_id < 0)
	return;
    /* this is ignored anyhow */
    ick.val = 0;
    semctl(sem_id, 0, IPC_RMID, ick);
}

#define accept_mutex_child_init(x)

static void accept_mutex_init(ap_context_t *p)
{
    union semun ick;
    struct semid_ds buf;

    /* acquire the semaphore */
    sem_id = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    if (sem_id < 0) {
	perror("semget");
	exit(APEXIT_INIT);
    }
    ick.val = 1;
    if (semctl(sem_id, 0, SETVAL, ick) < 0) {
	perror("semctl(SETVAL)");
	exit(APEXIT_INIT);
    }
    if (!getuid()) {
	/* restrict it to use only by the appropriate user_id ... not that this
	 * stops CGIs from acquiring it and dinking around with it.
	 */
	buf.sem_perm.uid = unixd_config.user_id;
	buf.sem_perm.gid = unixd_config.group_id;
	buf.sem_perm.mode = 0600;
	ick.buf = &buf;
	if (semctl(sem_id, 0, IPC_SET, ick) < 0) {
	    perror("semctl(IPC_SET)");
	    exit(APEXIT_INIT);
	}
    }
    ap_register_cleanup(p, NULL, accept_mutex_cleanup, ap_null_cleanup);

    /* pre ap_context_t nitialize these */
    op_on.sem_num = 0;
    op_on.sem_op = -1;
    op_on.sem_flg = SEM_UNDO;
    op_off.sem_num = 0;
    op_off.sem_op = 1;
    op_off.sem_flg = SEM_UNDO;
}

static void accept_mutex_on(void)
{
    while (semop(sem_id, &op_on, 1) < 0) {
	if (errno != EINTR) {
	    perror("accept_mutex_on");
	    clean_child_exit(APEXIT_CHILDFATAL);
	}
    }
}

static void accept_mutex_off(void)
{
    while (semop(sem_id, &op_off, 1) < 0) {
	if (errno != EINTR) {
	    perror("accept_mutex_off");
	    clean_child_exit(APEXIT_CHILDFATAL);
	}
    }
}

#elif defined(USE_FCNTL_SERIALIZED_ACCEPT)
static struct flock lock_it;
static struct flock unlock_it;

static int lock_fd = -1;

#define accept_mutex_child_init(x)

/*
 * Initialize mutex lock.
 * Must be safe to call this on a restart.
 */
static void accept_mutex_init(ap_context_t *p)
{
    ap_file_t *tempfile;
    lock_it.l_whence = SEEK_SET;	/* from current point */
    lock_it.l_start = 0;		/* -"- */
    lock_it.l_len = 0;			/* until end of file */
    lock_it.l_type = F_WRLCK;		/* set exclusive/write lock */
    lock_it.l_pid = 0;			/* pid not actually interesting */
    unlock_it.l_whence = SEEK_SET;	/* from current point */
    unlock_it.l_start = 0;		/* -"- */
    unlock_it.l_len = 0;		/* until end of file */
    unlock_it.l_type = F_UNLCK;		/* set exclusive/write lock */
    unlock_it.l_pid = 0;		/* pid not actually interesting */

    expand_lock_fname(p);
    ap_open(p, ap_lock_fname, APR_CREATE | APR_WRITE | APR_EXCL,
            APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD, &tempfile);
    ap_get_os_file(tempfile, &lock_fd);
    if (lock_fd == -1) {
	perror("open");
	fprintf(stderr, "Cannot open lock file: %s\n", ap_lock_fname);
	exit(APEXIT_INIT);
    }
    unlink(ap_lock_fname);
}

static void accept_mutex_on(void)
{
    int ret;

    while ((ret = fcntl(lock_fd, F_SETLKW, &lock_it)) < 0 && errno == EINTR) {
	/* nop */
    }

    if (ret < 0) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf,
		    "fcntl: F_SETLKW: Error getting accept lock, exiting!  "
		    "Perhaps you need to use the LockFile directive to place "
		    "your lock file on a local disk!");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}

static void accept_mutex_off(void)
{
    int ret;

    while ((ret = fcntl(lock_fd, F_SETLKW, &unlock_it)) < 0 && errno == EINTR) {
	/* nop */
    }
    if (ret < 0) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf,
		    "fcntl: F_SETLKW: Error freeing accept lock, exiting!  "
		    "Perhaps you need to use the LockFile directive to place "
		    "your lock file on a local disk!");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}

#elif defined(USE_FLOCK_SERIALIZED_ACCEPT)

static int lock_fd = -1;

static void accept_mutex_cleanup(void *foo)
{
    unlink(ap_lock_fname);
}

/*
 * Initialize mutex lock.
 * Done by each child at it's birth
 */
static void accept_mutex_child_init(ap_context_t *p)
{

    lock_fd = ap_popenf(p, ap_lock_fname, O_WRONLY, 0600);
    if (lock_fd == -1) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf,
		    "Child cannot open lock file: %s", ap_lock_fname);
	clean_child_exit(APEXIT_CHILDINIT);
    }
}

/*
 * Initialize mutex lock.
 * Must be safe to call this on a restart.
 */
static void accept_mutex_init(ap_context_t *p)
{
    expand_lock_fname(p);
    unlink(ap_lock_fname);
    lock_fd = ap_popenf(p, ap_lock_fname, O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (lock_fd == -1) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf,
		    "Parent cannot open lock file: %s", ap_lock_fname);
	exit(APEXIT_INIT);
    }
    ap_register_cleanup(p, NULL, accept_mutex_cleanup, ap_null_cleanup);
}

static void accept_mutex_on(void)
{
    int ret;

    while ((ret = flock(lock_fd, LOCK_EX)) < 0 && errno == EINTR)
	continue;

    if (ret < 0) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf,
		    "flock: LOCK_EX: Error getting accept lock. Exiting!");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}

static void accept_mutex_off(void)
{
    if (flock(lock_fd, LOCK_UN) < 0) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf,
		    "flock: LOCK_UN: Error freeing accept lock. Exiting!");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}

#elif defined(USE_OS2SEM_SERIALIZED_ACCEPT)

static HMTX lock_sem = -1;

static void accept_mutex_cleanup(void *foo)
{
    DosReleaseMutexSem(lock_sem);
    DosCloseMutexSem(lock_sem);
}

/*
 * Initialize mutex lock.
 * Done by each child at it's birth
 */
static void accept_mutex_child_init(ap_context_t *p)
{
    int rc = DosOpenMutexSem(NULL, &lock_sem);

    if (rc != 0) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, server_conf,
		    "Child cannot open lock semaphore, rc=%d", rc);
	clean_child_exit(APEXIT_CHILDINIT);
    } else {
        ap_register_cleanup(p, NULL, accept_mutex_cleanup, ap_null_cleanup);
    }
}

/*
 * Initialize mutex lock.
 * Must be safe to call this on a restart.
 */
static void accept_mutex_init(ap_context_t *p)
{
    int rc = DosCreateMutexSem(NULL, &lock_sem, DC_SEM_SHARED, FALSE);

    if (rc != 0) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, server_conf,
		    "Parent cannot create lock semaphore, rc=%d", rc);
	exit(APEXIT_INIT);
    }

    ap_register_cleanup(p, NULL, accept_mutex_cleanup, ap_null_cleanup);
}

static void accept_mutex_on(void)
{
    int rc = DosRequestMutexSem(lock_sem, SEM_INDEFINITE_WAIT);

    if (rc != 0) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, server_conf,
		    "OS2SEM: Error %d getting accept lock. Exiting!", rc);
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}

static void accept_mutex_off(void)
{
    int rc = DosReleaseMutexSem(lock_sem);
    
    if (rc != 0) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, server_conf,
		    "OS2SEM: Error %d freeing accept lock. Exiting!", rc);
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}

#elif defined(USE_TPF_CORE_SERIALIZED_ACCEPT)

static int tpf_core_held;

static void accept_mutex_cleanup(void *foo)
{
    if(tpf_core_held)
        coruc(RESOURCE_KEY);
}

#define accept_mutex_init(x)

static void accept_mutex_child_init(ap_context_t *p)
{
    ap_register_cleanup(p, NULL, accept_mutex_cleanup, ap_null_cleanup);
    tpf_core_held = 0;
}

static void accept_mutex_on(void)
{
    corhc(RESOURCE_KEY);
    tpf_core_held = 1;
    ap_check_signals();
}

static void accept_mutex_off(void)
{
    coruc(RESOURCE_KEY);
    tpf_core_held = 0;
    ap_check_signals();
}

#else
/* Default --- no serialization.  Other methods *could* go here,
 * as #elifs...
 */
#if !defined(MULTITHREAD)
/* Multithreaded systems don't complete between processes for
 * the sockets. */
#define NO_SERIALIZED_ACCEPT
#define accept_mutex_child_init(x)
#define accept_mutex_init(x)
#define accept_mutex_on()
#define accept_mutex_off()
#endif
#endif

/* On some architectures it's safe to do unserialized accept()s in the single
 * Listen case.  But it's never safe to do it in the case where there's
 * multiple Listen statements.  Define SINGLE_LISTEN_UNSERIALIZED_ACCEPT
 * when it's safe in the single Listen case.
 */
#ifdef SINGLE_LISTEN_UNSERIALIZED_ACCEPT
#define SAFE_ACCEPT(stmt) do {if (ap_listeners->next) {stmt;}} while(0)
#else
#define SAFE_ACCEPT(stmt) do {stmt;} while(0)
#endif


/*****************************************************************
 * dealing with other children
 */

#ifdef HAS_OTHER_CHILD
API_EXPORT(void) ap_register_other_child(int pid,
		       void (*maintenance) (int reason, void *, ap_wait_t status),
			  void *data, int write_fd)
{
    other_child_rec *ocr;

    ocr = ap_palloc(pconf, sizeof(*ocr));
    ocr->pid = pid;
    ocr->maintenance = maintenance;
    ocr->data = data;
    ocr->write_fd = write_fd;
    ocr->next = other_children;
    other_children = ocr;
}

/* note that since this can be called by a maintenance function while we're
 * scanning the other_children list, all scanners should protect themself
 * by loading ocr->next before calling any maintenance function.
 */
API_EXPORT(void) ap_unregister_other_child(void *data)
{
    other_child_rec **pocr, *nocr;

    for (pocr = &other_children; *pocr; pocr = &(*pocr)->next) {
	if ((*pocr)->data == data) {
	    nocr = (*pocr)->next;
	    (*(*pocr)->maintenance) (OC_REASON_UNREGISTER, (*pocr)->data, -1);
	    *pocr = nocr;
	    /* XXX: um, well we've just wasted some space in pconf ? */
	    return;
	}
    }
}

/* test to ensure that the write_fds are all still writable, otherwise
 * invoke the maintenance functions as appropriate */
static void probe_writable_fds(void)
{
    fd_set writable_fds;
    int fd_max;
    other_child_rec *ocr, *nocr;
    struct timeval tv;
    int rc;

    if (other_children == NULL)
	return;

    fd_max = 0;
    FD_ZERO(&writable_fds);
    do {
	for (ocr = other_children; ocr; ocr = ocr->next) {
	    if (ocr->write_fd == -1)
		continue;
	    FD_SET(ocr->write_fd, &writable_fds);
	    if (ocr->write_fd > fd_max) {
		fd_max = ocr->write_fd;
	    }
	}
	if (fd_max == 0)
	    return;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	rc = ap_select(fd_max + 1, NULL, &writable_fds, NULL, &tv);
    } while (rc == -1 && errno == EINTR);

    if (rc == -1) {
	/* XXX: uhh this could be really bad, we could have a bad file
	 * descriptor due to a bug in one of the maintenance routines */
	ap_log_unixerr("probe_writable_fds", "select",
		    "could not probe writable fds", server_conf);
	return;
    }
    if (rc == 0)
	return;

    for (ocr = other_children; ocr; ocr = nocr) {
	nocr = ocr->next;
	if (ocr->write_fd == -1)
	    continue;
	if (FD_ISSET(ocr->write_fd, &writable_fds))
	    continue;
	(*ocr->maintenance) (OC_REASON_UNWRITABLE, ocr->data, -1);
    }
}

/* possibly reap an other_child, return 0 if yes, -1 if not */
static int reap_other_child(int pid, ap_wait_t status)
{
    other_child_rec *ocr, *nocr;

    for (ocr = other_children; ocr; ocr = nocr) {
	nocr = ocr->next;
	if (ocr->pid != pid)
	    continue;
	ocr->pid = -1;
	(*ocr->maintenance) (OC_REASON_DEATH, ocr->data, status);
	return 0;
    }
    return -1;
}
#endif

/*****************************************************************
 *
 * Dealing with the scoreboard... a lot of these variables are global
 * only to avoid getting clobbered by the longjmp() that happens when
 * a hard timeout expires...
 *
 * We begin with routines which deal with the file itself... 
 */

#if defined(USE_OS2_SCOREBOARD)

/* The next two routines are used to access shared memory under OS/2.  */
/* This requires EMX v09c to be installed.                           */

caddr_t create_shared_heap(const char *name, size_t size)
{
    ULONG rc;
    void *mem;
    Heap_t h;

    rc = DosAllocSharedMem(&mem, name, size,
			   PAG_COMMIT | PAG_READ | PAG_WRITE);
    if (rc != 0)
	return NULL;
    h = _ucreate(mem, size, !_BLOCK_CLEAN, _HEAP_REGULAR | _HEAP_SHARED,
		 NULL, NULL);
    if (h == NULL)
	DosFreeMem(mem);
    return (caddr_t) h;
}

caddr_t get_shared_heap(const char *Name)
{

    PVOID BaseAddress;		/* Pointer to the base address of
				   the shared memory object */
    ULONG AttributeFlags;	/* Flags describing characteristics
				   of the shared memory object */
    APIRET rc;			/* Return code */

    /* Request read and write access to */
    /*   the shared memory object       */
    AttributeFlags = PAG_WRITE | PAG_READ;

    rc = DosGetNamedSharedMem(&BaseAddress, Name, AttributeFlags);

    if (rc != 0) {
	printf("DosGetNamedSharedMem error: return code = %ld", rc);
	return 0;
    }

    return BaseAddress;
}

static void setup_shared_mem(ap_context_t *p)
{
    caddr_t m;

    int rc;

    m = (caddr_t) create_shared_heap("\\SHAREMEM\\SCOREBOARD", SCOREBOARD_SIZE);
    if (m == 0) {
	fprintf(stderr, "%s: Could not create OS/2 Shared memory pool.\n",
		ap_server_argv0);
	exit(APEXIT_INIT);
    }

    rc = _uopen((Heap_t) m);
    if (rc != 0) {
	fprintf(stderr,
		"%s: Could not uopen() newly created OS/2 Shared memory pool.\n",
		ap_server_argv0);
    }
    ap_scoreboard_image = (scoreboard *) m;
    ap_scoreboard_image->global.running_generation = 0;
}

static void reopen_scoreboard(ap_context_t *p)
{
    caddr_t m;
    int rc;

    m = (caddr_t) get_shared_heap("\\SHAREMEM\\SCOREBOARD");
    if (m == 0) {
	fprintf(stderr, "%s: Could not find existing OS/2 Shared memory pool.\n",
		ap_server_argv0);
	exit(APEXIT_INIT);
    }

    rc = _uopen((Heap_t) m);
    ap_scoreboard_image = (scoreboard *) m;
}

#elif defined(USE_POSIX_SCOREBOARD)
#include <sys/mman.h>
/* 
 * POSIX 1003.4 style
 *
 * Note 1: 
 * As of version 4.23A, shared memory in QNX must reside under /dev/shmem,
 * where no subdirectories allowed.
 *
 * POSIX shm_open() and shm_unlink() will take care about this issue,
 * but to avoid confusion, I suggest to redefine scoreboard file name
 * in httpd.conf to cut "logs/" from it. With default setup actual name
 * will be "/dev/shmem/logs.apache_status". 
 * 
 * If something went wrong and Apache did not unlinked this object upon
 * exit, you can remove it manually, using "rm -f" command.
 * 
 * Note 2:
 * <sys/mman.h> in QNX defines MAP_ANON, but current implementation 
 * does NOT support BSD style anonymous mapping. So, the order of 
 * conditional compilation is important: 
 * this #ifdef section must be ABOVE the next one (BSD style).
 *
 * I tested this stuff and it works fine for me, but if it provides 
 * trouble for you, just comment out USE_MMAP_SCOREBOARD in QNX section
 * of ap_config.h
 *
 * June 5, 1997, 
 * Igor N. Kovalenko -- infoh@mail.wplus.net
 */

static void cleanup_shared_mem(void *d)
{
    shm_unlink(ap_scoreboard_fname);
}

static void setup_shared_mem(ap_context_t *p)
{
    char buf[512];
    caddr_t m;
    int fd;

    fd = shm_open(ap_scoreboard_fname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
	ap_snprintf(buf, sizeof(buf), "%s: could not open(create) scoreboard",
		    ap_server_argv0);
	perror(buf);
	exit(APEXIT_INIT);
    }
    if (ltrunc(fd, (off_t) SCOREBOARD_SIZE, SEEK_SET) == -1) {
	ap_snprintf(buf, sizeof(buf), "%s: could not ltrunc scoreboard",
		    ap_server_argv0);
	perror(buf);
	shm_unlink(ap_scoreboard_fname);
	exit(APEXIT_INIT);
    }
    if ((m = (caddr_t) mmap((caddr_t) 0,
			    (size_t) SCOREBOARD_SIZE, PROT_READ | PROT_WRITE,
			    MAP_SHARED, fd, (off_t) 0)) == (caddr_t) - 1) {
	ap_snprintf(buf, sizeof(buf), "%s: cannot mmap scoreboard",
		    ap_server_argv0);
	perror(buf);
	shm_unlink(ap_scoreboard_fname);
	exit(APEXIT_INIT);
    }
    close(fd);
    ap_register_cleanup(p, NULL, cleanup_shared_mem, ap_null_cleanup);
    ap_scoreboard_image = (scoreboard *) m;
    ap_scoreboard_image->global.running_generation = 0;
}

static void reopen_scoreboard(ap_context_t *p)
{
}

#elif defined(USE_MMAP_SCOREBOARD)

static void setup_shared_mem(ap_context_t *p)
{
    caddr_t m;

#if defined(MAP_ANON)
/* BSD style */
#ifdef CONVEXOS11
    /*
     * 9-Aug-97 - Jeff Venters (venters@convex.hp.com)
     * ConvexOS maps address space as follows:
     *   0x00000000 - 0x7fffffff : Kernel
     *   0x80000000 - 0xffffffff : User
     * Start mmapped area 1GB above start of text.
     *
     * Also, the length requires a pointer as the actual length is
     * returned (rounded up to a page boundary).
     */
    {
	unsigned len = SCOREBOARD_SIZE;

	m = mmap((caddr_t) 0xC0000000, &len,
		 PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, NOFD, 0);
    }
#elif defined(MAP_TMPFILE)
    {
	char mfile[] = "/tmp/apache_shmem_XXXX";
	int fd = mkstemp(mfile);
	if (fd == -1) {
	    perror("open");
	    fprintf(stderr, "%s: Could not open %s\n", ap_server_argv0, mfile);
	    exit(APEXIT_INIT);
	}
	m = mmap((caddr_t) 0, SCOREBOARD_SIZE,
		PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (m == (caddr_t) - 1) {
	    perror("mmap");
	    fprintf(stderr, "%s: Could not mmap %s\n", ap_server_argv0, mfile);
	    exit(APEXIT_INIT);
	}
	close(fd);
	unlink(mfile);
    }
#else
    m = mmap((caddr_t) 0, SCOREBOARD_SIZE,
	     PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
#endif
    if (m == (caddr_t) - 1) {
	perror("mmap");
	fprintf(stderr, "%s: Could not mmap memory\n", ap_server_argv0);
	exit(APEXIT_INIT);
    }
#else
/* Sun style */
    int fd;

    fd = open("/dev/zero", O_RDWR);
    if (fd == -1) {
	perror("open");
	fprintf(stderr, "%s: Could not open /dev/zero\n", ap_server_argv0);
	exit(APEXIT_INIT);
    }
    m = mmap((caddr_t) 0, SCOREBOARD_SIZE,
	     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == (caddr_t) - 1) {
	perror("mmap");
	fprintf(stderr, "%s: Could not mmap /dev/zero\n", ap_server_argv0);
	exit(APEXIT_INIT);
    }
    close(fd);
#endif
    ap_scoreboard_image = (scoreboard *) m;
    ap_scoreboard_image->global.running_generation = 0;
}

static void reopen_scoreboard(ap_context_t *p)
{
}

#elif defined(USE_SHMGET_SCOREBOARD)
static key_t shmkey = IPC_PRIVATE;
static int shmid = -1;

static void setup_shared_mem(ap_context_t *p)
{
    struct shmid_ds shmbuf;
#ifdef MOVEBREAK
    char *obrk;
#endif

    if ((shmid = shmget(shmkey, SCOREBOARD_SIZE, IPC_CREAT | SHM_R | SHM_W)) == -1) {
#ifdef LINUX
	if (errno == ENOSYS) {
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, server_conf,
			 "Your kernel was built without CONFIG_SYSVIPC\n"
			 "%s: Please consult the Apache FAQ for details",
			 ap_server_argv0);
	}
#endif
	ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf,
		    "could not call shmget");
	exit(APEXIT_INIT);
    }

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, server_conf,
		"created shared memory segment #%d", shmid);

#ifdef MOVEBREAK
    /*
     * Some SysV systems place the shared segment WAY too close
     * to the dynamic memory break point (sbrk(0)). This severely
     * limits the use of malloc/sbrk in the program since sbrk will
     * refuse to move past that point.
     *
     * To get around this, we move the break point "way up there",
     * attach the segment and then move break back down. Ugly
     */
    if ((obrk = sbrk(MOVEBREAK)) == (char *) -1) {
	ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
	    "sbrk() could not move break");
    }
#endif

#define BADSHMAT	((scoreboard *)(-1))
    if ((ap_scoreboard_image = (scoreboard *) shmat(shmid, 0, 0)) == BADSHMAT) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf, "shmat error");
	/*
	 * We exit below, after we try to remove the segment
	 */
    }
    else {			/* only worry about permissions if we attached the segment */
	if (shmctl(shmid, IPC_STAT, &shmbuf) != 0) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
		"shmctl() could not stat segment #%d", shmid);
	}
	else {
	    shmbuf.shm_perm.uid = unixd_config.user_id;
	    shmbuf.shm_perm.gid = unixd_config.group_id;
	    if (shmctl(shmid, IPC_SET, &shmbuf) != 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
		    "shmctl() could not set segment #%d", shmid);
	    }
	}
    }
    /*
     * We must avoid leaving segments in the kernel's
     * (small) tables.
     */
    if (shmctl(shmid, IPC_RMID, NULL) != 0) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf,
		"shmctl: IPC_RMID: could not remove shared memory segment #%d",
		shmid);
    }
    if (ap_scoreboard_image == BADSHMAT)	/* now bailout */
	exit(APEXIT_INIT);

#ifdef MOVEBREAK
    if (obrk == (char *) -1)
	return;			/* nothing else to do */
    if (sbrk(-(MOVEBREAK)) == (char *) -1) {
	ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
	    "sbrk() could not move break back");
    }
#endif
    ap_scoreboard_image->global.running_generation = 0;
}

static void reopen_scoreboard(ap_context_t *p)
{
}

#elif defined(USE_TPF_SCOREBOARD)

static void cleanup_scoreboard_heap()
{
    int rv;
    rv = rsysc(ap_scoreboard_image, SCOREBOARD_FRAMES, SCOREBOARD_NAME);
    if(rv == RSYSC_ERROR) {
        ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
            "rsysc() could not release scoreboard system heap");
    }
}

static void setup_shared_mem(ap_context_t *p)
{
    cinfc(CINFC_WRITE, CINFC_CMMCTK2);
    ap_scoreboard_image = (scoreboard *) gsysc(SCOREBOARD_FRAMES, SCOREBOARD_NAME);

    if (!ap_scoreboard_image) {
        fprintf(stderr, "httpd: Could not create scoreboard system heap storage.\n");
        exit(APEXIT_INIT);
    }

    ap_register_cleanup(p, NULL, cleanup_scoreboard_heap, ap_null_cleanup);
    ap_scoreboard_image->global.running_generation = 0;
}

static void reopen_scoreboard(ap_context_t *p)
{
    cinfc(CINFC_WRITE, CINFC_CMMCTK2);
}

#else
#define SCOREBOARD_FILE
static scoreboard _scoreboard_image;
static int scoreboard_fd = -1;

/* XXX: things are seriously screwed if we ever have to do a partial
 * read or write ... we could get a corrupted scoreboard
 */
static int force_write(int fd, void *buffer, int bufsz)
{
    int rv, orig_sz = bufsz;

    do {
	rv = write(fd, buffer, bufsz);
	if (rv > 0) {
	    buffer = (char *) buffer + rv;
	    bufsz -= rv;
	}
    } while ((rv > 0 && bufsz > 0) || (rv == -1 && errno == EINTR));

    return rv < 0 ? rv : orig_sz - bufsz;
}

static int force_read(int fd, void *buffer, int bufsz)
{
    int rv, orig_sz = bufsz;

    do {
	rv = read(fd, buffer, bufsz);
	if (rv > 0) {
	    buffer = (char *) buffer + rv;
	    bufsz -= rv;
	}
    } while ((rv > 0 && bufsz > 0) || (rv == -1 && errno == EINTR));

    return rv < 0 ? rv : orig_sz - bufsz;
}

static void cleanup_scoreboard_file(void *foo)
{
    unlink(ap_scoreboard_fname);
}

void reopen_scoreboard(ap_context_t *p)
{
    if (scoreboard_fd != -1)
	ap_pclosef(p, scoreboard_fd);

#ifdef TPF
    ap_scoreboard_fname = ap_server_root_relative(p, ap_scoreboard_fname);
#endif /* TPF */
    scoreboard_fd = ap_popenf(p, ap_scoreboard_fname, O_CREAT | O_BINARY | O_RDWR, 0666);
    if (scoreboard_fd == -1) {
	perror(ap_scoreboard_fname);
	fprintf(stderr, "Cannot open scoreboard file:\n");
	clean_child_exit(1);
    }
}
#endif

/* Called by parent process */
static void reinit_scoreboard(ap_context_t *p)
{
    int running_gen = 0;
    if (ap_scoreboard_image)
	running_gen = ap_scoreboard_image->global.running_generation;

#ifndef SCOREBOARD_FILE
    if (ap_scoreboard_image == NULL) {
	setup_shared_mem(p);
    }
    memset(ap_scoreboard_image, 0, SCOREBOARD_SIZE);
    ap_scoreboard_image->global.running_generation = running_gen;
#else
    ap_scoreboard_image = &_scoreboard_image;
    ap_scoreboard_fname = ap_server_root_relative(p, ap_scoreboard_fname);

    scoreboard_fd = ap_popenf(p, ap_scoreboard_fname, O_CREAT | O_BINARY | O_RDWR, 0644);
    if (scoreboard_fd == -1) {
	perror(ap_scoreboard_fname);
	fprintf(stderr, "Cannot open scoreboard file:\n");
	exit(APEXIT_INIT);
    }
    ap_register_cleanup(p, NULL, cleanup_scoreboard_file, ap_null_cleanup);

    memset((char *) ap_scoreboard_image, 0, sizeof(*ap_scoreboard_image));
    ap_scoreboard_image->global.running_generation = running_gen;
    force_write(scoreboard_fd, ap_scoreboard_image, sizeof(*ap_scoreboard_image));
#endif
}

/* Routines called to deal with the scoreboard image
 * --- note that we do *not* need write locks, since update_child_status
 * only updates a *single* record in place, and only one process writes to
 * a given scoreboard slot at a time (either the child process owning that
 * slot, or the parent, noting that the child has died).
 *
 * As a final note --- setting the score entry to getpid() is always safe,
 * since when the parent is writing an entry, it's only noting SERVER_DEAD
 * anyway.
 */

ap_inline void ap_sync_scoreboard_image(void)
{
#ifdef SCOREBOARD_FILE
    lseek(scoreboard_fd, 0L, 0);
    force_read(scoreboard_fd, ap_scoreboard_image, sizeof(*ap_scoreboard_image));
#endif
}

API_EXPORT(int) ap_exists_scoreboard_image(void)
{
    return (ap_scoreboard_image ? 1 : 0);
}

static ap_inline void put_scoreboard_info(int child_num,
				       short_score *new_score_rec)
{
#ifdef SCOREBOARD_FILE
    lseek(scoreboard_fd, (long) child_num * sizeof(short_score), 0);
    force_write(scoreboard_fd, new_score_rec, sizeof(short_score));
#endif
}

int ap_update_child_status(int child_num, int status, request_rec *r)
{
    int old_status;
    short_score *ss;

    if (child_num < 0)
	return -1;

    ap_check_signals();

    ap_sync_scoreboard_image();
    ss = &ap_scoreboard_image->servers[child_num];
    old_status = ss->status;
    ss->status = status;

    if (ap_extended_status) {
	if (status == SERVER_READY || status == SERVER_DEAD) {
	    /*
	     * Reset individual counters
	     */
	    if (status == SERVER_DEAD) {
		ss->my_access_count = 0L;
		ss->my_bytes_served = 0L;
	    }
	    ss->conn_count = (unsigned short) 0;
	    ss->conn_bytes = (unsigned long) 0;
	}
	if (r) {
	    conn_rec *c = r->connection;
	    ap_cpystrn(ss->client, ap_get_remote_host(c, r->per_dir_config,
				  REMOTE_NOLOOKUP), sizeof(ss->client));
	    if (r->the_request == NULL) {
		    ap_cpystrn(ss->request, "NULL", sizeof(ss->request));
	    } else if (r->parsed_uri.password == NULL) {
		    ap_cpystrn(ss->request, r->the_request, sizeof(ss->request));
	    } else {
		/* Don't reveal the password in the server-status view */
		    ap_cpystrn(ss->request, ap_pstrcat(r->pool, r->method, " ",
					       ap_unparse_uri_components(r->pool, &r->parsed_uri, UNP_OMITPASSWORD),
					       r->assbackwards ? NULL : " ", r->protocol, NULL),
				       sizeof(ss->request));
	    }
	    ss->vhostrec =  r->server;
	}
    }
    if (status == SERVER_STARTING && r == NULL) {
	/* clean up the slot's vhostrec pointer (maybe re-used)
	 * and mark the slot as belonging to a new generation.
	 */
	ss->vhostrec = NULL;
	ap_scoreboard_image->parent[child_num].generation = ap_my_generation;
#ifdef SCOREBOARD_FILE
	lseek(scoreboard_fd, XtOffsetOf(scoreboard, parent[child_num]), 0);
	force_write(scoreboard_fd, &ap_scoreboard_image->parent[child_num],
	    sizeof(parent_score));
#endif
    }
    put_scoreboard_info(child_num, ss);

    return old_status;
}

static void update_scoreboard_global(void)
{
#ifdef SCOREBOARD_FILE
    lseek(scoreboard_fd,
	  (char *) &ap_scoreboard_image->global -(char *) ap_scoreboard_image, 0);
    force_write(scoreboard_fd, &ap_scoreboard_image->global,
		sizeof ap_scoreboard_image->global);
#endif
}

void ap_time_process_request(int child_num, int status)
{
    short_score *ss;
#if defined(NO_GETTIMEOFDAY) && !defined(NO_TIMES)
    struct tms tms_blk;
#endif

    if (child_num < 0)
	return;

    ap_sync_scoreboard_image();
    ss = &ap_scoreboard_image->servers[child_num];

    if (status == START_PREQUEST) {
#if defined(NO_GETTIMEOFDAY)
#ifndef NO_TIMES
	if ((ss->start_time = times(&tms_blk)) == -1)
#endif /* NO_TIMES */
	    ss->start_time = (clock_t) 0;
#else
	if (gettimeofday(&ss->start_time, (struct timezone *) 0) < 0)
	    ss->start_time.tv_sec =
		ss->start_time.tv_usec = 0L;
#endif
    }
    else if (status == STOP_PREQUEST) {
#if defined(NO_GETTIMEOFDAY)
#ifndef NO_TIMES
	if ((ss->stop_time = times(&tms_blk)) == -1)
#endif
	    ss->stop_time = ss->start_time = (clock_t) 0;
#else
	if (gettimeofday(&ss->stop_time, (struct timezone *) 0) < 0)
	    ss->stop_time.tv_sec =
		ss->stop_time.tv_usec =
		ss->start_time.tv_sec =
		ss->start_time.tv_usec = 0L;
#endif

    }

    put_scoreboard_info(child_num, ss);
}

/*
static void increment_counts(int child_num, request_rec *r)
{
    long int bs = 0;
    short_score *ss;

    ap_sync_scoreboard_image();
    ss = &ap_scoreboard_image->servers[child_num];

    if (r->sent_bodyct)
	ap_bgetopt(r->connection->client, BO_BYTECT, &bs);

#ifndef NO_TIMES
    times(&ss->times);
#endif
    ss->access_count++;
    ss->my_access_count++;
    ss->conn_count++;
    ss->bytes_served += (unsigned long) bs;
    ss->my_bytes_served += (unsigned long) bs;
    ss->conn_bytes += (unsigned long) bs;

    put_scoreboard_info(child_num, ss);
}
*/

static int find_child_by_pid(int pid)
{
    int i;

    for (i = 0; i < max_daemons_limit; ++i)
	if (ap_scoreboard_image->parent[i].pid == pid)
	    return i;

    return -1;
}

static void reclaim_child_processes(int terminate)
{
#ifndef MULTITHREAD
    int i, status;
    long int waittime = 1024 * 16;	/* in usecs */
    struct timeval tv;
    int waitret, tries;
    int not_dead_yet;
#ifdef HAS_OTHER_CHILD
    other_child_rec *ocr, *nocr;
#endif

    ap_sync_scoreboard_image();

    for (tries = terminate ? 4 : 1; tries <= 9; ++tries) {
	/* don't want to hold up progress any more than 
	 * necessary, but we need to allow children a few moments to exit.
	 * Set delay with an exponential backoff.
	 */
	tv.tv_sec = waittime / 1000000;
	tv.tv_usec = waittime % 1000000;
	waittime = waittime * 4;
	ap_select(0, NULL, NULL, NULL, &tv);

	/* now see who is done */
	not_dead_yet = 0;
	for (i = 0; i < max_daemons_limit; ++i) {
	    int pid = ap_scoreboard_image->parent[i].pid;

	    if (pid == my_pid || pid == 0)
		continue;

	    waitret = waitpid(pid, &status, WNOHANG);
	    if (waitret == pid || waitret == -1) {
		ap_scoreboard_image->parent[i].pid = 0;
		continue;
	    }
	    ++not_dead_yet;
	    switch (tries) {
	    case 1:     /*  16ms */
	    case 2:     /*  82ms */
		break;
	    case 3:     /* 344ms */
		/* perhaps it missed the SIGHUP, lets try again */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING,
			    server_conf,
		    "child process %d did not exit, sending another SIGHUP",
			    pid);
		kill(pid, SIGHUP);
		waittime = 1024 * 16;
		break;
	    case 4:     /*  16ms */
	    case 5:     /*  82ms */
	    case 6:     /* 344ms */
		break;
	    case 7:     /* 1.4sec */
		/* ok, now it's being annoying */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING,
			    server_conf,
		   "child process %d still did not exit, sending a SIGTERM",
			    pid);
		kill(pid, SIGTERM);
		break;
	    case 8:     /*  6 sec */
		/* die child scum */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, server_conf,
		   "child process %d still did not exit, sending a SIGKILL",
			    pid);
		kill(pid, SIGKILL);
		break;
	    case 9:     /* 14 sec */
		/* gave it our best shot, but alas...  If this really 
		 * is a child we are trying to kill and it really hasn't
		 * exited, we will likely fail to bind to the port
		 * after the restart.
		 */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, server_conf,
			    "could not make child process %d exit, "
			    "attempting to continue anyway", pid);
		break;
	    }
	}
#ifdef HAS_OTHER_CHILD
	for (ocr = other_children; ocr; ocr = nocr) {
	    nocr = ocr->next;
	    if (ocr->pid == -1)
		continue;

	    waitret = waitpid(ocr->pid, &status, WNOHANG);
	    if (waitret == ocr->pid) {
		ocr->pid = -1;
		(*ocr->maintenance) (OC_REASON_DEATH, ocr->data, status);
	    }
	    else if (waitret == 0) {
		(*ocr->maintenance) (OC_REASON_RESTART, ocr->data, -1);
		++not_dead_yet;
	    }
	    else if (waitret == -1) {
		/* uh what the heck? they didn't call unregister? */
		ocr->pid = -1;
		(*ocr->maintenance) (OC_REASON_LOST, ocr->data, -1);
	    }
	}
#endif
	if (!not_dead_yet) {
	    /* nothing left to wait for */
	    break;
	}
    }
#endif /* ndef MULTITHREAD */
}


#if defined(NEED_WAITPID)
/*
   Systems without a real waitpid sometimes lose a child's exit while waiting
   for another.  Search through the scoreboard for missing children.
 */
int reap_children(ap_wait_t *status)
{
    int n, pid;

    for (n = 0; n < max_daemons_limit; ++n) {
        ap_sync_scoreboard_image();
	if (ap_scoreboard_image->servers[n].status != SERVER_DEAD &&
		kill((pid = ap_scoreboard_image->parent[n].pid), 0) == -1) {
	    ap_update_child_status(n, SERVER_DEAD, NULL);
	    /* just mark it as having a successful exit status */
	    bzero((char *) status, sizeof(ap_wait_t));
	    return(pid);
	}
    }
    return 0;
}
#endif

/* Finally, this routine is used by the caretaker process to wait for
 * a while...
 */

/* number of calls to wait_or_timeout between writable probes */
#ifndef INTERVAL_OF_WRITABLE_PROBES
#define INTERVAL_OF_WRITABLE_PROBES 10
#endif
static int wait_or_timeout_counter;

static int wait_or_timeout(ap_wait_t *status)
{
    struct timeval tv;
    int ret;

    ++wait_or_timeout_counter;
    if (wait_or_timeout_counter == INTERVAL_OF_WRITABLE_PROBES) {
	wait_or_timeout_counter = 0;
#ifdef HAS_OTHER_CHILD
	probe_writable_fds();
#endif
    }
    ret = waitpid(-1, status, WNOHANG);
    if (ret == -1 && errno == EINTR) {
	return -1;
    }
    if (ret > 0) {
	return ret;
    }
#ifdef NEED_WAITPID
    if ((ret = reap_children(status)) > 0) {
	return ret;
    }
#endif
    tv.tv_sec = SCOREBOARD_MAINTENANCE_INTERVAL / 1000000;
    tv.tv_usec = SCOREBOARD_MAINTENANCE_INTERVAL % 1000000;
    ap_select(0, NULL, NULL, NULL, &tv);
    return -1;
}

/* handle all varieties of core dumping signals */
static void sig_coredump(int sig)
{
    chdir(ap_coredump_dir);
    signal(sig, SIG_DFL);
    kill(getpid(), sig);
    /* At this point we've got sig blocked, because we're still inside
     * the signal handler.  When we leave the signal handler it will
     * be unblocked, and we'll take the signal... and coredump or whatever
     * is appropriate for this particular Unix.  In addition the parent
     * will see the real signal we received -- whereas if we called
     * abort() here, the parent would only see SIGABRT.
     */
}

/*****************************************************************
 * Connection structures and accounting...
 */

static void just_die(int sig)
{
    clean_child_exit(0);
}

static int volatile deferred_die;
static int volatile usr1_just_die;

static void usr1_handler(int sig)
{
    if (usr1_just_die) {
	just_die(sig);
    }
    deferred_die = 1;
}

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful;
ap_generation_t volatile ap_my_generation=0;

static void sig_term(int sig)
{
    if (shutdown_pending == 1) {
	/* Um, is this _probably_ not an error, if the user has
	 * tried to do a shutdown twice quickly, so we won't
	 * worry about reporting it.
	 */
	return;
    }
    shutdown_pending = 1;
}

static void restart(int sig)
{
    if (restart_pending == 1) {
	/* Probably not an error - don't bother reporting it */
	return;
    }
    restart_pending = 1;
    is_graceful = sig == SIGUSR1;
}

static void set_signals(void)
{
#ifndef NO_USE_SIGACTION
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (!one_process) {
	sa.sa_handler = sig_coredump;
#if defined(SA_ONESHOT)
	sa.sa_flags = SA_ONESHOT;
#elif defined(SA_RESETHAND)
	sa.sa_flags = SA_RESETHAND;
#endif
	if (sigaction(SIGSEGV, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGSEGV)");
#ifdef SIGBUS
	if (sigaction(SIGBUS, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGBUS)");
#endif
#ifdef SIGABORT
	if (sigaction(SIGABORT, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGABORT)");
#endif
#ifdef SIGABRT
	if (sigaction(SIGABRT, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGABRT)");
#endif
#ifdef SIGILL
	if (sigaction(SIGILL, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGILL)");
#endif
	sa.sa_flags = 0;
    }
    sa.sa_handler = sig_term;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGTERM)");
#ifdef SIGINT
    if (sigaction(SIGINT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGINT)");
#endif
#ifdef SIGXCPU
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGXCPU, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGXCPU)");
#endif
#ifdef SIGXFSZ
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGXFSZ, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGXFSZ)");
#endif
#ifdef SIGPIPE
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGPIPE)");
#endif

    /* we want to ignore HUPs and USR1 while we're busy processing one */
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, SIGUSR1);
    sa.sa_handler = restart;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGHUP)");
    if (sigaction(SIGUSR1, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGUSR1)");
#else
    if (!one_process) {
	signal(SIGSEGV, sig_coredump);
#ifdef SIGBUS
	signal(SIGBUS, sig_coredump);
#endif /* SIGBUS */
#ifdef SIGABORT
	signal(SIGABORT, sig_coredump);
#endif /* SIGABORT */
#ifdef SIGABRT
	signal(SIGABRT, sig_coredump);
#endif /* SIGABRT */
#ifdef SIGILL
	signal(SIGILL, sig_coredump);
#endif /* SIGILL */
#ifdef SIGXCPU
	signal(SIGXCPU, SIG_DFL);
#endif /* SIGXCPU */
#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_DFL);
#endif /* SIGXFSZ */
    }

    signal(SIGTERM, sig_term);
#ifdef SIGHUP
    signal(SIGHUP, restart);
#endif /* SIGHUP */
#ifdef SIGUSR1
    signal(SIGUSR1, restart);
#endif /* SIGUSR1 */
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif /* SIGPIPE */

#endif
}

#if defined(TCP_NODELAY) && !defined(MPE) && !defined(TPF)
static void sock_disable_nagle(int s)
{
    /* The Nagle algorithm says that we should delay sending partial
     * packets in hopes of getting more data.  We don't want to do
     * this; we are not telnet.  There are bad interactions between
     * persistent connections and Nagle's algorithm that have very severe
     * performance penalties.  (Failing to disable Nagle is not much of a
     * problem with simple HTTP.)
     *
     * In spite of these problems, failure here is not a shooting offense.
     */
    int just_say_no = 1;

    if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &just_say_no,
		   sizeof(int)) < 0) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf,
		    "setsockopt: (TCP_NODELAY)");
    }
}

#else
#define sock_disable_nagle(s)	/* NOOP */
#endif


/*****************************************************************
 * Child process main loop.
 * The following vars are static to avoid getting clobbered by longjmp();
 * they are really private to child_main.
 */

static int srv;
static ap_socket_t *csd;
static int requests_this_child;
static fd_set main_fds;

API_EXPORT(void) ap_child_terminate(request_rec *r)
{
    r->connection->keepalive = 0;
    requests_this_child = ap_max_requests_per_child = 1;
}

int ap_graceful_stop_signalled(void)
{
    ap_sync_scoreboard_image();
    if (deferred_die ||
	ap_scoreboard_image->global.running_generation != ap_my_generation) {
	return 1;
    }
    return 0;
}

static void child_main(int child_num_arg)
{
    NET_SIZE_T clen;
    struct sockaddr sa_server;
    struct sockaddr sa_client;
    ap_listen_rec *lr;
    ap_listen_rec *last_lr;
    ap_listen_rec *first_lr;
    ap_context_t *ptrans;
    conn_rec *current_conn;
    ap_iol *iol;
    ap_status_t stat;
    int sockdes;

    my_pid = getpid();
    csd = NULL;
    my_child_num = child_num_arg;
    requests_this_child = 0;
    last_lr = NULL;

    /* Get a sub ap_context_t for global allocations in this child, so that
     * we can have cleanups occur when the child exits.
     */
    ap_create_context(pconf, NULL, &pchild);

    ap_create_context(pchild, NULL, &ptrans);

    /* needs to be done before we switch UIDs so we have permissions */
    reopen_scoreboard(pchild);
    SAFE_ACCEPT(accept_mutex_child_init(pchild));

    if (unixd_setup_child()) {
	clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_child_init_hook(pchild, server_conf);

    (void) ap_update_child_status(my_child_num, SERVER_READY, (request_rec *) NULL);

    signal(SIGHUP, just_die);
    signal(SIGTERM, just_die);

#ifdef OS2
/* Stop Ctrl-C/Ctrl-Break signals going to child processes */
    {
        unsigned long ulTimes;
        DosSetSignalExceptionFocus(0, &ulTimes);
    }
#endif

    while (!ap_graceful_stop_signalled()) {
	BUFF *conn_io;

	/* Prepare to receive a SIGUSR1 due to graceful restart so that
	 * we can exit cleanly.
	 */
	usr1_just_die = 1;
	signal(SIGUSR1, usr1_handler);

	/*
	 * (Re)initialize this child to a pre-connection state.
	 */

	current_conn = NULL;

	ap_clear_pool(ptrans);

	if ((ap_max_requests_per_child > 0
	     && requests_this_child++ >= ap_max_requests_per_child)) {
	    clean_child_exit(0);
	}

	(void) ap_update_child_status(my_child_num, SERVER_READY, (request_rec *) NULL);

	/*
	 * Wait for an acceptable connection to arrive.
	 */

	/* Lock around "accept", if necessary */
	SAFE_ACCEPT(accept_mutex_on());

	for (;;) {
	    if (ap_listeners->next) {
		/* more than one socket */
		memcpy(&main_fds, &listenfds, sizeof(fd_set));
		srv = ap_select(listenmaxfd + 1, &main_fds, NULL, NULL, NULL);

		if (srv < 0 && errno != EINTR) {
		    /* Single Unix documents select as returning errnos
		     * EBADF, EINTR, and EINVAL... and in none of those
		     * cases does it make sense to continue.  In fact
		     * on Linux 2.0.x we seem to end up with EFAULT
		     * occasionally, and we'd loop forever due to it.
		     */
		    ap_log_error(APLOG_MARK, APLOG_ERR, server_conf, "select: (listen)");
		    clean_child_exit(1);
		}

		if (srv <= 0)
		    continue;

		/* we remember the last_lr we searched last time around so that
		   we don't end up starving any particular listening socket */
		if (last_lr == NULL) {
		    lr = ap_listeners;
		}
		else {
		    lr = last_lr->next;
		    if (!lr)
			lr = ap_listeners;
		}
		first_lr=lr;
		do {
                    ap_get_os_sock(lr->sd, &sockdes);
		    if (FD_ISSET(sockdes, &main_fds))
			goto got_listener;
		    lr = lr->next;
		    if (!lr)
			lr = ap_listeners;
		}
		while (lr != first_lr);
		/* FIXME: if we get here, something bad has happened, and we're
		   probably gonna spin forever.
		*/
		continue;
	got_listener:
		last_lr = lr;
		sd = lr->sd;
	    }
	    else {
		/* only one socket, just pretend we did the other stuff */
		sd = ap_listeners->sd;
	    }

	    /* if we accept() something we don't want to die, so we have to
	     * defer the exit
	     */
	    usr1_just_die = 0;
	    for (;;) {
		if (deferred_die) {
		    /* we didn't get a socket, and we were told to die */
		    clean_child_exit(0);
		}
		clen = sizeof(sa_client);
		stat = ap_accept(sd, &csd);
		if (stat == APR_SUCCESS || stat != APR_EINTR)
		    break;
	    }

	    if (stat == APR_SUCCESS)
		break;		/* We have a socket ready for reading */
	    else {

/* TODO: this accept result handling stuff should be abstracted...
 * it's already out of date between the various unix mpms
 */
		/* Our old behaviour here was to continue after accept()
		 * errors.  But this leads us into lots of troubles
		 * because most of the errors are quite fatal.  For
		 * example, EMFILE can be caused by slow descriptor
		 * leaks (say in a 3rd party module, or libc).  It's
		 * foolish for us to continue after an EMFILE.  We also
		 * seem to tickle kernel bugs on some platforms which
		 * lead to never-ending loops here.  So it seems best
		 * to just exit in most cases.
		 */
                switch (errno) {
#ifdef EPROTO
		    /* EPROTO on certain older kernels really means
		     * ECONNABORTED, so we need to ignore it for them.
		     * See discussion in new-httpd archives nh.9701
		     * search for EPROTO.
		     *
		     * Also see nh.9603, search for EPROTO:
		     * There is potentially a bug in Solaris 2.x x<6,
		     * and other boxes that implement tcp sockets in
		     * userland (i.e. on top of STREAMS).  On these
		     * systems, EPROTO can actually result in a fatal
		     * loop.  See PR#981 for example.  It's hard to
		     * handle both uses of EPROTO.
		     */
                case EPROTO:
#endif
#ifdef ECONNABORTED
                case ECONNABORTED:
#endif
		    /* Linux generates the rest of these, other tcp
		     * stacks (i.e. bsd) tend to hide them behind
		     * getsockopt() interfaces.  They occur when
		     * the net goes sour or the client disconnects
		     * after the three-way handshake has been done
		     * in the kernel but before userland has picked
		     * up the socket.
		     */
#ifdef ECONNRESET
                case ECONNRESET:
#endif
#ifdef ETIMEDOUT
                case ETIMEDOUT:
#endif
#ifdef EHOSTUNREACH
		case EHOSTUNREACH:
#endif
#ifdef ENETUNREACH
		case ENETUNREACH:
#endif
                    break;
#ifdef ENETDOWN
		case ENETDOWN:
		     /*
		      * When the network layer has been shut down, there
		      * is not much use in simply exiting: the parent
		      * would simply re-create us (and we'd fail again).
		      * Use the CHILDFATAL code to tear the server down.
		      * @@@ Martin's idea for possible improvement:
		      * A different approach would be to define
		      * a new APEXIT_NETDOWN exit code, the reception
		      * of which would make the parent shutdown all
		      * children, then idle-loop until it detected that
		      * the network is up again, and restart the children.
		      * Ben Hyde noted that temporary ENETDOWN situations
		      * occur in mobile IP.
		      */
		    ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf,
			"accept: giving up.");
		    clean_child_exit(APEXIT_CHILDFATAL);
#endif /*ENETDOWN*/

#ifdef TPF
		case EINACT:
		    ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf,
			"offload device inactive");
		    clean_child_exit(APEXIT_CHILDFATAL);
		    break;
		default:
		    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, server_conf,
			"select/accept error (%u)", errno);
		    clean_child_exit(APEXIT_CHILDFATAL);
#else
		default:
		    ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
				"accept: (client socket)");
		    clean_child_exit(1);
#endif
		}
	    }

	    if (ap_graceful_stop_signalled()) {
		clean_child_exit(0);
	    }
	    usr1_just_die = 1;
	}

	SAFE_ACCEPT(accept_mutex_off());	/* unlock after "accept" */

#ifdef TPF
	if (csd == 0)                       /* 0 is invalid socket for TPF */
	    continue;
#endif

	/* We've got a socket, let's at least process one request off the
	 * socket before we accept a graceful restart request.  We set
	 * the signal to ignore because we don't want to disturb any
	 * third party code.
	 */
	signal(SIGUSR1, SIG_IGN);

	/*
	 * We now have a connection, so set it up with the appropriate
	 * socket options, file descriptors, and read/write buffers.
	 */

        ap_get_os_sock(csd, &sockdes);

	clen = sizeof(sa_server);
	if (getsockname(sockdes, &sa_server, &clen) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, server_conf, "getsockname");
	    ap_close_socket(csd);
	    continue;
	}

	sock_disable_nagle(sockdes);

	iol = unix_attach_socket(sockdes);
	if (iol == NULL) {
	    if (errno == EBADF) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, NULL,
		    "filedescriptor (%u) larger than FD_SETSIZE (%u) "
		    "found, you probably need to rebuild Apache with a "
		    "larger FD_SETSIZE", sockdes, FD_SETSIZE);
	    }
	    else {
		ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
		    "error attaching to socket");
	    }
	    ap_close_socket(csd);
	    continue;
	}

	(void) ap_update_child_status(my_child_num, SERVER_BUSY_READ,
				   (request_rec *) NULL);

	conn_io = ap_bcreate(ptrans, B_RDWR);

	ap_bpush_iol(conn_io, iol);

	current_conn = ap_new_connection(ptrans, server_conf, conn_io,
					 (struct sockaddr_in *) &sa_client,
					 (struct sockaddr_in *) &sa_server,
					 my_child_num);

	ap_process_connection(current_conn);
    }
}


static int make_child(server_rec *s, int slot, time_t now)
{
    int pid;

    if (slot + 1 > max_daemons_limit) {
	max_daemons_limit = slot + 1;
    }

    if (one_process) {
	signal(SIGHUP, just_die);
	signal(SIGINT, just_die);
#ifdef SIGQUIT
	signal(SIGQUIT, SIG_DFL);
#endif
	signal(SIGTERM, just_die);
	child_main(slot);
    }

    (void) ap_update_child_status(slot, SERVER_STARTING, (request_rec *) NULL);


#ifdef _OSD_POSIX
    /* BS2000 requires a "special" version of fork() before a setuid() call */
    if ((pid = os_fork(unixd_config.user_name)) == -1) {
#elif defined(TPF)
    if ((pid = os_fork(s, slot)) == -1) {
#else
    if ((pid = fork()) == -1) {
#endif
	ap_log_error(APLOG_MARK, APLOG_ERR, s, "fork: Unable to fork new process");

	/* fork didn't succeed. Fix the scoreboard or else
	 * it will say SERVER_STARTING forever and ever
	 */
	(void) ap_update_child_status(slot, SERVER_DEAD, (request_rec *) NULL);

	/* In case system resources are maxxed out, we don't want
	   Apache running away with the CPU trying to fork over and
	   over and over again. */
	sleep(10);

	return -1;
    }

    if (!pid) {
#ifdef AIX_BIND_PROCESSOR
/* by default AIX binds to a single processor
 * this bit unbinds children which will then bind to another cpu
 */
#include <sys/processor.h>
	int status = bindprocessor(BINDPROCESS, (int)getpid(), 
				   PROCESSOR_CLASS_ANY);
	if (status != OK) {
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, server_conf,
			"processor unbind failed %d", status);
	}
#endif
	RAISE_SIGSTOP(MAKE_CHILD);
	/* Disable the restart signal handlers and enable the just_die stuff.
	 * Note that since restart() just notes that a restart has been
	 * requested there's no race condition here.
	 */
	signal(SIGHUP, just_die);
	signal(SIGUSR1, just_die);
	signal(SIGTERM, just_die);
	child_main(slot);
    }

    ap_scoreboard_image->parent[slot].pid = pid;
#ifdef SCOREBOARD_FILE
    lseek(scoreboard_fd, XtOffsetOf(scoreboard, parent[slot]), 0);
    force_write(scoreboard_fd, &ap_scoreboard_image->parent[slot],
		sizeof(parent_score));
#endif

    return 0;
}


/* start up a bunch of children */
static void startup_children(int number_to_start)
{
    int i;
    time_t now = time(0);

    for (i = 0; number_to_start && i < ap_daemons_limit; ++i) {
	if (ap_scoreboard_image->servers[i].status != SERVER_DEAD) {
	    continue;
	}
	if (make_child(server_conf, i, now) < 0) {
	    break;
	}
	--number_to_start;
    }
}


/*
 * idle_spawn_rate is the number of children that will be spawned on the
 * next maintenance cycle if there aren't enough idle servers.  It is
 * doubled up to MAX_SPAWN_RATE, and reset only when a cycle goes by
 * without the need to spawn.
 */
static int idle_spawn_rate = 1;
#ifndef MAX_SPAWN_RATE
#define MAX_SPAWN_RATE	(32)
#endif
static int hold_off_on_exponential_spawning;

static void perform_idle_server_maintenance(void)
{
    int i;
    int to_kill;
    int idle_count;
    short_score *ss;
    time_t now = time(0);
    int free_length;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead;
    int total_non_dead;

    /* initialize the free_list */
    free_length = 0;

    to_kill = -1;
    idle_count = 0;
    last_non_dead = -1;
    total_non_dead = 0;

    ap_sync_scoreboard_image();
    for (i = 0; i < ap_daemons_limit; ++i) {
	int status;

	if (i >= max_daemons_limit && free_length == idle_spawn_rate)
	    break;
	ss = &ap_scoreboard_image->servers[i];
	status = ss->status;
	if (status == SERVER_DEAD) {
	    /* try to keep children numbers as low as possible */
	    if (free_length < idle_spawn_rate) {
		free_slots[free_length] = i;
		++free_length;
	    }
	}
	else {
	    /* We consider a starting server as idle because we started it
	     * at least a cycle ago, and if it still hasn't finished starting
	     * then we're just going to swamp things worse by forking more.
	     * So we hopefully won't need to fork more if we count it.
	     * This depends on the ordering of SERVER_READY and SERVER_STARTING.
	     */
	    if (status <= SERVER_READY) {
		++ idle_count;
		/* always kill the highest numbered child if we have to...
		 * no really well thought out reason ... other than observing
		 * the server behaviour under linux where lower numbered children
		 * tend to service more hits (and hence are more likely to have
		 * their data in cpu caches).
		 */
		to_kill = i;
	    }

	    ++total_non_dead;
	    last_non_dead = i;
	}
    }
    max_daemons_limit = last_non_dead + 1;
    if (idle_count > ap_daemons_max_free) {
	/* kill off one child... we use SIGUSR1 because that'll cause it to
	 * shut down gracefully, in case it happened to pick up a request
	 * while we were counting
	 */
	kill(ap_scoreboard_image->parent[to_kill].pid, SIGUSR1);
	idle_spawn_rate = 1;
    }
    else if (idle_count < ap_daemons_min_free) {
	/* terminate the free list */
	if (free_length == 0) {
	    /* only report this condition once */
	    static int reported = 0;

	    if (!reported) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, server_conf,
			    "server reached MaxClients setting, consider"
			    " raising the MaxClients setting");
		reported = 1;
	    }
	    idle_spawn_rate = 1;
	}
	else {
	    if (idle_spawn_rate >= 8) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, server_conf,
		    "server seems busy, (you may need "
		    "to increase StartServers, or Min/MaxSpareServers), "
		    "spawning %d children, there are %d idle, and "
		    "%d total children", idle_spawn_rate,
		    idle_count, total_non_dead);
	    }
	    for (i = 0; i < free_length; ++i) {
#ifdef TPF
        if(make_child(server_conf, free_slots[i], now) == -1) {
            if(free_length == 1) {
                shutdown_pending = 1;
                ap_log_error(APLOG_MARK, APLOG_EMERG, server_conf,
                "No active child processes: shutting down");
            }
        }
#else
		make_child(server_conf, free_slots[i], now);
#endif /* TPF */
	    }
	    /* the next time around we want to spawn twice as many if this
	     * wasn't good enough, but not if we've just done a graceful
	     */
	    if (hold_off_on_exponential_spawning) {
		--hold_off_on_exponential_spawning;
	    }
	    else if (idle_spawn_rate < MAX_SPAWN_RATE) {
		idle_spawn_rate *= 2;
	    }
	}
    }
    else {
	idle_spawn_rate = 1;
    }
}


static void process_child_status(int pid, ap_wait_t status)
{
    /* Child died... if it died due to a fatal error,
	* we should simply bail out.
	*/
    if ((WIFEXITED(status)) &&
	WEXITSTATUS(status) == APEXIT_CHILDFATAL) {
	ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, server_conf,
			"Child %d returned a Fatal error... \n"
			"Apache is exiting!",
			pid);
	exit(APEXIT_CHILDFATAL);
    }
    if (WIFSIGNALED(status)) {
	switch (WTERMSIG(status)) {
	case SIGTERM:
	case SIGHUP:
	case SIGUSR1:
	case SIGKILL:
	    break;
	default:
#ifdef SYS_SIGLIST
#ifdef WCOREDUMP
	    if (WCOREDUMP(status)) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
			     server_conf,
			     "child pid %d exit signal %s (%d), "
			     "possible coredump in %s",
			     pid, (WTERMSIG(status) >= NumSIG) ? "" : 
			     SYS_SIGLIST[WTERMSIG(status)], WTERMSIG(status),
			     ap_coredump_dir);
	    }
	    else {
#endif
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
			     server_conf,
			     "child pid %d exit signal %s (%d)", pid,
			     SYS_SIGLIST[WTERMSIG(status)], WTERMSIG(status));
#ifdef WCOREDUMP
	    }
#endif
#else
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
			 server_conf,
			 "child pid %d exit signal %d",
			 pid, WTERMSIG(status));
#endif
	}
    }
}


static int setup_listeners(ap_context_t *p, server_rec *s)
{
    ap_listen_rec *lr;
    int sockdes;

    if (ap_listen_open(p, s->port)) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, s,
		    "no listening sockets available, shutting down");
	return -1;
    }

    listenmaxfd = -1;
    FD_ZERO(&listenfds);
    for (lr = ap_listeners; lr; lr = lr->next) {
        ap_get_os_sock(lr->sd, &sockdes);
	FD_SET(sockdes, &listenfds);
	if (sockdes > listenmaxfd) {
	    listenmaxfd = sockdes;
	}
    }
    return 0;
}


/*****************************************************************
 * Executive routines.
 */

int ap_mpm_run(ap_context_t *_pconf, ap_context_t *plog, server_rec *s)
{
    int remaining_children_to_start;

    pconf = _pconf;

    server_conf = s;
 
    ap_log_pid(pconf, ap_pid_fname);

    if (setup_listeners(pconf, s)) {
	/* XXX: hey, what's the right way for the mpm to indicate a fatal error? */
	return 1;
    }

    SAFE_ACCEPT(accept_mutex_init(pconf));
    if (!is_graceful) {
	reinit_scoreboard(pconf);
    }
#ifdef SCOREBOARD_FILE
    else {
	ap_scoreboard_fname = ap_server_root_relative(pconf, ap_scoreboard_fname);
	ap_note_cleanups_for_fd(pconf, scoreboard_fd);
    }
#endif

    set_signals();

    if (ap_daemons_max_free < ap_daemons_min_free + 1)	/* Don't thrash... */
	ap_daemons_max_free = ap_daemons_min_free + 1;

    /* If we're doing a graceful_restart then we're going to see a lot
	* of children exiting immediately when we get into the main loop
	* below (because we just sent them SIGUSR1).  This happens pretty
	* rapidly... and for each one that exits we'll start a new one until
	* we reach at least daemons_min_free.  But we may be permitted to
	* start more than that, so we'll just keep track of how many we're
	* supposed to start up without the 1 second penalty between each fork.
	*/
    remaining_children_to_start = ap_daemons_to_start;
    if (remaining_children_to_start > ap_daemons_limit) {
	remaining_children_to_start = ap_daemons_limit;
    }
    if (!is_graceful) {
	startup_children(remaining_children_to_start);
	remaining_children_to_start = 0;
    }
    else {
	/* give the system some time to recover before kicking into
	    * exponential mode */
	hold_off_on_exponential_spawning = 10;
    }

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, server_conf,
		"%s configured -- resuming normal operations",
		ap_get_server_version());
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, server_conf,
		"Server built: %s", ap_get_server_built());
    restart_pending = shutdown_pending = 0;

    while (!restart_pending && !shutdown_pending) {
	int child_slot;
	ap_wait_t status;
	int pid = wait_or_timeout(&status);

	/* XXX: if it takes longer than 1 second for all our children
	 * to start up and get into IDLE state then we may spawn an
	 * extra child
	 */
	if (pid >= 0) {
	    process_child_status(pid, status);
	    /* non-fatal death... note that it's gone in the scoreboard. */
	    ap_sync_scoreboard_image();
	    child_slot = find_child_by_pid(pid);
	    if (child_slot >= 0) {
		(void) ap_update_child_status(child_slot, SERVER_DEAD,
					    (request_rec *) NULL);
		if (remaining_children_to_start
		    && child_slot < ap_daemons_limit) {
		    /* we're still doing a 1-for-1 replacement of dead
			* children with new children
			*/
		    make_child(server_conf, child_slot, time(0));
		    --remaining_children_to_start;
		}
#ifdef HAS_OTHER_CHILD
	    }
	    else if (reap_other_child(pid, status) == 0) {
		/* handled */
#endif
	    }
	    else if (is_graceful) {
		/* Great, we've probably just lost a slot in the
		    * scoreboard.  Somehow we don't know about this
		    * child.
		    */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, server_conf,
			    "long lost child came home! (pid %d)", pid);
	    }
	    /* Don't perform idle maintenance when a child dies,
		* only do it when there's a timeout.  Remember only a
		* finite number of children can die, and it's pretty
		* pathological for a lot to die suddenly.
		*/
	    continue;
	}
	else if (remaining_children_to_start) {
	    /* we hit a 1 second timeout in which none of the previous
		* generation of children needed to be reaped... so assume
		* they're all done, and pick up the slack if any is left.
		*/
	    startup_children(remaining_children_to_start);
	    remaining_children_to_start = 0;
	    /* In any event we really shouldn't do the code below because
		* few of the servers we just started are in the IDLE state
		* yet, so we'd mistakenly create an extra server.
		*/
	    continue;
	}

	perform_idle_server_maintenance();
#ifdef TPF
    shutdown_pending = os_check_server(tpf_server_name);
    ap_check_signals();
    sleep(1);
#endif /*TPF */
    }

    if (shutdown_pending) {
	/* Time to gracefully shut down:
	 * Kill child processes, tell them to call child_exit, etc...
	 */
	if (ap_killpg(getpgrp(), SIGTERM) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "killpg SIGTERM");
	}
	reclaim_child_processes(1);		/* Start with SIGTERM */

	/* cleanup pid file on normal shutdown */
	{
	    const char *pidfile = NULL;
	    pidfile = ap_server_root_relative (pconf, ap_pid_fname);
	    if ( pidfile != NULL && unlink(pidfile) == 0)
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO,
				server_conf,
				"removed PID file %s (pid=%ld)",
				pidfile, (long)getpid());
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, server_conf,
		    "caught SIGTERM, shutting down");
	return 1;
    }

    /* we've been told to restart */
    signal(SIGHUP, SIG_IGN);
    signal(SIGUSR1, SIG_IGN);

    if (one_process) {
	/* not worth thinking about */
	return 1;
    }

    /* advance to the next generation */
    /* XXX: we really need to make sure this new generation number isn't in
     * use by any of the children.
     */
    ++ap_my_generation;
    ap_scoreboard_image->global.running_generation = ap_my_generation;
    update_scoreboard_global();

    if (is_graceful) {
#ifndef SCOREBOARD_FILE
	int i;
#endif
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, server_conf,
		    "SIGUSR1 received.  Doing graceful restart");

	/* kill off the idle ones */
	if (ap_killpg(getpgrp(), SIGUSR1) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "killpg SIGUSR1");
	}
#ifndef SCOREBOARD_FILE
	/* This is mostly for debugging... so that we know what is still
	    * gracefully dealing with existing request.  But we can't really
	    * do it if we're in a SCOREBOARD_FILE because it'll cause
	    * corruption too easily.
	    */
	ap_sync_scoreboard_image();
	for (i = 0; i < ap_daemons_limit; ++i) {
	    if (ap_scoreboard_image->servers[i].status != SERVER_DEAD) {
		ap_scoreboard_image->servers[i].status = SERVER_GRACEFUL;
	    }
	}
#endif
    }
    else {
	/* Kill 'em off */
	if (ap_killpg(getpgrp(), SIGHUP) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "killpg SIGHUP");
	}
	reclaim_child_processes(0);		/* Not when just starting up */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, server_conf,
		    "SIGHUP received.  Attempting to restart");
    }

    if (!is_graceful) {
	ap_restart_time = time(NULL);
    }

    return 0;
}

static void prefork_pre_config(ap_context_t *p, ap_context_t *plog, ap_context_t *ptemp)
{
    static int restart_num = 0;

    one_process = !!getenv("ONE_PROCESS");

    /* sigh, want this only the second time around */
    if (restart_num++ == 1) {
	is_graceful = 0;

	if (!one_process) {
	    unixd_detach();
	}

	my_pid = getpid();
    }

    unixd_pre_config();
    ap_listen_pre_config();
    ap_daemons_to_start = DEFAULT_START_DAEMON;
    ap_daemons_min_free = DEFAULT_MIN_FREE_DAEMON;
    ap_daemons_max_free = DEFAULT_MAX_FREE_DAEMON;
    ap_daemons_limit = HARD_SERVER_LIMIT;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_scoreboard_fname = DEFAULT_SCOREBOARD;
    ap_lock_fname = DEFAULT_LOCKFILE;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    ap_extended_status = 0;

    ap_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));
}

static void prefork_hooks(void)
{
    ap_hook_pre_config(prefork_pre_config,NULL,NULL,HOOK_MIDDLE);
    INIT_SIGLIST();
#ifdef AUX3
    (void) set42sig();
#endif
    /* TODO: set one_process properly */ one_process = 0;
}

static const char *set_pidfile(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (cmd->server->is_virtual) {
	return "PidFile directive not allowed in <VirtualHost>";
    }
    ap_pid_fname = arg;
    return NULL;
}

static const char *set_scoreboard(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_scoreboard_fname = arg;
    return NULL;
}

static const char *set_lockfile(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_lock_fname = arg;
    return NULL;
}

static const char *set_daemons_to_start(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_to_start = atoi(arg);
    return NULL;
}

static const char *set_min_free_servers(cmd_parms *cmd, void *dummy, char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_min_free = atoi(arg);
    if (ap_daemons_min_free <= 0) {
       fprintf(stderr, "WARNING: detected MinSpareServers set to non-positive.\n");
       fprintf(stderr, "Resetting to 1 to avoid almost certain Apache failure.\n");
       fprintf(stderr, "Please read the documentation.\n");
       ap_daemons_min_free = 1;
    }
       
    return NULL;
}

static const char *set_max_free_servers(cmd_parms *cmd, void *dummy, char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_max_free = atoi(arg);
    return NULL;
}

static const char *set_server_limit (cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_limit = atoi(arg);
    if (ap_daemons_limit > HARD_SERVER_LIMIT) {
       fprintf(stderr, "WARNING: MaxClients of %d exceeds compile time limit "
           "of %d servers,\n", ap_daemons_limit, HARD_SERVER_LIMIT);
       fprintf(stderr, " lowering MaxClients to %d.  To increase, please "
           "see the\n", HARD_SERVER_LIMIT);
       fprintf(stderr, " HARD_SERVER_LIMIT define in src/include/httpd.h.\n");
       ap_daemons_limit = HARD_SERVER_LIMIT;
    } 
    else if (ap_daemons_limit < 1) {
	fprintf(stderr, "WARNING: Require MaxClients > 0, setting to 1\n");
	ap_daemons_limit = 1;
    }
    return NULL;
}

static const char *set_max_requests(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_max_requests_per_child = atoi(arg);

    return NULL;
}

static const char *set_coredumpdir (cmd_parms *cmd, void *dummy, char *arg) 
{
    struct stat finfo;
    const char *fname;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    fname = ap_server_root_relative(cmd->pool, arg);
    /* ZZZ change this to the AP func FileInfo*/
    if ((stat(fname, &finfo) == -1) || !S_ISDIR(finfo.st_mode)) {
	return ap_pstrcat(cmd->pool, "CoreDumpDirectory ", fname, 
			  " does not exist or is not a directory", NULL);
    }
    ap_cpystrn(ap_coredump_dir, fname, sizeof(ap_coredump_dir));
    return NULL;
}

/* there are no threads in the prefork model, so the mutexes are
   nops. */
/* TODO: make these #defines to eliminate the function call */

struct ap_thread_mutex {
    int dummy;
};

API_EXPORT(ap_thread_mutex *) ap_thread_mutex_new(void)
{
    return malloc(sizeof(ap_thread_mutex));
}

API_EXPORT(void) ap_thread_mutex_lock(ap_thread_mutex *mtx)
{
}

API_EXPORT(void) ap_thread_mutex_unlock(ap_thread_mutex *mtx)
{
}

API_EXPORT(void) ap_thread_mutex_destroy(ap_thread_mutex *mtx)
{
    free(mtx);
}


static const command_rec prefork_cmds[] = {
UNIX_DAEMON_COMMANDS
LISTEN_COMMANDS
{ "PidFile", set_pidfile, NULL, RSRC_CONF, TAKE1,
    "A file for logging the server process ID"},
{ "ScoreBoardFile", set_scoreboard, NULL, RSRC_CONF, TAKE1,
    "A file for Apache to maintain runtime process management information"},
{ "LockFile", set_lockfile, NULL, RSRC_CONF, TAKE1,
    "The lockfile used when Apache needs to lock the accept() call"},
{ "StartServers", set_daemons_to_start, NULL, RSRC_CONF, TAKE1,
  "Number of child processes launched at server startup" },
{ "MinSpareServers", set_min_free_servers, NULL, RSRC_CONF, TAKE1,
  "Minimum number of idle children, to handle request spikes" },
{ "MaxSpareServers", set_max_free_servers, NULL, RSRC_CONF, TAKE1,
  "Maximum number of idle children" },
{ "MaxClients", set_server_limit, NULL, RSRC_CONF, TAKE1,
  "Maximum number of children alive at the same time" },
{ "MaxRequestsPerChild", set_max_requests, NULL, RSRC_CONF, TAKE1,
  "Maximum number of requests a particular child serves before dying." },
{ "CoreDumpDirectory", set_coredumpdir, NULL, RSRC_CONF, TAKE1,
  "The location of the directory Apache changes to before dumping core" },
{ NULL }
};

module MODULE_VAR_EXPORT mpm_prefork_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    prefork_cmds,		/* command ap_table_t */
    NULL,			/* handlers */
    prefork_hooks,		/* register hooks */
};
