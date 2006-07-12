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

/*
time-sem.c has the basics of the semaphores we use in http_main.c.  It's
intended for timing differences between various methods on an
architecture.  In practice we've found many things affect which semaphore
to be used:

    - NFS filesystems absolutely suck for fcntl() and flock()

    - uslock absolutely sucks on single-processor IRIX boxes, but
        absolutely rocks on multi-processor boxes.  The converse
        is true for fcntl.  sysvsem seems a moderate balance.

    - Under Solaris you can't have too many processes use SEM_UNDO, there
        might be a tuneable somewhere that increases the limit from 29.
        We're not sure what the tunable is, so there's a define
        NO_SEM_UNDO which can be used to simulate us trapping/blocking
        signals to be able to properly release the semaphore on a clean
        child death.  You'll also need to define NEED_UNION_SEMUN
        under solaris.

You'll need to define USE_SHMGET_SCOREBOARD if anonymous shared mmap()
doesn't work on your system (i.e. linux).

argv[1] is the #children, argv[2] is the #iterations per child

You should run each over many different #children inputs, and choose
#iter such that the program runs for at least a second or so... or even
longer depending on your patience.

compile with:

gcc -o time-FCNTL -Wall -O time-sem.c -DUSE_FCNTL_SERIALIZED_ACCEPT
gcc -o time-FLOCK -Wall -O time-sem.c -DUSE_FLOCK_SERIALIZED_ACCEPT
gcc -o time-SYSVSEM -Wall -O time-sem.c -DUSE_SYSVSEM_SERIALIZED_ACCEPT
gcc -o time-SYSVSEM2 -Wall -O time-sem.c -DUSE_SYSVSEM_SERIALIZED_ACCEPT -DNO_SEM_UNDO
gcc -o time-PTHREAD -Wall -O time-sem.c -DUSE_PTHREAD_SERIALIZED_ACCEPT -lpthread
gcc -o time-USLOCK -Wall -O time-sem.c -DUSE_USLOCK_SERIALIZED_ACCEPT

not all versions work on all systems.
*/

#include <errno.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>

#if defined(USE_FCNTL_SERIALIZED_ACCEPT)

static struct flock lock_it;
static struct flock unlock_it;

static int fcntl_fd=-1;

#define accept_mutex_child_init()
#define accept_mutex_cleanup()

/*
 * Initialize mutex lock.
 * Must be safe to call this on a restart.
 */
void
accept_mutex_init(void)
{

    lock_it.l_whence = SEEK_SET;   /* from current point */
    lock_it.l_start  = 0;          /* -"- */
    lock_it.l_len    = 0;          /* until end of file */
    lock_it.l_type   = F_WRLCK;    /* set exclusive/write lock */
    lock_it.l_pid    = 0;          /* pid not actually interesting */
    unlock_it.l_whence = SEEK_SET; /* from current point */
    unlock_it.l_start  = 0;        /* -"- */
    unlock_it.l_len    = 0;        /* until end of file */
    unlock_it.l_type   = F_UNLCK;  /* set exclusive/write lock */
    unlock_it.l_pid    = 0;        /* pid not actually interesting */

    printf("opening test-lock-thing in current directory\n");
    fcntl_fd = open("test-lock-thing", O_CREAT | O_WRONLY | O_EXCL, 0644);
    if (fcntl_fd == -1)
    {
        perror ("open");
        fprintf (stderr, "Cannot open lock file: %s\n", "test-lock-thing");
        exit (1);
    }
    unlink("test-lock-thing");
}

void accept_mutex_on(void)
{
    int ret;

    while ((ret = fcntl(fcntl_fd, F_SETLKW, &lock_it)) < 0 && errno == EINTR)
        continue;

    if (ret < 0) {
        perror ("fcntl lock_it");
        exit(1);
    }
}

void accept_mutex_off(void)
{
    if (fcntl (fcntl_fd, F_SETLKW, &unlock_it) < 0)
    {
        perror ("fcntl unlock_it");
        exit(1);
    }
}

#elif defined(USE_FLOCK_SERIALIZED_ACCEPT)

#include <sys/file.h>

static int flock_fd=-1;

#define FNAME "test-lock-thing"

/*
 * Initialize mutex lock.
 * Must be safe to call this on a restart.
 */
void accept_mutex_init(void)
{

    printf("opening " FNAME " in current directory\n");
    flock_fd = open(FNAME, O_CREAT | O_WRONLY | O_EXCL, 0644);
    if (flock_fd == -1)
    {
        perror ("open");
        fprintf (stderr, "Cannot open lock file: %s\n", "test-lock-thing");
        exit (1);
    }
}

void accept_mutex_child_init(void)
{
    flock_fd = open(FNAME, O_WRONLY, 0600);
    if (flock_fd == -1) {
        perror("open");
        exit(1);
    }
}

void accept_mutex_cleanup(void)
{
    unlink(FNAME);
}

void accept_mutex_on(void)
{
    int ret;

    while ((ret = flock(flock_fd, LOCK_EX)) < 0 && errno == EINTR)
        continue;

    if (ret < 0) {
        perror ("flock(LOCK_EX)");
        exit(1);
    }
}

void accept_mutex_off(void)
{
    if (flock (flock_fd, LOCK_UN) < 0)
    {
        perror ("flock(LOCK_UN)");
        exit(1);
    }
}

#elif defined (USE_SYSVSEM_SERIALIZED_ACCEPT)

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

static   int sem_id = -1;
#ifdef NO_SEM_UNDO
static sigset_t accept_block_mask;
static sigset_t accept_previous_mask;
#endif

#define accept_mutex_child_init()
#define accept_mutex_cleanup()

void accept_mutex_init(void)
{
#ifdef NEED_UNION_SEMUN
    /* believe it or not, you need to define this under solaris */
    union semun {
        int val;
        struct semid_ds *buf;
        ushort *array;
    };
#endif

    union semun ick;

    sem_id = semget(999, 1, IPC_CREAT | 0666);
    if (sem_id < 0) {
       perror ("semget");
       exit (1);
    }
    ick.val = 1;
    if (semctl(sem_id, 0, SETVAL, ick) < 0) {
       perror ("semctl");
        exit(1);
    }
#ifdef NO_SEM_UNDO
    sigfillset(&accept_block_mask);
    sigdelset(&accept_block_mask, SIGHUP);
    sigdelset(&accept_block_mask, SIGTERM);
    sigdelset(&accept_block_mask, SIGUSR1);
#endif
}

void accept_mutex_on()
{
    struct sembuf op;

#ifdef NO_SEM_UNDO
    if (sigprocmask(SIG_BLOCK, &accept_block_mask, &accept_previous_mask)) {
        perror("sigprocmask(SIG_BLOCK)");
        exit (1);
    }
    op.sem_flg = 0;
#else
    op.sem_flg = SEM_UNDO;
#endif
    op.sem_num = 0;
    op.sem_op  = -1;
    if (semop(sem_id, &op, 1) < 0) {
        perror ("accept_mutex_on");
        exit (1);
    }
}

void accept_mutex_off()
{
    struct sembuf op;

    op.sem_num = 0;
    op.sem_op  = 1;
#ifdef NO_SEM_UNDO
    op.sem_flg = 0;
#else
    op.sem_flg = SEM_UNDO;
#endif
    if (semop(sem_id, &op, 1) < 0) {
        perror ("accept_mutex_off");
        exit (1);
    }
#ifdef NO_SEM_UNDO
    if (sigprocmask(SIG_SETMASK, &accept_previous_mask, NULL)) {
        perror("sigprocmask(SIG_SETMASK)");
        exit (1);
    }
#endif
}

#elif defined (USE_PTHREAD_SERIALIZED_ACCEPT)

/* note: pthread mutexes aren't released on child death, hence the
 * signal goop ... in a real implementation we'd do special things
 * during hup, term, usr1.
 */

#include <pthread.h>

static pthread_mutex_t *mutex;
static sigset_t accept_block_mask;
static sigset_t accept_previous_mask;

#define accept_mutex_child_init()
#define accept_mutex_cleanup()

void accept_mutex_init(void)
{
    pthread_mutexattr_t mattr;
    int fd;

    fd = open ("/dev/zero", O_RDWR);
    if (fd == -1) {
        perror ("open(/dev/zero)");
        exit (1);
    }
    mutex = (pthread_mutex_t *)mmap ((caddr_t)0, sizeof (*mutex),
                    PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (mutex == (void *)(caddr_t)-1) {
        perror ("mmap");
        exit (1);
    }
    close (fd);
    if (pthread_mutexattr_init(&mattr)) {
        perror ("pthread_mutexattr_init");
        exit (1);
    }
    if (pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED)) {
        perror ("pthread_mutexattr_setpshared");
        exit (1);
    }
    if (pthread_mutex_init(mutex, &mattr)) {
        perror ("pthread_mutex_init");
        exit (1);
    }
    sigfillset(&accept_block_mask);
    sigdelset(&accept_block_mask, SIGHUP);
    sigdelset(&accept_block_mask, SIGTERM);
    sigdelset(&accept_block_mask, SIGUSR1);
}

void accept_mutex_on()
{
    if (sigprocmask(SIG_BLOCK, &accept_block_mask, &accept_previous_mask)) {
        perror("sigprocmask(SIG_BLOCK)");
        exit (1);
    }
    if (pthread_mutex_lock (mutex)) {
        perror ("pthread_mutex_lock");
        exit (1);
    }
}

void accept_mutex_off()
{
    if (pthread_mutex_unlock (mutex)) {
        perror ("pthread_mutex_unlock");
        exit (1);
    }
    if (sigprocmask(SIG_SETMASK, &accept_previous_mask, NULL)) {
        perror("sigprocmask(SIG_SETMASK)");
        exit (1);
    }
}

#elif defined (USE_USLOCK_SERIALIZED_ACCEPT)

#include <ulocks.h>

static usptr_t *us = NULL;
static ulock_t uslock = NULL;

#define accept_mutex_child_init()
#define accept_mutex_cleanup()

void accept_mutex_init(void)
{
    ptrdiff_t old;
    /* default is 8 */
#define CONF_INITUSERS_MAX 15
    if ((old = usconfig(CONF_INITUSERS, CONF_INITUSERS_MAX)) == -1) {
        perror("usconfig");
        exit(-1);
    }
    if ((old = usconfig(CONF_LOCKTYPE, US_NODEBUG)) == -1) {
        perror("usconfig");
        exit(-1);
    }
    if ((old = usconfig(CONF_ARENATYPE, US_SHAREDONLY)) == -1) {
        perror("usconfig");
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
void accept_mutex_on()
{
    switch(ussetlock(uslock)) {
        case 1:
            /* got lock */
            break;
        case 0:
            fprintf(stderr, "didn't get lock\n");
            exit(-1);
        case -1:
            perror("ussetlock");
            exit(-1);
    }
}
void accept_mutex_off()
{
    if (usunsetlock(uslock) == -1) {
        perror("usunsetlock");
        exit(-1);
    }
}
#endif


#ifndef USE_SHMGET_SCOREBOARD
static void *get_shared_mem(apr_size_t size)
{
    void *result;

    /* allocate shared memory for the shared_counter */
    result = (unsigned long *)mmap ((caddr_t)0, size,
                    PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    if (result == (void *)(caddr_t)-1) {
        perror ("mmap");
        exit (1);
    }
    return result;
}
#else
#include <sys/types.h>
#include <sys/ipc.h>
#ifdef HAVE_SYS_MUTEX_H
#include <sys/mutex.h>
#endif
#include <sys/shm.h>

static void *get_shared_mem(apr_size_t size)
{
    key_t shmkey = IPC_PRIVATE;
    int shmid = -1;
    void *result;
#ifdef MOVEBREAK
    char *obrk;
#endif

    if ((shmid = shmget(shmkey, size, IPC_CREAT | SHM_R | SHM_W)) == -1) {
        perror("shmget");
        exit(1);
    }

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
        perror("sbrk");
    }
#endif

#define BADSHMAT  ((void *)(-1))
    if ((result = shmat(shmid, 0, 0)) == BADSHMAT) {
        perror("shmat");
    }
    /*
     * We must avoid leaving segments in the kernel's
     * (small) tables.
     */
    if (shmctl(shmid, IPC_RMID, NULL) != 0) {
        perror("shmctl(IPC_RMID)");
    }
    if (result == BADSHMAT)  /* now bailout */
        exit(1);

#ifdef MOVEBREAK
    if (obrk == (char *) -1)
        return;  /* nothing else to do */
    if (sbrk(-(MOVEBREAK)) == (char *) -1) {
        perror("sbrk 2");
    }
#endif
    return result;
}
#endif

#ifdef _POSIX_PRIORITY_SCHEDULING
/* don't ask */
#define _P __P
#include <sched.h>
#define YIELD  sched_yield()
#else
#define YIELD  do { struct timeval zero; zero.tv_sec = zero.tv_usec = 0; select(0,0,0,0,&zero); } while(0)
#endif

void main (int argc, char **argv)
{
    int num_iter;
    int num_child;
    int i;
    struct timeval first;
    struct timeval last;
    long ms;
    int pid;
    unsigned long *shared_counter;

    if (argc != 3) {
        fprintf (stderr, "Usage: time-sem num-child num iter\n");
        exit (1);
    }

    num_child = atoi (argv[1]);
    num_iter = atoi (argv[2]);

    /* allocate shared memory for the shared_counter */
    shared_counter = get_shared_mem(sizeof(*shared_counter));

    /* initialize counter to 0 */
    *shared_counter = 0;

    accept_mutex_init ();

    /* parent grabs mutex until done spawning children */
    accept_mutex_on ();

    for (i = 0; i < num_child; ++i) {
        pid = fork();
        if (pid == 0) {
            /* child, do our thing */
            accept_mutex_child_init();
            for (i = 0; i < num_iter; ++i) {
                unsigned long tmp;

                accept_mutex_on ();
                tmp = *shared_counter;
                YIELD;
                *shared_counter = tmp + 1;
                accept_mutex_off ();
            }
            exit (0);
        } else if (pid == -1) {
            perror ("fork");
            exit (1);
        }
    }

    /* a quick test to see that nothing is screwed up */
    if (*shared_counter != 0) {
        puts ("WTF! shared_counter != 0 before the children have been started!");
        exit (1);
    }

    gettimeofday (&first, NULL);
    /* launch children into action */
    accept_mutex_off ();
    for (i = 0; i < num_child; ++i) {
        if (wait(NULL) == -1) {
            perror ("wait");
        }
    }
    gettimeofday (&last, NULL);

    if (*shared_counter != num_child * num_iter) {
        printf ("WTF! shared_counter != num_child * num_iter!\n"
                "shared_counter = %lu\nnum_child = %d\nnum_iter=%d\n",
                *shared_counter,
                num_child, num_iter);
    }

    last.tv_sec -= first.tv_sec;
    ms = last.tv_usec - first.tv_usec;
    if (ms < 0) {
        --last.tv_sec;
        ms += 1000000;
    }
    last.tv_usec = ms;
    printf ("%8lu.%06lu\n", last.tv_sec, last.tv_usec);

    accept_mutex_cleanup();

    exit(0);
}

