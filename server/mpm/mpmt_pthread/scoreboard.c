#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "http_conf_globals.h"
#include "scoreboard.h"
#ifdef USE_SHMGET_SCOREBOARD
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#endif

#ifdef USE_OS2_SCOREBOARD
    /* Add MMAP style functionality to OS/2 */
#define INCL_DOSMEMMGR
#define INCL_DOSEXCEPTIONS
#define INCL_DOSSEMAPHORES
#include <os2.h>
#include <umalloc.h>
#include <stdio.h>
caddr_t create_shared_heap(const char *, size_t);
caddr_t get_shared_heap(const char *);
#endif

scoreboard *ap_scoreboard_image = NULL;
static char *ap_server_argv0=NULL;
extern pool * pconf;

/*****************************************************************
 *
 * Dealing with the scoreboard... a lot of these variables are global
 * only to avoid getting clobbered by the longjmp() that happens when
 * a hard timeout expires...
 *
 * We begin with routines which deal with the file itself... 
 */

#ifdef MULTITHREAD
/*
 * In the multithreaded mode, have multiple threads - not multiple
 * processes that need to talk to each other. Just use a simple
 * malloc. But let the routines that follow, think that you have
 * shared memory (so they use memcpy etc.)
 */

void reinit_scoreboard(pool *p)
{
    ap_assert(!ap_scoreboard_image);
    ap_scoreboard_image = (scoreboard *) malloc(SCOREBOARD_SIZE);
    if (ap_scoreboard_image == NULL) {
        fprintf(stderr, "Ouch! Out of memory reiniting scoreboard!\n");
    }
    memset(ap_scoreboard_image, 0, SCOREBOARD_SIZE);
}

void cleanup_scoreboard(void)
{
    ap_assert(ap_scoreboard_image);
    free(ap_scoreboard_image);
    ap_scoreboard_image = NULL;
}

API_EXPORT(void) ap_sync_scoreboard_image(void)
{
}


#else /* MULTITHREAD */
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

static void setup_shared_mem(pool *p)
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

API_EXPORT(void) reopen_scoreboard(pool *p)
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

static void setup_shared_mem(pool *p)
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

API_EXPORT(void) reopen_scoreboard(pool *p)
{
}

#elif defined(USE_MMAP_SCOREBOARD)

static void setup_shared_mem(pool *p)
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

API_EXPORT(void) reopen_scoreboard(pool *p)
{
}

#elif defined(USE_SHMGET_SCOREBOARD)
static key_t shmkey = IPC_PRIVATE;
static int shmid = -1;

static void setup_shared_mem(pool *p)
{
    struct shmid_ds shmbuf;
    const server_rec * server_conf = ap_get_server_conf();
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

API_EXPORT(void) reopen_scoreboard(pool *p)
{
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

API_EXPORT(void) reopen_scoreboard(pool *p)
{
    if (scoreboard_fd != -1)
	ap_pclosef(p, scoreboard_fd);

    scoreboard_fd = ap_popenf(p, ap_scoreboard_fname, O_CREAT | O_BINARY | O_RDWR, 0666);
    if (scoreboard_fd == -1) {
	perror(ap_scoreboard_fname);
	fprintf(stderr, "Cannot open scoreboard file:\n");
	clean_child_exit(1);
    }
}
#endif

/* Called by parent process */
void reinit_scoreboard(pool *p)
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

#endif /* MULTITHREAD */

API_EXPORT(int) ap_exists_scoreboard_image(void)
{
    return (ap_scoreboard_image ? 1 : 0);
}

static ap_inline void put_scoreboard_info(int child_num, int thread_num, 
				       thread_score *new_score_rec)
{
    /* XXX - needs to be fixed to account for threads */
#ifdef SCOREBOARD_FILE
    lseek(scoreboard_fd, (long) child_num * sizeof(thread_score), 0);
    force_write(scoreboard_fd, new_score_rec, sizeof(thread_score));
#endif
}

void update_scoreboard_global(void)
{
#ifdef SCOREBOARD_FILE
    lseek(scoreboard_fd,
	  (char *) &ap_scoreboard_image->global -(char *) ap_scoreboard_image, 0);
    force_write(scoreboard_fd, &ap_scoreboard_image->global,
		sizeof ap_scoreboard_image->global);
#endif
}

void increment_counts(int child_num, int thread_num, request_rec *r)
{
    long int bs = 0;
    thread_score *ss;

    ss = &ap_scoreboard_image->servers[child_num][thread_num];

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

    put_scoreboard_info(child_num, thread_num, ss);

}

API_EXPORT(int) find_child_by_pid(int pid)
{
    int i;
    int max_daemons_limit = ap_get_max_daemons();

    for (i = 0; i < max_daemons_limit; ++i)
	if (ap_scoreboard_image->parent[i].pid == pid)
	    return i;

    return -1;
}

int ap_update_child_status(int child_num, int thread_num, int status, request_rec *r)
{
    int old_status;
    thread_score *ss;
    parent_score *ps;

    if (child_num < 0)
	return -1;

    ss = &ap_scoreboard_image->servers[child_num][thread_num];
    old_status = ss->status;
    ss->status = status;

    ps = &ap_scoreboard_image->parent[child_num];
    
    if ((status == SERVER_READY  || status == SERVER_ACCEPTING)
	&& old_status == SERVER_STARTING) {
        ss->tid = pthread_self();
	ps->worker_threads = ap_threads_per_child;
	ps->acceptor_threads = ap_acceptors_per_child;
    }

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
    
    put_scoreboard_info(child_num, thread_num, ss);
    return old_status;
}

void ap_time_process_request(int child_num, int thread_num, int status)
{
    thread_score *ss;

    if (child_num < 0)
	return;

    ss = &ap_scoreboard_image->servers[child_num][thread_num];

    if (status == START_PREQUEST) {
      /*ss->start_time = GetCurrentTime(); ZZZ return time in uS since the 
	epoch. Some platforms do not support gettimeofday. Create a routine 
	to get the current time is some useful units. */
        if (gettimeofday(&ss->start_time, (struct timezone *) 0) < 0) {
            ss->start_time.tv_sec = ss->start_time.tv_usec = 0L;
        }
    }
    else if (status == STOP_PREQUEST) {
      /*ss->stop_time = GetCurrentTime(); 
	ZZZ return time in uS since the epoch */
        
        if (gettimeofday(&ss->stop_time, (struct timezone *) 0) < 0) {
            ss->start_time.tv_sec = ss->start_time.tv_usec = 0L;
        }
    }
    put_scoreboard_info(child_num, thread_num, ss);
}
