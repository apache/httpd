#include "ap_config.h"
#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "http_config.h"
#include "unixd.h"
#include "http_conf_globals.h"
#include "mpm_status.h"
#include "mpmt_pthread.h"
#include "scoreboard.h"
#include <sys/types.h>

scoreboard *ap_scoreboard_image = NULL;
API_VAR_IMPORT char *ap_scoreboard_fname;
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

void reinit_scoreboard(ap_context_t *p)
{
    ap_assert(!ap_scoreboard_image);
    ap_scoreboard_image = (scoreboard *) malloc(SCOREBOARD_SIZE);
    if (ap_scoreboard_image == NULL) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "Ouch! Out of memory reiniting scoreboard!");
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
#if APR_HAS_SHARED_MEMORY
#include "apr_shmem.h"

static ap_shmem_t *scoreboard_shm = NULL;

ap_status_t cleanup_shared_mem(void *d)
{
    mm_free(scoreboard_shm, ap_scoreboard_image);
    ap_scoreboard_image = NULL;
    ap_shm_destroy(scoreboard_shm);
}

void setup_shared_mem(ap_context_t *p)
{
    char buf[512];
    const char *fname;

    fname = ap_server_root_relative(p, ap_scoreboard_fname);
    if (ap_shm_init(&scoreboard_shm, SCOREBOARD_SIZE + 40, fname) != APR_SUCCESS) {
        ap_snprintf(buf, sizeof(buf), "%s: could not open(create) scoreboard",
                    ap_server_argv0);
        perror(buf);
        exit(APEXIT_INIT);
    }
    ap_scoreboard_image = ap_shm_malloc(scoreboard_shm, SCOREBOARD_SIZE);
    if (ap_scoreboard_image == NULL) {
        ap_snprintf(buf, sizeof(buf), "%s: cannot allocate scoreboard",
                    ap_server_argv0);
        perror(buf);
        ap_shm_destroy(scoreboard_shm);
        exit(APEXIT_INIT);
    }
    ap_register_cleanup(p, NULL, cleanup_shared_mem, ap_null_cleanup);
    ap_scoreboard_image->global.running_generation = 0;
}

void reopen_scoreboard(ap_context_t *p)
{
}
#endif   /* APR_SHARED_MEM */

/* Called by parent process */
void reinit_scoreboard(ap_context_t *p)
{
    int running_gen = 0;
    if (ap_scoreboard_image)
	running_gen = ap_scoreboard_image->global.running_generation;
    if (ap_scoreboard_image == NULL) {
        setup_shared_mem(p);
    }
    memset(ap_scoreboard_image, 0, SCOREBOARD_SIZE);
    ap_scoreboard_image->global.running_generation = running_gen;
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

#ifdef HAVE_TIMES
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
      /*ss->start_time = GetCurrentTime(); return time in uS since the 
	epoch. Some platforms do not support gettimeofday. Create a routine 
	to get the current time is some useful units. */
        if (gettimeofday(&ss->start_time, (struct timezone *) 0) < 0) {
            ss->start_time.tv_sec = ss->start_time.tv_usec = 0L;
        }
    }
    else if (status == STOP_PREQUEST) {
      /*ss->stop_time = GetCurrentTime(); 
	return time in uS since the epoch */
        
        if (gettimeofday(&ss->stop_time, (struct timezone *) 0) < 0) {
            ss->start_time.tv_sec = ss->start_time.tv_usec = 0L;
        }
    }
    put_scoreboard_info(child_num, thread_num, ss);
}

/* Stub functions until this MPM supports the connection status API */

API_EXPORT(void) ap_update_connection_status(long conn_id, const char *key, \
                                             const char *value)
{
    /* NOP */
}

API_EXPORT(void) ap_reset_connection_status(long conn_id)
{
    /* NOP */
}

