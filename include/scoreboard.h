/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
 * reserved.
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
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#ifndef APACHE_SCOREBOARD_H
#define APACHE_SCOREBOARD_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_SYS_TIMES_H
#include <sys/time.h>
#include <sys/times.h>
#elif defined(TPF)
#include <time.h>
#endif

#include "ap_config.h"
#include "apr_hooks.h"
#include "apr_thread_proc.h"
#include "apr_portable.h"
#include "apr_shm.h"

/* Scoreboard file, if there is one */
#ifndef DEFAULT_SCOREBOARD
#define DEFAULT_SCOREBOARD "logs/apache_runtime_status"
#endif

/* Scoreboard info on a process is, for now, kept very brief --- 
 * just status value and pid (the latter so that the caretaker process
 * can properly update the scoreboard when a process dies).  We may want
 * to eventually add a separate set of long_score structures which would
 * give, for each process, the number of requests serviced, and info on
 * the current, or most recent, request.
 *
 * Status values:
 */

#define SERVER_DEAD 0
#define SERVER_STARTING 1	/* Server Starting up */
#define SERVER_READY 2		/* Waiting for connection (or accept() lock) */
#define SERVER_BUSY_READ 3	/* Reading a client request */
#define SERVER_BUSY_WRITE 4	/* Processing a client request */
#define SERVER_BUSY_KEEPALIVE 5	/* Waiting for more requests via keepalive */
#define SERVER_BUSY_LOG 6	/* Logging the request */
#define SERVER_BUSY_DNS 7	/* Looking up a hostname */
#define SERVER_CLOSING 8	/* Closing the connection */
#define SERVER_GRACEFUL 9	/* server is gracefully finishing request */
#define SERVER_IDLE_KILL 10     /* Server is cleaning up idle children. */
#define SERVER_NUM_STATUS 11	/* number of status settings */

/* Type used for generation indicies.  Startup and every restart cause a
 * new generation of children to be spawned.  Children within the same
 * generation share the same configuration information -- pointers to stuff
 * created at config time in the parent are valid across children.  However,
 * this can't work effectively with non-forked architectures.  So while the
 * arrays in the scoreboard never change between the parent and forked
 * children, so they do not require shm storage, the contents of the shm
 * may contain no pointers.
 */
typedef int ap_generation_t;

/* Is the scoreboard shared between processes or not? 
 * Set by the MPM when the scoreboard is created.
 */
typedef enum {
    SB_NOT_SHARED = 1,
    SB_SHARED = 2
} ap_scoreboard_e;

#define SB_WORKING  0  /* The server is busy and the child is useful. */
#define SB_IDLE_DIE 1  /* The server is idle and the child is superfluous. */
                       /*   The child should check for this and exit gracefully. */

/* stuff which is worker specific */
/***********************WARNING***************************************/
/* These are things that are used by mod_status. Do not put anything */
/*   in here that you cannot live without. This structure will not   */
/*   be available if mod_status is not loaded.                       */
/*********************************************************************/
typedef struct worker_score worker_score;

struct worker_score {
    int thread_num;
#if APR_HAS_THREADS
    apr_os_thread_t tid;
#endif
    unsigned char status;
    unsigned long access_count;
    apr_off_t     bytes_served;
    unsigned long my_access_count;
    apr_off_t     my_bytes_served;
    apr_off_t     conn_bytes;
    unsigned short conn_count;
    apr_time_t start_time;
    apr_time_t stop_time;
#ifdef HAVE_TIMES
    struct tms times;
#endif
    apr_time_t last_used;
    char client[32];		/* Keep 'em small... */
    char request[64];		/* We just want an idea... */
    char vhost[32];	        /* What virtual host is being accessed? */
};

typedef struct {
    int             server_limit;
    int             thread_limit;
    ap_scoreboard_e sb_type;
    ap_generation_t running_generation;	/* the generation of children which
                                         * should still be serving requests. */
    apr_time_t restart_time;
} global_score;

/* stuff which the parent generally writes and the children rarely read */
typedef struct process_score process_score;
struct process_score{
    pid_t pid;
    ap_generation_t generation;	/* generation of this child */
    ap_scoreboard_e sb_type;
    int quiescing;          /* the process whose pid is stored above is
                             * going down gracefully
                             */
};

/* Scoreboard is now in 'local' memory, since it isn't updated once created,
 * even in forked architectures.  Child created-processes (non-fork) will
 * set up these indicies into the (possibly relocated) shmem records.
 */
typedef struct {
    global_score *global;
    process_score *parent;
    worker_score **servers;
} scoreboard;

typedef struct ap_sb_handle_t ap_sb_handle_t;

AP_DECLARE(int) ap_exists_scoreboard_image(void);
AP_DECLARE(void) ap_increment_counts(ap_sb_handle_t *sbh, request_rec *r);

int ap_create_scoreboard(apr_pool_t *p, ap_scoreboard_e t);
apr_status_t ap_reopen_scoreboard(apr_pool_t *p, apr_shm_t **shm, int detached);
void ap_init_scoreboard(void *shared_score);
AP_DECLARE(int) ap_calc_scoreboard_size(void);
apr_status_t ap_cleanup_scoreboard(void *d);

AP_DECLARE(void) ap_create_sb_handle(ap_sb_handle_t **new_sbh, apr_pool_t *p,
                                     int child_num, int thread_num);
    
AP_DECLARE(int) find_child_by_pid(apr_proc_t *pid);
AP_DECLARE(int) ap_update_child_status(ap_sb_handle_t *sbh, int status, request_rec *r);
AP_DECLARE(int) ap_update_child_status_from_indexes(int child_num, int thread_num,
                                                    int status, request_rec *r);
void ap_time_process_request(int child_num, int thread_num, int status);

AP_DECLARE(worker_score *) ap_get_scoreboard_worker(int x, int y);
AP_DECLARE(process_score *) ap_get_scoreboard_process(int x);
AP_DECLARE(global_score *) ap_get_scoreboard_global(void);

AP_DECLARE_DATA extern scoreboard *ap_scoreboard_image;
AP_DECLARE_DATA extern const char *ap_scoreboard_fname;
AP_DECLARE_DATA extern int ap_extended_status;

AP_DECLARE_DATA extern ap_generation_t volatile ap_my_generation;

/* Hooks */
/**
  * Hook for post scoreboard creation, pre mpm.
  * @param p       Apache pool to allocate from.
  * @param sb_type 
  * @ingroup hooks
  * @return OK or DECLINE on success; anything else is a error
  */  
AP_DECLARE_HOOK(int, pre_mpm, (apr_pool_t *p, ap_scoreboard_e sb_type))

/* for time_process_request() in http_main.c */
#define START_PREQUEST 1
#define STOP_PREQUEST  2

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_SCOREBOARD_H */
