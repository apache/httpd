/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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

#include "mpm_default.h"	/* For HARD_.*_LIMIT */
#include "apr_thread_proc.h"

/*The optimized timeout code only works if we're not using a scoreboard file*/
#if defined(AP_USE_MEM_BASED_SCOREBOARD)
#define OPTIMIZE_TIMEOUTS
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
#define SERVER_GRACEFUL 8	/* server is gracefully finishing request */
#define SERVER_ACCEPTING 9	/* thread is accepting connections */
#define SERVER_QUEUEING	10      /* thread is putting connection on the queue */
#define SERVER_NUM_STATUS 11	/* number of status settings */

/* A "virtual time" is simply a counter that indicates that a child is
 * making progress.  The parent checks up on each child, and when they have
 * made progress it resets the last_rtime element.  But when the child hasn't
 * made progress in a time that's roughly timeout_len seconds long, it is
 * sent a SIGALRM.
 *
 * vtime is an optimization that is used only when the scoreboard is in
 * shared memory (it's not easy/feasible to do it in a scoreboard file).
 * The essential observation is that timeouts rarely occur, the vast majority
 * of hits finish before any timeout happens.  So it really sucks to have to
 * ask the operating system to set up and destroy alarms many times during
 * a request.
 */
typedef unsigned vtime_t;

/* Type used for generation indicies.  Startup and every restart cause a
 * new generation of children to be spawned.  Children within the same
 * generation share the same configuration information -- pointers to stuff
 * created at config time in the parent are valid across children.  For
 * example, the vhostrec pointer in the scoreboard below is valid in all
 * children of the same generation.
 *
 * The safe way to access the vhost pointer is like this:
 *
 * short_score *ss = pointer to whichver slot is interesting;
 * parent_score *ps = pointer to whichver slot is interesting;
 * server_rec *vh = ss->vhostrec;
 *
 * if (ps->generation != ap_my_generation) {
 *     vh = NULL;
 * }
 *
 * then if vh is not NULL it's valid in this child.
 *
 * This avoids various race conditions around restarts.
 */
typedef int ap_generation_t;

/* stuff which is thread/process specific */
typedef struct {
#ifdef OPTIMIZE_TIMEOUTS
    vtime_t cur_vtime;		/* the child's current vtime */
    unsigned short timeout_len;	/* length of the timeout */
#endif
    int thread_num;
    unsigned char status;
    unsigned long access_count;
    unsigned long bytes_served;
    unsigned long my_access_count;
    unsigned long my_bytes_served;
    unsigned long conn_bytes;
    unsigned short conn_count;
    apr_time_t start_time;
    apr_time_t stop_time;
#ifdef HAVE_TIMES
    struct tms times;
#endif
#ifndef OPTIMIZE_TIMEOUTS
    time_t last_used;
#endif
    char client[32];		/* Keep 'em small... */
    char request[64];		/* We just want an idea... */
    server_rec *vhostrec;	/* What virtual host is being accessed? */
                                /* SEE ABOVE FOR SAFE USAGE! */
} short_score;

typedef struct {
    ap_generation_t running_generation;	/* the generation of children which
                                         * should still be serving requests. */
} global_score;

/* stuff which the parent generally writes and the children rarely read */
typedef struct {
    pid_t pid;
    ap_generation_t generation;	/* generation of this child */
    int worker_threads;
#ifdef OPTIMIZE_TIMEOUTS
    time_t last_rtime;		/* time(0) of the last change */
    vtime_t last_vtime;		/* the last vtime the parent has seen */
#endif
} parent_score;

typedef struct {
    short_score servers[HARD_SERVER_LIMIT][HARD_THREAD_LIMIT];
    parent_score parent[HARD_SERVER_LIMIT];
    global_score global;
} scoreboard;

#define KEY_LENGTH 16
#define VALUE_LENGTH 64
typedef struct {
    char key[KEY_LENGTH];
    char value[VALUE_LENGTH];
} status_table_entry;

#define STATUSES_PER_CONNECTION 10

typedef struct {
    status_table_entry
        table[HARD_SERVER_LIMIT*HARD_THREAD_LIMIT][STATUSES_PER_CONNECTION];
} new_scoreboard;

#define SCOREBOARD_SIZE		sizeof(scoreboard)
#define NEW_SCOREBOARD_SIZE	sizeof(new_scoreboard)
#ifdef TPF
#define SCOREBOARD_NAME		"SCOREBRD"
#define SCOREBOARD_FRAMES		SCOREBOARD_SIZE/4095 + 1
#endif

AP_DECLARE(int) ap_exists_scoreboard_image(void);
void reinit_scoreboard(apr_pool_t *p);
apr_status_t ap_cleanup_shared_mem(void *d);
AP_DECLARE(void) ap_sync_scoreboard_image(void);

AP_DECLARE(void) reopen_scoreboard(apr_pool_t *p);

apr_inline void ap_sync_scoreboard_image(void);
void increment_counts(int child_num, int thread_num, request_rec *r);
void update_scoreboard_global(void);
AP_DECLARE(int) find_child_by_pid(apr_proc_t *pid);
int ap_update_child_status(int child_num, int thread_num, int status, request_rec *r);
void ap_time_process_request(int child_num, int thread_num, int status);


AP_DECLARE_DATA extern scoreboard *ap_scoreboard_image;
AP_DECLARE_DATA extern const char *ap_scoreboard_fname;
AP_DECLARE_DATA extern int ap_extended_status;
AP_DECLARE_DATA apr_time_t ap_restart_time;

AP_DECLARE_DATA extern ap_generation_t volatile ap_my_generation;

/* for time_process_request() in http_main.c */
#define START_PREQUEST 1
#define STOP_PREQUEST  2

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_SCOREBOARD_H */
