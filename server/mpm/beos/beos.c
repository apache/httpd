/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

/* The new BeOS MPM!
 *
 * This one basically is a single process multi threaded model, but 
 * I couldn't be bothered adding the spmt_ to the front of the name!
 * Anyway, this is still under development so it isn't yet the default
 * choice.
 */
 
#define CORE_PRIVATE 
 
#include <kernel/OS.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>

#include "apr_strings.h"
#include "apr_portable.h"
#include "httpd.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "http_config.h"	/* for read_config */ 
#include "http_core.h"		/* for get_remote_host */ 
#include "http_connection.h"
#include "ap_mpm.h"
#include "beosd.h"
#include "ap_listen.h"
#include "scoreboard.h" 
#include "mpm_common.h"
#include "mpm.h"
#include "mpm_default.h"
#include "apr_thread_mutex.h"
#include "apr_poll.h"

extern int _kset_fd_limit_(int num);

/* Limit on the total --- clients will be locked out if more servers than
 * this are needed.  It is intended solely to keep the server from crashing
 * when things get out of hand.
 *
 * We keep a hard maximum number of servers, for two reasons:
 * 1) in case something goes seriously wrong, we want to stop the server starting
 *    threads ad infinitum and crashing the server (remember that BeOS has a 192
 *    thread per team limit).
 * 2) it keeps the size of the scoreboard file small
 *    enough that we can read the whole thing without worrying too much about
 *    the overhead.
 */

/* we only ever have 1 main process running... */ 
#define HARD_SERVER_LIMIT 1

/* Limit on the threads per process.  Clients will be locked out if more than
 * this  * HARD_SERVER_LIMIT are needed.
 *
 * We keep this for one reason it keeps the size of the scoreboard file small
 * enough that we can read the whole thing without worrying too much about
 * the overhead.
 */
#ifdef NO_THREADS
#define HARD_THREAD_LIMIT 1
#endif
#ifndef HARD_THREAD_LIMIT
#define HARD_THREAD_LIMIT 50 
#endif

/*
 * Actual definitions of config globals
 */

static int ap_threads_to_start=0;
static int ap_max_requests_per_thread = 0;
static int min_spare_threads=0;
static int max_spare_threads=0;
static int ap_thread_limit=0;
static int num_listening_sockets = 0;
static apr_socket_t ** listening_sockets;
apr_thread_mutex_t *accept_mutex = NULL;

static apr_pool_t *pconf;		/* Pool for config stuff */
static apr_pool_t *pchild;		/* Pool for httpd child stuff */

static int server_pid; 

/* Keep track of the number of worker threads currently active */
static int worker_thread_count;
apr_thread_mutex_t *worker_thread_count_mutex;

/* The structure used to pass unique initialization info to each thread */
typedef struct {
    int slot;
    apr_pool_t *tpool;
} proc_info;

static void check_restart(void *data);

/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with MaxClients changes across AP_SIG_GRACEFUL restarts.  We use 
 * this value to optimize routines that have to scan the entire scoreboard.
 */
int ap_max_child_assigned = -1;
int ap_max_threads_limit = -1;

static apr_socket_t *udp_sock;
static apr_sockaddr_t *udp_sa;

/* shared http_main globals... */

server_rec *ap_server_conf;

/* one_process */
static int one_process = 0;

#ifdef DEBUG_SIGSTOP
int raise_sigstop_flags;
#endif

/* a clean exit from a child with proper cleanup 
   static void clean_child_exit(int code) __attribute__ ((noreturn)); */
static void clean_child_exit(int code)
{
    if (pchild)
        apr_pool_destroy(pchild);
    exit(code);
}

/* handle all varieties of core dumping signals */
static void sig_coredump(int sig)
{
    chdir(ap_coredump_dir);
    signal(sig, SIG_DFL);
    kill(server_pid, sig);
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

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful;
static int volatile child_fatal;
ap_generation_t volatile ap_my_generation = 0;

/*
 * ap_start_shutdown() and ap_start_restart(), below, are a first stab at
 * functions to initiate shutdown or restart without relying on signals. 
 * Previously this was initiated in sig_term() and restart() signal handlers, 
 * but we want to be able to start a shutdown/restart from other sources --
 * e.g. on Win32, from the service manager. Now the service manager can
 * call ap_start_shutdown() or ap_start_restart() as appropiate.  Note that
 * these functions can also be called by the child processes, since global
 * variables are no longer used to pass on the required action to the parent.
 *
 * These should only be called from the parent process itself, since the
 * parent process will use the shutdown_pending and restart_pending variables
 * to determine whether to shutdown or restart. The child process should
 * call signal_parent() directly to tell the parent to die -- this will
 * cause neither of those variable to be set, which the parent will
 * assume means something serious is wrong (which it will be, for the
 * child to force an exit) and so do an exit anyway.
 */

static void ap_start_shutdown(void)
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

/* do a graceful restart if graceful == 1 */
static void ap_start_restart(int graceful)
{

    if (restart_pending == 1) {
        /* Probably not an error - don't bother reporting it */
        return;
    }
    restart_pending = 1;
    is_graceful = graceful;
}

static void sig_term(int sig)
{
    ap_start_shutdown();
}

static void restart(int sig)
{
    ap_start_restart(sig == AP_SIG_GRACEFUL);
}

static void tell_workers_to_exit(void)
{
    apr_size_t len;
    int i = 0;
    for (i = 0 ; i < ap_max_child_assigned; i++){
        len = 4;
        if (apr_sendto(udp_sock, udp_sa, 0, "die!", &len) != APR_SUCCESS)
            break;
    }   
}

static void set_signals(void)
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (!one_process) {
	sa.sa_handler = sig_coredump;

	if (sigaction(SIGSEGV, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGSEGV)");
	if (sigaction(SIGBUS, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGBUS)");
	if (sigaction(SIGABRT, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGABRT)");
	if (sigaction(SIGILL, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGILL)");
	sa.sa_flags = 0;
    }
    sa.sa_handler = sig_term;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGTERM)");
    if (sigaction(SIGINT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGINT)");
    
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
    	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGPIPE)");

    /* we want to ignore HUPs and AP_SIG_GRACEFUL while we're busy 
     * processing one */
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, AP_SIG_GRACEFUL);
    sa.sa_handler = restart;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
    	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGHUP)");
    if (sigaction(AP_SIG_GRACEFUL, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(" AP_SIG_GRACEFUL_STRING ")");
}

/*****************************************************************
 * Here follows a long bunch of generic server bookkeeping stuff...
 */

int ap_graceful_stop_signalled(void)
{
    /* XXX - Does this really work? - Manoj */
    return is_graceful;
}

/*****************************************************************
 * Child process main loop.
 */

static void process_socket(apr_pool_t *p, apr_socket_t *sock,
                           int my_child_num, apr_bucket_alloc_t *bucket_alloc)
{
    conn_rec *current_conn;
    long conn_id = my_child_num;
    int csd;
    ap_sb_handle_t *sbh;

    (void)apr_os_sock_get(&csd, sock);
    
    if (csd >= FD_SETSIZE) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
                     "filedescriptor (%u) larger than FD_SETSIZE (%u) "
                     "found, you probably need to rebuild Apache with a "
                     "larger FD_SETSIZE", csd, FD_SETSIZE);
        apr_socket_close(sock);
        return;
    }

    ap_create_sb_handle(&sbh, p, 0, my_child_num);
    current_conn = ap_run_create_connection(p, ap_server_conf,
                                            sock, conn_id, sbh,
                                            bucket_alloc);

    if (current_conn) {
        ap_process_connection(current_conn, sock);
        ap_lingering_close(current_conn);
    }
}

static int32 worker_thread(void * dummy)
{
    proc_info * ti = dummy;
    int child_slot = ti->slot;
    apr_pool_t *tpool = ti->tpool;
    apr_allocator_t *allocator;
    apr_socket_t *csd = NULL;
    apr_pool_t *ptrans;		/* Pool for per-transaction stuff */
    apr_bucket_alloc_t *bucket_alloc;
    apr_socket_t *sd = NULL;
    apr_status_t rv = APR_EINIT;
    int srv , n;
    int curr_pollfd = 0, last_pollfd = 0;
    sigset_t sig_mask;
    int requests_this_child = ap_max_requests_per_thread;
    apr_pollfd_t *pollset;
    /* each worker thread is in control of its own destiny...*/
    int this_worker_should_exit = 0; 
    free(ti);

    on_exit_thread(check_restart, (void*)child_slot);
          
    /* block the signals for this thread */
    sigfillset(&sig_mask);
    sigprocmask(SIG_BLOCK, &sig_mask, NULL);

    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    apr_pool_create_ex(&ptrans, tpool, NULL, allocator);
    apr_allocator_owner_set(allocator, ptrans);

    apr_pool_tag(ptrans, "transaction");

    bucket_alloc = apr_bucket_alloc_create_ex(allocator);

    apr_thread_mutex_lock(worker_thread_count_mutex);
    worker_thread_count++;
    apr_thread_mutex_unlock(worker_thread_count_mutex);

    (void) ap_update_child_status_from_indexes(0, child_slot, SERVER_STARTING,
                                               (request_rec*)NULL);
                                  
    apr_poll_setup(&pollset, num_listening_sockets + 1, tpool);
    for(n=0 ; n <= num_listening_sockets ; n++)
        apr_poll_socket_add(pollset, listening_sockets[n], APR_POLLIN);

    while (1) {
        /* If we're here, then chances are (unless we're the first thread created) 
         * we're going to be held up in the accept mutex, so doing this here
         * shouldn't hurt performance.
         */

        this_worker_should_exit |= (ap_max_requests_per_thread != 0) && (requests_this_child <= 0);
        
        if (this_worker_should_exit) break;

        (void) ap_update_child_status_from_indexes(0, child_slot, SERVER_READY,
                                                   (request_rec*)NULL);

        apr_thread_mutex_lock(accept_mutex);

        while (!this_worker_should_exit) {
            apr_int16_t event;
            apr_status_t ret;

            ret = apr_poll(pollset, num_listening_sockets + 1, &srv, -1);

            if (ret != APR_SUCCESS) {
                if (APR_STATUS_IS_EINTR(ret)) {
                    continue;
                }
                /* poll() will only return errors in catastrophic
                 * circumstances. Let's try exiting gracefully, for now. */
                ap_log_error(APLOG_MARK, APLOG_ERR, ret, (const server_rec *)
                             ap_server_conf, "apr_poll: (listen)");
                this_worker_should_exit = 1;
            } else {
                /* if we've bailed in apr_poll what's the point of trying to use the data? */
                apr_poll_revents_get(&event, listening_sockets[0], pollset);

                if (event & APR_POLLIN){
                    apr_sockaddr_t *rec_sa;
                    apr_size_t len = 5;
                    char *tmpbuf = apr_palloc(ptrans, sizeof(char) * 5);
                    apr_sockaddr_info_get(&rec_sa, "127.0.0.1", APR_UNSPEC, 7772, 0, ptrans);
                    
                    if ((ret = apr_recvfrom(rec_sa, listening_sockets[0], 0, tmpbuf, &len))
                        != APR_SUCCESS){
                        ap_log_error(APLOG_MARK, APLOG_ERR, ret, NULL, 
                            "error getting data from UDP!!");
                    }else {
                        /* add checking??? */              
                    }
                    this_worker_should_exit = 1;
                }
            }
          
            if (this_worker_should_exit) break;

            if (num_listening_sockets == 1) {
                sd = ap_listeners->sd;
                goto got_fd;
            }
            else {
                /* find a listener */
                curr_pollfd = last_pollfd;
                do {
                    curr_pollfd++;

                    if (curr_pollfd > num_listening_sockets)
                        curr_pollfd = 1;
                    
                    /* Get the revent... */
                    apr_poll_revents_get(&event, listening_sockets[curr_pollfd], pollset);
                    
                    if (event & APR_POLLIN) {
                        last_pollfd = curr_pollfd;
                        sd = listening_sockets[curr_pollfd];
                        goto got_fd;
                    }
                } while (curr_pollfd != last_pollfd);
            }
        }
    got_fd:

        if (!this_worker_should_exit) {
            rv = apr_accept(&csd, sd, ptrans);

            apr_thread_mutex_unlock(accept_mutex);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                  "apr_accept");
            } else {
                process_socket(ptrans, csd, child_slot, bucket_alloc);
                requests_this_child--;
            }
        }
        else {
            apr_thread_mutex_unlock(accept_mutex);
            break;
        }
        apr_pool_clear(ptrans);
    }

    ap_update_child_status_from_indexes(0, child_slot, SERVER_DEAD, (request_rec*)NULL);

    apr_bucket_alloc_destroy(bucket_alloc);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                 "worker_thread %ld exiting", find_thread(NULL));
    
    apr_thread_mutex_lock(worker_thread_count_mutex);
    worker_thread_count--;
    apr_thread_mutex_unlock(worker_thread_count_mutex);

    return (0);
}

static int make_worker(int slot)
{
    thread_id tid;
    proc_info *my_info = (proc_info *)malloc(sizeof(proc_info)); /* freed by thread... */

    if (my_info == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, ap_server_conf,
            "malloc: out of memory");
        clean_child_exit(APEXIT_CHILDFATAL);
    }
    
    my_info->slot = slot;
    apr_pool_create(&my_info->tpool, pchild);
    
    if (slot + 1 > ap_max_child_assigned)
	    ap_max_child_assigned = slot + 1;

    if (one_process) {
    	set_signals();
        ap_scoreboard_image->parent[0].pid = getpid();
        return 0;
    }

    (void) ap_update_child_status_from_indexes(0, slot, SERVER_STARTING, (request_rec*)NULL);
    tid = spawn_thread(worker_thread, "apache_worker", B_NORMAL_PRIORITY,
        my_info);
    if (tid < B_NO_ERROR) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, NULL, 
            "spawn_thread: Unable to start a new thread");
        /* In case system resources are maxxed out, we don't want
         * Apache running away with the CPU trying to fork over and
         * over and over again. 
         */
        (void) ap_update_child_status_from_indexes(0, slot, SERVER_DEAD, 
                                                   (request_rec*)NULL);
        
    	sleep(10);
        free(my_info);
        
    	return -1;
    }
    resume_thread(tid);

    ap_scoreboard_image->servers[0][slot].tid = tid;
    return 0;
}

static void check_restart(void *data)
{
    if (!restart_pending && !shutdown_pending) {
        int slot = (int)data;
        make_worker(slot);
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL, 
            "spawning a new worker thread in slot %d", slot);
    }
}

/* start up a bunch of children */
static void startup_threads(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < ap_thread_limit; ++i) {
	if (ap_scoreboard_image->servers[0][i].tid) {
	    continue;
	}
	if (make_worker(i) < 0) {
	    break;
	}
	--number_to_start;
    }
}


/*
 * spawn_rate is the number of children that will be spawned on the
 * next maintenance cycle if there aren't enough idle servers.  It is
 * doubled up to MAX_SPAWN_RATE, and reset only when a cycle goes by
 * without the need to spawn.
 */
static int spawn_rate = 1;
#ifndef MAX_SPAWN_RATE
#define MAX_SPAWN_RATE	(32)
#endif
static int hold_off_on_exponential_spawning;

static void perform_idle_server_maintenance(void)
{
    int i;
    int free_length;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead  = -1;

    /* initialize the free_list */
    free_length = 0;

    for (i = 0; i < ap_thread_limit; ++i) {
        if (ap_scoreboard_image->servers[0][i].tid == 0) {
            if (free_length < spawn_rate) {
                free_slots[free_length] = i;
                ++free_length;
            }
        }
        else {
            last_non_dead = i;
        }

    	if (i >= ap_max_child_assigned && free_length >= spawn_rate) {
	         break;
	    }
    }
    ap_max_child_assigned = last_non_dead + 1;

    if (free_length > 0) {
    	for (i = 0; i < free_length; ++i) {
	        make_worker(free_slots[i]);
	    }
	    /* the next time around we want to spawn twice as many if this
	     * wasn't good enough, but not if we've just done a graceful
	     */
	    if (hold_off_on_exponential_spawning) {
	        --hold_off_on_exponential_spawning;
	    } else if (spawn_rate < MAX_SPAWN_RATE) {
	        spawn_rate *= 2;
	    }
    } else {
        spawn_rate = 1;
    }
}

static void server_main_loop(int remaining_threads_to_start)
{
    int child_slot;
    apr_exit_why_e exitwhy;
    int status;
    apr_proc_t pid;
    int i;

    while (!restart_pending && !shutdown_pending) {

        ap_wait_or_timeout(&exitwhy, &status, &pid, pconf);
         
        if (pid.pid >= 0) {
            if (ap_process_child_status(&pid, exitwhy, status) == APEXIT_CHILDFATAL) {
                shutdown_pending = 1;
                child_fatal = 1;
                return;
            }
            /* non-fatal death... note that it's gone in the scoreboard. */
            child_slot = -1;
            for (i = 0; i < ap_max_child_assigned; ++i) {
        	if (ap_scoreboard_image->servers[0][i].tid == pid.pid) {
                    child_slot = i;
                    break;
                }
            }
            if (child_slot >= 0) {
                ap_scoreboard_image->servers[0][child_slot].tid = 0;
                (void) ap_update_child_status_from_indexes(0, child_slot, 
                                                           SERVER_DEAD, 
                                                           (request_rec*)NULL);
                
                if (remaining_threads_to_start
		            && child_slot < ap_thread_limit) {
                    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
                    make_worker(child_slot);
                    --remaining_threads_to_start;
		        }
#if APR_HAS_OTHER_CHILD
            }
            else if (apr_proc_other_child_read(&pid, status) == 0) {
    		/* handled */
#endif
            }
            else if (is_graceful) {
                /* Great, we've probably just lost a slot in the
                 * scoreboard.  Somehow we don't know about this
                 * child.
                 */
                 ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
			                  "long lost child came home! (pid %ld)", pid.pid);
            }
	    
            /* Don't perform idle maintenance when a child dies,
             * only do it when there's a timeout.  Remember only a
             * finite number of children can die, and it's pretty
             * pathological for a lot to die suddenly.
             */
             continue;
         }
	     else if (remaining_threads_to_start) {
             /* we hit a 1 second timeout in which none of the previous
              * generation of children needed to be reaped... so assume
              * they're all done, and pick up the slack if any is left.
              */
              startup_threads(remaining_threads_to_start);
              remaining_threads_to_start = 0;
              /* In any event we really shouldn't do the code below because
               * few of the servers we just started are in the IDLE state
               * yet, so we'd mistakenly create an extra server.
               */
              continue;
         }
         perform_idle_server_maintenance();
    }
}

AP_DECLARE(apr_status_t) ap_mpm_query(int query_code, int *result)
{
    switch(query_code){
        case AP_MPMQ_MAX_DAEMON_USED:
            *result = ap_max_child_assigned;
            return APR_SUCCESS;
        case AP_MPMQ_IS_THREADED:
            *result = AP_MPMQ_DYNAMIC;
            return APR_SUCCESS;
        case AP_MPMQ_IS_FORKED:
            *result = AP_MPMQ_NOT_SUPPORTED;
            return APR_SUCCESS;
        case AP_MPMQ_HARD_LIMIT_DAEMONS:
            *result = HARD_SERVER_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_HARD_LIMIT_THREADS:
            *result = HARD_THREAD_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_THREADS:
            *result = HARD_THREAD_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_THREADS:    
            *result = max_spare_threads;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_THREADS:
            *result = min_spare_threads;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_REQUESTS_DAEMON:
            *result = ap_max_requests_per_thread;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_DAEMONS:
            *result = HARD_SERVER_LIMIT;
            return APR_SUCCESS;
    }
    return APR_ENOTIMPL;
}

int ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
{
    int remaining_threads_to_start, i,j;
    apr_status_t rv;
    ap_listen_rec *lr;    
    pconf = _pconf;
    ap_server_conf = s;

    /* Increase the available pool of fd's.  This code from
     * Joe Kloss <joek@be.com>
     */
    if( FD_SETSIZE > 128 && (i = _kset_fd_limit_( 128 )) < 0 ){
        ap_log_error(APLOG_MARK, APLOG_ERR, i, s,
            "could not set FD_SETSIZE (_kset_fd_limit_ failed)");
    }

    /* BeOS R5 doesn't support pipes on select() calls, so we use a 
       UDP socket as these are supported in both R5 and BONE.  If we only cared
       about BONE we'd use a pipe, but there it is.
       As we have UDP support in APR, now use the APR functions and check all the
       return values...
      */
    if (apr_sockaddr_info_get(&udp_sa, "127.0.0.1", APR_UNSPEC, 7772, 0, _pconf)
        != APR_SUCCESS){
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, s,
            "couldn't create control socket information, shutting down");
        return 1;
    }
    if (apr_socket_create(&udp_sock, udp_sa->family, SOCK_DGRAM,
                      _pconf) != APR_SUCCESS){
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, s,
            "couldn't create control socket, shutting down");
        return 1;
    }
    if (apr_bind(udp_sock, udp_sa) != APR_SUCCESS){
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, s,
            "couldn't bind UDP socket!");
        return 1;
    }
 
    if ((num_listening_sockets = ap_setup_listeners(ap_server_conf)) < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s,
            "no listening sockets available, shutting down");
        return 1;
    }

    ap_log_pid(pconf, ap_pid_fname);

    /*
     * Create our locks... 
     */
    
    /* accept_mutex
     * used to lock around select so we only have one thread
     * in select at a time
     */
    rv = apr_thread_mutex_create(&accept_mutex, 0, pconf);
    if (rv != APR_SUCCESS) {
        /* tsch tsch, can't have more than one thread in the accept loop
           at a time so we need to fall on our sword... */
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "Couldn't create accept lock");
        return 1;
    }

    /* worker_thread_count_mutex
     * locks the worker_thread_count so we have ana ccurate count...
     */
    rv = apr_thread_mutex_create(&worker_thread_count_mutex, 0, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "Couldn't create worker thread count lock");
        return 1;
    }

    /*
     * Startup/shutdown... 
     */
    
    if (!is_graceful) {
        /* setup the scoreboard shared memory */
        if (ap_run_pre_mpm(s->process->pool, SB_SHARED) != OK) {
            return 1;
        }

        for (i = 0; i < HARD_SERVER_LIMIT; i++) {
            ap_scoreboard_image->parent[i].pid = 0;
            for (j = 0;j < HARD_THREAD_LIMIT; j++)
                ap_scoreboard_image->servers[i][j].tid = 0;
        }
    }

    if (HARD_SERVER_LIMIT == 1)
        ap_scoreboard_image->parent[0].pid = getpid();

    set_signals();

    /* Sanity checks to avoid thrashing... */
    if (max_spare_threads < min_spare_threads )
        max_spare_threads = min_spare_threads;

    /* If we're doing a graceful_restart then we're going to see a lot
     * of threads exiting immediately when we get into the main loop
     * below (because we just sent them AP_SIG_GRACEFUL).  This happens 
     * pretty rapidly... and for each one that exits we'll start a new one 
     * until we reach at least threads_min_free.  But we may be permitted to
     * start more than that, so we'll just keep track of how many we're
     * supposed to start up without the 1 second penalty between each fork.
     */
    remaining_threads_to_start = ap_threads_to_start;
    /* sanity check on the number to start... */
    if (remaining_threads_to_start > ap_thread_limit) {
	    remaining_threads_to_start = ap_thread_limit;
    }

    /* setup the child pool to use for the workers.  Each worker creates
     * a seperate pool of its own to use.
     */
    apr_pool_create(&pchild, pconf);

    /* Now that we have the child pool (pchild) we can allocate
     * the listenfds and creat the pollset...
     */
    listening_sockets = apr_palloc(pchild,
       sizeof(*listening_sockets) * (num_listening_sockets + 1));

    listening_sockets[0] = udp_sock;
    for (lr = ap_listeners, i = 1; i <= num_listening_sockets; lr = lr->next, ++i)
	    listening_sockets[i]=lr->sd;

    /* we assume all goes OK...hmm might want to check that! */
    /* if we're in one_process mode we don't want to start threads
     * do we??
     */
    if (!is_graceful && !one_process) {
	    startup_threads(remaining_threads_to_start);
	    remaining_threads_to_start = 0;
    }
    else {
	    /* give the system some time to recover before kicking into
	     * exponential mode */
        hold_off_on_exponential_spawning = 10;
    }

    /*
     * record that we've entered the world !
     */
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
		"%s configured -- resuming normal operations",
		ap_get_server_version());

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf,
		"Server built: %s", ap_get_server_built());

    restart_pending = shutdown_pending = 0;

    /*
     * main_loop until it's all over
     */
    if (!one_process) {
        server_main_loop(remaining_threads_to_start);
    
        tell_workers_to_exit(); /* if we get here we're exiting... */
        sleep(1); /* give them a brief chance to exit */
    } else {
        proc_info *my_info = (proc_info *)malloc(sizeof(proc_info));
        my_info->slot = 0;
        apr_pool_create(&my_info->tpool, pchild);
        worker_thread(my_info);
    }
        
    /* close the UDP socket we've been using... */
    apr_socket_close(listening_sockets[0]);

    if ((one_process || shutdown_pending) && !child_fatal) {
        const char *pidfile = NULL;
        pidfile = ap_server_root_relative (pconf, ap_pid_fname);
        if ( pidfile != NULL && unlink(pidfile) == 0)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf,
                         "removed PID file %s (pid=%ld)", pidfile, 
                         (long)getpid());
    }

    if (one_process) {
        return 1;
    }
        
    /*
     * If we get here we're shutting down...
     */
    if (shutdown_pending) {
        /* Time to gracefully shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        if (beosd_killpg(getpgrp(), SIGTERM) < 0)
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
             "killpg SIGTERM");
      
        /* use ap_reclaim_child_processes starting with SIGTERM */
        ap_reclaim_child_processes(1);

        if (!child_fatal) {         /* already recorded */
            /* record the shutdown in the log */
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                         "caught SIGTERM, shutting down");
        }
    
        return 1;
    }

    /* we've been told to restart */
    signal(SIGHUP, SIG_IGN);

    if (is_graceful) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
		    AP_SIG_GRACEFUL_STRING " received.  Doing graceful restart");
    }
    else {
        /* Kill 'em all.  Since the child acts the same on the parents SIGTERM 
         * and a SIGHUP, we may as well use the same signal, because some user
         * pthreads are stealing signals from us left and right.
         */
	    
        ap_reclaim_child_processes(1);		/* Start with SIGTERM */
	    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
		    "SIGHUP received.  Attempting to restart");
    }
    
    /* just before we go, tidy up the locks we've created to prevent a 
     * potential leak of semaphores... */
    apr_thread_mutex_destroy(worker_thread_count_mutex);
    apr_thread_mutex_destroy(accept_mutex);
    
    return 0;
}

static int beos_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static int restart_num = 0;
    int no_detach, debug, foreground;
    apr_status_t rv;

    debug = ap_exists_config_define("DEBUG");

    if (debug) {
        foreground = one_process = 1;
        no_detach = 0;
    }
    else
    {
        one_process = ap_exists_config_define("ONE_PROCESS");
        no_detach = ap_exists_config_define("NO_DETACH");
        foreground = ap_exists_config_define("FOREGROUND");
    }

    /* sigh, want this only the second time around */
    if (restart_num++ == 1) {
        is_graceful = 0;
        
        if (!one_process && !foreground) {
            rv = apr_proc_detach(no_detach ? APR_PROC_DETACH_FOREGROUND
                                           : APR_PROC_DETACH_DAEMONIZE);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                             "apr_proc_detach failed");
                return HTTP_INTERNAL_SERVER_ERROR;
            }                  
        }

        server_pid = getpid();
    }

    beosd_pre_config();
    ap_listen_pre_config();
    ap_threads_to_start = DEFAULT_START_THREADS;
    min_spare_threads = DEFAULT_MIN_FREE_THREADS;
    max_spare_threads = DEFAULT_MAX_FREE_THREADS;
    ap_thread_limit = HARD_THREAD_LIMIT;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_max_requests_per_thread = DEFAULT_MAX_REQUESTS_PER_THREAD;
#ifdef AP_MPM_WANT_SET_MAX_MEM_FREE
	ap_max_mem_free = APR_ALLOCATOR_MAX_FREE_UNLIMITED;
#endif

    apr_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));

    return OK;
}

static void beos_hooks(apr_pool_t *p)
{
    one_process = 0;
    
    ap_hook_pre_config(beos_pre_config, NULL, NULL, APR_HOOK_MIDDLE); 
}

static const char *set_threads_to_start(cmd_parms *cmd, void *dummy, const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_to_start = atoi(arg);
    if (ap_threads_to_start < 0) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "StartThreads set to a value less than 0, reset to 1");
        ap_threads_to_start = 1;
    }
    return NULL;
}

static const char *set_min_spare_threads(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    min_spare_threads = atoi(arg);
    if (min_spare_threads <= 0) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "WARNING: detected MinSpareThreads set to non-positive.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                    "Resetting to 1 to avoid almost certain Apache failure.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "Please read the documentation.");
       min_spare_threads = 1;
    }
       
    return NULL;
}

static const char *set_max_spare_threads(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_spare_threads = atoi(arg);
    return NULL;
}

static const char *set_threads_limit (cmd_parms *cmd, void *dummy, const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_thread_limit = atoi(arg);
    if (ap_thread_limit > HARD_THREAD_LIMIT) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "WARNING: MaxClients of %d exceeds compile time limit "
                    "of %d servers,", ap_thread_limit, HARD_THREAD_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    " lowering MaxClients to %d.  To increase, please "
                    "see the", HARD_THREAD_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    " HARD_THREAD_LIMIT define in server/mpm/beos/mpm_default.h.");
       ap_thread_limit = HARD_THREAD_LIMIT;
    } 
    else if (ap_thread_limit < 1) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "WARNING: Require MaxClients > 0, setting to %d", HARD_THREAD_LIMIT);
        ap_thread_limit = HARD_THREAD_LIMIT;
    }
    return NULL;
}

static const char *set_max_requests_per_thread (cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_max_requests_per_thread = atoi(arg);
    if (ap_max_requests_per_thread < 0) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "WARNING: MaxRequestsPerThread was set below 0"
                     "reset to 0, but this may not be what you want.");
        ap_max_requests_per_thread = 0;
    }

    return NULL;
}

static const command_rec beos_cmds[] = {
BEOS_DAEMON_COMMANDS,
LISTEN_COMMANDS,
AP_INIT_TAKE1( "StartThreads", set_threads_to_start, NULL, RSRC_CONF,
  "Number of threads to launch at server startup"),
AP_INIT_TAKE1( "MinSpareThreads", set_min_spare_threads, NULL, RSRC_CONF,
  "Minimum number of idle children, to handle request spikes"),
AP_INIT_TAKE1( "MaxSpareThreads", set_max_spare_threads, NULL, RSRC_CONF,
  "Maximum number of idle children" ),
AP_INIT_TAKE1( "MaxClients", set_threads_limit, NULL, RSRC_CONF, 
  "Maximum number of children alive at the same time (max threads)" ),
AP_INIT_TAKE1( "MaxRequestsPerThread", set_max_requests_per_thread, NULL, RSRC_CONF,
  "Maximum number of requests served by a thread" ),
{ NULL }
};

module AP_MODULE_DECLARE_DATA mpm_beos_module = {
    MPM20_MODULE_STUFF,
    NULL,                       /* hook to run before apache parses args */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    beos_cmds,		/* command apr_table_t */
    beos_hooks		/* register_hooks */
};

