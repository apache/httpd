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

#define CORE_PRIVATE 
 
#include "apr_portable.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_thread_proc.h"
#include "ap_config.h"
#include "httpd.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "http_config.h"	/* for read_config */ 
#include "http_core.h"		/* for get_remote_host */ 
#include "http_connection.h"
#include "ap_mpm.h"
#include "unixd.h"
#include "mpm_common.h"
#include "ap_listen.h"
#include "scoreboard.h" 

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h> 
#endif
#include <pthread.h>
#include <signal.h>

/*
 * Actual definitions of config globals
 */

int ap_threads_per_child=0;         /* Worker threads per child */
int ap_max_requests_per_child=0;
static const char *ap_pid_fname=NULL;
static int ap_daemons_to_start=0;
static int min_spare_threads=0;
static int max_spare_threads=0;
static int ap_daemons_limit=0;
static int workers_may_exit = 0;
static int requests_this_child;
static int num_listensocks = 0;
static apr_socket_t **listensocks;

/* The structure used to pass unique initialization info to each thread */
typedef struct {
    int pid;
    int tid;
    int sd;
    apr_pool_t *tpool; /* "pthread" would be confusing */
} proc_info;

/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with MaxClients changes across SIGWINCH restarts.  We use this
 * value to optimize routines that have to scan the entire scoreboard.
 */
int ap_max_daemons_limit = -1;

char ap_coredump_dir[MAX_STRING_LEN];

static apr_file_t *pipe_of_death_in = NULL;
static apr_file_t *pipe_of_death_out = NULL;
static pthread_mutex_t pipe_of_death_mutex;

/* *Non*-shared http_main globals... */

server_rec *ap_server_conf;

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

#ifdef DEBUG_SIGSTOP
int raise_sigstop_flags;
#endif

static apr_pool_t *pconf;		/* Pool for config stuff */
static apr_pool_t *pchild;		/* Pool for httpd child stuff */

unsigned int ap_my_pid; /* Linux getpid() doesn't work except in main 
                           thread. Use this instead */
/* Keep track of the number of worker threads currently active */
static int worker_thread_count;
static pthread_mutex_t worker_thread_count_mutex;

/* Locks for accept serialization */
static apr_lock_t *accept_mutex;
static const char *lock_fname;

#ifdef NO_SERIALIZED_ACCEPT
#define SAFE_ACCEPT(stmt) APR_SUCCESS
#else
#define SAFE_ACCEPT(stmt) (stmt)
#endif

AP_DECLARE(int) ap_get_max_daemons(void)
{
    return ap_max_daemons_limit;
}

/* a clean exit from a child with proper cleanup */ 
static void clean_child_exit(int code) __attribute__ ((noreturn));
void clean_child_exit(int code)
{
    if (pchild) {
	apr_destroy_pool(pchild);
    }
    exit(code);
}

/* handle all varieties of core dumping signals */
static void sig_coredump(int sig)
{
    chdir(ap_coredump_dir);
    apr_signal(sig, SIG_DFL);
    kill(ap_my_pid, sig);
    /* At this point we've got sig blocked, because we're still inside
     * the signal handler.  When we leave the signal handler it will
     * be unblocked, and we'll take the signal... and coredump or whatever
     * is appropriate for this particular Unix.  In addition the parent
     * will see the real signal we received -- whereas if we called
     * abort() here, the parent would only see SIGABRT.
     */
}

static void just_die(int sig)
{
    clean_child_exit(0);
}

/*****************************************************************
 * Connection structures and accounting...
 */

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful;
ap_generation_t volatile ap_my_generation;

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
    if (is_graceful) {
        apr_kill_cleanup(pconf, NULL, ap_cleanup_shared_mem);
    }
}

static void sig_term(int sig)
{
    ap_start_shutdown();
}

static void restart(int sig)
{
#ifndef WIN32
    ap_start_restart(sig == SIGWINCH);
#else
    ap_start_restart(1);
#endif
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
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGSEGV)");
#ifdef SIGBUS
	if (sigaction(SIGBUS, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGBUS)");
#endif
#ifdef SIGABORT
	if (sigaction(SIGABORT, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGABORT)");
#endif
#ifdef SIGABRT
	if (sigaction(SIGABRT, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGABRT)");
#endif
#ifdef SIGILL
	if (sigaction(SIGILL, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGILL)");
#endif
	sa.sa_flags = 0;
    }
    sa.sa_handler = sig_term;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGTERM)");
#ifdef SIGINT
    if (sigaction(SIGINT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGINT)");
#endif
#ifdef SIGXCPU
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGXCPU, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGXCPU)");
#endif
#ifdef SIGXFSZ
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGXFSZ, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGXFSZ)");
#endif
#ifdef SIGPIPE
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGPIPE)");
#endif

    /* we want to ignore HUPs and WINCH while we're busy processing one */
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, SIGWINCH);
    sa.sa_handler = restart;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGHUP)");
    if (sigaction(SIGWINCH, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGWINCH)");
#else
    if (!one_process) {
	apr_signal(SIGSEGV, sig_coredump);
#ifdef SIGBUS
	apr_signal(SIGBUS, sig_coredump);
#endif /* SIGBUS */
#ifdef SIGABORT
	apr_signal(SIGABORT, sig_coredump);
#endif /* SIGABORT */
#ifdef SIGABRT
	apr_signal(SIGABRT, sig_coredump);
#endif /* SIGABRT */
#ifdef SIGILL
	apr_signal(SIGILL, sig_coredump);
#endif /* SIGILL */
#ifdef SIGXCPU
	apr_signal(SIGXCPU, SIG_DFL);
#endif /* SIGXCPU */
#ifdef SIGXFSZ
	apr_signal(SIGXFSZ, SIG_DFL);
#endif /* SIGXFSZ */
    }

    apr_signal(SIGTERM, sig_term);
#ifdef SIGHUP
    apr_signal(SIGHUP, restart);
#endif /* SIGHUP */
#ifdef SIGWINCH
    apr_signal(SIGWINCH, restart);
#endif /* SIGWINCH */
#ifdef SIGPIPE
    apr_signal(SIGPIPE, SIG_IGN);
#endif /* SIGPIPE */

#endif
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

static void process_socket(apr_pool_t *p, apr_socket_t *sock, int my_child_num, int my_thread_num)
{
    conn_rec *current_conn;
    long conn_id = my_child_num * HARD_THREAD_LIMIT + my_thread_num;
    int csd;

    (void) apr_get_os_sock(&csd, sock);

    if (csd >= FD_SETSIZE) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, NULL,
                     "new file descriptor %d is too large; you probably need "
                     "to rebuild Apache with a larger FD_SETSIZE "
                     "(currently %d)", 
                     csd, FD_SETSIZE);
        apr_close_socket(sock);
        return;
    }

    ap_sock_disable_nagle(sock);

    (void) ap_update_child_status(my_child_num, my_thread_num,  
				  SERVER_BUSY_READ, (request_rec *) NULL);

    current_conn = ap_new_connection(p, ap_server_conf, sock, conn_id);

    ap_process_connection(current_conn);
    ap_lingering_close(current_conn);
}
/* Sets workers_may_exit if we received a character on the pipe_of_death */
static void check_pipe_of_death(void)
{
    pthread_mutex_lock(&pipe_of_death_mutex);
    if (!workers_may_exit) {
        apr_status_t ret;
        char pipe_read_char;
	apr_size_t n = 1;

        ret = apr_recv(listensocks[0], &pipe_read_char, &n);
        if (APR_STATUS_IS_EAGAIN(ret)) {
            /* It lost the lottery. It must continue to suffer
             * through a life of servitude. */
        }
        else {
            /* It won the lottery (or something else is very
             * wrong). Embrace death with open arms. */
            workers_may_exit = 1;
        }
    }
    pthread_mutex_unlock(&pipe_of_death_mutex);
}

static void * worker_thread(void * dummy)
{
    proc_info * ti = dummy;
    int process_slot = ti->pid;
    int thread_slot = ti->tid;
    apr_pool_t *tpool = ti->tpool;
    apr_socket_t *csd = NULL;
    apr_pool_t *ptrans;		/* Pool for per-transaction stuff */
    apr_socket_t *sd = NULL;
    int n;
    int curr_pollfd, last_pollfd = 0;
    apr_pollfd_t *pollset;
    apr_status_t rv;

    free(ti);

    apr_create_pool(&ptrans, tpool);

    pthread_mutex_lock(&worker_thread_count_mutex);
    worker_thread_count++;
    pthread_mutex_unlock(&worker_thread_count_mutex);

    apr_setup_poll(&pollset, num_listensocks+1, tpool);
    for(n=0 ; n <= num_listensocks ; ++n)
	apr_add_poll_socket(pollset, listensocks[n], APR_POLLIN);

    /* TODO: Switch to a system where threads reuse the results from earlier
       poll calls - manoj */
    while (1) {
        workers_may_exit |= (ap_max_requests_per_child != 0) && (requests_this_child <= 0);
        if (workers_may_exit) break;

        (void) ap_update_child_status(process_slot, thread_slot, SERVER_READY, 
                                      (request_rec *) NULL);
        if ((rv = SAFE_ACCEPT(apr_lock(accept_mutex)))
            != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                         "apr_lock failed. Attempting to shutdown "
                         "process gracefully.");
            workers_may_exit = 1;
        }

        while (!workers_may_exit) {
	    apr_status_t ret;
	    apr_int16_t event;

            ret = apr_poll(pollset, &n, -1);
            if (ret != APR_SUCCESS) {
                if (APR_STATUS_IS_EINTR(ret)) {
                    continue;
                }

                /* apr_poll() will only return errors in catastrophic
                 * circumstances. Let's try exiting gracefully, for now. */
                ap_log_error(APLOG_MARK, APLOG_ERR, ret, (const server_rec *)
                             ap_server_conf, "apr_poll: (listen)");
                workers_may_exit = 1;
            }

            if (workers_may_exit) break;

	    apr_get_revents(&event, listensocks[0], pollset);
            if (event & APR_POLLIN) {
                /* A process got a signal on the shutdown pipe. Check if we're
                 * the lucky process to die. */
                check_pipe_of_death();
                continue;
            }

            if (num_listensocks == 1) {
                sd = ap_listeners->sd;
                goto got_fd;
            }
            else {
                /* find a listener */
                curr_pollfd = last_pollfd;
                do {
                    curr_pollfd++;
                    if (curr_pollfd > num_listensocks) {
                        curr_pollfd = 1;
                    }
                    /* XXX: Should we check for POLLERR? */
		    apr_get_revents(&event, listensocks[curr_pollfd], pollset);
                    if (event & APR_POLLIN) {
                        last_pollfd = curr_pollfd;
			sd=listensocks[curr_pollfd];
                        goto got_fd;
                    }
                } while (curr_pollfd != last_pollfd);
            }
        }
    got_fd:
        if (!workers_may_exit) {
            if ((rv = apr_accept(&csd, sd, ptrans)) != APR_SUCCESS) {
                csd = NULL;
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, 
                             "apr_accept");
            }
            if ((rv = SAFE_ACCEPT(apr_unlock(accept_mutex)))
                != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                             "apr_unlock failed. Attempting to shutdown "
                             "process gracefully.");
                workers_may_exit = 1;
            }
            if (csd != NULL) {
                process_socket(ptrans, csd, process_slot, thread_slot);
                requests_this_child--;
            }
        }
        else {
            if ((rv = SAFE_ACCEPT(apr_unlock(accept_mutex)))
                != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                             "apr_unlock failed. Attempting to shutdown "
                             "process gracefully.");
                workers_may_exit = 1;
            }
            break;
        }
        apr_clear_pool(ptrans);
    }

    apr_destroy_pool(tpool);
    ap_update_child_status(process_slot, thread_slot, SERVER_DEAD,
        (request_rec *) NULL);
    pthread_mutex_lock(&worker_thread_count_mutex);
    worker_thread_count--;
    if (worker_thread_count == 0) {
        /* All the threads have exited, now finish the shutdown process
         * by signalling the sigwait thread */
        kill(ap_my_pid, SIGTERM);
    }
    pthread_mutex_unlock(&worker_thread_count_mutex);

    return NULL;
}


static void child_main(int child_num_arg)
{
    sigset_t sig_mask;
    int signal_received;
    pthread_t thread;
    pthread_attr_t thread_attr;
    int i;
    int my_child_num = child_num_arg;
    proc_info *my_info = NULL;
    ap_listen_rec *lr;
    apr_status_t rv;


    ap_my_pid = getpid();
    apr_create_pool(&pchild, pconf);

    /*stuff to do before we switch id's, so we have permissions.*/
    reopen_scoreboard(pchild);

    rv = SAFE_ACCEPT(apr_child_init_lock(&accept_mutex, lock_fname,
                     pchild));
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                     "Couldn't initialize cross-process lock in child");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    if (unixd_setup_child()) {
	clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_child_init_hook(pchild, ap_server_conf);

    /*done with init critical section */

    /* All threads should mask signals out, accoring to sigwait(2) man page */
    sigfillset(&sig_mask);

#ifdef SIGPROCMASK_SETS_THREAD_MASK
    if (sigprocmask(SIG_SETMASK, &sig_mask, NULL) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, ap_server_conf, "sigprocmask");
    }
#else
    if ((rv = pthread_sigmask(SIG_SETMASK, &sig_mask, NULL)) != 0) {
#ifdef PTHREAD_SETS_ERRNO
        rv = errno;
#endif
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, "pthread_sigmask");
    }
#endif

    requests_this_child = ap_max_requests_per_child;
    
    /* Set up the pollfd array */
    listensocks = apr_pcalloc(pchild,
			    sizeof(*listensocks) * (num_listensocks + 1));
#if APR_FILES_AS_SOCKETS
    apr_socket_from_file(&listensocks[0], pipe_of_death_in);
#endif
    for (lr = ap_listeners, i = 1; i <= num_listensocks; lr = lr->next, ++i)
	listensocks[i]=lr->sd;

    /* Setup worker threads */

    worker_thread_count = 0;
    pthread_mutex_init(&worker_thread_count_mutex, NULL);
    pthread_mutex_init(&pipe_of_death_mutex, NULL);
    pthread_attr_init(&thread_attr);
#ifdef PTHREAD_ATTR_SETDETACHSTATE_ARG2_ADDR
    {
        int on = 1;

        pthread_attr_setdetachstate(&thread_attr, &on);
    }
#else
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
#endif
    for (i=0; i < ap_threads_per_child; i++) {

	my_info = (proc_info *)malloc(sizeof(proc_info));
        if (my_info == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, ap_server_conf,
		         "malloc: out of memory");
            clean_child_exit(APEXIT_CHILDFATAL);
        }
	my_info->pid = my_child_num;
        my_info->tid = i;
	my_info->sd = 0;
	apr_create_pool(&my_info->tpool, pchild);
	
	/* We are creating threads right now */
	(void) ap_update_child_status(my_child_num, i, SERVER_STARTING, 
				      (request_rec *) NULL);
#ifndef NO_THREADS
	if ((rv = pthread_create(&thread, &thread_attr, worker_thread, my_info))) {
#ifdef PTHREAD_SETS_ERRNO
            rv = errno;
#endif
	    ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf,
			 "pthread_create: unable to create worker thread");
            /* In case system resources are maxxed out, we don't want
               Apache running away with the CPU trying to fork over and
               over and over again if we exit. */
            sleep(10);
	    clean_child_exit(APEXIT_CHILDFATAL);
	}
#else
	worker_thread(my_info);
	/* The SIGTERM shouldn't let us reach this point, but just in case... */
	clean_child_exit(APEXIT_OK);
#endif

	/* We let each thread update it's own scoreboard entry.  This is done
	 * because it let's us deal with tid better.
	 */
    }

    pthread_attr_destroy(&thread_attr);

    /* This thread will be the one responsible for handling signals */
    sigemptyset(&sig_mask);
    sigaddset(&sig_mask, SIGTERM);
    sigaddset(&sig_mask, SIGINT);
    ap_sigwait(&sig_mask, &signal_received);
    switch (signal_received) {
        case SIGTERM:
        case SIGINT:
            just_die(signal_received);
            break;
        default:
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, ap_server_conf,
            "received impossible signal: %d", signal_received);
            just_die(SIGTERM);
    }
}

static int make_child(server_rec *s, int slot, time_t now) 
{
    int pid;

    if (slot + 1 > ap_max_daemons_limit) {
	ap_max_daemons_limit = slot + 1;
    }

    if (one_process) {
	set_signals();
        ap_scoreboard_image->parent[slot].pid = getpid();
	child_main(slot);
    }

    /* Tag this slot as occupied so that perform_idle_server_maintenance
     * doesn't try to steal it */
    (void) ap_update_child_status(slot, 0, SERVER_STARTING, (request_rec *) NULL);

    if ((pid = fork()) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s, "fork: Unable to fork new process");

        /* fork didn't succeed. Fix the scoreboard or else
         * it will say SERVER_STARTING forever and ever
         */
        (void) ap_update_child_status(slot, 0, SERVER_DEAD, (request_rec *) NULL);

	/* In case system resources are maxxed out, we don't want
	   Apache running away with the CPU trying to fork over and
	   over and over again. */
	sleep(10);

	return -1;
    }

    if (!pid) {
#ifdef AIX_BIND_PROCESSOR
      /* By default, AIX binds to a single processor.  This bit unbinds
	 children which will then bind to another CPU.
      */
#include <sys/processor.h>
        int status = bindprocessor(BINDPROCESS, (int)getpid(),
			       PROCESSOR_CLASS_ANY);
	if (status != OK)
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, errno, ap_server_conf,
			 "processor unbind failed %d", status);
#endif

        RAISE_SIGSTOP(MAKE_CHILD);

        apr_signal(SIGTERM, just_die);
        child_main(slot);

	return 0;
    }
    /* else */
    ap_scoreboard_image->parent[slot].pid = pid;
    return 0;
}

/* start up a bunch of children */
static void startup_children(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < ap_daemons_limit; ++i) {
	if (ap_scoreboard_image->parent[i].pid != 0) {
	    continue;
	}
	if (make_child(ap_server_conf, i, 0) < 0) {
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
    int i, j;
    int idle_thread_count;
    short_score *ss;
    time_t now = 0;
    int free_length;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead;
    int total_non_dead;
    apr_size_t one = 1;
    apr_status_t rv;

    /* initialize the free_list */
    free_length = 0;

    idle_thread_count = 0;
    last_non_dead = -1;
    total_non_dead = 0;

    ap_sync_scoreboard_image();
    for (i = 0; i < ap_daemons_limit; ++i) {
	/* Initialization to satisfy the compiler. It doesn't know
	 * that ap_threads_per_child is always > 0 */
	int status = SERVER_DEAD;
	int any_dying_threads = 0;
	int all_dead_threads = 1;
	int idle_thread_addition = 0;

	if (i >= ap_max_daemons_limit && free_length == idle_spawn_rate)
	    break;
	for (j = 0; j < ap_threads_per_child; j++) {
            ss = &ap_scoreboard_image->servers[i][j];
	    status = ss->status;

	    any_dying_threads = any_dying_threads || (status == SERVER_DEAD)
                                    || (status == SERVER_GRACEFUL);
	    all_dead_threads = all_dead_threads && (status == SERVER_DEAD);

	    /* We consider a starting server as idle because we started it
	     * at least a cycle ago, and if it still hasn't finished starting
	     * then we're just going to swamp things worse by forking more.
	     * So we hopefully won't need to fork more if we count it.
	     * This depends on the ordering of SERVER_READY and SERVER_STARTING.
	     */
	    if (status <= SERVER_READY) {
	        ++idle_thread_addition;
	    }
	}
	if (all_dead_threads && free_length < idle_spawn_rate) {
	    free_slots[free_length] = i;
	    ++free_length;
	}
	if (!all_dead_threads) {
            last_non_dead = i;
	}
        if (!any_dying_threads) {
            ++total_non_dead;
	    idle_thread_count += idle_thread_addition;
        }
    }
    ap_max_daemons_limit = last_non_dead + 1;

    if (idle_thread_count > max_spare_threads) {
        /* Kill off one child */
        char char_of_death = '!';
        if ((rv = apr_write(pipe_of_death_out, &char_of_death, &one)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf, "write pipe_of_death");
        }
        idle_spawn_rate = 1;
    }
    else if (idle_thread_count < min_spare_threads) {
        /* terminate the free list */
        if (free_length == 0) {
	    /* only report this condition once */
	    static int reported = 0;
	    
	    if (!reported) {
	        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, ap_server_conf,
			     "server reached MaxClients setting, consider"
			     " raising the MaxClients setting");
		reported = 1;
	    }
	    idle_spawn_rate = 1;
	}
	else {
	    
	    if (idle_spawn_rate >= 8) {
	        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, ap_server_conf,
			     "server seems busy, (you may need "
			     "to increase StartServers, ThreadsPerChild "
                             "or Min/MaxSpareThreads), "
			     "spawning %d children, there are around %d idle "
                             "threads, and %d total children", idle_spawn_rate,
			     idle_thread_count, total_non_dead);
	    }
	    for (i = 0; i < free_length; ++i) {
	        make_child(ap_server_conf, free_slots[i], now);
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

static void server_main_loop(int remaining_children_to_start)
{
    int child_slot;
    apr_wait_t status;
    apr_proc_t pid;
    int i;

    while (!restart_pending && !shutdown_pending) {
        ap_wait_or_timeout(&status, &pid, pconf);
        
        if (pid.pid != -1) {
            ap_process_child_status(&pid, status);
            /* non-fatal death... note that it's gone in the scoreboard. */
            child_slot = find_child_by_pid(&pid);
            if (child_slot >= 0) {
                for (i = 0; i < ap_threads_per_child; i++)
                    ap_update_child_status(child_slot, i, SERVER_DEAD, (request_rec *) NULL);
                
		if (remaining_children_to_start
		    && child_slot < ap_daemons_limit) {
		    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
		    make_child(ap_server_conf, child_slot, time(NULL));
		    --remaining_children_to_start;
		}
#if APR_HAS_OTHER_CHILD
	    }
	    else if (apr_reap_other_child(&pid, status) == 0) {
		/* handled */
#endif
	    }
	    else if (is_graceful) {
		/* Great, we've probably just lost a slot in the
		 * scoreboard.  Somehow we don't know about this child.
		 */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0,
		             ap_server_conf,
		             "long lost child came home! (pid %ld)",
		             (long)pid.pid);
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
    }
}

int ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
{
    int remaining_children_to_start;
    apr_status_t rv;
    apr_size_t one = 1;

    pconf = _pconf;
    ap_server_conf = s;
    rv = apr_create_pipe(&pipe_of_death_in, &pipe_of_death_out, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv,
                     (const server_rec*) ap_server_conf,
                     "apr_create_pipe (pipe_of_death)");
        exit(1);
    }

    if ((rv = apr_set_pipe_timeout(pipe_of_death_in, 0)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv,
                     (const server_rec*) ap_server_conf,
                     "apr_set_pipe_timeout (pipe_of_death)");
        exit(1);
    }
    ap_server_conf = s;
    if ((num_listensocks = ap_setup_listeners(ap_server_conf)) < 1) {
        /* XXX: hey, what's the right way for the mpm to indicate a fatal error? */
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, 0, s,
            "no listening sockets available, shutting down");
        return 1;
    }
    ap_log_pid(pconf, ap_pid_fname);

    /* Initialize cross-process accept lock */
    lock_fname = apr_psprintf(_pconf, "%s.%u",
                             ap_server_root_relative(_pconf, lock_fname),
                             ap_my_pid);
    rv = apr_create_lock(&accept_mutex, APR_MUTEX, APR_LOCKALL,
                   lock_fname, _pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "Couldn't create accept lock");
        return 1;
    }


    if (!is_graceful) {
	reinit_scoreboard(pconf);
    }

    set_signals();
    /* Don't thrash... */
    if (max_spare_threads < min_spare_threads + ap_threads_per_child)
	max_spare_threads = min_spare_threads + ap_threads_per_child;

    /* If we're doing a graceful_restart then we're going to see a lot
     * of children exiting immediately when we get into the main loop
     * below (because we just sent them SIGWINCH).  This happens pretty
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

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		"%s configured -- resuming normal operations",
		ap_get_server_version());
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, ap_server_conf,
		"Server built: %s", ap_get_server_built());
    restart_pending = shutdown_pending = 0;

    server_main_loop(remaining_children_to_start);

    if (shutdown_pending) {
        /* Time to gracefully shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        if (unixd_killpg(getpgrp(), SIGTERM) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "killpg SIGTERM");
        }
        ap_reclaim_child_processes(1);		/* Start with SIGTERM */
    
        /* cleanup pid file on normal shutdown */
        {
            const char *pidfile = NULL;
            pidfile = ap_server_root_relative (pconf, ap_pid_fname);
            if ( pidfile != NULL && unlink(pidfile) == 0)
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0,
            		 ap_server_conf,
            		 "removed PID file %s (pid=%ld)",
            		 pidfile, (long)getpid());
        }
    
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
            "caught SIGTERM, shutting down");
    
	return 1;
    }

    /* we've been told to restart */
    apr_signal(SIGHUP, SIG_IGN);

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
	int i, j;
        char char_of_death = '!';

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		    "SIGWINCH received.  Doing graceful restart");

	/* give the children the signal to die */
        for (i = 0; i < ap_daemons_limit;) {
            if ((rv = apr_write(pipe_of_death_in, &char_of_death, &one)) != APR_SUCCESS) {
                if (APR_STATUS_IS_EINTR(rv)) continue;
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf, "write pipe_of_death");
            }
            i++;
        }

	/* This is mostly for debugging... so that we know what is still
         * gracefully dealing with existing request.
         */
	
	for (i = 0; i < ap_daemons_limit; ++i) {
  	    for (j = 0; j < ap_threads_per_child; j++) { 
	        if (ap_scoreboard_image->servers[i][j].status != SERVER_DEAD) {
		    ap_scoreboard_image->servers[i][j].status = SERVER_GRACEFUL;
		}
	    } 
	}
    }
    else {
      /* Kill 'em all.  Since the child acts the same on the parents SIGTERM 
       * and a SIGHUP, we may as well use the same signal, because some user
       * pthreads are stealing signals from us left and right.
       */
	if (unixd_killpg(getpgrp(), SIGTERM) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "killpg SIGTERM");
	}
        ap_reclaim_child_processes(1);		/* Start with SIGTERM */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		    "SIGHUP received.  Attempting to restart");
    }
    if (!is_graceful) {
        ap_restart_time = time(NULL); 
    }
    return 0;
}

static void mpmt_pthread_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static int restart_num = 0;
    int no_detach = 0;

    one_process = !!ap_exists_config_define("ONE_PROCESS");
    no_detach = !!ap_exists_config_define("NO_DETACH");

    /* sigh, want this only the second time around */
    if (restart_num++ == 1) {
	is_graceful = 0;

	if (!one_process && !no_detach) {
	    apr_detach();
	}
	ap_my_pid = getpid();
    }

    unixd_pre_config(ptemp);
    ap_listen_pre_config();
    ap_daemons_to_start = DEFAULT_START_DAEMON;
    min_spare_threads = DEFAULT_MIN_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    max_spare_threads = DEFAULT_MAX_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    ap_daemons_limit = HARD_SERVER_LIMIT;
    ap_threads_per_child = DEFAULT_THREADS_PER_CHILD;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_scoreboard_fname = DEFAULT_SCOREBOARD;
    lock_fname = DEFAULT_LOCKFILE;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    ap_extended_status = 0;

    apr_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));
}

static void mpmt_pthread_hooks(apr_pool_t *p)
{
    INIT_SIGLIST()
    one_process = 0;

    ap_hook_pre_config(mpmt_pthread_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}


static const char *set_pidfile(cmd_parms *cmd, void *dummy, const char *arg) 
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

static const char *set_scoreboard(cmd_parms *cmd, void *dummy,
				  const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_scoreboard_fname = arg;
    return NULL;
}

static const char *set_lockfile(cmd_parms *cmd, void *dummy, const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    lock_fname = arg;
    return NULL;
}

static const char *set_daemons_to_start(cmd_parms *cmd, void *dummy,
					const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_to_start = atoi(arg);
    return NULL;
}

static const char *set_min_spare_threads(cmd_parms *cmd, void *dummy,
					 const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    min_spare_threads = atoi(arg);
    if (min_spare_threads <= 0) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "WARNING: detected MinSpareThreads set to non-positive.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "Resetting to 1 to avoid almost certain Apache failure.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "Please read the documentation.");
       min_spare_threads = 1;
    }
       
    return NULL;
}

static const char *set_max_spare_threads(cmd_parms *cmd, void *dummy,
					 const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_spare_threads = atoi(arg);
    return NULL;
}

static const char *set_server_limit (cmd_parms *cmd, void *dummy,
				     const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_limit = atoi(arg);
    if (ap_daemons_limit > HARD_SERVER_LIMIT) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "WARNING: MaxClients of %d exceeds compile time limit "
                    "of %d servers,", ap_daemons_limit, HARD_SERVER_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " lowering MaxClients to %d.  To increase, please "
                    "see the", HARD_SERVER_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " HARD_SERVER_LIMIT define in %s.",
                    AP_MPM_HARD_LIMITS_FILE);
       ap_daemons_limit = HARD_SERVER_LIMIT;
    } 
    else if (ap_daemons_limit < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, "WARNING: Require MaxClients > 0, setting to 1");
	ap_daemons_limit = 1;
    }
    return NULL;
}

static const char *set_threads_per_child (cmd_parms *cmd, void *dummy,
					  const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_per_child = atoi(arg);
    if (ap_threads_per_child > HARD_THREAD_LIMIT) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "WARNING: ThreadsPerChild of %d exceeds compile time"
                     "limit of %d threads,", ap_threads_per_child,
                     HARD_THREAD_LIMIT);
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     " lowering ThreadsPerChild to %d. To increase, please"
                     " see the", HARD_THREAD_LIMIT);
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     " HARD_THREAD_LIMIT define in %s.",
                     AP_MPM_HARD_LIMITS_FILE);
    }
    else if (ap_threads_per_child < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "WARNING: Require ThreadsPerChild > 0, setting to 1");
	ap_threads_per_child = 1;
    }
    return NULL;
}

static const char *set_max_requests(cmd_parms *cmd, void *dummy,
				    const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_max_requests_per_child = atoi(arg);

    return NULL;
}

static const char *set_coredumpdir (cmd_parms *cmd, void *dummy,
				    const char *arg) 
{
    apr_finfo_t finfo;
    const char *fname;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    fname = ap_server_root_relative(cmd->pool, arg);
    if ((apr_stat(&finfo, fname, APR_FINFO_TYPE, cmd->pool) != APR_SUCCESS) 
        || (finfo.filetype != APR_DIR)) {
	return apr_pstrcat(cmd->pool, "CoreDumpDirectory ", fname, 
			  " does not exist or is not a directory", NULL);
    }
    apr_cpystrn(ap_coredump_dir, fname, sizeof(ap_coredump_dir));
    return NULL;
}

static const command_rec mpmt_pthread_cmds[] = {
UNIX_DAEMON_COMMANDS
LISTEN_COMMANDS
AP_INIT_TAKE1("PidFile", set_pidfile, NULL, RSRC_CONF,
    "A file for logging the server process ID"),
AP_INIT_TAKE1("ScoreBoardFile", set_scoreboard, NULL, RSRC_CONF,
    "A file for Apache to maintain runtime process management information"),
AP_INIT_TAKE1("LockFile", set_lockfile, NULL, RSRC_CONF,
    "The lockfile used when Apache needs to lock the accept() call"),
AP_INIT_TAKE1("StartServers", set_daemons_to_start, NULL, RSRC_CONF,
  "Number of child processes launched at server startup"),
AP_INIT_TAKE1("MinSpareThreads", set_min_spare_threads, NULL, RSRC_CONF,
  "Minimum number of idle children, to handle request spikes"),
AP_INIT_TAKE1("MaxSpareThreads", set_max_spare_threads, NULL, RSRC_CONF,
  "Maximum number of idle children"),
AP_INIT_TAKE1("MaxClients", set_server_limit, NULL, RSRC_CONF,
  "Maximum number of children alive at the same time"),
AP_INIT_TAKE1("ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF,
  "Number of threads each child creates"),
AP_INIT_TAKE1("MaxRequestsPerChild", set_max_requests, NULL, RSRC_CONF,
  "Maximum number of requests a particular child serves before dying."),
AP_INIT_TAKE1("CoreDumpDirectory", set_coredumpdir, NULL, RSRC_CONF,
  "The location of the directory Apache changes to before dumping core"),
{ NULL }
};

module AP_MODULE_DECLARE_DATA mpm_mpmt_pthread_module = {
    MPM20_MODULE_STUFF,
    NULL,                       /* hook to run before apache parses args */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    mpmt_pthread_cmds,		/* command apr_table_t */
    mpmt_pthread_hooks		/* register_hooks */
};

