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

/* This module is effectivly mpmt_pthread much modified to
 * allow it work on BeOS.  It's stable and works OK.
 */
 
#define CORE_PRIVATE 
 
#include "apr_portable.h"
#include "httpd.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "http_config.h"	/* for read_config */ 
#include "http_core.h"		/* for get_remote_host */ 
#include "http_connection.h"
#include "ap_mpm.h"
#include "beosd.h"
#include "iol_socket.h"
#include "ap_listen.h"
#include "scoreboard.h" 
#include "poll.h"
#include "mpm_default.h"

/*
 * Actual definitions of config globals
 */

int ap_threads_per_child=0;         /* Worker threads per child */
int ap_max_requests_per_child=0;
static char *ap_pid_fname=NULL;
static char *ap_scoreboard_fname=NULL;
static int ap_daemons_to_start=0;
static int min_spare_threads=0;
static int max_spare_threads=0;
static int ap_daemons_limit=0;
static time_t ap_restart_time=0;
API_VAR_EXPORT int ap_extended_status = 0;
static int workers_may_exit = 0;
static int requests_this_child;
static int num_listenfds = 0;
static struct pollfd *listenfds;
ap_lock_t *accept_mutex = NULL;

static ap_context_t *pconf;		/* Pool for config stuff */
static ap_context_t *pchild;		/* Pool for httpd child stuff */

static int my_pid; /* Linux getpid() doesn't work except in main thread. Use
                      this instead */

/* Keep track of the number of worker threads currently active */
static int worker_thread_count;
ap_lock_t *worker_thread_count_mutex;

/* The structure used to pass unique initialization info to each thread */
typedef struct {
    int pid;
    thread_id tid;
    int sd;
    ap_context_t *tpool; /* "pthread" would be confusing */
} proc_info;

#define SERVER_DEAD 0
#define SERVER_DYING 1
#define SERVER_ALIVE 2

static struct {
    pid_t pid;
    unsigned char status;
} child_table[HARD_SERVER_LIMIT];

/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with MaxClients changes across SIGWINCH restarts.  We use this
 * value to optimize routines that have to scan the entire scoreboard.
 */
int max_daemons_limit = -1;
static char ap_coredump_dir[MAX_STRING_LEN];
port_id port_of_death;

/* *Non*-shared http_main globals... */

static server_rec *server_conf;

/* one_process */
/* TODO - get this working again... */
static int one_process = 0;

#ifdef DEBUG_SIGSTOP
int raise_sigstop_flags;
#endif

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


/* Global, alas, so http_core can talk to us */
enum server_token_type ap_server_tokens = SrvTk_FULL;

API_EXPORT(const server_rec *) ap_get_server_conf(void)
{
    return (server_conf);
}

API_EXPORT(int) ap_get_max_daemons(void)
{
    return max_daemons_limit;
}

/* a clean exit from a child with proper cleanup 
   static void clean_child_exit(int code) __attribute__ ((noreturn)); */
void clean_child_exit(int code)
{
    if (pchild) {
	ap_destroy_pool(pchild);
    }
    exit(code);
}

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
    return;
#if 0
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
#endif
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

static void reclaim_child_processes(int terminate)
{
    int i, status;
    long int waittime = 1024 * 16;	/* in usecs */
    struct timeval tv;
    int waitret, tries;
    int not_dead_yet;
#ifdef HAS_OTHER_CHILD
    other_child_rec *ocr, *nocr;
#endif

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
        int pid;
        if (child_table[i].status == SERVER_DEAD)
            continue;

	    pid = child_table[i].pid;

	    waitret = waitpid(pid, &status, WNOHANG);
	    if (waitret == pid || waitret == -1) {
		    child_table[i].status = SERVER_DEAD;
		    continue;
	    }
	    ++not_dead_yet;
	    switch (tries) {
	    case 1:     /*  16ms */
	    case 2:     /*  82ms */
		break;
	    case 3:     /* 344ms */
	    case 4:     /*  16ms */
	    case 5:     /*  82ms */
	    case 6:     /* 344ms */
	    case 7:     /* 1.4sec */
		/* ok, now it's being annoying */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING,
			    errno, server_conf,
		   "child process %d still did not exit, sending a SIGTERM",
			    pid);
		kill(pid, SIGTERM);
		break;
	    case 8:     /*  6 sec */
		/* die child scum */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, errno, server_conf,
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
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, errno, server_conf,
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
}

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
    kill(my_pid, sig);
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

void ap_start_shutdown(void)
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
void ap_start_restart(int graceful)
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
    ap_start_restart(sig == SIGWINCH);
}

static void set_signals(void)
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (!one_process) {
	sa.sa_handler = sig_coredump;

	if (sigaction(SIGSEGV, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf, "sigaction(SIGSEGV)");
	if (sigaction(SIGBUS, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf, "sigaction(SIGBUS)");
	if (sigaction(SIGABRT, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf, "sigaction(SIGABRT)");
	if (sigaction(SIGILL, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf, "sigaction(SIGILL)");
	sa.sa_flags = 0;
    }
    sa.sa_handler = sig_term;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf, "sigaction(SIGTERM)");
    if (sigaction(SIGINT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf, "sigaction(SIGINT)");
    
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
    	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf, "sigaction(SIGPIPE)");

    /* we want to ignore HUPs and WINCH while we're busy processing one */
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, SIGWINCH);
    sa.sa_handler = restart;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
    	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf, "sigaction(SIGHUP)");
    if (sigaction(SIGWINCH, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf, "sigaction(SIGWINCH)");
}

static void process_child_status(int pid, ap_wait_t status)
{
    /* Child died... if it died due to a fatal error,
	* we should simply bail out.
	*/
    if ((WIFEXITED(status)) &&
	WEXITSTATUS(status) == APEXIT_CHILDFATAL) {
	ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, errno, server_conf,
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
			     errno, server_conf,
			     "child pid %d exit signal %s (%d), "
			     "possible coredump in %s",
			     pid, (WTERMSIG(status) >= NumSIG) ? "" : 
			     SYS_SIGLIST[WTERMSIG(status)], WTERMSIG(status),
			     ap_coredump_dir);
	    }
	    else {
#endif
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
			     errno, server_conf,
			     "child pid %d exit signal %s (%d)", pid,
			     SYS_SIGLIST[WTERMSIG(status)], WTERMSIG(status));
#ifdef WCOREDUMP
	    }
#endif
#else
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
			 errno, server_conf,
			 "child pid %d exit signal %d",
			 pid, WTERMSIG(status));
#endif
	}
    }
}

static int setup_listeners(server_rec *s)
{
    ap_listen_rec *lr;
    int num_listeners = 0;
    if (ap_listen_open(s->process, s->port)) {
       return 0;
    }
    for (lr = ap_listeners; lr; lr = lr->next) {
        num_listeners++;
    }
    return num_listeners;
}

/*****************************************************************
 * Here follows a long bunch of generic server bookkeeping stuff...
 */

#define sock_disable_nagle(s)	/* NOOP */

int ap_graceful_stop_signalled(void)
{
    /* XXX - Does this really work? - Manoj */
    return is_graceful;
}

/*****************************************************************
 * Child process main loop.
 */

static void process_socket(ap_context_t *p, ap_socket_t *sock, int my_child_num, int my_thread_num)
{
    BUFF *conn_io;
    conn_rec *current_conn;
    ap_iol *iol;
    long conn_id = my_child_num * HARD_THREAD_LIMIT + my_thread_num;
    int csd;

    iol = beos_attach_socket(sock);
    if (iol == NULL) {
        if (errno == EBADF) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, errno, NULL,
                "filedescriptor (%u) larger than FD_SETSIZE (%u) "
                "found, you probably need to rebuild Apache with a "
                "larger FD_SETSIZE", csd, FD_SETSIZE);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, NULL,
                "error attaching to socket");
        }
        ap_close_socket(sock);
	return;
    }

    conn_io = ap_bcreate(p, B_RDWR);
    ap_bpush_iol(conn_io, iol);

    current_conn = ap_new_apr_connection(p, server_conf, conn_io, sock, 
                                         conn_id);

    ap_process_connection(current_conn);
}

static int32 worker_thread(void * dummy)
{
    proc_info * ti = dummy;
    int process_slot = ti->pid;
    int thread_slot = ti->tid;
    ap_context_t *tpool = ti->tpool;
    struct sockaddr sa_client;
    ap_socket_t *csd = NULL;
    ap_context_t *ptrans;		/* Pool for per-transaction stuff */
    ap_socket_t *sd = NULL;
    int srv;
    int curr_pollfd, last_pollfd = 0;
    int thesock;
    sigset_t sig_mask;
    
    free(ti);

    /* block the signals for this thread */
    sigfillset(&sig_mask);
    sigprocmask(SIG_BLOCK, &sig_mask, NULL);

    ap_create_context(&ptrans, tpool);

    ap_lock(worker_thread_count_mutex);
    worker_thread_count++;
    ap_unlock(worker_thread_count_mutex);

    /* TODO: Switch to a system where threads reuse the results from earlier
       poll calls - manoj */
    while (!workers_may_exit) {
        workers_may_exit |= (ap_max_requests_per_child != 0) && (requests_this_child <= 0);
        if (workers_may_exit) break;

        ap_lock(accept_mutex);
        while (!workers_may_exit) {
            srv = poll(listenfds, num_listenfds + 1, -1);
            if (srv < 0) {
                if (errno == EINTR) {
                    continue;
                }

                /* poll() will only return errors in catastrophic
                 * circumstances. Let's try exiting gracefully, for now. */
                ap_log_error(APLOG_MARK, APLOG_ERR,errno,  (const server_rec *)
                             ap_get_server_conf(), "poll: (listen)");
                workers_may_exit = 1;
            }

            if (workers_may_exit) break;

            if (num_listenfds == 1) {
                sd = ap_listeners->sd;
                goto got_fd;
            }
            else {
                /* find a listener */
                curr_pollfd = last_pollfd;
                do {
                    curr_pollfd++;
                    if (curr_pollfd > num_listenfds) {
                        curr_pollfd = 1;
                    }
                    /* XXX: Should we check for POLLERR? */
                    if (listenfds[curr_pollfd].revents & POLLIN) {
                        last_pollfd = curr_pollfd;
                        ap_put_os_sock(&sd, &listenfds[curr_pollfd].fd, tpool); 
                        goto got_fd;
                    }
                } while (curr_pollfd != last_pollfd);
            }
        }
    got_fd:
        if (!workers_may_exit) {
            ap_accept(&csd, sd, ptrans);
            ap_unlock(accept_mutex);
            process_socket(ptrans, csd, process_slot,
                       thread_slot);
            requests_this_child--;
        }
        else {
            ap_unlock(accept_mutex);
            break;
        }
        ap_clear_pool(ptrans);
    }

    ap_destroy_pool(tpool);
    ap_lock(worker_thread_count_mutex);
    worker_thread_count--;
    if (worker_thread_count == 0) {
        /* All the threads have exited, now finish the shutdown process
         * by signalling the sigwait thread */
        kill(my_pid, SIGTERM);
    }
    ap_unlock(worker_thread_count_mutex);

    return (0);
}


static int32 child_main(void * data)
{
    int child_num_arg = (int) data;
    sigset_t sig_mask;
    thread_id thread;
    int i;
    int my_child_num = child_num_arg;
    proc_info *my_info = NULL;
    ap_listen_rec *lr;
    struct sigaction sa;
    int32 msg;
    char buf;
    ap_status_t rv;
        
    my_pid = getpid();
    ap_create_context(&pchild, pconf);

    if (beosd_setup_child()) {
	clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_child_init_hook(pchild, server_conf);

    /*done with init critical section */

    /* All threads should mask signals out, accoring to sigwait(2) man page */
    sigfillset(&sig_mask);
    sigprocmask(SIG_BLOCK, &sig_mask, NULL);
    
    requests_this_child = ap_max_requests_per_child;
    
    /* Set up the pollfd array */
    listenfds = ap_palloc(pchild, sizeof(struct pollfd) * (num_listenfds));
    for (lr = ap_listeners, i = 0; i < num_listenfds; lr = lr->next, ++i) {
        ap_get_os_sock(&listenfds[i].fd , lr->sd);
        listenfds[i].events = POLLIN; /* should we add POLLPRI ?*/
        listenfds[i].revents = 0;
    }

    /* Setup worker threads */

    worker_thread_count = 0;
    if ((rv = ap_create_lock(&worker_thread_count_mutex, APR_MUTEX, 
        APR_CROSS_PROCESS, NULL, pchild)) != APR_SUCCESS) {
        /* Oh dear, didn't manage to create a worker thread mutex, 
           so there's no point on going on with this child... */
        return (0);
    }

    for (i=0; i < ap_threads_per_child; i++) {
        my_info = (proc_info *)malloc(sizeof(proc_info));
        if (my_info == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, server_conf,
		         "malloc: out of memory");
            clean_child_exit(APEXIT_CHILDFATAL);
        }
        my_info->pid = my_child_num;
        my_info->tid = i;
        my_info->sd = 0;
        ap_create_context(&my_info->tpool, pchild);
	
        /* We are creating threads right now */

        if ((thread = spawn_thread(worker_thread, "httpd_worker_thread",
	      B_NORMAL_PRIORITY, my_info)) < B_NO_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, server_conf,
			 "spawn_thread: unable to create worker thread");
            /* In case system resources are maxxed out, we don't want
               Apache running away with the CPU trying to fork over and
               over and over again if we exit. */
            sleep(10);
	        clean_child_exit(APEXIT_CHILDFATAL);
        }
        resume_thread(thread);
    	/* We let each thread update it's own scoreboard entry.  This is done
	     * because it let's us deal with tid better.
	     */
    }

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = just_die;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    /* this blocks until it gets a message... */
    read_port(port_of_death, &msg, &buf, 1);

    return (0);
}

static int make_child(server_rec *s, int slot, time_t now)
{
    thread_id tid;
    
    if (slot + 1 > max_daemons_limit) {
	max_daemons_limit = slot + 1;
    }

    if (one_process) {
    	set_signals();
        child_table[slot].pid = getpid();
        child_table[slot].status = SERVER_ALIVE;
	    //child_main(slot);
    }

    tid = spawn_thread(child_main, "httpd_child", B_NORMAL_PRIORITY,
        (void*)slot);
    if (tid < B_NO_ERROR) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s, 
            "spawn_thread: Unable to fork new process");
	/* In case system resources are maxxed out, we don't want
	   Apache running away with the CPU trying to fork over and
	   over and over again. */
    	sleep(10);

    	return -1;
    }
    resume_thread(tid);
    
    child_table[slot].pid = getpid();
    child_table[slot].status = SERVER_ALIVE;
    return 0;
}

/* start up a bunch of children */
static void startup_children(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < ap_daemons_limit; ++i) {
	if (child_table[i].status  != SERVER_DEAD) {
	    continue;
	}
	if (make_child(server_conf, i, 0) < 0) {
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
    int i, j;
    int idle_thread_count;
    time_t now = 0;
    int free_length;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead;
    int total_non_dead;

    /* initialize the free_list */
    free_length = 0;

    for (i = 0; i < ap_daemons_limit; ++i) {
        if (child_table[i].status == SERVER_DEAD) {
            if (free_length < spawn_rate) {
                free_slots[free_length] = i;
                ++free_length;
            }
        }
        else {
            last_non_dead = i;
        }

    	if (i >= max_daemons_limit && free_length >= spawn_rate) {
	         break;
	    }
    }
    max_daemons_limit = last_non_dead + 1;

    if (free_length > 0) {
    	for (i = 0; i < free_length; ++i) {
	        make_child(server_conf, free_slots[i], now);
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

static void server_main_loop(int remaining_children_to_start)
{
    int child_slot;
    ap_wait_t status;
    int pid;
    int i;

    while (!restart_pending && !shutdown_pending) {
        pid = wait_or_timeout(&status);
        
        if (pid >= 0) {
            process_child_status(pid, status);
            /* non-fatal death... note that it's gone in the scoreboard. */
            child_slot = -1;
            for (i = 0; i < max_daemons_limit; ++i) {
        	if (child_table[i].pid == pid) {
                    int j;

                    child_slot = i;
                    for (j = 0; j < HARD_THREAD_LIMIT; j++) {
                        ap_mpmt_beos_force_reset_connection_status(i * HARD_THREAD_LIMIT + j);
                    }
                    break;
                }
            }
            if (child_slot >= 0) {
                child_table[child_slot].status = SERVER_DEAD;
                
		if (remaining_children_to_start
		    && child_slot < ap_daemons_limit) {
		    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
		    make_child(server_conf, child_slot, time(NULL));
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
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, errno, server_conf,
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
    }
}

int ap_mpm_run(ap_context_t *_pconf, ap_context_t *plog, server_rec *s)
{
    int remaining_children_to_start;
    ap_status_t rv;
    
    pconf = _pconf;
    server_conf = s;
    port_of_death = create_port(1, "httpd_port_of_death");

    if ((num_listenfds = setup_listeners(server_conf)) < 1) {
        /* XXX: hey, what's the right way for the mpm to indicate a fatal error? */
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, errno, s,
            "no listening sockets available, shutting down");
        return 1;
    }
    ap_log_pid(pconf, ap_pid_fname);

    /* create the accept_mutex */
    if ((rv = ap_create_lock(&accept_mutex, APR_MUTEX, APR_CROSS_PROCESS,
        NULL, pconf)) != APR_SUCCESS) {
        /* tsch tsch, can't have more than one thread in the accept loop
           at a time so we need to fall on our sword... */
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

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, errno, server_conf,
		"%s configured -- resuming normal operations",
		ap_get_server_version());
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, errno, server_conf,
		"Server built: %s", ap_get_server_built());
    restart_pending = shutdown_pending = 0;

    server_main_loop(remaining_children_to_start);

    if (shutdown_pending) {
        /* Time to gracefully shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        if (beosd_killpg(getpgrp(), SIGTERM) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf,
             "killpg SIGTERM");
        }
        reclaim_child_processes(1);		/* Start with SIGTERM */
    
        /* cleanup pid file on normal shutdown */
        {
            const char *pidfile = NULL;
            pidfile = ap_server_root_relative (pconf, ap_pid_fname);
            if ( pidfile != NULL && unlink(pidfile) == 0)
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO,
            		 errno, server_conf,
            		 "removed PID file %s (pid=%ld)",
            		 pidfile, (long)getpid());
        }
    
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, errno, server_conf,
            "caught SIGTERM, shutting down");
    
	return 1;
    }

    /* we've been told to restart */
    signal(SIGHUP, SIG_IGN);

    if (one_process) {
	/* not worth thinking about */
	return 1;
    }

    if (is_graceful) {
	int i, j;
        char char_of_death = '!';

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, errno, server_conf,
		    "SIGWINCH received.  Doing graceful restart");

	/* give the children the signal to die */
        for (i = 0; i < ap_daemons_limit;) {
            if(child_table[i].status != SERVER_DEAD) {
                if (write_port(port_of_death, 99, &char_of_death, 1) != B_OK) {
                    if (errno == EINTR) continue;
                    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf,
                       "write port_of_death");
                }
            }
            i++;
        }

    }
    else {
      /* Kill 'em all.  Since the child acts the same on the parents SIGTERM 
       * and a SIGHUP, we may as well use the same signal, because some user
       * pthreads are stealing signals from us left and right.
       */
	if (beosd_killpg(getpgrp(), SIGTERM) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf,
	       "killpg SIGTERM");
	}
        reclaim_child_processes(1);		/* Start with SIGTERM */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, errno, server_conf,
		    "SIGHUP received.  Attempting to restart");
    }
    if (!is_graceful) {
        ap_restart_time = time(NULL); 
    }
    delete_port(port_of_death);
    return 0;
}

static void mpmt_beos_pre_config(ap_context_t *pconf, ap_context_t *plog, ap_context_t *ptemp)
{
    static int restart_num = 0;

    one_process = !!getenv("ONE_PROCESS");

    /* sigh, want this only the second time around */
    if (restart_num++ == 1) {
	is_graceful = 0;

	if (!one_process) {
	    beosd_detach();
	}

	my_pid = getpid();
    }

    beosd_pre_config();
    ap_listen_pre_config();
    ap_daemons_to_start = DEFAULT_START_DAEMON;
    min_spare_threads = DEFAULT_MIN_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    max_spare_threads = DEFAULT_MAX_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    ap_daemons_limit = HARD_SERVER_LIMIT;
    ap_threads_per_child = DEFAULT_THREADS_PER_CHILD;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    ap_mpmt_beos_set_maintain_connection_status(1);

    ap_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));
}

static void mpmt_beos_hooks(void)
{
    INIT_SIGLIST()
    one_process = 0;
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

static const char *set_daemons_to_start(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_to_start = atoi(arg);
    return NULL;
}

static const char *set_min_spare_threads(cmd_parms *cmd, void *dummy, char *arg)
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

static const char *set_max_spare_threads(cmd_parms *cmd, void *dummy, char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_spare_threads = atoi(arg);
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
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "WARNING: MaxClients of %d exceeds compile time limit "
                    "of %d servers,", ap_daemons_limit, HARD_SERVER_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " lowering MaxClients to %d.  To increase, please "
                    "see the", HARD_SERVER_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " HARD_SERVER_LIMIT define in src/include/httpd.h.");
       ap_daemons_limit = HARD_SERVER_LIMIT;
    } 
    else if (ap_daemons_limit < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "WARNING: Require MaxClients > 0, setting to 1");
	ap_daemons_limit = 1;
    }
    return NULL;
}

static const char *set_threads_per_child (cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_per_child = atoi(arg);
    if (ap_threads_per_child > HARD_THREAD_LIMIT) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "WARNING: ThreadsPerChild of %d exceeds compile time"
                     "limit of %d threads,\n", ap_threads_per_child,
                     HARD_THREAD_LIMIT);
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     " lowering ThreadsPerChild to %d. To increase, please"
                     "see the", HARD_THREAD_LIMIT);
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     " HARD_THREAD_LIMIT define in src/include/httpd.h.");
    }
    else if (ap_threads_per_child < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "WARNING: Require ThreadsPerChild > 0, setting to 1");
	ap_threads_per_child = 1;
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

static const char *set_maintain_connection_status(cmd_parms *cmd,
                                                  core_dir_config *d, int arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_mpmt_beos_set_maintain_connection_status(arg != 0);
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
    if ((stat(fname, &finfo) == -1) || !S_ISDIR(finfo.st_mode)) {
	return ap_pstrcat(cmd->pool, "CoreDumpDirectory ", fname, 
			  " does not exist or is not a directory", NULL);
    }
    ap_cpystrn(ap_coredump_dir, fname, sizeof(ap_coredump_dir));
    return NULL;
}

static const command_rec mpmt_beos_cmds[] = {
UNIX_DAEMON_COMMANDS
LISTEN_COMMANDS
{ "PidFile", set_pidfile, NULL, RSRC_CONF, TAKE1,
    "A file for logging the server process ID"},
{ "ScoreBoardFile", set_scoreboard, NULL, RSRC_CONF, TAKE1,
    "A file for Apache to maintain runtime process management information"},
{ "StartServers", set_daemons_to_start, NULL, RSRC_CONF, TAKE1,
  "Number of child processes launched at server startup" },
{ "MinSpareThreads", set_min_spare_threads, NULL, RSRC_CONF, TAKE1,
  "Minimum number of idle children, to handle request spikes" },
{ "MaxSpareThreads", set_max_spare_threads, NULL, RSRC_CONF, TAKE1,
  "Maximum number of idle children" },
{ "MaxClients", set_server_limit, NULL, RSRC_CONF, TAKE1,
  "Maximum number of children alive at the same time" },
{ "ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF, TAKE1,
  "Number of threads each child creates" },
{ "MaxRequestsPerChild", set_max_requests, NULL, RSRC_CONF, TAKE1,
  "Maximum number of requests a particular child serves before dying." },
{ "ConnectionStatus", set_maintain_connection_status, NULL, RSRC_CONF, FLAG,
  "Whether or not to maintain status information on current connections"},
{ "CoreDumpDirectory", set_coredumpdir, NULL, RSRC_CONF, TAKE1,
  "The location of the directory Apache changes to before dumping core" },
{ NULL }
};

module MODULE_VAR_EXPORT mpm_mpmt_beos_module = {
    MPM20_MODULE_STUFF,
    mpmt_beos_pre_config,       /* hook run before the configuration is read */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    mpmt_beos_cmds,		/* command ap_table_t */
    NULL,			/* handlers */
    mpmt_beos_hooks		/* register_hooks */
};

