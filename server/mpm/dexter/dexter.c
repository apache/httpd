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
 
#define CORE_PRIVATE 
 
#include "apr_portable.h"
#include "httpd.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "http_config.h"	/* for read_config */ 
#include "http_core.h"		/* for get_remote_host */ 
#include "http_connection.h"
#include "ap_mpm.h"
#include "unixd.h"
#include "iol_socket.h"
#include "ap_listen.h"
#include "acceptlock.h"
#include "mpm_default.h"
#include "dexter.h"
#include "scoreboard.h"

#include <poll.h>
#include <netinet/tcp.h> 
#include <pthread.h>

/*
 * Actual definitions of config globals
 */

static int threads_to_start = 0;         /* Worker threads per child */
static int min_spare_threads = 0;
static int max_spare_threads = 0;
static int max_threads = 0;
static int max_requests_per_child = 0;
static char *ap_pid_fname=NULL;
static int num_daemons=0;
static int workers_may_exit = 0;
static int requests_this_child;
static int num_listenfds = 0;
static struct pollfd *listenfds;

/* Table of child status */
#define SERVER_DEAD 0
#define SERVER_DYING 1
#define SERVER_ALIVE 2

static struct {
    pid_t pid;
    unsigned char status;
} child_table[HARD_SERVER_LIMIT];

#if 0
#define SAFE_ACCEPT(stmt) do {if (ap_listeners->next != NULL) {stmt;}} while (0)
#else
#define SAFE_ACCEPT(stmt) do {stmt;} while (0)
#endif

/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with NumServers changes across SIGWINCH restarts.  We use this
 * value to optimize routines that have to scan the entire child table.
 *
 * XXX - It might not be worth keeping this code in. There aren't very
 * many child processes in this MPM.
 */
int max_daemons_limit = -1;


static char ap_coredump_dir[MAX_STRING_LEN];

static int pipe_of_death[2];
static pthread_mutex_t pipe_of_death_mutex;

/* *Non*-shared http_main globals... */

static server_rec *server_conf;

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

#ifdef HAS_OTHER_CHILD
/* used to maintain list of children which aren't part of the child table */
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
static ap_context_t *thread_pool_parent; /* Parent of per-thread pools */
static pthread_mutex_t thread_pool_create_mutex;

static int child_num;
static int my_pid; /* Linux getpid() doesn't work except in main thread. Use
                      this instead */
/* Keep track of the number of worker threads currently active */
static int worker_thread_count;
static pthread_mutex_t worker_thread_count_mutex;
static int worker_thread_free_ids[HARD_THREAD_LIMIT];
static pthread_attr_t worker_thread_attr;

/* Keep track of the number of idle worker threads */
static int idle_thread_count;
static pthread_mutex_t idle_thread_count_mutex;

/* Global, alas, so http_core can talk to us */
enum server_token_type ap_server_tokens = SrvTk_FULL;

API_EXPORT(const server_rec *) ap_get_server_conf(void)
{
    return (server_conf);
}

/* a clean exit from a child with proper cleanup 
   static void ap_clean_child_exit(int code) __attribute__ ((noreturn)); */
void ap_clean_child_exit(int code)
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
    kill(getpid(), sig);
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
    ap_clean_child_exit(0);
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

    /* we want to ignore HUPs and WINCH while we're busy processing one */
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, SIGWINCH);
    sa.sa_handler = restart;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGHUP)");
    if (sigaction(SIGWINCH, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "sigaction(SIGWINCH)");
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
#ifdef SIGWINCH
    signal(SIGWINCH, restart);
#endif /* SIGWINCH */
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif /* SIGPIPE */

#endif
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

#if defined(TCP_NODELAY) && !defined(MPE) && !defined(TPF)
static void sock_disable_nagle(int s) /* ZZZ abstract */
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

int ap_graceful_stop_signalled(void)
{
    /* XXX - Does this really work? - Manoj */
    return is_graceful;
}

/*****************************************************************
 * Child process main loop.
 */

static void process_socket(ap_context_t *p, struct sockaddr *sa_client, int csd,
                           int conn_id)
{
    struct sockaddr sa_server; /* ZZZZ */
    NET_SIZE_T len = sizeof(struct sockaddr);
    BUFF *conn_io;
    conn_rec *current_conn;
    ap_iol *iol;

    if (getsockname(csd, &sa_server, &len) < 0) { 
	ap_log_error(APLOG_MARK, APLOG_ERR, server_conf, "getsockname");
	close(csd);
	return;
    }

    sock_disable_nagle(csd);

    iol = unix_attach_socket(csd);
    if (iol == NULL) {
        if (errno == EBADF) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, NULL,
                "filedescriptor (%u) larger than FD_SETSIZE (%u) "
                "found, you probably need to rebuild Apache with a "
                "larger FD_SETSIZE", csd, FD_SETSIZE);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
                "error attaching to socket");
        }
        close(csd);
	return;
    }

    conn_io = ap_bcreate(p, B_RDWR);
    ap_bpush_iol(conn_io, iol);

    current_conn = ap_new_connection(p, server_conf, conn_io,
                                  (const struct sockaddr_in *) sa_client, 
                                  (const struct sockaddr_in *) &sa_server,
                                  conn_id);

    ap_process_connection(current_conn);
}

static void *worker_thread(void *);

/* Starts a thread as long as we're below max_threads */
static int start_thread(void)
{
    pthread_t thread;

    pthread_mutex_lock(&worker_thread_count_mutex);
    if (worker_thread_count < max_threads) {
        if (pthread_create(&thread, &worker_thread_attr, worker_thread,
	  &worker_thread_free_ids[worker_thread_count])) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, server_conf,
                         "pthread_create: unable to create worker thread");
            /* In case system resources are maxxed out, we don't want
               Apache running away with the CPU trying to fork over and
               over and over again if we exit. */
            sleep(10);
            workers_may_exit = 1;
            pthread_mutex_unlock(&worker_thread_count_mutex);
            return 0;
        }
	else {
	    worker_thread_count++;
	}
    }
    else {
        static int reported = 0;
        
        if (!reported) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, server_conf,
                         "server reached MaxThreadsPerChild setting, consider raising the"
                         " MaxThreadsPerChild or NumServers settings");
            reported = 1;
        }
        pthread_mutex_unlock(&worker_thread_count_mutex);
        return 0;
    }
    pthread_mutex_unlock(&worker_thread_count_mutex);
    return 1;

}
/* Sets workers_may_exit if we received a character on the pipe_of_death */
static void check_pipe_of_death(void)
{
    pthread_mutex_lock(&pipe_of_death_mutex);
    if (!workers_may_exit) {
        int ret;
        char pipe_read_char;

        ret = read(listenfds[0].fd, &pipe_read_char, 1);
        if (ret == -1 && errno == EAGAIN) {
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

/* idle_thread_count should be incremented before starting a worker_thread */

static void *worker_thread(void *arg)
{
    struct sockaddr sa_client;
    ap_socket_t *csd = NULL;
    ap_context_t *tpool;		/* Pool for this thread           */
    ap_context_t *ptrans;		/* Pool for per-transaction stuff */
    ap_socket_t *sd = NULL;
    int srv;
    int curr_pollfd, last_pollfd = 0;
    int thread_just_started = 1;
    int thread_num = *((int *) arg);
    long conn_id = child_num * HARD_THREAD_LIMIT + thread_num;
    int native_socket;

    pthread_mutex_lock(&thread_pool_create_mutex);
    ap_create_context(&tpool, thread_pool_parent);
    pthread_mutex_unlock(&thread_pool_create_mutex);
    ap_create_context(&ptrans, tpool);

    while (!workers_may_exit) {
        workers_may_exit |= (max_requests_per_child != 0) && (requests_this_child <= 0);
        if (workers_may_exit) break;
        if (!thread_just_started) {
            pthread_mutex_lock(&idle_thread_count_mutex);
            if (idle_thread_count < max_spare_threads) {
                idle_thread_count++;
                pthread_mutex_unlock(&idle_thread_count_mutex);
            }
            else {
                pthread_mutex_unlock(&idle_thread_count_mutex);
                break;
            }
        }
        else {
            thread_just_started = 0;
        }
        SAFE_ACCEPT(intra_mutex_on(0));
        if (workers_may_exit) {
            SAFE_ACCEPT(intra_mutex_off(0));
            break;
        }
        SAFE_ACCEPT(accept_mutex_on(0));
        while (!workers_may_exit) {
            srv = poll(listenfds, num_listenfds + 1, -1);

            if (srv < 0) {
                if (errno == EINTR) {
                    continue;
                }

                /* poll() will only return errors in catastrophic
                 * circumstances. Let's try exiting gracefully, for now. */
                ap_log_error(APLOG_MARK, APLOG_ERR, (const server_rec *)
                             ap_get_server_conf(), "poll: (listen)");
                workers_may_exit = 1;
            }
            if (workers_may_exit) break;

            if (listenfds[0].revents & POLLIN) {
                /* A process got a signal on the shutdown pipe. Check if we're
                 * the lucky process to die. */
                check_pipe_of_death();
                continue;
            }

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
            ap_accept(&csd, sd);
            SAFE_ACCEPT(accept_mutex_off(0));
            SAFE_ACCEPT(intra_mutex_off(0));
	    pthread_mutex_lock(&idle_thread_count_mutex);
            if (idle_thread_count > min_spare_threads) {
                idle_thread_count--;
            }
            else {
                if (!start_thread()) {
                    idle_thread_count--;
                }
            }
            pthread_mutex_unlock(&idle_thread_count_mutex);
	} else {
            SAFE_ACCEPT(accept_mutex_off(0));
            SAFE_ACCEPT(intra_mutex_off(0));
	    pthread_mutex_lock(&idle_thread_count_mutex);
            idle_thread_count--;
            pthread_mutex_unlock(&idle_thread_count_mutex);
	    break;
	}
        ap_get_os_sock(&native_socket, csd);
        process_socket(ptrans, &sa_client, native_socket, conn_id);
        ap_clear_pool(ptrans);
        requests_this_child--;
    }

    ap_destroy_pool(tpool);
    pthread_mutex_lock(&worker_thread_count_mutex);
    worker_thread_count--;
    worker_thread_free_ids[worker_thread_count] = thread_num;
    if (worker_thread_count == 0) {
        /* All the threads have exited, now finish the shutdown process
         * by signalling the sigwait thread */
        kill(my_pid, SIGTERM);
    }
    pthread_mutex_unlock(&worker_thread_count_mutex);

    return NULL;
}

static void child_main(int child_num_arg)
{
    sigset_t sig_mask;
    int signal_received;
    int i;
    ap_listen_rec *lr;

    my_pid = getpid();
    child_num = child_num_arg;
    ap_create_context(&pchild, pconf);

    /*stuff to do before we switch id's, so we have permissions.*/

    SAFE_ACCEPT(intra_mutex_init(pchild, 1));
    SAFE_ACCEPT(accept_mutex_child_init(pchild));

    if (unixd_setup_child()) {
	ap_clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_child_init_hook(pchild, server_conf);

    /*done with init critical section */

    /* All threads should mask signals out, accoring to sigwait(2) man page */
    sigfillset(&sig_mask);

    if (pthread_sigmask(SIG_SETMASK, &sig_mask, NULL) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, server_conf, "pthread_sigmask");
    }

    requests_this_child = max_requests_per_child;
    
    /* Set up the pollfd array */
    listenfds = ap_palloc(pchild, sizeof(struct pollfd) * (num_listenfds + 1));
    listenfds[0].fd = pipe_of_death[0];
    listenfds[0].events = POLLIN;
    listenfds[0].revents = 0;
    for (lr = ap_listeners, i = 1; i <= num_listenfds; lr = lr->next, ++i) {
        ap_get_os_sock(&listenfds[i].fd, lr->sd);
        listenfds[i].events = POLLIN; /* should we add POLLPRI ?*/
        listenfds[i].revents = 0;
    }

    /* Setup worker threads */

    if (threads_to_start > max_threads) {
        threads_to_start = max_threads;
    }
    idle_thread_count = threads_to_start;
    worker_thread_count = 0;
    for (i = 0; i < max_threads; i++) {
        worker_thread_free_ids[i] = i;
    }
    ap_create_context(&thread_pool_parent, pchild);
    pthread_mutex_init(&thread_pool_create_mutex, NULL);
    pthread_mutex_init(&idle_thread_count_mutex, NULL);
    pthread_mutex_init(&worker_thread_count_mutex, NULL);
    pthread_mutex_init(&pipe_of_death_mutex, NULL);
    pthread_attr_init(&worker_thread_attr);
    pthread_attr_setdetachstate(&worker_thread_attr, PTHREAD_CREATE_DETACHED);

    /* We are creating worker threads right now */
    for (i=0; i < threads_to_start; i++) {
        /* start_thread shouldn't fail here */
        if (!start_thread()) {
            break;
        }
    }

    /* This thread will be the one responsible for handling signals */
    sigemptyset(&sig_mask);
    sigaddset(&sig_mask, SIGTERM);
    sigaddset(&sig_mask, SIGINT);
    sigwait(&sig_mask, &signal_received);
    switch (signal_received) {
        case SIGTERM:
        case SIGINT:
            just_die(signal_received);
            break;
        default:
            ap_log_error(APLOG_MARK, APLOG_ALERT, server_conf,
            "received impossible signal: %d", signal_received);
            just_die(SIGTERM);
    }
}

static int make_child(server_rec *s, int slot, time_t now) /* ZZZ */
{
    int pid;

    if (slot + 1 > max_daemons_limit) {
        max_daemons_limit = slot + 1;
    }

    if (one_process) {
	set_signals();
        child_table[slot].pid = getpid();
        child_table[slot].status = SERVER_ALIVE;
	child_main(slot);
    }

    if ((pid = fork()) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, s, "fork: Unable to fork new process");
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
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, server_conf,
			 "processor unbind failed %d", status);
#endif

        RAISE_SIGSTOP(MAKE_CHILD);

	/* XXX - For an unthreaded server, a signal handler will be necessary
        signal(SIGTERM, just_die);
	*/
        child_main(slot);

	return 0;
    }
    /* else */
    child_table[slot].pid = pid;
    child_table[slot].status = SERVER_ALIVE;

    return 0;
}

/* start up a bunch of children */
static int startup_children(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < num_daemons; ++i) {
	if (child_table[i].status != SERVER_DEAD) {
	    continue;
	}
	if (make_child(server_conf, i, 0) < 0) {
	    break;
	}
	--number_to_start;
    }
    return number_to_start;
}


/*
 * spawn_rate is the number of children that will be spawned on the
 * next maintenance cycle if there aren't enough servers.  It is
 * doubled up to MAX_SPAWN_RATE, and reset only when a cycle goes by
 * without the need to spawn.
 */
static int spawn_rate = 1;
#ifndef MAX_SPAWN_RATE
#define MAX_SPAWN_RATE	(32)
#endif
static int hold_off_on_exponential_spawning;

static void perform_child_maintenance(void)
{
    int i;
    time_t now = 0;
    int free_length;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead = -1;

    /* initialize the free_list */
    free_length = 0;
    
    ap_check_signals();
    
    for (i = 0; i < num_daemons; ++i) {
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
	}
	else if (spawn_rate < MAX_SPAWN_RATE) {
	    spawn_rate *= 2;
	}
    }
    else {
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
            /* non-fatal death... note that it's gone in the child table and
             * clean out the status table. */
            child_slot = -1;
            for (i = 0; i < max_daemons_limit; ++i) {
        	if (child_table[i].pid == pid) {
                    int j;

                    child_slot = i;
                    for (j = 0; j < HARD_THREAD_LIMIT; j++) {
                        ap_reset_connection_status(i * HARD_THREAD_LIMIT + j);
                    }
                    break;
                }
            }
            if (child_slot >= 0) {
                child_table[child_slot].status = SERVER_DEAD;
                
		if (remaining_children_to_start
		    && child_slot < num_daemons) {
		    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
                    /* ZZZ abstract out for AP funcs. */
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
		 * child table.  Somehow we don't know about this
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
	    remaining_children_to_start = \
	    	startup_children(remaining_children_to_start);
	    /* In any event we really shouldn't do the code below because
	     * few of the servers we just started are in the IDLE state
	     * yet, so we'd mistakenly create an extra server.
	     */
	    continue;
	}

	perform_child_maintenance();
    }
}

static ap_status_t cleanup_fd(void *fdptr)
{
    if (close(*((int *) fdptr)) < 0) {
        return APR_EBADF;
    }
    return APR_SUCCESS;
}

int ap_mpm_run(ap_context_t *_pconf, ap_context_t *plog, server_rec *s)
{
    int remaining_children_to_start;
    int i;

    pconf = _pconf;
    server_conf = s;
    if (pipe(pipe_of_death) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR,
                     (const server_rec*) server_conf,
                     "pipe: (pipe_of_death)");
        exit(1);
    }
    ap_register_cleanup(pconf, &pipe_of_death[0], cleanup_fd, cleanup_fd);
    ap_register_cleanup(pconf, &pipe_of_death[1], cleanup_fd, cleanup_fd);
    if (fcntl(pipe_of_death[0], F_SETFD, O_NONBLOCK) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR,
                     (const server_rec*) server_conf,
                     "fcntl: O_NONBLOCKing (pipe_of_death)");
        exit(1);
    }
    server_conf = s;
    if ((num_listenfds = setup_listeners(server_conf)) < 1) {
        /* XXX: hey, what's the right way for the mpm to indicate a fatal error? */
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, s,
            "no listening sockets available, shutting down");
        return 1;
    }
    ap_log_pid(pconf, ap_pid_fname);
    SAFE_ACCEPT(accept_mutex_init(pconf, 1));
    if (!is_graceful) {
        reinit_scoreboard(pconf);
    }
    /* Initialize the child table */
    if (!is_graceful) {
        for (i = 0; i < HARD_SERVER_LIMIT; i++) {
            child_table[i].status = SERVER_DEAD;
        }
    }

    set_signals();

    /* If we're doing a graceful_restart then we're going to see a lot
     * of children exiting immediately when we get into the main loop
     * below (because we just sent them SIGWINCH).  This happens pretty
     * rapidly... and for each one that exits we'll start a new one until
     * we reach at least daemons_min_free.  But we may be permitted to
     * start more than that, so we'll just keep track of how many we're
     * supposed to start up without the 1 second penalty between each fork.
     */
    remaining_children_to_start = num_daemons;
    if (!is_graceful) {
	remaining_children_to_start = \
	    startup_children(remaining_children_to_start);
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

    server_main_loop(remaining_children_to_start);

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

    if (one_process) {
	/* not worth thinking about */
	return 1;
    }

    if (is_graceful) {
        char char_of_death = '!';

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, server_conf,
		    "SIGWINCH received.  Doing graceful restart");

	/* This is mostly for debugging... so that we know what is still
         * gracefully dealing with existing request.
         */
	
	for (i = 0; i < num_daemons; ++i) {
	    if (child_table[i].status != SERVER_DEAD) {
	        child_table[i].status = SERVER_DYING;
	    } 
	}
	/* give the children the signal to die */
        for (i = 0; i < num_daemons;) {
            if (write(pipe_of_death[1], &char_of_death, 1) == -1) {
                if (errno == EINTR) continue;
                ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "write pipe_of_death");
            }
            i++;
        }
    }
    else {
      /* Kill 'em all.  Since the child acts the same on the parents SIGTERM 
       * and a SIGHUP, we may as well use the same signal, because some user
       * pthreads are stealing signals from us left and right.
       */
	if (ap_killpg(getpgrp(), SIGTERM) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "killpg SIGTERM");
	}
        reclaim_child_processes(1);		/* Start with SIGTERM */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, server_conf,
		    "SIGHUP received.  Attempting to restart");
    }
    return 0;
}

static void dexter_pre_config(ap_context_t *p, ap_context_t *plog, ap_context_t *ptemp)
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
    num_daemons = DEFAULT_NUM_DAEMON;
    threads_to_start = DEFAULT_START_THREAD;
    min_spare_threads = DEFAULT_MIN_SPARE_THREAD;
    max_spare_threads = DEFAULT_MAX_SPARE_THREAD;
    max_threads = HARD_THREAD_LIMIT;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_lock_fname = DEFAULT_LOCKFILE;
    max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;

    ap_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));
}

static void dexter_hooks(void)
{
    ap_hook_pre_config(dexter_pre_config, NULL, NULL, HOOK_MIDDLE);
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

static const char *set_lockfile(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_lock_fname = arg;
    return NULL;
}
static const char *set_num_daemons (cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    num_daemons = atoi(arg);
    if (num_daemons > HARD_SERVER_LIMIT) {
       fprintf(stderr, "WARNING: NumServers of %d exceeds compile time limit "
           "of %d servers,\n", num_daemons, HARD_SERVER_LIMIT);
       fprintf(stderr, " lowering NumServers to %d.  To increase, please "
           "see the\n", HARD_SERVER_LIMIT);
       fprintf(stderr, " HARD_SERVER_LIMIT define in src/include/httpd.h.\n");
       num_daemons = HARD_SERVER_LIMIT;
    } 
    else if (num_daemons < 1) {
	fprintf(stderr, "WARNING: Require NumServers > 0, setting to 1\n");
	num_daemons = 1;
    }
    return NULL;
}

static const char *set_threads_to_start (cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    threads_to_start = atoi(arg);
    if (threads_to_start > HARD_THREAD_LIMIT) {
        fprintf(stderr, "WARNING: StartThreads of %d exceeds compile time"
                "limit of %d threads,\n", threads_to_start,
                HARD_THREAD_LIMIT);
        fprintf(stderr, " lowering StartThreads to %d. To increase, please"
                "see the\n", HARD_THREAD_LIMIT);
        fprintf(stderr, " HARD_THREAD_LIMIT define in src/include/httpd.h.\n");
    }
    else if (threads_to_start < 1) {
	fprintf(stderr, "WARNING: Require StartThreads > 0, setting to 1\n");
	threads_to_start = 1;
    }
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
       fprintf(stderr, "WARNING: detected MinSpareThreads set to non-positive.\n");
       fprintf(stderr, "Resetting to 1 to avoid almost certain Apache failure.\n");
       fprintf(stderr, "Please read the documentation.\n");
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
    if (max_spare_threads >= HARD_THREAD_LIMIT) {
       fprintf(stderr, "WARNING: detected MinSpareThreads set higher than\n");
       fprintf(stderr, "HARD_THREAD_LIMIT. Resetting to %d\n", HARD_THREAD_LIMIT);
       max_spare_threads = HARD_THREAD_LIMIT;
    }
    return NULL;
}

static const char *set_max_threads(cmd_parms *cmd, void *dummy, char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_threads = atoi(arg);
    if (max_threads > HARD_THREAD_LIMIT) {
       fprintf(stderr, "WARNING: detected MaxThreadsPerChild set higher than\n");
       fprintf(stderr, "HARD_THREAD_LIMIT. Resetting to %d\n", HARD_THREAD_LIMIT);
       max_threads = HARD_THREAD_LIMIT;
    }
    return NULL;
}

static const char *set_max_requests(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_requests_per_child = atoi(arg);

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

struct ap_thread_mutex {
    pthread_mutex_t mutex;
};

API_EXPORT(ap_thread_mutex *) ap_thread_mutex_new(void)
{
    ap_thread_mutex *mtx;

    mtx = malloc(sizeof(ap_thread_mutex));
    pthread_mutex_init(&(mtx->mutex), NULL);
    return mtx;
}

API_EXPORT(void) ap_thread_mutex_lock(ap_thread_mutex *mtx)
{
    /* Ignoring error conditions here. :( */
    pthread_mutex_lock(&(mtx->mutex));
}

API_EXPORT(void) ap_thread_mutex_unlock(ap_thread_mutex *mtx)
{
    /* Here too. */
    pthread_mutex_unlock(&(mtx->mutex));
}

API_EXPORT(void) ap_thread_mutex_destroy(ap_thread_mutex *mtx)
{
    /* Here too. */
    pthread_mutex_destroy(&(mtx->mutex));
    free(mtx);
}


static const command_rec dexter_cmds[] = {
UNIX_DAEMON_COMMANDS
LISTEN_COMMANDS
{ "PidFile", set_pidfile, NULL, RSRC_CONF, TAKE1,
    "A file for logging the server process ID"},
{ "LockFile", set_lockfile, NULL, RSRC_CONF, TAKE1,
    "The lockfile used when Apache needs to lock the accept() call"},
{ "NumServers", set_num_daemons, NULL, RSRC_CONF, TAKE1,
  "Number of children alive at the same time" },
{ "StartThreads", set_threads_to_start, NULL, RSRC_CONF, TAKE1,
  "Number of threads each child creates" },
{ "MinSpareThreads", set_min_spare_threads, NULL, RSRC_CONF, TAKE1,
  "Minimum number of idle threads per child, to handle request spikes" },
{ "MaxSpareThreads", set_max_spare_threads, NULL, RSRC_CONF, TAKE1,
  "Maximum number of idle threads per child" },
{ "MaxThreadsPerChild", set_max_threads, NULL, RSRC_CONF, TAKE1,
  "Maximum number of threads per child" },
{ "MaxRequestsPerChild", set_max_requests, NULL, RSRC_CONF, TAKE1,
  "Maximum number of requests a particular child serves before dying." },
{ "CoreDumpDirectory", set_coredumpdir, NULL, RSRC_CONF, TAKE1,
  "The location of the directory Apache changes to before dumping core" },
{ NULL }
};

module MODULE_VAR_EXPORT mpm_dexter_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    dexter_cmds,		/* command ap_table_t */
    NULL,			/* handlers */
    dexter_hooks 		/* register_hooks */
};

