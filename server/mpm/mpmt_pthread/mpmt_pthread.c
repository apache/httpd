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
 
#include "httpd.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "http_config.h"	/* for read_config */ 
#include "http_core.h"		/* for get_remote_host */ 
#include "http_connection.h"
#include "ap_mpm.h"
#include "unixd.h"
#include "scoreboard.h" 

#include "http_accept.h"
#include <netinet/tcp.h> 
#include "pthread.h" 

/*
 * Actual definitions of config globals
 */

static int ap_threads_per_child=0;         /* Worker threads per child */
static int ap_acceptors_per_child=0;       /* Accept threads per child */
static int ap_max_requests_per_child=0;
static char *ap_pid_fname=NULL;
static char *ap_scoreboard_fname=NULL;
static char *ap_lock_fname;
static struct in_addr ap_bind_address; /* ZZZZZ Abstract out the in_addr */
static int ap_daemons_to_start=0;
static int ap_daemons_min_free=0;
static int ap_daemons_max_free=0;
static int ap_daemons_limit=0;
static time_t ap_restart_time=0;
static int ap_listenbacklog;
API_VAR_EXPORT int ap_extended_status = 0;


/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with MaxClients changes across SIGWINCH restarts.  We use this
 * value to optimize routines that have to scan the entire scoreboard.
 */
static int max_daemons_limit = -1;

/*
 * During config time, listeners is treated as a NULL-terminated list.
 * ;child_main previously would start at the beginning of the list each time
 * through the loop, so a socket early on in the list could easily starve out
 * sockets later on in the list.  The solution is to start at the listener
 * after the last one processed.  But to do that fast/easily in child_main it's
 * way more convenient for listeners to be a ring that loops back on itself.
 * The routine setup_listeners() is called after config time to both open up
 * the sockets and to turn the NULL-terminated list into a ring that loops back
 * on itself.
 *
 * head_listener is used by each child to keep track of what they consider
 * to be the "start" of the ring.  It is also set by make_child to ensure
 * that new children also don't starve any sockets.
 *
 * Note that listeners != NULL is ensured by read_config().
 */
listen_rec *ap_listeners;

static char ap_coredump_dir[MAX_STRING_LEN];

int ap_pipe_of_death[2];

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

static pool *pconf;		/* Pool for config stuff */
static pool *pchild;		/* Pool for httpd child stuff */

static int my_pid; /* Linux getpid() doesn't work except in main thread. Use
                      this instead */
/* Keep track of the number of worker threads currently active */
static int worker_thread_count;
static pthread_mutex_t worker_thread_count_mutex;

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

#if defined(NSIG)
#define NumSIG NSIG
#elif defined(_NSIG)
#define NumSIG _NSIG
#elif defined(__NSIG)
#define NumSIG __NSIG
#else
#define NumSIG 32   /* for 1998's unixes, this is still a good assumption */
#endif

#ifdef SYS_SIGLIST /* platform has sys_siglist[] */
#define INIT_SIGLIST()  /*nothing*/
#else /* platform has no sys_siglist[], define our own */
#define SYS_SIGLIST ap_sys_siglist
#define INIT_SIGLIST() siglist_init();

const char *ap_sys_siglist[NumSIG];

static void siglist_init(void)
{
    int sig;

    ap_sys_siglist[0] = "Signal 0";
#ifdef SIGHUP
    ap_sys_siglist[SIGHUP] = "Hangup";
#endif
#ifdef SIGINT
    ap_sys_siglist[SIGINT] = "Interrupt";
#endif
#ifdef SIGQUIT
    ap_sys_siglist[SIGQUIT] = "Quit";
#endif
#ifdef SIGILL
    ap_sys_siglist[SIGILL] = "Illegal instruction";
#endif
#ifdef SIGTRAP
    ap_sys_siglist[SIGTRAP] = "Trace/BPT trap";
#endif
#ifdef SIGIOT
    ap_sys_siglist[SIGIOT] = "IOT instruction";
#endif
#ifdef SIGABRT
    ap_sys_siglist[SIGABRT] = "Abort";
#endif
#ifdef SIGEMT
    ap_sys_siglist[SIGEMT] = "Emulator trap";
#endif
#ifdef SIGFPE
    ap_sys_siglist[SIGFPE] = "Arithmetic exception";
#endif
#ifdef SIGKILL
    ap_sys_siglist[SIGKILL] = "Killed";
#endif
#ifdef SIGBUS
    ap_sys_siglist[SIGBUS] = "Bus error";
#endif
#ifdef SIGSEGV
    ap_sys_siglist[SIGSEGV] = "Segmentation fault";
#endif
#ifdef SIGSYS
    ap_sys_siglist[SIGSYS] = "Bad system call";
#endif
#ifdef SIGPIPE
    ap_sys_siglist[SIGPIPE] = "Broken pipe";
#endif
#ifdef SIGALRM
    ap_sys_siglist[SIGALRM] = "Alarm clock";
#endif
#ifdef SIGTERM
    ap_sys_siglist[SIGTERM] = "Terminated";
#endif
#ifdef SIGUSR1
    ap_sys_siglist[SIGUSR1] = "User defined signal 1";
#endif
#ifdef SIGUSR2
    ap_sys_siglist[SIGUSR2] = "User defined signal 2";
#endif
#ifdef SIGCLD
    ap_sys_siglist[SIGCLD] = "Child status change";
#endif
#ifdef SIGCHLD
    ap_sys_siglist[SIGCHLD] = "Child status change";
#endif
#ifdef SIGPWR
    ap_sys_siglist[SIGPWR] = "Power-fail restart";
#endif
#ifdef SIGWINCH
    ap_sys_siglist[SIGWINCH] = "Window changed";
#endif
#ifdef SIGURG
    ap_sys_siglist[SIGURG] = "urgent socket condition";
#endif
#ifdef SIGPOLL
    ap_sys_siglist[SIGPOLL] = "Pollable event occurred";
#endif
#ifdef SIGIO
    ap_sys_siglist[SIGIO] = "socket I/O possible";
#endif
#ifdef SIGSTOP
    ap_sys_siglist[SIGSTOP] = "Stopped (signal)";
#endif
#ifdef SIGTSTP
    ap_sys_siglist[SIGTSTP] = "Stopped";
#endif
#ifdef SIGCONT
    ap_sys_siglist[SIGCONT] = "Continued";
#endif
#ifdef SIGTTIN
    ap_sys_siglist[SIGTTIN] = "Stopped (tty input)";
#endif
#ifdef SIGTTOU
    ap_sys_siglist[SIGTTOU] = "Stopped (tty output)";
#endif
#ifdef SIGVTALRM
    ap_sys_siglist[SIGVTALRM] = "virtual timer expired";
#endif
#ifdef SIGPROF
    ap_sys_siglist[SIGPROF] = "profiling timer expired";
#endif
#ifdef SIGXCPU
    ap_sys_siglist[SIGXCPU] = "exceeded cpu limit";
#endif
#ifdef SIGXFSZ
    ap_sys_siglist[SIGXFSZ] = "exceeded file size limit";
#endif
    for (sig=0; sig < sizeof(ap_sys_siglist)/sizeof(ap_sys_siglist[0]); ++sig)
        if (ap_sys_siglist[sig] == NULL)
            ap_sys_siglist[sig] = "";
}
#endif /* platform has sys_siglist[] */

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

/*****************************************************************
 * Here follows a long bunch of generic server bookkeeping stuff...
 */

/*****************************************************************
 * Connection structures and accounting...
 */


static conn_rec *new_connection(pool *p, server_rec *server, BUFF *inout,
                                const struct sockaddr_in *remaddr,   /* ZZZ */
                                const struct sockaddr_in *saddr,     /* ZZZ */
			     int child_num, int thread_num)
{
    conn_rec *conn = (conn_rec *) ap_pcalloc(p, sizeof(conn_rec));

    /* Got a connection structure, so initialize what fields we can
     * (the rest are zeroed out by pcalloc).
     */

    conn->child_num = child_num;
    conn->thread_num = thread_num;

    conn->pool = p;
    conn->local_addr = *saddr;
    conn->base_server = server;
    conn->client = inout;

    conn->remote_addr = *remaddr;
    conn->remote_ip = ap_pstrdup(conn->pool,
			      inet_ntoa(conn->remote_addr.sin_addr));

    return conn;
}

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


static int make_sock(pool *p, const struct sockaddr_in *server) 
     /* abstract sockaddr_in */
{
    int s;
    int one = 1;
    char addr[512];

    if (server->sin_addr.s_addr != htonl(INADDR_ANY))
	ap_snprintf(addr, sizeof(addr), "address %s port %d",
		inet_ntoa(server->sin_addr), ntohs(server->sin_port));
    else
	ap_snprintf(addr, sizeof(addr), "port %d", ntohs(server->sin_port));

    /* note that because we're about to slack we don't use psocket */
    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, server_conf,
		    "make_sock: failed to get a socket for %s", addr);
        printf("make_sock: failed to get socket for %s\n", addr);
	exit(1);
    }

    /* Solaris (probably versions 2.4, 2.5, and 2.5.1 with various levels
     * of tcp patches) has some really weird bugs where if you dup the
     * socket now it breaks things across SIGHUP restarts.  It'll either
     * be unable to bind, or it won't respond.
     */
#if defined (SOLARIS2) && SOLARIS2 < 260
#define WORKAROUND_SOLARIS_BUG
#endif

    /* PR#1282 Unixware 1.x appears to have the same problem as solaris */
#if defined (UW) && UW < 200
#define WORKAROUND_SOLARIS_BUG
#endif

    /* PR#1973 NCR SVR4 systems appear to have the same problem */
#if defined (MPRAS)
#define WORKAROUND_SOLARIS_BUG
#endif

#ifndef WORKAROUND_SOLARIS_BUG
    s = ap_slack(s, AP_SLACK_HIGH);

    ap_note_cleanups_for_socket(p, s);	/* arrange to close on exec or restart */
#endif

#ifndef MPE
/* MPE does not support SO_REUSEADDR and SO_KEEPALIVE */
#ifndef _OSD_POSIX
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(int)) < 0) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, server_conf,
		    "make_sock: for %s, setsockopt: (SO_REUSEADDR)", addr);
        printf("make_sock: failed to setsockopt for %s\n", addr);
	close(s);
	return 0; 
    }
#endif /*_OSD_POSIX*/
    one = 1;
#ifndef BEOS
/* BeOS does not support SO_KEEPALIVE */
    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(int)) < 0) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, server_conf,
		    "make_sock: for %s, setsockopt: (SO_KEEPALIVE)", addr);
	close(s);
	return 0;
    }
#endif
#endif

    sock_disable_nagle(s);
/*    sock_enable_linger(s);  XXX - Need to reenable? - Manoj */



    /*
     * To send data over high bandwidth-delay connections at full
     * speed we must force the TCP window to open wide enough to keep the
     * pipe full.  The default window size on many systems
     * is only 4kB.  Cross-country WAN connections of 100ms
     * at 1Mb/s are not impossible for well connected sites.
     * If we assume 100ms cross-country latency,
     * a 4kB buffer limits throughput to 40kB/s.
     *
     * To avoid this problem I've added the SendBufferSize directive
     * to allow the web master to configure send buffer size.
     *
     * The trade-off of larger buffers is that more kernel memory
     * is consumed.  YMMV, know your customers and your network!
     *
     * -John Heidemann <johnh@isi.edu> 25-Oct-96
     *
     * If no size is specified, use the kernel default.
     */
#ifndef BEOS			/* BeOS does not support SO_SNDBUF */
    if (server_conf->send_buffer_size) {
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		(char *) &server_conf->send_buffer_size, sizeof(int)) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf,
			"make_sock: failed to set SendBufferSize for %s, "
			"using default", addr);
	    /* not a fatal error */
	}
    }
#endif

#ifdef MPE
/* MPE requires CAP=PM and GETPRIVMODE to bind to ports less than 1024 */
    if (ntohs(server->sin_port) < 1024)
	GETPRIVMODE();
#endif
    if (bind(s, (struct sockaddr *) server, sizeof(struct sockaddr_in)) == -1) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, server_conf,
	    "make_sock: could not bind to %s", addr);
#ifdef MPE
	if (ntohs(server->sin_port) < 1024)
	    GETUSERMODE();
#endif
	close(s);
	exit(1);
    }
#ifdef MPE
    if (ntohs(server->sin_port) < 1024)
	GETUSERMODE();
#endif

    if (listen(s, ap_listenbacklog) == -1) {
	ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
	    "make_sock: unable to listen for connections on %s", addr);
	close(s);
	exit(1);
    }

#ifdef WORKAROUND_SOLARIS_BUG
    s = ap_slack(s, AP_SLACK_HIGH);

    ap_note_cleanups_for_socket(p, s);	/* arrange to close on exec or restart */
#endif

#ifdef CHECK_FD_SETSIZE
    /* protect various fd_sets */
    if (s >= FD_SETSIZE) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, NULL,
	    "make_sock: problem listening on %s, filedescriptor (%u) "
	    "larger than FD_SETSIZE (%u) "
	    "found, you probably need to rebuild Apache with a "
	    "larger FD_SETSIZE", addr, s, FD_SETSIZE);
	close(s);
	return 0;
    }
#endif

    return s;
}


/*
 * During a restart we keep track of the old listeners here, so that we
 * can re-use the sockets.  We have to do this because we won't be able
 * to re-open the sockets ("Address already in use").
 *
 * Unlike the listeners ring, old_listeners is a NULL terminated list.
 *
 * copy_listeners() makes the copy, find_listener() finds an old listener
 * and close_unused_listener() cleans up whatever wasn't used.
 */
static listen_rec *old_listeners;

/* unfortunately copy_listeners may be called before listeners is a ring */
static void copy_listeners(pool *p)
{
    listen_rec *lr;

    ap_assert(old_listeners == NULL);
    if (ap_listeners == NULL) {
	return;
    }
    lr = ap_listeners;
    do {
	listen_rec *nr = malloc(sizeof *nr);
	if (nr == NULL) {
	    fprintf(stderr, "Ouch!  malloc failed in copy_listeners()\n");
	    exit(1);
	}
	*nr = *lr;
	ap_kill_cleanups_for_socket(p, nr->fd);
        nr->next = old_listeners;
	old_listeners = nr;
	lr = lr->next;
    } while (lr && lr != ap_listeners);
}


static int find_listener(listen_rec *lr)
{
    listen_rec *or;
    for (or = old_listeners; or; or = or->next) {
	if (!memcmp(&or->local_addr, &lr->local_addr, sizeof(or->local_addr))) {
	    or->used = 1;
            return or->fd;
	}
    }
    return -1;
}


static void close_unused_listeners(void)
{
    listen_rec *or, *next;

    for (or = old_listeners; or; or = next) {
	next = or->next;
	if (!or->used) 
	    closesocket(or->fd);
	free(or);
    }
    old_listeners = NULL;
}


/* open sockets, and turn the listeners list into a singly linked ring */
static int setup_listeners(pool *p)
{
    listen_rec *lr;
    int fd;
    int listener_count = 0;

    lr = ap_listeners;
    for (;;) {
	fd = find_listener(lr);
	if (fd < 0) {
	    fd = make_sock(p, &lr->local_addr);
	}
	else {
	    ap_note_cleanups_for_socket(p, fd);
	}
	if (fd >= 0) {
            ++listener_count;
	}
	lr->fd = fd;
	if (lr->next == NULL)
	    break;
	lr = lr->next;
    }
    /* turn the list into a ring */
    /*
    lr->next = ap_listeners;
    head_listener = ap_listeners;
    */

    close_unused_listeners();

#ifdef NO_SERIALIZED_ACCEPT
    /* warn them about the starvation problem if they're using multiple
     * sockets
     */
    if (ap_listeners->next != ap_listeners) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_CRIT, NULL,
		    "You cannot use multiple Listens safely on your system, "
		    "proceeding anyway.  See src/PORTING, search for "
		    "SERIALIZED_ACCEPT.");
    }
#endif
    return listener_count;
}

int ap_graceful_stop_signalled(void)
{
    /* XXX - Does this really work? - Manoj */
    return is_graceful;
}

/*****************************************************************
 * Child process main loop.
 */

static void process_socket(pool *p, struct sockaddr *sa_client, int csd, int my_child_num, int my_thread_num)
{
    struct sockaddr sa_server; /* ZZZZ */
    size_t len = sizeof(struct sockaddr);
    BUFF *conn_io;
    conn_rec *current_conn;

    ap_note_cleanups_for_fd(p, csd);

    /* ZZZ change to AP func */
    if (getsockname(csd, &sa_server, &len) < 0) { 
	ap_log_error(APLOG_MARK, APLOG_ERR, server_conf, "getsockname");
	return;
    }
    (void) ap_update_child_status(my_child_num, my_thread_num,  
				  SERVER_BUSY_READ, (request_rec *) NULL);
    conn_io = ap_bcreate(p, B_RDWR | B_SOCKET);
    ap_bpushfd(conn_io, csd);

    current_conn = new_connection(p, server_conf, conn_io,
                                  (const struct sockaddr_in *) sa_client, 
                                  (const struct sockaddr_in *) &sa_server, 
                                  my_child_num, my_thread_num);

    ap_process_connection(current_conn);
}

static void * worker_thread(void * dummy)
{
    proc_info * ti = dummy;
    int process_slot = ti->pid;
    int thread_slot = ti->tid;
    pool *tpool = ti->tpool;
    struct sockaddr sa_client;
    int csd;
    pool *ptrans;		/* Pool for per-transaction stuff */

    free(ti);

    ptrans = ap_make_sub_pool(tpool);

    pthread_mutex_lock(&worker_thread_count_mutex);
    worker_thread_count++;
    pthread_mutex_unlock(&worker_thread_count_mutex);

    while (1) {
        (void) ap_update_child_status(process_slot, thread_slot, SERVER_READY, 
				  (request_rec *) NULL);
        csd = get_connection(&sa_client);
	if (csd < 0) {
            break;
        } 
        process_socket(ptrans, &sa_client, csd, process_slot, thread_slot);
	ap_clear_pool(ptrans);
    }

    ap_destroy_pool(tpool);
    ap_update_child_status(process_slot, thread_slot, SERVER_DEAD,
        (request_rec *) NULL);
    pthread_mutex_lock(&worker_thread_count_mutex);
    worker_thread_count--;
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
    pthread_t thread;
    pthread_attr_t thread_attr;
    int i;
    int my_child_num = child_num_arg;
    proc_info *my_info = NULL;

    my_pid = getpid();
    pchild = ap_make_sub_pool(pconf);

    /*stuff to do before we switch id's, so we have permissions.*/
    reopen_scoreboard(pchild);

    if (unixd_setup_child()) {
	clean_child_exit(APEXIT_CHILDFATAL);
    }

    accept_child_init(pchild, ap_threads_per_child);
    ap_child_init_hook(pchild, server_conf);

    /*done with init critical section */

    /* All threads should mask signals out, accoring to sigwait(2) man page */
    sigemptyset(&sig_mask);

    if (pthread_sigmask(SIG_SETMASK, &sig_mask, NULL) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, server_conf, "pthread_sigmask");
    }

    /* Setup worker threads */

    worker_thread_count = 0;
    pthread_mutex_init(&worker_thread_count_mutex, NULL);
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    for (i=0; i < ap_threads_per_child; i++) {

	my_info = (proc_info *)malloc(sizeof(proc_info));
        if (my_info == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, server_conf,
		         "malloc: out of memory");
            clean_child_exit(APEXIT_CHILDFATAL);
        }
	my_info->pid = my_child_num;
        my_info->tid = i;
	my_info->sd = 0;
	my_info->tpool = ap_make_sub_pool(pchild);
	
	/* We are creating threads right now */
	(void) ap_update_child_status(my_child_num, i, SERVER_STARTING, 
				      (request_rec *) NULL);
	if (pthread_create(&thread, &thread_attr, worker_thread, my_info)) {
	    ap_log_error(APLOG_MARK, APLOG_ALERT, server_conf,
			 "pthread_create: unable to create worker thread");
            /* In case system resources are maxxed out, we don't want
               Apache running away with the CPU trying to fork over and
               over and over again if we exit. */
            sleep(10);
	    clean_child_exit(APEXIT_CHILDFATAL);
	}

	/* We let each thread update it's own scoreboard entry.  This is done
	 * because it let's us deal with tid better.
	 */
    }

    pthread_attr_destroy(&thread_attr);
    start_accepting_connections(my_child_num);

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

    if (ap_acceptors_per_child + ap_threads_per_child  > HARD_THREAD_LIMIT) {
        ap_log_error(APLOG_MARK, APLOG_ERR, s,
		     "Worker threads plus acceptor threads is greater than HARD_THREAD_LIMIT, please correct");
	exit(-1);
    }


    if (slot + 1 > max_daemons_limit) {
	max_daemons_limit = slot + 1;
    }

    if (one_process) {
	set_signals();
        ap_scoreboard_image->parent[slot].pid = getpid();
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
	if (make_child(server_conf, i, 0) < 0) {
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
    int idle_count_ceil, idle_count_floor, idle_thread_count;
    thread_score *ss;
    time_t now = 0;
    int free_length;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead;
    int total_non_dead;

    /* initialize the free_list */
    free_length = 0;

    idle_count_ceil = 0;
    idle_count_floor = 0;
    idle_thread_count = 0;
    last_non_dead = -1;
    total_non_dead = 0;

    ap_check_signals();

    ap_sync_scoreboard_image();
    for (i = 0; i < ap_daemons_limit; ++i) {
	/* Initialization to satisfy the compiler. It doesn't know
	 * that ap_threads_per_child is always > 0 */
	int status = SERVER_DEAD;
	int any_dying_threads = 0;
	int all_dead_threads = 1;
	int idle_thread_addition = 0;

	if (i >= max_daemons_limit && free_length == idle_spawn_rate)
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
    max_daemons_limit = last_non_dead + 1;
    idle_count_floor = idle_thread_count / ap_threads_per_child;
    idle_count_ceil = idle_count_floor;
    if (idle_thread_count % ap_threads_per_child) {
        idle_count_ceil++;
    }

    if (idle_count_ceil > ap_daemons_max_free) {
        /* Kill off one child */
        char char_of_death = '!';
        if (write(ap_pipe_of_death[1], &char_of_death, 1) == -1) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "write ap_pipe_of_death");
        }
        idle_spawn_rate = 1;
    }
    else if (idle_count_floor < ap_daemons_min_free) {
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
	    /* ZZZZ */
	    
	    if (idle_spawn_rate >= 8) {
	        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, server_conf,
			     "server seems busy, (you may need "
			     "to increase StartServers, or Min/MaxSpareServers), "
			     "spawning %d children, there are %d idle, and "
			     "%d total children", idle_spawn_rate,
			     idle_count_floor, total_non_dead);
	    }
	    for (i = 0; i < free_length; ++i) {
	        make_child(server_conf, free_slots[i], now);
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
    ap_wait_t status;
    int pid;
    int i;

    while (!restart_pending && !shutdown_pending) {
        pid = wait_or_timeout(&status);
        
        if (pid >= 0) {
            child_slot = find_child_by_pid(pid);
            if (child_slot >= 0) {
                for (i = 0; i < ap_threads_per_child + ap_acceptors_per_child; i++)
                    ap_update_child_status(child_slot, i, SERVER_DEAD, (request_rec *) NULL);
                
		if (remaining_children_to_start
		    && child_slot < ap_daemons_limit) {
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
    }
}

int ap_mpm_run(pool *_pconf, pool *plog, server_rec *s)
{
    int remaining_children_to_start;
    int listener_count;

    pconf = _pconf;
    server_conf = s;
    if (pipe(ap_pipe_of_death) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR,
                     (const server_rec*) server_conf,
                     "pipe: (pipe_of_death)");
        exit(1);
    }
    ap_note_cleanups_for_fd(pconf, ap_pipe_of_death[0]);
    ap_note_cleanups_for_fd(pconf, ap_pipe_of_death[1]);
    if (fcntl(ap_pipe_of_death[0], F_SETFD, O_NONBLOCK) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR,
                     (const server_rec*) server_conf,
                     "fcntl: O_NONBLOCKing (pipe_of_death)");
        exit(1);
    }
    server_conf = s;
    listener_count = setup_listeners(pconf);
    ap_clear_pool(plog);
    ap_open_logs(server_conf, plog);
    ap_log_pid(pconf, ap_pid_fname);
    accept_parent_init(pconf, listener_count);
    if (!is_graceful) {
	reinit_scoreboard(pconf);
    }

    set_signals();
    /* set up get_socket */

    if (ap_daemons_max_free < ap_daemons_min_free + 1)	/* Don't thrash... */
	ap_daemons_max_free = ap_daemons_min_free + 1;

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

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, server_conf,
		    "SIGWINCH received.  Doing graceful restart");

	/* kill off the idle ones */
        for (i = 0; i < ap_daemons_limit; ++i) {
            if (write(ap_pipe_of_death[1], &char_of_death, 1) == -1) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "write ap_pipe_of_death");
            }
        }

	/* This is mostly for debugging... so that we know what is still
         * gracefully dealing with existing request.
         */
	
	for (i = 0; i < ap_daemons_limit; ++i) {
  	    for (j = 0; j < ap_threads_per_child + ap_acceptors_per_child; 
		 j++) { 
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
	if (ap_killpg(getpgrp(), SIGTERM) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "killpg SIGTERM");
	}
        reclaim_child_processes(1);		/* Start with SIGTERM */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, server_conf,
		    "SIGHUP received.  Attempting to restart");
    }
    copy_listeners(pconf);
    if (!is_graceful) {
        ap_restart_time = time(NULL); /* ZZZZZ */
    }
    return 0;
}

static void mpmt_pthread_pre_command_line(pool *pcommands)
{
    INIT_SIGLIST()
    one_process = 0;
}

static void mpmt_pthread_pre_config(pool *pconf, pool *plog, pool *ptemp)
{
    static int restart_num = 0;

    one_process = ap_exists_config_define("ONE_PROCESS");

    /* sigh, want this only the second time around */
    if (restart_num++ == 1) {
	is_graceful = 0;

	if (!one_process) {
	    unixd_detach();
	}

	my_pid = getpid();
    }

    unixd_pre_config();
    ap_daemons_to_start = DEFAULT_START_DAEMON;
    ap_daemons_min_free = DEFAULT_MIN_FREE_DAEMON;
    ap_daemons_max_free = DEFAULT_MAX_FREE_DAEMON;
    ap_daemons_limit = HARD_SERVER_LIMIT;
    ap_threads_per_child = DEFAULT_THREADS_PER_CHILD;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_scoreboard_fname = DEFAULT_SCOREBOARD;
    ap_lock_fname = DEFAULT_LOCKFILE;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    /* ZZZ  Initialize the Network Address here. */
    ap_bind_address.s_addr = htonl(INADDR_ANY);
    ap_listeners = NULL;
    ap_listenbacklog = DEFAULT_LISTENBACKLOG;
    ap_extended_status = 0;

    ap_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));
}

static void mpmt_pthread_post_config(pool *pconf, pool *plog, pool *ptemp, server_rec *s)
{
    if (ap_listeners == NULL) {
	/* allocate a default listener */
	listen_rec *new;

	new = ap_pcalloc(pconf, sizeof(listen_rec));
	new->local_addr.sin_family = AF_INET;
	new->local_addr.sin_addr = ap_bind_address;
	new->local_addr.sin_port = htons(s->port ? s->port : DEFAULT_HTTP_PORT);
	new->fd = -1;
	new->next = NULL;
	ap_listeners = new;
    }
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

static const char *set_threads_per_child (cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_per_child = atoi(arg);
    if (ap_threads_per_child < 1) {
	fprintf(stderr, "WARNING: Require ThreadsPerChild > 0, setting to 1\n");
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

static const char *set_listenbacklog(cmd_parms *cmd, void *dummy, char *arg) 
{
    int b;

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    b = atoi(arg);
    if (b < 1) {
        return "ListenBacklog must be > 0";
    }
    ap_listenbacklog = b;
    return NULL;
}

static const char *set_listener(cmd_parms *cmd, void *dummy, char *ips)
{
    listen_rec *new;
    char *ports;
    unsigned short port;

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ports = strchr(ips, ':');
    if (ports != NULL) {
	if (ports == ips) {
	    return "Missing IP address";
	}
	else if (ports[1] == '\0') {
	    return "Address must end in :<port-number>";
	}
	*(ports++) = '\0';
    }
    else {
	ports = ips;
    }

    new=ap_pcalloc(cmd->pool, sizeof(listen_rec));
    /* ZZZ let's set this using the AP funcs. */
    new->local_addr.sin_family = AF_INET;
    if (ports == ips) { /* no address */
      /*  ZZZ Initialize the Network Address */
	new->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else {
	new->local_addr.sin_addr.s_addr = ap_get_virthost_addr(ips, NULL);
    }
    port = atoi(ports);
    if (!port) {
	return "Port must be numeric";
    }
    /* ZZZ change to AP funcs.*/
    new->local_addr.sin_port = htons(port);
    new->fd = -1;    /*ZZZ change to NULL */
    new->used = 0;
    new->next = ap_listeners;
    ap_listeners = new;
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


static const command_rec mpmt_pthread_cmds[] = {
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
{ "ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF, TAKE1,
  "Number of threads each child creates" },
{ "MaxRequestsPerChild", set_max_requests, NULL, RSRC_CONF, TAKE1,
  "Maximum number of requests a particular child serves before dying." },
{ "CoreDumpDirectory", set_coredumpdir, NULL, RSRC_CONF, TAKE1,
  "The location of the directory Apache changes to before dumping core" },
{ "ListenBacklog", set_listenbacklog, NULL, RSRC_CONF, TAKE1,
  "Maximum length of the queue of pending connections, as used by listen(2)" },
{ "Listen", set_listener, NULL, RSRC_CONF, TAKE1,
  "A port number or a numeric IP address and a port number"},
{ NULL }
};

module MODULE_VAR_EXPORT mpm_mpmt_pthread_module = {
    STANDARD20_MODULE_STUFF,
    mpmt_pthread_pre_command_line,	/* pre_command_line */
    mpmt_pthread_pre_config,		/* pre_config */
    mpmt_pthread_post_config,	/* post_config */
    NULL,			/* open_logs */
    NULL, 			/* child_init */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    mpmt_pthread_cmds,		/* command table */
    NULL,			/* handlers */
    NULL,			/* translate_handler */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* pre-run fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL			/* post_read_request */
};

/* force Expat to be linked into the server executable */
#if defined(USE_EXPAT) && !defined(SHARED_CORE_BOOTSTRAP)
#include "xmlparse.h"
const XML_LChar *suck_in_expat(void);
const XML_LChar *suck_in_expat(void)
{
    return XML_ErrorString(XML_ERROR_NONE);
}
#endif /* USE_EXPAT */

#include "acceptlock.c"
#include "http_accept.c"
#include "scoreboard.c"
