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
#define INCL_DOS
#define INCL_DOSERRORS

#include "ap_config.h"
#include "httpd.h"
#include "mpm_default.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"		/* for get_remote_host */
#include "http_connection.h"
#include "scoreboard.h"
#include "ap_mpm.h"
#include "apr_listen.h"
#include "ap_iol.h"
#include "apr_portable.h"
#include "mpm_common.h"

#include <os2.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <process.h>
#include <time.h>
#include <io.h>

/* config globals */

static int ap_max_requests_per_child=0;
static char *ap_pid_fname=NULL;
static int ap_daemons_to_start=0;
static int ap_daemons_min_free=0;
static int ap_daemons_max_free=0;
static int ap_daemons_limit=0;
static time_t ap_restart_time=0;
static int ap_extended_status = 0;

/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with MaxClients changes across SIGUSR1 restarts.  We use this
 * value to optimize routines that have to scan the entire scoreboard.
 */
static int max_daemons_limit = -1;

char ap_coredump_dir[MAX_STRING_LEN];

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

static apr_pool_t *pconf;		/* Pool for config stuff */
static scoreboard *ap_scoreboard_image = NULL;

struct thread_globals {
    int child_num;
    apr_pool_t *pchild;		/* Pool for httpd child stuff */
    int usr1_just_die;
};

static struct thread_globals **ppthread_globals = NULL;

#define THREAD_GLOBAL(gvar) ((*ppthread_globals)->gvar)


void reinit_scoreboard(apr_pool_t *p)
{
    if (ap_scoreboard_image == NULL) {
        ap_scoreboard_image = (scoreboard *) malloc(SCOREBOARD_SIZE);

        if (ap_scoreboard_image == NULL) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                         "Ouch! Out of memory reiniting scoreboard!");
        }
    }

    memset(ap_scoreboard_image, 0, SCOREBOARD_SIZE);
}

void cleanup_scoreboard(void)
{
    ap_assert(ap_scoreboard_image);
    free(ap_scoreboard_image);
    ap_scoreboard_image = NULL;
}


/* a clean exit from a child with proper cleanup */
static void clean_child_exit(int code)
{
    if (THREAD_GLOBAL(pchild)) {
        apr_destroy_pool(THREAD_GLOBAL(pchild));
    }

    ap_scoreboard_image->servers[THREAD_GLOBAL(child_num)].thread_retval = code;
    _endthread();
}



static apr_lock_t *accept_mutex = NULL;

static apr_status_t accept_mutex_child_cleanup(void *foo)
{
    return apr_unlock(accept_mutex);
}

/*
 * Initialize mutex lock.
 * Done by each child at it's birth
 */
static void accept_mutex_child_init(apr_pool_t *p)
{
    apr_register_cleanup(p, NULL, accept_mutex_child_cleanup, apr_null_cleanup);
}

/*
 * Initialize mutex lock.
 * Must be safe to call this on a restart.
 */
static void accept_mutex_init(apr_pool_t *p)
{
    apr_status_t rc = apr_create_lock(&accept_mutex, APR_MUTEX, APR_INTRAPROCESS, NULL, p);

    if (rc != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, rc, ap_server_conf,
		    "Error creating accept lock. Exiting!");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}

static void accept_mutex_on(void)
{
    apr_status_t rc = apr_lock(accept_mutex);

    if (rc != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, rc, ap_server_conf,
		    "Error getting accept lock. Exiting!");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}

static void accept_mutex_off(void)
{
    apr_status_t rc = apr_unlock(accept_mutex);

    if (rc != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, rc, ap_server_conf,
		    "Error freeing accept lock. Exiting!");
	clean_child_exit(APEXIT_CHILDFATAL);
    }
}



/* On some architectures it's safe to do unserialized accept()s in the single
 * Listen case.  But it's never safe to do it in the case where there's
 * multiple Listen statements.  Define SINGLE_LISTEN_UNSERIALIZED_ACCEPT
 * when it's safe in the single Listen case.
 */
#ifdef SINGLE_LISTEN_UNSERIALIZED_ACCEPT
#define SAFE_ACCEPT(stmt) do {if (ap_listeners->next) {stmt;}} while(0)
#else
#define SAFE_ACCEPT(stmt) do {stmt;} while(0)
#endif

API_EXPORT(int) ap_exists_scoreboard_image(void)
{
    return (ap_scoreboard_image ? 1 : 0);
}

API_EXPORT(int) ap_get_max_daemons(void)
{
    return max_daemons_limit;
}

int ap_update_child_status(int child_num, int status, request_rec *r)
{
    int old_status;
    short_score *ss;

    if (child_num < 0)
	return -1;

    ss = &ap_scoreboard_image->servers[child_num];
    old_status = ss->status;
    ss->status = status;

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
	    apr_cpystrn(ss->client, ap_get_remote_host(c, r->per_dir_config,
				  REMOTE_NOLOOKUP), sizeof(ss->client));
	    if (r->the_request == NULL) {
		    apr_cpystrn(ss->request, "NULL", sizeof(ss->request));
	    } else if (r->parsed_uri.password == NULL) {
		    apr_cpystrn(ss->request, r->the_request, sizeof(ss->request));
	    } else {
		/* Don't reveal the password in the server-status view */
		    apr_cpystrn(ss->request, apr_pstrcat(r->pool, r->method, " ",
					       ap_unparse_uri_components(r->pool, &r->parsed_uri, UNP_OMITPASSWORD),
					       r->assbackwards ? NULL : " ", r->protocol, NULL),
				       sizeof(ss->request));
	    }
	    ss->vhostrec =  r->server;
	}
    }

    if (status == SERVER_STARTING && r == NULL) {
	/* clean up the slot's vhostrec pointer (maybe re-used)
	 * and mark the slot as belonging to a new generation.
	 */
	ss->vhostrec = NULL;
	ap_scoreboard_image->parent[child_num].generation = ap_scoreboard_image->global.running_generation;
    }

    return old_status;
}

void ap_time_process_request(int child_num, int status)
{
    short_score *ss;

    if (child_num < 0)
	return;

    ss = &ap_scoreboard_image->servers[child_num];

    if (status == START_PREQUEST) {
	ss->start_time = apr_now();
    }
    else if (status == STOP_PREQUEST) {
	ss->stop_time = apr_now();
    }
}

/* TODO: call me some time */
static void increment_counts(int child_num, request_rec *r)
{
    long int bs = 0;
    short_score *ss;

    ss = &ap_scoreboard_image->servers[child_num];

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
}

static int find_child_by_tid(int tid)
{
    int i;

    for (i = 0; i < max_daemons_limit; ++i)
	if (ap_scoreboard_image->parent[i].tid == tid)
	    return i;

    return -1;
}

/* Finally, this routine is used by the caretaker thread to wait for
 * a while...
 */

/* number of calls to wait_or_timeout between writable probes */
#ifndef INTERVAL_OF_WRITABLE_PROBES
#define INTERVAL_OF_WRITABLE_PROBES 10
#endif
static int wait_or_timeout_counter;

static int wait_or_timeout(ap_wait_t *status)
{
    int ret;
    ULONG tid;

    ++wait_or_timeout_counter;
    if (wait_or_timeout_counter == INTERVAL_OF_WRITABLE_PROBES) {
	wait_or_timeout_counter = 0;
#if APR_HAS_OTHER_CHILD
	apr_probe_writable_fds();
#endif
    }

    tid = 0;
    ret = DosWaitThread(&tid, DCWW_NOWAIT);

    if (ret == 0) {
        int child_num = find_child_by_tid(tid);
        ap_assert( child_num > 0 );
        *status = ap_scoreboard_image->servers[child_num].thread_retval;
	return tid;
    }
    
    DosSleep(SCOREBOARD_MAINTENANCE_INTERVAL / 1000);
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

/*****************************************************************
 * Connection structures and accounting...
 */

static void just_die(int sig)
{
    clean_child_exit(0);
}


static void usr1_handler(int sig)
{
    if (THREAD_GLOBAL(usr1_just_die)) {
	just_die(sig);
    }
    ap_scoreboard_image->parent[THREAD_GLOBAL(child_num)].deferred_die = 1;
}

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful;

static void sig_term(int sig)
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

static void restart(int sig)
{
    if (restart_pending == 1) {
	/* Probably not an error - don't bother reporting it */
	return;
    }
    restart_pending = 1;
    is_graceful = sig == SIGUSR1;
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

    /* we want to ignore HUPs and USR1 while we're busy processing one */
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, SIGUSR1);
    sa.sa_handler = restart;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGHUP)");
    if (sigaction(SIGUSR1, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGUSR1)");
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
#ifdef SIGUSR1
    signal(SIGUSR1, restart);
#endif /* SIGUSR1 */
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif /* SIGPIPE */

#endif
}

/*****************************************************************
 * Child process main loop.
 */

API_EXPORT(void) ap_child_terminate(request_rec *r)
{
    r->connection->keepalive = 0;
    ap_scoreboard_image->parent[THREAD_GLOBAL(child_num)].deferred_die = 1;
}



int ap_graceful_stop_signalled(void)
{
    if (ap_scoreboard_image->parent[THREAD_GLOBAL(child_num)].deferred_die ||
	ap_scoreboard_image->global.running_generation != ap_scoreboard_image->parent[THREAD_GLOBAL(child_num)].generation) {
	return 1;
    }
    return 0;
}



int ap_stop_signalled(void)
{
    if (shutdown_pending || restart_pending ||
        ap_scoreboard_image->parent[THREAD_GLOBAL(child_num)].deferred_die ||
	ap_scoreboard_image->global.running_generation != ap_scoreboard_image->parent[THREAD_GLOBAL(child_num)].generation) {
	return 1;
    }
    return 0;
}



static int setup_listen_poll(apr_pool_t *pchild, apr_pollfd_t **listen_poll)
{
    ap_listen_rec *lr;
    int numfds = 0;

    for (lr = ap_listeners; lr; lr = lr->next) {
        numfds++;
    }

    apr_setup_poll(listen_poll, numfds, pchild);

    for (lr = ap_listeners; lr; lr = lr->next) {
	apr_add_poll_socket(*listen_poll, lr->sd, APR_POLLIN);
    }
    return 0;
}



static void child_main(void *child_num_arg)
{
    ap_listen_rec *lr = NULL;
    ap_listen_rec *first_lr = NULL;
    apr_pool_t *ptrans;
    conn_rec *current_conn;
    ap_iol *iol;
    apr_pool_t *pchild;
    parent_score *sc_parent_rec;
    int requests_this_child = 0;
    apr_pollfd_t *listen_poll;
    apr_socket_t *csd = NULL;
    int nsds, rv;

    /* Disable the restart signal handlers and enable the just_die stuff.
     * Note that since restart() just notes that a restart has been
     * requested there's no race condition here.
     */

    set_signals(); /* signals aren't inherrited by child threads */
    signal(SIGHUP, just_die);
    signal(SIGUSR1, just_die);
    signal(SIGTERM, just_die);

    /* Get a sub pool for global allocations in this child, so that
     * we can have cleanups occur when the child exits.
     */
    apr_create_pool(&pchild, pconf);
    *ppthread_globals = (struct thread_globals *)apr_palloc(pchild, sizeof(struct thread_globals));
    THREAD_GLOBAL(child_num) = (int)child_num_arg;
    sc_parent_rec = ap_scoreboard_image->parent + THREAD_GLOBAL(child_num);
    THREAD_GLOBAL(pchild) = pchild;
    apr_create_pool(&ptrans, pchild);

    if (setup_listen_poll(pchild, &listen_poll)) {
	clean_child_exit(1);
    }

    /* needs to be done before we switch UIDs so we have permissions */
    SAFE_ACCEPT(accept_mutex_child_init(pchild));

    ap_child_init_hook(pchild, ap_server_conf);

    (void) ap_update_child_status(THREAD_GLOBAL(child_num), SERVER_READY, (request_rec *) NULL);
    

    signal(SIGHUP, just_die);
    signal(SIGTERM, just_die);

    while (!ap_stop_signalled()) {
        BUFF *conn_io;
        int srv;
        apr_socket_t *sd;

	/* Prepare to receive a SIGUSR1 due to graceful restart so that
	 * we can exit cleanly.
	 */
	THREAD_GLOBAL(usr1_just_die) = 1;
	signal(SIGUSR1, usr1_handler);

	/*
	 * (Re)initialize this child to a pre-connection state.
	 */

	current_conn = NULL;

	apr_clear_pool(ptrans);

	if ((ap_max_requests_per_child > 0
	     && requests_this_child++ >= ap_max_requests_per_child)) {
	    clean_child_exit(0);
	}

	(void) ap_update_child_status(THREAD_GLOBAL(child_num), SERVER_READY, (request_rec *) NULL);

	/*
	 * Wait for an acceptable connection to arrive.
	 */

	/* Lock around "accept", if necessary */
        SAFE_ACCEPT(accept_mutex_on());

        if (ap_stop_signalled()) {
            clean_child_exit(0);
        }

	for (;;) {
	    if (ap_listeners->next) {
		/* more than one socket */
                srv = apr_poll(listen_poll, &nsds, -1);

		if (srv != APR_SUCCESS) {
		    /* Single Unix documents select as returning errnos
		     * EBADF, EINTR, and EINVAL... and in none of those
		     * cases does it make sense to continue.  In fact
		     * on Linux 2.0.x we seem to end up with EFAULT
		     * occasionally, and we'd loop forever due to it.
		     */
		    ap_log_error(APLOG_MARK, APLOG_ERR, errno, ap_server_conf, "select: (listen)");
		    clean_child_exit(1);
		}

		/* we remember the last_lr we searched last time around so that
		   we don't end up starving any particular listening socket */
		if (first_lr == NULL) {
		    first_lr = ap_listeners;
		}
		
                lr = first_lr;
		
                do {
                    apr_int16_t event;

		    if (!lr) {
			lr = ap_listeners;
		    }

                    apr_get_revents(&event, lr->sd, listen_poll);

		    if (event == APR_POLLIN) {
                        first_lr = lr->next;
		        break;
		    }
		    lr = lr->next;
		} while (lr != first_lr);
		
		if (lr == first_lr) {
		    continue;
		}
		sd = lr->sd;
	    }
	    else {
		/* only one socket, just pretend we did the other stuff */
		sd = ap_listeners->sd;
	    }

	    /* if we accept() something we don't want to die, so we have to
	     * defer the exit
	     */
            THREAD_GLOBAL(usr1_just_die) = 0;
            rv = apr_accept(&csd, sd, ptrans);

	    if (rv == APR_SUCCESS)
		break;		/* We have a socket ready for reading */
	    else {

		/* Our old behaviour here was to continue after accept()
		 * errors.  But this leads us into lots of troubles
		 * because most of the errors are quite fatal.  For
		 * example, EMFILE can be caused by slow descriptor
		 * leaks (say in a 3rd party module, or libc).  It's
		 * foolish for us to continue after an EMFILE.  We also
		 * seem to tickle kernel bugs on some platforms which
		 * lead to never-ending loops here.  So it seems best
		 * to just exit in most cases.
		 */
                switch (apr_canonical_error(rv)) {
#ifdef EPROTO
		    /* EPROTO on certain older kernels really means
		     * ECONNABORTED, so we need to ignore it for them.
		     * See discussion in new-httpd archives nh.9701
		     * search for EPROTO.
		     *
		     * Also see nh.9603, search for EPROTO:
		     * There is potentially a bug in Solaris 2.x x<6,
		     * and other boxes that implement tcp sockets in
		     * userland (i.e. on top of STREAMS).  On these
		     * systems, EPROTO can actually result in a fatal
		     * loop.  See PR#981 for example.  It's hard to
		     * handle both uses of EPROTO.
		     */
                case EPROTO:
#endif
#ifdef ECONNABORTED
                case ECONNABORTED:
#endif
		    /* Linux generates the rest of these, other tcp
		     * stacks (i.e. bsd) tend to hide them behind
		     * getsockopt() interfaces.  They occur when
		     * the net goes sour or the client disconnects
		     * after the three-way handshake has been done
		     * in the kernel but before userland has picked
		     * up the socket.
		     */
#ifdef ECONNRESET
                case ECONNRESET:
#endif
#ifdef ETIMEDOUT
                case ETIMEDOUT:
#endif
#ifdef EHOSTUNREACH
		case EHOSTUNREACH:
#endif
#ifdef ENETUNREACH
		case ENETUNREACH:
#endif
                    break;

                case EINTR:
                    /* We only get hit by an EINTR if the parent is
                     * killing us off
                     */
                    clean_child_exit(0);
		default:
		    ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
				"accept: (client socket)");
		    clean_child_exit(1);
		}
	    }

	    if (ap_stop_signalled()) {
		clean_child_exit(0);
	    }
	    THREAD_GLOBAL(usr1_just_die) = 1;
	}

	SAFE_ACCEPT(accept_mutex_off());	/* unlock after "accept" */

	/* We've got a socket, let's at least process one request off the
	 * socket before we accept a graceful restart request.  We set
	 * the signal to ignore because we don't want to disturb any
	 * third party code.
	 */
	signal(SIGUSR1, SIG_IGN);

	/*
	 * We now have a connection, so set it up with the appropriate
	 * socket options, file descriptors, and read/write buffers.
	 */

	ap_sock_disable_nagle(csd);

        iol = ap_iol_attach_socket(ptrans, csd);

	if (iol == NULL) {
          ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, NULL,
                       "error attaching to socket");
	    apr_close_socket(csd);
	    continue;
        }

	(void) ap_update_child_status(THREAD_GLOBAL(child_num), SERVER_BUSY_READ,
				   (request_rec *) NULL);

	conn_io = ap_bcreate(ptrans, B_RDWR);
        ap_bpush_iol(conn_io, iol);

	current_conn = ap_new_apr_connection(ptrans, ap_server_conf, conn_io, csd,
                                             THREAD_GLOBAL(child_num));

	ap_process_connection(current_conn);
        ap_lingering_close(current_conn);
    }

    clean_child_exit(0);
}


static int make_child(server_rec *s, int slot, time_t now)
{
    TID tid;

    if (slot + 1 > max_daemons_limit) {
	max_daemons_limit = slot + 1;
    }

    if (one_process) {
        struct thread_globals *parent_globals = *ppthread_globals;
	signal(SIGHUP, just_die);
	signal(SIGINT, just_die);
#ifdef SIGQUIT
	signal(SIGQUIT, SIG_DFL);
#endif
	signal(SIGTERM, just_die);
        child_main((void *)slot);
        *ppthread_globals = parent_globals;
    }

    ap_update_child_status(slot, SERVER_STARTING, (request_rec *) NULL);

    if ((tid = _beginthread(child_main, NULL,  256*1024, (void *)slot)) == -1) {
	ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, s, "_beginthread: Unable to create new thread");

	/* _beginthread didn't succeed. Fix the scoreboard or else
	 * it will say SERVER_STARTING forever and ever
	 */
	(void) ap_update_child_status(slot, SERVER_DEAD, (request_rec *) NULL);

	/* In case system resources are maxxed out, we don't want
	   Apache running away with the CPU trying to _beginthread over and
	   over and over again. */
	sleep(10);

	return -1;
    }

    ap_scoreboard_image->parent[slot].tid = tid;
    return 0;
}


/* start up a bunch of children */
static void startup_children(int number_to_start)
{
    int i;
    time_t now = time(0);

    for (i = 0; number_to_start && i < ap_daemons_limit; ++i) {
	if (ap_scoreboard_image->servers[i].status != SERVER_DEAD) {
	    continue;
	}
	if (make_child(ap_server_conf, i, now) < 0) {
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
    int i;
    int to_kill;
    int idle_count;
    short_score *ss;
    time_t now = time(0);
    int free_length;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead;
    int total_non_dead;

    /* initialize the free_list */
    free_length = 0;

    to_kill = -1;
    idle_count = 0;
    last_non_dead = -1;
    total_non_dead = 0;

    for (i = 0; i < ap_daemons_limit; ++i) {
	int status;

	if (i >= max_daemons_limit && free_length == idle_spawn_rate)
	    break;
	ss = &ap_scoreboard_image->servers[i];
	status = ss->status;
	if (status == SERVER_DEAD) {
	    /* try to keep children numbers as low as possible */
	    if (free_length < idle_spawn_rate) {
		free_slots[free_length] = i;
		++free_length;
	    }
	}
	else {
	    /* We consider a starting server as idle because we started it
	     * at least a cycle ago, and if it still hasn't finished starting
	     * then we're just going to swamp things worse by forking more.
	     * So we hopefully won't need to fork more if we count it.
	     * This depends on the ordering of SERVER_READY and SERVER_STARTING.
	     */
	    if (status <= SERVER_READY) {
		++ idle_count;
		/* always kill the highest numbered child if we have to...
		 * no really well thought out reason ... other than observing
		 * the server behaviour under linux where lower numbered children
		 * tend to service more hits (and hence are more likely to have
		 * their data in cpu caches).
		 */
		to_kill = i;
	    }

	    ++total_non_dead;
	    last_non_dead = i;
	}
    }
    max_daemons_limit = last_non_dead + 1;
    if (idle_count > ap_daemons_max_free) {
	/* kill off one child... we use SIGUSR1 because that'll cause it to
	 * shut down gracefully, in case it happened to pick up a request
	 * while we were counting
	 */
	ap_scoreboard_image->parent[to_kill].deferred_die = 1;
	idle_spawn_rate = 1;
    }
    else if (idle_count < ap_daemons_min_free) {
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
		    "to increase StartServers, or Min/MaxSpareServers), "
		    "spawning %d children, there are %d idle, and "
		    "%d total children", idle_spawn_rate,
		    idle_count, total_non_dead);
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


/*****************************************************************
 * Executive routines.
 */

int ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
{
    int remaining_children_to_start;
    int i;
    apr_status_t status;

    pconf = _pconf;
    ap_server_conf = s;
    ap_log_pid(pconf, ap_pid_fname);

    if ((status = ap_listen_open(s->process, s->port)) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, status, s,
		    "no listening sockets available, shutting down");
	return -1;
    }

    SAFE_ACCEPT(accept_mutex_init(pconf));

    if (!is_graceful) {
	reinit_scoreboard(pconf);
    }

    set_signals();

    if (ppthread_globals == NULL) {
        if (DosAllocThreadLocalMemory(1, (PULONG *)&ppthread_globals)) {
            ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, 0, ap_server_conf,
                         "Error allocating thread local storage"
                         "Apache is exiting!");
        } else {
          *ppthread_globals = (struct thread_globals *)apr_palloc(pconf, sizeof(struct thread_globals));
        }
    }

    if (ap_daemons_max_free < ap_daemons_min_free + 1)	/* Don't thrash... */
	ap_daemons_max_free = ap_daemons_min_free + 1;

    /* If we're doing a graceful_restart then we're going to see a lot
	* of children exiting immediately when we get into the main loop
	* below (because we just sent them SIGUSR1).  This happens pretty
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

    while (!restart_pending && !shutdown_pending) {
	int child_slot;
	ap_wait_t status;
	int tid = wait_or_timeout(&status);

	/* XXX: if it takes longer than 1 second for all our children
	 * to start up and get into IDLE state then we may spawn an
	 * extra child
	 */
	if (tid >= 0) {
            apr_proc_t dummyproc;
            dummyproc.pid = tid;
            ap_process_child_status(&dummyproc, status);
	    /* non-fatal death... note that it's gone in the scoreboard. */
	    child_slot = find_child_by_tid(tid);
	    if (child_slot >= 0) {
		(void) ap_update_child_status(child_slot, SERVER_DEAD,
					    (request_rec *) NULL);
		if (remaining_children_to_start
		    && child_slot < ap_daemons_limit) {
		    /* we're still doing a 1-for-1 replacement of dead
			* children with new children
			*/
		    make_child(ap_server_conf, child_slot, time(0));
		    --remaining_children_to_start;
		}
#if APR_HAS_OTHER_CHILD
/* TODO: this won't work, we waited on a thread not a process
	    }
	    else if (reap_other_child(pid, status) == 0) {
*/
#endif
	    }
	    else if (is_graceful) {
		/* Great, we've probably just lost a slot in the
		    * scoreboard.  Somehow we don't know about this
		    * child.
		    */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, ap_server_conf,
			    "long lost child came home! (tid %d)", tid);
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

    if (shutdown_pending) {
	/* Time to gracefully shut down */
        const char *pidfile = NULL;
        int slot;
        TID tid;
        ULONG rc;
        ap_listen_rec *lr;

        for (lr = ap_listeners; lr; lr = lr->next) {
            apr_close_socket(lr->sd);
            DosSleep(0);
        }

        /* Kill off running threads */
        for (slot=0; slot<max_daemons_limit; slot++) {
            if (ap_scoreboard_image->servers[slot].status != SERVER_DEAD) {
                tid = ap_scoreboard_image->parent[slot].tid;
                rc = DosKillThread(tid);

                if (rc != ERROR_INVALID_THREADID) { // Already dead, ignore
                    if (rc == 0) {
                        rc = DosWaitThread(&tid, DCWW_WAIT);

                        if (rc) {
                            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, ap_server_conf,
                                         "error %lu waiting for thread to terminate", rc);
                        }
                    } else {
                        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, ap_server_conf,
                                     "error %lu killing thread", rc);
                    }
                }
            }
        }

        /* cleanup pid file on normal shutdown */
        pidfile = ap_server_root_relative (pconf, ap_pid_fname);
        if ( pidfile != NULL && unlink(pidfile) == 0)
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0,
                            ap_server_conf,
                            "removed PID file %s (pid=%ld)",
                            pidfile, (long)getpid());

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		    "caught SIGTERM, shutting down");
	return 1;
    }

    /* we've been told to restart */
    signal(SIGHUP, SIG_IGN);
    signal(SIGUSR1, SIG_IGN);

    if (one_process) {
	/* not worth thinking about */
	return 1;
    }

    /* advance to the next generation */
    /* XXX: we really need to make sure this new generation number isn't in
     * use by any of the children.
     */
    ++ap_scoreboard_image->global.running_generation;

    if (is_graceful) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		    "SIGUSR1 received.  Doing graceful restart");

        /* kill off the idle ones */
        for (i = 0; i < ap_daemons_limit; ++i) {
            ap_scoreboard_image->parent[i].deferred_die = 1;
        }

	/* This is mostly for debugging... so that we know what is still
	    * gracefully dealing with existing request.  But we can't really
	    * do it if we're in a SCOREBOARD_FILE because it'll cause
	    * corruption too easily.
	    */
	for (i = 0; i < ap_daemons_limit; ++i) {
	    if (ap_scoreboard_image->servers[i].status != SERVER_DEAD) {
		ap_scoreboard_image->servers[i].status = SERVER_GRACEFUL;
	    }
	}
    }
    else {
	/* Kill 'em off */
        for (i = 0; i < ap_daemons_limit; ++i) {
            DosKillThread(ap_scoreboard_image->parent[i].tid);
        }
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
                     "SIGHUP received.  Attempting to restart");
    }

    if (!is_graceful) {
	ap_restart_time = time(NULL);
    }

    return 0;
}

static void spmt_os2_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    one_process = !!getenv("ONE_PROCESS");

    is_graceful = 0;
    ap_listen_pre_config();
    ap_daemons_to_start = DEFAULT_START_DAEMON;
    ap_daemons_min_free = DEFAULT_MIN_FREE_DAEMON;
    ap_daemons_max_free = DEFAULT_MAX_FREE_DAEMON;
    ap_daemons_limit = HARD_SERVER_LIMIT;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    ap_extended_status = 0;

    apr_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));
}

static void spmt_os2_hooks(void)
{
    INIT_SIGLIST();
    /* TODO: set one_process properly */ one_process = 0;

    ap_hook_pre_config(spmt_os2_pre_config, NULL, NULL, AP_HOOK_MIDDLE);
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
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "WARNING: detected MinSpareServers set to non-positive.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "Resetting to 1 to avoid almost certain Apache failure.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "Please read the documentation.");
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
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "WARNING: Require MaxClients > 0, setting to 1");
	ap_daemons_limit = 1;
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
    apr_finfo_t finfo;
    const char *fname;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    fname = ap_server_root_relative(cmd->pool, arg);
    if ((apr_stat(&finfo, fname, cmd->pool) != APR_SUCCESS) || 
        (finfo.filetype != APR_DIR)) {
	return apr_pstrcat(cmd->pool, "CoreDumpDirectory ", fname, 
			  " does not exist or is not a directory", NULL);
    }
    apr_cpystrn(ap_coredump_dir, fname, sizeof(ap_coredump_dir));
    return NULL;
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

static const command_rec spmt_os2_cmds[] = {
LISTEN_COMMANDS
{ "PidFile", set_pidfile, NULL, RSRC_CONF, TAKE1,
    "A file for logging the server process ID"},
{ "StartServers", set_daemons_to_start, NULL, RSRC_CONF, TAKE1,
  "Number of child processes launched at server startup" },
{ "MinSpareServers", set_min_free_servers, NULL, RSRC_CONF, TAKE1,
  "Minimum number of idle children, to handle request spikes" },
{ "MaxSpareServers", set_max_free_servers, NULL, RSRC_CONF, TAKE1,
  "Maximum number of idle children" },
{ "MaxClients", set_server_limit, NULL, RSRC_CONF, TAKE1,
  "Maximum number of children alive at the same time" },
{ "MaxRequestsPerChild", set_max_requests, NULL, RSRC_CONF, TAKE1,
  "Maximum number of requests a particular child serves before dying." },
{ "CoreDumpDirectory", set_coredumpdir, NULL, RSRC_CONF, TAKE1,
  "The location of the directory Apache changes to before dumping core" },
{ NULL }
};

module MODULE_VAR_EXPORT mpm_spmt_os2_module = {
    MPM20_MODULE_STUFF,
    NULL,                       /* hook to run before apache parses args */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    spmt_os2_cmds,		/* command apr_table_t */
    NULL,			/* handlers */
    spmt_os2_hooks,		/* register_hooks */
};
