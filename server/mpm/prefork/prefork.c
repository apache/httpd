/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

/*
 * httpd.c: simple http daemon for answering WWW file requests
 *
 * 
 * 03-21-93  Rob McCool wrote original code (up to NCSA HTTPd 1.3)
 * 
 * 03-06-95  blong
 *  changed server number for child-alone processes to 0 and changed name
 *   of processes
 *
 * 03-10-95  blong
 *      Added numerous speed hacks proposed by Robert S. Thau (rst@ai.mit.edu) 
 *      including set group before fork, and call gettime before to fork
 *      to set up libraries.
 *
 * 04-14-95  rst / rh
 *      Brandon's code snarfed from NCSA 1.4, but tinkered to work with the
 *      Apache server, and also to have child processes do accept() directly.
 *
 * April-July '95 rst
 *      Extensive rework for Apache.
 */

/* TODO: this is a cobbled together prefork MPM example... it should mostly
 * TODO: behave like apache-1.3... here's a short list of things I think
 * TODO: need cleaning up still:
 */

#include "apr.h"
#include "apr_portable.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#define CORE_PRIVATE

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
#include "unixd.h"
#include "mpm_common.h"
#include "ap_listen.h"
#include "ap_mmn.h"

#ifdef HAVE_BSTRING_H
#include <bstring.h>		/* for IRIX, FD_SET calls bzero() */
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_PROCESSOR_H
#include <sys/processor.h> /* for bindprocessor() */
#endif

#include <signal.h>
#include <sys/times.h>

/* config globals */

int ap_threads_per_child=0;         /* Worker threads per child */
static int ap_max_requests_per_child=0;
static const char *ap_pid_fname=NULL;
static apr_lock_t *accept_lock;
static const char *ap_lock_fname;
static apr_lockmech_e_np accept_lock_mech = APR_LOCK_DEFAULT;
static int ap_daemons_to_start=0;
static int ap_daemons_min_free=0;
static int ap_daemons_max_free=0;
static int ap_daemons_limit=0;

static ap_pod_t *pod;

/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with MaxClients changes across SIGWINCH restarts.  We use this
 * value to optimize routines that have to scan the entire scoreboard.
 */
int ap_max_daemons_limit = -1;
server_rec *ap_server_conf;

char ap_coredump_dir[MAX_STRING_LEN];

/* *Non*-shared http_main globals... */

static apr_socket_t *sd;
static fd_set listenfds;
static int listenmaxfd;

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
static apr_pool_t *pchild;		/* Pool for httpd child stuff */

static pid_t ap_my_pid;	/* it seems silly to call getpid all the time */
#ifndef MULTITHREAD
static int my_child_num;
#endif

#ifdef TPF
int tpf_child = 0;
char tpf_server_name[INETD_SERVNAME_LENGTH+1];
#endif /* TPF */

static int die_now = 0;

#ifdef GPROF
/* 
 * change directory for gprof to plop the gmon.out file
 * configure in httpd.conf:
 * GprofDir logs/   -> $ServerRoot/logs/gmon.out
 * GprofDir logs/%  -> $ServerRoot/logs/gprof.$pid/gmon.out
 */
static void chdir_for_gprof(void)
{
    core_server_config *sconf = 
	ap_get_module_config(ap_server_conf->module_config, &core_module);    
    char *dir = sconf->gprof_dir;
    const char *use_dir;

    if(dir) {
        apr_status_t res;
	char buf[512];
	int len = strlen(sconf->gprof_dir) - 1;
	if(*(dir + len) == '%') {
	    dir[len] = '\0';
	    apr_snprintf(buf, sizeof(buf), "%sgprof.%d", dir, (int)getpid());
	} 
	use_dir = ap_server_root_relative(pconf, buf[0] ? buf : dir);
	res = apr_dir_make(use_dir, 0755, pconf);
	if(res != APR_SUCCESS && !APR_STATUS_IS_EEXIST(res)) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, errno, ap_server_conf,
			 "gprof: error creating directory %s", dir);
	}
    }
    else {
	use_dir = ap_server_root_relative(pconf, "logs");
    }

    chdir(dir);
}
#else
#define chdir_for_gprof()
#endif

/* XXX - I don't know if TPF will ever use this module or not, so leave
 * the ap_check_signals calls in but disable them - manoj */
#define ap_check_signals() 

/* a clean exit from a child with proper cleanup */
static void clean_child_exit(int code) __attribute__ ((noreturn));
static void clean_child_exit(int code)
{
    if (pchild) {
	apr_pool_destroy(pchild);
    }
    ap_mpm_pod_close(pod);
    chdir_for_gprof();
    exit(code);
}

static void expand_lock_fname(apr_pool_t *p)
{
    /* XXXX possibly bogus cast */
    ap_lock_fname = apr_psprintf(p, "%s.%lu",
	ap_server_root_relative(p, ap_lock_fname), (unsigned long)getpid());
}

/* Initialize mutex lock.
 * Done by each child at its birth
 */
static void accept_mutex_child_init(apr_pool_t *p)
{
    apr_status_t rv;

    rv = apr_lock_child_init(&accept_lock, ap_lock_fname, p);
    if (rv) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, rv, NULL, 
                     "couldn't do child init for accept mutex");
        clean_child_exit(APEXIT_CHILDINIT);
    }
}

/* Initialize mutex lock.
 * Must be safe to call this on a restart.
 */
static void accept_mutex_init(apr_pool_t *p)
{
    apr_status_t rv;

    expand_lock_fname(p);
    rv = apr_lock_create_np(&accept_lock, APR_MUTEX, APR_CROSS_PROCESS, 
                            accept_lock_mech, ap_lock_fname, p);
    if (rv) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, rv, NULL, "couldn't create accept mutex");
        exit(APEXIT_INIT);
    }
}

static void accept_mutex_on(void)
{
    apr_status_t rv = apr_lock_acquire(accept_lock);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, NULL, "couldn't grab the accept mutex");
        exit(APEXIT_CHILDFATAL);
    }
}

static void accept_mutex_off(void)
{
    apr_status_t rv = apr_lock_release(accept_lock);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, NULL, "couldn't release the accept mutex");
        exit(APEXIT_CHILDFATAL);
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

AP_DECLARE(apr_status_t) ap_mpm_query(int query_code, int *result)
{
    switch(query_code){
        case AP_MPMQ_MAX_DAEMON_USED:
            *result = ap_daemons_limit;
            return APR_SUCCESS;
        case AP_MPMQ_IS_THREADED:
            *result = AP_MPMQ_NOT_SUPPORTED;
            return APR_SUCCESS;
        case AP_MPMQ_IS_FORKED:
            *result = AP_MPMQ_DYNAMIC;
            return APR_SUCCESS;
        case AP_MPMQ_HARD_LIMIT_DAEMONS:
            *result = HARD_SERVER_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_HARD_LIMIT_THREADS:
            *result = HARD_THREAD_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_THREADS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_DEAMONS:
            *result = ap_daemons_min_free;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_THREADS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_DAEMONS:
            *result = ap_daemons_max_free;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_THREADS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_REQUESTS_DEAMON:
            *result = ap_max_requests_per_child;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_DAEMONS:
            *result = ap_daemons_limit;
            return APR_SUCCESS;
    }
    return APR_ENOTIMPL;
}

#if defined(NEED_WAITPID)
/*
   Systems without a real waitpid sometimes lose a child's exit while waiting
   for another.  Search through the scoreboard for missing children.
 */
int reap_children(apr_wait_t *status)
{
    int n, pid;

    for (n = 0; n < ap_max_daemons_limit; ++n) {
        ap_sync_scoreboard_image();
	if (ap_scoreboard_image->servers[n][0].status != SERVER_DEAD &&
		kill((pid = ap_scoreboard_image->parent[n].pid), 0) == -1) {
	    ap_update_child_status(AP_CHILD_THREAD_FROM_ID(n), SERVER_DEAD, NULL);
	    /* just mark it as having a successful exit status */
	    memset(status, 0, sizeof(apr_wait_t));
	    return(pid);
	}
    }
    return 0;
}
#endif

/* handle all varieties of core dumping signals */
static void sig_coredump(int sig)
{
    chdir(ap_coredump_dir);
    apr_signal(sig, SIG_DFL);
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

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful;
ap_generation_t volatile ap_my_generation=0;

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

/* restart() is the signal handler for SIGHUP and SIGWINCH
 * in the parent process, unless running in ONE_PROCESS mode
 */
static void restart(int sig)
{
    if (restart_pending == 1) {
	/* Probably not an error - don't bother reporting it */
	return;
    }
    restart_pending = 1;
    if ((is_graceful = (sig == SIGWINCH))) {
        apr_pool_cleanup_kill(pconf, NULL, ap_cleanup_scoreboard);
    }
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
 * Child process main loop.
 * The following vars are static to avoid getting clobbered by longjmp();
 * they are really private to child_main.
 */

static int srv;
static apr_socket_t *csd;
static int requests_this_child;
static fd_set main_fds;

int ap_graceful_stop_signalled(void)
{
    /* not ever called anymore... */
    return 0;
}


static void child_main(int child_num_arg)
{
    ap_listen_rec *lr;
    ap_listen_rec *last_lr;
    ap_listen_rec *first_lr;
    apr_pool_t *ptrans;
    conn_rec *current_conn;
    apr_status_t stat = APR_EINIT;
    int sockdes;

    my_child_num = child_num_arg;
    ap_my_pid = getpid();
    csd = NULL;
    requests_this_child = 0;
    last_lr = NULL;

    /* Get a sub context for global allocations in this child, so that
     * we can have cleanups occur when the child exits.
     */
    apr_pool_create(&pchild, pconf);

    apr_pool_create(&ptrans, pchild);

    /* needs to be done before we switch UIDs so we have permissions */
    reopen_scoreboard(pchild);
    SAFE_ACCEPT(accept_mutex_child_init(pchild));

    if (unixd_setup_child()) {
	clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_run_child_init(pchild, ap_server_conf);

    (void) ap_update_child_status(AP_CHILD_THREAD_FROM_ID(my_child_num), SERVER_READY, (request_rec *) NULL);

    ap_sync_scoreboard_image();
    while (!die_now) {
	/*
	 * (Re)initialize this child to a pre-connection state.
	 */

	current_conn = NULL;

	apr_pool_clear(ptrans);

	if ((ap_max_requests_per_child > 0
	     && requests_this_child++ >= ap_max_requests_per_child)) {
	    clean_child_exit(0);
	}

	(void) ap_update_child_status(AP_CHILD_THREAD_FROM_ID(my_child_num), SERVER_READY, (request_rec *) NULL);

	/*
	 * Wait for an acceptable connection to arrive.
	 */

	/* Lock around "accept", if necessary */
	SAFE_ACCEPT(accept_mutex_on());

	for (;;) {
	    if (ap_listeners->next) {
		/* more than one socket */
		memcpy(&main_fds, &listenfds, sizeof(fd_set));
		srv = select(listenmaxfd + 1, &main_fds, NULL, NULL, NULL);

		if (srv < 0 && errno != EINTR) {
		    /* Single Unix documents select as returning errnos
		     * EBADF, EINTR, and EINVAL... and in none of those
		     * cases does it make sense to continue.  In fact
		     * on Linux 2.0.x we seem to end up with EFAULT
		     * occasionally, and we'd loop forever due to it.
		     */
		    ap_log_error(APLOG_MARK, APLOG_ERR, errno, ap_server_conf, "select: (listen)");
		    clean_child_exit(1);
		}

		if (srv <= 0)
		    continue;

		/* we remember the last_lr we searched last time around so that
		   we don't end up starving any particular listening socket */
		if (last_lr == NULL) {
		    lr = ap_listeners;
		}
		else {
		    lr = last_lr->next;
		    if (!lr)
			lr = ap_listeners;
		}
		first_lr=lr;
		do {
                    apr_os_sock_get(&sockdes, lr->sd);
		    if (FD_ISSET(sockdes, &main_fds))
			goto got_listener;
		    lr = lr->next;
		    if (!lr)
			lr = ap_listeners;
		}
		while (lr != first_lr);
		/* FIXME: if we get here, something bad has happened, and we're
		   probably gonna spin forever.
		*/
		continue;
	got_listener:
		last_lr = lr;
		sd = lr->sd;
	    }
	    else {
		/* only one socket, just pretend we did the other stuff */
		sd = ap_listeners->sd;
	    }

	    /* if we accept() something we don't want to die, so we have to
	     * defer the exit
	     */
	    for (;;) {
                ap_sync_scoreboard_image();
		stat = apr_accept(&csd, sd, ptrans);
		if (stat == APR_SUCCESS || !APR_STATUS_IS_EINTR(stat))
		    break;
	    }

	    if (stat == APR_SUCCESS)
		break;		/* We have a socket ready for reading */
	    else {

/* TODO: this accept result handling stuff should be abstracted...
 * it's already out of date between the various unix mpms
 */
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
                switch (stat) {
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
#ifdef ENETDOWN
		case ENETDOWN:
		     /*
		      * When the network layer has been shut down, there
		      * is not much use in simply exiting: the parent
		      * would simply re-create us (and we'd fail again).
		      * Use the CHILDFATAL code to tear the server down.
		      * @@@ Martin's idea for possible improvement:
		      * A different approach would be to define
		      * a new APEXIT_NETDOWN exit code, the reception
		      * of which would make the parent shutdown all
		      * children, then idle-loop until it detected that
		      * the network is up again, and restart the children.
		      * Ben Hyde noted that temporary ENETDOWN situations
		      * occur in mobile IP.
		      */
		    ap_log_error(APLOG_MARK, APLOG_EMERG, stat, ap_server_conf,
			"apr_accept: giving up.");
		    clean_child_exit(APEXIT_CHILDFATAL);
#endif /*ENETDOWN*/

#ifdef TPF
		case EINACT:
		    ap_log_error(APLOG_MARK, APLOG_EMERG, stat, ap_server_conf,
			"offload device inactive");
		    clean_child_exit(APEXIT_CHILDFATAL);
		    break;
		default:
		    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, ap_server_conf,
			"select/accept error (%d)", stat);
		    clean_child_exit(APEXIT_CHILDFATAL);
#else
		default:
		    ap_log_error(APLOG_MARK, APLOG_ERR, stat, ap_server_conf,
				"apr_accept: (client socket)");
		    clean_child_exit(1);
#endif
		}
	    }

            ap_sync_scoreboard_image();
	}

	SAFE_ACCEPT(accept_mutex_off());	/* unlock after "accept" */

	/*
	 * We now have a connection, so set it up with the appropriate
	 * socket options, file descriptors, and read/write buffers.
	 */

        apr_os_sock_get(&sockdes, csd);

        if (sockdes >= FD_SETSIZE) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, NULL,
                         "new file descriptor %d is too large; you probably need "
                         "to rebuild Apache with a larger FD_SETSIZE "
                         "(currently %d)", 
                         sockdes, FD_SETSIZE);
	    apr_socket_close(csd);
            ap_sync_scoreboard_image();
	    continue;
        }

#ifdef TPF
	if (sockdes == 0) {                  /* 0 is invalid socket for TPF */
	    ap_sync_scoreboard_image();
            continue;
        }
#endif

	ap_sock_disable_nagle(csd);

	current_conn = ap_new_connection(ptrans, ap_server_conf, csd, 
                                         my_child_num);
        if (current_conn) {
            ap_process_connection(current_conn);
            ap_lingering_close(current_conn);
        }
        
        /* Check the pod after processing a connection so that we'll go away
         * if a graceful restart occurred while we were processing the 
         * connection.  Otherwise, we won't wake up until a real connection 
         * comes in and we'll use the wrong config to process it and we may
         * block in the wrong syscall (because the new generation is using a
         * different accept mutex) and in general it is goofy.
         */
        if (!ap_mpm_pod_check(pod)) {
            die_now = 1;
        }
        ap_sync_scoreboard_image();
    }
    clean_child_exit(0);
}


static int make_child(server_rec *s, int slot)
{
    int pid;

    if (slot + 1 > ap_max_daemons_limit) {
	ap_max_daemons_limit = slot + 1;
    }

    if (one_process) {
	apr_signal(SIGHUP, just_die);
        /* Don't catch SIGWINCH in ONE_PROCESS mode :) */
	apr_signal(SIGINT, just_die);
#ifdef SIGQUIT
	apr_signal(SIGQUIT, SIG_DFL);
#endif
	apr_signal(SIGTERM, just_die);
	child_main(slot);
    }

    (void) ap_update_child_status(AP_CHILD_THREAD_FROM_ID(slot), SERVER_STARTING, (request_rec *) NULL);


#ifdef _OSD_POSIX
    /* BS2000 requires a "special" version of fork() before a setuid() call */
    if ((pid = os_fork(unixd_config.user_name)) == -1) {
#elif defined(TPF)
    if ((pid = os_fork(s, slot)) == -1) {
#else
    if ((pid = fork()) == -1) {
#endif
	ap_log_error(APLOG_MARK, APLOG_ERR, errno, s, "fork: Unable to fork new process");

	/* fork didn't succeed. Fix the scoreboard or else
	 * it will say SERVER_STARTING forever and ever
	 */
	(void) ap_update_child_status(AP_CHILD_THREAD_FROM_ID(slot), SERVER_DEAD, (request_rec *) NULL);

	/* In case system resources are maxxed out, we don't want
	   Apache running away with the CPU trying to fork over and
	   over and over again. */
	sleep(10);

	return -1;
    }

    if (!pid) {
#ifdef HAVE_BINDPROCESSOR
        /* by default AIX binds to a single processor
         * this bit unbinds children which will then bind to another cpu
         */
	int status = bindprocessor(BINDPROCESS, (int)getpid(), 
				   PROCESSOR_CLASS_ANY);
	if (status != OK) {
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, errno, 
                         ap_server_conf, "processor unbind failed %d", status);
	}
#endif
	RAISE_SIGSTOP(MAKE_CHILD);
        /* Disable the parent's signal handlers and set up proper handling in
         * the child.
	 */
	apr_signal(SIGHUP, just_die);
	apr_signal(SIGTERM, just_die);
        /* The child process doesn't do anything for SIGWINCH.  Instead, the
         * pod is used for signalling graceful restart.
         */
        apr_signal(SIGWINCH, SIG_IGN);
	child_main(slot);
    }

    ap_scoreboard_image->parent[slot].pid = pid;
#ifdef SCOREBOARD_FILE
    lseek(scoreboard_fd, XtOffsetOf(scoreboard, parent[slot]), 0);
    force_write(scoreboard_fd, &ap_scoreboard_image->parent[slot],
		sizeof(process_score));
#endif

    return 0;
}


/* start up a bunch of children */
static void startup_children(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < ap_daemons_limit; ++i) {
	if (ap_scoreboard_image->servers[i][0].status != SERVER_DEAD) {
	    continue;
	}
	if (make_child(ap_server_conf, i) < 0) {
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

static void perform_idle_server_maintenance(apr_pool_t *p)
{
    int i;
    int to_kill;
    int idle_count;
    worker_score *ws;
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

    ap_sync_scoreboard_image();
    for (i = 0; i < ap_daemons_limit; ++i) {
	int status;

	if (i >= ap_max_daemons_limit && free_length == idle_spawn_rate)
	    break;
	ws = &ap_scoreboard_image->servers[i][0];
	status = ws->status;
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
    ap_max_daemons_limit = last_non_dead + 1;
    if (idle_count > ap_daemons_max_free) {
	/* kill off one child... we use the pod because that'll cause it to
	 * shut down gracefully, in case it happened to pick up a request
	 * while we were counting
	 */
	ap_mpm_pod_signal(pod);
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
#ifdef TPF
        if (make_child(ap_server_conf, free_slots[i]) == -1) {
            if(free_length == 1) {
                shutdown_pending = 1;
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, 0, ap_server_conf,
                "No active child processes: shutting down");
            }
        }
#else
		make_child(ap_server_conf, free_slots[i]);
#endif /* TPF */
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

static int setup_listeners(server_rec *s)
{
    ap_listen_rec *lr;
    int sockdes;

    if (ap_setup_listeners(s) < 1 ) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, 0, s,
		    "no listening sockets available, shutting down");
	return -1;
    }

    listenmaxfd = -1;
    FD_ZERO(&listenfds);
    for (lr = ap_listeners; lr; lr = lr->next) {
        apr_os_sock_get(&sockdes, lr->sd);
	FD_SET(sockdes, &listenfds);
	if (sockdes > listenmaxfd) {
	    listenmaxfd = sockdes;
	}
    }
    return 0;
}

/*****************************************************************
 * Executive routines.
 */

int ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
{
    int index;
    int remaining_children_to_start;
    apr_status_t rv;

    pconf = _pconf;

    ap_server_conf = s;
 
    ap_log_pid(pconf, ap_pid_fname);

    if (setup_listeners(s)) {
	/* XXX: hey, what's the right way for the mpm to indicate a fatal error? */
	return 1;
    }
    if ((rv = ap_mpm_pod_open(pconf, &pod))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
		"Could not open pipe-of-death.");
        return 1;
    }

    SAFE_ACCEPT(accept_mutex_init(pconf));
    if (!is_graceful) {
        ap_create_scoreboard(pconf, SB_SHARED);
    }
#ifdef SCOREBOARD_FILE
    else {
	ap_scoreboard_fname = ap_server_root_relative(pconf, ap_scoreboard_fname);
	ap_note_cleanups_for_fd(pconf, scoreboard_fd);
    }
#endif

    set_signals();

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

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		"%s configured -- resuming normal operations",
		ap_get_server_version());
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, ap_server_conf,
		"Server built: %s", ap_get_server_built());
    restart_pending = shutdown_pending = 0;

    while (!restart_pending && !shutdown_pending) {
	int child_slot;
	apr_wait_t status;
        /* this is a memory leak, but I'll fix it later. */
	apr_proc_t pid;

        ap_wait_or_timeout(&status, &pid, pconf);

	/* XXX: if it takes longer than 1 second for all our children
	 * to start up and get into IDLE state then we may spawn an
	 * extra child
	 */
	if (pid.pid != -1) {
	    ap_process_child_status(&pid, status);
	    /* non-fatal death... note that it's gone in the scoreboard. */
	    ap_sync_scoreboard_image();
	    child_slot = find_child_by_pid(&pid);
	    if (child_slot >= 0) {
		(void) ap_update_child_status(AP_CHILD_THREAD_FROM_ID(child_slot), SERVER_DEAD,
					    (request_rec *) NULL);
		if (remaining_children_to_start
		    && child_slot < ap_daemons_limit) {
		    /* we're still doing a 1-for-1 replacement of dead
			* children with new children
			*/
		    make_child(ap_server_conf, child_slot);
		    --remaining_children_to_start;
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
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 
                            0, ap_server_conf,
			    "long lost child came home! (pid %ld)", (long)pid.pid);
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

	perform_idle_server_maintenance(pconf);
#ifdef TPF
    shutdown_pending = os_check_server(tpf_server_name);
    ap_check_signals();
    sleep(1);
#endif /*TPF */
    }

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
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO,
				0, ap_server_conf,
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
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		    "Graceful restart requested, doing restart");

	/* kill off the idle ones */
        ap_mpm_pod_killpg(pod, ap_daemons_limit);

#ifndef SCOREBOARD_FILE
	/* This is mostly for debugging... so that we know what is still
	    * gracefully dealing with existing request.  But we can't really
	    * do it if we're in a SCOREBOARD_FILE because it'll cause
	    * corruption too easily.
	    */
	ap_sync_scoreboard_image();
	for (index = 0; index < ap_daemons_limit; ++index) {
	    if (ap_scoreboard_image->servers[index][0].status != SERVER_DEAD) {
		ap_scoreboard_image->servers[index][0].status = SERVER_GRACEFUL;
	    }
	}
#endif
    }
    else {
	/* Kill 'em off */
	if (unixd_killpg(getpgrp(), SIGHUP) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "killpg SIGHUP");
	}
	ap_reclaim_child_processes(0);		/* Not when just starting up */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		    "SIGHUP received.  Attempting to restart");
    }

    return 0;
}

static void prefork_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static int restart_num = 0;
    int no_detach = 0;

    no_detach = !!ap_exists_config_define("NO_DETACH");
    one_process = !!ap_exists_config_define("ONE_PROCESS");

    /* sigh, want this only the second time around */
    if (restart_num++ == 1) {
	is_graceful = 0;

	if (!one_process && !no_detach) {
	    apr_proc_detach();
	}

	ap_my_pid = getpid();
    }

    unixd_pre_config(ptemp);
    ap_listen_pre_config();
    ap_daemons_to_start = DEFAULT_START_DAEMON;
    ap_daemons_min_free = DEFAULT_MIN_FREE_DAEMON;
    ap_daemons_max_free = DEFAULT_MAX_FREE_DAEMON;
    ap_daemons_limit = HARD_SERVER_LIMIT;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_scoreboard_fname = DEFAULT_SCOREBOARD;
    ap_lock_fname = DEFAULT_LOCKFILE;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    ap_extended_status = 0;

    apr_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));
}

static void prefork_hooks(apr_pool_t *p)
{
#ifdef AUX3
    (void) set42sig();
#endif

    ap_hook_pre_config(prefork_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
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

static const char *set_scoreboard(cmd_parms *cmd, void *dummy, const char *arg) 
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

    ap_lock_fname = arg;
    return NULL;
}

static const char *set_daemons_to_start(cmd_parms *cmd, void *dummy, const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_to_start = atoi(arg);
    return NULL;
}

static const char *set_min_free_servers(cmd_parms *cmd, void *dummy, const char *arg)
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

static const char *set_max_free_servers(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_max_free = atoi(arg);
    return NULL;
}

static const char *set_server_limit (cmd_parms *cmd, void *dummy, const char *arg) 
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

static const char *set_max_requests(cmd_parms *cmd, void *dummy, const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_max_requests_per_child = atoi(arg);

    return NULL;
}

static const char *set_coredumpdir (cmd_parms *cmd, void *dummy, const char *arg) 
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

static const char *set_accept_lock_mech(cmd_parms *cmd, void *dummy, const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (!strcasecmp(arg, "default")) {
        accept_lock_mech = APR_LOCK_DEFAULT;
    }
#if APR_HAS_FLOCK_SERIALIZE
    else if (!strcasecmp(arg, "flock")) {
        accept_lock_mech = APR_LOCK_FLOCK;
    }
#endif
#if APR_HAS_FCNTL_SERIALIZE
    else if (!strcasecmp(arg, "fcntl")) {
        accept_lock_mech = APR_LOCK_FCNTL;
    }
#endif
#if APR_HAS_SYSVSEM_SERIALIZE
    else if (!strcasecmp(arg, "sysvsem")) {
        accept_lock_mech = APR_LOCK_SYSVSEM;
    }
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    else if (!strcasecmp(arg, "proc_pthread")) {
        accept_lock_mech = APR_LOCK_PROC_PTHREAD;
    }
#endif
    else {
        return apr_pstrcat(cmd->pool, arg, " is an invalid mutex mechanism; valid "
                           "ones for this platform are: default"
#if APR_HAS_FLOCK_SERIALIZE
                           ", flock"
#endif
#if APR_HAS_FCNTL_SERIALIZE
                           ", fcntl"
#endif
#if APR_HAS_SYSVSEM_SERIALIZE
                           ", sysvsem"
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
                           ", proc_pthread"
#endif
                           , NULL);
    }
    return NULL;
}

static const command_rec prefork_cmds[] = {
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
AP_INIT_TAKE1("MinSpareServers", set_min_free_servers, NULL, RSRC_CONF,
              "Minimum number of idle children, to handle request spikes"),
AP_INIT_TAKE1("MaxSpareServers", set_max_free_servers, NULL, RSRC_CONF,
              "Maximum number of idle children"),
AP_INIT_TAKE1("MaxClients", set_server_limit, NULL, RSRC_CONF,
              "Maximum number of children alive at the same time"),
AP_INIT_TAKE1("MaxRequestsPerChild", set_max_requests, NULL, RSRC_CONF,
              "Maximum number of requests a particular child serves before dying."),
AP_INIT_TAKE1("CoreDumpDirectory", set_coredumpdir, NULL, RSRC_CONF,
              "The location of the directory Apache changes to before dumping core"),
AP_INIT_TAKE1("AcceptMutex", set_accept_lock_mech, NULL, RSRC_CONF,
              "The system mutex implementation to use for the accept mutex"),
{ NULL }
};

module AP_MODULE_DECLARE_DATA mpm_prefork_module = {
    MPM20_MODULE_STUFF,
    NULL,                       /* hook to run before apache parses args */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    prefork_cmds,		/* command apr_table_t */
    prefork_hooks,		/* register hooks */
};
