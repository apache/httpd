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
#include "apr_tables.h"
#include "apr_getopt.h"
#include "apr_thread_mutex.h"

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
#include "mpm_common.h"
#include "ap_listen.h"
#include "ap_mmn.h"

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include <signal.h>

#define WORKER_DEAD         SERVER_DEAD
#define WORKER_STARTING     SERVER_STARTING
#define WORKER_READY        SERVER_READY

/* config globals */

int ap_threads_per_child=0;         /* Worker threads per child */
int ap_thread_stack_size=65536;
static apr_thread_mutex_t *accept_lock;
static int ap_threads_to_start=0;
static int ap_threads_min_free=0;
static int ap_threads_max_free=0;
static int ap_threads_limit=0;

/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with MaxClients changes across SIGWINCH restarts.  We use this
 * value to optimize routines that have to scan the entire scoreboard.
 */
int ap_max_workers_limit = -1;
server_rec *ap_server_conf;

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
static apr_pool_t *pmain;		/* Pool for httpd child stuff */

static pid_t ap_my_pid;	/* it seems silly to call getpid all the time */
static pid_t parent_pid;
#ifndef MULTITHREAD
static int my_child_num;
#endif

static int die_now = 0;
static apr_thread_mutex_t *accept_mutex = NULL;

/* Keep track of the number of worker threads currently active */
static int worker_thread_count;
static apr_thread_mutex_t *worker_thread_count_mutex;


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
    apr_thread_mutex_lock(worker_thread_count_mutex);
    worker_thread_count--;
    apr_thread_mutex_unlock(worker_thread_count_mutex);
    NXThreadExit((void*)&code);
}

static apr_status_t accept_mutex_child_cleanup(void *foo)
{
    return apr_thread_mutex_unlock(accept_mutex);
}

/* Initialize mutex lock.
 * Done by each child at its birth
 */
static void accept_mutex_child_init(apr_pool_t *p)
{
    apr_pool_cleanup_register(p, NULL, accept_mutex_child_cleanup, apr_pool_cleanup_null);
}

static void accept_mutex_on(void)
{
    apr_status_t rc = apr_thread_mutex_lock(accept_mutex);

    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rc, ap_server_conf,
                     "Error getting accept lock. Exiting!");
        clean_child_exit(APEXIT_CHILDFATAL);
    }
}

static void accept_mutex_off(void)
{
    apr_status_t rc = apr_thread_mutex_unlock(accept_mutex);

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

//#ifdef NO_SERIALIZED_ACCEPT
//#define SAFE_ACCEPT(stmt) APR_SUCCESS
//#else
//#define SAFE_ACCEPT(stmt) (stmt)
//#endif

AP_DECLARE(apr_status_t) ap_mpm_query(int query_code, int *result)
{
    switch(query_code){
        case AP_MPMQ_MAX_DAEMON_USED:
            *result = ap_threads_limit;
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
            *result = ap_threads_min_free;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_THREADS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_DAEMONS:
            *result = ap_threads_max_free;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_THREADS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_REQUESTS_DEAMON:
            *result = ap_max_requests_per_child;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_DAEMONS:
            *result = ap_threads_limit;
            return APR_SUCCESS;
    }
    return APR_ENOTIMPL;
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
static int volatile wait_to_finish=1;
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

    while (wait_to_finish)
        delay(500);
//        NXThreadYield();
    delay(2000);
// The shut down flag wait_to_finish needs to be set in  
//    the atexit() routine when it is finally working.
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
}

static void set_signals(void)
{
    apr_signal(SIGTERM, sig_term);
}

/*****************************************************************
 * Child process main loop.
 * The following vars are static to avoid getting clobbered by longjmp();
 * they are really private to child_main.
 */

//static int srv;
//static apr_socket_t *csd;
//static int requests_this_child;
static fd_set main_fds;

int ap_graceful_stop_signalled(void)
{
    /* not ever called anymore... */
    return 0;
}

static int setup_listen_poll(apr_pool_t *pmain, apr_pollfd_t **listen_poll)
{
    ap_listen_rec *lr;
    int numfds = 0;

    for (lr = ap_listeners; lr; lr = lr->next) {
        numfds++;
    }

    apr_poll_setup(listen_poll, numfds, pmain);

    for (lr = ap_listeners; lr; lr = lr->next) {
        apr_poll_socket_add(*listen_poll, lr->sd, APR_POLLIN);
    }
    return 0;
}


static void worker_main(void *arg)
{
    ap_listen_rec *lr;
    ap_listen_rec *last_lr;
    ap_listen_rec *first_lr;
    apr_pool_t *ptrans;
    conn_rec *current_conn;
    apr_status_t stat = APR_EINIT;
    int sockdes;
    int worker_num_arg = *((int*)arg);
    apr_pollfd_t *listen_poll;
    int nsds, rv;

    int my_worker_num = worker_num_arg;
    apr_socket_t *csd = NULL;
    int requests_this_child = 0;
    int srv;
    struct timeval tv;

    last_lr = NULL;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    apr_pool_create(&ptrans, pmain);

    apr_thread_mutex_lock(worker_thread_count_mutex);
    worker_thread_count++;
    apr_thread_mutex_unlock(worker_thread_count_mutex);

    if (setup_listen_poll(pmain, &listen_poll)) {
        clean_child_exit(1);
    }

    ap_update_child_status(AP_CHILD_THREAD_FROM_ID(my_child_num), WORKER_READY, (request_rec *) NULL);

//    ap_sync_scoreboard_image();
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

        ap_update_child_status(AP_CHILD_THREAD_FROM_ID(my_child_num), WORKER_READY, (request_rec *) NULL);

        /*
        * Wait for an acceptable connection to arrive.
        */

        /* Lock around "accept", if necessary */
        SAFE_ACCEPT(accept_mutex_on());

        for (;;) {
            if (shutdown_pending) {
printf ("Thread %d is shutting down\n", getpid());
                SAFE_ACCEPT(accept_mutex_off());
                clean_child_exit(0);
            }

            /* more than one socket */
            memcpy(&main_fds, &listenfds, sizeof(fd_set));
            srv = select(listenmaxfd + 1, &main_fds, NULL, NULL, &tv);

            if (srv < 0 && h_errno != EINTR) {
                /* Single Unix documents select as returning errnos
                * EBADF, EINTR, and EINVAL... and in none of those
                * cases does it make sense to continue.  In fact
                * on Linux 2.0.x we seem to end up with EFAULT
                * occasionally, and we'd loop forever due to it.
                */
                ap_log_error(APLOG_MARK, APLOG_ERR, h_errno, ap_server_conf, "select: (listen)");
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
            first_lr = lr;
            do {
                apr_os_sock_get(&sockdes, lr->sd);
                if (FD_ISSET(sockdes, &main_fds))
                    goto got_listener;
                lr = lr->next;
                if (!lr)
                    lr = ap_listeners;
            } while (lr != first_lr);
            /* FIXME: if we get here, something bad has happened, and we're
            probably gonna spin forever.
            */
            continue;
got_listener:
            last_lr = lr;
            sd = lr->sd;

            /* if we accept() something we don't want to die, so we have to
            * defer the exit
            */
            for (;;) {
//                ap_sync_scoreboard_image();
                stat = apr_accept(&csd, sd, ptrans);
                if (stat == APR_SUCCESS || !APR_STATUS_IS_EINTR(stat))
                    break;
            }

            if (stat == APR_SUCCESS)
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
                switch (stat) {

		            /* Linux generates the rest of these, other tcp
		             * stacks (i.e. bsd) tend to hide them behind
		             * getsockopt() interfaces.  They occur when
		             * the net goes sour or the client disconnects
		             * after the three-way handshake has been done
		             * in the kernel but before userland has picked
		             * up the socket.
		             */
                    case ECONNRESET:
                    case ETIMEDOUT:
                    case EHOSTUNREACH:
                    case ENETUNREACH:
                        break;

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

                    default:
                        ap_log_error(APLOG_MARK, APLOG_ERR, stat, ap_server_conf,
                            "apr_accept: (client socket)");
                        clean_child_exit(1);
                }
            }

//            ap_sync_scoreboard_image();
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
//            ap_sync_scoreboard_image();
            continue;
        }

        ap_sock_disable_nagle(csd);

        current_conn = ap_new_connection(ptrans, ap_server_conf, csd, 
                                         my_child_num);
        if (current_conn) {
            ap_process_connection(current_conn);
            ap_lingering_close(current_conn);
        }
        
//        ap_sync_scoreboard_image();
    }
    clean_child_exit(0);
}


static int make_child(server_rec *s, int slot)
{
    int tid;
    int err=0;
    NXContext_t ctx;

    if (slot + 1 > ap_max_workers_limit) {
        ap_max_workers_limit = slot + 1;
    }

    if (one_process) {
        apr_signal(SIGINT, just_die);
        apr_signal(SIGTERM, just_die);
        worker_main((void*)&slot);
    }

    ap_update_child_status(AP_CHILD_THREAD_FROM_ID(slot), WORKER_STARTING, (request_rec *) NULL);

    if (ctx = NXContextAlloc((void (*)(void *)) worker_main, &slot, NX_PRIO_MED, ap_thread_stack_size, NX_CTX_NORMAL, &err)) {
        char threadName[32];

        sprintf (threadName, "Apache_Worker %d", slot);
        NXContextSetName(ctx, threadName);
        err = NXThreadCreate(ctx, NX_THR_BIND_CONTEXT, &tid);
        if (err) {
            NXContextFree (ctx);
        }
    }

    if (err) {
        /* create thread didn't succeed. Fix the scoreboard or else
        * it will say SERVER_STARTING forever and ever
        */
        ap_update_child_status(AP_CHILD_THREAD_FROM_ID(slot), WORKER_DEAD, (request_rec *) NULL);

        /* In case system resources are maxxed out, we don't want
        Apache running away with the CPU trying to fork over and
        over and over again. */
        apr_thread_yield();

        return -1;
    }

    ap_scoreboard_image->servers[0][slot].tid = tid;

    return 0;
}


/* start up a bunch of worker threads */
static void startup_workers(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < ap_threads_limit; ++i) {
        if (ap_scoreboard_image->servers[0][i].status != WORKER_DEAD) {
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
    for (i = 0; i < ap_threads_limit; ++i) {
	int status;

	if (i >= ap_max_workers_limit && free_length == idle_spawn_rate)
	    break;
	ws = &ap_scoreboard_image->servers[i][0];
	status = ws->status;
	if (status == WORKER_DEAD) {
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
    ap_max_workers_limit = last_non_dead + 1;
    if (idle_count > ap_threads_max_free) {
	/* kill off one child... we use the pod because that'll cause it to
	 * shut down gracefully, in case it happened to pick up a request
	 * while we were counting
	 */
	idle_spawn_rate = 1;
    }
    else if (idle_count < ap_threads_min_free) {
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
		make_child(ap_server_conf, free_slots[i]);
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
    int remaining_workers_to_start;
    apr_status_t status=0;

    pconf = _pconf;
    ap_server_conf = s;

    if (setup_listeners(s)) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, status, s,
            "no listening sockets available, shutting down");
        return -1;
    }

    ap_log_pid(pconf, ap_pid_fname);

    worker_thread_count = 0;
    apr_thread_mutex_create(&worker_thread_count_mutex, APR_THREAD_MUTEX_DEFAULT, pconf);
    apr_thread_mutex_create(&accept_mutex, APR_THREAD_MUTEX_DEFAULT, pconf);
    if (!is_graceful) {
        ap_run_pre_mpm(pconf, SB_NOT_SHARED);
    }

    set_signals();

/* Normal child main stuff */

    apr_pool_create(&pmain, pconf);

    /* needs to be done before we switch UIDs so we have permissions */
    reopen_scoreboard(pmain);

    ap_run_child_init(pmain, ap_server_conf);


/* End Normal child main stuff */

    if (ap_threads_max_free < ap_threads_min_free + 1)	/* Don't thrash... */
        ap_threads_max_free = ap_threads_min_free + 1;

    /* If we're doing a graceful_restart then we're going to see a lot
	* of children exiting immediately when we get into the main loop
	* below (because we just sent them SIGWINCH).  This happens pretty
	* rapidly... and for each one that exits we'll start a new one until
	* we reach at least daemons_min_free.  But we may be permitted to
	* start more than that, so we'll just keep track of how many we're
	* supposed to start up without the 1 second penalty between each fork.
	*/
    remaining_workers_to_start = ap_threads_to_start;
    if (remaining_workers_to_start > ap_threads_limit) {
        remaining_workers_to_start = ap_threads_limit;
    }
    if (!is_graceful) {
        startup_workers(remaining_workers_to_start);
        remaining_workers_to_start = 0;
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

    printf("%s \n", ap_get_server_version());

    while (!restart_pending && !shutdown_pending) {
        int worker_slot;
        apr_wait_t status;

//        /* this is a memory leak, but I'll fix it later. */
//        apr_proc_t pid;
//
//        ap_wait_or_timeout(&status, &pid, pconf);
//
//        /* XXX: if it takes longer than 1 second for all our children
//        * to start up and get into IDLE state then we may spawn an
//        * extra child
//        */
//        if (pid.pid != -1) {
//            ap_process_child_status(&pid, status);
//            /* non-fatal death... note that it's gone in the scoreboard. */
//            ap_sync_scoreboard_image();
//            child_slot = find_child_by_pid(&pid);
//            if (child_slot >= 0) {
//                ap_update_child_status(AP_CHILD_THREAD_FROM_ID(child_slot), WORKER_DEAD,
//                    (request_rec *) NULL);
//                if (remaining_workers_to_start && child_slot < ap_threads_limit) {
//                    /* we're still doing a 1-for-1 replacement of dead
//                    * children with new children
//                    */
//                    make_child(ap_server_conf, child_slot);
//                    --remaining_workers_to_start;
//                }
//#if APR_HAS_OTHER_CHILD
//            }
//            else if (apr_proc_other_child_read(&pid, status) == 0) {
//            /* handled */
//#endif
//            }
//            else if (is_graceful) {
//                /* Great, we've probably just lost a slot in the
//                * scoreboard.  Somehow we don't know about this
//                * child.
//                */
//                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 
//                    0, ap_server_conf,
//                    "long lost child came home! (pid %ld)", (long)pid.pid);
//            }
//            /* Don't perform idle maintenance when a child dies,
//            * only do it when there's a timeout.  Remember only a
//            * finite number of children can die, and it's pretty
//            * pathological for a lot to die suddenly.
//            */
//            continue;
//        }
//        else if (remaining_workers_to_start) {
//            /* we hit a 1 second timeout in which none of the previous
//            * generation of children needed to be reaped... so assume
//            * they're all done, and pick up the slack if any is left.
//            */
//            startup_children(remaining_workers_to_start);
//            remaining_workers_to_start = 0;
//            /* In any event we really shouldn't do the code below because
//            * few of the servers we just started are in the IDLE state
//            * yet, so we'd mistakenly create an extra server.
//            */
//            continue;
//        }

//        perform_idle_server_maintenance(pconf);
        apr_thread_yield();
    }

    if (shutdown_pending) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
            "caught SIGTERM, shutting down");

        while (worker_thread_count > 0)
            apr_thread_yield();

        printf ("Press any key to continue...");
        getc(stdin);
        wait_to_finish = 0;
        return 1;
    }

    /* we've been told to restart */
//    apr_signal(SIGHUP, SIG_IGN);
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

#ifndef SCOREBOARD_FILE
	/* This is mostly for debugging... so that we know what is still
	    * gracefully dealing with existing request.  But we can't really
	    * do it if we're in a SCOREBOARD_FILE because it'll cause
	    * corruption too easily.
	    */
	ap_sync_scoreboard_image();
	for (index = 0; index < ap_threads_limit; ++index) {
	    if (ap_scoreboard_image->servers[0][index].status != WORKER_DEAD) {
		ap_scoreboard_image->servers[0][index].status = SERVER_GRACEFUL;
	    }
	}
#endif
    }
    else {
        /* Kill 'em off */
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
            "SIGHUP received.  Attempting to restart");
    }

    return 0;
}

static void netware_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static int restart_num = 0;
    int no_detach, debug;

    debug = ap_exists_config_define("DEBUG");

    if (debug)
        no_detach = one_process = 1;
    else
    {
        no_detach = ap_exists_config_define("NO_DETACH");
        one_process = ap_exists_config_define("ONE_PROCESS");
    }

    /* sigh, want this only the second time around */
    if (restart_num++ == 1) {
        is_graceful = 0;

        parent_pid = ap_my_pid = getpid();
    }

    ap_listen_pre_config();
    ap_threads_to_start = DEFAULT_START_DAEMON;
    ap_threads_min_free = DEFAULT_MIN_FREE_DAEMON;
    ap_threads_max_free = DEFAULT_MAX_FREE_DAEMON;
    ap_threads_limit = HARD_THREAD_LIMIT;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_scoreboard_fname = DEFAULT_SCOREBOARD;
    ap_lock_fname = DEFAULT_LOCKFILE;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    ap_extended_status = 0;

    apr_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));
}

static void netware_mpm_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(netware_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

void netware_rewrite_args(process_rec *process) 
{
    char *def_server_root;
    char optbuf[3];
    const char *optarg;
    apr_getopt_t *opt;
    apr_array_header_t *mpm_new_argv;


    /* Rewrite process->argv[]; 
     *
     * add default -d serverroot from the path of this executable
     * 
     * The end result will look like:
     *     The -d serverroot default from the running executable
     */
    if (process->argc > 0) {
        char *s = apr_pstrdup (process->pconf, process->argv[0]);
        if (s) {
            int i, len = strlen(s);

            for (i=len; i; i--) {
                if (s[i] == '\\' || s[i] == '/') {
                    s[i] = NULL;
                    apr_filepath_merge(&def_server_root, NULL, s, 
                        APR_FILEPATH_TRUENAME, process->pool);
                    break;
                }
            }
            /* Use process->pool so that the rewritten argv
            * lasts for the lifetime of the server process,
            * because pconf will be destroyed after the 
            * initial pre-flight of the config parser.
            */
            mpm_new_argv = apr_array_make(process->pool, process->argc + 2,
                                  sizeof(const char *));
            *(const char **)apr_array_push(mpm_new_argv) = process->argv[0];
            *(const char **)apr_array_push(mpm_new_argv) = "-d";
            *(const char **)apr_array_push(mpm_new_argv) = def_server_root;

            optbuf[0] = '-';
            optbuf[2] = '\0';
            apr_getopt_init(&opt, process->pool, process->argc, (char**) process->argv);
            while (apr_getopt(opt, AP_SERVER_BASEARGS, optbuf + 1, &optarg) == APR_SUCCESS) {
                switch (optbuf[1]) {
                default:
                    *(const char **)apr_array_push(mpm_new_argv) =
                        apr_pstrdup(process->pool, optbuf);

                    if (optarg) {
                        *(const char **)apr_array_push(mpm_new_argv) = optarg;
                    }
                    break;
                }
            }
            process->argc = mpm_new_argv->nelts; 
            process->argv = (const char * const *) mpm_new_argv->elts;
        }
    }
}

static const char *set_threads_to_start(cmd_parms *cmd, void *dummy, const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_to_start = atoi(arg);
    return NULL;
}

static const char *set_min_free_threads(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_min_free = atoi(arg);
    if (ap_threads_min_free <= 0) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "WARNING: detected MinSpareServers set to non-positive.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "Resetting to 1 to avoid almost certain Apache failure.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "Please read the documentation.");
       ap_threads_min_free = 1;
    }
       
    return NULL;
}

static const char *set_max_free_threads(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_max_free = atoi(arg);
    return NULL;
}

static const char *set_thread_limit (cmd_parms *cmd, void *dummy, const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_limit = atoi(arg);
    if (ap_threads_limit > HARD_THREAD_LIMIT) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "WARNING: MaxClients of %d exceeds compile time limit "
                    "of %d servers,", ap_threads_limit, HARD_SERVER_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " lowering MaxClients to %d.  To increase, please "
                    "see the", HARD_SERVER_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                    " HARD_SERVER_LIMIT define in %s.",
                    AP_MPM_HARD_LIMITS_FILE);
       ap_threads_limit = HARD_THREAD_LIMIT;
    } 
    else if (ap_threads_limit < 1) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
            "WARNING: Require MaxClients > 0, setting to 1");
        ap_threads_limit = 1;
    }
    return NULL;
}

static const char *set_thread_stacksize(cmd_parms *cmd, void *dummy, 
                                        const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    
    ap_thread_stack_size = atoi(arg);
    return NULL;
}

static const command_rec netware_mpm_cmds[] = {
AP_INIT_TAKE1("ThreadStackSize", set_thread_stacksize, NULL, RSRC_CONF,
              "Stack size each created thread will use."),
LISTEN_COMMANDS
AP_INIT_TAKE1("StartThreads", set_threads_to_start, NULL, RSRC_CONF,
              "Number of worker threads launched at server startup"),
AP_INIT_TAKE1("MinSpareThreads", set_min_free_threads, NULL, RSRC_CONF,
              "Minimum number of idle threads, to handle request spikes"),
AP_INIT_TAKE1("MaxSpareThreads", set_max_free_threads, NULL, RSRC_CONF,
              "Maximum number of idle threads"),
AP_INIT_TAKE1("MaxThreads", set_thread_limit, NULL, RSRC_CONF,
              "Maximum number of worker threads alive at the same time"),
{ NULL }
};

module AP_MODULE_DECLARE_DATA mpm_netware_module = {
    MPM20_MODULE_STUFF,
    netware_rewrite_args,   /* hook to run before apache parses args */
    NULL,			        /* create per-directory config structure */
    NULL,			        /* merge per-directory config structures */
    NULL,			        /* create per-server config structure */
    NULL,			        /* merge per-server config structures */
    netware_mpm_cmds,       /* command apr_table_t */
    netware_mpm_hooks,      /* register hooks */
};
