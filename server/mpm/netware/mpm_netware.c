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

#include <netware.h>
#include <nks/netware.h>
#include <library.h>

/* Limit on the total --- clients will be locked out if more servers than
 * this are needed.  It is intended solely to keep the server from crashing
 * when things get out of hand.
 *
 * We keep a hard maximum number of servers, for two reasons --- first off,
 * in case something goes seriously wrong, we want to stop the fork bomb
 * short of actually crashing the machine we're running on by filling some
 * kernel table.  Secondly, it keeps the size of the scoreboard file small
 * enough that we can read the whole thing without worrying too much about
 * the overhead.
 */
#ifndef HARD_SERVER_LIMIT
#define HARD_SERVER_LIMIT 1
#endif

#define WORKER_DEAD         SERVER_DEAD
#define WORKER_STARTING     SERVER_STARTING
#define WORKER_READY        SERVER_READY
#define WORKER_IDLE_KILL    SERVER_IDLE_KILL

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

static fd_set listenfds;
static int listenmaxfd;

static apr_pool_t *pconf;		/* Pool for config stuff */
static apr_pool_t *pmain;		/* Pool for httpd child stuff */

static pid_t ap_my_pid;	/* it seems silly to call getpid all the time */

static int die_now = 0;
static apr_thread_mutex_t *accept_mutex = NULL;

/* Keep track of the number of worker threads currently active */
static int worker_thread_count;
static apr_thread_mutex_t *worker_thread_count_mutex;
static int request_count;

/*  Structure used to register/deregister a console handler with the OS */
static int CommandLineInterpreter(scr_t screenID, const char *commandLine);
static  CommandParser_t ConsoleHandler = {0, NULL, 0};
#define HANDLEDCOMMAND  0
#define NOTMYCOMMAND    1

static int show_settings = 0;

#if 0
#define DBPRINT0(s) printf(s)
#define DBPRINT1(s,v1) printf(s,v1)
#define DBPRINT2(s,v1,v2) printf(s,v1,v2)
#else
#define DBPRINT0(s)
#define DBPRINT1(s,v1)
#define DBPRINT2(s,v1,v2)
#endif

/* a clean exit from a child with proper cleanup */
static void clean_child_exit(int code, int worker_num) __attribute__ ((noreturn));
static void clean_child_exit(int code, int worker_num)
{
    apr_thread_mutex_lock(worker_thread_count_mutex);
    worker_thread_count--;
    apr_thread_mutex_unlock(worker_thread_count_mutex);
    if (worker_num >=0)
        ap_update_child_status_from_indexes(0, worker_num, WORKER_DEAD, 
                                            (request_rec *) NULL);
    NXThreadExit((void*)&code);
}

AP_DECLARE(apr_status_t) ap_mpm_query(int query_code, int *result)
{
    switch(query_code){
        case AP_MPMQ_MAX_DAEMON_USED:
            *result = 1;
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
            *result = ap_threads_limit;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_THREADS:
            *result = ap_threads_min_free;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_THREADS:
            *result = ap_threads_max_free;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_REQUESTS_DAEMON:
            *result = ap_max_requests_per_child;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_DAEMONS:
            *result = 1;
            return APR_SUCCESS;
    }
    return APR_ENOTIMPL;
}


/*****************************************************************
 * Connection structures and accounting...
 */

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful;
static int volatile wait_to_finish=1;
ap_generation_t volatile ap_my_generation=0;

static void mpm_term(void)
{
    UnRegisterConsoleCommand(&ConsoleHandler);
    wait_to_finish = 0;
}

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

    DBPRINT0 ("waiting for threads\n");
    while (wait_to_finish) {
        apr_thread_yield();
    }
    DBPRINT0 ("goodbye\n");
}

/* restart() is the signal handler for SIGHUP and SIGWINCH
 * in the parent process, unless running in ONE_PROCESS mode
 */
static void restart(void)
{
    if (restart_pending == 1) {
        /* Probably not an error - don't bother reporting it */
        return;
    }
    restart_pending = 1;
    is_graceful = 1;
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

static fd_set main_fds;

int ap_graceful_stop_signalled(void)
{
    /* not ever called anymore... */
    return 0;
}

static int just_go = 0;
static int would_block = 0;
static void worker_main(void *arg)
{
    ap_listen_rec *lr;
    ap_listen_rec *last_lr = NULL;
    apr_pool_t *ptrans;
    conn_rec *current_conn;
    apr_status_t stat = APR_EINIT;
    int worker_num_arg = (int)arg;
    void *sbh;

    int my_worker_num = worker_num_arg;
    apr_socket_t *csd = NULL;
    apr_socket_t *sd = NULL;
    int requests_this_child = 0;

    DWORD ret;

    apr_pool_create(&ptrans, pmain);

    apr_thread_mutex_lock(worker_thread_count_mutex);
    worker_thread_count++;
    apr_thread_mutex_unlock(worker_thread_count_mutex);

    ap_update_child_status_from_indexes(0, my_worker_num, WORKER_READY, 
                                        (request_rec *) NULL);

    while (!die_now) {
        /*
        * (Re)initialize this child to a pre-connection state.
        */
        current_conn = NULL;
        apr_pool_clear(ptrans);

        if ((ap_max_requests_per_child > 0
            && requests_this_child++ >= ap_max_requests_per_child)) {
            clean_child_exit(0, my_worker_num);
        }

        ap_update_child_status_from_indexes(0, my_worker_num, WORKER_READY, 
                                            (request_rec *) NULL);

        /*
        * Wait for an acceptable connection to arrive.
        */

        /* Lock around "accept", if necessary */
        apr_thread_mutex_lock(accept_mutex);

        for (;;) {
            if (shutdown_pending || restart_pending || (ap_scoreboard_image->servers[0][my_worker_num].status == WORKER_IDLE_KILL)) {
                DBPRINT1 ("\nThread slot %d is shutting down\n", my_worker_num);
                apr_thread_mutex_unlock(accept_mutex);
                clean_child_exit(0, my_worker_num);
            }

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
            last_lr = lr;
            sd = lr->sd;

            stat = apr_accept(&csd, sd, ptrans);
            if (stat == APR_SUCCESS) {
                apr_setsocketopt(csd, APR_SO_NONBLOCK, 0);
                break;		/* We have a socket ready for reading */
            }
            else {
                just_go = 0;
                ret = APR_TO_NETOS_ERROR(stat);

                switch (ret) {

                    case WSAEWOULDBLOCK:
                        would_block++;
                        apr_thread_yield();
                        continue;
                        break;

                    case WSAECONNRESET:
                    case WSAETIMEDOUT:
                    case WSAEHOSTUNREACH:
                    case WSAENETUNREACH:
                        break;

                    case WSAENETDOWN:
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
                        clean_child_exit(APEXIT_CHILDFATAL, my_worker_num);

                    default:
                        ap_log_error(APLOG_MARK, APLOG_ERR, stat, ap_server_conf,
                            "apr_accept: (client socket)");
                        clean_child_exit(1, my_worker_num);
                }
            }
        }

        apr_thread_mutex_unlock(accept_mutex);

        ap_create_sb_handle(&sbh, ptrans, 0, my_worker_num);
        /*
        * We now have a connection, so set it up with the appropriate
        * socket options, file descriptors, and read/write buffers.
        */
        current_conn = ap_run_create_connection(ptrans, ap_server_conf, csd, 
                                                my_worker_num, sbh);
        if (current_conn) {
            ap_process_connection(current_conn);
            ap_lingering_close(current_conn);
        }
        request_count++;
    }
    clean_child_exit(0, my_worker_num);
}


static int make_child(server_rec *s, int slot)
{
    int tid;
    int err=0;
    NXContext_t ctx;

    if (slot + 1 > ap_max_workers_limit) {
        ap_max_workers_limit = slot + 1;
    }

    ap_update_child_status_from_indexes(0, slot, WORKER_STARTING, 
                                        (request_rec *) NULL);

    if (ctx = NXContextAlloc((void (*)(void *)) worker_main, (void*)slot, NX_PRIO_MED, ap_thread_stack_size, NX_CTX_NORMAL, &err)) {
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
        ap_update_child_status_from_indexes(0, slot, WORKER_DEAD, 
                                            (request_rec *) NULL);

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
#define MAX_SPAWN_RATE	(64)
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

    for (i = 0; i < ap_threads_limit; ++i) {
        int status;

        if (i >= ap_max_workers_limit && free_length == idle_spawn_rate)
            break;
        ws = &ap_scoreboard_image->servers[0][i];
        status = ws->status;
        if (status == WORKER_DEAD) {
            /* try to keep children numbers as low as possible */
            if (free_length < idle_spawn_rate) {
                free_slots[free_length] = i;
                ++free_length;
            }
        }
        else if (status == WORKER_IDLE_KILL) {
            /* If it is already marked to die, skip it */
            continue;
        }
        else {
            /* We consider a starting server as idle because we started it
            * at least a cycle ago, and if it still hasn't finished starting
            * then we're just going to swamp things worse by forking more.
            * So we hopefully won't need to fork more if we count it.
            * This depends on the ordering of SERVER_READY and SERVER_STARTING.
            */
            if (status <= WORKER_READY) {
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
    DBPRINT2("Total: %d Idle Count: %d  \r", total_non_dead, idle_count);
    ap_max_workers_limit = last_non_dead + 1;
    if (idle_count > ap_threads_max_free) {
        /* kill off one child... we use the pod because that'll cause it to
        * shut down gracefully, in case it happened to pick up a request
        * while we were counting
        */
        idle_spawn_rate = 1;
        ap_update_child_status_from_indexes(0, last_non_dead, WORKER_IDLE_KILL, 
                                            (request_rec *) NULL);
        DBPRINT1("\nKilling idle thread: %d\n", last_non_dead);
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
            DBPRINT0("\n");
            for (i = 0; i < free_length; ++i) {
                DBPRINT1("Spawning additional thread slot: %d\n", free_slots[i]);
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

static void display_settings ()
{
    int status_array[SERVER_NUM_STATUS];
    int i, status, total=0;
    int reqs = request_count;
    int wblock = would_block;

    request_count = 0;
    would_block = 0;

    ClearScreen (getscreenhandle());
    printf("%s \n", ap_get_server_version());

    for (i=0;i<SERVER_NUM_STATUS;i++) {
        status_array[i] = 0;
    }

    for (i = 0; i < ap_threads_limit; ++i) {
        status = (ap_scoreboard_image->servers[0][i]).status;
        status_array[status]++;
    }

    for (i=0;i<SERVER_NUM_STATUS;i++) {
        switch(i)
        {
        case SERVER_DEAD:
            printf ("Available:\t%d\n", status_array[i]);
            break;
        case SERVER_STARTING:
            printf ("Starting:\t%d\n", status_array[i]);
            break;
        case SERVER_READY:
            printf ("Ready:\t\t%d\n", status_array[i]);
            break;
        case SERVER_BUSY_READ:
            printf ("Busy:\t\t%d\n", status_array[i]);
            break;
        case SERVER_BUSY_WRITE:
            printf ("Busy Write:\t%d\n", status_array[i]);
            break;
        case SERVER_BUSY_KEEPALIVE:
            printf ("Busy Keepalive:\t%d\n", status_array[i]);
            break;
        case SERVER_BUSY_LOG:
            printf ("Busy Log:\t%d\n", status_array[i]);
            break;
        case SERVER_BUSY_DNS:
            printf ("Busy DNS:\t%d\n", status_array[i]);
            break;
        case SERVER_CLOSING:
            printf ("Closing:\t%d\n", status_array[i]);
            break;
        case SERVER_GRACEFUL:
            printf ("Restart:\t%d\n", status_array[i]);
            break;
        case SERVER_IDLE_KILL:
            printf ("Idle Kill:\t%d\n", status_array[i]);
            break;
        default:
            printf ("Unknown Status:\t%d\n", status_array[i]);
            break;
        }
        if (i != SERVER_DEAD)
            total+=status_array[i];
    }
    printf ("Total Running:\t%d\tout of: \t%d\n", total, ap_threads_limit);
    printf ("Requests per interval:\t%d\n", reqs);
    printf ("Would blocks:\t%d\n", wblock);
}

static void show_server_data()
{
    ap_listen_rec *lr;
    module **m;

    printf("%s \n", ap_get_server_version());

    /* Display listening ports */
    printf("   Listening on port(s):");
    lr = ap_listeners;
    do {
       printf(" %d", lr->bind_addr->port);
       lr = lr->next;
    } while(lr && lr != ap_listeners);
    
    /* Display dynamic modules loaded */
    printf("\n");    
    for (m = ap_loaded_modules; *m != NULL; m++) {
        if (((module*)*m)->dynamic_load_handle) {
            printf("   Loaded dynamic module %s\n", ((module*)*m)->name);
        }
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
        apr_setsocketopt(lr->sd, APR_SO_NONBLOCK, 1);
    }
    return 0;
}

/*****************************************************************
 * Executive routines.
 */

int ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
{
    apr_status_t status=0;

    pconf = _pconf;
    ap_server_conf = s;

    if (setup_listeners(s)) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, status, s,
            "no listening sockets available, shutting down");
        return -1;
    }

    restart_pending = shutdown_pending = 0;
    worker_thread_count = 0;
    apr_thread_mutex_create(&worker_thread_count_mutex, APR_THREAD_MUTEX_DEFAULT, pconf);
    apr_thread_mutex_create(&accept_mutex, APR_THREAD_MUTEX_DEFAULT, pconf);

    if (!is_graceful) {
        ap_run_pre_mpm(pconf, SB_NOT_SHARED);
    }

    /* Only set slot 0 since that is all NetWare will ever have. */
    ap_scoreboard_image->parent[0].pid = getpid();

    set_signals();

    apr_pool_create(&pmain, pconf);
    ap_run_child_init(pmain, ap_server_conf);

    if (ap_threads_max_free < ap_threads_min_free + 1)	/* Don't thrash... */
        ap_threads_max_free = ap_threads_min_free + 1;
    request_count = 0;

    startup_workers(ap_threads_to_start);

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		"%s configured -- resuming normal operations",
		ap_get_server_version());
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, ap_server_conf,
		"Server built: %s", ap_get_server_built());

    show_server_data();

    while (!restart_pending && !shutdown_pending) {
        perform_idle_server_maintenance(pconf);
        if (show_settings)
            display_settings();
        apr_thread_yield();
        apr_sleep(SCOREBOARD_MAINTENANCE_INTERVAL);
    }

    if (shutdown_pending) { /* Got an unload from the console */
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
            "caught SIGTERM, shutting down");

        DBPRINT0 ("Shutdown pending. Waiting for threads to terminate...\n");
        while (worker_thread_count > 0)
            apr_thread_yield();

        return 1;
    }
    else {  /* the only other way out is a restart */
        /* advance to the next generation */
        /* XXX: we really need to make sure this new generation number isn't in
         * use by any of the children.
         */
        ++ap_my_generation;
        ap_scoreboard_image->global.running_generation = ap_my_generation;
        update_scoreboard_global();

    	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		    "Graceful restart requested, doing restart");

        /* Wait for all of the threads to terminate before initiating the restart */
        DBPRINT0 ("Restart pending. Waiting for threads to terminate...\n");
        while (worker_thread_count > 0) {
            apr_thread_yield();
        }
        DBPRINT0 ("restarting...\n");
    }

    return 0;
}

static void netware_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    int debug;

    debug = ap_exists_config_define("DEBUG");

    is_graceful = 0;
    ap_my_pid = getpid();

    ap_listen_pre_config();
    ap_threads_to_start = DEFAULT_START_THREADS;
    ap_threads_min_free = DEFAULT_MIN_FREE_THREADS;
    ap_threads_max_free = DEFAULT_MAX_FREE_THREADS;
    ap_threads_limit = HARD_THREAD_LIMIT;
    ap_scoreboard_fname = DEFAULT_SCOREBOARD;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    ap_extended_status = 0;
}

static void netware_mpm_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(netware_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

void netware_rewrite_args(process_rec *process) 
{
    char *def_server_root;
    char optbuf[3];
    const char *opt_arg;
    apr_getopt_t *opt;
    apr_array_header_t *mpm_new_argv;


    atexit (mpm_term);
    InstallConsoleHandler();

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
            while (apr_getopt(opt, AP_SERVER_BASEARGS, optbuf + 1, &opt_arg) == APR_SUCCESS) {
                switch (optbuf[1]) {
                default:
                    *(const char **)apr_array_push(mpm_new_argv) =
                        apr_pstrdup(process->pool, optbuf);

                    if (opt_arg) {
                        *(const char **)apr_array_push(mpm_new_argv) = opt_arg;
                    }
                    break;
                }
            }
            process->argc = mpm_new_argv->nelts; 
            process->argv = (const char * const *) mpm_new_argv->elts;
        }
    }
}


static int CommandLineInterpreter(scr_t screenID, const char *commandLine)
{
    screenID = screenID;
    /*  All added commands begin with "HTTPD " */

    if (!strnicmp("HTTPD ", commandLine, 6)) {
        ActivateScreen (getscreenhandle());

        if (!strnicmp("RESTART",&commandLine[6],3)) {
            printf("Restart Requested...\n");
            restart();
        }
        else if (!strnicmp("VERSION",&commandLine[6],3)) {
            printf("Server version: %s\n", ap_get_server_version());
            printf("Server built:   %s\n", ap_get_server_built());
        }
        else if (!strnicmp("MODULES",&commandLine[6],3)) {
    	    ap_show_modules();
        }
        else if (!strnicmp("DIRECTIVES",&commandLine[6],3)) {
	        ap_show_directives();
        }
        else if (!strnicmp("SHUTDOWN",&commandLine[6],3)) {
            printf("Shutdown Requested...\n");
            shutdown_pending = 1;
        }
        else if (!strnicmp("SETTINGS",&commandLine[6],3)) {
            if (show_settings) {
                show_settings = 0;
                ClearScreen (getscreenhandle());
                show_server_data();
            }
            else {
                show_settings = 1;
                display_settings();
            }
        }
        else {
            printf("Unknown HTTPD command %s\n", &commandLine[6]);
        }

        /*  Tell NetWare we handled the command */
        return HANDLEDCOMMAND;
    }

    /*  Tell NetWare that the command isn't mine */
    return NOTMYCOMMAND;
}

static int InstallConsoleHandler(void)
{
    /*  Our command line handler interfaces the system operator
    with this NLM */

    NX_WRAP_INTERFACE(CommandLineInterpreter, 2, (void*)&(ConsoleHandler.parser));

    ConsoleHandler.rTag = AllocateResourceTag(getnlmhandle(), "Command Line Processor",
        ConsoleCommandSignature);
    if (!ConsoleHandler.rTag)
    {
        printf("Error on allocate resource tag\n");
        return 1;
    }

    RegisterConsoleCommand(&ConsoleHandler);

    /*  The Remove procedure unregisters the console handler */

    return 0;
}

static void RemoveConsoleHandler(void)
{
    UnRegisterConsoleCommand(&ConsoleHandler);
    NX_UNWRAP_INTERFACE(ConsoleHandler.parser);
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
                    "WARNING: MaxThreads of %d exceeds compile time limit "
                    "of %d threads,", ap_threads_limit, HARD_THREAD_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " lowering MaxThreads to %d.  To increase, please "
                    "see the", HARD_THREAD_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                    " HARD_THREAD_LIMIT define in %s.",
                    AP_MPM_HARD_LIMITS_FILE);
       ap_threads_limit = HARD_THREAD_LIMIT;
    } 
    else if (ap_threads_limit < 1) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
            "WARNING: Require MaxThreads > 0, setting to 1");
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
LISTEN_COMMANDS,
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
