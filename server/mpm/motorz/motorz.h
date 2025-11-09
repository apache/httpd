/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

#include "ap_config.h"
#include "httpd.h"
#include "mpm_default.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"          /* for get_remote_host */
#include "http_connection.h"
#include "scoreboard.h"
#include "ap_mpm.h"
#include "util_mutex.h"
#include "unixd.h"
#include "http_vhost.h"
#include "mpm_common.h"
#include "ap_listen.h"
#include "ap_mmn.h"
#include "apr_poll.h"
#include "apr_skiplist.h"
#include "apr_thread_pool.h"
#include "util_time.h"

#include <stdlib.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_PROCESSOR_H
#include <sys/processor.h> /* for bindprocessor() */
#endif

#include <signal.h>
#include <sys/times.h>

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
#ifndef DEFAULT_SERVER_LIMIT
#define DEFAULT_SERVER_LIMIT 256
#endif

/* Admin can't tune ServerLimit beyond MAX_SERVER_LIMIT.  We want
 * some sort of compile-time limit to help catch typos.
 */
#ifndef MAX_SERVER_LIMIT
#define MAX_SERVER_LIMIT 200000
#endif

/* Limit on the threads per process.  Clients will be locked out if more than
 * this are needed.
 *
 * We keep this for one reason it keeps the size of the scoreboard file small
 * enough that we can read the whole thing without worrying too much about
 * the overhead.
 */
#ifndef DEFAULT_THREAD_LIMIT
#define DEFAULT_THREAD_LIMIT 64
#endif

/* Admin can't tune ThreadLimit beyond MAX_THREAD_LIMIT.  We want
 * some sort of compile-time limit to help catch typos.
 */
#ifndef MAX_THREAD_LIMIT
#define MAX_THREAD_LIMIT 100000
#endif

#define MPM_CHILD_PID(i) (ap_scoreboard_image->parent[i].pid)

/**
 * typedefs
 */
/* data retained by prefork across load/unload of the module
 * allocated on first call to pre-config hook; located on
 * subsequent calls to pre-config hook
 */
typedef struct motorz_core_t motorz_core_t;
struct motorz_core_t {
    ap_unixd_mpm_retained_data *mpm;

    int first_server_limit;
    int maxclients_reported;
    /*
     * The max child slot ever assigned, preserved across restarts.  Necessary
     * to deal with MaxRequestWorkers changes across AP_SIG_GRACEFUL restarts.  We
     * use this value to optimize routines that have to scan the entire scoreboard.
     */
    int max_daemons_limit;
    apr_pool_t *pool;
    apr_thread_mutex_t *mtx;
    apr_pollset_t *pollset;
    apr_skiplist *timeout_ring;
    apr_thread_pool_t *workers;
};

typedef struct motorz_child_bucket motorz_child_bucket;
struct motorz_child_bucket {
    ap_pod_t *pod;
    ap_listen_rec *listeners;
    apr_proc_mutex_t *mutex;
};

typedef enum
{
    PT_CSD,
    PT_ACCEPT,
    PT_USER
} motorz_poll_type_e;

typedef struct motorz_sb_t motorz_sb_t;
struct motorz_sb_t
{
    motorz_poll_type_e type;
    void *baton;
};

typedef void (*motorz_timer_cb) (motorz_core_t *mz, void *baton);
typedef void (*motorz_io_sock_cb) (motorz_core_t *mz, apr_socket_t *sock,
                                   int flags, void *baton);
typedef void (*motorz_io_file_cb) (motorz_core_t *mz, apr_socket_t *sock,
                                   int flags, void *baton);


typedef struct motorz_timer_t motorz_timer_t;
struct motorz_timer_t
{
    apr_time_t expires;
    motorz_timer_cb cb;
    void *baton;
    apr_pool_t *pool;
    motorz_core_t *mz;
};

typedef struct motorz_conn_t motorz_conn_t;
struct motorz_conn_t
{
    apr_pool_t *pool;
    motorz_core_t *mz;
    apr_socket_t *sock;
    apr_bucket_alloc_t *ba;
    ap_sb_handle_t *sbh;
    /** connection record this struct refers to */
    conn_rec *c;
    /** request record (if any) this struct refers to */
    request_rec *r;
    /** is the current conn_rec suspended? */
    int suspended;
    /** poll file descriptor information */
    apr_pollfd_t pfd;
    /** public parts of the connection state */
    conn_state_t cs;
    /** timer associated with the connection */
    motorz_timer_t timer;
};
