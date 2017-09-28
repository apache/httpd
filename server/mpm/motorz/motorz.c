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

#include "motorz.h"

/**
 * config globals
 */
static motorz_core_t *g_motorz_core;
static int threads_per_child = 16;
static int ap_num_kids = DEFAULT_START_DAEMON;
static int thread_limit = MAX_THREAD_LIMIT/10;

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

static apr_pool_t *pconf;               /* Pool for config stuff */
static apr_pool_t *pchild;              /* Pool for httpd child stuff */

static pid_t ap_my_pid; /* it seems silly to call getpid all the time */
static pid_t parent_pid;
static int my_child_num;
static motorz_child_bucket *all_buckets, /* All listeners buckets */
                            *my_bucket;   /* Current child bucket */

static void clean_child_exit(int code) __attribute__ ((noreturn));


static apr_status_t motorz_io_process(motorz_conn_t *scon);
static void clean_child_exit(int code) __attribute__ ((noreturn));

static apr_pollset_t *motorz_pollset;
static apr_skiplist *motorz_timer_ring;

static motorz_core_t *motorz_core_get(void)
{
    return g_motorz_core;
}

static int timer_comp(void *a, void *b)
{
    apr_time_t t1 = (apr_time_t) (((motorz_timer_t *) a)->expires);
    apr_time_t t2 = (apr_time_t) (((motorz_timer_t *) b)->expires);
    AP_DEBUG_ASSERT(t1);
    AP_DEBUG_ASSERT(t2);
    return ((t1 < t2) ? -1 : 1);
}

static apr_status_t motorz_conn_pool_cleanup(void *baton)
{
    motorz_conn_t *scon = (motorz_conn_t *)baton;

    if (scon->timer.expires) {
        motorz_core_t *mz = scon->mz;

        apr_thread_mutex_lock(mz->mtx);
        apr_skiplist_remove(mz->timeout_ring, &scon->timer, NULL);
        apr_thread_mutex_unlock(mz->mtx);
    }

    return APR_SUCCESS;
}

static APR_INLINE apr_interval_time_t
motorz_get_timeout(motorz_conn_t *scon)
{
    if (scon->c->base_server) {
        return scon->c->base_server->timeout;
    }
    else {
        return ap_server_conf->timeout;
    }
}

static APR_INLINE apr_interval_time_t
motorz_get_keep_alive_timeout(motorz_conn_t *scon)
{
    if (scon->c->base_server) {
        return scon->c->base_server->keep_alive_timeout;
    }
    else {
        return ap_server_conf->keep_alive_timeout;
    }
}

static void motorz_io_timeout_cb(motorz_core_t *mz, void *baton)
{

    motorz_conn_t *scon = (motorz_conn_t *) baton;
    conn_rec *c = scon->c;
    scon->cs.state = CONN_STATE_LINGER;
    ap_lingering_close(c);

    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, APLOGNO(02842)
                 "io timeout hit (?) scon: %pp, c: %pp", scon, c);
}

static void *motorz_io_setup_conn(apr_thread_t *thread, void *baton)
{
    apr_status_t status;
    ap_sb_handle_t *sbh;
    long conn_id = 0;
    motorz_sb_t *sb;
    motorz_conn_t *scon = (motorz_conn_t *) baton;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03316)
                         "motorz_io_setup_conn(): entered");

    ap_create_sb_handle(&sbh, scon->pool, 0, 0);
    scon->sbh = sbh;
    scon->ba = apr_bucket_alloc_create(scon->pool);

    scon->c = ap_run_create_connection(scon->pool, ap_server_conf, scon->sock,
                                       conn_id, sbh, scon->ba);
    /* XXX: handle failure */

    scon->c->cs = &scon->cs;
    sb = apr_pcalloc(scon->pool, sizeof(motorz_sb_t));

    scon->c->current_thread = thread;

    scon->pfd.p = scon->pool;
    scon->pfd.desc_type = APR_POLL_SOCKET;
    scon->pfd.desc.s = scon->sock;
    scon->pfd.reqevents = APR_POLLIN;

    sb->type = PT_CSD;
    sb->baton = scon;
    scon->pfd.client_data = sb;

    ap_update_vhost_given_ip(scon->c);

    status = ap_run_pre_connection(scon->c, scon->sock);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03317)
                         "motorz_io_setup_conn(): did pre-conn");
    if (status != OK && status != DONE) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(02843)
                     "motorz_io_setup_conn: connection aborted");
        scon->c->aborted = 1;
    }

    scon->cs.state = CONN_STATE_READ_REQUEST_LINE;
    scon->cs.sense = CONN_SENSE_DEFAULT;

    status = motorz_io_process(scon);

    if (1) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, status, ap_server_conf, APLOGNO(02844)
                     "motorz_io_setup_conn: motorz_io_process status: %d", (int)status);
    }
    return NULL;
}

static apr_status_t motorz_io_user(motorz_core_t *mz, motorz_sb_t *sb)
{
    /* TODO */
    return APR_SUCCESS;
}

static apr_status_t motorz_io_accept(motorz_core_t *mz, motorz_sb_t *sb)
{
    apr_status_t rv;
    apr_pool_t *ptrans;
    apr_socket_t *socket;
    ap_listen_rec *lr = (ap_listen_rec *) sb->baton;
    apr_allocator_t *allocator;

    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    apr_pool_create_ex(&ptrans, pconf, NULL, allocator);
    apr_allocator_owner_set(allocator, ptrans);
    apr_pool_tag(ptrans, "transaction");

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03318)
                         "motorz_io_accept(): entered");

    rv = lr->accept_func((void *)&socket, lr, ptrans);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(02845)
                     "motorz_io_accept failed");
        clean_child_exit(APEXIT_CHILDSICK);
    }
    else {
        motorz_conn_t *scon = apr_pcalloc(ptrans, sizeof(motorz_conn_t));
        scon->pool = ptrans;
        scon->sock = socket;
        scon->mz = mz;

        apr_pool_cleanup_register(scon->pool, scon, motorz_conn_pool_cleanup,
                                  apr_pool_cleanup_null);

        rv = apr_thread_pool_push(mz->workers,
                                  motorz_io_setup_conn,
                                  scon,
                                  APR_THREAD_TASK_PRIORITY_HIGHEST, NULL);
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf, APLOGNO(03319)
                         "motorz_io_accept(): exited: %d", (int)rv);

    return rv;
}

static void *motorz_timer_invoke(apr_thread_t *thread, void *baton)
{
    motorz_timer_t *ep = (motorz_timer_t *)baton;
    motorz_conn_t *scon = (motorz_conn_t *)ep->baton;

    scon->c->current_thread = thread;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03320)
                         "motorz_timer_invoke(): entered");

    ep->cb(ep->mz, ep->baton);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03321)
                         "motorz_timer_invoke(): exited");

    return NULL;
}

static apr_status_t motorz_timer_event_process(motorz_core_t *mz, motorz_timer_t *te)
{
    motorz_conn_t *scon = (motorz_conn_t *)te->baton;
    scon->timer.expires = 0;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03322)
                         "motorz_timer_event_process(): entered");

    return apr_thread_pool_push(mz->workers,
                                motorz_timer_invoke,
                                te, APR_THREAD_TASK_PRIORITY_NORMAL, NULL);
}

static void *motorz_io_invoke(apr_thread_t *thread, void *baton)
{
    motorz_sb_t *sb = (motorz_sb_t *) baton;
    motorz_conn_t *scon = (motorz_conn_t *) sb->baton;
    apr_status_t rv;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03323)
                         "motorz_io_invoke(): entered");
    scon->c->current_thread = thread;

    rv = motorz_io_process(scon);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf, APLOGNO(02846)
                     "motorz_io_invoke: motorz_io_process failed (?)");
    }
    return NULL;
}

static apr_status_t motorz_io_event_process(motorz_core_t *mz, motorz_sb_t *sb)
{
    return apr_thread_pool_push(mz->workers,
                                motorz_io_invoke,
                                sb, APR_THREAD_TASK_PRIORITY_NORMAL, NULL);
}

static apr_status_t motorz_io_callback(void *baton, const apr_pollfd_t *pfd)
{
    apr_status_t status = APR_SUCCESS;
    motorz_core_t *mz = (motorz_core_t *) baton;
    motorz_sb_t *sb = pfd->client_data;


    if (sb->type == PT_ACCEPT) {
        status = motorz_io_accept(mz, sb);
    }
    else if (sb->type == PT_CSD) {
        status = motorz_io_event_process(mz, sb);
    }
    else if (sb->type == PT_USER) {
        status = motorz_io_user(mz, sb);
    }
    return status;
}

static void motorz_register_timeout(motorz_conn_t *scon,
                                    motorz_timer_cb cb,
                                    apr_interval_time_t relative_time)
{
    apr_time_t t = apr_time_now() + relative_time;
    motorz_timer_t *elem = &scon->timer;
    motorz_core_t *mz = scon->mz;

    elem->expires = t;
    elem->cb = cb;
    elem->baton = scon;
    elem->pool = scon->pool;
    elem->mz = mz;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03324)
                         "motorz_register_timer(): insert ELEM: %pp", elem);

    apr_thread_mutex_lock(mz->mtx);
#ifdef AP_DEBUG
    ap_assert(apr_skiplist_insert(mz->timeout_ring, elem));
#else
    apr_skiplist_insert(mz->timeout_ring, elem);
#endif
    apr_thread_mutex_unlock(mz->mtx);
}

static apr_status_t motorz_io_process(motorz_conn_t *scon)
{
    apr_status_t rv;
    motorz_core_t *mz;
    conn_rec *c;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03325)
                         "motorz_io_process(): entered");

    if (scon->c->clogging_input_filters && !scon->c->aborted) {
        /* Since we have an input filter which 'clogs' the input stream,
         * like mod_ssl used to, lets just do the normal read from input
         * filters, like the Worker MPM does. Filters that need to write
         * where they would otherwise read, or read where they would
         * otherwise write, should set the sense appropriately.
         */
        ap_run_process_connection(scon->c);
        if (scon->cs.state != CONN_STATE_SUSPENDED) {
            scon->cs.state = CONN_STATE_LINGER;
        }
    }

    mz = scon->mz;
    c = scon->c;

    if (!c->aborted) {

        if (scon->pfd.reqevents != 0) {
            /*
             * Some of the pollset backends, like KQueue or Epoll
             * automagically remove the FD if the socket is closed,
             * therefore, we can accept _SUCCESS or _NOTFOUND,
             * and we still want to keep going
             */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03326)
                                 "motorz_io_process(): apr_pollset_remove");

            rv = apr_pollset_remove(mz->pollset, &scon->pfd);
            if (rv != APR_SUCCESS && !APR_STATUS_IS_NOTFOUND(rv)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(02847)
                             "motorz_io_process: apr_pollset_remove failure");
                /*AP_DEBUG_ASSERT(rv == APR_SUCCESS);*/
            }
            scon->pfd.reqevents = 0;
        }

        if (scon->cs.state == CONN_STATE_CHECK_REQUEST_LINE_READABLE) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03327)
                                 "motorz_io_process(): Set to CONN_STATE_READ_REQUEST_LINE");
            scon->cs.state = CONN_STATE_READ_REQUEST_LINE;
        }

read_request:
        if (scon->cs.state == CONN_STATE_READ_REQUEST_LINE) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03328)
                                 "motorz_io_process(): CONN_STATE_READ_REQUEST_LINE");
            if (!c->aborted) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03329)
                                     "motorz_io_process(): !aborted");
                ap_run_process_connection(c);
                /* state will be updated upon return
                 * fall thru to either wait for readability/timeout or
                 * do lingering close
                 */
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03330)
                                     "motorz_io_process(): aborted");
                scon->cs.state = CONN_STATE_LINGER;
            }
        }

        if (scon->cs.state == CONN_STATE_WRITE_COMPLETION) {
            int pending;

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03331)
                                  "motorz_io_process(): CONN_STATE_WRITE_COMPLETION");

            ap_update_child_status(scon->sbh, SERVER_BUSY_WRITE, NULL);

            pending = ap_run_output_pending(c);
            if (pending == OK) {
                /* Still in WRITE_COMPLETION_STATE:
                 * Set a write timeout for this connection, and let the
                 * event thread poll for writeability.
                 */
                motorz_register_timeout(scon,
                                      motorz_io_timeout_cb,
                                      motorz_get_timeout(scon));

                scon->pfd.reqevents = (
                                       scon->cs.sense == CONN_SENSE_WANT_READ ? APR_POLLIN :
                                       APR_POLLOUT) | APR_POLLHUP | APR_POLLERR;
                scon->cs.sense = CONN_SENSE_DEFAULT;

                rv = apr_pollset_add(mz->pollset, &scon->pfd);

                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                                 ap_server_conf, APLOGNO(02849)
                                 "apr_pollset_add: failed in write completion");
                }
                return APR_SUCCESS;
            }
            if (pending != DECLINED
                    || c->keepalive != AP_CONN_KEEPALIVE
                    || c->aborted) {
                scon->cs.state = CONN_STATE_LINGER;
            }
            else if (c->data_in_input_filters || ap_run_input_pending(c) == OK) {
                scon->cs.state = CONN_STATE_READ_REQUEST_LINE;
                goto read_request;
            }
            else {
                scon->cs.state = CONN_STATE_CHECK_REQUEST_LINE_READABLE;
            }
        }

        if (scon->cs.state == CONN_STATE_LINGER) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03332)
                                  "motorz_io_process(): CONN_STATE_LINGER");
            ap_lingering_close(c);
        }

        if (scon->cs.state == CONN_STATE_CHECK_REQUEST_LINE_READABLE) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03333)
                                  "motorz_io_process(): CONN_STATE_CHECK_REQUEST_LINE_READABLE");
            motorz_register_timeout(scon,
                                  motorz_io_timeout_cb,
                                  motorz_get_keep_alive_timeout(scon));

            scon->pfd.reqevents = APR_POLLIN | APR_POLLHUP | APR_POLLERR;
            scon->cs.sense = CONN_SENSE_DEFAULT;

            rv = apr_pollset_add(mz->pollset, &scon->pfd);

            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(02850)
                             "process_socket: apr_pollset_add failure in read request line");
                return rv;
            }
        }
    } else {
        ap_lingering_close(c);
    }
    return APR_SUCCESS;
}

static apr_status_t motorz_pollset_cb(motorz_core_t *mz, apr_interval_time_t timeout)
{
    apr_status_t rc;
    const apr_pollfd_t *out_pfd = NULL;
    apr_int32_t num = 0;

    rc = apr_pollset_poll(mz->pollset, timeout, &num, &out_pfd);
    if (rc != APR_SUCCESS) {
        if (APR_STATUS_IS_EINTR(rc) || APR_STATUS_IS_TIMEUP(rc)) {
                return APR_SUCCESS;
        } else {
            return rc;
        }
    }
    while (num > 0) {
        rc = motorz_io_callback(mz, out_pfd);
        if (rc != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rc, NULL, APLOGNO(03334)
                         "Call to motorz_io_callback() failed");
        }
        out_pfd++;
        num--;
    }
    return APR_SUCCESS;
}

/**
 * Create worker thread pool.
 */
static apr_status_t motorz_setup_workers(motorz_core_t *mz)
{
    apr_status_t rv;

    rv = apr_thread_pool_create(&mz->workers,
                                threads_per_child,
                                threads_per_child, mz->pool);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(02851)
                     "motorz_setup_workers: apr_thread_pool_create with %d threads failed",
                     threads_per_child);
        return rv;
    }

    return APR_SUCCESS;
}

static int motorz_setup_pollset(motorz_core_t *mz)
{
    int i;
    apr_status_t rv;
    int good_methods[] = {APR_POLLSET_KQUEUE, APR_POLLSET_PORT, APR_POLLSET_EPOLL};

    for (i = 0; i < sizeof(good_methods) / sizeof(good_methods[0]); i++) {
        rv = apr_pollset_create_ex(&mz->pollset,
                                  512,
                                  mz->pool,
                                  APR_POLLSET_NODEFAULT,
                                  good_methods[i]);
        if (rv == APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf, APLOGNO(02852)
                         "motorz_setup_pollset: apr_pollset_create_ex using %s", apr_pollset_method_name(mz->pollset));

            break;
        }
    }
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, ap_server_conf, APLOGNO(02853)
                     "motorz_setup_pollset: apr_pollset_create_ex failed for all possible backends!");
        rv = apr_pollset_create(&mz->pollset,
                                    512,
                                    mz->pool,
                                    0);
    }
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(02854)
                     "motorz_setup_pollset: apr_pollset_create failed for all possible backends!");
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03335)
                 "motorz_setup_pollset: Using %s", apr_pollset_method_name(mz->pollset));
    return rv;
}

static void motorz_note_child_killed(int childnum, pid_t pid,
                                      ap_generation_t gen)
{
    AP_DEBUG_ASSERT(childnum != -1); /* no scoreboard squatting with this MPM */
    ap_run_child_status(ap_server_conf,
                        ap_scoreboard_image->parent[childnum].pid,
                        ap_scoreboard_image->parent[childnum].generation,
                        childnum, MPM_CHILD_EXITED);
    ap_scoreboard_image->parent[childnum].pid = 0;
}

static void motorz_note_child_started(motorz_core_t *mz, int slot, pid_t pid)
{
    ap_scoreboard_image->parent[slot].pid = pid;
    ap_run_child_status(ap_server_conf,
                        ap_scoreboard_image->parent[slot].pid,
                        mz->mpm->my_generation, slot, MPM_CHILD_STARTED);
}

/* a clean exit from a child with proper cleanup */
static void clean_child_exit(int code)
{
    motorz_core_t *mz = motorz_core_get();

    mz->mpm->mpm_state = AP_MPMQ_STOPPING;

    apr_signal(SIGHUP, SIG_IGN);
    apr_signal(SIGTERM, SIG_IGN);

    if (pchild) {
        apr_pool_destroy(pchild);
    }

    if (one_process) {
        motorz_note_child_killed(/* slot */ 0, 0, 0);
    }

    ap_mpm_pod_close(my_bucket->pod);
    exit(code);
}

#if 0 /* unused for now */
static apr_status_t accept_mutex_on(void)
{
    motorz_core_t *mz = motorz_core_get();
    apr_status_t rv = apr_proc_mutex_lock(my_bucket->mutex);
    if (rv != APR_SUCCESS) {
        const char *msg = "couldn't grab the accept mutex";

        if (mz->mpm->my_generation !=
            ap_scoreboard_image->global->running_generation) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf, APLOGNO(02855) "%s", msg);
            clean_child_exit(0);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf, APLOGNO(02856) "%s", msg);
            exit(APEXIT_CHILDFATAL);
        }
    }
    return APR_SUCCESS;
}

static apr_status_t accept_mutex_off(void)
{
    motorz_core_t *mz = motorz_core_get();
    apr_status_t rv = apr_proc_mutex_unlock(my_bucket->mutex);
    if (rv != APR_SUCCESS) {
        const char *msg = "couldn't release the accept mutex";

        if (mz->mpm->my_generation !=
            ap_scoreboard_image->global->running_generation) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf, APLOGNO(02857) "%s", msg);
            /* don't exit here... we have a connection to
             * process, after which point we'll see that the
             * generation changed and we'll exit cleanly
             */
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf, APLOGNO(02858) "%s", msg);
            exit(APEXIT_CHILDFATAL);
        }
    }
    return APR_SUCCESS;
}
#endif

/* On some architectures it's safe to do unserialized accept()s in the single
 * Listen case.  But it's never safe to do it in the case where there's
 * multiple Listen statements.  Define SINGLE_LISTEN_UNSERIALIZED_ACCEPT
 * when it's safe in the single Listen case.
 */
#ifdef SINGLE_LISTEN_UNSERIALIZED_ACCEPT
#define SAFE_ACCEPT(stmt) (ap_listeners->next ? (stmt) : APR_SUCCESS)
#else
#define SAFE_ACCEPT(stmt) (stmt)
#endif

static int motorz_query(int query_code, int *result, apr_status_t *rv)
{
    motorz_core_t *mz = motorz_core_get();
    *rv = APR_SUCCESS;
    switch(query_code){
    case AP_MPMQ_IS_ASYNC:
        *result = 1;
        break;
    case AP_MPMQ_MAX_DAEMON_USED:
        *result = ap_num_kids;
        break;
    case AP_MPMQ_IS_THREADED:
        *result = AP_MPMQ_STATIC;
        break;
    case AP_MPMQ_IS_FORKED:
        *result = AP_MPMQ_STATIC;
        break;
    case AP_MPMQ_HARD_LIMIT_DAEMONS:
        *result = ap_num_kids;
        break;
    case AP_MPMQ_HARD_LIMIT_THREADS:
        *result = thread_limit;
        break;
    case AP_MPMQ_MAX_THREADS:
        *result = threads_per_child;
        break;
    case AP_MPMQ_MIN_SPARE_DAEMONS:
        *result = 0;
        break;
    case AP_MPMQ_MIN_SPARE_THREADS:
        *result = 0;
        break;
    case AP_MPMQ_MAX_SPARE_DAEMONS:
        *result = ap_num_kids;
        break;
    case AP_MPMQ_MAX_SPARE_THREADS:
        *result = 0;
        break;
    case AP_MPMQ_MAX_REQUESTS_DAEMON:
        *result = 0;
        break;
    case AP_MPMQ_MAX_DAEMONS:
        *result = ap_num_kids;
        break;
    case AP_MPMQ_MPM_STATE:
        *result = mz->mpm->mpm_state;
        break;
    case AP_MPMQ_GENERATION:
        *result = mz->mpm->my_generation;
        break;
    default:
        *rv = APR_ENOTIMPL;
        break;
    }
    return OK;
}

static const char *motorz_get_name(void)
{
    return "motorz";
}

/*****************************************************************
 * Connection structures and accounting...
 */

static void just_die(int sig)
{
    clean_child_exit(0);
}

/* volatile because it's updated from a signal handler */
static int volatile die_now = 0;

static void stop_listening(int sig)
{
    motorz_core_t *mz = motorz_core_get();

    mz->mpm->mpm_state = AP_MPMQ_STOPPING;
    ap_close_listeners_ex(my_bucket->listeners);

    /* For a graceful stop, we want the child to exit when done */
    die_now = 1;
}

/*****************************************************************
 * Child process main loop.
 * The following vars are static to avoid getting clobbered by longjmp();
 * they are really private to child_main.
 */

static int requests_this_child;
static int num_listensocks = 0;

static void child_main(motorz_core_t *mz, int child_num_arg, int child_bucket)
{
#if APR_HAS_THREADS
    apr_thread_t *thd = NULL;
    apr_os_thread_t osthd;
#endif
    apr_status_t status;
    int i;
    ap_listen_rec *lr;
    ap_sb_handle_t *sbh;
    const char *lockfile;

    /* for benefit of any hooks that run as this child initializes */
    mz->mpm->mpm_state = AP_MPMQ_STARTING;

    my_child_num = child_num_arg;
    ap_my_pid = getpid();
    requests_this_child = 0;

    ap_fatal_signal_child_setup(ap_server_conf);

    /* Get a sub context for global allocations in this child, so that
     * we can have cleanups occur when the child exits.
     */
    apr_pool_create(&pchild, pconf);
    apr_pool_tag(pchild, "pchild");

#if APR_HAS_THREADS
    osthd = apr_os_thread_current();
    apr_os_thread_put(&thd, &osthd, pchild);
#endif

    /* close unused listeners and pods */
    for (i = 0; i < mz->mpm->num_buckets; i++) {
        if (i != child_bucket) {
            ap_close_listeners_ex(all_buckets[i].listeners);
            ap_mpm_pod_close(all_buckets[i].pod);
        }
    }

    /* needs to be done before we switch UIDs so we have permissions */
    ap_reopen_scoreboard(pchild, NULL, 0);
    status = SAFE_ACCEPT(apr_proc_mutex_child_init(&my_bucket->mutex,
                                    apr_proc_mutex_lockfile(my_bucket->mutex),
                                    pchild));
    if (status != APR_SUCCESS) {
        lockfile = apr_proc_mutex_lockfile(my_bucket->mutex);
        ap_log_error(APLOG_MARK, APLOG_EMERG, status, ap_server_conf, APLOGNO(02867)
                     "Couldn't initialize cross-process lock in child "
                     "(%s) (%s)",
                     lockfile ? lockfile : "none",
                     apr_proc_mutex_name(my_bucket->mutex));
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    if (ap_run_drop_privileges(pchild, ap_server_conf)) {
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_run_child_init(pchild, ap_server_conf);

    ap_create_sb_handle(&sbh, pchild, my_child_num, 0);

    ap_update_child_status(sbh, SERVER_READY, NULL);

    apr_skiplist_init(&mz->timeout_ring, mz->pool);
    apr_skiplist_set_compare(mz->timeout_ring, timer_comp, timer_comp);
    status = motorz_setup_workers(mz);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, ap_server_conf, APLOGNO(02868)
                     "child_main: motorz_setup_workers failed");
        clean_child_exit(APEXIT_CHILDSICK);
    }

    status = motorz_setup_pollset(mz);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, status, ap_server_conf, APLOGNO(02869)
                     "Couldn't setup pollset in child; check system or user limits");
        clean_child_exit(APEXIT_CHILDSICK); /* assume temporary resource issue */
    }

    for (lr = my_bucket->listeners, i = num_listensocks; i--; lr = lr->next) {
        apr_pollfd_t *pfd = apr_pcalloc(mz->pool, sizeof *pfd);
        motorz_sb_t *sb = apr_pcalloc(mz->pool, sizeof(motorz_sb_t));

        pfd->desc_type = APR_POLL_SOCKET;
        pfd->desc.s = lr->sd;
        pfd->reqevents = APR_POLLIN;
        pfd->p = mz->pool;
        pfd->client_data = sb;

        sb->type = PT_ACCEPT;
        sb->baton = lr;

        status = apr_socket_opt_set(pfd->desc.s, APR_SO_NONBLOCK, 1);
        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, status, NULL, APLOGNO(02870)
                         "apr_socket_opt_set(APR_SO_NONBLOCK = 1) failed on %pI",
                         lr->bind_addr);
            clean_child_exit(0);
        }

        status = apr_pollset_add(mz->pollset, pfd);
        if (status != APR_SUCCESS) {
            /* If the child processed a SIGWINCH before setting up the
             * pollset, this error path is expected and harmless,
             * since the listener fd was already closed; so don't
             * pollute the logs in that case. */
            if (!die_now) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, status, ap_server_conf, APLOGNO(02871)
                             "Couldn't add listener to pollset; check system or user limits");
                clean_child_exit(APEXIT_CHILDSICK);
            }
            clean_child_exit(0);
        }

        lr->accept_func = ap_unixd_accept;
    }

    mz->mpm->mpm_state = AP_MPMQ_RUNNING;

    /* die_now is set when AP_SIG_GRACEFUL is received in the child;
     * {shutdown,restart}_pending are set when a signal is received while
     * running in single process mode.
     */
    while (!die_now
           && !mz->mpm->shutdown_pending
           && !mz->mpm->restart_pending) {
        /*
         * (Re)initialize this child to a pre-connection state.
         */

        if ((ap_max_requests_per_child > 0
             && requests_this_child++ >= ap_max_requests_per_child)) {
            clean_child_exit(0);
        }

        ap_update_child_status(sbh, SERVER_READY, NULL);
        {
            apr_time_t tnow = apr_time_now();
            motorz_timer_t *te;
            apr_interval_time_t timeout = apr_time_from_msec(500);

            apr_thread_mutex_lock(mz->mtx);
            te = apr_skiplist_peek(mz->timeout_ring);

            if (te) {
                if (tnow < te->expires) {
                    timeout = (te->expires - tnow);
                    if (timeout > apr_time_from_msec(500)) {
                        timeout = apr_time_from_msec(500);
                    }
                }
                else {
                    timeout = 0;
                }
            }
            apr_thread_mutex_unlock(mz->mtx);

            status = motorz_pollset_cb(mz, timeout);

            tnow = apr_time_now();

            if (status != APR_SUCCESS) {
                if (!APR_STATUS_IS_EINTR(status) && !APR_STATUS_IS_TIMEUP(status)) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, status, NULL, APLOGNO(03117)
                                 "motorz_main_loop: apr_pollcb_poll failed");
                    clean_child_exit(0);
                }
            }

            apr_thread_mutex_lock(mz->mtx);

            /* now iterate any timers and push to worker pool */
            while (te && te->expires < tnow) {
                apr_skiplist_pop(mz->timeout_ring, NULL);
                motorz_timer_event_process(mz, te);
                te = apr_skiplist_peek(mz->timeout_ring);
            }

            apr_thread_mutex_unlock(mz->mtx);
        }
        if (ap_mpm_pod_check(my_bucket->pod) == APR_SUCCESS) { /* selected as idle? */
            die_now = 1;
        }
        else if (mz->mpm->my_generation !=
                 ap_scoreboard_image->global->running_generation) { /* restart? */
            /* yeah, this could be non-graceful restart, in which case the
             * parent will kill us soon enough, but why bother checking?
             */
            die_now = 1;
        }
    }

    clean_child_exit(0);
}

static int make_child(motorz_core_t *mz, server_rec *s, int slot, int bucket)
{
    int pid;

    if (slot + 1 > mz->max_daemons_limit) {
        mz->max_daemons_limit = slot + 1;
    }

    if (one_process) {
        my_bucket = &all_buckets[0];

        motorz_note_child_started(mz, slot, getpid());
        child_main(mz, slot, 0);
        /* NOTREACHED */
        ap_assert(0);
        return -1;
    }

    ap_update_child_status_from_indexes(slot, 0, SERVER_STARTING, NULL);

    if ((pid = fork()) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s, APLOGNO(02872) "fork: Unable to fork new process");

        /* fork didn't succeed. Fix the scoreboard or else
         * it will say SERVER_STARTING forever and ever
         */
        ap_update_child_status_from_indexes(slot, 0, SERVER_DEAD, NULL);

        /* In case system resources are maxxed out, we don't want
         * Apache running away with the CPU trying to fork over and
         * over and over again.
         */
        sleep(10);

        return -1;
    }

    if (!pid) {
        my_bucket = &all_buckets[bucket];

#ifdef HAVE_BINDPROCESSOR
        /* by default AIX binds to a single processor
         * this bit unbinds children which will then bind to another cpu
         */
        int status = bindprocessor(BINDPROCESS, (int)getpid(),
                                   PROCESSOR_CLASS_ANY);
        if (status != OK) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, errno,
                         ap_server_conf, APLOGNO(02873) "processor unbind failed");
        }
#endif
        RAISE_SIGSTOP(MAKE_CHILD);
        AP_MONCONTROL(1);
        /* Disable the parent's signal handlers and set up proper handling in
         * the child.
         */
        apr_signal(SIGHUP, just_die);
        apr_signal(SIGTERM, just_die);
        /* Ignore SIGINT in child. This fixes race-condition in signals
         * handling when httpd is runnning on foreground and user hits ctrl+c.
         * In this case, SIGINT is sent to all children followed by SIGTERM
         * from the main process, which interrupts the SIGINT handler and
         * leads to inconsistency.
         */
        apr_signal(SIGINT, SIG_IGN);
        /* The child process just closes listeners on AP_SIG_GRACEFUL.
         * The pod is used for signalling the graceful restart.
         */
        apr_signal(AP_SIG_GRACEFUL, stop_listening);
        child_main(mz, slot, bucket);
    }

    ap_scoreboard_image->parent[slot].bucket = bucket;
    motorz_note_child_started(mz, slot, pid);

    return 0;
}


/* start up a bunch of children */
static void startup_children(motorz_core_t *mz, int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < ap_num_kids; ++i) {
        if (ap_scoreboard_image->servers[i][0].status != SERVER_DEAD) {
            continue;
        }
        if (make_child(mz, ap_server_conf, i, i % mz->mpm->num_buckets) < 0) {
            break;
        }
        --number_to_start;
    }
}

static void perform_idle_server_maintenance(motorz_core_t *mz, apr_pool_t *p)
{
    static int bucket_make_child_record = -1;
    static int bucket_kill_child_record = -1;
    int free_length;
    int free_slots[1];

    int i;
    worker_score *ws;

    int active = 0;
    free_length = 0;
    free_slots[0] = 0;

    for (i = 0; i < ap_num_kids; ++i) {
        int status;
        ws = &ap_scoreboard_image->servers[i][0];
        status = ws->status;
        if (status == SERVER_DEAD && !free_length) {
            free_slots[free_length] = i;
            free_length++;
        }
        if (status >= SERVER_READY) {
            active++;
        }
    }
    if (active > ap_num_kids) {
        /* kill off one child... we use the pod because that'll cause it to
         * shut down gracefully, in case it happened to pick up a request
         * while we were counting
         */
        bucket_kill_child_record = (bucket_kill_child_record + 1) % mz->mpm->num_buckets;
        ap_mpm_pod_signal(all_buckets[bucket_kill_child_record].pod);
    }
    else if (active < ap_num_kids) {
        bucket_make_child_record++;
        bucket_make_child_record %= mz->mpm->num_buckets;
        make_child(mz, ap_server_conf, free_slots[0],
                   bucket_make_child_record);
    }
}

/*****************************************************************
 * Executive routines.
 */

static int motorz_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
{
    int index;
    int remaining_children_to_start;
    int i;
    motorz_core_t *mz = motorz_core_get();

    ap_log_pid(pconf, ap_pid_fname);

    if (!mz->mpm->was_graceful) {
        if (ap_run_pre_mpm(s->process->pool, SB_SHARED) != OK) {
            mz->mpm->mpm_state = AP_MPMQ_STOPPING;
            return !OK;
        }
        /* fix the generation number in the global score; we just got a new,
         * cleared scoreboard
         */
        ap_scoreboard_image->global->running_generation = mz->mpm->my_generation;
    }

    ap_unixd_mpm_set_signals(pconf, one_process);

    if (one_process) {
        AP_MONCONTROL(1);
        make_child(mz, ap_server_conf, 0, 0);
        /* NOTREACHED */
        ap_assert(0);
        return !OK;
    }

    /* Don't thrash since num_buckets depends on the
     * system and the number of online CPU cores...
     */
    if (ap_num_kids < mz->mpm->num_buckets)
        ap_num_kids = mz->mpm->num_buckets;

    /* If we're doing a graceful_restart then we're going to see a lot
     * of children exiting immediately when we get into the main loop
     * below (because we just sent them AP_SIG_GRACEFUL).  This happens pretty
     * rapidly... and for each one that exits we'll start a new one until
     * we reach at least daemons_min_free.  But we may be permitted to
     * start more than that, so we'll just keep track of how many we're
     * supposed to start up without the 1 second penalty between each fork.
     */
    remaining_children_to_start = ap_num_kids;
    if (!mz->mpm->was_graceful) {
        startup_children(mz, remaining_children_to_start);
        remaining_children_to_start = 0;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(02874)
                "%s configured -- resuming normal operations",
                ap_get_server_description());
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(02875)
                "Server built: %s", ap_get_server_built());
    ap_log_command_line(plog, s);
    ap_log_mpm_common(s);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(02876)
                "Accept mutex: %s (default: %s)",
                (all_buckets[0].mutex)
                    ? apr_proc_mutex_name(all_buckets[0].mutex)
                    : "none",
                apr_proc_mutex_defname());

    mz->mpm->mpm_state = AP_MPMQ_RUNNING;

    while (!mz->mpm->restart_pending && !mz->mpm->shutdown_pending) {
        int child_slot;
        apr_exit_why_e exitwhy;
        int status, processed_status;
        /* this is a memory leak, but I'll fix it later. */
        apr_proc_t pid;

        ap_wait_or_timeout(&exitwhy, &status, &pid, pconf, ap_server_conf);

        /* XXX: if it takes longer than 1 second for all our children
         * to start up and get into IDLE state then we may spawn an
         * extra child
         */
        if (pid.pid != -1) {
            processed_status = ap_process_child_status(&pid, exitwhy, status);
            child_slot = ap_find_child_by_pid(&pid);
            if (processed_status == APEXIT_CHILDFATAL) {
                /* fix race condition found in PR 39311
                 * A child created at the same time as a graceful happens
                 * can find the lock missing and create a fatal error.
                 * It is not fatal for the last generation to be in this state.
                 */
                if (child_slot < 0
                    || ap_get_scoreboard_process(child_slot)->generation
                       == mz->mpm->my_generation) {
                    mz->mpm->mpm_state = AP_MPMQ_STOPPING;
                    return !OK;
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, APLOGNO(02877)
                                 "Ignoring fatal error in child of previous "
                                 "generation (pid %ld).",
                                 (long)pid.pid);
                }
            }

            /* non-fatal death... note that it's gone in the scoreboard. */
            if (child_slot >= 0) {
                ap_update_child_status_from_indexes(child_slot, 0,
                                                    SERVER_DEAD, NULL);
                motorz_note_child_killed(child_slot, 0, 0);
                if (remaining_children_to_start
                    && child_slot < ap_num_kids) {
                    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
                    make_child(mz, ap_server_conf, child_slot,
                               ap_get_scoreboard_process(child_slot)->bucket);
                    --remaining_children_to_start;
                }
#if APR_HAS_OTHER_CHILD
            }
            else if (apr_proc_other_child_alert(&pid, APR_OC_REASON_DEATH, status) == APR_SUCCESS) {
                /* handled */
#endif
            }
            else if (mz->mpm->was_graceful) {
                /* Great, we've probably just lost a slot in the
                 * scoreboard.  Somehow we don't know about this
                 * child.
                 */
                ap_log_error(APLOG_MARK, APLOG_WARNING,
                            0, ap_server_conf, APLOGNO(02878)
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
            startup_children(mz, remaining_children_to_start);
            remaining_children_to_start = 0;
            /* In any event we really shouldn't do the code below because
             * few of the servers we just started are in the IDLE state
             * yet, so we'd mistakenly create an extra server.
             */
            continue;
        }

        perform_idle_server_maintenance(mz, pconf);
    }

    mz->mpm->mpm_state = AP_MPMQ_STOPPING;

    if (mz->mpm->shutdown_pending && mz->mpm->is_ungraceful) {
        /* Time to shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        if (ap_unixd_killpg(getpgrp(), SIGTERM) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(02879) "killpg SIGTERM");
        }
        ap_reclaim_child_processes(1, /* Start with SIGTERM */
                                   motorz_note_child_killed);

        /* cleanup pid file on normal shutdown */
        ap_remove_pid(pconf, ap_pid_fname);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(02880)
                    "caught SIGTERM, shutting down");

        return DONE;
    }

    if (mz->mpm->shutdown_pending) {
        /* Time to perform a graceful shut down:
         * Reap the inactive children, and ask the active ones
         * to close their listeners, then wait until they are
         * all done to exit.
         */
        int active_children;
        apr_time_t cutoff = 0;

        /* Stop listening */
        ap_close_listeners();

        /* kill off the idle ones */
        for (i = 0; i < mz->mpm->num_buckets; i++) {
            ap_mpm_pod_killpg(all_buckets[i].pod, mz->max_daemons_limit);
        }

        /* Send SIGUSR1 to the active children */
        active_children = 0;
        for (index = 0; index < ap_num_kids; ++index) {
            if (ap_scoreboard_image->servers[index][0].status != SERVER_DEAD) {
                /* Ask each child to close its listeners. */
                ap_mpm_safe_kill(MPM_CHILD_PID(index), AP_SIG_GRACEFUL);
                active_children++;
            }
        }

        /* Allow each child which actually finished to exit */
        ap_relieve_child_processes(motorz_note_child_killed);

        /* cleanup pid file */
        ap_remove_pid(pconf, ap_pid_fname);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(02881)
           "caught " AP_SIG_GRACEFUL_STOP_STRING ", shutting down gracefully");

        if (ap_graceful_shutdown_timeout) {
            cutoff = apr_time_now() +
                     apr_time_from_sec(ap_graceful_shutdown_timeout);
        }

        /* Don't really exit until each child has finished */
        mz->mpm->shutdown_pending = 0;
        do {
            /* Pause for a second */
            sleep(1);

            /* Relieve any children which have now exited */
            ap_relieve_child_processes(motorz_note_child_killed);

            active_children = 0;
            for (index = 0; index < ap_num_kids; ++index) {
                if (ap_mpm_safe_kill(MPM_CHILD_PID(index), 0) == APR_SUCCESS) {
                    active_children = 1;
                    /* Having just one child is enough to stay around */
                    break;
                }
            }
        } while (!mz->mpm->shutdown_pending && active_children &&
                 (!ap_graceful_shutdown_timeout || apr_time_now() < cutoff));

        /* We might be here because we received SIGTERM, either
         * way, try and make sure that all of our processes are
         * really dead.
         */
        ap_unixd_killpg(getpgrp(), SIGTERM);

        return DONE;
    }

    /* we've been told to restart */
    if (one_process) {
        /* not worth thinking about */
        return DONE;
    }

    /* advance to the next generation */
    /* XXX: we really need to make sure this new generation number isn't in
     * use by any of the children.
     */
    ++mz->mpm->my_generation;
    ap_scoreboard_image->global->running_generation = mz->mpm->my_generation;

    if (!mz->mpm->is_ungraceful) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(02882)
                    "Graceful restart requested, doing restart");

        /* kill off the idle ones */
        for (i = 0; i < mz->mpm->num_buckets; i++) {
            ap_mpm_pod_killpg(all_buckets[i].pod, mz->max_daemons_limit);
        }

        /* This is mostly for debugging... so that we know what is still
         * gracefully dealing with existing request.  This will break
         * in a very nasty way if we ever have the scoreboard totally
         * file-based (no shared memory)
         */
        for (index = 0; index < ap_num_kids; ++index) {
            if (ap_scoreboard_image->servers[index][0].status != SERVER_DEAD) {
                ap_scoreboard_image->servers[index][0].status = SERVER_GRACEFUL;
                /* Ask each child to close its listeners.
                 *
                 * NOTE: we use the scoreboard, because if we send SIGUSR1
                 * to every process in the group, this may include CGI's,
                 * piped loggers, etc. They almost certainly won't handle
                 * it gracefully.
                 */
                ap_mpm_safe_kill(ap_scoreboard_image->parent[index].pid, AP_SIG_GRACEFUL);
            }
        }
    }
    else {
        /* Kill 'em off */
        if (ap_unixd_killpg(getpgrp(), SIGHUP) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(02883) "killpg SIGHUP");
        }
        ap_reclaim_child_processes(0, /* Not when just starting up */
                                   motorz_note_child_killed);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(02884)
                    "SIGHUP received.  Attempting to restart");
    }

    return OK;
}

/* This really should be a post_config hook, but the error log is already
 * redirected by that point, so we need to do this in the open_logs phase.
 */
static int motorz_open_logs(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    int startup = 0;
    int level_flags = 0;
    ap_listen_rec **listen_buckets;
    apr_status_t rv;
    char id[16];
    int i;

    motorz_core_t *mz = motorz_core_get();
    pconf = p;

    /* the reverse of pre_config, we want this only the first time around */
    if (mz->mpm->module_loads == 1) {
        startup = 1;
        level_flags |= APLOG_STARTUP;
    }

    if ((num_listensocks = ap_setup_listeners(ap_server_conf)) < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT | level_flags, 0,
                     (startup ? NULL : s), APLOGNO(03275)
                     "no listening sockets available, shutting down");
        return !OK;
    }

    if (one_process) {
        mz->mpm->num_buckets = 1;
    }
    else if (!mz->mpm->was_graceful) {
        /* Preserve the number of buckets on graceful restarts. */
        mz->mpm->num_buckets = 0;
    }
    if ((rv = ap_duplicate_listeners(pconf, ap_server_conf,
                                     &listen_buckets, &mz->mpm->num_buckets))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT | level_flags, rv,
                     (startup ? NULL : s), APLOGNO(03276)
                     "could not duplicate listeners");
        return !OK;
    }
    all_buckets = apr_pcalloc(pconf, mz->mpm->num_buckets *
                                     sizeof(motorz_child_bucket));
    for (i = 0; i < mz->mpm->num_buckets; i++) {
        if ((rv = ap_mpm_pod_open(pconf, &all_buckets[i].pod))) {
            ap_log_error(APLOG_MARK, APLOG_CRIT | level_flags, rv,
                         (startup ? NULL : s), APLOGNO(03277)
                         "could not open pipe-of-death");
            return !OK;
        }
        /* Initialize cross-process accept lock (safe accept needed only) */
        if ((rv = SAFE_ACCEPT((apr_snprintf(id, sizeof id, "%i", i),
                               ap_proc_mutex_create(&all_buckets[i].mutex,
                                                    NULL, AP_ACCEPT_MUTEX_TYPE,
                                                    id, s, pconf, 0))))) {
            ap_log_error(APLOG_MARK, APLOG_CRIT | level_flags, rv,
                         (startup ? NULL : s), APLOGNO(03278)
                         "could not create accept mutex");
            return !OK;
        }
        all_buckets[i].listeners = listen_buckets[i];
    }

    return OK;
}

static int motorz_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    int no_detach, debug, foreground;
    apr_status_t rv;
    const char *userdata_key = "mpm_motorz_module";
    motorz_core_t *mz;

    debug = ap_exists_config_define("DEBUG");

    if (debug) {
        foreground = one_process = 1;
        no_detach = 0;
    }
    else
    {
        no_detach = ap_exists_config_define("NO_DETACH");
        one_process = ap_exists_config_define("ONE_PROCESS");
        foreground = ap_exists_config_define("FOREGROUND");
    }

    ap_mutex_register(p, AP_ACCEPT_MUTEX_TYPE, NULL, APR_LOCK_DEFAULT, 0);

    mz = g_motorz_core = ap_retained_data_get(userdata_key);
    if (!g_motorz_core) {
        mz = g_motorz_core = ap_retained_data_create(userdata_key, sizeof(*g_motorz_core));
        mz->mpm = ap_unixd_mpm_get_retained_data();
        mz->max_daemons_limit = -1;
        mz->timeout_ring = motorz_timer_ring;
        mz->pollset = motorz_pollset;
    }
    mz->mpm->mpm_state = AP_MPMQ_STARTING;
    if (mz->mpm->baton != mz) {
        mz->mpm->was_graceful = 0;
        mz->mpm->baton = mz;
    }
    ++mz->mpm->module_loads;

    /* sigh, want this only the second time around */
    if (mz->mpm->module_loads == 2) {
        if (!one_process && !foreground) {
            /* before we detach, setup crash handlers to log to errorlog */
            ap_fatal_signal_setup(ap_server_conf, pconf);
            rv = apr_proc_detach(no_detach ? APR_PROC_DETACH_FOREGROUND
                                           : APR_PROC_DETACH_DAEMONIZE);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(02885)
                             "apr_proc_detach failed");
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
        apr_pool_create(&mz->pool, ap_pglobal);
        apr_pool_tag(mz->pool, "motorz-mpm-core");
        rv = apr_thread_mutex_create(&mz->mtx, 0, mz->pool);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(02966)
                         "motorz_pre_config: apr_thread_mutex_create failed");
            return rv;
        }
    }

    parent_pid = ap_my_pid = getpid();

    ap_listen_pre_config();
    ap_num_kids = DEFAULT_START_DAEMON;
    ap_extended_status = 0;

    return OK;
}

static int motorz_check_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    int startup = 0;
    motorz_core_t *mz = motorz_core_get();

    /* the reverse of pre_config, we want this only the first time around */
    if (mz->mpm->module_loads == 1) {
        startup = 1;
    }

    if (ap_num_kids > DEFAULT_SERVER_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(02886)
                         "WARNING: StartServers of %d exceeds compile-time "
                         "limit of %d servers, decreasing to %d.",
                         ap_num_kids, DEFAULT_SERVER_LIMIT, DEFAULT_SERVER_LIMIT);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(02887)
                         "StartServers of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         ap_num_kids, DEFAULT_SERVER_LIMIT);
        }
        ap_num_kids = DEFAULT_SERVER_LIMIT;
    }
    else if (ap_num_kids < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(02888)
                         "WARNING: StartServers of %d not allowed, "
                         "increasing to 1.", ap_num_kids);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(02889)
                         "StartServers of %d not allowed, increasing to 1",
                         ap_num_kids);
        }
        ap_num_kids = 1;
    }

    if (thread_limit > MAX_THREAD_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(10015)
                         "WARNING: ThreadLimit of %d exceeds compile-time "
                         "limit of %d threads, decreasing to %d.",
                         thread_limit, MAX_THREAD_LIMIT, MAX_THREAD_LIMIT);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10016)
                         "ThreadLimit of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         thread_limit, MAX_THREAD_LIMIT);
        }
        thread_limit = MAX_THREAD_LIMIT;
    }
    else if (thread_limit < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(10017)
                         "WARNING: ThreadLimit of %d not allowed, "
                         "increasing to 1.", thread_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10018)
                         "ThreadLimit of %d not allowed, increasing to 1",
                         thread_limit);
        }
        thread_limit = 1;
    }

    if (threads_per_child > thread_limit) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(03336)
                         "WARNING: ThreadsPerChild of %d exceeds run-time "
                         "limit of", threads_per_child);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(03337)
                         " %d servers, decreasing to %d.",
                         thread_limit, thread_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(03338)
                         "ThreadsPerChild of %d exceeds run-time limit "
                         "of %d, decreasing to match",
                         threads_per_child, thread_limit);
        }
        threads_per_child = thread_limit;
    }
    else if (threads_per_child < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(03339)
                         "WARNING: ThreadsPerChild of %d not allowed, "
                         "increasing to 1.", threads_per_child);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(03340)
                         "ThreadsPerChild of %d not allowed, increasing to 1",
                         threads_per_child);
        }
        threads_per_child = 1;
    }

    return OK;
}

static void motorz_hooks(apr_pool_t *p)
{
    /* Our open_logs hook function must run before the core's, or stderr
     * will be redirected to a file, and the messages won't print to the
     * console.
     */
    static const char *const aszSucc[] = {"core.c", NULL};
    ap_force_set_tz(p);

    ap_hook_open_logs(motorz_open_logs, NULL, aszSucc, APR_HOOK_REALLY_FIRST);
    /* we need to set the MPM state before other pre-config hooks use MPM query
     * to retrieve it, so register as REALLY_FIRST
     */
    ap_hook_pre_config(motorz_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_check_config(motorz_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm(motorz_run, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_query(motorz_query, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_get_name(motorz_get_name, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *set_daemons_to_start(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    ap_num_kids = atoi(arg);
    return NULL;
}

static const char *set_threads_per_child(cmd_parms * cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    threads_per_child = atoi(arg);
    return NULL;
}

static const char *set_thread_limit (cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    thread_limit = atoi(arg);
    return NULL;
}

static const command_rec motorz_cmds[] = {
LISTEN_COMMANDS,
AP_INIT_TAKE1("StartServers", set_daemons_to_start, NULL, RSRC_CONF,
              "Number of child processes launched at server startup"),
AP_INIT_TAKE1("ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF,
              "Number of threads each child creates"),
AP_INIT_TAKE1("ThreadLimit", set_thread_limit, NULL, RSRC_CONF,
  "Maximum number of worker threads per child process for this run of Apache - Upper limit for ThreadsPerChild"),
AP_GRACEFUL_SHUTDOWN_TIMEOUT_COMMAND,
{ NULL }
};

AP_DECLARE_MODULE(mpm_motorz) = {
    MPM20_MODULE_STUFF,
    NULL,                       /* hook to run before apache parses args */
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    motorz_cmds,               /* command apr_table_t */
    motorz_hooks,              /* register hooks */
};
