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
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "http_config.h"
#include "ap_mpm.h"

#include "scoreboard.h"

AP_DECLARE_DATA scoreboard *ap_scoreboard_image = NULL;
AP_DECLARE_DATA const char *ap_scoreboard_fname = NULL;
AP_DECLARE_DATA int ap_extended_status = 0;
AP_DECLARE_DATA int ap_mod_status_reqtail = 0;

#if APR_HAS_SHARED_MEMORY

#include "apr_shm.h"

#ifndef WIN32
static /* but must be exported to mpm_winnt */
#endif
        apr_shm_t *ap_scoreboard_shm = NULL;

#endif

APR_HOOK_STRUCT(
    APR_HOOK_LINK(pre_mpm)
)

AP_IMPLEMENT_HOOK_RUN_ALL(int,pre_mpm,
                          (apr_pool_t *p, ap_scoreboard_e sb_type),
                          (p, sb_type),OK,DECLINED)

static APR_OPTIONAL_FN_TYPE(ap_proxy_lb_workers)
                                *pfn_proxy_lb_workers;
static APR_OPTIONAL_FN_TYPE(ap_proxy_lb_worker_size)
                                *pfn_proxy_lb_worker_size;
static APR_OPTIONAL_FN_TYPE(ap_logio_get_last_bytes)
                                *pfn_ap_logio_get_last_bytes;

struct ap_sb_handle_t {
    int child_num;
    int thread_num;
};

static int server_limit, thread_limit, lb_limit, lb_size;
static apr_size_t scoreboard_size;

/*
 * ToDo:
 * This function should be renamed to cleanup_shared
 * and it should handle cleaning up a scoreboard shared
 * between processes using any form of IPC (file, shared memory
 * segment, etc.). Leave it as is now because it is being used
 * by various MPMs.
 */
static apr_status_t ap_cleanup_shared_mem(void *d)
{
#if APR_HAS_SHARED_MEMORY
    free(ap_scoreboard_image);
    ap_scoreboard_image = NULL;
    apr_shm_destroy(ap_scoreboard_shm);
#endif
    return APR_SUCCESS;
}

AP_DECLARE(int) ap_calc_scoreboard_size(void)
{
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

    if (!pfn_proxy_lb_workers)
        pfn_proxy_lb_workers = APR_RETRIEVE_OPTIONAL_FN(ap_proxy_lb_workers);
    if (pfn_proxy_lb_workers)
        lb_limit = pfn_proxy_lb_workers();
    else
        lb_limit = 0;

    if (!pfn_proxy_lb_worker_size)
        pfn_proxy_lb_worker_size = APR_RETRIEVE_OPTIONAL_FN(ap_proxy_lb_worker_size);
    if (pfn_proxy_lb_worker_size)
        lb_size = pfn_proxy_lb_worker_size();
    else
        lb_size = sizeof(lb_score);

    scoreboard_size = sizeof(global_score);
    scoreboard_size += sizeof(process_score) * server_limit;
    scoreboard_size += sizeof(worker_score) * server_limit * thread_limit;
    if (lb_limit && lb_size)
        scoreboard_size += lb_size * lb_limit;

    pfn_ap_logio_get_last_bytes = APR_RETRIEVE_OPTIONAL_FN(ap_logio_get_last_bytes);

    return scoreboard_size;
}

void ap_init_scoreboard(void *shared_score)
{
    char *more_storage;
    int i;

    ap_calc_scoreboard_size();
    ap_scoreboard_image =
        calloc(1, sizeof(scoreboard) + server_limit * sizeof(worker_score *));
    more_storage = shared_score;
    ap_scoreboard_image->global = (global_score *)more_storage;
    more_storage += sizeof(global_score);
    ap_scoreboard_image->parent = (process_score *)more_storage;
    more_storage += sizeof(process_score) * server_limit;
    ap_scoreboard_image->servers =
        (worker_score **)((char*)ap_scoreboard_image + sizeof(scoreboard));
    for (i = 0; i < server_limit; i++) {
        ap_scoreboard_image->servers[i] = (worker_score *)more_storage;
        more_storage += thread_limit * sizeof(worker_score);
    }
    if (lb_limit && lb_size) {
        ap_scoreboard_image->balancers = (void *)more_storage;
        more_storage += lb_limit * lb_size;
    }
    ap_assert(more_storage == (char*)shared_score + scoreboard_size);
    ap_scoreboard_image->global->server_limit = server_limit;
    ap_scoreboard_image->global->thread_limit = thread_limit;
    ap_scoreboard_image->global->lb_limit     = lb_limit;
}

/**
 * Create a name-based scoreboard in the given pool using the
 * given filename.
 */
static apr_status_t create_namebased_scoreboard(apr_pool_t *pool,
                                                const char *fname)
{
#if APR_HAS_SHARED_MEMORY
    apr_status_t rv;

    /* The shared memory file must not exist before we create the
     * segment. */
    apr_shm_remove(fname, pool); /* ignore errors */

    rv = apr_shm_create(&ap_scoreboard_shm, scoreboard_size, fname, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "unable to create or access scoreboard \"%s\" "
                     "(name-based shared memory failure)", fname);
        return rv;
    }
#endif /* APR_HAS_SHARED_MEMORY */
    return APR_SUCCESS;
}

/* ToDo: This function should be made to handle setting up
 * a scoreboard shared between processes using any IPC technique,
 * not just a shared memory segment
 */
static apr_status_t open_scoreboard(apr_pool_t *pconf)
{
#if APR_HAS_SHARED_MEMORY
    apr_status_t rv;
    char *fname = NULL;
    apr_pool_t *global_pool;

    /* We don't want to have to recreate the scoreboard after
     * restarts, so we'll create a global pool and never clean it.
     */
    rv = apr_pool_create(&global_pool, NULL);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Fatal error: unable to create global pool "
                     "for use by the scoreboard");
        return rv;
    }

    /* The config says to create a name-based shmem */
    if (ap_scoreboard_fname) {
        /* make sure it's an absolute pathname */
        fname = ap_server_root_relative(pconf, ap_scoreboard_fname);
        if (!fname) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, APR_EBADPATH, NULL,
                         "Fatal error: Invalid Scoreboard path %s",
                         ap_scoreboard_fname);
            return APR_EBADPATH;
        }
        return create_namebased_scoreboard(global_pool, fname);
    }
    else { /* config didn't specify, we get to choose shmem type */
        rv = apr_shm_create(&ap_scoreboard_shm, scoreboard_size, NULL,
                            global_pool); /* anonymous shared memory */
        if ((rv != APR_SUCCESS) && (rv != APR_ENOTIMPL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                         "Unable to create or access scoreboard "
                         "(anonymous shared memory failure)");
            return rv;
        }
        /* Make up a filename and do name-based shmem */
        else if (rv == APR_ENOTIMPL) {
            /* Make sure it's an absolute pathname */
            ap_scoreboard_fname = DEFAULT_SCOREBOARD;
            fname = ap_server_root_relative(pconf, ap_scoreboard_fname);

            return create_namebased_scoreboard(global_pool, fname);
        }
    }
#endif /* APR_HAS_SHARED_MEMORY */
    return APR_SUCCESS;
}

/* If detach is non-zero, this is a seperate child process,
 * if zero, it is a forked child.
 */
apr_status_t ap_reopen_scoreboard(apr_pool_t *p, apr_shm_t **shm, int detached)
{
#if APR_HAS_SHARED_MEMORY
    if (!detached) {
        return APR_SUCCESS;
    }
    if (apr_shm_size_get(ap_scoreboard_shm) < scoreboard_size) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL,
                     "Fatal error: shared scoreboard too small for child!");
        apr_shm_detach(ap_scoreboard_shm);
        ap_scoreboard_shm = NULL;
        return APR_EINVAL;
    }
    /* everything will be cleared shortly */
    if (*shm) {
        *shm = ap_scoreboard_shm;
    }
#endif
    return APR_SUCCESS;
}

apr_status_t ap_cleanup_scoreboard(void *d)
{
    if (ap_scoreboard_image == NULL) {
        return APR_SUCCESS;
    }
    if (ap_scoreboard_image->global->sb_type == SB_SHARED) {
        ap_cleanup_shared_mem(NULL);
    }
    else {
        free(ap_scoreboard_image->global);
        free(ap_scoreboard_image);
        ap_scoreboard_image = NULL;
    }
    return APR_SUCCESS;
}

/* Create or reinit an existing scoreboard. The MPM can control whether
 * the scoreboard is shared across multiple processes or not
 */
int ap_create_scoreboard(apr_pool_t *p, ap_scoreboard_e sb_type)
{
    int running_gen = 0;
    int i;
#if APR_HAS_SHARED_MEMORY
    apr_status_t rv;
#endif

    if (ap_scoreboard_image) {
        running_gen = ap_scoreboard_image->global->running_generation;
        ap_scoreboard_image->global->restart_time = apr_time_now();
        memset(ap_scoreboard_image->parent, 0,
               sizeof(process_score) * server_limit);
        for (i = 0; i < server_limit; i++) {
            memset(ap_scoreboard_image->servers[i], 0,
                   sizeof(worker_score) * thread_limit);
        }
        /* Clean up the lb workers data */
        if (lb_limit && lb_size) {
            memset(ap_scoreboard_image->balancers, 0,
                   lb_size * lb_limit);
        }
        return OK;
    }

    ap_calc_scoreboard_size();
#if APR_HAS_SHARED_MEMORY
    if (sb_type == SB_SHARED) {
        void *sb_shared;
        rv = open_scoreboard(p);
        if (rv || !(sb_shared = apr_shm_baseaddr_get(ap_scoreboard_shm))) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        memset(sb_shared, 0, scoreboard_size);
        ap_init_scoreboard(sb_shared);
    }
    else
#endif
    {
        /* A simple malloc will suffice */
        void *sb_mem = calloc(1, scoreboard_size);
        if (sb_mem == NULL) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL,
                         "(%d)%s: cannot allocate scoreboard",
                         errno, strerror(errno));
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_init_scoreboard(sb_mem);
    }

    ap_scoreboard_image->global->sb_type = sb_type;
    ap_scoreboard_image->global->running_generation = running_gen;
    ap_scoreboard_image->global->restart_time = apr_time_now();

    apr_pool_cleanup_register(p, NULL, ap_cleanup_scoreboard, apr_pool_cleanup_null);

    return OK;
}

/* Routines called to deal with the scoreboard image
 * --- note that we do *not* need write locks, since update_child_status
 * only updates a *single* record in place, and only one process writes to
 * a given scoreboard slot at a time (either the child process owning that
 * slot, or the parent, noting that the child has died).
 *
 * As a final note --- setting the score entry to getpid() is always safe,
 * since when the parent is writing an entry, it's only noting SERVER_DEAD
 * anyway.
 */

AP_DECLARE(int) ap_exists_scoreboard_image(void)
{
    return (ap_scoreboard_image ? 1 : 0);
}

AP_DECLARE(void) ap_increment_counts(ap_sb_handle_t *sb, request_rec *r)
{
    worker_score *ws;
    apr_off_t bytes;

    if (!sb)
        return;

    ws = &ap_scoreboard_image->servers[sb->child_num][sb->thread_num];
    if (pfn_ap_logio_get_last_bytes != NULL) {
        bytes = pfn_ap_logio_get_last_bytes(r->connection);
    }
    else if (r->method_number == M_GET && r->method[0] == 'H') {
        bytes = 0;
    }
    else {
        bytes = r->bytes_sent;
    }

#ifdef HAVE_TIMES
    times(&ws->times);
#endif
    ws->access_count++;
    ws->my_access_count++;
    ws->conn_count++;
    ws->bytes_served += bytes;
    ws->my_bytes_served += bytes;
    ws->conn_bytes += bytes;
}

AP_DECLARE(int) ap_find_child_by_pid(apr_proc_t *pid)
{
    int i;
    int max_daemons_limit;

    ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_daemons_limit);

    for (i = 0; i < max_daemons_limit; ++i) {
        if (ap_scoreboard_image->parent[i].pid == pid->pid) {
            return i;
        }
    }

    return -1;
}

AP_DECLARE(void) ap_create_sb_handle(ap_sb_handle_t **new_sbh, apr_pool_t *p,
                                     int child_num, int thread_num)
{
    *new_sbh = (ap_sb_handle_t *)apr_palloc(p, sizeof(ap_sb_handle_t));
    (*new_sbh)->child_num = child_num;
    (*new_sbh)->thread_num = thread_num;
}

static void copy_request(char *rbuf, apr_size_t rbuflen, request_rec *r)
{
    char *p;

    if (r->the_request == NULL) {
        apr_cpystrn(rbuf, "NULL", rbuflen);
        return; /* short circuit below */
    }

    if (r->parsed_uri.password == NULL) {
        p = r->the_request;
    }
    else {
        /* Don't reveal the password in the server-status view */
        p = apr_pstrcat(r->pool, r->method, " ",
                        apr_uri_unparse(r->pool, &r->parsed_uri,
                        APR_URI_UNP_OMITPASSWORD),
                        r->assbackwards ? NULL : " ", r->protocol, NULL);
    }

    /* now figure out if we copy over the 1st rbuflen chars or the last */
    if (!ap_mod_status_reqtail) {
        apr_cpystrn(rbuf, p, rbuflen);
    }
    else {
        apr_size_t slen = strlen(p);
        if (slen < rbuflen) {
            /* it all fits anyway */
            apr_cpystrn(rbuf, p, rbuflen);
        }
        else {
            apr_cpystrn(rbuf, p+(slen-rbuflen+1), rbuflen);
        }
    }
}

static int update_child_status_internal(int child_num,
                                        int thread_num,
                                        int status,
                                        conn_rec *c,
                                        request_rec *r)
{
    int old_status;
    worker_score *ws;
    process_score *ps;
    int mpm_generation;

    ws = &ap_scoreboard_image->servers[child_num][thread_num];
    old_status = ws->status;
    ws->status = status;

    ps = &ap_scoreboard_image->parent[child_num];

    if (status == SERVER_READY
        && old_status == SERVER_STARTING) {
        ws->thread_num = child_num * thread_limit + thread_num;
        ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);
        ps->generation = mpm_generation;
    }

    if (ap_extended_status) {
        ws->last_used = apr_time_now();
        if (status == SERVER_READY || status == SERVER_DEAD) {
            /*
             * Reset individual counters
             */
            if (status == SERVER_DEAD) {
                ws->my_access_count = 0L;
                ws->my_bytes_served = 0L;
            }
            ws->conn_count = 0;
            ws->conn_bytes = 0;
        }
        if (r) {
            apr_cpystrn(ws->client, ap_get_remote_host(c, r->per_dir_config,
                        REMOTE_NOLOOKUP, NULL), sizeof(ws->client));
            copy_request(ws->request, sizeof(ws->request), r);
            if (r->server) {
            	apr_cpystrn(ws->vhost, r->server->server_hostname,
                            sizeof(ws->vhost));
            }
        }
        else if (c) {
            apr_cpystrn(ws->client, ap_get_remote_host(c, NULL,
                        REMOTE_NOLOOKUP, NULL), sizeof(ws->client));
        }
    }

    return old_status;
}

AP_DECLARE(int) ap_update_child_status_from_indexes(int child_num,
                                                    int thread_num,
                                                    int status,
                                                    request_rec *r)
{
    if (child_num < 0) {
        return -1;
    }

    return update_child_status_internal(child_num, thread_num, status,
                                        r ? r->connection : NULL,
                                        r);
}

AP_DECLARE(int) ap_update_child_status(ap_sb_handle_t *sbh, int status,
                                      request_rec *r)
{
    if (!sbh)
        return -1;

    return update_child_status_internal(sbh->child_num, sbh->thread_num,
                                        status,
                                        r ? r->connection : NULL,
                                        r);
}

AP_DECLARE(int) ap_update_child_status_from_conn(ap_sb_handle_t *sbh, int status,
                                       conn_rec *c)
{
    if (!sbh)
        return -1;
    
    return update_child_status_internal(sbh->child_num, sbh->thread_num,
                                        status, c, NULL);
}

AP_DECLARE(void) ap_time_process_request(ap_sb_handle_t *sbh, int status)
{
    worker_score *ws;

    if (!sbh)
        return;

    if (sbh->child_num < 0) {
        return;
    }

    ws = &ap_scoreboard_image->servers[sbh->child_num][sbh->thread_num];

    if (status == START_PREQUEST) {
        ws->start_time = apr_time_now();
    }
    else if (status == STOP_PREQUEST) {
        ws->stop_time = apr_time_now();
    }
}

AP_DECLARE(worker_score *) ap_get_scoreboard_worker_from_indexes(int x, int y)
{
    if (((x < 0) || (x >= server_limit)) ||
        ((y < 0) || (y >= thread_limit))) {
        return(NULL); /* Out of range */
    }
    return &ap_scoreboard_image->servers[x][y];
}

AP_DECLARE(worker_score *) ap_get_scoreboard_worker(ap_sb_handle_t *sbh)
{
    if (!sbh)
        return NULL;

    return ap_get_scoreboard_worker_from_indexes(sbh->child_num,
                                                 sbh->thread_num);
}

AP_DECLARE(process_score *) ap_get_scoreboard_process(int x)
{
    if ((x < 0) || (x >= server_limit)) {
        return(NULL); /* Out of range */
    }
    return &ap_scoreboard_image->parent[x];
}

AP_DECLARE(global_score *) ap_get_scoreboard_global()
{
    return ap_scoreboard_image->global;
}

AP_DECLARE(lb_score *) ap_get_scoreboard_lb(int lb_num)
{
    if ( (lb_num < 0) || (lb_limit < lb_num) || (lb_size==0) ) {
        return(NULL); /* Out of range */
    }
    return (lb_score *) ( ((char *) ap_scoreboard_image->balancers) +
                          (lb_num*lb_size) );
}
