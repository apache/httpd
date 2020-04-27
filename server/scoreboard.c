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
#include "apr_atomic.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <time.h>

#include "ap_config.h"
#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_mpm.h"

#include "scoreboard.h"

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

#ifdef HAVE_TIMES
/* ugh... need to know if we're running with a pthread implementation
 * such as linuxthreads that treats individual threads as distinct
 * processes; that affects how we add up CPU time in a process
 */
static pid_t child_pid;
#endif

AP_DECLARE_DATA scoreboard *ap_scoreboard_image = NULL;
AP_DECLARE_DATA const char *ap_scoreboard_fname = NULL;
static ap_scoreboard_e scoreboard_type;

const char * ap_set_scoreboard(cmd_parms *cmd, void *dummy,
                               const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_scoreboard_fname = arg;
    return NULL;
}

/* Default to false when mod_status is not loaded */
AP_DECLARE_DATA int ap_extended_status = 0;

const char *ap_set_extended_status(cmd_parms *cmd, void *dummy, int arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    ap_extended_status = arg;
    return NULL;
}

AP_DECLARE_DATA int ap_mod_status_reqtail = 0;

const char *ap_set_reqtail(cmd_parms *cmd, void *dummy, int arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    ap_mod_status_reqtail = arg;
    return NULL;
}

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

static APR_OPTIONAL_FN_TYPE(ap_logio_get_last_bytes)
                                *pfn_ap_logio_get_last_bytes;

struct ap_sb_handle_t {
    int child_num;
    int thread_num;
};

static int server_limit, thread_limit;
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

#define SIZE_OF_scoreboard    APR_ALIGN_DEFAULT(sizeof(scoreboard))
#define SIZE_OF_global_score  APR_ALIGN_DEFAULT(sizeof(global_score))
#define SIZE_OF_process_score APR_ALIGN_DEFAULT(sizeof(process_score))
#define SIZE_OF_worker_score  APR_ALIGN_DEFAULT(sizeof(worker_score))

AP_DECLARE(int) ap_calc_scoreboard_size(void)
{
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

    scoreboard_size  = SIZE_OF_global_score;
    scoreboard_size += SIZE_OF_process_score * server_limit;
    scoreboard_size += SIZE_OF_worker_score * server_limit * thread_limit;

    return scoreboard_size;
}

AP_DECLARE(void) ap_init_scoreboard(void *shared_score)
{
    char *more_storage;
    int i;

    pfn_ap_logio_get_last_bytes = APR_RETRIEVE_OPTIONAL_FN(ap_logio_get_last_bytes);
    if (!shared_score) {
        return;
    }
    
    ap_calc_scoreboard_size();
    ap_scoreboard_image =
        ap_calloc(1, SIZE_OF_scoreboard + server_limit * sizeof(worker_score *));
    more_storage = shared_score;
    ap_scoreboard_image->global = (global_score *)more_storage;
    more_storage += SIZE_OF_global_score;
    ap_scoreboard_image->parent = (process_score *)more_storage;
    more_storage += SIZE_OF_process_score * server_limit;
    ap_scoreboard_image->servers =
        (worker_score **)((char*)ap_scoreboard_image + SIZE_OF_scoreboard);
    for (i = 0; i < server_limit; i++) {
        ap_scoreboard_image->servers[i] = (worker_score *)more_storage;
        more_storage += thread_limit * SIZE_OF_worker_score;
    }
    ap_assert(more_storage == (char*)shared_score + scoreboard_size);
    ap_scoreboard_image->global->server_limit = server_limit;
    ap_scoreboard_image->global->thread_limit = thread_limit;
    ap_scoreboard_image->global->sload0.access_count = -1;
    ap_scoreboard_image->global->sload1.access_count = -1;
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
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00001)
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
    apr_pool_t *global_pool = apr_pool_parent_get(pconf);

    /* If this is not passed pconf, or pconf is no longer a direct
     * child of a global pool, this should change... */
    AP_DEBUG_ASSERT(apr_pool_parent_get(global_pool) == NULL);
    
    /* The config says to create a name-based shmem */
    if (ap_scoreboard_fname) {
        /* make sure it's an absolute pathname */
        fname = ap_runtime_dir_relative(pconf, ap_scoreboard_fname);
        if (!fname) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, APR_EBADPATH, ap_server_conf, APLOGNO(00003)
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
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00004)
                         "Unable to create or access scoreboard "
                         "(anonymous shared memory failure)");
            return rv;
        }
        /* Make up a filename and do name-based shmem */
        else if (rv == APR_ENOTIMPL) {
            /* Make sure it's an absolute pathname */
            ap_scoreboard_fname = DEFAULT_SCOREBOARD;
            fname = ap_runtime_dir_relative(pconf, ap_scoreboard_fname);

            return create_namebased_scoreboard(global_pool, fname);
        }
    }
#endif /* APR_HAS_SHARED_MEMORY */
    return APR_SUCCESS;
}

/* If detach is non-zero, this is a separate child process,
 * if zero, it is a forked child.
 */
AP_DECLARE(apr_status_t) ap_reopen_scoreboard(apr_pool_t *p, apr_shm_t **shm,
                                              int detached)
{
#if APR_HAS_SHARED_MEMORY
    if (!detached) {
        return APR_SUCCESS;
    }
    if (apr_shm_size_get(ap_scoreboard_shm) < scoreboard_size) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, ap_server_conf, APLOGNO(00005)
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
    if (scoreboard_type == SB_SHARED) {
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
    int i;
#if APR_HAS_SHARED_MEMORY
    apr_status_t rv;
#endif

    if (ap_scoreboard_image) {
        ap_scoreboard_image->global->restart_time = apr_time_now();
        memset(ap_scoreboard_image->parent, 0,
               SIZE_OF_process_score * server_limit);
        for (i = 0; i < server_limit; i++) {
            memset(ap_scoreboard_image->servers[i], 0,
                   SIZE_OF_worker_score * thread_limit);
        }
        ap_init_scoreboard(NULL);
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
        void *sb_mem = ap_calloc(1, scoreboard_size);
        ap_init_scoreboard(sb_mem);
    }

    scoreboard_type = sb_type;
    ap_scoreboard_image->global->running_generation = 0;
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

AP_DECLARE(void) ap_set_conn_count(ap_sb_handle_t *sb, request_rec *r, 
                                   unsigned short conn_count)
{
    worker_score *ws;

    if (!sb)
        return;

    ws = &ap_scoreboard_image->servers[sb->child_num][sb->thread_num];
    ws->conn_count = conn_count;
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
    int max_daemons_limit = 0;

    ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_daemons_limit);

    for (i = 0; i < max_daemons_limit; ++i) {
        if (ap_scoreboard_image->parent[i].pid == pid->pid) {
            return i;
        }
    }

    return -1;
}

AP_DECLARE(void) ap_update_sb_handle(ap_sb_handle_t *sbh,
                                     int child_num, int thread_num)
{
    sbh->child_num = child_num;
    sbh->thread_num = thread_num;
}

AP_DECLARE(void) ap_create_sb_handle(ap_sb_handle_t **new_sbh, apr_pool_t *p,
                                     int child_num, int thread_num)
{
    *new_sbh = (ap_sb_handle_t *)apr_palloc(p, sizeof(ap_sb_handle_t));
    ap_update_sb_handle(*new_sbh, child_num, thread_num);
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
                                        server_rec *s,
                                        request_rec *r,
                                        const char *descr)
{
    int old_status;
    worker_score *ws;
    int mpm_generation;

    ws = &ap_scoreboard_image->servers[child_num][thread_num];
    old_status = ws->status;
    ws->status = status;
    
    if (status == SERVER_READY
        && old_status == SERVER_STARTING) {
        process_score *ps = &ap_scoreboard_image->parent[child_num];
        ws->thread_num = child_num * thread_limit + thread_num;
        ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);
        ps->generation = mpm_generation;
    }

    if (ap_extended_status) {
        const char *val;
        
        if (status == SERVER_READY || status == SERVER_DEAD) {
            /*
             * Reset individual counters
             */
            if (status == SERVER_DEAD) {
                ws->my_access_count = 0L;
                ws->my_bytes_served = 0L;
#ifdef HAVE_TIMES
                ws->times.tms_utime = 0;
                ws->times.tms_stime = 0;
                ws->times.tms_cutime = 0;
                ws->times.tms_cstime = 0;
#endif
            }
            ws->conn_count = 0;
            ws->conn_bytes = 0;
            ws->last_used = apr_time_now();
        }

        if (descr) {
            apr_cpystrn(ws->request, descr, sizeof(ws->request));
        }
        else if (r) {
            copy_request(ws->request, sizeof(ws->request), r);
        }
        else if (c) {
            ws->request[0]='\0';
        }

        if (r && r->useragent_ip) {
            if (!(val = ap_get_useragent_host(r, REMOTE_NOLOOKUP, NULL))) {
                apr_cpystrn(ws->client, r->useragent_ip, sizeof(ws->client)); /* DEPRECATE */
                apr_cpystrn(ws->client64, r->useragent_ip, sizeof(ws->client64));
            }
            else {
                apr_cpystrn(ws->client, val, sizeof(ws->client)); /* DEPRECATE */
                apr_cpystrn(ws->client64, val, sizeof(ws->client64));
            }
        }
        else if (c) {
            if (!(val = ap_get_remote_host(c, c->base_server->lookup_defaults,
                                           REMOTE_NOLOOKUP, NULL))) {
                apr_cpystrn(ws->client, c->client_ip, sizeof(ws->client)); /* DEPRECATE */
                apr_cpystrn(ws->client64, c->client_ip, sizeof(ws->client64));
            }
            else {
                apr_cpystrn(ws->client, val, sizeof(ws->client)); /* DEPRECATE */
                apr_cpystrn(ws->client64, val, sizeof(ws->client64));
            }
        }

        if (s) {
            if (c) {
                apr_snprintf(ws->vhost, sizeof(ws->vhost), "%s:%d",
                             s->server_hostname, c->local_addr->port);
            }
            else {
                apr_cpystrn(ws->vhost, s->server_hostname, sizeof(ws->vhost));
            }
        }
        else if (c) {
            ws->vhost[0]='\0';
        }

        if (c) {
            val = ap_get_protocol(c);
            apr_cpystrn(ws->protocol, val, sizeof(ws->protocol));
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
                                        r ? r->server : NULL,
                                        r, NULL);
}

AP_DECLARE(int) ap_update_child_status(ap_sb_handle_t *sbh, int status,
                                      request_rec *r)
{
    if (!sbh || (sbh->child_num < 0))
        return -1;

    return update_child_status_internal(sbh->child_num, sbh->thread_num,
                                        status,
                                        r ? r->connection : NULL,
                                        r ? r->server : NULL,
                                        r, NULL);
}

AP_DECLARE(int) ap_update_child_status_from_conn(ap_sb_handle_t *sbh, int status,
                                                 conn_rec *c)
{
    if (!sbh || (sbh->child_num < 0))
        return -1;

    return update_child_status_internal(sbh->child_num, sbh->thread_num,
                                        status, c, NULL, NULL, NULL);
}

AP_DECLARE(int) ap_update_child_status_from_server(ap_sb_handle_t *sbh, int status, 
                                                   conn_rec *c, server_rec *s)
{
    if (!sbh || (sbh->child_num < 0))
        return -1;

    return update_child_status_internal(sbh->child_num, sbh->thread_num,
                                        status, c, s, NULL, NULL);
}

AP_DECLARE(int) ap_update_child_status_descr(ap_sb_handle_t *sbh, int status, const char *descr)
{
    if (!sbh || (sbh->child_num < 0))
        return -1;

    return update_child_status_internal(sbh->child_num, sbh->thread_num,
                                        status, NULL, NULL, NULL, descr);
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
        ws->start_time = ws->last_used = apr_time_now();
    }
    else if (status == STOP_PREQUEST) {
        ws->stop_time = ws->last_used = apr_time_now();
        if (ap_extended_status) {
            ws->duration += ws->stop_time - ws->start_time;
        }
    }
}

AP_DECLARE(int) ap_update_global_status()
{
#ifdef HAVE_TIMES
    if (ap_scoreboard_image == NULL) {
        return APR_SUCCESS;
    }
    times(&ap_scoreboard_image->global->times);
#endif
    return APR_SUCCESS;
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

AP_DECLARE(void) ap_copy_scoreboard_worker(worker_score *dest, 
                                           int child_num,
                                           int thread_num)
{
    worker_score *ws = ap_get_scoreboard_worker_from_indexes(child_num, thread_num);

    memcpy(dest, ws, sizeof *ws);

    /* For extra safety, NUL-terminate the strings returned, though it
     * should be true those last bytes are always zero anyway. */
    dest->client[sizeof(dest->client) - 1] = '\0';
    dest->client64[sizeof(dest->client64) - 1] = '\0';
    dest->request[sizeof(dest->request) - 1] = '\0';
    dest->vhost[sizeof(dest->vhost) - 1] = '\0';
    dest->protocol[sizeof(dest->protocol) - 1] = '\0';
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

AP_DECLARE(void) ap_get_sload(ap_sload_t *sl)
{
    int i, j, server_limit, thread_limit;
    int ready = 0;
    int busy = 0;
    int dead = 0;
    int total;
    ap_generation_t mpm_generation;
    global_score *global_record;
#ifdef HAVE_TIMES
    int times_per_thread;
#endif

#ifdef HAVE_TIMES
    times_per_thread = getpid() != child_pid;
#endif

    /* preload errored fields, we overwrite */
    sl->idle = -1;
    sl->busy = -1;
    sl->dead = -1;
    sl->cpu_usr = 0;
    sl->cpu_sys = 0;
    sl->bytes_served = 0;
    sl->access_count = 0;
    sl->duration = 0;
    sl->timestamp = apr_time_now();

    if (ap_scoreboard_image == NULL) {
        return;
    }

    ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

    for (i = 0; i < server_limit; i++) {
#ifdef HAVE_TIMES
        clock_t proc_tu = 0, proc_ts = 0, proc_tcu = 0, proc_tcs = 0;
        clock_t tmp_tu, tmp_ts, tmp_tcu, tmp_tcs;
#endif
        process_score *ps = ap_get_scoreboard_process(i);

        for (j = 0; j < thread_limit; j++) {
            int res;
            worker_score *ws = NULL;
            ws = &ap_scoreboard_image->servers[i][j];
            res = ws->status;

            if (!ps->quiescing && ps->pid) {
                if (res == SERVER_READY && ps->generation == mpm_generation) {
                    ready++;
                }
                else if (res != SERVER_DEAD &&
                         res != SERVER_STARTING && res != SERVER_IDLE_KILL &&
                         ps->generation == mpm_generation) {
                    busy++;
                } else {   
                    dead++;
                }   
            }

            if (ap_extended_status && !ps->quiescing && ps->pid) {
                if (ws->access_count != 0 
                    || (res != SERVER_READY && res != SERVER_DEAD)) {
#ifdef HAVE_TIMES
                    tmp_tu = ws->times.tms_utime;
                    tmp_ts = ws->times.tms_stime;
                    tmp_tcu = ws->times.tms_cutime;
                    tmp_tcs = ws->times.tms_cstime;

                    if (times_per_thread) {
                        proc_tu += tmp_tu;
                        proc_ts += tmp_ts;
                        proc_tcu += tmp_tcu;
                        proc_tcs += tmp_tcs;
                    }
                    else {
                        if (tmp_tu > proc_tu ||
                            tmp_ts > proc_ts ||
                            tmp_tcu > proc_tcu ||
                            tmp_tcs > proc_tcs) {
                            proc_tu = tmp_tu;
                            proc_ts = tmp_ts;
                            proc_tcu = tmp_tcu;
                            proc_tcs = tmp_tcs;
                        }
                    }
#endif /* HAVE_TIMES */
                    sl->access_count += ws->access_count;
                    sl->bytes_served += ws->bytes_served;
                    sl->duration += ws->duration;
                }
            }
        }
#ifdef HAVE_TIMES
        sl->cpu_usr += proc_tu + proc_tcu;
        sl->cpu_sys += proc_ts + proc_tcs;
#endif
    }
#ifdef HAVE_TIMES
    global_record = ap_get_scoreboard_global();
    sl->cpu_usr += global_record->times.tms_utime
                   + global_record->times.tms_cutime;
    sl->cpu_sys += global_record->times.tms_stime
                   + global_record->times.tms_cstime;
#endif
    total = busy + ready + dead;
    if (total) {
        sl->idle = (float)ready * 100 / total;
        sl->busy = (float)busy * 100 / total;
        sl->dead = (float)dead * 100 / total;
    }
}

static void calc_mon_data(ap_sload_t *s0, ap_sload_t *s1,
                          ap_mon_snap_t *snap)
{
    unsigned long accesses;
#ifdef HAVE_TIMES
    float tick;
#endif

    snap->acc_per_sec = -1;
    snap->bytes_per_sec = -1;
    snap->average_concurrency = -1;
    snap->cpu_load = -1;
    snap->bytes_per_acc = -1;
    snap->ms_per_acc = -1;
    snap->interval = -1;
    snap->sload = NULL;

    /* Need two iterations for complete data in s0 and s1 */
    if (s0->access_count < 0 || s1->access_count < 0) {
        return;
    }

    snap->interval = (apr_interval_time_t) (s1->timestamp - s0->timestamp);
    accesses = s1->access_count - s0->access_count;
    if (snap->interval > 0) {
        snap->acc_per_sec = (float)accesses / snap->interval * APR_USEC_PER_SEC;
        snap->bytes_per_sec = (float)(s1->bytes_served - s0->bytes_served)
                              / snap->interval * APR_USEC_PER_SEC;
        snap->average_concurrency = (float)(s1->duration - s0->duration)
                                    / snap->interval;
#ifdef HAVE_TIMES
#ifdef _SC_CLK_TCK
        tick = sysconf(_SC_CLK_TCK);
#else
        tick = HZ;
#endif
        snap->cpu_load = (float)(s1->cpu_usr - s0->cpu_usr
                                 + s1->cpu_sys - s0->cpu_sys)
                              / tick / snap->interval * APR_USEC_PER_SEC;
#endif
    }
    if (accesses > 0) {
        snap->bytes_per_acc = (float)(s1->bytes_served - s0->bytes_served)
                              / accesses;
        snap->ms_per_acc = (float)(s1->duration - s0->duration)
                           / accesses / 1000.0;
    }
}

int ap_scoreboard_monitor(apr_pool_t *p, server_rec *s)
{
    ap_sload_t *sload_last;
    ap_sload_t *sload_next;
    ap_mon_snap_t *snap_next;
    apr_uint32_t index;

    if (ap_scoreboard_image == NULL) {
        return DECLINED;
    }

    index = apr_atomic_read32(&ap_scoreboard_image->global->snap_index);
    if (index == 0) {
        sload_last = &ap_scoreboard_image->global->sload0;
        sload_next = &ap_scoreboard_image->global->sload1;
        snap_next = &ap_scoreboard_image->global->snap1;
        index = 1;
    } else {
        sload_last = &ap_scoreboard_image->global->sload1;
        sload_next = &ap_scoreboard_image->global->sload0;
        snap_next = &ap_scoreboard_image->global->snap0;
        index = 0;
    }
    ap_get_sload(sload_next);
    calc_mon_data(sload_last, sload_next, snap_next);
    apr_atomic_set32(&ap_scoreboard_image->global->snap_index, index);
    return DECLINED;
}

AP_DECLARE(void) ap_get_mon_snap(ap_mon_snap_t *ms)
{
    ap_sload_t *sload;
    ap_mon_snap_t *snap;
    apr_uint32_t index;

    if (ap_scoreboard_image == NULL) {
        if (ms->sload) {
            ms->sload->idle = -1;
            ms->sload->busy = -1;
            ms->sload->access_count = -1;
            ms->sload->bytes_served = -1;
            ms->sload->duration = -1;
            ms->sload->timestamp = -1;
        }
        ms->interval = -1;
        ms->acc_per_sec = -1;
        ms->bytes_per_sec = -1;
        ms->bytes_per_acc = -1;
        ms->ms_per_acc = -1;
        ms->average_concurrency = -1;
        return;
    }

    index = apr_atomic_read32(&ap_scoreboard_image->global->snap_index);
    if (index == 0) {
        sload = &ap_scoreboard_image->global->sload0;
        snap = &ap_scoreboard_image->global->snap0;
    } else {
        sload = &ap_scoreboard_image->global->sload1;
        snap = &ap_scoreboard_image->global->snap1;
    }
    memcpy(ms, snap, sizeof(*snap));
    if (ms->sload) {
        memcpy(ms->sload, sload, sizeof(*sload));
    }
}

void ap_scoreboard_child_init(apr_pool_t *p, server_rec *s)
{
#ifdef HAVE_TIMES
    child_pid = getpid();
#endif
}
