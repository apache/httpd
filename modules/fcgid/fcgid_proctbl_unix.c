/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

#include "fcgid_proctbl.h"
#include "apr_version.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "fcgid_global.h"
#include "fcgid_conf.h"
#include "fcgid_mutex.h"
#include <unistd.h>

static apr_shm_t *g_sharemem = NULL;
static apr_global_mutex_t *g_sharelock = NULL;
static const char *g_sharelock_name;
static const char *g_sharelock_mutex_type = "fcgid-proctbl";
static fcgid_procnode *g_proc_array = NULL; /* Contain all process slot */
static fcgid_procnode *g_free_list_header = NULL;   /* Attach to no process list */
static fcgid_procnode *g_busy_list_header = NULL;   /* Attach to a working process list */
static fcgid_procnode *g_idle_list_header = NULL;   /* Attach to an idle process list */
static fcgid_procnode *g_error_list_header = NULL;  /* Attach to an error process list */
static fcgid_share *_global_memory = NULL;
static fcgid_global_share *g_global_share = NULL;   /* global information */
static size_t g_table_size = FCGID_PROC_TABLE_SIZE;

/* apr version 0.x not support apr_shm_remove, I have to copy it from apr version 1.x */
#if (APR_MAJOR_VERSION < 1)
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#ifdef HAVE_SYS_IPC_H
#include <sys/ipc.h>
#endif
#ifdef HAVE_SYS_MUTEX_H
#include <sys/mutex.h>
#endif
#ifdef HAVE_SYS_SHM_H
#include <sys/shm.h>
#endif
#if !defined(SHM_R)
#define SHM_R 0400
#endif
#if !defined(SHM_W)
#define SHM_W 0200
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

static apr_status_t apr_shm_remove(const char *filename, apr_pool_t * pool)
{
#if APR_USE_SHMEM_SHMGET
    apr_status_t status;
    apr_file_t *file;
    key_t shmkey;
    int shmid;
#endif

#if APR_USE_SHMEM_MMAP_TMP
    return apr_file_remove(filename, pool);
#endif
#if APR_USE_SHMEM_MMAP_SHM
    if (shm_unlink(filename) == -1) {
        return errno;
    }
    return APR_SUCCESS;
#endif
#if APR_USE_SHMEM_SHMGET
    /* Presume that the file already exists; just open for writing */
    status = apr_file_open(&file, filename, APR_WRITE,
                           APR_OS_DEFAULT, pool);
    if (status) {
        return status;
    }

    /* ftok() (on solaris at least) requires that the file actually
     * exist before calling ftok(). */
    shmkey = ftok(filename, 1);
    if (shmkey == (key_t) - 1) {
        goto shm_remove_failed;
    }

    apr_file_close(file);

    if ((shmid = shmget(shmkey, 0, SHM_R | SHM_W)) < 0) {
        goto shm_remove_failed;
    }

    /* Indicate that the segment is to be destroyed as soon
     * as all processes have detached. This also disallows any
     * new attachments to the segment. */
    if (shmctl(shmid, IPC_RMID, NULL) == -1) {
        goto shm_remove_failed;
    }
    return apr_file_remove(filename, pool);

  shm_remove_failed:
    status = errno;
    /* ensure the file has been removed anyway. */
    apr_file_remove(filename, pool);
    return status;
#endif

    /* No support for anonymous shm */
    return APR_ENOTIMPL;
}
#endif                          /* APR_MAJOR_VERSION<1 */

apr_status_t proctable_pre_config(apr_pool_t *p, apr_pool_t *plog,
                                  apr_pool_t *ptemp)
{
    return fcgid_mutex_register(g_sharelock_mutex_type, p);
}

apr_status_t
proctable_post_config(server_rec * main_server, apr_pool_t * configpool)
{
    size_t shmem_size = sizeof(fcgid_share);
    fcgid_procnode *ptmpnode = NULL;
    int i;
    apr_status_t rv;
    fcgid_server_conf *sconf = ap_get_module_config(main_server->module_config,
                                                    &fcgid_module);

    /* Remove share memory first */
    apr_shm_remove(sconf->shmname_path, main_server->process->pconf);

    /* Create share memory */
    if ((rv = apr_shm_create(&g_sharemem, shmem_size, sconf->shmname_path,
                             main_server->process->pconf)) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: Can't create shared memory for size %" APR_SIZE_T_FMT " bytes",
                     shmem_size);
        exit(1);
    }
    _global_memory = apr_shm_baseaddr_get(g_sharemem);

    /* Create global mutex */
    rv = fcgid_mutex_create(&g_sharelock, &g_sharelock_name,
                            g_sharelock_mutex_type,
                            main_server->process->pconf, main_server);
    if (rv != APR_SUCCESS) {
        exit(1);
    }

    memset(_global_memory, 0, shmem_size);
    g_proc_array = _global_memory->procnode_array;
    g_global_share = &_global_memory->global;

    g_global_share->must_exit = 0;

    /* Init the array */
    g_idle_list_header = g_proc_array;
    g_busy_list_header = g_idle_list_header + 1;
    g_error_list_header = g_busy_list_header + 1;
    g_free_list_header = g_error_list_header + 1;
    ptmpnode = g_free_list_header;
    for (i = 0; i < FCGID_MAX_APPLICATION; i++) {
        ptmpnode->next_index = ptmpnode - g_proc_array + 1;
        ptmpnode++;
    }

    return APR_SUCCESS;
}

apr_status_t
proctable_child_init(server_rec * main_server, apr_pool_t * configpool)
{
    apr_status_t rv;

    if ((rv = apr_global_mutex_child_init(&g_sharelock,
                                          g_sharelock_name,
                                          main_server->process->pconf)) !=
        APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: apr_global_mutex_child_init error");
        exit(1);
    }

    return rv;
}

static apr_status_t proctable_lock_internal(void)
{
    return apr_global_mutex_lock(g_sharelock);
}

static apr_status_t proctable_unlock_internal(void)
{
    return apr_global_mutex_unlock(g_sharelock);
}

fcgid_procnode *proctable_get_free_list(void)
{
    return g_free_list_header;
}

fcgid_procnode *proctable_get_busy_list(void)
{
    return g_busy_list_header;
}

fcgid_procnode *proctable_get_idle_list(void)
{
    return g_idle_list_header;
}

fcgid_procnode *proctable_get_table_array(void)
{
    return g_proc_array;
}

fcgid_procnode *proctable_get_error_list(void)
{
    return g_error_list_header;
}

fcgid_global_share *proctable_get_globalshare(void)
{
    return g_global_share;
}

size_t proctable_get_table_size(void)
{
    return g_table_size;
}

void proctable_lock(request_rec *r)
{
    /* Lock error is a fatal error */
    apr_status_t rv;

    if ((rv = proctable_lock_internal()) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_EMERG, rv, r,
                      "mod_fcgid: can't lock process table in pid %"
                      APR_PID_T_FMT,
                      getpid());
        exit(1);
    }
}

void proctable_unlock(request_rec *r)
{
    /* Lock error is a fatal error */
    apr_status_t rv;

    if ((rv = proctable_unlock_internal()) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_EMERG, rv, r,
                      "mod_fcgid: can't unlock process table in pid %"
                      APR_PID_T_FMT,
                      getpid());
        exit(1);
    }
}

void proctable_pm_lock(server_rec *s)
{
    apr_status_t rv;

    if (g_global_share->must_exit) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                     "mod_fcgid: server is restarted, pid %" APR_PID_T_FMT
                     " must exit",
                     getpid());
        kill(getpid(), SIGTERM);
    }

    /* Lock error is a fatal error */
    if ((rv = proctable_lock_internal()) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "mod_fcgid: can't lock process table in PM, pid %"
                     APR_PID_T_FMT,
                     getpid());
        exit(1);
    }
}

void proctable_pm_unlock(server_rec *s)
{
    /* Lock error is a fatal error */
    apr_status_t rv;

    if ((rv = proctable_unlock_internal()) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "mod_fcgid: can't unlock process table in PM, pid %"
                     APR_PID_T_FMT,
                     getpid());
        exit(1);
    }
}

void proctable_print_debug_info(server_rec * main_server)
{
    int freecount = 0;
    fcgid_procnode *current_node;

    for (current_node = &g_proc_array[g_free_list_header->next_index];
         current_node != g_proc_array;
         current_node = &g_proc_array[current_node->next_index])
        freecount++;

    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
                 "mod_fcgid: total node count: %d, free node count: %d",
                 FCGID_MAX_APPLICATION, freecount);

    for (current_node = &g_proc_array[g_idle_list_header->next_index];
         current_node != g_proc_array;
         current_node = &g_proc_array[current_node->next_index]) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
                     "mod_fcgid: idle node index: %ld",
                     (long)(current_node - g_proc_array));
    }

    for (current_node = &g_proc_array[g_busy_list_header->next_index];
         current_node != g_proc_array;
         current_node = &g_proc_array[current_node->next_index]) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
                     "mod_fcgid: busy node index: %ld",
                     (long)(current_node - g_proc_array));
    }

    for (current_node = &g_proc_array[g_error_list_header->next_index];
         current_node != g_proc_array;
         current_node = &g_proc_array[current_node->next_index]) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
                     "mod_fcgid: error node index: %ld",
                     (long)(current_node - g_proc_array));
    }
}
