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


#include "httpd.h"
#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_pools.h"
#include "util_script.h"
#include "mod_core.h"
#include "mod_cgi.h"
#include "apr_tables.h"
#include "fcgid_proc.h"
#include "fcgid_proctbl.h"
#include "fcgid_protocol.h"
#include "fcgid_conf.h"
#include "fcgid_pm.h"
#include "fcgid_spawn_ctl.h"
#define SHUTDOWN_EVENT_NAME "_FCGI_SHUTDOWN_EVENT_"
#define FINISH_EVENT_DATA_NAME "finish_event"
#ifndef SIGKILL
#define SIGKILL 9
#endif

/* It's tested on WinNT ONLY, if it work on the other MS platform, let me know */
#if WINVER < 0x0400
#error It is tested on WinNT only
#endif

typedef struct {
    HANDLE handle_pipe;
    OVERLAPPED overlap_read;
    OVERLAPPED overlap_write;
} fcgid_namedpipe_handle;

static int g_process_counter = 0;

static apr_status_t close_finish_event(void *finishevent)
{
    HANDLE *finish_event = finishevent;

    CloseHandle(*finish_event);
    return APR_SUCCESS;
}

apr_status_t proc_spawn_process(const char *cmdline, fcgid_proc_info *procinfo,
                                fcgid_procnode *procnode)
{
    HANDLE *finish_event, listen_handle;
    SECURITY_ATTRIBUTES SecurityAttributes;
    fcgid_server_conf *sconf;
    apr_procattr_t *proc_attr;
    apr_status_t rv;
    apr_file_t *file;
    const char * const *proc_environ;
    char sock_path[FCGID_PATH_MAX];
    const char **wargv;

    /* Build wrapper args */
    apr_tokenize_to_argv(cmdline, (char ***)&wargv, procnode->proc_pool);

    memset(&SecurityAttributes, 0, sizeof(SecurityAttributes));

    /* Prepare finish event */
    finish_event = apr_palloc(procnode->proc_pool, sizeof(HANDLE));
    *finish_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (*finish_event == NULL
        || !SetHandleInformation(*finish_event, HANDLE_FLAG_INHERIT, TRUE))
    {
        ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                     procinfo->main_server,
                     "mod_fcgid: can't create mutex for subprocess");
        return APR_ENOLOCK;
    }
    apr_pool_cleanup_register(procnode->proc_pool, finish_event,
                              close_finish_event, apr_pool_cleanup_null);

    /* For proc_kill_gracefully() */
    apr_pool_userdata_set(finish_event, FINISH_EVENT_DATA_NAME,
                          NULL, procnode->proc_pool);

    /* Pass the finish event id to subprocess */
    apr_table_setn(procinfo->proc_environ, SHUTDOWN_EVENT_NAME,
                   apr_ltoa(procnode->proc_pool, (long) *finish_event));

    /* Prepare the listen namedpipe file name (no check for truncation) */
    apr_snprintf(sock_path, sizeof sock_path,
                 "\\\\.\\pipe\\fcgidpipe-%lu.%d",
                 GetCurrentProcessId(), g_process_counter++);

    /* Prepare the listen namedpipe handle */
    SecurityAttributes.bInheritHandle = TRUE;
    SecurityAttributes.nLength = sizeof(SecurityAttributes);
    SecurityAttributes.lpSecurityDescriptor = NULL;
    listen_handle = CreateNamedPipe(sock_path,
                                    PIPE_ACCESS_DUPLEX,
                                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
                                    PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
                                    8192, 8192, 0, &SecurityAttributes);
    if (listen_handle == INVALID_HANDLE_VALUE) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                     procinfo->main_server,
                     "mod_fcgid: can't create namedpipe for subprocess");
        return APR_ENOSOCKET;
    }
    apr_cpystrn(procnode->socket_path, sock_path, sizeof(procnode->socket_path));
    apr_cpystrn(procnode->executable_path, wargv[0],
                sizeof(procnode->executable_path));

    /* Build environment variables */
    proc_environ = (const char * const *)
                   ap_create_environment(procnode->proc_pool,
                                         procinfo->proc_environ);
    if (!proc_environ) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                     procinfo->main_server,
                     "mod_fcgid: can't build environment variables");
        return APR_ENOMEM;
    }

    /* Create process now */
    if ((rv = apr_procattr_create(&proc_attr, procnode->proc_pool))
               != APR_SUCCESS
        || (rv = apr_procattr_dir_set(proc_attr,
                     ap_make_dirstr_parent(procnode->proc_pool,
                                           wargv[0]))) != APR_SUCCESS
        || (rv = apr_procattr_cmdtype_set(proc_attr, APR_PROGRAM))
               != APR_SUCCESS
        || (rv = apr_procattr_detach_set(proc_attr, 1)) != APR_SUCCESS
        || (rv = apr_procattr_io_set(proc_attr, APR_NO_PIPE,
                                     APR_NO_FILE, APR_NO_FILE)) != APR_SUCCESS
        || (rv = apr_os_file_put(&file, &listen_handle, 0,
                                 procnode->proc_pool)) != APR_SUCCESS
        || (rv = apr_procattr_child_in_set(proc_attr, file, NULL))
               != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, procinfo->main_server,
                     "mod_fcgid: can't create FastCGI process attribute");
        CloseHandle(listen_handle);
        return APR_ENOPROC;
    }

    /* fork and exec now */
    rv = apr_proc_create(&(procnode->proc_id), wargv[0], wargv,
                         proc_environ,
                         proc_attr, procnode->proc_pool);

    /* OK, I created the process, now put it back to idle list */
    CloseHandle(listen_handle);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, procinfo->main_server,
                     "mod_fcgid: can't run %s", wargv[0]);
        return rv;
    }

    /* FcgidWin32PreventOrphans feature */
    sconf = ap_get_module_config(procinfo->main_server->module_config,
                                 &fcgid_module);

    if (sconf->hJobObjectForAutoCleanup != NULL) {
        /* Associate cgi process to current process */
        if (AssignProcessToJobObject(sconf->hJobObjectForAutoCleanup,
                                     procnode->proc_id.hproc) == 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                         procinfo->main_server,
                         "mod_fcgid: unable to assign child process to "
                         "job object");
        }
    }

    return APR_SUCCESS;
}

apr_status_t proc_kill_gracefully(fcgid_procnode *procnode,
                                  server_rec *main_server)
{
    HANDLE *finish_event = NULL;

    apr_pool_userdata_get((void **) &finish_event,
                          FINISH_EVENT_DATA_NAME, procnode->proc_pool);

    if (finish_event != NULL)
        SetEvent(*finish_event);
    return APR_SUCCESS;
}

apr_status_t proc_kill_force(fcgid_procnode *procnode,
                             server_rec *main_server)
{
    return apr_proc_kill(&(procnode->proc_id), SIGKILL);
}

apr_status_t proc_wait_process(server_rec *main_server,
                               fcgid_procnode *procnode)
{
    apr_status_t rv;
    int exitcode;
    apr_exit_why_e exitwhy;

    if ((rv = apr_proc_wait(&(procnode->proc_id), &exitcode, &exitwhy,
                            APR_NOWAIT)) == APR_CHILD_DONE) {
        /* Log why and how it die */
        proc_print_exit_info(procnode, exitcode, exitwhy, main_server);

        /* Register the death */
        register_termination(main_server, procnode);

        /* Destroy pool */
        apr_pool_destroy(procnode->proc_pool);
        procnode->proc_pool = NULL;
    }

    return rv;
}

static apr_status_t ipc_handle_cleanup(void *thehandle)
{
    fcgid_namedpipe_handle *handle = thehandle;

    /* Sanity check */
    if (handle) {
        if (handle->handle_pipe != INVALID_HANDLE_VALUE)
            CloseHandle(handle->handle_pipe);
        if (handle->overlap_read.hEvent != NULL)
            CloseHandle(handle->overlap_read.hEvent);
        if (handle->overlap_write.hEvent != NULL)
            CloseHandle(handle->overlap_write.hEvent);
        handle->handle_pipe = INVALID_HANDLE_VALUE;
        handle->overlap_read.hEvent = NULL;
        handle->overlap_write.hEvent = NULL;
    }

    return APR_SUCCESS;
}

apr_status_t proc_connect_ipc(fcgid_procnode *procnode, fcgid_ipc *ipc_handle)
{
    /* Prepare the ipc struct */
    fcgid_namedpipe_handle *handle_info;

    ipc_handle->ipc_handle_info =
        (fcgid_namedpipe_handle *) apr_pcalloc(ipc_handle->request->pool,
                                               sizeof
                                               (fcgid_namedpipe_handle));
    handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;

    /* Prepare OVERLAPPED struct for non-block I/O */
    handle_info->overlap_read.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    handle_info->overlap_write.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    handle_info->handle_pipe = INVALID_HANDLE_VALUE;

    apr_pool_cleanup_register(ipc_handle->request->pool,
                              handle_info,
                              ipc_handle_cleanup, apr_pool_cleanup_null);

    if (handle_info->overlap_read.hEvent == NULL
            || handle_info->overlap_write.hEvent == NULL)
        return APR_ENOMEM;

    /* Connect to name pipe */
    handle_info->handle_pipe = CreateFile(procnode->socket_path,
                                          GENERIC_READ | GENERIC_WRITE,
                                          0, NULL, OPEN_EXISTING,
                                          FILE_FLAG_OVERLAPPED, NULL);

    if (handle_info->handle_pipe == INVALID_HANDLE_VALUE
        && ipc_handle->connect_timeout != 0
        && GetLastError() == ERROR_PIPE_BUSY)
    {
        /* XXX - there appears to be a race, here
         * Wait for pipe to be ready for connect, and try again
         */
        if (WaitNamedPipe(procnode->socket_path, ipc_handle->connect_timeout))
        {
            handle_info->handle_pipe = CreateFile(procnode->socket_path,
                                                  GENERIC_READ | GENERIC_WRITE,
                                                  0, NULL, OPEN_EXISTING,
                                                  FILE_FLAG_OVERLAPPED, NULL);
        }
    }

    if (handle_info->handle_pipe == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) /* The process has exited */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, ipc_handle->request,
                          "mod_fcgid: can't connect to named pipe, FastCGI"
                          " server %" APR_PID_T_FMT " has been terminated",
                          procnode->proc_id.pid);
        else
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, apr_get_os_error(),
                          ipc_handle->request,
                          "mod_fcgid: can't connect to named pipe, FastCGI"
                          " server pid %" APR_PID_T_FMT,
                          procnode->proc_id.pid);
        return APR_ESPIPE;
    }

    /* Now named pipe connected */
    return APR_SUCCESS;
}

apr_status_t proc_close_ipc(fcgid_ipc * ipc_handle)
{
    apr_status_t rv;

    rv = apr_pool_cleanup_run(ipc_handle->request->pool,
                              ipc_handle->ipc_handle_info,
                              ipc_handle_cleanup);
    ipc_handle->ipc_handle_info = NULL;
    return rv;
}

apr_status_t proc_read_ipc(fcgid_ipc * ipc_handle, const char *buffer,
                           apr_size_t * size)
{
    apr_status_t rv;
    fcgid_namedpipe_handle *handle_info;
    DWORD bytesread;

    handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;

    if (ReadFile(handle_info->handle_pipe, (LPVOID) buffer,
                 *size, &bytesread, &handle_info->overlap_read)) {
        *size = bytesread;
        return APR_SUCCESS;
    } else if ((rv = GetLastError()) != ERROR_IO_PENDING) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_FROM_OS_ERROR(rv),
                      ipc_handle->request,
                      "mod_fcgid: can't read from pipe");
        return rv;
    } else {
        /* it's ERROR_IO_PENDING */
        DWORD transferred;
        DWORD dwWaitResult
            = WaitForSingleObject(handle_info->overlap_read.hEvent,
                                  ipc_handle->communation_timeout * 1000);

        if (dwWaitResult == WAIT_OBJECT_0) {
            if (!GetOverlappedResult(handle_info->handle_pipe,
                                     &handle_info->overlap_read,
                                     &transferred, FALSE /* don't wait */ )
                || transferred == 0) {
                rv = apr_get_os_error();
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv,
                              ipc_handle->request,
                              "mod_fcgid: get overlap result error");
                return rv;
            }

            *size = transferred;
            return APR_SUCCESS;
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, ipc_handle->request,
                          "mod_fcgid: read timeout from pipe");
            return APR_ETIMEDOUT;
        }
    }
}

apr_status_t proc_write_ipc(fcgid_ipc * ipc_handle,
                            apr_bucket_brigade * birgade_send)
{
    fcgid_namedpipe_handle *handle_info;
    apr_bucket *bucket_request;
    apr_status_t rv;
    DWORD transferred;
    apr_bucket_brigade *tmpbb = apr_brigade_create(birgade_send->p, 
                                                   birgade_send->bucket_alloc);

    handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;

    while (!APR_BRIGADE_EMPTY(birgade_send)) {
        const char *write_buf;
        apr_size_t write_buf_len;
        apr_size_t has_write;

        bucket_request = APR_BRIGADE_FIRST(birgade_send);

        if (APR_BUCKET_IS_METADATA(bucket_request)) {
            apr_bucket_delete(bucket_request);
            continue;
        }

        if ((rv = apr_bucket_read(bucket_request, &write_buf, &write_buf_len,
                                  APR_BLOCK_READ)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, ipc_handle->request,
                          "mod_fcgid: can't read request from bucket");
            return rv;
        }

        APR_BUCKET_REMOVE(bucket_request);
        APR_BRIGADE_INSERT_TAIL(tmpbb, bucket_request);

        /* Write the buffer to fastcgi server */
        has_write = 0;
        while (has_write < write_buf_len) {
            DWORD byteswrite;

            if (WriteFile(handle_info->handle_pipe,
                          write_buf + has_write,
                          write_buf_len - has_write,
                          &byteswrite, &handle_info->overlap_write)) {
                has_write += byteswrite;
                apr_brigade_cleanup(tmpbb);
                continue;
            } else if ((rv = GetLastError()) != ERROR_IO_PENDING) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING,
                              APR_FROM_OS_ERROR(rv), ipc_handle->request,
                              "mod_fcgid: can't write to pipe");
                return rv;
            } else {
                /*
                   it's ERROR_IO_PENDING on write
                 */
                DWORD dwWaitResult =
                    WaitForSingleObject(handle_info->overlap_write.hEvent,
                                        ipc_handle->communation_timeout * 1000);
                if (dwWaitResult == WAIT_OBJECT_0) {
                    if (!GetOverlappedResult(handle_info->handle_pipe,
                                             &handle_info->overlap_write,
                                             &transferred,
                                             FALSE /* don't wait */ )
                        || transferred == 0)
                    {
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING,
                                      apr_get_os_error(), ipc_handle->request,
                                      "mod_fcgid: get overlap result error");
                        return APR_ESPIPE;
                    }
                    has_write += transferred;
                    apr_brigade_cleanup(tmpbb);
                    continue;
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0,
                                  ipc_handle->request,
                                  "mod_fcgid: write timeout to pipe");
                    return APR_ESPIPE;
                }
            }
        }
    }

    apr_brigade_destroy(tmpbb);
    return APR_SUCCESS;
}

void proc_print_exit_info(fcgid_procnode * procnode, int exitcode,
                          apr_exit_why_e exitwhy, server_rec * main_server)
{
    char *diewhy = NULL;

    /* Reasons to exit */
    switch (procnode->diewhy) {
    case FCGID_DIE_KILLSELF:
        if (exitwhy == APR_PROC_EXIT)
            diewhy = "normal exit";
        else
            diewhy = "access violation";
        break;
    case FCGID_DIE_IDLE_TIMEOUT:
        diewhy = "idle timeout";
        break;
    case FCGID_DIE_LIFETIME_EXPIRED:
        diewhy = "lifetime expired";
        break;
    case FCGID_DIE_BUSY_TIMEOUT:
        diewhy = "busy timeout";
        break;
    case FCGID_DIE_CONNECT_ERROR:
        diewhy = "connect error, server may has exited";
        break;
    case FCGID_DIE_COMM_ERROR:
        diewhy = "communication error";
        break;
    case FCGID_DIE_SHUTDOWN:
        diewhy = "shutting down";
        break;
    default:
        diewhy = "unknown";
    }

    /* Print log now */
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, main_server,
                     "mod_fcgid: process %s(%" APR_PID_T_FMT ") exit(%s), return code %d",
                     procnode->executable_path, procnode->proc_id.pid, diewhy, exitcode);
}
