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

#ifndef FCGID_PM_PROC_H
#define FCGID_PM_PROC_H
#include "httpd.h"
#include "apr_pools.h"
#include "apr_file_io.h"
#include "fcgid_proctbl.h"

typedef struct {
    apr_table_t *proc_environ;
    server_rec *main_server;
    apr_pool_t *configpool;
    char *cgipath;
    uid_t uid;                  /* For suEXEC */
    gid_t gid;                  /* For suEXEC */
    int userdir;                /* For suEXEC */
} fcgid_proc_info;

typedef struct {
    int connect_timeout;        /* in second */
    int communation_timeout;    /* in second */
    void *ipc_handle_info;
    request_rec *request;
} fcgid_ipc;

apr_status_t proc_spawn_process(const char *cmdline,
                                fcgid_proc_info * procinfo,
                                fcgid_procnode * procnode);

apr_status_t proc_kill_gracefully(fcgid_procnode * procnode,
                                  server_rec * main_server);
apr_status_t proc_kill_force(fcgid_procnode * procnode,
                             server_rec * main_server);
apr_status_t proc_wait_process(server_rec * main_server,
                               fcgid_procnode * procnode);

apr_status_t proc_connect_ipc(fcgid_procnode * procnode,
                              fcgid_ipc * ipc_handle);

apr_status_t proc_read_ipc(fcgid_ipc * ipc_handle, const char *buffer,
                           apr_size_t * size);

apr_status_t proc_write_ipc(fcgid_ipc * ipc_handle,
                            apr_bucket_brigade * output_brigade);

apr_status_t proc_close_ipc(fcgid_ipc * ipc_handle);

void proc_print_exit_info(fcgid_procnode * procnode, int exitcode,
                          apr_exit_why_e exitwhy,
                          server_rec * main_server);
#endif
