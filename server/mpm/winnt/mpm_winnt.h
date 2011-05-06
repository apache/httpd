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

/**
 * @file  mpm_winnt.h
 * @brief WinNT MPM specific 
 *
 * @addtogroup APACHE_MPM_WINNT
 * @{
 */

#ifndef APACHE_MPM_WINNT_H
#define APACHE_MPM_WINNT_H

#include "ap_listen.h"

/* From service.c: */

#define SERVICE_APACHE_RESTART 128

#ifndef AP_DEFAULT_SERVICE_NAME
#define AP_DEFAULT_SERVICE_NAME "Apache2.2"
#endif

#define SERVICECONFIG9X "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
#define SERVICECONFIG "System\\CurrentControlSet\\Services\\%s"
#define SERVICEPARAMS "System\\CurrentControlSet\\Services\\%s\\Parameters"

apr_status_t mpm_service_set_name(apr_pool_t *p, const char **display_name, 
                                                 const char *set_name);
apr_status_t mpm_merge_service_args(apr_pool_t *p, apr_array_header_t *args, 
                                   int fixed_args);

apr_status_t mpm_service_to_start(const char **display_name, apr_pool_t *p);
apr_status_t mpm_service_started(void);
apr_status_t mpm_service_install(apr_pool_t *ptemp, int argc, 
                                char const* const* argv, int reconfig);
apr_status_t mpm_service_uninstall(void);

apr_status_t mpm_service_start(apr_pool_t *ptemp, int argc, 
                              char const* const* argv);

void mpm_signal_service(apr_pool_t *ptemp, int signal);

void mpm_service_stopping(void);

void mpm_start_console_handler(void);
void mpm_start_child_console_handler(void);

/* From nt_eventlog.c: */

void mpm_nt_eventlog_stderr_open(const char *display_name, apr_pool_t *p);
void mpm_nt_eventlog_stderr_flush(void);

/* From winnt.c: */

extern int use_acceptex;
extern int winnt_mpm_state;
extern OSVERSIONINFO osver;
extern void clean_child_exit(int);

void setup_signal_names(char *prefix);

typedef enum {
    SIGNAL_PARENT_SHUTDOWN,
    SIGNAL_PARENT_RESTART,
    SIGNAL_PARENT_RESTART_GRACEFUL
} ap_signal_parent_e;
AP_DECLARE(void) ap_signal_parent(ap_signal_parent_e type);

/*
 * The Windoes MPM uses a queue of completion contexts that it passes
 * between the accept threads and the worker threads. Declare the
 * functions to access the queue and the structures passed on the
 * queue in the header file to enable modules to access them
 * if necessary. The queue resides in the MPM.
 */
#ifdef CONTAINING_RECORD
#undef CONTAINING_RECORD
#endif
#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (PCHAR)(&((type *)0)->field)))
#if APR_HAVE_IPV6
#define PADDED_ADDR_SIZE (sizeof(SOCKADDR_IN6)+16)
#else
#define PADDED_ADDR_SIZE (sizeof(SOCKADDR_IN)+16)
#endif

typedef struct CompContext {
    struct CompContext *next;
    OVERLAPPED Overlapped;
    apr_socket_t *sock;
    SOCKET accept_socket;
    char buff[2*PADDED_ADDR_SIZE];
    struct sockaddr *sa_server;
    int sa_server_len;
    struct sockaddr *sa_client;
    int sa_client_len;
    apr_pool_t *ptrans;
    apr_bucket_alloc_t *ba;
    short socket_family;
} COMP_CONTEXT, *PCOMP_CONTEXT;

typedef enum {
    IOCP_CONNECTION_ACCEPTED = 1,
    IOCP_WAIT_FOR_RECEIVE = 2,
    IOCP_WAIT_FOR_TRANSMITFILE = 3,
    IOCP_SHUTDOWN = 4
} io_state_e;

PCOMP_CONTEXT mpm_get_completion_context(void);
void          mpm_recycle_completion_context(PCOMP_CONTEXT pCompContext);
apr_status_t  mpm_post_completion_context(PCOMP_CONTEXT pCompContext, io_state_e state);
void hold_console_open_on_error(void);

/* From child.c: */
void child_main(apr_pool_t *pconf);

#endif /* APACHE_MPM_WINNT_H */
/** @} */
