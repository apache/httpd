/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

#ifndef APACHE_MPM_WINNT_H
#define APACHE_MPM_WINNT_H

#include "ap_listen.h"

/* From service.c: */

#define SERVICE_APACHE_RESTART 128

#ifndef AP_DEFAULT_SERVICE_NAME
#define AP_DEFAULT_SERVICE_NAME "Apache2"
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

void mpm_nt_eventlog_stderr_open(char *display_name, apr_pool_t *p);
void mpm_nt_eventlog_stderr_flush(void);

/* From winnt.c: */

extern int windows_sockets_workaround;
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
#define PADDED_ADDR_SIZE sizeof(SOCKADDR_IN)+16
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
} COMP_CONTEXT, *PCOMP_CONTEXT;

typedef enum {
    IOCP_CONNECTION_ACCEPTED = 1,
    IOCP_WAIT_FOR_RECEIVE = 2,
    IOCP_WAIT_FOR_TRANSMITFILE = 3,
    IOCP_SHUTDOWN = 4
} io_state_e;

AP_DECLARE(PCOMP_CONTEXT) mpm_get_completion_context(void);
AP_DECLARE(void)          mpm_recycle_completion_context(PCOMP_CONTEXT pCompContext);
AP_DECLARE(apr_status_t)  mpm_post_completion_context(PCOMP_CONTEXT pCompContext, io_state_e state);
void hold_console_open_on_error(void);
#endif /* APACHE_MPM_WINNT_H */
