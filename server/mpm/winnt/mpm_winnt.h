/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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

#include "apr_listen.h"

/* From registry.c: */

apr_status_t ap_registry_create_key(const char *key);
apr_status_t ap_registry_delete_key(const char *key);

apr_status_t ap_registry_store_value(const char *key, const char *name, 
                                    const char *value);
apr_status_t ap_registry_get_value(apr_pool_t *p, const char *key, 
                                  const char *name, char **ppValue);
apr_status_t ap_registry_store_array(apr_pool_t *p, const char *key, 
                                    const char *name, int nelts, 
                                    char const* const* elts);
apr_status_t ap_registry_get_array(apr_pool_t *p, const char *key, 
                                  const char *name, 
                                  apr_array_header_t **parray);
apr_status_t ap_registry_delete_value(const char *key, const char *name);


/* From service.c: */

#define SERVICE_APACHE_RESTART 128

#define DEFAULT_SERVICE_NAME AP_SERVER_BASEPRODUCT
#define SERVICECONFIG9X "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
#define SERVICECONFIG "System\\CurrentControlSet\\Services\\%s"
#define SERVICEPARAMS "System\\CurrentControlSet\\Services\\%s\\Parameters"

extern char *service_name;
extern char *display_name;

apr_status_t mpm_service_set_name(apr_pool_t *p, char *name);
apr_status_t mpm_merge_service_args(apr_pool_t *p, apr_array_header_t *args, 
                                   int fixed_args);

apr_status_t mpm_service_to_start(void);
apr_status_t mpm_service_started(void);
apr_status_t mpm_service_install(apr_pool_t *ptemp, int argc, 
                                char const* const* argv);
apr_status_t mpm_service_uninstall(void);

apr_status_t mpm_service_start(apr_pool_t *ptemp, int argc, 
                              char const* const* argv);

void mpm_signal_service(apr_pool_t *ptemp, int signal);

void mpm_service_stopping(void);

void mpm_start_console_handler(void);
void mpm_start_child_console_handler(void);

/* From winnt.c: */

extern OSVERSIONINFO osver;
extern int ap_threads_per_child;
extern int ap_max_requests_per_child;
extern int ap_extended_status;
extern void clean_child_exit(int);

API_EXPORT(void) ap_start_shutdown(void);
API_EXPORT(void) ap_start_restart(int gracefully);

void setup_signal_names(char *prefix);
void signal_parent(int type);

typedef struct CompContext {
    OVERLAPPED Overlapped;
    SOCKET accept_socket;
    apr_socket_t *sock;
    ap_listen_rec *lr;
    BUFF *conn_io;
    char *recv_buf;
    int  recv_buf_size;
    apr_pool_t *ptrans;
    struct sockaddr *sa_server;
    int sa_server_len;
    struct sockaddr *sa_client;
    int sa_client_len;
} COMP_CONTEXT, *PCOMP_CONTEXT;

/* This code is stolen from the apr_private.h and misc/win32/misc.c
 * Please see those sources for detailed documentation.
 */
typedef enum {
    DLL_WINBASEAPI = 0,    // kernel32 From WinBase.h
    DLL_WINADVAPI = 1,     // advapi32 From WinBase.h
    DLL_WINSOCKAPI = 2,    // mswsock  From WinSock.h
    DLL_WINSOCK2API = 3,   // ws2_32   From WinSock2.h
    DLL_defined = 4        // must define as last idx_ + 1
} ap_dlltoken_e;

FARPROC ap_load_dll_func(ap_dlltoken_e fnLib, char *fnName, int ordinal);

#define AP_DECLARE_LATE_DLL_FUNC(lib, rettype, calltype, fn, ord, args, names) \
    typedef rettype (calltype *ap_winapi_fpt_##fn) args; \
    static ap_winapi_fpt_##fn ap_winapi_pfn_##fn = NULL; \
    __inline rettype ap_winapi_##fn args \
    {   if (!ap_winapi_pfn_##fn) \
            ap_winapi_pfn_##fn = (ap_winapi_fpt_##fn) ap_load_dll_func(lib, #fn, ord); \
        return (*(ap_winapi_pfn_##fn)) names; }; \

/* WinNT kernel only */
AP_DECLARE_LATE_DLL_FUNC(DLL_WINBASEAPI, BOOL, WINAPI, CancelIo, 0, (
    IN HANDLE hFile),
    (hFile));
#define CancelIo ap_winapi_CancelIo

/* Win9x kernel only */
AP_DECLARE_LATE_DLL_FUNC(DLL_WINBASEAPI, DWORD, WINAPI, RegisterServiceProcess, 0, (
    DWORD dwProcessId,
    DWORD dwType),
    (dwProcessId, dwType));
#define RegisterServiceProcess ap_winapi_RegisterServiceProcess

#endif /* APACHE_MPM_WINNT_H */
