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

#ifdef WIN32

#ifndef AP_OS_H
#define AP_OS_H
/* Delegate windows include to the apr.h header, if USER or GDI declarations
 * are required (for a window rather than console application), include
 * windows.h prior to any other Apache header files.
 */
#include "apr_pools.h"

#include <io.h>
#include <fcntl.h>

#define PLATFORM "Win32"

/* going away shortly... */
#define HAVE_DRIVE_LETTERS
#define HAVE_UNC_PATHS
#define CASE_BLIND_FILESYSTEM

#define APACHE_MPM_DIR  "server/mpm/winnt" /* generated on unix */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BIG RED WARNING: exit() is mapped to allow us to capture the exit
 * status.  This header must only be included from modules linked into
 * the ApacheCore.dll - since it's a horrible behavior to exit() from
 * any module outside the main() block, and we -will- assume it's a
 * fatal error.
 */

AP_DECLARE_DATA extern int real_exit_code;

#define exit(status) ((exit)((real_exit_code==2) ? (real_exit_code = (status)) \
                                                 : ((real_exit_code = 0), (status))))


#ifdef AP_DECLARE_EXPORT

/* Defined in util_win32.c and available only to the core module for
 * win32 MPM design.
 */

AP_DECLARE(apr_status_t) ap_os_proc_filepath(char **binpath, apr_pool_t *p);

typedef enum {
    AP_DLL_WINBASEAPI = 0,    // kernel32 From WinBase.h
    AP_DLL_WINADVAPI = 1,     // advapi32 From WinBase.h
    AP_DLL_WINSOCKAPI = 2,    // mswsock  From WinSock.h
    AP_DLL_WINSOCK2API = 3,   // ws2_32   From WinSock2.h
    AP_DLL_defined = 4        // must define as last idx_ + 1
} ap_dlltoken_e;

FARPROC ap_load_dll_func(ap_dlltoken_e fnLib, char* fnName, int ordinal);

PSECURITY_ATTRIBUTES GetNullACL();
void CleanNullACL(void *sa);

DWORD wait_for_many_objects(DWORD nCount, CONST HANDLE *lpHandles, 
                            DWORD dwSeconds);

int set_listeners_noninheritable(apr_pool_t *p);


#define AP_DECLARE_LATE_DLL_FUNC(lib, rettype, calltype, fn, ord, args, names) \
    typedef rettype (calltype *ap_winapi_fpt_##fn) args; \
    static ap_winapi_fpt_##fn ap_winapi_pfn_##fn = NULL; \
    __inline rettype ap_winapi_##fn args \
    {   if (!ap_winapi_pfn_##fn) \
            ap_winapi_pfn_##fn = (ap_winapi_fpt_##fn) ap_load_dll_func(lib, #fn, ord); \
        return (*(ap_winapi_pfn_##fn)) names; }; \

/* Win2K kernel only */
AP_DECLARE_LATE_DLL_FUNC(AP_DLL_WINADVAPI, BOOL, WINAPI, ChangeServiceConfig2A, 0, (
    SC_HANDLE hService, 
    DWORD dwInfoLevel, 
    LPVOID lpInfo),
    (hService, dwInfoLevel, lpInfo));
#undef ChangeServiceConfig2
#define ChangeServiceConfig2 ap_winapi_ChangeServiceConfig2A

/* WinNT kernel only */
AP_DECLARE_LATE_DLL_FUNC(AP_DLL_WINBASEAPI, BOOL, WINAPI, CancelIo, 0, (
    IN HANDLE hFile),
    (hFile));
#undef CancelIo
#define CancelIo ap_winapi_CancelIo

/* Win9x kernel only */
AP_DECLARE_LATE_DLL_FUNC(AP_DLL_WINBASEAPI, DWORD, WINAPI, RegisterServiceProcess, 0, (
    DWORD dwProcessId,
    DWORD dwType),
    (dwProcessId, dwType));
#define RegisterServiceProcess ap_winapi_RegisterServiceProcess

#endif /* def AP_DECLARE_EXPORT */

#ifdef __cplusplus
}
#endif

#endif  /* ndef AP_OS_H */
#endif  /* def WIN32 */
