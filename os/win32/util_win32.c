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

#include "apr_strings.h"
#include "arch/win32/apr_arch_file_io.h"
#include "arch/win32/apr_arch_misc.h"

#include "httpd.h"
#include "http_log.h"

#include <stdarg.h>
#include <time.h>
#include <stdlib.h>


AP_DECLARE(apr_status_t) ap_os_proc_filepath(char **binpath, apr_pool_t *p)
{
    apr_wchar_t wbinpath[APR_PATH_MAX];

#if APR_HAS_UNICODE_FS
    IF_WIN_OS_IS_UNICODE 
    {
        apr_size_t binlen;
        apr_size_t wbinlen;
        apr_status_t rv;
        if (!GetModuleFileNameW(NULL, wbinpath, sizeof(wbinpath) 
                                              / sizeof(apr_wchar_t))) {
            return apr_get_os_error();
        }
        wbinlen = wcslen(wbinpath) + 1;
        binlen = (wbinlen - 1) * 3 + 1;
        *binpath = apr_palloc(p, binlen);
        rv = apr_conv_ucs2_to_utf8(wbinpath, &wbinlen, *binpath, &binlen);
        if (rv != APR_SUCCESS)
            return rv;
        else if (wbinlen)
            return APR_ENAMETOOLONG;
    }
#endif /* APR_HAS_UNICODE_FS */
#if APR_HAS_ANSI_FS
    ELSE_WIN_OS_IS_ANSI
    {
        /* share the same scratch buffer */
        char *pathbuf = (char*) wbinpath;
        if (!GetModuleFileName(NULL, pathbuf, sizeof(wbinpath))) {
            return apr_get_os_error();
        }
        *binpath = apr_pstrdup(p, pathbuf);
    }
#endif
    return APR_SUCCESS;
}


AP_DECLARE(apr_status_t) ap_os_create_privileged_process(
    const request_rec *r,
    apr_proc_t *newproc, const char *progname,
    const char * const *args,
    const char * const *env,
    apr_procattr_t *attr, apr_pool_t *p)
{
    return apr_proc_create(newproc, progname, args, env, attr, p);
}


/* This code is stolen from misc/win32/misc.c and apr_private.h
 * This helper code resolves late bound entry points 
 * missing from one or more releases of the Win32 API...
 * but it sure would be nice if we didn't duplicate this code
 * from the APR ;-)
 */
static const char* const lateDllName[DLL_defined] = {
    "kernel32", "advapi32", "mswsock",  "ws2_32"  };
static HMODULE lateDllHandle[DLL_defined] = {
    NULL,       NULL,       NULL,       NULL      };


FARPROC ap_load_dll_func(ap_dlltoken_e fnLib, char* fnName, int ordinal)
{
    if (!lateDllHandle[fnLib]) { 
        lateDllHandle[fnLib] = LoadLibrary(lateDllName[fnLib]);
        if (!lateDllHandle[fnLib])
            return NULL;
    }
    if (ordinal)
        return GetProcAddress(lateDllHandle[fnLib], (char *) ordinal);
    else
        return GetProcAddress(lateDllHandle[fnLib], fnName);
}


/* To share the semaphores with other processes, we need a NULL ACL
 * Code from MS KB Q106387
 */
PSECURITY_ATTRIBUTES GetNullACL()
{
    PSECURITY_DESCRIPTOR pSD;
    PSECURITY_ATTRIBUTES sa;

    sa  = (PSECURITY_ATTRIBUTES) LocalAlloc(LPTR, sizeof(SECURITY_ATTRIBUTES));
    sa->nLength = sizeof(sizeof(SECURITY_ATTRIBUTES));

    pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    sa->lpSecurityDescriptor = pSD;

    if (pSD == NULL || sa == NULL) {
        return NULL;
    }
    apr_set_os_error(0);
    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)
	|| apr_get_os_error()) {
        LocalFree( pSD );
        LocalFree( sa );
        return NULL;
    }
    if (!SetSecurityDescriptorDacl(pSD, TRUE, (PACL) NULL, FALSE)
	|| apr_get_os_error()) {
        LocalFree( pSD );
        LocalFree( sa );
        return NULL;
    }

    sa->bInheritHandle = FALSE;
    return sa;
}


void CleanNullACL(void *sa) 
{
    if (sa) {
        LocalFree(((PSECURITY_ATTRIBUTES)sa)->lpSecurityDescriptor);
        LocalFree(sa);
    }
}


/*
 * The Win32 call WaitForMultipleObjects will only allow you to wait for 
 * a maximum of MAXIMUM_WAIT_OBJECTS (current 64).  Since the threading 
 * model in the multithreaded version of apache wants to use this call, 
 * we are restricted to a maximum of 64 threads.  This is a simplistic 
 * routine that will increase this size.
 */
DWORD wait_for_many_objects(DWORD nCount, CONST HANDLE *lpHandles, 
                            DWORD dwSeconds)
{
    time_t tStopTime;
    DWORD dwRet = WAIT_TIMEOUT;
    DWORD dwIndex=0;
    BOOL bFirst = TRUE;
  
    tStopTime = time(NULL) + dwSeconds;
  
    do {
        if (!bFirst)
            Sleep(1000);
        else
            bFirst = FALSE;
          
        for (dwIndex = 0; dwIndex * MAXIMUM_WAIT_OBJECTS < nCount; dwIndex++) {
            dwRet = WaitForMultipleObjects( 
                min(MAXIMUM_WAIT_OBJECTS, nCount - (dwIndex * MAXIMUM_WAIT_OBJECTS)),
                lpHandles + (dwIndex * MAXIMUM_WAIT_OBJECTS), 
                0, 0);
                                           
            if (dwRet != WAIT_TIMEOUT) {                                          
              break;
            }
        }
    } while((time(NULL) < tStopTime) && (dwRet == WAIT_TIMEOUT));
    
    return dwRet;
}
