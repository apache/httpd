/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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

#ifndef APACHE_OS_H
#define APACHE_OS_H

#include "ap_config.h"

/*
 * Define the API_EXPORT declaration for creating a dynamic
 * loadable library (DLL) version of Apache on Cygwin 1.x platforms.
 */

#ifndef API_EXPORT
#ifdef SHARED_CORE
# ifdef SHARED_MODULE
#  define API_VAR_EXPORT      __declspec(dllimport)
#  define API_EXPORT(type)    __declspec(dllimport) type
#  define MODULE_VAR_EXPORT   __declspec(dllexport)
# else
#  define API_VAR_EXPORT      __declspec(dllexport)
#  define API_EXPORT(type)    __declspec(dllexport) type
# endif /* def SHARED_MODULE */
#endif /* def SHARED_CORE */ 
#endif /* ndef API_EXPORT */

/*
 * We don't consider the Cygwin 1.x support neither an Unix nor
 * a Win32 platform. Basicly it's something between both, so that
 * is why we introduce our own PLATFORM define.
 */
#ifndef PLATFORM
#define PLATFORM "Cygwin"
#endif

/* 
 * Define winsock.h and winsock2.h stuff taken from Win32 API in case we  
 * want to do socket communication in Win32 native way rather then using 
 * Cygwin's POSIX wrapper to the native ones. These are needed for 
 * main/buff.c and main/http_main.c. They are linked against libwsock32.a 
 * for the import declarations of the corresponding Win32 native DLLs. 
 */ 
#ifdef CYGWIN_WINSOCK 
#define WSAEWOULDBLOCK (10035) 
#define SOCKET_ERROR (-1) 
 
#define WIN32API_IMPORT(type)  __declspec(dllimport) type __stdcall 
 
WIN32API_IMPORT(int) WSAGetLastError(void); 
WIN32API_IMPORT(int) WSASetLastError(int); 
WIN32API_IMPORT(int) ioctlsocket(unsigned int, long, unsigned long *); 
WIN32API_IMPORT(void) Sleep(unsigned int); 
#endif /* CYGWIN_WINSOCK */ 

/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */

#if !defined(INLINE) && defined(USE_GNU_INLINE)
/* Compiler supports inline, so include the inlineable functions as
 * part of the header
 */
#define INLINE extern ap_inline

INLINE int ap_os_is_path_absolute(const char *file);

/*
 * The inline things are the same as in the os/unix branch, so include
 * that one rather than our own copy that would be the same.
 */
#include "os-inline.c"

#else

/* Compiler does not support inline, so prototype the inlineable functions
 * as normal
 */
extern int ap_os_is_path_absolute(const char *file);
#endif

/* Other ap_os_ routines not used by this platform */

#define ap_os_is_filename_valid(f)          (1)
#define ap_os_kill(pid, sig)                kill(pid, sig)

/*
 *  Abstraction layer for loading
 *  Apache modules under run-time via 
 *  dynamic shared object (DSO) mechanism
 */

#ifdef HAVE_DL_H
#include <dl.h>
#endif

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#else
void *dlopen(const char *, int);
int dlclose(void *);
void *dlsym(void *, const char *);
const char *dlerror(void);
#endif

/* probably on an older system that doesn't support RTLD_NOW or RTLD_LAZY.
 * The below define is a lie since we are really doing RTLD_LAZY since the
 * system doesn't support RTLD_NOW.
 */
#ifndef RTLD_NOW
#define RTLD_NOW 1
#endif

#ifndef RTLD_GLOBAL
#define RTLD_GLOBAL 0
#endif

#define     ap_os_dso_handle_t  void *
void        ap_os_dso_init(void);
void *      ap_os_dso_load(const char *);
void        ap_os_dso_unload(void *);
void *      ap_os_dso_sym(void *, const char *);
const char *ap_os_dso_error(void);

#endif	/* !APACHE_OS_H */
