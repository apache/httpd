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
