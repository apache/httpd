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
 */

#ifndef AP_AC_CONFIG_H
#define AP_AC_CONFIG_H

#include "ap_mmn.h"		/* MODULE_MAGIC_NUMBER_ */

/* Implemented flags for dynamic library bindings.
 *
 *   API_EXPORT(type)        for functions bound in the apache core, except:
 *   API_EXPORT_NONSTD(type) for functions with var args (only as ...)
 *   API_VAR_EXPORT          for data residing in the core
 *   MODULE_VAR_EXPORT       is a hack that will need to go away
 */

#if !defined(WIN32)
#define API_EXPORT(type)        type
#define API_EXPORT_NONSTD(type) type
#define API_VAR_EXPORT
#define MODULE_VAR_EXPORT
#elif defined(API_STATIC)
#define API_EXPORT(type)        type __stdcall
#define API_EXPORT_NONSTD(type) type
#define API_VAR_EXPORT
#define MODULE_VAR_EXPORT
#elif defined(API_EXPORT_SYMBOLS)
#define API_EXPORT(type)        __declspec(dllexport) type __stdcall
#define API_EXPORT_NONSTD(type) __declspec(dllexport) type
#define API_VAR_EXPORT		__declspec(dllexport)
#define MODULE_VAR_EXPORT       __declspec(dllexport)
#else
#define API_EXPORT(type)        __declspec(dllimport) type __stdcall
#define API_EXPORT_NONSTD(type) __declspec(dllimport) type
#define API_VAR_EXPORT		__declspec(dllimport)
#define MODULE_VAR_EXPORT       __declspec(dllexport)
#endif

#ifdef WIN32
#include "os.h"
#else
#include "ap_config_auto.h"
#include "ap_config_path.h"
#include "os.h"
#endif /* !WIN32 */
#include "apr.h"
#ifdef STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#endif

/* ap_ versions of ctype macros to make sure they deal with 8-bit chars */
#include "ap_ctype.h"

#ifdef SIGWAIT_TAKES_ONE_ARG
#define ap_sigwait(a,b) ((*(b)=sigwait((a)))<0?-1:0)
#else
#define ap_sigwait(a,b) sigwait((a),(b))
#endif

/*
 * String and memory functions
 */

#ifndef HAVE_MEMMOVE
#define memmove(a,b,c) bcopy(b,a,c)
#endif

#ifndef HAVE_BZERO
#define bzero(a,b) memset(a,0,b)
#endif

/* TODO - We need to put OS detection back to make all the following work */

#if defined(SUNOS4) || defined(IRIX) || defined(NEXT) || defined(AUX3) \
    || defined (UW) || defined(LYNXOS) || defined(TPF)
/* These systems don't do well with any lingering close code; I don't know
 * why -- manoj */
#define NO_LINGCLOSE
#endif

#ifdef SCO5
/* This allows Apache to run from a startup script on a SCO box in high
 * security (C2) mode.  
 */
#define SecureWare
#endif

/* XXX - The PHP4 comments say -D_HPUX_SOURCE is obsolete. */

/* TODO - none of the dynamic linking defines are in yet, but that's because
 * Manoj needs to learn what the exact ramifications of libtool on DSOs are */

#undef PACKAGE
#undef VERSION

#if APR_HAS_MMAP
#define USE_MMAP_FILES 1
#else
#undef USE_MMAP_FILES
#endif

#if APR_FILE_BASED_SHM
#define USE_FILE_BASED_SCOREBOARD
#else
#define USE_MEM_BASED_SCOREBOARD
#endif

/* If APR has OTHER_CHILD logic, use reliable piped logs.
 */
#if (APR_HAS_OTHER_CHILD)
#define HAVE_RELIABLE_PIPED_LOGS TRUE
#endif

#if defined(CHARSET_EBCDIC) && !defined(APACHE_XLATE)
#define APACHE_XLATE
#endif

#endif /* AP_AC_CONFIG_H */
