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
#include "apr_lib.h"		/* apr_isfoo() macros */

/**
 * AP_DECLARE_EXPORT is defined when building the Apache Core dynamic
 * library, so that all public symbols are exported.
 *
 * AP_DECLARE_STATIC is defined when including Apache's Core headers,
 * to provide static linkage when the dynamic library may be unavailable.
 *
 * AP_DECLARE_STATIC and AP_DECLARE_EXPORT are left undefined when
 * including Apache's Core headers, to import and link the symbols from the 
 * dynamic Apache Core library and assure appropriate indirection and calling 
 * conventions at compile time.
 */

#if !defined(WIN32)
/**
 * Apache Core dso functions are declared with AP_DECLARE(), so they may
 * use the most appropriate calling convention.  Hook functions and other
 * Core functions with variable arguments must use AP_DECLARE_NONSTD().
 *
 * @deffunc AP_DECLARE(rettype) ap_func(args);
 */
#define AP_DECLARE(type)            type
/**
 * Apache Core dso variable argument and hook functions are declared with 
 * AP_DECLARE(), as they must use the C language calling convention.
 *
 * @deffunc AP_DECLARE_NONSTD(rettype) ap_func(args [...]);
 */
#define AP_DECLARE_NONSTD(type)     type
/**
 * Apache Core dso variables are declared with AP_MODULE_DECLARE_DATA.
 * This assures the appropriate indirection is invoked at compile time.
 *
 * @deffunc type AP_DECLARE_DATA ap_variable;
 */
#define AP_DECLARE_DATA
#elif defined(AP_DECLARE_STATIC)
#define AP_DECLARE(type)            type __stdcall
#define AP_DECLARE_NONSTD(type)     type
#define AP_DECLARE_DATA
#elif defined(AP_DECLARE_EXPORT)
#define AP_DECLARE(type)            __declspec(dllexport) type __stdcall
#define AP_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define AP_DECLARE_DATA             __declspec(dllexport)
#else
#define AP_DECLARE(type)            __declspec(dllimport) type __stdcall
#define AP_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define AP_DECLARE_DATA             __declspec(dllimport)
#endif

/* XXX: move to compatibility aliases once the symbol rename is complete
 */
#define API_EXPORT(t)        AP_DECLARE(t)
#define API_EXPORT_NONSTD(t) AP_DECLARE_NONSTD(t)
#define API_VAR_EXPORT       AP_DECLARE_DATA

#if !defined(WIN32) || defined(AP_MODULE_DECLARE_STATIC)
/**
 * Declare a dso module's exported module structure as AP_MODULE_DECLARE_DATA.
 *
 * Unless AP_MODULE_DECLARE_STATIC is defined at compile time, symbols 
 * declared with AP_MODULE_DECLARE_DATA are always exported.
 *
 * @deffunc module AP_MODULE_DECLARE_DATA mod_tag
 */
#define AP_MODULE_DECLARE_DATA
#else
/**
 * AP_MODULE_DECLARE_EXPORT is a no-op.  Unless contradicted by the
 * AP_MODULE_DECLARE_STATIC compile-time symbol, it is assumed and defined.
 *
 * The old SHARED_MODULE compile-time symbol is now the default behavior, 
 * so it is no longer referenced anywhere with Apache 2.0.
 */
#define AP_MODULE_DECLARE_EXPORT
#define AP_MODULE_DECLARE_DATA __declspec(dllexport)
#endif

/* XXX: Must go away, perhaps into compat, maybe not even there.
 */
#define MODULE_VAR_EXPORT    AP_MODULE_DECLARE_DATA

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

#ifdef SIGWAIT_TAKES_ONE_ARG
#define ap_sigwait(a,b) ((*(b)=sigwait((a)))<0?-1:0)
#else
#define ap_sigwait(a,b) sigwait((a),(b))
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
