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
 *   API_EXPORT_VAR          for data residing in the core
 *   MODULE_EXPORT_VAR       is a hack that will need to go away
 */

#if !defined(WIN32) || defined(API_STATIC)
#define API_EXPORT(type)        type __stdcall
#define API_EXPORT_NONSTD(type) type
#define API_EXPORT_VAR
#define MODULE_EXPORT_VAR
#elif defined(API_EXPORT_SYMBOLS)
#define API_EXPORT(type)        __declspec(dllexport) type __stdcall
#define API_EXPORT_NONSTD(type) __declspec(dllexport) type
#define API_EXPORT_VAR		__declspec(dllexport)
#define MODULE_EXPORT_VAR       __declspec(dllexport)
#else
#define API_EXPORT(type)        __declspec(dllimport) type __stdcall
#define API_EXPORT_NONSTD(type) __declspec(dllimport) type
#define API_EXPORT_VAR		__declspec(dllimport)
#define MODULE_EXPORT_VAR       __declspec(dllexport)
#endif

#ifdef __cplusplus
extern "C" {
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

/* The next three are for inet_*() */

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_PWD_H    /* XXX - For getpw*. This should be moved to unixd */
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H    /* XXX - For getgr*. This should be moved to unixd */
#include <grp.h>
#endif

/* ap_ versions of ctype macros to make sure they deal with 8-bit chars */
#include "ap_ctype.h"


/* XXX - This probably doesn't handle OS/2 */
#ifdef SELECT_NEEDS_CAST
#define ap_select(_a, _b, _c, _d, _e)   \
    select((SELECT_TYPE_ARG1)(_a), (SELECT_TYPE_ARG234)(_b), \
           (SELECT_TYPE_ARG234)(_c), (SELECT_TYPE_ARG234)(_d), \
           (SELECT_TYPE_ARG5)(_e))
#else
#define ap_select(_a, _b, _c, _d, _e) select(_a, _b, _c, _d, _e)
#endif

#ifdef SIGWAIT_TAKES_ONE_ARG
#define ap_sigwait(a,b) ((*(b)=sigwait((a)))<0?-1:0)
#else
#define ap_sigwait(a,b) sigwait((a),(b))
#endif

/* So that we can use inline on some critical functions, and use
 * GNUC attributes (such as to get -Wall warnings for printf-like
 * functions).  Only do this in gcc 2.7 or later ... it may work
 * on earlier stuff, but why chance it.
 *
 * We've since discovered that the gcc shipped with NeXT systems
 * as "cc" is completely broken.  It claims to be __GNUC__ and so
 * on, but it doesn't implement half of the things that __GNUC__
 * means.  In particular it's missing inline and the __attribute__
 * stuff.  So we hack around it.  PR#1613. -djg
 */
#if !defined(__GNUC__) || __GNUC__ < 2 || \
    (__GNUC__ == 2 && __GNUC_MINOR__ < 7) ||\
    defined(NEXT)
#define ap_inline
#define __attribute__(__x)
#define ENUM_BITFIELD(e,n,w)  signed int n : w
#else
#define ap_inline __inline__
#define USE_GNU_INLINE
#define ENUM_BITFIELD(e,n,w)  e n : w
#endif

/* EAGAIN apparently isn't defined on some systems */
#if !defined(HAVE_EAGAIN) && !defined(EAGAIN)
#define EAGAIN EWOULDBLOCK
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
/* XXX - What's this for */
#define SecureWare

/* Although SCO 5 defines these in <strings.h> (note the "s") they don't have
   consts. Sigh. */
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *, const char *, unsigned);
#endif /* SCO5 */

/* If APR has OTHER_CHILD logic, use reliable piped logs.
 */
#if (APR_HAS_OTHER_CHILD)
#define HAVE_RELIABLE_PIPED_LOGS TRUE
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

#if defined(CHARSET_EBCDIC) && !defined(APACHE_XLATE)
#define APACHE_XLATE
#endif

#endif /* AP_AC_CONFIG_H */
