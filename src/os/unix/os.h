/* ====================================================================
 * Copyright (c) 1998 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#ifndef APACHE_OS_H
#define APACHE_OS_H

/*
 * We can't include conf.h (where the hide.h stuff is done) because it
 * includes us.  So we do the hide.h stuff ourself.
 */
#ifdef HIDE
#include "hide.h"
#endif

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
#include "os-inline.c"

#else

/* Compiler does not support inline, so prototype the inlineable functions
 * as normal
 */
extern int os_is_path_absolute(const char *f);
#endif

/*
 * Abstraction layer for dynamic loading of modules (mod_so.c)
 */

#if defined(LINUX) || defined(__FreeBSD__) || defined(SOLARIS2) || \
    defined(__bsdi__) || defined(IRIX) || defined(SVR4) || defined(OSF1)
# define HAVE_DLFCN_H 1
#endif

#if defined(__FreeBSD__)
# define NEED_UNDERSCORE_SYM
#endif

     /* OSes that don't support dlopen */
#if defined(UW) || defined(ULTRIX) || defined(HPUX) || defined(HPUX10)
# define NO_DL
#endif

     /* Start of real module */
#ifdef HAVE_DLFCN_H
# include <dlfcn.h>
#else
void * dlopen (const char * __filename, int __flag);
const char * dlerror (void);
void * dlsym (void *, const char *);
int dlclose (void *);
#endif

#ifndef RTLD_NOW
/* 
 * probably on an older system that doesn't support RTLD_NOW or RTLD_LAZY.
 * The below define is a lie since we are really doing RTLD_LAZY since the
 * system doesn't support RTLD_NOW.
 */
# define RTLD_NOW 1
#endif

#define os_dl_module_handle_type void *
#define os_dl_load(l)   dlopen(l, RTLD_NOW)
#define os_dl_unload(l) dlclose(l)
#define os_dl_sym(h,s)  dlsym(h,s)
#define os_dl_error()   dlerror()

#endif	/* !APACHE_OS_H */
